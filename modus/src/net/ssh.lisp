;;;; SSH-2 Server Implementation for Modus
;;;; Based on RFC 4253 (SSH Transport Layer Protocol)
;;;;       RFC 4252 (SSH Authentication Protocol)
;;;;       RFC 4254 (SSH Connection Protocol)
;;;;       RFC 8731 (curve25519-sha256 Key Exchange)
;;;;
;;;; Supports:
;;;; - Key exchange: curve25519-sha256
;;;; - Host key: ssh-ed25519
;;;; - Encryption: chacha20-poly1305@openssh.com
;;;; - MAC: implicit (AEAD)
;;;; - Compression: none
;;;; - Authentication: publickey (ssh-ed25519)

(require :lib/crypto/sha256)
(require :lib/crypto/sha512)
(require :lib/crypto/x25519)
(require :lib/crypto/ed25519)
(require :lib/crypto/chacha20)
(require :lib/crypto/poly1305)
(require :lib/crypto/aead)
(require :x86-pc/e1000)

(provide :lib/net/ssh)

(in-package muerte)

;;; SSH Constants

;; Message numbers
(defconstant +ssh-msg-disconnect+ 1)
(defconstant +ssh-msg-ignore+ 2)
(defconstant +ssh-msg-unimplemented+ 3)
(defconstant +ssh-msg-debug+ 4)
(defconstant +ssh-msg-service-request+ 5)
(defconstant +ssh-msg-service-accept+ 6)
(defconstant +ssh-msg-kexinit+ 20)
(defconstant +ssh-msg-newkeys+ 21)

;; KEX specific (curve25519-sha256)
(defconstant +ssh-msg-kex-ecdh-init+ 30)
(defconstant +ssh-msg-kex-ecdh-reply+ 31)

;; User auth
(defconstant +ssh-msg-userauth-request+ 50)
(defconstant +ssh-msg-userauth-failure+ 51)
(defconstant +ssh-msg-userauth-success+ 52)
(defconstant +ssh-msg-userauth-banner+ 53)
(defconstant +ssh-msg-userauth-pk-ok+ 60)

;; Connection protocol
(defconstant +ssh-msg-global-request+ 80)
(defconstant +ssh-msg-request-success+ 81)
(defconstant +ssh-msg-request-failure+ 82)
(defconstant +ssh-msg-channel-open+ 90)
(defconstant +ssh-msg-channel-open-confirm+ 91)
(defconstant +ssh-msg-channel-open-failure+ 92)
(defconstant +ssh-msg-channel-window-adjust+ 93)
(defconstant +ssh-msg-channel-data+ 94)
(defconstant +ssh-msg-channel-extended-data+ 95)
(defconstant +ssh-msg-channel-eof+ 96)
(defconstant +ssh-msg-channel-close+ 97)
(defconstant +ssh-msg-channel-request+ 98)
(defconstant +ssh-msg-channel-success+ 99)
(defconstant +ssh-msg-channel-failure+ 100)

;; Disconnect reason codes
(defconstant +ssh-disconnect-host-not-allowed+ 1)
(defconstant +ssh-disconnect-protocol-error+ 2)
(defconstant +ssh-disconnect-key-exchange-failed+ 3)
(defconstant +ssh-disconnect-reserved+ 4)
(defconstant +ssh-disconnect-mac-error+ 5)
(defconstant +ssh-disconnect-compression-error+ 6)
(defconstant +ssh-disconnect-service-not-available+ 7)
(defconstant +ssh-disconnect-protocol-version-not-supported+ 8)
(defconstant +ssh-disconnect-host-key-not-verifiable+ 9)
(defconstant +ssh-disconnect-connection-lost+ 10)
(defconstant +ssh-disconnect-by-application+ 11)
(defconstant +ssh-disconnect-too-many-connections+ 12)
(defconstant +ssh-disconnect-auth-cancelled+ 13)
(defconstant +ssh-disconnect-no-more-auth-methods+ 14)
(defconstant +ssh-disconnect-illegal-user-name+ 15)

;; Channel open failure reason codes
(defconstant +ssh-open-administratively-prohibited+ 1)
(defconstant +ssh-open-connect-failed+ 2)
(defconstant +ssh-open-unknown-channel-type+ 3)
(defconstant +ssh-open-resource-shortage+ 4)

;;; SSH Version String
(defvar *ssh-version-string* "SSH-2.0-Modus_1.0")

;;; SSH Verbose flag
(defvar *ssh-verbose* t)

;;; Authorized public keys for authentication
(defvar *ssh-allowed-keys* nil
  "List of authorized Ed25519 public keys (each is 32-byte array)")

;;; Host key pair (set by ssh-server or generated)
(defvar *ssh-host-private-key* nil)
(defvar *ssh-host-public-key* nil)

;;; SSH Connection State

(defun make-ssh-connection (tcp-conn)
  "Create a new SSH connection state."
  (list :tcp tcp-conn
        :state :init
        :client-version nil
        :server-version *ssh-version-string*
        :client-kexinit nil
        :server-kexinit nil
        :session-id nil           ; First exchange hash becomes session ID
        :exchange-hash nil        ; H from key exchange
        :shared-secret nil        ; K from key exchange
        ;; Encryption state
        :client-to-server-key nil
        :server-to-client-key nil
        :client-to-server-iv nil
        :server-to-client-iv nil
        :client-seq 0             ; Packet sequence numbers
        :server-seq 0
        :encrypted nil            ; T after NEWKEYS
        ;; Channels
        :channels nil             ; Association list of channels
        :next-channel-id 0
        ;; Auth state
        :authenticated nil
        :username nil
        ;; REPL state
        :repl-buffer ""           ; Line buffer for REPL input
        ;; Receive buffer for data that arrived but wasn't consumed
        :buffer nil))

(defun ssh-get (conn key)
  (getf conn key))

(defun ssh-set (conn key value)
  (setf (getf conn key) value))

;;; Utility Functions

(defun ssh-u32-to-bytes (n)
  "Convert 32-bit integer to 4 bytes (big-endian)."
  (let ((result (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref result 0) (logand (ash n -24) #xff))
    (setf (aref result 1) (logand (ash n -16) #xff))
    (setf (aref result 2) (logand (ash n -8) #xff))
    (setf (aref result 3) (logand n #xff))
    result))

(defun ssh-bytes-to-u32 (bytes &optional (offset 0))
  "Convert 4 bytes to 32-bit integer (big-endian)."
  (logior (ash (aref bytes offset) 24)
          (ash (aref bytes (+ offset 1)) 16)
          (ash (aref bytes (+ offset 2)) 8)
          (aref bytes (+ offset 3))))

(defun ssh-make-string (str)
  "Create SSH string (4-byte length + data)."
  (let* ((len (length str))
         (result (make-array (+ 4 len) :element-type '(unsigned-byte 8))))
    (setf (aref result 0) (logand (ash len -24) #xff))
    (setf (aref result 1) (logand (ash len -16) #xff))
    (setf (aref result 2) (logand (ash len -8) #xff))
    (setf (aref result 3) (logand len #xff))
    (dotimes (i len)
      (setf (aref result (+ 4 i))
            (if (characterp (elt str i))
                (char-code (elt str i))
                (elt str i))))
    result))

(defun ssh-parse-string (data offset)
  "Parse SSH string at offset. Returns (string new-offset)."
  (let* ((len (ssh-bytes-to-u32 data offset))
         (str (make-array len :element-type '(unsigned-byte 8))))
    (dotimes (i len)
      (setf (aref str i) (aref data (+ offset 4 i))))
    (list str (+ offset 4 len))))

(defun ssh-make-mpint (bytes)
  "Create SSH mpint from byte array (handles leading zeros and sign bit)."
  ;; Skip leading zeros
  (let ((start 0))
    (loop while (and (< start (length bytes))
                     (= (aref bytes start) 0))
          do (incf start))
    (let* ((significant (subseq bytes start))
           ;; Add leading zero if high bit set (to ensure positive)
           (needs-zero (and (> (length significant) 0)
                            (>= (aref significant 0) #x80)))
           (len (+ (length significant) (if needs-zero 1 0)))
           (result (make-array (+ 4 len) :element-type '(unsigned-byte 8))))
      ;; Length
      (setf (aref result 0) (logand (ash len -24) #xff))
      (setf (aref result 1) (logand (ash len -16) #xff))
      (setf (aref result 2) (logand (ash len -8) #xff))
      (setf (aref result 3) (logand len #xff))
      ;; Data
      (let ((offset 4))
        (when needs-zero
          (setf (aref result offset) 0)
          (incf offset))
        (dotimes (i (length significant))
          (setf (aref result (+ offset i)) (aref significant i))))
      result)))

(defun ssh-concat (&rest arrays)
  "Concatenate byte arrays."
  (let* ((total-len (reduce #'+ arrays :key #'length))
         (result (make-array total-len :element-type '(unsigned-byte 8)))
         (pos 0))
    (dolist (arr arrays)
      (dotimes (i (length arr))
        (setf (aref result (+ pos i)) (aref arr i)))
      (incf pos (length arr)))
    result))

;;; Algorithm Name Lists

(defun ssh-namelist (names)
  "Create SSH name-list from list of strings."
  (ssh-make-string (format nil "~{~A~^,~}" names)))

;;; Packet Framing (unencrypted)

(defun ssh-make-packet (payload)
  "Create an SSH binary packet from payload.
   Format: packet_length(4) + padding_length(1) + payload + padding + MAC(0)"
  (let* ((payload-len (length payload))
         ;; Block size is 8 for unencrypted, padding must be 4-255 bytes
         ;; Total of length+padding_length+payload+padding must be multiple of 8
         (block-size 8)
         (base-len (+ 5 payload-len))  ; 4 length + 1 pad-len + payload
         (pad-len (- block-size (mod base-len block-size)))
         (packet-len (+ 1 payload-len pad-len))  ; excludes length field
         (total-len (+ 4 packet-len)))
    (when (< pad-len 4)
      (incf pad-len block-size))
    (setf packet-len (+ 1 payload-len pad-len))
    (setf total-len (+ 4 packet-len))
    (let ((packet (make-array total-len :element-type '(unsigned-byte 8))))
      ;; packet_length (4 bytes, big-endian)
      (setf (aref packet 0) (logand (ash packet-len -24) #xff))
      (setf (aref packet 1) (logand (ash packet-len -16) #xff))
      (setf (aref packet 2) (logand (ash packet-len -8) #xff))
      (setf (aref packet 3) (logand packet-len #xff))
      ;; padding_length (1 byte)
      (setf (aref packet 4) pad-len)
      ;; payload
      (dotimes (i payload-len)
        (setf (aref packet (+ 5 i)) (aref payload i)))
      ;; random padding
      (dotimes (i pad-len)
        (setf (aref packet (+ 5 payload-len i)) (random 256)))
      packet)))

(defun ssh-parse-packet (data)
  "Parse SSH binary packet. Returns (payload remaining-data) or NIL."
  (when (< (length data) 5)
    (return-from ssh-parse-packet nil))
  (let* ((packet-len (ssh-bytes-to-u32 data 0))
         (pad-len (aref data 4)))
    (when (< (length data) (+ 4 packet-len))
      (return-from ssh-parse-packet nil))
    (let* ((payload-len (- packet-len pad-len 1))
           (payload (make-array payload-len :element-type '(unsigned-byte 8))))
      (dotimes (i payload-len)
        (setf (aref payload i) (aref data (+ 5 i))))
      (let ((remaining (subseq data (+ 4 packet-len))))
        (list payload remaining)))))

;;; Encrypted Packet Handling (chacha20-poly1305@openssh.com)
;;;
;;; OpenSSH's chacha20-poly1305@openssh.com is different from RFC 8439:
;;; - 64-byte key: K1 = key[0:32] (main), K2 = key[32:64] (length)
;;; - 8-byte nonce = sequence number (big-endian), zero-padded to 12 for ChaCha20
;;; - Length (4 bytes) encrypted with K2, counter=0
;;; - Poly1305 key derived from K1, counter=0
;;; - Packet data encrypted with K1, counter=1
;;; - MAC = Poly1305(poly_key, encrypted_length || encrypted_data)

(defun ssh-make-nonce (seq)
  "Create 12-byte nonce from sequence number for OpenSSH chacha20."
  ;; OpenSSH uses 8-byte sequence number, padded with 4 zeros at start
  ;; For practical purposes, seq is always < 2^32, so bytes 4-7 are always 0
  (let ((nonce (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; nonce[0:4] = 0 (for IETF ChaCha20 compatibility)
    ;; nonce[4:8] = 0 (high 32 bits of seq, always 0)
    ;; nonce[8:12] = seq (big-endian, low 32 bits)
    (setf (aref nonce 8) (logand (ash seq -24) #xff))
    (setf (aref nonce 9) (logand (ash seq -16) #xff))
    (setf (aref nonce 10) (logand (ash seq -8) #xff))
    (setf (aref nonce 11) (logand seq #xff))
    nonce))

(defun ssh-encrypt-packet (conn payload)
  "Encrypt a packet using chacha20-poly1305@openssh.com."
  (let* ((key (ssh-get conn :server-to-client-key))
         (seq (ssh-get conn :server-seq))
         ;; Split 64-byte key per OpenSSH PROTOCOL.chacha20poly1305:
         ;; K_1 (message encryption) = key[0:32]
         ;; K_2 (length encryption) = key[32:64]
         (k1 (make-array 32 :element-type '(unsigned-byte 8)))
         (k2 (make-array 32 :element-type '(unsigned-byte 8)))
         ;; Create packet
         ;; For chacha20-poly1305, packet_length itself must be multiple of 8
         ;; packet_length = 1 (padding_len byte) + payload + padding
         (payload-len (length payload))
         (block-size 8)
         (base-len (+ 1 payload-len))  ; padding_len byte + payload
         (pad-len (- block-size (mod base-len block-size))))
    (when (= pad-len block-size)
      (setf pad-len 0))  ; If already aligned, no padding needed from this
    (when (< pad-len 4)
      (incf pad-len block-size))  ; Minimum 4 bytes padding

    ;; Extract K1 and K2 from 64-byte key
    (dotimes (i 32)
      (setf (aref k1 i) (aref key i))
      (setf (aref k2 i) (aref key (+ 32 i))))

    (let* ((packet-len (+ 1 payload-len pad-len))
           (packet-data (make-array packet-len :element-type '(unsigned-byte 8)))
           (nonce (ssh-make-nonce seq)))

      ;; Build packet data (without length): padding_length + payload + padding
      (setf (aref packet-data 0) pad-len)
      (dotimes (i payload-len)
        (setf (aref packet-data (+ 1 i)) (aref payload i)))
      (dotimes (i pad-len)
        (setf (aref packet-data (+ 1 payload-len i)) (random 256)))

      ;; 1. Encrypt length with K2, counter=0
      (let* ((len-bytes (make-array 4 :element-type '(unsigned-byte 8)))
             (len-keystream (chacha-block k2 nonce 0))
             (enc-len (make-array 4 :element-type '(unsigned-byte 8))))
        ;; Length in big-endian
        (setf (aref len-bytes 0) (logand (ash packet-len -24) #xff))
        (setf (aref len-bytes 1) (logand (ash packet-len -16) #xff))
        (setf (aref len-bytes 2) (logand (ash packet-len -8) #xff))
        (setf (aref len-bytes 3) (logand packet-len #xff))
        ;; XOR with keystream
        (dotimes (i 4)
          (setf (aref enc-len i) (logxor (aref len-bytes i) (aref len-keystream i))))

        (when *ssh-verbose*
          (format t "~&SSH: ENCRYPT seq=~D, payload-len=~D, packet-len=~D~%" seq payload-len packet-len)
          (format t "~&SSH: K2 (first 8): ")
          (dotimes (i 8) (format t "~2,'0X " (aref k2 i)))
          (format t "~%")
          (format t "~&SSH: Nonce: ")
          (dotimes (i 12) (format t "~2,'0X " (aref nonce i)))
          (format t "~%")
          (format t "~&SSH: keystream[0:4]=~2,'0X~2,'0X~2,'0X~2,'0X~%"
                  (aref len-keystream 0) (aref len-keystream 1)
                  (aref len-keystream 2) (aref len-keystream 3))
          (format t "~&SSH: len-bytes=~2,'0X~2,'0X~2,'0X~2,'0X~%"
                  (aref len-bytes 0) (aref len-bytes 1)
                  (aref len-bytes 2) (aref len-bytes 3))
          (format t "~&SSH: enc-len=~2,'0X~2,'0X~2,'0X~2,'0X~%"
                  (aref enc-len 0) (aref enc-len 1)
                  (aref enc-len 2) (aref enc-len 3)))

        ;; 2. Generate Poly1305 key from K1, counter=0
        (let* ((poly-keystream (chacha-block k1 nonce 0))
               (poly-key (make-array 32 :element-type '(unsigned-byte 8))))
          (dotimes (i 32)
            (setf (aref poly-key i) (aref poly-keystream i)))

          ;; 3. Encrypt packet data with K1, counter=1
          (let ((enc-data (chacha20-encrypt k1 nonce packet-data 1)))

            ;; 4. Compute MAC over encrypted_length || encrypted_data
            (let* ((mac-input (make-array (+ 4 (length enc-data))
                                          :element-type '(unsigned-byte 8))))
              (dotimes (i 4)
                (setf (aref mac-input i) (aref enc-len i)))
              (dotimes (i (length enc-data))
                (setf (aref mac-input (+ 4 i)) (aref enc-data i)))

              (let ((tag (poly1305 poly-key mac-input)))
                (when *ssh-verbose*
                  (format t "~&SSH: MAC tag (first 8): ")
                  (dotimes (i 8) (format t "~2,'0X " (aref tag i)))
                  (format t "~%"))
                ;; Increment sequence number
                (ssh-set conn :server-seq (1+ seq))

                ;; Return: encrypted_length || encrypted_data || tag
                (ssh-concat enc-len (ssh-concat enc-data tag))))))))))

(defun ssh-decrypt-packet (conn data)
  "Decrypt a packet using chacha20-poly1305@openssh.com.
   Returns (payload remaining-data) or NIL on error."
  (let* ((key (ssh-get conn :client-to-server-key))
         (seq (ssh-get conn :client-seq)))

    ;; Need at least 4 bytes for length + 16 bytes for tag
    (when (< (length data) 20)
      (return-from ssh-decrypt-packet nil))

    ;; Split 64-byte key per OpenSSH PROTOCOL.chacha20poly1305:
    ;; K_1 (message encryption) = key[0:32]
    ;; K_2 (length encryption) = key[32:64]
    (let ((k1 (make-array 32 :element-type '(unsigned-byte 8)))
          (k2 (make-array 32 :element-type '(unsigned-byte 8)))
          (nonce (ssh-make-nonce seq)))
      (dotimes (i 32)
        (setf (aref k1 i) (aref key i))
        (setf (aref k2 i) (aref key (+ 32 i))))

      ;; Debug: show received data and decryption attempt
      (when *ssh-verbose*
        (format t "~&SSH: Decrypt seq=~D, data len=~D~%" seq (length data))
        (format t "~&SSH: First 20 bytes of encrypted data:~%")
        (format t "~&SSH:   ")
        (dotimes (i (min 20 (length data)))
          (format t "~2,'0X " (aref data i)))
        (format t "~%")
        (format t "~&SSH: K2 (first 8): ")
        (dotimes (i 8) (format t "~2,'0X " (aref k2 i)))
        (format t "~%")
        (format t "~&SSH: Nonce: ")
        (dotimes (i 12) (format t "~2,'0X " (aref nonce i)))
        (format t "~%"))

      ;; 1. Decrypt length with K2, counter=0
      (let* ((enc-len (subseq data 0 4))
             (len-keystream (chacha-block k2 nonce 0))
             (packet-len 0))
        (when *ssh-verbose*
          (format t "~&SSH: keystream[0:4]=~2,'0X~2,'0X~2,'0X~2,'0X~%"
                  (aref len-keystream 0) (aref len-keystream 1)
                  (aref len-keystream 2) (aref len-keystream 3)))
        (dotimes (i 4)
          (let ((plain-byte (logxor (aref enc-len i) (aref len-keystream i))))
            (setf packet-len (logior (ash packet-len 8) plain-byte))))

        (when *ssh-verbose*
          (format t "~&SSH: Decrypted packet length: ~D~%" packet-len))

        ;; Check if we have complete packet
        (when (< (length data) (+ 4 packet-len 16))
          (when *ssh-verbose*
            (format t "~&SSH: Need ~D bytes, have ~D~%"
                    (+ 4 packet-len 16) (length data)))
          (return-from ssh-decrypt-packet nil))

        ;; 2. Extract encrypted data and tag
        (let* ((enc-data (subseq data 4 (+ 4 packet-len)))
               (tag (subseq data (+ 4 packet-len) (+ 4 packet-len 16))))

          ;; 3. Generate Poly1305 key from K1, counter=0
          (let* ((poly-keystream (chacha-block k1 nonce 0))
                 (poly-key (make-array 32 :element-type '(unsigned-byte 8))))
            (dotimes (i 32)
              (setf (aref poly-key i) (aref poly-keystream i)))

            ;; 4. Verify MAC over encrypted_length || encrypted_data
            (let* ((mac-input (make-array (+ 4 packet-len) :element-type '(unsigned-byte 8))))
              (dotimes (i 4)
                (setf (aref mac-input i) (aref enc-len i)))
              (dotimes (i packet-len)
                (setf (aref mac-input (+ 4 i)) (aref enc-data i)))

              (let ((expected-tag (poly1305 poly-key mac-input))
                    (tag-match t))
                ;; Constant-time comparison
                (dotimes (i 16)
                  (unless (= (aref tag i) (aref expected-tag i))
                    (setf tag-match nil)))

                (unless tag-match
                  (when *ssh-verbose*
                    (format t "~&SSH: MAC verification failed~%")
                    (format t "~&SSH: Expected: ")
                    (dotimes (i 16) (format t "~2,'0X" (aref expected-tag i)))
                    (format t "~%~&SSH: Got:      ")
                    (dotimes (i 16) (format t "~2,'0X" (aref tag i)))
                    (format t "~%"))
                  (return-from ssh-decrypt-packet nil))

                ;; 5. Decrypt data with K1, counter=1
                (let ((plaintext (chacha20-decrypt k1 nonce enc-data 1)))
                  ;; Parse packet
                  (let* ((pad-len (aref plaintext 0))
                         (payload-len (- packet-len pad-len 1))
                         (payload (make-array payload-len :element-type '(unsigned-byte 8))))
                    (dotimes (i payload-len)
                      (setf (aref payload i) (aref plaintext (+ 1 i))))

                    ;; Increment sequence number
                    (ssh-set conn :client-seq (1+ seq))

                    ;; Return payload and remaining data
                    (let ((remaining (subseq data (+ 4 packet-len 16))))
                      (list payload remaining))))))))))))

;;; Version Exchange

(defun ssh-send-version (conn)
  "Send SSH version string."
  (let* ((tcp (ssh-get conn :tcp))
         (version-line (format nil "~A~C~C" *ssh-version-string* #\return #\linefeed))
         (bytes (make-array (length version-line) :element-type '(unsigned-byte 8))))
    (dotimes (i (length version-line))
      (setf (aref bytes i) (char-code (char version-line i))))
    (muerte.x86-pc.e1000::tcp-send tcp bytes)))

(defun ssh-receive-version (conn)
  "Receive and parse client's SSH version string."
  (let* ((tcp (ssh-get conn :tcp))
         (data (muerte.x86-pc.e1000::tcp-receive tcp :timeout 30)))
    (unless data
      (when *ssh-verbose*
        (format t "~&SSH: No version received~%"))
      (return-from ssh-receive-version nil))
    ;; Convert to string and find SSH-2.0 prefix
    (let ((str (make-array (length data) :element-type 'character)))
      (dotimes (i (length data))
        (setf (aref str i) (code-char (aref data i))))
      ;; Find line end (CR-LF or just LF)
      (let* ((end (or (position #\return str)
                      (position #\linefeed str)
                      (length str)))
             ;; Find where the actual data after version line starts
             (line-end end))
        ;; Skip past CR and/or LF
        (when (and (< line-end (length str)) (eql (aref str line-end) #\return))
          (incf line-end))
        (when (and (< line-end (length str)) (eql (aref str line-end) #\linefeed))
          (incf line-end))
        (let ((version (subseq str 0 end)))
          (when *ssh-verbose*
            (format t "~&SSH: Client version: ~A~%" version))
          (unless (and (>= (length version) 7)
                       (string= (subseq version 0 7) "SSH-2.0"))
            (when *ssh-verbose*
              (format t "~&SSH: Invalid version~%"))
            (return-from ssh-receive-version nil))
          (ssh-set conn :client-version version)
          ;; Save any remaining data (could be KEXINIT that arrived in same segment)
          (when (< line-end (length data))
            (let ((remaining (subseq data line-end)))
              (when (> (length remaining) 0)
                (when *ssh-verbose*
                  (format t "~&SSH: Buffered ~D bytes after version~%" (length remaining)))
                (ssh-set conn :buffer remaining))))
          version)))))

;;; KEXINIT

(defun ssh-make-kexinit ()
  "Create a KEXINIT payload."
  (let ((cookie (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref cookie i) (random 256)))
    (ssh-concat
     (vector +ssh-msg-kexinit+)
     cookie
     ;; kex_algorithms
     (ssh-namelist '("curve25519-sha256" "curve25519-sha256@libssh.org"))
     ;; server_host_key_algorithms
     (ssh-namelist '("ssh-ed25519"))
     ;; encryption_algorithms_client_to_server
     (ssh-namelist '("chacha20-poly1305@openssh.com"))
     ;; encryption_algorithms_server_to_client
     (ssh-namelist '("chacha20-poly1305@openssh.com"))
     ;; mac_algorithms_client_to_server (implicit with AEAD)
     (ssh-namelist '("none"))
     ;; mac_algorithms_server_to_client
     (ssh-namelist '("none"))
     ;; compression_algorithms_client_to_server
     (ssh-namelist '("none"))
     ;; compression_algorithms_server_to_client
     (ssh-namelist '("none"))
     ;; languages_client_to_server
     (ssh-namelist '())
     ;; languages_server_to_client
     (ssh-namelist '())
     ;; first_kex_packet_follows
     (vector 0)
     ;; reserved (future extension)
     (ssh-u32-to-bytes 0))))

(defun ssh-send-kexinit (conn)
  "Send KEXINIT message."
  (let* ((kexinit (ssh-make-kexinit))
         (packet (ssh-make-packet kexinit)))
    (ssh-set conn :server-kexinit kexinit)
    (muerte.x86-pc.e1000::tcp-send (ssh-get conn :tcp) packet)
    (when *ssh-verbose*
      (format t "~&SSH: Sent KEXINIT~%"))))

(defun ssh-receive-kexinit (conn)
  "Receive and parse client's KEXINIT."
  ;; First check buffer
  (let ((buffered (ssh-get conn :buffer))
        (data nil)
        (tcp (ssh-get conn :tcp)))
    (if (and buffered (> (length buffered) 0))
        (progn
          (setf data buffered)
          (ssh-set conn :buffer nil)
          (when *ssh-verbose*
            (format t "~&SSH: Using ~D bytes from buffer for KEXINIT~%" (length data))))
        (let ((received (muerte.x86-pc.e1000::tcp-receive tcp :timeout 30)))
          (when *ssh-verbose*
            (format t "~&SSH: tcp-receive returned ~A~%"
                    (if received (format nil "~D bytes" (length received)) "NIL")))
          (setf data received)))
    (unless data
      (when *ssh-verbose*
        (format t "~&SSH: No KEXINIT data received~%"))
      (return-from ssh-receive-kexinit nil))

    ;; Check if we have enough data for the packet
    ;; Keep reading until we have the full packet
    (loop
      (when (>= (length data) 4)
        (let ((packet-len (ssh-bytes-to-u32 data 0)))
          (when *ssh-verbose*
            (format t "~&SSH: Have ~D bytes, need ~D bytes~%"
                    (length data) (+ 4 packet-len)))
          (when (>= (length data) (+ 4 packet-len))
            ;; Have complete packet
            (return))))
      ;; Need more data
      (let ((more (muerte.x86-pc.e1000::tcp-receive tcp :timeout 30)))
        (unless more
          (when *ssh-verbose*
            (format t "~&SSH: Timeout waiting for more KEXINIT data~%"))
          (return-from ssh-receive-kexinit nil))
        (when *ssh-verbose*
          (format t "~&SSH: Got ~D more bytes~%" (length more)))
        ;; Concatenate data
        (setf data (ssh-concat data more))))

    (when *ssh-verbose*
      (format t "~&SSH: Parsing ~D bytes of KEXINIT data~%" (length data)))
    (let ((parsed (ssh-parse-packet data)))
      (unless parsed
        (when *ssh-verbose*
          (format t "~&SSH: Failed to parse KEXINIT packet~%"))
        (return-from ssh-receive-kexinit nil))
      (let ((payload (first parsed))
            (remaining (second parsed)))
        (when *ssh-verbose*
          (format t "~&SSH: Parsed packet, payload ~D bytes, msg type ~D~%"
                  (length payload) (aref payload 0)))
        (unless (= (aref payload 0) +ssh-msg-kexinit+)
          (when *ssh-verbose*
            (format t "~&SSH: Expected KEXINIT, got ~D~%" (aref payload 0)))
          (return-from ssh-receive-kexinit nil))
        (ssh-set conn :client-kexinit payload)
        ;; Save any remaining data (e.g., KEX_ECDH_INIT that arrived in same segment)
        (when (and remaining (> (length remaining) 0))
          (when *ssh-verbose*
            (format t "~&SSH: Buffered ~D bytes of remaining data~%" (length remaining)))
          (ssh-set conn :buffer remaining))
        (when *ssh-verbose*
          (format t "~&SSH: Received KEXINIT~%"))
        t))))

;;; Key Exchange (curve25519-sha256)

(defun ssh-encode-host-key ()
  "Encode host public key in SSH format."
  (ssh-concat
   (ssh-make-string "ssh-ed25519")
   (ssh-make-string *ssh-host-public-key*)))

(defun ssh-compute-exchange-hash (conn client-ephemeral server-ephemeral shared-secret)
  "Compute the exchange hash H."
  ;; H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
  ;; V_C, V_S: version strings
  ;; I_C, I_S: KEXINIT payloads
  ;; K_S: server's host key
  ;; Q_C, Q_S: ephemeral public keys
  ;; K: shared secret (mpint)
  (let* ((v-c (ssh-make-string (ssh-get conn :client-version)))
         (v-s (ssh-make-string (ssh-get conn :server-version)))
         (i-c (ssh-make-string (ssh-get conn :client-kexinit)))
         (i-s (ssh-make-string (ssh-get conn :server-kexinit)))
         (k-s (ssh-make-string (ssh-encode-host-key)))
         (q-c (ssh-make-string client-ephemeral))
         (q-s (ssh-make-string server-ephemeral))
         (k (ssh-make-mpint shared-secret))
         (hash-input (ssh-concat v-c v-s i-c i-s k-s q-c q-s k)))
    (sha256 hash-input)))

(defun ssh-derive-key (conn key-id needed-len)
  "Derive encryption key using RFC 4253 key derivation.
   KEY-ID is a single character: A-F for different keys."
  ;; K1 = SHA256(K || H || key-id || session-id)
  ;; K2 = SHA256(K || H || K1)
  ;; etc.
  (let* ((k (ssh-make-mpint (ssh-get conn :shared-secret)))
         (h (ssh-get conn :exchange-hash))
         (session-id (ssh-get conn :session-id))
         (id-byte (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element (char-code key-id)))
         (k1-input (ssh-concat k h id-byte session-id))
         (k1 (sha256 k1-input))
         (key k1))
    (when (and *ssh-verbose* (or (eql key-id #\C) (eql key-id #\D)))
      (format t "~&SSH: Key derivation for ~A:~%" key-id)
      (format t "~&SSH: K (mpint, all ~D bytes):~%" (length k))
      (dotimes (i (length k))
        (format t "~2,'0X " (aref k i))
        (when (and (> i 0) (= (mod (1+ i) 16) 0))
          (format t "~%")))
      (format t "~%")
      (format t "~&SSH: H (~D bytes):~%" (length h))
      (dotimes (i (length h))
        (format t "~2,'0X " (aref h i))
        (when (and (> i 0) (= (mod (1+ i) 16) 0))
          (format t "~%")))
      (format t "~%")
      (format t "~&SSH: id-byte: ~2,'0X (char ~A)~%" (aref id-byte 0) key-id)
      (format t "~&SSH: session-id ~A, len=~D~%"
              (if session-id "present" "NIL!")
              (if session-id (length session-id) 0))
      (when session-id
        (format t "~&SSH: session-id (~D bytes):~%" (length session-id))
        (dotimes (i (length session-id))
          (format t "~2,'0X " (aref session-id i))
          (when (and (> i 0) (= (mod (1+ i) 16) 0))
            (format t "~%")))
        (format t "~%"))
      (format t "~&SSH: k1-input total ~D bytes~%" (length k1-input))
      (format t "~&SSH: k1-input (first 64):~%")
      (dotimes (i (min 64 (length k1-input)))
        (format t "~2,'0X " (aref k1-input i))
        (when (and (> i 0) (= (mod (1+ i) 16) 0))
          (format t "~%")))
      (format t "~%")
      (format t "~&SSH: K1 result (first 16): ")
      (dotimes (i 16) (format t "~2,'0X " (aref k1 i)))
      (format t "~%"))
    ;; If we need more bytes, compute K2, K3, etc.
    (loop while (< (length key) needed-len)
          do (let ((kn-input (ssh-concat k h key)))
               (setf key (ssh-concat key (sha256 kn-input)))))
    (subseq key 0 needed-len)))

(defun ssh-handle-kex-ecdh-init (conn data)
  "Handle KEX_ECDH_INIT message and send KEX_ECDH_REPLY."
  ;; Parse client's ephemeral public key
  (let ((client-pubkey-result (ssh-parse-string data 1)))
    (unless client-pubkey-result
      (when *ssh-verbose*
        (format t "~&SSH: Failed to parse client ephemeral key~%"))
      (return-from ssh-handle-kex-ecdh-init nil))
    (let* ((client-ephemeral (first client-pubkey-result))
           ;; Generate server's ephemeral key pair
           (server-private (make-array 32 :element-type '(unsigned-byte 8)))
           (server-ephemeral nil)
           (shared-secret nil))
      (when *ssh-verbose*
        (format t "~&SSH: Client ephemeral key: ~D bytes~%" (length client-ephemeral)))
      ;; Generate random private key
      (dotimes (i 32)
        (setf (aref server-private i) (random 256)))
      ;; Compute public key
      (setf server-ephemeral (x25519-public-key server-private))
      (when *ssh-verbose*
        (format t "~&SSH: Server ephemeral key generated~%"))
      ;; Compute shared secret
      (setf shared-secret (x25519 server-private client-ephemeral))
      (ssh-set conn :shared-secret shared-secret)
      (when *ssh-verbose*
        (format t "~&SSH: Shared secret computed~%"))

      ;; Compute exchange hash
      (let ((h (ssh-compute-exchange-hash conn client-ephemeral server-ephemeral shared-secret)))
        (ssh-set conn :exchange-hash h)
        (when *ssh-verbose*
          (format t "~&SSH: Exchange hash: ")
          (dotimes (i (min 16 (length h)))
            (format t "~2,'0X" (aref h i)))
          (format t "...~%"))
        ;; First exchange hash becomes session ID
        (unless (ssh-get conn :session-id)
          (ssh-set conn :session-id h))

        ;; Sign the hash with host key
        (when *ssh-verbose*
          (format t "~&SSH: Signing with host key~%"))
        (let* ((signature (ed25519-sign *ssh-host-private-key* h))
               ;; Encode signature in SSH format
               (sig-blob (ssh-concat
                          (ssh-make-string "ssh-ed25519")
                          (ssh-make-string signature))))
          (when *ssh-verbose*
            (format t "~&SSH: Signature: ")
            (dotimes (i (min 16 (length signature)))
              (format t "~2,'0X" (aref signature i)))
            (format t "... (~D bytes)~%" (length signature)))
          ;; Verify our own signature for debugging
          (when *ssh-verbose*
            (format t "~&SSH: About to verify - pubkey (8): ")
            (dotimes (i (min 8 (length *ssh-host-public-key*)))
              (format t "~2,'0X" (aref *ssh-host-public-key* i)))
            (format t "~%")
            (format t "~&SSH: About to verify - sig (16): ")
            (dotimes (i (min 16 (length signature)))
              (format t "~2,'0X" (aref signature i)))
            (format t "~%")
            (format t "~&SSH: About to verify - hash (16): ")
            (dotimes (i (min 16 (length h)))
              (format t "~2,'0X" (aref h i)))
            (format t "~%"))
          (let ((verify-result (ed25519-verify *ssh-host-public-key* signature h)))
            (when *ssh-verbose*
              (format t "~&SSH: Self-verify: ~A~%" (if verify-result "OK" "FAILED"))))
          ;; Build KEX_ECDH_REPLY
          (let* ((reply (ssh-concat
                         (vector +ssh-msg-kex-ecdh-reply+)
                         (ssh-make-string (ssh-encode-host-key))
                         (ssh-make-string server-ephemeral)
                         (ssh-make-string sig-blob)))
                 (packet (ssh-make-packet reply)))
            (muerte.x86-pc.e1000::tcp-send (ssh-get conn :tcp) packet)
            (when *ssh-verbose*
              (format t "~&SSH: Sent KEX_ECDH_REPLY (~D bytes)~%" (length packet)))
            t))))))

(defun ssh-send-newkeys (conn)
  "Send NEWKEYS message."
  (let* ((payload (vector +ssh-msg-newkeys+))
         (packet (ssh-make-packet payload)))
    (muerte.x86-pc.e1000::tcp-send (ssh-get conn :tcp) packet)
    (when *ssh-verbose*
      (format t "~&SSH: Sent NEWKEYS~%"))))

(defun ssh-receive-newkeys (conn)
  "Receive NEWKEYS message from client."
  ;; First check buffer
  (let ((buffered (ssh-get conn :buffer))
        (data nil))
    (if (and buffered (> (length buffered) 0))
        (progn
          (setf data buffered)
          (ssh-set conn :buffer nil)
          (when *ssh-verbose*
            (format t "~&SSH: Using ~D bytes from buffer for NEWKEYS~%" (length data))))
        (let* ((tcp (ssh-get conn :tcp))
               (received (muerte.x86-pc.e1000::tcp-receive tcp :timeout 30)))
          (setf data received)))
    (unless data
      (return-from ssh-receive-newkeys nil))
    (let ((parsed (ssh-parse-packet data)))
      (unless parsed
        (return-from ssh-receive-newkeys nil))
      (let ((payload (first parsed))
            (remaining (second parsed)))
        (unless (= (aref payload 0) +ssh-msg-newkeys+)
          (when *ssh-verbose*
            (format t "~&SSH: Expected NEWKEYS, got ~D~%" (aref payload 0)))
          (return-from ssh-receive-newkeys nil))
        ;; Save any remaining data
        (when (and remaining (> (length remaining) 0))
          (ssh-set conn :buffer remaining))
        (when *ssh-verbose*
          (format t "~&SSH: Received NEWKEYS~%"))
        t))))

(defun ssh-derive-keys (conn)
  "Derive all encryption keys after key exchange."
  ;; For chacha20-poly1305@openssh.com:
  ;; Key length = 64 bytes (32 for main key, 32 for length encryption)
  (ssh-set conn :client-to-server-key (ssh-derive-key conn #\C 64))
  (ssh-set conn :server-to-client-key (ssh-derive-key conn #\D 64))
  ;; IV not used for chacha20-poly1305 (nonce derived from sequence number)
  (ssh-set conn :client-to-server-iv (ssh-derive-key conn #\A 0))
  (ssh-set conn :server-to-client-iv (ssh-derive-key conn #\B 0))
  ;; Set sequence numbers: both sides have sent 3 packets before encryption
  ;; (KEXINIT=0, KEX=1, NEWKEYS=2), so first encrypted packet is seq 3
  (ssh-set conn :client-seq 3)
  (ssh-set conn :server-seq 3)
  (ssh-set conn :encrypted t)
  (when *ssh-verbose*
    (format t "~&SSH: Keys derived, encryption enabled~%")))

;;; Packet Send/Receive with Encryption

(defun ssh-send-packet (conn payload)
  "Send an SSH packet (encrypting if needed)."
  (if (ssh-get conn :encrypted)
      (let ((encrypted (ssh-encrypt-packet conn payload)))
        (when *ssh-verbose*
          (format t "~&SSH: Sending ~D encrypted bytes:~%" (length encrypted))
          (format t "~&SSH:   ")
          (dotimes (i (min 48 (length encrypted)))
            (format t "~2,'0X " (aref encrypted i)))
          (format t "~%"))
        (muerte.x86-pc.e1000::tcp-send (ssh-get conn :tcp) encrypted))
      (let ((packet (ssh-make-packet payload)))
        (muerte.x86-pc.e1000::tcp-send (ssh-get conn :tcp) packet))))

(defun ssh-receive-packet (conn &key (timeout 30))
  "Receive an SSH packet (decrypting if needed). Returns payload or NIL."
  ;; First check if we have buffered data from a previous read
  (let ((buffered (ssh-get conn :buffer))
        (data nil))
    (if (and buffered (> (length buffered) 0))
        (progn
          ;; Use buffered data
          (setf data buffered)
          (ssh-set conn :buffer nil)
          (when *ssh-verbose*
            (format t "~&SSH: Using ~D bytes from buffer~%" (length data))))
        ;; No buffered data, read from TCP
        (let* ((tcp (ssh-get conn :tcp))
               (received (muerte.x86-pc.e1000::tcp-receive tcp :timeout timeout)))
          (setf data received)))
    (unless data
      (return-from ssh-receive-packet nil))
    (if (ssh-get conn :encrypted)
        (let ((result (ssh-decrypt-packet conn data)))
          (when result
            ;; Save any remaining data
            (let ((remaining (second result)))
              (when (and remaining (> (length remaining) 0))
                (ssh-set conn :buffer remaining)))
            (first result)))
        (let ((result (ssh-parse-packet data)))
          (when result
            ;; Save any remaining data
            (let ((remaining (second result)))
              (when (and remaining (> (length remaining) 0))
                (ssh-set conn :buffer remaining)))
            (first result))))))

;;; Authentication

(defun ssh-handle-service-request (conn payload)
  "Handle SSH_MSG_SERVICE_REQUEST."
  (let ((service-result (ssh-parse-string payload 1)))
    (unless service-result
      (return-from ssh-handle-service-request nil))
    (let ((service (first service-result)))
      ;; Convert to string
      (let ((service-name (make-array (length service) :element-type 'character)))
        (dotimes (i (length service))
          (setf (aref service-name i) (code-char (aref service i))))
        (when *ssh-verbose*
          (format t "~&SSH: Service request: ~A~%" service-name))
        (cond
          ((string= service-name "ssh-userauth")
           ;; Accept userauth service
           (let ((reply (ssh-concat
                         (vector +ssh-msg-service-accept+)
                         (ssh-make-string "ssh-userauth"))))
             (ssh-send-packet conn reply)
             ;; Send banner/MOTD
             (ssh-send-banner conn)
             (when *ssh-verbose*
               (format t "~&SSH: Accepted ssh-userauth~%"))
             t))
          (t
           (when *ssh-verbose*
             (format t "~&SSH: Unknown service~%"))
           nil))))))

(defun ssh-handle-userauth-request (conn payload)
  "Handle SSH_MSG_USERAUTH_REQUEST."
  ;; Parse: username, service-name, method-name, method-specific
  (let* ((pos 1)
         (username-result (ssh-parse-string payload pos))
         (username (first username-result)))
    (setf pos (second username-result))
    (let* ((service-result (ssh-parse-string payload pos))
           (service (first service-result)))
      (setf pos (second service-result))
      (let* ((method-result (ssh-parse-string payload pos))
             (method (first method-result)))
        (setf pos (second method-result))
        ;; Convert to strings
        (let ((username-str (make-array (length username) :element-type 'character))
              (method-str (make-array (length method) :element-type 'character)))
          (dotimes (i (length username))
            (setf (aref username-str i) (code-char (aref username i))))
          (dotimes (i (length method))
            (setf (aref method-str i) (code-char (aref method i))))
          (when *ssh-verbose*
            (format t "~&SSH: Auth request: user=~A method=~A~%" username-str method-str))
          (ssh-set conn :username username-str)
          (cond
            ((string= method-str "none")
             ;; Reject none, list available methods
             (ssh-send-auth-failure conn))
            ((string= method-str "publickey")
             (ssh-handle-publickey-auth conn payload pos))
            (t
             (ssh-send-auth-failure conn))))))))

(defun ssh-send-auth-failure (conn)
  "Send SSH_MSG_USERAUTH_FAILURE."
  (let ((reply (ssh-concat
                (vector +ssh-msg-userauth-failure+)
                (ssh-namelist '("publickey"))
                (vector 0))))  ; partial success = false
    (ssh-send-packet conn reply)))

(defun ssh-send-auth-success (conn)
  "Send SSH_MSG_USERAUTH_SUCCESS."
  (let ((reply (vector +ssh-msg-userauth-success+)))
    (ssh-send-packet conn reply)
    (ssh-set conn :authenticated t)
    (when *ssh-verbose*
      (format t "~&SSH: Authentication successful~%"))))

(defun ssh-handle-publickey-auth (conn payload pos)
  "Handle publickey authentication."
  ;; Parse: has-signature, algorithm, public-key-blob
  (let ((has-sig (aref payload pos)))
    (incf pos)
    (let* ((algo-result (ssh-parse-string payload pos))
           (algo (first algo-result)))
      (setf pos (second algo-result))
      (let* ((key-result (ssh-parse-string payload pos))
             (key-blob (first key-result)))
        (setf pos (second key-result))
        ;; Parse key blob to get actual public key
        (let* ((key-algo-result (ssh-parse-string key-blob 0))
               (key-data-result (ssh-parse-string key-blob (second key-algo-result)))
               (public-key (first key-data-result)))
          ;; Check if this key is authorized
          (let ((authorized (ssh-key-authorized-p public-key)))
            (cond
              ((zerop has-sig)
               ;; Query only - respond with PK_OK if key is known
               (if authorized
                   (let ((reply (ssh-concat
                                 (vector +ssh-msg-userauth-pk-ok+)
                                 (ssh-make-string algo)
                                 (ssh-make-string key-blob))))
                     (ssh-send-packet conn reply)
                     (when *ssh-verbose*
                       (format t "~&SSH: Public key OK~%")))
                   (ssh-send-auth-failure conn)))
              (t
               ;; Has signature - verify it
               (let* ((sig-result (ssh-parse-string payload pos))
                      (sig-blob (first sig-result)))
                 ;; Parse signature blob
                 (let* ((sig-algo-result (ssh-parse-string sig-blob 0))
                        (sig-data-result (ssh-parse-string sig-blob (second sig-algo-result)))
                        (signature (first sig-data-result)))
                   ;; Build message that was signed
                   ;; session_id || SSH_MSG_USERAUTH_REQUEST || username || service || "publickey" || TRUE || algorithm || key
                   (let* ((session-id (ssh-get conn :session-id))
                          (msg (ssh-concat
                                (ssh-make-string session-id)
                                (vector +ssh-msg-userauth-request+)
                                (ssh-make-string (ssh-get conn :username))
                                (ssh-make-string "ssh-connection")
                                (ssh-make-string "publickey")
                                (vector 1)
                                (ssh-make-string algo)
                                (ssh-make-string key-blob))))
                     (when *ssh-verbose*
                       (format t "~&SSH: Session ID (first 8): ")
                       (dotimes (i (min 8 (length session-id)))
                         (format t "~2,'0X" (aref session-id i)))
                       (format t "~%")
                       (format t "~&SSH: Username: ~A~%" (ssh-get conn :username))
                       (format t "~&SSH: Public key (first 8): ")
                       (dotimes (i (min 8 (length public-key)))
                         (format t "~2,'0X" (aref public-key i)))
                       (format t "~%")
                       (format t "~&SSH: Signature (first 16): ")
                       (dotimes (i (min 16 (length signature)))
                         (format t "~2,'0X" (aref signature i)))
                       (format t "~%")
                       (format t "~&SSH: Message len=~D, first 32: " (length msg))
                       (dotimes (i (min 32 (length msg)))
                         (format t "~2,'0X" (aref msg i)))
                       (format t "~%"))
                     (if (and authorized
                              (ed25519-verify public-key signature msg))
                         (ssh-send-auth-success conn)
                         (progn
                           (when *ssh-verbose*
                             (format t "~&SSH: Signature verification failed~%"))
                           (ssh-send-auth-failure conn))))))))))))))

(defun ssh-key-authorized-p (public-key)
  "Check if public key is in the authorized keys list."
  (dolist (authorized-key *ssh-allowed-keys*)
    (when (and (= (length public-key) (length authorized-key))
               (let ((match t))
                 (dotimes (i (length public-key))
                   (when (/= (aref public-key i) (aref authorized-key i))
                     (setf match nil)))
                 match))
      (return-from ssh-key-authorized-p t)))
  nil)

;;; Channel Management

(defun ssh-handle-channel-open (conn payload)
  "Handle SSH_MSG_CHANNEL_OPEN."
  (let* ((pos 1)
         (type-result (ssh-parse-string payload pos))
         (channel-type (first type-result)))
    (setf pos (second type-result))
    (let* ((sender-channel (ssh-bytes-to-u32 payload pos))
           (initial-window (ssh-bytes-to-u32 payload (+ pos 4)))
           (max-packet (ssh-bytes-to-u32 payload (+ pos 8))))
      (declare (ignore initial-window max-packet))
      ;; Convert type to string
      (let ((type-str (make-array (length channel-type) :element-type 'character)))
        (dotimes (i (length channel-type))
          (setf (aref type-str i) (code-char (aref channel-type i))))
        (when *ssh-verbose*
          (format t "~&SSH: Channel open: type=~A sender=~D~%" type-str sender-channel))
        (cond
          ((string= type-str "session")
           ;; Accept session channel
           (let* ((our-channel (or (ssh-get conn :next-channel-id) 0))
                  (channel (list :type "session"
                                 :sender sender-channel
                                 :receiver our-channel
                                 :window #x100000
                                 :max-packet #x4000)))
             (ssh-set conn :next-channel-id (1+ our-channel))
             (ssh-set conn :channels
                      (cons (cons our-channel channel) (ssh-get conn :channels)))
             ;; Send confirmation
             (let ((reply (ssh-concat
                           (vector +ssh-msg-channel-open-confirm+)
                           (ssh-u32-to-bytes sender-channel)
                           (ssh-u32-to-bytes our-channel)
                           (ssh-u32-to-bytes #x100000)  ; window
                           (ssh-u32-to-bytes #x4000)))) ; max packet
               (ssh-send-packet conn reply)
               (when *ssh-verbose*
                 (format t "~&SSH: Channel opened~%")))))
          (t
           ;; Unknown channel type
           (let ((reply (ssh-concat
                         (vector +ssh-msg-channel-open-failure+)
                         (ssh-u32-to-bytes sender-channel)
                         (ssh-u32-to-bytes +ssh-open-unknown-channel-type+)
                         (ssh-make-string "Unknown channel type")
                         (ssh-make-string ""))))
             (ssh-send-packet conn reply))))))))

(defun ssh-handle-channel-request (conn payload)
  "Handle SSH_MSG_CHANNEL_REQUEST."
  (let* ((channel-id (ssh-bytes-to-u32 payload 1))
         (pos 5)
         (type-result (ssh-parse-string payload pos))
         (request-type (first type-result)))
    (setf pos (second type-result))
    (let ((want-reply (aref payload pos)))
      ;; Convert type to string
      (let ((type-str (make-array (length request-type) :element-type 'character)))
        (dotimes (i (length request-type))
          (setf (aref type-str i) (code-char (aref request-type i))))
        (when *ssh-verbose*
          (format t "~&SSH: Channel request: type=~A channel=~D~%" type-str channel-id))
        (cond
          ((string= type-str "pty-req")
           ;; Accept PTY request (we'll ignore the terminal settings)
           (when (plusp want-reply)
             (let ((reply (ssh-concat
                           (vector +ssh-msg-channel-success+)
                           (ssh-u32-to-bytes channel-id))))
               (ssh-send-packet conn reply))))
          ((string= type-str "shell")
           ;; Accept shell request - start REPL
           (when (plusp want-reply)
             (let ((reply (ssh-concat
                           (vector +ssh-msg-channel-success+)
                           (ssh-u32-to-bytes channel-id))))
               (ssh-send-packet conn reply)))
           ;; Mark channel for shell
           (let ((channel-entry (assoc channel-id (ssh-get conn :channels))))
             (when channel-entry
               (setf (getf (cdr channel-entry) :shell) t)))
           (when *ssh-verbose*
             (format t "~&SSH: Shell request accepted~%"))
           ;; Send welcome message and prompt
           (ssh-send-string conn channel-id "
Welcome to Modus SSH REPL
Type 'help' for commands, 'exit' to disconnect.

")
           (ssh-repl-send-prompt conn channel-id))
          ((string= type-str "exec")
           ;; Parse command string
           (let* ((cmd-result (ssh-parse-string payload (1+ pos)))
                  (cmd-bytes (first cmd-result))
                  (cmd-str (make-array (length cmd-bytes) :element-type 'character)))
             (dotimes (i (length cmd-bytes))
               (setf (aref cmd-str i) (code-char (aref cmd-bytes i))))
             (when *ssh-verbose*
               (format t "~&SSH: Exec command: ~A~%" cmd-str))
             ;; Accept exec request
             (when (plusp want-reply)
               (let ((reply (ssh-concat
                             (vector +ssh-msg-channel-success+)
                             (ssh-u32-to-bytes channel-id))))
                 (ssh-send-packet conn reply)))
             ;; Execute command and send result
             (let ((result (ssh-exec-command cmd-str)))
               (ssh-send-string conn channel-id result)
               ;; Send exit status (0 = success)
               (ssh-send-exit-status conn channel-id 0)
               ;; Send channel EOF
               (ssh-send-channel-eof conn channel-id)
               ;; Close channel
               (ssh-send-channel-close conn channel-id)))
           (when *ssh-verbose*
             (format t "~&SSH: Exec request completed~%")))
          ((string= type-str "env")
           ;; Ignore environment requests but confirm
           (when (plusp want-reply)
             (let ((reply (ssh-concat
                           (vector +ssh-msg-channel-success+)
                           (ssh-u32-to-bytes channel-id))))
               (ssh-send-packet conn reply))))
          (t
           (when (plusp want-reply)
             (let ((reply (ssh-concat
                           (vector +ssh-msg-channel-failure+)
                           (ssh-u32-to-bytes channel-id))))
               (ssh-send-packet conn reply)))))))))

(defun ssh-handle-channel-data (conn payload)
  "Handle SSH_MSG_CHANNEL_DATA."
  (let* ((channel-id (ssh-bytes-to-u32 payload 1))
         (data-result (ssh-parse-string payload 5))
         (data (first data-result)))
    (when *ssh-verbose*
      (format t "~&SSH: Channel data: ~D bytes on channel ~D~%" (length data) channel-id))
    ;; Return the data for processing
    data))

(defun ssh-send-channel-data (conn channel-id data)
  "Send SSH_MSG_CHANNEL_DATA."
  (let* ((channel-entry (assoc channel-id (ssh-get conn :channels)))
         (sender-channel (if channel-entry
                             (getf (cdr channel-entry) :sender)
                             channel-id)))
    (let ((msg (ssh-concat
                (vector +ssh-msg-channel-data+)
                (ssh-u32-to-bytes sender-channel)
                (ssh-make-string data))))
      (ssh-send-packet conn msg))))

(defun ssh-send-string (conn channel-id string)
  "Send a string over SSH channel. Converts LF to CRLF for terminal compatibility."
  ;; Count LFs that need conversion (LF not preceded by CR)
  (let ((lf-count 0))
    (dotimes (i (length string))
      (when (char= (char string i) #\newline)
        (unless (and (plusp i) (char= (char string (1- i)) #\return))
          (incf lf-count))))
    ;; Build byte array with CRLF
    (let ((bytes (make-array (+ (length string) lf-count)
                             :element-type '(unsigned-byte 8)))
          (j 0))
      (dotimes (i (length string))
        (let ((ch (char string i)))
          (when (char= ch #\newline)
            ;; Add CR before LF if not already there
            (unless (and (plusp i) (char= (char string (1- i)) #\return))
              (setf (aref bytes j) 13)
              (incf j)))
          (setf (aref bytes j) (char-code ch))
          (incf j)))
      (ssh-send-channel-data conn channel-id bytes))))

(defun ssh-send-exit-status (conn channel-id status)
  "Send SSH_MSG_CHANNEL_REQUEST for exit-status."
  (let* ((channel-entry (assoc channel-id (ssh-get conn :channels)))
         (sender-channel (if channel-entry
                             (getf (cdr channel-entry) :sender)
                             channel-id)))
    (let ((msg (ssh-concat
                (vector +ssh-msg-channel-request+)
                (ssh-u32-to-bytes sender-channel)
                (ssh-make-string "exit-status")
                (vector 0)  ; want-reply = false
                (ssh-u32-to-bytes status))))
      (ssh-send-packet conn msg))))

(defun ssh-send-channel-eof (conn channel-id)
  "Send SSH_MSG_CHANNEL_EOF."
  (let* ((channel-entry (assoc channel-id (ssh-get conn :channels)))
         (sender-channel (if channel-entry
                             (getf (cdr channel-entry) :sender)
                             channel-id)))
    (let ((msg (ssh-concat
                (vector +ssh-msg-channel-eof+)
                (ssh-u32-to-bytes sender-channel))))
      (ssh-send-packet conn msg))))

(defun ssh-send-channel-close (conn channel-id)
  "Send SSH_MSG_CHANNEL_CLOSE."
  (let* ((channel-entry (assoc channel-id (ssh-get conn :channels)))
         (sender-channel (if channel-entry
                             (getf (cdr channel-entry) :sender)
                             channel-id)))
    (let ((msg (ssh-concat
                (vector +ssh-msg-channel-close+)
                (ssh-u32-to-bytes sender-channel))))
      (ssh-send-packet conn msg))))

(defun ssh-exec-command (cmd)
  "Execute a command string and return the result as a string."
  ;; Simple command execution - evaluate as Lisp if it looks like it
  ;; Otherwise just echo it back
  (handler-case
      (let* ((trimmed (ssh-trim-string cmd)))
        (cond
          ;; Simple echo command
          ((and (>= (length trimmed) 5)
                (string= (subseq trimmed 0 5) "echo "))
           (concatenate 'string (subseq trimmed 5) (string #\newline)))
          ;; Lisp expression
          ((and (plusp (length trimmed))
                (char= (char trimmed 0) #\())
           (let ((result (eval (read-from-string trimmed))))
             (format nil "~S~%" result)))
          ;; Unknown command
          (t
           (format nil "modus: command not found: ~A~%" trimmed))))
    (error (e)
      (format nil "Error: ~A~%" e))))

;;; SSH REPL

(defvar *ssh-repl-prompt* "SSH> ")

(defun ssh-repl-send-prompt (conn channel-id)
  "Send REPL prompt."
  (ssh-send-string conn channel-id *ssh-repl-prompt*))

(defun bytes-to-string (bytes)
  "Convert byte array to string."
  (let ((str (make-array (length bytes) :element-type 'character)))
    (dotimes (i (length bytes))
      (setf (aref str i) (code-char (aref bytes i))))
    str))

(defun ssh-trim-string (str)
  "Trim whitespace from both ends of string."
  (let* ((len (length str))
         (start 0)
         (end len))
    ;; Find start
    (loop while (and (< start len)
                     (member (char str start) '(#\space #\tab #\newline #\return)))
          do (incf start))
    ;; Find end
    (loop while (and (> end start)
                     (member (char str (1- end)) '(#\space #\tab #\newline #\return)))
          do (decf end))
    (if (>= start end)
        ""
        (subseq str start end))))

(defun ssh-repl-eval (conn channel-id input-string)
  "Evaluate input and send result back."
  (let ((trimmed (ssh-trim-string input-string)))
    (when (plusp (length trimmed))
      ;; Check for special commands
      (cond
        ((or (string= trimmed "exit") (string= trimmed "quit") (string= trimmed "logout"))
         (ssh-send-string conn channel-id "Goodbye!
")
         :exit)
        ((string= trimmed "help")
         (ssh-send-string conn channel-id "Modus SSH REPL
  Type Lisp expressions to evaluate.
  Special commands: exit, quit, logout, help
")
         nil)
        (t
         ;; Try to parse and evaluate
         (handler-case
             (multiple-value-bind (form pos)
                 (muerte::simple-read-from-string trimmed nil nil)
               (declare (ignore pos))
               (handler-case
                   (let ((results (multiple-value-list (eval form))))
                     ;; Format results
                     (if results
                         (dolist (r results)
                           (let ((result-str (format nil "~S~%" r)))
                             (ssh-send-string conn channel-id result-str)))
                         (ssh-send-string conn channel-id "NIL
")))
                 (error (e)
                   (let ((err-str (format nil "Error: ~A~%" e)))
                     (ssh-send-string conn channel-id err-str)))))
           (error (e)
             (let ((err-str (format nil "Read error: ~A~%" e)))
               (ssh-send-string conn channel-id err-str))))
         nil)))))

(defun ssh-find-line-end (str)
  "Find position of first CR or LF in string, or NIL if none."
  (let ((cr-pos (position #\return str))
        (lf-pos (position #\newline str)))
    (cond
      ((and cr-pos lf-pos) (min cr-pos lf-pos))
      (cr-pos cr-pos)
      (lf-pos lf-pos)
      (t nil))))

(defun ssh-skip-line-endings (str pos)
  "Skip past CR, LF, or CRLF at POS, return new position."
  (let ((len (length str)))
    (if (>= pos len)
        pos
        (let ((ch (char str pos)))
          (cond
            ;; CR+LF
            ((and (char= ch #\return)
                  (< (1+ pos) len)
                  (char= (char str (1+ pos)) #\newline))
             (+ pos 2))
            ;; Just CR or just LF
            ((or (char= ch #\return) (char= ch #\newline))
             (1+ pos))
            (t pos))))))

(defun ssh-crlf-echo (data)
  "Convert CR to CRLF in byte array for proper terminal echo.
   Terminals expect CRLF to move cursor down and to start of line."
  (let* ((cr-count 0))
    ;; Count CRs that aren't followed by LF
    (dotimes (i (length data))
      (when (= (aref data i) 13)  ; CR
        (unless (and (< (1+ i) (length data))
                     (= (aref data (1+ i)) 10))  ; not followed by LF
          (incf cr-count))))
    (if (zerop cr-count)
        data  ; No conversion needed
        ;; Build new array with CRLFs
        (let ((result (make-array (+ (length data) cr-count)
                                  :element-type '(unsigned-byte 8)))
              (j 0))
          (dotimes (i (length data))
            (let ((byte (aref data i)))
              (setf (aref result j) byte)
              (incf j)
              ;; Add LF after CR if not already followed by LF
              (when (= byte 13)  ; CR
                (unless (and (< (1+ i) (length data))
                             (= (aref data (1+ i)) 10))
                  (setf (aref result j) 10)  ; LF
                  (incf j)))))
          result))))

(defun ssh-repl-process (conn channel-id data)
  "Process incoming data for REPL. Returns :exit if session should end."
  ;; Check for special characters first
  (when (and (= (length data) 1)
             (let ((byte (aref data 0)))
               (or (= byte 4)    ; Ctrl+D (EOT)
                   (= byte 3)))) ; Ctrl+C
    (ssh-send-string conn channel-id "
Goodbye!
")
    (return-from ssh-repl-process :exit))
  ;; Handle backspace/delete
  (when (and (= (length data) 1)
             (let ((byte (aref data 0)))
               (or (= byte 127)   ; DEL
                   (= byte 8))))  ; Backspace (Ctrl+H)
    (let ((buffer (or (ssh-get conn :repl-buffer) "")))
      (when (plusp (length buffer))
        ;; Remove last character from buffer
        (ssh-set conn :repl-buffer (subseq buffer 0 (1- (length buffer))))
        ;; Send backspace-space-backspace to erase on terminal
        (ssh-send-channel-data conn channel-id #(8 32 8))))
    (return-from ssh-repl-process nil))
  ;; Normal character processing
  (let* ((buffer (or (ssh-get conn :repl-buffer) ""))
         (data-str (bytes-to-string data))
         (new-buffer (concatenate 'string buffer data-str)))
    ;; Echo the input back - convert CR to CRLF for proper terminal behavior
    (let ((echo-data (ssh-crlf-echo data)))
      (ssh-send-channel-data conn channel-id echo-data))
    ;; Check for complete line (ends with CR or LF)
    (let ((line-end-pos (ssh-find-line-end new-buffer)))
      (if line-end-pos
          ;; Process the complete line
          (let* ((line (subseq new-buffer 0 line-end-pos))
                 (after-eol (ssh-skip-line-endings new-buffer line-end-pos))
                 (rest (if (< after-eol (length new-buffer))
                           (subseq new-buffer after-eol)
                           "")))
            (ssh-set conn :repl-buffer rest)
            (let ((result (ssh-repl-eval conn channel-id line)))
              (if (eq result :exit)
                  :exit
                  (progn
                    (ssh-repl-send-prompt conn channel-id)
                    nil))))
          ;; Incomplete line, save buffer
          (progn
            (ssh-set conn :repl-buffer new-buffer)
            nil)))))

;;; Banner / MOTD

(defvar *ssh-banner*
  "
    __  __           _
   |  \\/  | ___   __| |_   _ ___
   | |\\/| |/ _ \\ / _` | | | / __|
   | |  | | (_) | (_| | |_| \\__ \\
   |_|  |_|\\___/ \\__,_|\\__,_|___/

   Welcome to Modus - a bare-metal Lisp OS

"
  "SSH banner displayed before authentication.")

(defun ssh-send-banner (conn)
  "Send SSH_MSG_USERAUTH_BANNER to display MOTD."
  (when *ssh-banner*
    (let ((msg (ssh-concat
                (vector +ssh-msg-userauth-banner+)
                (ssh-make-string *ssh-banner*)
                (ssh-make-string ""))))  ; language tag
      (ssh-send-packet conn msg))))

;;; Authorized Key Management

(defvar *ssh-key-buffer* nil
  "Temporary buffer for building a key in chunks.")

(defun ssh-key-start ()
  "Start building a new authorized key."
  (setf *ssh-key-buffer* (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
  (format t "~&SSH: Started new key buffer~%"))

(defun ssh-key-set (offset &rest bytes)
  "Set bytes in the key buffer at OFFSET. Usage: (ssh-key-set 0 #xc2 #xf1 #xaa #x91)"
  (unless *ssh-key-buffer*
    (ssh-key-start))
  (let ((i offset))
    (dolist (b bytes)
      (when (< i 32)
        (setf (aref *ssh-key-buffer* i) b)
        (incf i))))
  (format t "~&SSH: Set bytes ~D-~D~%" offset (+ offset (length bytes) -1)))

(defun ssh-key-add ()
  "Add the key buffer to authorized keys."
  (if *ssh-key-buffer*
      (progn
        (push *ssh-key-buffer* *ssh-allowed-keys*)
        (format t "~&SSH: Added key: ")
        (dotimes (i 8) (format t "~2,'0X" (aref *ssh-key-buffer* i)))
        (format t "...~%")
        (setf *ssh-key-buffer* nil))
      (format t "~&SSH: No key buffer - call ssh-key-start first~%")))

(defun ssh-allow-key (key-string)
  "Add a public key to the authorized keys list.
   KEY-STRING should be 64-character hex string."
  ;; For simplicity, expect raw 32-byte hex
  (let ((key (if (= (length key-string) 64)
                 ;; Hex encoded
                 (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
                   (dotimes (i 32)
                     (setf (aref result i)
                           (parse-integer key-string :start (* i 2) :end (+ (* i 2) 2)
                                          :radix 16)))
                   result)
                 ;; Assume it's the key directly
                 key-string)))
    (push key *ssh-allowed-keys*)
    (format t "~&SSH: Added authorized key~%")))

(defun ssh-clear-keys ()
  "Clear all authorized keys."
  (setf *ssh-allowed-keys* nil)
  (setf *ssh-key-buffer* nil)
  (format t "~&SSH: Cleared authorized keys~%"))

;;; Host Key Generation

(defun ssh-generate-host-key ()
  "Generate a new Ed25519 host key pair."
  (let ((keypair (ed25519-keypair)))
    (setf *ssh-host-private-key* (car keypair))
    (setf *ssh-host-public-key* (cdr keypair))
    (format t "~&SSH: Generated host key~%")
    keypair))

(defun ssh-fingerprint (pubkey)
  "Compute SHA-256 fingerprint of public key."
  (let* ((encoded (ssh-concat
                   (ssh-make-string "ssh-ed25519")
                   (ssh-make-string pubkey)))
         (hash (sha256 encoded))
         (result (make-array 43 :element-type 'character :initial-element #\=)))
    ;; Base64 encode (simplified)
    (let ((b64-chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
          (pos 0))
      (loop for i from 0 below 32 by 3
            for b1 = (aref hash i)
            for b2 = (if (< (1+ i) 32) (aref hash (1+ i)) 0)
            for b3 = (if (< (+ i 2) 32) (aref hash (+ i 2)) 0)
            do (setf (aref result pos) (aref b64-chars (ash b1 -2)))
               (incf pos)
               (setf (aref result pos) (aref b64-chars (logior (ash (logand b1 3) 4) (ash b2 -4))))
               (incf pos)
               (when (< (1+ i) 32)
                 (setf (aref result pos) (aref b64-chars (logior (ash (logand b2 15) 2) (ash b3 -6))))
                 (incf pos))
               (when (< (+ i 2) 32)
                 (setf (aref result pos) (aref b64-chars (logand b3 63)))
                 (incf pos))))
    (format nil "SHA256:~A" result)))

;;; Main Server Loop

(defun ssh-server (&key (port 22) host-key)
  "Start SSH server on PORT.
   HOST-KEY should be a 32-byte Ed25519 private key, or NIL to generate one."
  (format t "~&SSH: Starting server on port ~D~%" port)

  ;; Set up host key
  (if host-key
      (progn
        (setf *ssh-host-private-key* host-key)
        (setf *ssh-host-public-key* (ed25519-public-key host-key)))
      (ssh-generate-host-key))

  (format t "~&SSH: Host key fingerprint: ~A~%"
          (ssh-fingerprint *ssh-host-public-key*))

  ;; Start listening
  (let ((listener (muerte.x86-pc.e1000::tcp-listen port)))
    (unwind-protect
        (loop
          (format t "~&SSH: Waiting for connection...~%")
          (let ((tcp-conn (muerte.x86-pc.e1000::tcp-accept listener :timeout 120)))
            (if tcp-conn
                (progn
                  (format t "~&SSH: Connection accepted~%")
                  (ssh-handle-connection tcp-conn))
                (format t "~&SSH: Accept timeout~%"))))
      (muerte.x86-pc.e1000::tcp-listener-close listener))))

(defun ssh-handle-connection (tcp-conn)
  "Handle a single SSH connection."
  (let ((conn (make-ssh-connection tcp-conn)))
    (unwind-protect
        (block connection-block
          ;; Version exchange
          (ssh-send-version conn)
          (unless (ssh-receive-version conn)
            (return-from connection-block))

          ;; Key exchange
          (ssh-send-kexinit conn)
          (unless (ssh-receive-kexinit conn)
            (return-from connection-block))

          ;; Wait for KEX_ECDH_INIT
          (let ((payload (ssh-receive-packet conn)))
            (unless (and payload (= (aref payload 0) +ssh-msg-kex-ecdh-init+))
              (when *ssh-verbose*
                (format t "~&SSH: Expected KEX_ECDH_INIT~%"))
              (return-from connection-block))
            (unless (ssh-handle-kex-ecdh-init conn payload)
              (return-from connection-block)))

          ;; NEWKEYS exchange
          (ssh-send-newkeys conn)
          (unless (ssh-receive-newkeys conn)
            (return-from connection-block))

          ;; Derive keys and enable encryption
          (ssh-derive-keys conn)

          ;; Main message loop
          (loop
            (let ((payload (ssh-receive-packet conn :timeout 60)))
              (unless payload
                (when *ssh-verbose*
                  (format t "~&SSH: Connection timeout~%"))
                (return-from connection-block))
              (let ((msg-type (aref payload 0)))
                (cond
                  ((= msg-type +ssh-msg-service-request+)
                   (ssh-handle-service-request conn payload))
                  ((= msg-type +ssh-msg-userauth-request+)
                   (ssh-handle-userauth-request conn payload))
                  ((= msg-type +ssh-msg-channel-open+)
                   (ssh-handle-channel-open conn payload))
                  ((= msg-type +ssh-msg-channel-request+)
                   (ssh-handle-channel-request conn payload))
                  ((= msg-type +ssh-msg-channel-data+)
                   (let ((data (ssh-handle-channel-data conn payload)))
                     ;; Process through REPL
                     (when (eq (ssh-repl-process conn 0 data) :exit)
                       (return-from connection-block))))
                  ((= msg-type +ssh-msg-channel-eof+)
                   (when *ssh-verbose*
                     (format t "~&SSH: Channel EOF~%")))
                  ((= msg-type +ssh-msg-channel-close+)
                   (when *ssh-verbose*
                     (format t "~&SSH: Channel close~%"))
                   (return-from connection-block))
                  ((= msg-type +ssh-msg-disconnect+)
                   (when *ssh-verbose*
                     (format t "~&SSH: Client disconnected~%"))
                   (return-from connection-block))
                  ((= msg-type +ssh-msg-ignore+)
                   ;; Ignore message
                   nil)
                  (t
                   (when *ssh-verbose*
                     (format t "~&SSH: Unknown message type ~D~%" msg-type))))))))
      ;; Cleanup
      (muerte.x86-pc.e1000::tcp-close tcp-conn)
      (when *ssh-verbose*
        (format t "~&SSH: Connection closed~%")))))

;;; Test function
(defun ssh-test ()
  "Test SSH server functionality."
  (format t "~&SSH server test~%")

  ;; Initialize Ed25519
  (ed25519-init)

  ;; Generate host key
  (ssh-generate-host-key)
  (format t "~&Host key fingerprint: ~A~%"
          (ssh-fingerprint *ssh-host-public-key*))

  ;; Test key encoding
  (let ((encoded (ssh-encode-host-key)))
    (format t "~&Encoded host key: ~D bytes~%" (length encoded)))

  (format t "~&SSH test complete~%")
  t)

;;; Default authorized key (generated for testing)
;;; ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMLxqpGoutPcGmkNyALh3qiS7BAQNi1OZiqxOCU3CCwv
(defvar *ssh-default-pubkey*
  (make-array 32 :element-type '(unsigned-byte 8)
              :initial-contents
              '(#xc2 #xf1 #xaa #x91 #xa8 #xba #xd3 #xdc
                #x1a #x69 #x0d #xc8 #x02 #xe1 #xde #xa8
                #x92 #xec #x10 #x10 #x36 #x2d #x4e #x66
                #x2a #xb1 #x38 #x25 #x37 #x08 #x2c #x2f))
  "Default authorized Ed25519 public key for testing")

(defun ssh-use-default-key ()
  "Add the built-in test key to authorized keys."
  (push *ssh-default-pubkey* *ssh-allowed-keys*)
  (format t "~&Added default test key~%")
  t)

(defun ssh-show-keys ()
  "Show all authorized public keys."
  (if (null *ssh-allowed-keys*)
      (format t "~&No authorized keys configured~%")
      (let ((n 0))
        (dolist (key *ssh-allowed-keys*)
          (format t "~&Key ~D: " n)
          (dotimes (i (min 8 (length key)))
            (format t "~2,'0X" (aref key i)))
          (format t "...~%")
          (incf n))))
  t)

(defun ssh-init ()
  "Initialize SSH server (generates host key, does NOT add authorized keys)."
  (format t "~&SSH: Initializing Ed25519...")
  (multiple-value-bind (t0-lo t0-hi) (read-time-stamp-counter)
    (ed25519-init)
    (multiple-value-bind (t1-lo t1-hi) (read-time-stamp-counter)
      (format t " ~D cycles~%" (+ (- t1-lo t0-lo) (* (- t1-hi t0-hi) 536870912)))))

  (format t "~&SSH: Generating host key...")
  (multiple-value-bind (t0-lo t0-hi) (read-time-stamp-counter)
    (ssh-generate-host-key)
    (multiple-value-bind (t1-lo t1-hi) (read-time-stamp-counter)
      (format t " ~D cycles~%" (+ (- t1-lo t0-lo) (* (- t1-hi t0-hi) 536870912)))))

  (format t "~&SSH initialized~%")
  (format t "~&Host key fingerprint: ~A~%"
          (ssh-fingerprint *ssh-host-public-key*))
  (format t "~&~%To add authorized keys via serial:~%")
  (format t "~&  (ssh-use-default-key)     ; Add built-in test key~%")
  (format t "~&  (ssh-clear-keys)          ; Clear all keys~%")
  (format t "~&  (ssh-show-keys)           ; List authorized keys~%")
  (format t "~&  (ssh-key-start)           ; Start adding custom key~%")
  (format t "~&  (ssh-key-set 0 #xAA ...)  ; Set key bytes~%")
  (format t "~&  (ssh-key-add)             ; Finish adding key~%")
  t)

(defun ssh-start (&key (port 2222))
  "Initialize and start SSH server on PORT."
  (ssh-init)
  (ssh-server :port port))
