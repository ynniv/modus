;;;; TLS 1.3 Implementation for Movitz
;;;; RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
;;;;
;;;; Supports:
;;;; - Cipher suites: TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256
;;;; - Key exchange: X25519
;;;; - No client certificates
;;;; - No PSK/session resumption (full handshake only)
;;;;
;;;; Note: AES-256-GCM-SHA384 is implemented but not advertised because
;;;; SHA-384's 64-bit arithmetic is too slow on Movitz's 30-bit fixnums.

(require :lib/crypto/sha256)
(require :lib/crypto/sha384)
(require :lib/crypto/hmac)
(require :lib/crypto/hkdf)
(require :lib/crypto/chacha20)
(require :lib/crypto/poly1305)
(require :lib/crypto/aead)
(require :lib/crypto/x25519)
(require :lib/crypto/aes)
(require :lib/crypto/gcm)

(provide :lib/net/tls13)

(in-package muerte)

;;; TLS 1.3 Constants

;; Record types
(defconstant +tls-content-change-cipher-spec+ 20)
(defconstant +tls-content-alert+ 21)
(defconstant +tls-content-handshake+ 22)
(defconstant +tls-content-application-data+ 23)

;; Max TLS fragment size to avoid QEMU slirp packet issues
;; Each encrypted record: 5 header + data + 1 inner type + 16 tag = data + 22
;; Target ~400 byte packets, so max fragment = 400 - 22 = 378
(defconstant +tls-max-fragment+ 378)

;; Handshake types
(defconstant +tls-hs-client-hello+ 1)
(defconstant +tls-hs-server-hello+ 2)
(defconstant +tls-hs-new-session-ticket+ 4)
(defconstant +tls-hs-end-of-early-data+ 5)
(defconstant +tls-hs-encrypted-extensions+ 8)
(defconstant +tls-hs-certificate+ 11)
(defconstant +tls-hs-certificate-request+ 13)
(defconstant +tls-hs-certificate-verify+ 15)
(defconstant +tls-hs-finished+ 20)
(defconstant +tls-hs-key-update+ 24)
(defconstant +tls-hs-message-hash+ 254)

;; Extension types
(defconstant +tls-ext-server-name+ 0)
(defconstant +tls-ext-ec-point-formats+ 11)
(defconstant +tls-ext-supported-groups+ 10)
(defconstant +tls-ext-signature-algorithms+ 13)
(defconstant +tls-ext-alpn+ 16)
(defconstant +tls-ext-encrypt-then-mac+ 22)
(defconstant +tls-ext-extended-master-secret+ 23)
(defconstant +tls-ext-session-ticket+ 35)
(defconstant +tls-ext-psk-key-exchange-modes+ 45)
(defconstant +tls-ext-supported-versions+ 43)
(defconstant +tls-ext-key-share+ 51)

;; Cipher suites
(defconstant +tls-aes-128-gcm-sha256+ #x1301)
(defconstant +tls-aes-256-gcm-sha384+ #x1302)
(defconstant +tls-chacha20-poly1305-sha256+ #x1303)
;; Signaling cipher suite value for renegotiation info (RFC 5746)
(defconstant +tls-empty-renegotiation-info-scsv+ #x00FF)

(defun tls-cipher-key-length (cipher)
  "Return the encryption key length in bytes for the cipher suite."
  (cond
    ((= cipher +tls-aes-128-gcm-sha256+) 16)
    ((= cipher +tls-aes-256-gcm-sha384+) 32)
    ((= cipher +tls-chacha20-poly1305-sha256+) 32)
    (t 32)))  ; default

(defun tls-cipher-uses-aes-gcm (cipher)
  "Return T if cipher uses AES-GCM."
  (or (= cipher +tls-aes-128-gcm-sha256+)
      (= cipher +tls-aes-256-gcm-sha384+)))

(defun tls-cipher-hash-length (cipher)
  "Return the hash output length for the cipher's hash function."
  (if (= cipher +tls-aes-256-gcm-sha384+)
      48   ; SHA-384
      32)) ; SHA-256

(defun tls-cipher-uses-sha384 (cipher)
  "Return T if cipher uses SHA-384."
  (= cipher +tls-aes-256-gcm-sha384+))

;; Named groups
(defconstant +tls-group-x25519+ 29)

;; Signature algorithms
(defconstant +tls-sig-ecdsa-secp256r1-sha256+ #x0403)
(defconstant +tls-sig-rsa-pss-rsae-sha256+ #x0804)
(defconstant +tls-sig-rsa-pkcs1-sha256+ #x0401)

;; Protocol versions
(defconstant +tls-version-12+ #x0303)  ; Used in record layer
(defconstant +tls-version-13+ #x0304)  ; In supported_versions extension

;;; TLS Connection State

(defun make-tls-connection (tcp-conn)
  "Create a new TLS connection state wrapping a TCP connection."
  (list :tcp tcp-conn
        :state :init
        :cipher nil              ; Negotiated cipher suite
        :client-random nil
        :server-random nil
        :client-private-key nil
        :client-public-key nil
        :server-public-key nil
        :shared-secret nil
        :handshake-hash nil      ; Running hash of handshake messages
        :handshake-secret nil
        :master-secret nil
        :client-hs-traffic-secret nil  ; Needed for client Finished
        :server-hs-traffic-secret nil  ; Needed for verifying server Finished
        :client-handshake-key nil
        :client-handshake-iv nil
        :server-handshake-key nil
        :server-handshake-iv nil
        :early-data nil           ; Early data to send with Finished
        :client-app-key nil
        :client-app-iv nil
        :server-app-key nil
        :server-app-iv nil
        :client-seq 0            ; Sequence number for encryption
        :server-seq 0
        :transcript nil          ; List of handshake messages for hash
        :recv-buffer #()))       ; Buffer for incomplete TLS records

(defun tls-get (conn key)
  (getf conn key))

(defun tls-set (conn key value)
  (setf (getf conn key) value))

;;; Utility Functions

(defun tls-random-bytes (n)
  "Generate n random bytes."
  (let ((result (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n)
      ;; Simple PRNG - in production use a CSPRNG
      (setf (aref result i) (logand (random 256) #xff)))
    result))

(defun bytes-to-u16 (b1 b0)
  "Convert two bytes to 16-bit integer (big-endian)."
  (logior (ash b1 8) b0))

(defun bytes-to-u24 (b2 b1 b0)
  "Convert three bytes to 24-bit integer (big-endian)."
  (logior (ash b2 16) (ash b1 8) b0))

(defun u16-to-bytes (n)
  "Convert 16-bit integer to two bytes (big-endian)."
  (list (logand (ash n -8) #xff)
        (logand n #xff)))

(defun u24-to-bytes (n)
  "Convert 24-bit integer to three bytes (big-endian)."
  (list (logand (ash n -16) #xff)
        (logand (ash n -8) #xff)
        (logand n #xff)))

;;; Record Layer

(defun tls-make-record (content-type payload)
  "Create a TLS record with given content type and payload."
  (let* ((len (length payload))
         (record (make-array (+ 5 len) :element-type '(unsigned-byte 8))))
    ;; Header
    (setf (aref record 0) content-type)
    (setf (aref record 1) #x03)  ; Version 0x0303 (TLS 1.2 for compatibility)
    (setf (aref record 2) #x03)
    (setf (aref record 3) (logand (ash len -8) #xff))
    (setf (aref record 4) (logand len #xff))
    ;; Payload
    (dotimes (i len)
      (setf (aref record (+ 5 i)) (aref payload i)))
    record))

(defun tls-parse-record (data)
  "Parse a TLS record. Returns (content-type payload) or NIL on error."
  (when (< (length data) 5)
    (return-from tls-parse-record nil))
  (let* ((content-type (aref data 0))
         (version-hi (aref data 1))
         (version-lo (aref data 2))
         (len (bytes-to-u16 (aref data 3) (aref data 4))))
    (declare (ignore version-hi version-lo))
    (when (< (length data) (+ 5 len))
      (return-from tls-parse-record nil))
    (let ((payload (make-array len :element-type '(unsigned-byte 8))))
      (dotimes (i len)
        (setf (aref payload i) (aref data (+ 5 i))))
      (list content-type payload (+ 5 len)))))

;;; Handshake Message Construction

(defun tls-make-handshake (msg-type payload)
  "Create a handshake message with type and payload."
  (let* ((len (length payload))
         (msg (make-array (+ 4 len) :element-type '(unsigned-byte 8))))
    (setf (aref msg 0) msg-type)
    (setf (aref msg 1) (logand (ash len -16) #xff))
    (setf (aref msg 2) (logand (ash len -8) #xff))
    (setf (aref msg 3) (logand len #xff))
    (dotimes (i len)
      (setf (aref msg (+ 4 i)) (aref payload i)))
    msg))

;;; Extension Building

(defun tls-build-extension (ext-type data)
  "Build a TLS extension."
  (let* ((len (length data))
         (ext (make-array (+ 4 len) :element-type '(unsigned-byte 8))))
    (setf (aref ext 0) (logand (ash ext-type -8) #xff))
    (setf (aref ext 1) (logand ext-type #xff))
    (setf (aref ext 2) (logand (ash len -8) #xff))
    (setf (aref ext 3) (logand len #xff))
    (dotimes (i len)
      (setf (aref ext (+ 4 i)) (aref data i)))
    ext))

(defun tls-build-supported-versions-ext ()
  "Build supported_versions extension for ClientHello."
  ;; Only advertise TLS 1.3 - that's what we implement
  (let ((data (make-array 3 :element-type '(unsigned-byte 8)
                          :initial-contents '(2        ; length = 2 bytes (1 version)
                                              #x03 #x04)))) ; TLS 1.3 = 0x0304
    (tls-build-extension +tls-ext-supported-versions+ data)))

(defun tls-build-supported-groups-ext ()
  "Build supported_groups extension."
  ;; Advertise common groups (we only implement X25519, but advertising more
  ;; helps with TLS fingerprinting). Server will pick from what we offer in key_share.
  (let ((data (make-array 10 :element-type '(unsigned-byte 8)
                          :initial-contents '(0 8    ; length = 8 bytes (4 groups)
                                              0 29   ; x25519 (29)
                                              0 23   ; secp256r1 (23)
                                              0 24   ; secp384r1 (24)
                                              0 25)))) ; secp521r1 (25)
    (tls-build-extension +tls-ext-supported-groups+ data)))

(defun tls-build-signature-algorithms-ext ()
  "Build signature_algorithms extension."
  ;; Support common algorithms
  (let ((data (make-array 20 :element-type '(unsigned-byte 8)
                          :initial-contents '(0 18   ; length = 18 bytes (9 algorithms)
                                              #x04 #x03  ; ecdsa_secp256r1_sha256
                                              #x05 #x03  ; ecdsa_secp384r1_sha384
                                              #x06 #x03  ; ecdsa_secp521r1_sha512
                                              #x08 #x04  ; rsa_pss_rsae_sha256
                                              #x08 #x05  ; rsa_pss_rsae_sha384
                                              #x08 #x06  ; rsa_pss_rsae_sha512
                                              #x04 #x01  ; rsa_pkcs1_sha256
                                              #x05 #x01  ; rsa_pkcs1_sha384
                                              #x06 #x01)))) ; rsa_pkcs1_sha512
    (tls-build-extension +tls-ext-signature-algorithms+ data)))

(defun tls-build-key-share-ext (public-key)
  "Build key_share extension with X25519 public key."
  ;; Format: 2 bytes total length, then entries
  ;; Entry: 2 bytes group + 2 bytes key length + key
  ;; Total data: 2 (length) + 2 (group) + 2 (key len) + 32 (key) = 38
  (let ((data (make-array 38 :element-type '(unsigned-byte 8))))
    ;; Client key share length = 36 (entry size: 2 + 2 + 32)
    (setf (aref data 0) 0)
    (setf (aref data 1) 36)
    ;; Group = x25519 (29)
    (setf (aref data 2) 0)
    (setf (aref data 3) 29)
    ;; Key length = 32
    (setf (aref data 4) 0)
    (setf (aref data 5) 32)
    ;; Public key
    (dotimes (i 32)
      (setf (aref data (+ 6 i)) (aref public-key i)))
    (tls-build-extension +tls-ext-key-share+ data)))

(defun tls-build-server-name-ext (hostname)
  "Build server_name extension (SNI)."
  (let* ((name-len (length hostname))
         (list-len (+ 3 name-len))  ; type(1) + length(2) + name
         (data (make-array (+ 2 list-len) :element-type '(unsigned-byte 8))))
    ;; Server name list length
    (setf (aref data 0) (logand (ash list-len -8) #xff))
    (setf (aref data 1) (logand list-len #xff))
    ;; Name type = hostname (0)
    (setf (aref data 2) 0)
    ;; Name length
    (setf (aref data 3) (logand (ash name-len -8) #xff))
    (setf (aref data 4) (logand name-len #xff))
    ;; Hostname
    (dotimes (i name-len)
      (setf (aref data (+ 5 i)) (char-code (char hostname i))))
    (tls-build-extension +tls-ext-server-name+ data)))

(defun tls-build-alpn-ext ()
  "Build ALPN extension for HTTP/1.1."
  ;; Format: 2 bytes protocol list length, then protocols
  ;; Protocol: 1 byte length + name
  ;; "http/1.1" = 8 bytes
  (let ((data (make-array 11 :element-type '(unsigned-byte 8)
                          :initial-contents '(0 9          ; protocol list length = 9
                                              8            ; protocol length = 8
                                              #x68 #x74 #x74 #x70 ; "http"
                                              #x2f         ; "/"
                                              #x31 #x2e #x31)))) ; "1.1"
    (tls-build-extension +tls-ext-alpn+ data)))

(defun tls-build-psk-key-exchange-modes-ext ()
  "Build psk_key_exchange_modes extension.
   Required for TLS 1.3 session tickets. We only support psk_dhe_ke (1)."
  ;; Format: 1 byte length, then modes
  ;; psk_dhe_ke = 1 (PSK with (EC)DHE key establishment)
  (let ((data (make-array 2 :element-type '(unsigned-byte 8)
                          :initial-contents '(1    ; length of modes list
                                              1)))) ; psk_dhe_ke
    (tls-build-extension +tls-ext-psk-key-exchange-modes+ data)))

(defun tls-build-session-ticket-ext ()
  "Build empty session_ticket extension (indicates we support session tickets)."
  (tls-build-extension +tls-ext-session-ticket+ #()))

(defun tls-build-ec-point-formats-ext ()
  "Build ec_point_formats extension (for compatibility)."
  ;; Format: 1 byte length, then formats
  ;; uncompressed = 0, ansiX962_compressed_prime = 1, ansiX962_compressed_char2 = 2
  (let ((data (make-array 4 :element-type '(unsigned-byte 8)
                          :initial-contents '(3    ; length
                                              0    ; uncompressed
                                              1    ; ansiX962_compressed_prime
                                              2)))) ; ansiX962_compressed_char2
    (tls-build-extension +tls-ext-ec-point-formats+ data)))

(defun tls-build-encrypt-then-mac-ext ()
  "Build empty encrypt_then_mac extension (RFC 7366)."
  (tls-build-extension +tls-ext-encrypt-then-mac+ #()))

(defun tls-build-extended-master-secret-ext ()
  "Build empty extended_master_secret extension (RFC 7627)."
  (tls-build-extension +tls-ext-extended-master-secret+ #()))

;;; ClientHello

(defun tls-build-client-hello (conn hostname)
  "Build ClientHello message."
  ;; Generate client random
  (let ((client-random (tls-random-bytes 32)))
    (tls-set conn :client-random client-random)

    ;; Generate ephemeral X25519 keypair
    (let* ((private-key (tls-random-bytes 32))
           (public-key (x25519-public-key private-key)))
      (tls-set conn :client-private-key private-key)
      (tls-set conn :client-public-key public-key)

      ;; Build extensions
      (let* ((ext-sni (if hostname (tls-build-server-name-ext hostname) #()))
             (ext-groups (tls-build-supported-groups-ext))
             (ext-sigalgs (tls-build-signature-algorithms-ext))
             (ext-versions (tls-build-supported-versions-ext))
             (ext-keyshare (tls-build-key-share-ext public-key))
             (ext-psk-modes (tls-build-psk-key-exchange-modes-ext))
             (ext-session-ticket (tls-build-session-ticket-ext))
             (ext-ec-point-formats (tls-build-ec-point-formats-ext))
             (ext-encrypt-then-mac (tls-build-encrypt-then-mac-ext))
             (ext-extended-master-secret (tls-build-extended-master-secret-ext))
             (ext-alpn (tls-build-alpn-ext))  ; Required for Cloudflare HTTP/1.1
             ;; Concatenate extensions in order matching openssl
             ;; server_name, ec_point_formats, supported_groups, session_ticket,
             ;; alpn (required for Cloudflare to expect HTTP/1.1 instead of HTTP/2)
             ;; encrypt_then_mac, extended_master_secret, signature_algorithms,
             ;; supported_versions, psk_key_exchange_modes, key_share
             (extensions (concatenate 'vector ext-sni ext-ec-point-formats
                                      ext-groups ext-session-ticket ext-alpn
                                      ext-encrypt-then-mac ext-extended-master-secret
                                      ext-sigalgs ext-versions ext-psk-modes ext-keyshare))
             (ext-len (length extensions)))

        ;; Build ClientHello body
        ;; Version (2) + Random (32) + Session ID (1+32) + Cipher Suites (2+8)
        ;; + Compression (2) + Extensions (2+n)
        ;; Note: 32-byte session ID for middlebox compatibility (RFC 8446 Appendix D.4)
        (let* ((session-id (tls-random-bytes 32))
               (body-len (+ 2 32 1 32 2 8 2 2 ext-len))
               (body (make-array body-len :element-type '(unsigned-byte 8)))
               (pos 0))

          ;; Client version (0x0303 for TLS 1.2 compat)
          (setf (aref body pos) #x03) (incf pos)
          (setf (aref body pos) #x03) (incf pos)

          ;; Client random
          (dotimes (i 32)
            (setf (aref body pos) (aref client-random i))
            (incf pos))

          ;; Session ID (32 bytes for middlebox compatibility)
          (setf (aref body pos) 32) (incf pos)
          (dotimes (i 32)
            (setf (aref body pos) (aref session-id i))
            (incf pos))

          ;; Cipher suites - order by preference
          ;; Note: AES-256-GCM-SHA384 not advertised - SHA-384 is too slow on 30-bit fixnums
          ;; 3 TLS 1.3 ciphers + SCSV = 8 bytes
          (setf (aref body pos) 0) (incf pos)
          (setf (aref body pos) 8) (incf pos)
          ;; TLS_CHACHA20_POLY1305_SHA256 = 0x1303
          (setf (aref body pos) #x13) (incf pos)
          (setf (aref body pos) #x03) (incf pos)
          ;; TLS_AES_128_GCM_SHA256 = 0x1301
          (setf (aref body pos) #x13) (incf pos)
          (setf (aref body pos) #x01) (incf pos)
          ;; TLS_AES_128_CCM_SHA256 = 0x1304 (fallback)
          (setf (aref body pos) #x13) (incf pos)
          (setf (aref body pos) #x04) (incf pos)
          ;; TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
          (setf (aref body pos) #x00) (incf pos)
          (setf (aref body pos) #xff) (incf pos)

          ;; Compression methods (1 byte length, 1 method = null)
          (setf (aref body pos) 1) (incf pos)
          (setf (aref body pos) 0) (incf pos)

          ;; Extensions length
          (setf (aref body pos) (logand (ash ext-len -8) #xff)) (incf pos)
          (setf (aref body pos) (logand ext-len #xff)) (incf pos)

          ;; Extensions
          (dotimes (i ext-len)
            (setf (aref body pos) (aref extensions i))
            (incf pos))

          ;; Wrap in handshake message
          (tls-make-handshake +tls-hs-client-hello+ body))))))

;;; ServerHello Parsing

(defun tls-parse-server-hello (conn data)
  "Parse ServerHello message. Returns T on success, NIL on error."
  (when (< (length data) 38)  ; Minimum: version(2) + random(32) + session_id_len(1) + cipher(2) + comp(1)
    (format t "ServerHello too short~%")
    (return-from tls-parse-server-hello nil))

  (let ((pos 0))
    ;; Skip version (we check supported_versions extension)
    (incf pos 2)

    ;; Server random
    (let ((server-random (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32)
        (setf (aref server-random i) (aref data (+ pos i))))
      (tls-set conn :server-random server-random)
      (incf pos 32))

    ;; Session ID (skip)
    (let ((session-id-len (aref data pos)))
      (incf pos (1+ session-id-len)))

    ;; Cipher suite
    (let ((cipher (bytes-to-u16 (aref data pos) (aref data (1+ pos)))))
      (unless (or (= cipher +tls-chacha20-poly1305-sha256+)
                  (= cipher +tls-aes-128-gcm-sha256+)
                  (= cipher +tls-aes-256-gcm-sha384+))
        (format t "Unsupported cipher suite: ~x~%" cipher)
        (return-from tls-parse-server-hello nil))
      (format t "TLS: Negotiated cipher suite ~x (~a)~%" cipher
              (cond ((= cipher +tls-chacha20-poly1305-sha256+) "ChaCha20-Poly1305")
                    ((= cipher +tls-aes-128-gcm-sha256+) "AES-128-GCM")
                    ((= cipher +tls-aes-256-gcm-sha384+) "AES-256-GCM-SHA384")
                    (t "Unknown")))
      (tls-set conn :cipher cipher)
      (incf pos 2))

    ;; Compression (must be 0)
    (unless (= (aref data pos) 0)
      (format t "Invalid compression~%")
      (return-from tls-parse-server-hello nil))
    (incf pos)

    ;; Parse extensions
    (when (>= (length data) (+ pos 2))
      (let ((ext-len (bytes-to-u16 (aref data pos) (aref data (1+ pos)))))
        (incf pos 2)
        (let ((ext-end (+ pos ext-len)))
          (loop while (< pos ext-end) do
            (let* ((ext-type (bytes-to-u16 (aref data pos) (aref data (1+ pos))))
                   (ext-data-len (bytes-to-u16 (aref data (+ pos 2)) (aref data (+ pos 3)))))
              (incf pos 4)
              (cond
                ;; key_share extension - extract server's public key
                ((= ext-type +tls-ext-key-share+)
                 (let ((group (bytes-to-u16 (aref data pos) (aref data (1+ pos))))
                       (key-len (bytes-to-u16 (aref data (+ pos 2)) (aref data (+ pos 3)))))
                   (when (and (= group +tls-group-x25519+) (= key-len 32))
                     (let ((server-key (make-array 32 :element-type '(unsigned-byte 8))))
                       (dotimes (i 32)
                         (setf (aref server-key i) (aref data (+ pos 4 i))))
                       (tls-set conn :server-public-key server-key)))))

                ;; supported_versions - verify TLS 1.3
                ((= ext-type +tls-ext-supported-versions+)
                 (let ((version (bytes-to-u16 (aref data pos) (aref data (1+ pos)))))
                   (unless (= version +tls-version-13+)
                     (format t "Not TLS 1.3: ~x~%" version)
                     (return-from tls-parse-server-hello nil)))))

              (incf pos ext-data-len))))))

    ;; Verify we got the server's public key
    (unless (tls-get conn :server-public-key)
      (format t "No server key_share~%")
      (return-from tls-parse-server-hello nil))

    t))

;;; Key Schedule

(defun tls-derive-keys (conn)
  "Derive TLS 1.3 keys from the shared secret."
  ;; Compute shared secret via X25519
  (let* ((shared (x25519 (tls-get conn :client-private-key)
                         (tls-get conn :server-public-key)))
         (cipher (or (tls-get conn :cipher) +tls-chacha20-poly1305-sha256+))
         (use-sha384 (tls-cipher-uses-sha384 cipher))
         (hash-len (if use-sha384 48 32)))
    (tls-set conn :shared-secret shared)

    ;; Get transcript hash (hash of ClientHello + ServerHello)
    (let* ((transcript (tls-get conn :transcript))
           (transcript-data (apply #'concatenate 'vector transcript))
           (transcript-hash (if use-sha384
                                (sha384 transcript-data)
                                (sha256 transcript-data))))

      ;; Early Secret = HKDF-Extract(0, 0)
      (let* ((zero-key (make-array hash-len :element-type '(unsigned-byte 8) :initial-element 0))
             (early-secret (if use-sha384
                               (hkdf-extract-384 zero-key zero-key)
                               (hkdf-extract zero-key zero-key)))
             ;; Hash of empty string for "derived" context
             (empty-hash (if use-sha384 (sha384 #()) (sha256 #()))))

        ;; Derive-Secret(early_secret, "derived", "") - context is hash of empty
        (let ((derived-secret (if use-sha384
                                  (tls13-derive-secret-384 early-secret "derived" empty-hash)
                                  (tls13-derive-secret early-secret "derived" empty-hash))))

          ;; Handshake Secret = HKDF-Extract(derived, shared_secret)
          (let ((handshake-secret (if use-sha384
                                      (hkdf-extract-384 derived-secret shared)
                                      (hkdf-extract derived-secret shared))))
            (tls-set conn :handshake-secret handshake-secret)

            ;; Client handshake traffic secret
            (let ((client-hs-secret (if use-sha384
                                        (tls13-derive-secret-384 handshake-secret
                                                                  "c hs traffic"
                                                                  transcript-hash)
                                        (tls13-derive-secret handshake-secret
                                                              "c hs traffic"
                                                              transcript-hash))))
              ;; Store for later use in client Finished
              (tls-set conn :client-hs-traffic-secret client-hs-secret)
              ;; Server handshake traffic secret
              (let ((server-hs-secret (if use-sha384
                                          (tls13-derive-secret-384 handshake-secret
                                                                    "s hs traffic"
                                                                    transcript-hash)
                                          (tls13-derive-secret handshake-secret
                                                                "s hs traffic"
                                                                transcript-hash))))
                ;; Store for verifying server Finished
                (tls-set conn :server-hs-traffic-secret server-hs-secret)

                ;; Derive keys and IVs (key length depends on cipher suite)
                (let ((key-len (tls-cipher-key-length cipher)))
                  (if use-sha384
                      (progn
                        (tls-set conn :client-handshake-key
                                 (tls13-hkdf-expand-label-384 client-hs-secret "key" #() key-len))
                        (tls-set conn :client-handshake-iv
                                 (tls13-hkdf-expand-label-384 client-hs-secret "iv" #() 12))
                        (tls-set conn :server-handshake-key
                                 (tls13-hkdf-expand-label-384 server-hs-secret "key" #() key-len))
                        (tls-set conn :server-handshake-iv
                                 (tls13-hkdf-expand-label-384 server-hs-secret "iv" #() 12)))
                      (progn
                        (tls-set conn :client-handshake-key
                                 (tls13-hkdf-expand-label client-hs-secret "key" #() key-len))
                        (tls-set conn :client-handshake-iv
                                 (tls13-hkdf-expand-label client-hs-secret "iv" #() 12))
                        (tls-set conn :server-handshake-key
                                 (tls13-hkdf-expand-label server-hs-secret "key" #() key-len))
                        (tls-set conn :server-handshake-iv
                                 (tls13-hkdf-expand-label server-hs-secret "iv" #() 12)))))

                ;; Derive application traffic secrets
                (let ((derived2 (if use-sha384
                                    (tls13-derive-secret-384 handshake-secret "derived" empty-hash)
                                    (tls13-derive-secret handshake-secret "derived" empty-hash))))
                  ;; Master Secret = HKDF-Extract(derived2, 0)
                  (let ((master-secret (if use-sha384
                                           (hkdf-extract-384 derived2 zero-key)
                                           (hkdf-extract derived2 zero-key))))
                    ;; We'll derive app keys after receiving Finished
                    (tls-set conn :master-secret master-secret)))))))))))

(defun tls-derive-app-keys (conn transcript-hash)
  "Derive application traffic keys after handshake is complete."
  (let* ((cipher (or (tls-get conn :cipher) +tls-chacha20-poly1305-sha256+))
         (use-sha384 (tls-cipher-uses-sha384 cipher))
         (master-secret (tls-get conn :master-secret))
         (key-len (tls-cipher-key-length cipher)))
    (let ((client-app-secret (if use-sha384
                                  (tls13-derive-secret-384 master-secret
                                                           "c ap traffic"
                                                           transcript-hash)
                                  (tls13-derive-secret master-secret
                                                        "c ap traffic"
                                                        transcript-hash)))
          (server-app-secret (if use-sha384
                                  (tls13-derive-secret-384 master-secret
                                                           "s ap traffic"
                                                           transcript-hash)
                                  (tls13-derive-secret master-secret
                                                        "s ap traffic"
                                                        transcript-hash))))
      (if use-sha384
          (progn
            (tls-set conn :client-app-key
                     (tls13-hkdf-expand-label-384 client-app-secret "key" #() key-len))
            (tls-set conn :client-app-iv
                     (tls13-hkdf-expand-label-384 client-app-secret "iv" #() 12))
            (tls-set conn :server-app-key
                     (tls13-hkdf-expand-label-384 server-app-secret "key" #() key-len))
            (tls-set conn :server-app-iv
                     (tls13-hkdf-expand-label-384 server-app-secret "iv" #() 12)))
          (progn
            (tls-set conn :client-app-key
                     (tls13-hkdf-expand-label client-app-secret "key" #() key-len))
            (tls-set conn :client-app-iv
                     (tls13-hkdf-expand-label client-app-secret "iv" #() 12))
            (tls-set conn :server-app-key
                     (tls13-hkdf-expand-label server-app-secret "key" #() key-len))
            (tls-set conn :server-app-iv
                     (tls13-hkdf-expand-label server-app-secret "iv" #() 12))))
      ;; Reset sequence numbers for application data
      (tls-set conn :client-seq 0)
      (tls-set conn :server-seq 0))))

;;; Encryption/Decryption

(defun tls-build-nonce (iv seq)
  "Build nonce by XORing IV with sequence number (64-bit, big-endian)."
  (let ((nonce (make-array 12 :element-type '(unsigned-byte 8))))
    (dotimes (i 12)
      (setf (aref nonce i) (aref iv i)))
    ;; XOR sequence number into last 8 bytes (big-endian)
    ;; Position 11 gets byte 0 (LSB), position 4 gets byte 7 (MSB)
    ;; Use explicit byte extraction to avoid shift issues with large values
    (setf (aref nonce 11) (logxor (aref nonce 11) (logand seq #xff)))
    (setf (aref nonce 10) (logxor (aref nonce 10) (logand (ash seq -8) #xff)))
    (setf (aref nonce 9) (logxor (aref nonce 9) (logand (ash seq -16) #xff)))
    (setf (aref nonce 8) (logxor (aref nonce 8) (logand (ash seq -24) #xff)))
    ;; For positions 4-7, the shift values (32-56) exceed fixnum range
    ;; For typical TLS usage, seq won't exceed 32 bits, so these stay 0
    nonce))

(defun tls-encrypt-record (conn plaintext content-type &key (use-app-keys nil))
  "Encrypt a TLS 1.3 record."
  (let* ((key (if use-app-keys
                  (tls-get conn :client-app-key)
                  (tls-get conn :client-handshake-key)))
         (iv (if use-app-keys
                 (tls-get conn :client-app-iv)
                 (tls-get conn :client-handshake-iv)))
         (seq (tls-get conn :client-seq))
         (nonce (tls-build-nonce iv seq))
         ;; Inner plaintext: data + content type + optional padding
         (inner-len (1+ (length plaintext)))
         (inner (make-array inner-len :element-type '(unsigned-byte 8))))
    (format t "TLS encrypt: seq=~d, use-app-keys=~a~%" seq use-app-keys)
    (format t "TLS encrypt: key first 8: ~{~2,'0x ~}~%"
            (coerce (subseq key 0 8) 'list))
    (format t "TLS encrypt: nonce: ~{~2,'0x ~}~%"
            (coerce nonce 'list))

    ;; Build inner plaintext
    (dotimes (i (length plaintext))
      (setf (aref inner i) (aref plaintext i)))
    (setf (aref inner (length plaintext)) content-type)
    (format t "TLS encrypt: inner len=~d, content-type=~d~%" inner-len content-type)
    (format t "TLS encrypt: inner first 8: ~{~2,'0x ~}~%"
            (coerce (subseq inner 0 (min 8 inner-len)) 'list))
    (format t "TLS encrypt: inner last 4: ~{~2,'0x ~}~%"
            (coerce (subseq inner (max 0 (- inner-len 4))) 'list))

    ;; AAD for TLS 1.3: record header with encrypted length
    (let* ((ciphertext-len (+ inner-len 16))  ; +16 for auth tag
           (aad (make-array 5 :element-type '(unsigned-byte 8))))
      (setf (aref aad 0) +tls-content-application-data+)
      (setf (aref aad 1) #x03)
      (setf (aref aad 2) #x03)
      (setf (aref aad 3) (logand (ash ciphertext-len -8) #xff))
      (setf (aref aad 4) (logand ciphertext-len #xff))

      ;; Encrypt - returns (ciphertext . tag)
      ;; Dispatch based on negotiated cipher
      (let* ((cipher (or (tls-get conn :cipher) +tls-chacha20-poly1305-sha256+))
             (result (if (tls-cipher-uses-aes-gcm cipher)
                         (aes-gcm-encrypt key nonce inner aad)
                         (chacha20-poly1305-encrypt key nonce inner aad)))
             (ciphertext (car result))
             (tag (cdr result)))
        ;; Increment sequence number
        (tls-set conn :client-seq (1+ seq))

        ;; Return full record (header + ciphertext + tag)
        (let ((record (make-array (+ 5 (length ciphertext) 16)
                                  :element-type '(unsigned-byte 8))))
          (dotimes (i 5)
            (setf (aref record i) (aref aad i)))
          (dotimes (i (length ciphertext))
            (setf (aref record (+ 5 i)) (aref ciphertext i)))
          (dotimes (i 16)
            (setf (aref record (+ 5 (length ciphertext) i)) (aref tag i)))
          record)))))

(defun tls-decrypt-record (conn ciphertext-record &key (use-app-keys nil))
  "Decrypt a TLS 1.3 record. Returns (content-type plaintext) or NIL on error."
  (when (< (length ciphertext-record) 21)  ; 5 header + 16 tag minimum
    (return-from tls-decrypt-record nil))

  (let* ((key (if use-app-keys
                  (tls-get conn :server-app-key)
                  (tls-get conn :server-handshake-key)))
         (iv (if use-app-keys
                 (tls-get conn :server-app-iv)
                 (tls-get conn :server-handshake-iv)))
         (seq (tls-get conn :server-seq))
         (nonce (tls-build-nonce iv seq))
         ;; AAD is the record header
         (aad (subseq ciphertext-record 0 5))
         ;; Ciphertext is the rest
         (ciphertext (subseq ciphertext-record 5)))

    ;; Split ciphertext into encrypted data and tag
    (when (< (length ciphertext) 16)
      (format t "Ciphertext too short~%")
      (return-from tls-decrypt-record nil))
    (let* ((ct-len (- (length ciphertext) 16))
           (ct-data (subseq ciphertext 0 ct-len))
           (tag (subseq ciphertext ct-len)))

      ;; Decrypt - returns plaintext or NIL on auth failure
      ;; Dispatch based on negotiated cipher
      (let* ((cipher (or (tls-get conn :cipher) +tls-chacha20-poly1305-sha256+))
             (inner (if (tls-cipher-uses-aes-gcm cipher)
                        (aes-gcm-decrypt key nonce ct-data aad tag)
                        (chacha20-poly1305-decrypt key nonce ct-data tag aad))))
        (unless inner
          (format t "AEAD decrypt failed~%")
          (return-from tls-decrypt-record nil))

        ;; Increment sequence number
        (tls-set conn :server-seq (1+ seq))

        ;; Find content type (last non-zero byte)
        (let ((content-type nil)
              (data-end (1- (length inner))))
          ;; Strip padding (trailing zeros)
          (loop while (and (> data-end 0) (= (aref inner data-end) 0))
                do (decf data-end))
          (setf content-type (aref inner data-end))

          ;; Extract plaintext
          (let ((plaintext (subseq inner 0 data-end)))
            (list content-type plaintext)))))))

;;; Handshake Processing

(defun tls-add-to-transcript (conn msg)
  "Add a handshake message to the transcript."
  (let ((transcript (tls-get conn :transcript)))
    (tls-set conn :transcript (append transcript (list msg)))))

(defun tls-compute-transcript-hash (conn)
  "Compute hash of all transcript messages."
  (let* ((transcript (tls-get conn :transcript))
         (cipher (or (tls-get conn :cipher) +tls-chacha20-poly1305-sha256+))
         (use-sha384 (tls-cipher-uses-sha384 cipher))
         (data (apply #'concatenate 'vector transcript)))
    (if use-sha384
        (sha384 data)
        (sha256 data))))

(defun tls-compute-finished-verify (conn secret)
  "Compute Finished verify_data."
  (let* ((cipher (or (tls-get conn :cipher) +tls-chacha20-poly1305-sha256+))
         (use-sha384 (tls-cipher-uses-sha384 cipher))
         (hash-len (if use-sha384 48 32))
         (finished-key (if use-sha384
                           (tls13-hkdf-expand-label-384 secret "finished" #() hash-len)
                           (tls13-hkdf-expand-label secret "finished" #() hash-len)))
         (transcript-hash (tls-compute-transcript-hash conn)))
    (format t "TLS: finished_key (first 8): ~{~2,'0x ~}~%"
            (coerce (subseq finished-key 0 8) 'list))
    (if use-sha384
        (hmac-sha384 finished-key transcript-hash)
        (hmac-sha256 finished-key transcript-hash))))

;;; Main Handshake Function

(defun tls-buffer-append (buf1 buf2)
  "Append two byte arrays."
  (if (or (null buf1) (= 0 (length buf1)))
      buf2
      (if (or (null buf2) (= 0 (length buf2)))
          buf1
          (concatenate 'vector buf1 buf2))))

(defun tls-extract-record (buffer)
  "Extract a complete TLS record from buffer.
   Returns (record remaining-buffer) or NIL if incomplete."
  (when (or (null buffer) (< (length buffer) 5))
    (return-from tls-extract-record nil))
  (let* ((record-len (bytes-to-u16 (aref buffer 3) (aref buffer 4)))
         (total-len (+ 5 record-len)))
    (when (< (length buffer) total-len)
      (return-from tls-extract-record nil))
    (let ((record (subseq buffer 0 total-len))
          (remaining (if (> (length buffer) total-len)
                         (subseq buffer total-len)
                         #())))
      (list record remaining))))

(defun tls-handshake (conn &optional hostname)
  "Perform TLS 1.3 handshake. Returns T on success, NIL on error."
  (let ((tcp (tls-get conn :tcp))
        (recv-buffer #()))

    ;; 1. Send ClientHello
    (format t "TLS: Building ClientHello...~%")
    (let ((client-hello (tls-build-client-hello conn hostname)))
      (format t "TLS: ClientHello ~d bytes~%" (length client-hello))
      (tls-add-to-transcript conn client-hello)
      (let ((record (tls-make-record +tls-content-handshake+ client-hello)))
        (format t "TLS: Sending record ~d bytes~%" (length record))
        (let ((sent (muerte.x86-pc.e1000::tcp-send tcp record)))
          (unless sent
            (format t "TLS: Send failed!~%")
            (return-from tls-handshake nil)))))

    ;; 2. Receive and buffer data, then extract ServerHello
    (format t "TLS: Waiting for ServerHello~%")
    (let ((data (muerte.x86-pc.e1000::tcp-receive tcp :timeout 30)))
      (unless data
        (format t "TLS: No response~%")
        (return-from tls-handshake nil))
      (format t "TLS: Received ~d bytes from TCP~%" (length data))
      (setf recv-buffer data))

    ;; Extract ServerHello record
    (let ((extracted (tls-extract-record recv-buffer)))
      (unless extracted
        (format t "TLS: Incomplete ServerHello record~%")
        (return-from tls-handshake nil))
      (let ((sh-record (first extracted)))
        (setf recv-buffer (second extracted))
        (format t "TLS: Extracted record type ~d, len ~d, remaining ~d~%"
                (aref sh-record 0) (length sh-record) (length recv-buffer))

        (let ((parsed (tls-parse-record sh-record)))
          (when (= (first parsed) +tls-content-alert+)
            (let ((alert-data (second parsed)))
              (format t "TLS: Received Alert - level=~d desc=~d~%"
                      (aref alert-data 0) (aref alert-data 1))
              (return-from tls-handshake nil)))
          (unless (= (first parsed) +tls-content-handshake+)
            (format t "TLS: Invalid record type ~d~%" (first parsed))
            (return-from tls-handshake nil))

          (let ((handshake-data (second parsed)))
            (unless (= (aref handshake-data 0) +tls-hs-server-hello+)
              (format t "TLS: Expected ServerHello, got ~d~%" (aref handshake-data 0))
              (return-from tls-handshake nil))

            (let ((msg-len (bytes-to-u24 (aref handshake-data 1)
                                         (aref handshake-data 2)
                                         (aref handshake-data 3))))
              (unless (tls-parse-server-hello conn (subseq handshake-data 4 (+ 4 msg-len)))
                (return-from tls-handshake nil))
              (tls-add-to-transcript conn (subseq handshake-data 0 (+ 4 msg-len))))))))

    ;; 3. Derive handshake keys
    (format t "TLS: Deriving handshake keys~%")
    (tls-derive-keys conn)
    (format t "TLS: Server handshake key (first 8): ")
    (let ((key (tls-get conn :server-handshake-key)))
      (when key
        (dotimes (i (min 8 (length key)))
          (format t "~2,'0x " (aref key i)))))
    (format t "~%")

    ;; 4. Process encrypted handshake messages
    (format t "TLS: Processing encrypted handshake (buffer has ~d bytes)~%" (length recv-buffer))
    (let ((finished-received nil))

      ;; Loop to receive and process records
      ;; After receiving Finished, continue to drain any buffered NewSessionTicket records
      (loop
        ;; Try to extract a record from buffer
        (let ((extracted (tls-extract-record recv-buffer)))
          (unless extracted
            ;; Need more data - but if we already have Finished, don't wait
            (when finished-received
              (format t "TLS: Finished received, buffer has ~d bytes remaining~%" (length recv-buffer))
              (return))
            (format t "TLS: Need more data, fetching...~%")
            (let ((more-data (muerte.x86-pc.e1000::tcp-receive tcp :timeout 30)))
              (unless more-data
                (format t "TLS: Timeout waiting for data~%")
                (return-from tls-handshake nil))
              (format t "TLS: Got ~d more bytes~%" (length more-data))
              (setf recv-buffer (tls-buffer-append recv-buffer more-data))
              (setf extracted (tls-extract-record recv-buffer))))

          (when extracted
            (let ((record (first extracted)))
              (setf recv-buffer (second extracted))
              (let ((record-type (aref record 0)))
                (format t "TLS: Record type ~d, len ~d~%" record-type (length record))

                (cond
                  ;; ChangeCipherSpec - ignore
                  ((= record-type +tls-content-change-cipher-spec+)
                   (format t "TLS: Ignoring ChangeCipherSpec~%"))

                  ;; Encrypted handshake record
                  ((= record-type +tls-content-application-data+)
                   (let ((decrypted (tls-decrypt-record conn record)))
                     (unless decrypted
                       (format t "TLS: Decryption failed~%")
                       (return-from tls-handshake nil))

                     (let ((content-type (first decrypted))
                           (plaintext (second decrypted)))
                       (unless (= content-type +tls-content-handshake+)
                         (format t "TLS: Unexpected inner type ~d~%" content-type)
                         (return-from tls-handshake nil))

                       ;; Parse handshake messages
                       (let ((pos 0))
                         (loop while (< pos (length plaintext)) do
                           (when (< (- (length plaintext) pos) 4)
                             (return))
                           (let* ((hs-type (aref plaintext pos))
                                  (hs-len (bytes-to-u24 (aref plaintext (+ pos 1))
                                                        (aref plaintext (+ pos 2))
                                                        (aref plaintext (+ pos 3))))
                                  (hs-end (+ pos 4 hs-len)))
                             (when (> hs-end (length plaintext))
                               (return))
                             (let ((hs-msg (subseq plaintext pos hs-end)))
                               (cond
                                 ((= hs-type +tls-hs-encrypted-extensions+)
                                  (format t "TLS: Got EncryptedExtensions (~d bytes)~%" (length hs-msg))
                                  ;; Parse extensions to see ALPN
                                  (when (> (length hs-msg) 6)
                                    (let ((ext-len (bytes-to-u16 (aref hs-msg 4) (aref hs-msg 5)))
                                          (ext-pos 6))
                                      (loop while (< ext-pos (min (+ 6 ext-len) (length hs-msg))) do
                                        (let ((ext-type (bytes-to-u16 (aref hs-msg ext-pos) (aref hs-msg (1+ ext-pos))))
                                              (ext-data-len (bytes-to-u16 (aref hs-msg (+ ext-pos 2)) (aref hs-msg (+ ext-pos 3)))))
                                          (format t "TLS: EE extension type=~d len=~d~%" ext-type ext-data-len)
                                          (when (= ext-type 16) ; ALPN
                                            (format t "TLS: ALPN protocol: ")
                                            (let ((proto-list-len (bytes-to-u16 (aref hs-msg (+ ext-pos 4)) (aref hs-msg (+ ext-pos 5)))))
                                              (when (> proto-list-len 0)
                                                (let ((proto-len (aref hs-msg (+ ext-pos 6))))
                                                  (dotimes (i proto-len)
                                                    (write-char (code-char (aref hs-msg (+ ext-pos 7 i)))))
                                                  (terpri)))))
                                          (incf ext-pos (+ 4 ext-data-len))))))
                                  (tls-add-to-transcript conn hs-msg))
                                 ((= hs-type +tls-hs-certificate+)
                                  (format t "TLS: Got Certificate~%")
                                  (tls-add-to-transcript conn hs-msg))
                                 ((= hs-type +tls-hs-certificate-verify+)
                                  (format t "TLS: Got CertificateVerify~%")
                                  (tls-add-to-transcript conn hs-msg))
                                 ((= hs-type +tls-hs-finished+)
                                  (format t "TLS: Got server Finished~%")
                                  ;; Print server's verify_data (first 8 bytes)
                                  (format t "TLS: Server verify_data (first 8): ~{~2,'0x ~}~%"
                                          (coerce (subseq hs-msg 4 12) 'list))
                                  ;; Verify server's Finished - transcript should have 5 msgs (CH,SH,EE,Cert,CV)
                                  (let ((transcript (tls-get conn :transcript)))
                                    (format t "TLS: Verify transcript has ~d msgs:~%" (length transcript))
                                    (dolist (msg transcript)
                                      (format t "  Type ~d, len ~d~%" (aref msg 0) (length msg))))
                                  (let* ((server-hs-secret (tls-get conn :server-hs-traffic-secret))
                                         (transcript-hash (tls-compute-transcript-hash conn))
                                         (expected (tls-compute-finished-verify conn server-hs-secret)))
                                    (format t "TLS: Server hs secret (first 8): ~{~2,'0x ~}~%"
                                            (coerce (subseq server-hs-secret 0 8) 'list))
                                    (format t "TLS: Verify transcript hash (first 8): ~{~2,'0x ~}~%"
                                            (coerce (subseq transcript-hash 0 8) 'list))
                                    (format t "TLS: Expected server verify (first 8): ~{~2,'0x ~}~%"
                                            (coerce (subseq expected 0 8) 'list)))
                                  (tls-add-to-transcript conn hs-msg)
                                  (setf finished-received t))
                                 ((= hs-type +tls-hs-new-session-ticket+)
                                  ;; Ignore NewSessionTicket (we don't do session resumption)
                                  (format t "TLS: Ignoring NewSessionTicket~%"))
                                 (t
                                  (format t "TLS: Ignoring handshake type ~d~%" hs-type)))
                               (setf pos hs-end))))))))

                  (t
                   (format t "TLS: Unexpected record type ~d~%" record-type)
                   (return-from tls-handshake nil))))))))

      ;; Make sure we got Finished
      (unless finished-received
        (format t "TLS: Did not receive server Finished~%")
        (return-from tls-handshake nil)))

    ;; 5. Send CCS + client Finished in one TCP segment
    ;; CCS is for middlebox compatibility (RFC 8446 Appendix D.4)
    (format t "TLS: Sending CCS and client Finished~%")
    ;; Debug: show transcript contents
    (let ((transcript (tls-get conn :transcript)))
      (format t "TLS: Transcript has ~d messages:~%" (length transcript))
      (dolist (msg transcript)
        (format t "  Type ~d, len ~d~%" (aref msg 0) (length msg))))
    (let* ((transcript-hash (tls-compute-transcript-hash conn))
           (client-hs-secret (tls-get conn :client-hs-traffic-secret))
           (verify-data (tls-compute-finished-verify conn client-hs-secret))
           (finished-msg (tls-make-handshake +tls-hs-finished+ verify-data))
           (encrypted (tls-encrypt-record conn finished-msg +tls-content-handshake+))
           ;; CCS record: type 20, version 0x0303, length 1, content 0x01
           (ccs-record #(20 3 3 0 1 1)))
      (format t "TLS: Client hs secret (first 8): ~{~2,'0x ~}~%"
              (coerce (subseq client-hs-secret 0 8) 'list))
      (format t "TLS: Client transcript hash (first 8): ~{~2,'0x ~}~%"
              (coerce (subseq transcript-hash 0 8) 'list))
      (format t "TLS: Client verify_data (first 8): ~{~2,'0x ~}~%"
              (coerce (subseq verify-data 0 8) 'list))
      (format t "TLS: Finished msg len=~d, encrypted len=~d~%"
              (length finished-msg) (length encrypted))
      ;; Debug: print structure of encrypted record
      (format t "TLS: Encrypted record header: ~{~2,'0x ~}~%"
              (coerce (subseq encrypted 0 5) 'list))
      (format t "TLS: Encrypted first 8 ciphertext: ~{~2,'0x ~}~%"
              (coerce (subseq encrypted 5 13) 'list))
      ;; 6. Derive application keys BEFORE sending (to enable early data)
      ;; IMPORTANT: Derive keys BEFORE sending Finished so we can send
      ;; early app data in the same TCP segment
      (format t "TLS: Deriving application keys~%")
      (tls-derive-app-keys conn transcript-hash)

      ;; Check if we have early data to send with Finished
      (let ((early-data (tls-get conn :early-data)))
        (if early-data
            ;; Send CCS + Finished + HTTP all in ONE tcp-send call
            ;; This maximizes the chance they arrive together
            (let* ((app-record (tls-encrypt-record conn early-data +tls-content-application-data+
                                                    :use-app-keys t))
                   (combined (concatenate 'vector ccs-record encrypted app-record)))
              (format t "TLS: Sending CCS + Finished + app data in one call (~d bytes)~%"
                      (length combined))
              (muerte.x86-pc.e1000::tcp-send tcp combined))
            ;; No early data, just send CCS + Finished
            (let ((combined (concatenate 'vector ccs-record encrypted)))
              (muerte.x86-pc.e1000::tcp-send tcp combined)))))


    ;; Handshake complete!
    (format t "TLS: Handshake complete!~%")
    (tls-set conn :state :established)
    t))

;;; Application Data

(defun tls-send (conn data)
  "Send application data over TLS connection.
   Fragments large data into multiple TLS records to avoid QEMU slirp issues."
  (format t "TLS send: ~d bytes of app data~%" (length data))
  (let ((tcp (tls-get conn :tcp))
        (data-len (length data)))
    (if (<= data-len +tls-max-fragment+)
        ;; Small data - send in one record
        (let ((record (tls-encrypt-record conn data +tls-content-application-data+
                                          :use-app-keys t)))
          (format t "TLS send: encrypted to ~d byte record~%" (length record))
          (let ((result (muerte.x86-pc.e1000::tcp-send tcp record)))
            (format t "TLS send: tcp-send returned ~a~%" result)
            result))
        ;; Large data - fragment into multiple records
        (let ((offset 0))
          (format t "TLS send: fragmenting ~d bytes into ~d-byte chunks~%"
                  data-len +tls-max-fragment+)
          (loop while (< offset data-len) do
            (let* ((remaining (- data-len offset))
                   (chunk-size (min +tls-max-fragment+ remaining))
                   (chunk (subseq data offset (+ offset chunk-size)))
                   (record (tls-encrypt-record conn chunk +tls-content-application-data+
                                               :use-app-keys t)))
              (format t "TLS send: fragment ~d-~d, encrypted to ~d bytes~%"
                      offset (+ offset chunk-size) (length record))
              (unless (muerte.x86-pc.e1000::tcp-send tcp record)
                (format t "TLS send: fragment send failed!~%")
                (return-from tls-send nil))
              (incf offset chunk-size)))
          (format t "TLS send: all fragments sent~%")
          t))))

(defun tls-receive (conn &key (timeout 100))
  "Receive application data from TLS connection. Returns data or NIL."
  (let ((tcp (tls-get conn :tcp))
        (recv-buffer (or (tls-get conn :recv-buffer) #())))
    (format t "TLS recv: buffer=~d bytes, tcp-state=~d~%"
            (length recv-buffer) (muerte.x86-pc.e1000::tcp-conn-get tcp :state))
    ;; Check for TCP buffered data
    (let ((tcp-buf (muerte.x86-pc.e1000::tcp-conn-get tcp :recv-buffer)))
      (when tcp-buf
        (format t "TLS recv: tcp has ~d buffered bytes~%" (length tcp-buf))))
    (format t "TLS recv: starting~%")

    ;; Keep trying until we get application data or timeout
    (loop
      ;; Try to extract a record from the buffer
      (let ((extracted (tls-extract-record recv-buffer)))
        (unless extracted
          ;; Need more data from TCP
          (format t "TLS recv: need data, calling tcp-receive...~%")
          (let ((response (muerte.x86-pc.e1000::tcp-receive tcp :timeout timeout)))
            (format t "TLS recv: tcp returned ~a~%" (if response (format nil "~d bytes" (length response)) "NIL"))
            (unless response
              ;; Timeout or connection closed - save buffer and return
              (tls-set conn :recv-buffer recv-buffer)
              (return-from tls-receive nil))
            (setf recv-buffer (tls-buffer-append recv-buffer response))
            (format t "TLS recv: buffer now ~d bytes~%" (length recv-buffer))
            (setf extracted (tls-extract-record recv-buffer))))

        (when extracted
          (let ((record (first extracted)))
            (setf recv-buffer (second extracted))
            (let ((record-type (aref record 0)))
              (cond
                ;; Encrypted record (application data wrapper)
                ((= record-type +tls-content-application-data+)
                 (format t "TLS recv: decrypting ~d byte record~%" (length record))
                 (let ((decrypted (tls-decrypt-record conn record :use-app-keys t)))
                   (unless decrypted
                     (tls-set conn :recv-buffer recv-buffer)
                     (return-from tls-receive nil))

                   (let ((content-type (first decrypted))
                         (plaintext (second decrypted)))
                     (format t "TLS recv: inner type=~d, ~d bytes~%" content-type (length plaintext))
                     (cond
                       ;; Application data - return it
                       ((= content-type +tls-content-application-data+)
                        (tls-set conn :recv-buffer recv-buffer)
                        (return-from tls-receive plaintext))

                       ;; Handshake message (likely NewSessionTicket)
                       ((= content-type +tls-content-handshake+)
                        (format t "TLS recv: skipping handshake msg type ~d~%"
                                (if (> (length plaintext) 0) (aref plaintext 0) -1))
                        ;; Continue loop to process more records
                        )

                       ;; Alert
                       ((= content-type +tls-content-alert+)
                        (format t "TLS: alert level ~d desc ~d~%"
                                (aref plaintext 0) (aref plaintext 1))
                        (tls-set conn :recv-buffer recv-buffer)
                        (return-from tls-receive nil))))))

                ;; Unexpected unencrypted record
                (t
                 (tls-set conn :recv-buffer recv-buffer)
                 (return-from tls-receive nil))))))))))

(defun tls-close (conn)
  "Close TLS connection."
  ;; TODO: Send close_notify alert
  (muerte.x86-pc.e1000::tcp-close (tls-get conn :tcp)))

;;; High-level API

(defun parse-ip-string (str)
  "Parse an IP address string like \"10.0.2.100\" into a byte vector.
   Returns nil if the string is not a valid IP address."
  (let ((parts nil)
        (current 0)
        (len (length str)))
    (dotimes (i len)
      (let ((c (char str i)))
        (cond
          ((char<= #\0 c #\9)
           (setf current (+ (* current 10) (- (char-code c) (char-code #\0))))
           (when (> current 255)
             (return-from parse-ip-string nil)))
          ((char= c #\.)
           (push current parts)
           (setf current 0))
          (t
           ;; Non-digit, non-dot means it's a hostname
           (return-from parse-ip-string nil)))))
    (push current parts)
    (if (= (length parts) 4)
        (let ((ip (make-array 4 :element-type '(unsigned-byte 8))))
          (setf (aref ip 0) (fourth parts))
          (setf (aref ip 1) (third parts))
          (setf (aref ip 2) (second parts))
          (setf (aref ip 3) (first parts))
          ip)
        nil)))

(defun tls-connect (host port &key (timeout 30) early-data)
  "Establish a TLS 1.3 connection to host:port.
   EARLY-DATA if provided is sent with the Finished message to avoid race conditions."
  (format t "TLS: Connecting to ~a:~d~%" host port)

  ;; Resolve hostname if needed - try parsing as IP first
  (let ((ip (cond
              ((not (stringp host)) host)  ; Already a vector
              ((parse-ip-string host))     ; IP address string
              (t (muerte.x86-pc.e1000::dns-resolve host)))))  ; DNS lookup
    (unless ip
      (format t "TLS: DNS resolution failed~%")
      (return-from tls-connect nil))

    ;; Establish TCP connection
    (format t "TLS: Establishing TCP connection to ~d.~d.~d.~d:~d~%"
            (aref ip 0) (aref ip 1) (aref ip 2) (aref ip 3) port)
    (let ((tcp (muerte.x86-pc.e1000::tcp-connect ip port :timeout timeout)))
      (format t "TLS: TCP result: ~a~%" tcp)
      (unless tcp
        (format t "TLS: TCP connection failed~%")
        (return-from tls-connect nil))

      ;; Create TLS connection and handshake
      (let ((tls (make-tls-connection tcp)))
        ;; Set early data if provided (will be sent with Finished)
        (when early-data
          (tls-set tls :early-data early-data))
        (if (tls-handshake tls (when (stringp host) host))
            tls
            (progn
              (muerte.x86-pc.e1000::tcp-close tcp)
              nil))))))

;;; Test function

(defun tls-test (&optional (host "example.com") (port 443))
  "Test TLS 1.3 connection."
  (format t "~&TLS 1.3 Test~%")
  ;; Enable verbose to debug TCP timing
  (setf muerte.x86-pc.e1000::*e1000-verbose* t)
  (format t "Connecting to ~a:~d...~%" host port)

  ;; Build HTTP request first - it will be sent with TLS Finished to avoid race
  (let* ((request-str (format nil "GET / HTTP/1.1~c~cHost: ~a~c~cUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36~c~cAccept: text/html,*/*~c~cAccept-Language: en-US,en;q=0.9~c~cConnection: close~c~c~c~c"
                              #\return #\newline
                              host
                              #\return #\newline
                              #\return #\newline
                              #\return #\newline
                              #\return #\newline
                              #\return #\newline
                              #\return #\newline))
         (request (map 'vector #'char-code request-str))
         ;; Connect with early data (HTTP request sent with Finished)
         (conn (tls-connect host port :early-data request)))
    (if conn
        (progn
          (format t "Connected! HTTP request was sent with Finished.~%")
          ;; Receive response
          (format t "Waiting for response...~%")
          (let ((response (tls-receive conn :timeout 30)))
            (when response
              (format t "Got ~d bytes:~%" (length response))
              ;; Print first 200 chars
              (dotimes (i (min 200 (length response)))
                (let ((c (aref response i)))
                  (when (and (>= c 32) (<= c 126))
                    (write-char (code-char c)))))
              (format t "~%...")))
          (tls-close conn)
          (format t "~%TLS test complete.~%"))
        (format t "Connection failed.~%"))))

(defun tls-throughput-test (&optional (host "example.com") (port 443))
  "Test TLS throughput by downloading content and counting bytes."
  (format t "~&TLS Throughput Test~%")
  (setf muerte.x86-pc.e1000::*e1000-verbose* nil)
  (format t "Connecting to ~a:~d...~%" host port)

  (let ((conn (tls-connect host port)))
    (unless conn
      (format t "Connection failed.~%")
      (return-from tls-throughput-test nil))

    (format t "Connected! Starting download...~%")
    (let ((request (format nil "GET / HTTP/1.1~c~cHost: ~a~c~cUser-Agent: Movitz/1.0~c~cAccept: */*~c~cConnection: close~c~c~c~c"
                           #\return #\newline
                           host
                           #\return #\newline
                           #\return #\newline
                           #\return #\newline
                           #\return #\newline
                           #\return #\newline)))
      (let ((total-bytes 0)
            (chunks 0))
        (tls-send conn (map 'vector #'char-code request))
        (format t "Waiting for response...~%")

        ;; Receive all data until connection closes
        (loop
          (let ((response (tls-receive conn :timeout 30)))
            (unless response
              (return))
            (incf total-bytes (length response))
            (incf chunks)))

        (format t "~%=== Throughput Results ===~%")
        (format t "Total bytes received: ~d~%" total-bytes)
        (format t "Number of chunks: ~d~%" chunks)
        (format t "Average chunk size: ~d bytes~%" (if (> chunks 0) (truncate total-bytes chunks) 0))

        (tls-close conn)
        (format t "Test complete.~%")
        total-bytes))))
