;;;; NIP-44: Encrypted Payloads (Versioned)
;;;; https://github.com/nostr-protocol/nips/blob/master/44.md
;;;;
;;;; Version 2: secp256k1 ECDH, HKDF, padding, ChaCha20, HMAC-SHA256, base64

(require :lib/crypto/sha256)
(require :lib/crypto/hmac)
(require :lib/crypto/hkdf)
(require :lib/crypto/chacha20)
(require :lib/crypto/secp256k1)
(require :lib/net/websocket)  ; for base64

(provide :lib/crypto/nip44)

(in-package :muerte)

;;; NIP-44 uses ECDH to compute a shared point, then HKDF to derive keys.
;;; Unlike NIP-04, the shared point's x-coordinate is NOT hashed before HKDF.

(defun nip44-get-conversation-key (privkey pubkey-bytes)
  "Compute NIP-44 conversation key using ECDH + HKDF.
   privkey: 32-byte integer (private key)
   pubkey-bytes: 32-byte x-only pubkey
   Returns: 32-byte conversation key"
  ;; Lift x-only pubkey to full point
  (let* ((other-point (secp-lift-x (bytes-to-integer pubkey-bytes)))
         ;; ECDH: shared_point = privkey * other_pubkey
         (shared-point (secp-mul-point privkey other-point))
         ;; Get x-coordinate as bytes (unhashed for NIP-44!)
         (shared-x (integer-to-bytes (car shared-point) 32))
         ;; Salt for NIP-44 v2
         (salt (make-array 8 :element-type '(unsigned-byte 8)
                          :initial-contents '(#x6e #x69 #x70 #x34 #x34 #x2d #x76 #x32))))
    ;; "nip44-v2" = #x6e69703434..
    ;; conversation_key = HKDF-extract(salt="nip44-v2", IKM=shared_x)
    (hkdf-extract salt shared-x)))

(defun nip44-get-message-keys (conversation-key nonce)
  "Derive per-message keys from conversation key and nonce.
   conversation-key: 32-byte key
   nonce: 32-byte nonce
   Returns: (chacha-key chacha-nonce hmac-key) as list of byte arrays"
  (let ((keys (hkdf-expand conversation-key nonce 76)))
    ;; chacha_key = keys[0:32]
    ;; chacha_nonce = keys[32:44]
    ;; hmac_key = keys[44:76]
    (let ((chacha-key (make-array 32 :element-type '(unsigned-byte 8)))
          (chacha-nonce (make-array 12 :element-type '(unsigned-byte 8)))
          (hmac-key (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32)
        (setf (aref chacha-key i) (aref keys i)))
      (dotimes (i 12)
        (setf (aref chacha-nonce i) (aref keys (+ 32 i))))
      (dotimes (i 32)
        (setf (aref hmac-key i) (aref keys (+ 44 i))))
      (list chacha-key chacha-nonce hmac-key))))

;;; Padding functions

(defun nip44-calc-padded-len (unpadded-len)
  "Calculate padded length for NIP-44.
   Returns the next power-of-two-based padded length.
   Uses NIP-44 formula: next_power = 2^(floor(log2(n-1)) + 2)"
  (cond
    ((<= unpadded-len 32) 32)
    (t
     ;; NIP-44 formula: next_power = 2^(1 + integer-length(n-1))
     ;; integer-length gives the number of bits, which is floor(log2(x))+1
     ;; So (1+ (integer-length (1- n))) gives floor(log2(n-1)) + 2
     (let* ((exp (1+ (integer-length (1- unpadded-len))))
            (next-power (ash 1 exp))
            ;; Chunk size
            (chunk (if (<= next-power 256)
                       32
                       (ash next-power -3))))  ; next-power / 8
       ;; Round up to next chunk boundary
       (* chunk (1+ (floor (1- unpadded-len) chunk)))))))

(defun nip44-pad (plaintext)
  "Pad plaintext for NIP-44 encryption.
   PLAINTEXT: string or byte array
   Returns: padded byte array with 2-byte length prefix"
  (let* ((pt-bytes (if (stringp plaintext)
                       (let ((b (make-array (length plaintext)
                                           :element-type '(unsigned-byte 8))))
                         (dotimes (i (length plaintext))
                           (setf (aref b i) (char-code (char plaintext i))))
                         b)
                       plaintext))
         (pt-len (length pt-bytes))
         (padded-len (nip44-calc-padded-len pt-len))
         (result (make-array (+ 2 padded-len) :element-type '(unsigned-byte 8)
                            :initial-element 0)))
    ;; Validate length
    (when (or (< pt-len 1) (> pt-len 65535))
      (error "NIP-44: invalid plaintext length ~d" pt-len))
    ;; 2-byte big-endian length prefix
    (setf (aref result 0) (ash pt-len -8))
    (setf (aref result 1) (logand pt-len #xff))
    ;; Copy plaintext
    (dotimes (i pt-len)
      (setf (aref result (+ 2 i)) (aref pt-bytes i)))
    ;; Rest is already zero-filled
    result))

(defun nip44-unpad (padded)
  "Remove padding from NIP-44 decrypted data.
   Returns: plaintext as string"
  (let* ((len (logior (ash (aref padded 0) 8) (aref padded 1)))
         (expected-padded-len (nip44-calc-padded-len len)))
    ;; Validate
    (when (or (zerop len)
              (/= (length padded) (+ 2 expected-padded-len)))
      (error "NIP-44: invalid padding"))
    ;; Extract plaintext
    (let ((result (make-array len :element-type 'character)))
      (dotimes (i len)
        (setf (aref result i) (code-char (aref padded (+ 2 i)))))
      (coerce result 'string))))

;;; HMAC with AAD (additional authenticated data)

(defun nip44-hmac-aad (key message aad)
  "Compute HMAC-SHA256 with additional authenticated data.
   KEY: 32-byte HMAC key
   MESSAGE: ciphertext
   AAD: 32-byte nonce
   Returns: 32-byte MAC"
  (when (/= (length aad) 32)
    (error "NIP-44: AAD must be 32 bytes"))
  (let* ((combined-len (+ (length aad) (length message)))
         (combined (make-array combined-len :element-type '(unsigned-byte 8))))
    ;; Concatenate AAD and message
    (dotimes (i (length aad))
      (setf (aref combined i) (aref aad i)))
    (dotimes (i (length message))
      (setf (aref combined (+ (length aad) i)) (aref message i)))
    (hmac-sha256 key combined)))

;;; Main encryption/decryption

(defun nip44-encrypt (privkey pubkey-hex plaintext)
  "Encrypt plaintext using NIP-44.
   PRIVKEY: 32-byte integer (sender's private key)
   PUBKEY-HEX: 64-char hex string (recipient's public key)
   PLAINTEXT: string to encrypt
   Returns: base64-encoded payload"
  (let* ((pubkey-bytes (hex-to-bytes pubkey-hex))
         (conversation-key (nip44-get-conversation-key privkey pubkey-bytes))
         ;; Generate random 32-byte nonce
         (nonce (make-array 32 :element-type '(unsigned-byte 8))))
    ;; Fill nonce with random bytes
    (dotimes (i 32)
      (setf (aref nonce i) (random 256)))
    (nip44-encrypt-with-nonce plaintext conversation-key nonce)))

(defun nip44-encrypt-with-nonce (plaintext conversation-key nonce)
  "Encrypt with explicit nonce (for testing).
   Returns: base64-encoded payload"
  (let* ((keys (nip44-get-message-keys conversation-key nonce))
         (chacha-key (first keys))
         (chacha-nonce (second keys))
         (hmac-key (third keys))
         ;; Pad plaintext
         (padded (nip44-pad plaintext))
         ;; Encrypt with ChaCha20 (counter=0 for NIP-44)
         (ciphertext (chacha20-encrypt chacha-key chacha-nonce padded 0))
         ;; Compute MAC over (nonce || ciphertext)
         (mac (nip44-hmac-aad hmac-key ciphertext nonce))
         ;; Build payload: version(1) || nonce(32) || ciphertext || mac(32)
         (payload-len (+ 1 32 (length ciphertext) 32))
         (payload (make-array payload-len :element-type '(unsigned-byte 8))))
    ;; Version byte
    (setf (aref payload 0) 2)
    ;; Nonce
    (dotimes (i 32)
      (setf (aref payload (+ 1 i)) (aref nonce i)))
    ;; Ciphertext
    (dotimes (i (length ciphertext))
      (setf (aref payload (+ 33 i)) (aref ciphertext i)))
    ;; MAC
    (dotimes (i 32)
      (setf (aref payload (+ 33 (length ciphertext) i)) (aref mac i)))
    ;; Base64 encode
    (base64-encode payload)))

(defun nip44-decrypt (privkey pubkey-hex payload)
  "Decrypt NIP-44 encrypted payload.
   PRIVKEY: 32-byte integer (recipient's private key)
   PUBKEY-HEX: 64-char hex string (sender's public key)
   PAYLOAD: base64-encoded string
   Returns: decrypted plaintext string"
  (let* ((pubkey-bytes (hex-to-bytes pubkey-hex))
         (conversation-key (nip44-get-conversation-key privkey pubkey-bytes)))
    (nip44-decrypt-with-key payload conversation-key)))

(defun nip44-decrypt-with-key (payload conversation-key)
  "Decrypt with explicit conversation key.
   Returns: plaintext string"
  ;; Validate and decode
  (when (or (zerop (length payload))
            (char= (char payload 0) #\#))
    (error "NIP-44: unknown version"))
  ;; Base64 decode
  (let* ((data (base64-decode payload))
         (dlen (length data)))
    ;; Validate length
    (when (< dlen 99)
      (error "NIP-44: payload too short"))
    ;; Parse
    (let ((version (aref data 0)))
      (unless (= version 2)
        (error "NIP-44: unsupported version ~d" version))
      ;; Extract nonce, ciphertext, mac
      (let* ((nonce (make-array 32 :element-type '(unsigned-byte 8)))
             (ciphertext-len (- dlen 1 32 32))
             (ciphertext (make-array ciphertext-len :element-type '(unsigned-byte 8)))
             (mac (make-array 32 :element-type '(unsigned-byte 8))))
        ;; Copy nonce
        (dotimes (i 32)
          (setf (aref nonce i) (aref data (+ 1 i))))
        ;; Copy ciphertext
        (dotimes (i ciphertext-len)
          (setf (aref ciphertext i) (aref data (+ 33 i))))
        ;; Copy MAC
        (dotimes (i 32)
          (setf (aref mac i) (aref data (+ 33 ciphertext-len i))))
        ;; Get message keys
        (let* ((keys (nip44-get-message-keys conversation-key nonce))
               (chacha-key (first keys))
               (chacha-nonce (second keys))
               (hmac-key (third keys))
               ;; Verify MAC
               (expected-mac (nip44-hmac-aad hmac-key ciphertext nonce)))
          ;; Constant-time compare (approximate)
          (let ((mac-ok t))
            (dotimes (i 32)
              (unless (= (aref mac i) (aref expected-mac i))
                (setf mac-ok nil)))
            (unless mac-ok
              (error "NIP-44: invalid MAC")))
          ;; Decrypt
          (let ((padded (chacha20-decrypt chacha-key chacha-nonce ciphertext 0)))
            ;; Unpad and return
            (nip44-unpad padded)))))))

;;; Test function

(defun nip44-test ()
  "Test NIP-44 encryption/decryption."
  (format t "~&=== NIP-44 Test ===~%")

  ;; Test padding
  (format t "Testing padding:~%")
  (dolist (len '(1 15 16 17 31 32 33 64 100 256 1000))
    (let ((padded-len (nip44-calc-padded-len len)))
      (format t "  ~d -> ~d~%" len padded-len)))

  ;; Test with known keys
  (let* ((alice-privkey #x0000000000000000000000000000000000000000000000000000000000000001)
         (bob-privkey #x0000000000000000000000000000000000000000000000000000000000000002)
         (alice-pubkey (bytes-to-hex (schnorr-pubkey alice-privkey)))
         (bob-pubkey (bytes-to-hex (schnorr-pubkey bob-privkey)))
         (message "Hello NIP-44!"))
    (format t "~%Alice pubkey: ~a~%" alice-pubkey)
    (format t "Bob pubkey: ~a~%" bob-pubkey)
    (format t "Original: ~a~%" message)

    ;; Alice encrypts to Bob
    (let ((encrypted (nip44-encrypt alice-privkey bob-pubkey message)))
      (format t "Encrypted length: ~d chars~%" (length encrypted))
      (format t "Encrypted: ~a...~%" (subseq encrypted 0 (min 40 (length encrypted))))

      ;; Bob decrypts from Alice
      (let ((decrypted (nip44-decrypt bob-privkey alice-pubkey encrypted)))
        (format t "Decrypted: ~a~%" decrypted)
        (format t "Match: ~a~%" (string= message decrypted)))))

  (format t "=== NIP-44 Test Complete ===~%"))

;;; Test with NIP-44 spec test vector

(defun nip44-test-vector ()
  "Test with official NIP-44 test vector."
  (format t "~&=== NIP-44 Test Vector ===~%")

  ;; Test vector from NIP-44 spec:
  ;; sec1: 0000...0001
  ;; sec2: 0000...0002
  ;; conversation_key: c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d
  ;; nonce: 0000...0001
  ;; plaintext: "a"
  ;; Expected payload starts with "AgAAAAA..."

  (let* ((sec1 #x0000000000000000000000000000000000000000000000000000000000000001)
         (sec2 #x0000000000000000000000000000000000000000000000000000000000000002)
         (pub2 (bytes-to-hex (schnorr-pubkey sec2)))
         (conv-key (nip44-get-conversation-key sec1 (hex-to-bytes pub2)))
         (nonce (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Set nonce to 1
    (setf (aref nonce 31) 1)

    (format t "Conversation key: ")
    (dotimes (i 8)
      (format t "~2,'0x" (aref conv-key i)))
    (format t "...~%")
    ;; Expected: c41c775356fd92ea...

    ;; Encrypt "a" with known nonce
    (let ((payload (nip44-encrypt-with-nonce "a" conv-key nonce)))
      (format t "Payload: ~a~%" payload)
      ;; Expected: AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb
      ))

  (format t "=== Test Vector Complete ===~%"))
