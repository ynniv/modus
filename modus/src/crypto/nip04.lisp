;;;; NIP-04: Encrypted Direct Messages
;;;; https://github.com/nostr-protocol/nips/blob/master/04.md

(require :lib/crypto/sha256)
(require :lib/crypto/aes)
(require :lib/crypto/secp256k1)

(provide :lib/crypto/nip04)

(in-package :muerte)

;;; NIP-04 uses ECDH + AES-256-CBC
;;; Shared secret = SHA256(ECDH_x_coordinate)
;;; Ciphertext format: base64(encrypted)?iv=base64(iv)

(defun nip04-compute-shared-secret (privkey pubkey-bytes)
  "Compute NIP-04 shared secret using ECDH.
   privkey: 32-byte integer
   pubkey-bytes: 32-byte x-only pubkey (as per BIP-340)
   Returns: 32-byte SHA256 hash of x-coordinate of shared point."
  ;; Lift x-only pubkey to full point (assuming even y)
  (let* ((other-point (secp-lift-x (bytes-to-integer pubkey-bytes)))
         ;; ECDH: shared_point = privkey * other_pubkey
         (shared-point (secp-mul-point privkey other-point))
         ;; Get x-coordinate as bytes
         (x-bytes (integer-to-bytes (car shared-point) 32)))
    ;; Shared secret = SHA256(x-coordinate)
    (sha256 x-bytes)))

(defun bytes-to-integer (bytes)
  "Convert byte array to integer (big-endian)."
  (let ((result 0))
    (dotimes (i (length bytes))
      (setf result (logior (ash result 8) (aref bytes i))))
    result))

(defun integer-to-bytes (n size)
  "Convert integer to byte array (big-endian)."
  (let ((result (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from (1- size) downto 0
          for shift from 0 by 8
          do (setf (aref result i) (logand (ash n (- shift)) #xff)))
    result))

(defun nip04-encrypt (privkey pubkey-hex plaintext)
  "Encrypt a message using NIP-04.
   privkey: 32-byte integer (sender's private key)
   pubkey-hex: 64-char hex string (recipient's public key)
   plaintext: string to encrypt
   Returns: encrypted string in format 'base64(ciphertext)?iv=base64(iv)'"
  (let* ((pubkey-bytes (hex-to-bytes pubkey-hex))
         (shared-secret (nip04-compute-shared-secret privkey pubkey-bytes))
         ;; Generate random 16-byte IV
         (iv (make-array 16 :element-type '(unsigned-byte 8)))
         ;; Convert plaintext to bytes
         (pt-bytes (make-array (length plaintext) :element-type '(unsigned-byte 8))))
    ;; Fill IV with random bytes
    (dotimes (i 16)
      (setf (aref iv i) (random 256)))
    ;; Convert plaintext string to bytes
    (dotimes (i (length plaintext))
      (setf (aref pt-bytes i) (char-code (char plaintext i))))
    ;; Encrypt with AES-256-CBC
    (let ((ciphertext (aes-256-cbc-encrypt shared-secret iv pt-bytes)))
      ;; Format: base64(ciphertext)?iv=base64(iv)
      (concatenate 'string
                   (base64-encode ciphertext)
                   "?iv="
                   (base64-encode iv)))))

(defun nip04-decrypt (privkey pubkey-hex encrypted)
  "Decrypt a NIP-04 encrypted message.
   privkey: 32-byte integer (recipient's private key)
   pubkey-hex: 64-char hex string (sender's public key)
   encrypted: string in format 'base64(ciphertext)?iv=base64(iv)'
   Returns: decrypted plaintext string."
  (let* ((pubkey-bytes (hex-to-bytes pubkey-hex))
         (shared-secret (nip04-compute-shared-secret privkey pubkey-bytes))
         ;; Parse encrypted string
         (iv-pos (search "?iv=" encrypted))
         (ciphertext-b64 (subseq encrypted 0 iv-pos))
         (iv-b64 (subseq encrypted (+ iv-pos 4)))
         ;; Decode base64
         (ciphertext (base64-decode ciphertext-b64))
         (iv (base64-decode iv-b64))
         ;; Decrypt
         (pt-bytes (aes-256-cbc-decrypt shared-secret iv ciphertext))
         ;; Convert to string
         (result (make-array (length pt-bytes) :element-type 'character)))
    (dotimes (i (length pt-bytes))
      (setf (aref result i) (code-char (aref pt-bytes i))))
    (coerce result 'string)))

;;; Test function
(defun nip04-test ()
  "Test NIP-04 encryption/decryption."
  (format t "~&=== NIP-04 Test ===~%")
  (let* ((alice-privkey #x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef)
         (bob-privkey #xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210)
         (alice-pubkey (bytes-to-hex (schnorr-pubkey alice-privkey)))
         (bob-pubkey (bytes-to-hex (schnorr-pubkey bob-privkey)))
         (message "Hello from NIP-04!"))
    (format t "Alice pubkey: ~a~%" alice-pubkey)
    (format t "Bob pubkey: ~a~%" bob-pubkey)
    (format t "Original: ~a~%" message)
    ;; Alice encrypts to Bob
    (let ((encrypted (nip04-encrypt alice-privkey bob-pubkey message)))
      (format t "Encrypted: ~a~%" encrypted)
      ;; Bob decrypts from Alice
      (let ((decrypted (nip04-decrypt bob-privkey alice-pubkey encrypted)))
        (format t "Decrypted: ~a~%" decrypted)
        (format t "Match: ~a~%" (string= message decrypted)))))
  (format t "=== NIP-04 Test Complete ===~%"))
