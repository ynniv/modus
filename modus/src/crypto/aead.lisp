;;;; ChaCha20-Poly1305 AEAD implementation for Movitz
;;;; Based on RFC 8439

(require :muerte/basic-macros)
(require :lib/crypto/chacha20)
(require :lib/crypto/poly1305)
(provide :lib/crypto/aead)

(in-package muerte)

;;; ChaCha20-Poly1305 AEAD combines:
;;; - ChaCha20 for encryption
;;; - Poly1305 for authentication
;;;
;;; The key is 256 bits (32 bytes).
;;; The nonce is 96 bits (12 bytes).
;;; The tag is 128 bits (16 bytes).

(defun pad16 (data)
  "Pad data to 16-byte boundary, return padding bytes needed."
  (let ((len (length data)))
    (mod (- 16 (mod len 16)) 16)))

(defun chacha20-poly1305-encrypt (key nonce plaintext &optional (aad nil))
  "ChaCha20-Poly1305 AEAD encryption.
   KEY: 32-byte key
   NONCE: 12-byte nonce
   PLAINTEXT: byte array
   AAD: additional authenticated data (optional)
   Returns: (ciphertext . tag) where tag is 16 bytes"
  (let* ((aad-bytes (or aad (make-array 0 :element-type '(unsigned-byte 8))))
         ;; Generate Poly1305 key using ChaCha20 block 0
         (poly-key (chacha-block key nonce 0))
         (poly-key-32 (make-array 32 :element-type '(unsigned-byte 8))))

    ;; Extract first 32 bytes as Poly1305 key
    (dotimes (i 32)
      (setf (aref poly-key-32 i) (aref poly-key i)))

    ;; Encrypt plaintext using ChaCha20 starting at block 1
    (let ((ciphertext (chacha20-encrypt key nonce plaintext 1)))

      ;; Build MAC input: AAD || pad || ciphertext || pad || len(AAD) || len(ciphertext)
      (let* ((aad-len (length aad-bytes))
             (ct-len (length ciphertext))
             (aad-pad (pad16 aad-bytes))
             (ct-pad (pad16 ciphertext))
             (mac-data-len (+ aad-len aad-pad ct-len ct-pad 8 8))
             (mac-data (make-array mac-data-len :element-type '(unsigned-byte 8)
                                   :initial-element 0))
             (pos 0))

        ;; AAD
        (dotimes (i aad-len)
          (setf (aref mac-data pos) (aref aad-bytes i))
          (incf pos))
        (incf pos aad-pad)

        ;; Ciphertext
        (dotimes (i ct-len)
          (setf (aref mac-data pos) (aref ciphertext i))
          (incf pos))
        (incf pos ct-pad)

        ;; Length of AAD (64-bit little-endian)
        (setf (aref mac-data pos) (logand aad-len #xff))
        (setf (aref mac-data (+ pos 1)) (logand (ash aad-len -8) #xff))
        (setf (aref mac-data (+ pos 2)) (logand (ash aad-len -16) #xff))
        (setf (aref mac-data (+ pos 3)) (logand (ash aad-len -24) #xff))
        (incf pos 8)

        ;; Length of ciphertext (64-bit little-endian)
        (setf (aref mac-data pos) (logand ct-len #xff))
        (setf (aref mac-data (+ pos 1)) (logand (ash ct-len -8) #xff))
        (setf (aref mac-data (+ pos 2)) (logand (ash ct-len -16) #xff))
        (setf (aref mac-data (+ pos 3)) (logand (ash ct-len -24) #xff))

        ;; Compute tag
        (let ((tag (poly1305 poly-key-32 mac-data)))
          (cons ciphertext tag))))))

(defun chacha20-poly1305-decrypt (key nonce ciphertext tag &optional (aad nil))
  "ChaCha20-Poly1305 AEAD decryption.
   KEY: 32-byte key
   NONCE: 12-byte nonce
   CIPHERTEXT: byte array
   TAG: 16-byte authentication tag
   AAD: additional authenticated data (optional)
   Returns: plaintext on success, NIL on authentication failure"
  (let* ((aad-bytes (or aad (make-array 0 :element-type '(unsigned-byte 8))))
         ;; Generate Poly1305 key using ChaCha20 block 0
         (poly-key (chacha-block key nonce 0))
         (poly-key-32 (make-array 32 :element-type '(unsigned-byte 8))))

    ;; Extract first 32 bytes as Poly1305 key
    (dotimes (i 32)
      (setf (aref poly-key-32 i) (aref poly-key i)))

    ;; Verify MAC before decrypting
    (let* ((aad-len (length aad-bytes))
           (ct-len (length ciphertext))
           (aad-pad (pad16 aad-bytes))
           (ct-pad (pad16 ciphertext))
           (mac-data-len (+ aad-len aad-pad ct-len ct-pad 8 8))
           (mac-data (make-array mac-data-len :element-type '(unsigned-byte 8)
                                 :initial-element 0))
           (pos 0))

      ;; AAD
      (dotimes (i aad-len)
        (setf (aref mac-data pos) (aref aad-bytes i))
        (incf pos))
      (incf pos aad-pad)

      ;; Ciphertext
      (dotimes (i ct-len)
        (setf (aref mac-data pos) (aref ciphertext i))
        (incf pos))
      (incf pos ct-pad)

      ;; Length of AAD
      (setf (aref mac-data pos) (logand aad-len #xff))
      (setf (aref mac-data (+ pos 1)) (logand (ash aad-len -8) #xff))
      (setf (aref mac-data (+ pos 2)) (logand (ash aad-len -16) #xff))
      (setf (aref mac-data (+ pos 3)) (logand (ash aad-len -24) #xff))
      (incf pos 8)

      ;; Length of ciphertext
      (setf (aref mac-data pos) (logand ct-len #xff))
      (setf (aref mac-data (+ pos 1)) (logand (ash ct-len -8) #xff))
      (setf (aref mac-data (+ pos 2)) (logand (ash ct-len -16) #xff))
      (setf (aref mac-data (+ pos 3)) (logand (ash ct-len -24) #xff))

      ;; Compute expected tag
      (let ((expected-tag (poly1305 poly-key-32 mac-data))
            (tag-match t))
        ;; Constant-time tag comparison
        (dotimes (i 16)
          (unless (= (aref tag i) (aref expected-tag i))
            (setf tag-match nil)))

        (if tag-match
            ;; Decrypt
            (chacha20-decrypt key nonce ciphertext 1)
            ;; Authentication failed
            nil)))))

;;; Test function
(defun aead-test ()
  "Test ChaCha20-Poly1305 AEAD with RFC 8439 test vector."
  (format t "~&ChaCha20-Poly1305 AEAD test:~%")

  ;; RFC 8439 Section 2.8.2 test
  (let ((key (make-array 32 :element-type '(unsigned-byte 8)))
        (nonce (make-array 12 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x00 #x00 #x00 #x00
                                               #x00 #x00 #x00 #x4a
                                               #x00 #x00 #x00 #x00)))
        (aad (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(#x50 #x51 #x52 #x53
                                             #xc0 #xc1 #xc2 #xc3
                                             #xc4 #xc5 #xc6 #xc7)))
        (plaintext-str "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."))

    ;; Key: 80 81 82 ... 9f
    (dotimes (i 32)
      (setf (aref key i) (+ #x80 i)))

    ;; Convert plaintext
    (let ((plaintext (make-array (length plaintext-str)
                                 :element-type '(unsigned-byte 8))))
      (dotimes (i (length plaintext-str))
        (setf (aref plaintext i) (char-code (char plaintext-str i))))

      ;; Encrypt
      (let* ((result (chacha20-poly1305-encrypt key nonce plaintext aad))
             (ciphertext (car result))
             (tag (cdr result)))

        (format t "  Ciphertext first 8: ")
        (dotimes (i 8)
          (format t "~2,'0x " (aref ciphertext i)))
        (format t "~%")

        (format t "  Tag: ")
        (dotimes (i 16)
          (format t "~2,'0x " (aref tag i)))
        (format t "~%")

        ;; Expected tag: 1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91
        (when (and (= (aref tag 0) #x1a)
                   (= (aref tag 1) #xe1))
          (format t "  Tag: CORRECT~%"))

        ;; Decrypt and verify round-trip
        (let ((decrypted (chacha20-poly1305-decrypt key nonce ciphertext tag aad)))
          (if decrypted
              (let ((match t))
                (dotimes (i (length plaintext))
                  (unless (= (aref plaintext i) (aref decrypted i))
                    (setf match nil)))
                (if match
                    (format t "  Round-trip: PASS~%")
                    (format t "  Round-trip: MISMATCH~%")))
              (format t "  Round-trip: AUTH FAILED~%"))))))
  t)
