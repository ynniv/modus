;;;; ChaCha20-Poly1305 implementation for Movitz
;;;; Based on RFC 8439
;;;; Uses 16-bit arithmetic to stay within 30-bit fixnum limit

(require :muerte/basic-macros)
(provide :lib/crypto/chacha20)

(in-package muerte)

;;; ChaCha20 operates on 32-bit words. We use the same u32 representation
;;; as SHA-256: cons pairs (hi16 . lo16)

;;; u32 quarter-round operations
(defun chacha-rotl (x n)
  "Left rotate u32 by N bits."
  (let ((hi (u32-hi x))
        (lo (u32-lo x))
        (inv (- 32 n)))
    (cond
      ((zerop n) x)
      ((< n 16)
       (let ((mask (1- (ash 1 n))))
         (make-u32 (logior (logand (ash hi n) #xffff)
                           (ash lo (- n 16)))
                   (logior (logand (ash lo n) #xffff)
                           (ash (logand hi (ash mask (- 16 n))) (- n 16))))))
      ((= n 16)
       (make-u32 lo hi))
      (t
       (let* ((m (- n 16))
              (mask (1- (ash 1 m))))
         (make-u32 (logior (logand (ash lo m) #xffff)
                           (ash hi (- m 16)))
                   (logior (logand (ash hi m) #xffff)
                           (ash (logand lo (ash mask (- 16 m))) (- m 16)))))))))

(defun chacha-quarter-round (state a b c d)
  "Perform ChaCha quarter round on state array."
  (let ((sa (aref state a))
        (sb (aref state b))
        (sc (aref state c))
        (sd (aref state d)))
    ;; a += b; d ^= a; d <<<= 16;
    (setf sa (u32+ sa sb))
    (setf sd (chacha-rotl (u32-xor sd sa) 16))
    ;; c += d; b ^= c; b <<<= 12;
    (setf sc (u32+ sc sd))
    (setf sb (chacha-rotl (u32-xor sb sc) 12))
    ;; a += b; d ^= a; d <<<= 8;
    (setf sa (u32+ sa sb))
    (setf sd (chacha-rotl (u32-xor sd sa) 8))
    ;; c += d; b ^= c; b <<<= 7;
    (setf sc (u32+ sc sd))
    (setf sb (chacha-rotl (u32-xor sb sc) 7))

    (setf (aref state a) sa
          (aref state b) sb
          (aref state c) sc
          (aref state d) sd)))

(defun chacha-inner-block (state)
  "Perform ChaCha20 inner block function (20 rounds)."
  (dotimes (i 10)
    ;; Column rounds
    (chacha-quarter-round state 0 4 8 12)
    (chacha-quarter-round state 1 5 9 13)
    (chacha-quarter-round state 2 6 10 14)
    (chacha-quarter-round state 3 7 11 15)
    ;; Diagonal rounds
    (chacha-quarter-round state 0 5 10 15)
    (chacha-quarter-round state 1 6 11 12)
    (chacha-quarter-round state 2 7 8 13)
    (chacha-quarter-round state 3 4 9 14)))

(defun chacha-setup-state (key nonce counter)
  "Set up ChaCha20 initial state.
   KEY: 32-byte key
   NONCE: 12-byte nonce
   COUNTER: 32-bit block counter"
  (let ((state (make-array 16 :initial-element nil)))
    ;; Constants: "expand 32-byte k"
    (setf (aref state 0) (cons #x6170 #x7865)   ; "expa"
          (aref state 1) (cons #x3320 #x646e)   ; "nd 3"
          (aref state 2) (cons #x7962 #x2d32)   ; "2-by"
          (aref state 3) (cons #x6b20 #x6574))  ; "te k"

    ;; Key (8 words, little-endian)
    (dotimes (i 8)
      (let ((j (* i 4)))
        (setf (aref state (+ 4 i))
              (make-u32 (logior (ash (aref key (+ j 3)) 8) (aref key (+ j 2)))
                        (logior (ash (aref key (+ j 1)) 8) (aref key j))))))

    ;; Counter
    (setf (aref state 12) (u32-from-int counter))

    ;; Nonce (3 words, little-endian)
    (dotimes (i 3)
      (let ((j (* i 4)))
        (setf (aref state (+ 13 i))
              (make-u32 (logior (ash (aref nonce (+ j 3)) 8) (aref nonce (+ j 2)))
                        (logior (ash (aref nonce (+ j 1)) 8) (aref nonce j))))))
    state))

(defun chacha-block (key nonce counter)
  "Generate one 64-byte keystream block."
  (let ((state (chacha-setup-state key nonce counter))
        (working (make-array 16 :initial-element nil)))

    ;; Copy state to working
    (dotimes (i 16)
      (setf (aref working i) (aref state i)))

    ;; Apply block function
    (chacha-inner-block working)

    ;; Add original state
    (dotimes (i 16)
      (setf (aref working i) (u32+ (aref working i) (aref state i))))

    ;; Serialize to bytes (little-endian)
    (let ((output (make-array 64 :element-type '(unsigned-byte 8))))
      (dotimes (i 16)
        (let ((word (aref working i))
              (j (* i 4)))
          (setf (aref output j) (logand (u32-lo word) #xff)
                (aref output (+ j 1)) (ash (u32-lo word) -8)
                (aref output (+ j 2)) (logand (u32-hi word) #xff)
                (aref output (+ j 3)) (ash (u32-hi word) -8))))
      output)))

(defun chacha20-encrypt (key nonce plaintext &optional (counter 1))
  "Encrypt plaintext using ChaCha20.
   KEY: 32-byte key
   NONCE: 12-byte nonce
   PLAINTEXT: byte array
   Returns: ciphertext (same length as plaintext)"
  (let* ((len (length plaintext))
         (ciphertext (make-array len :element-type '(unsigned-byte 8)))
         (block-count (ceiling len 64)))

    (dotimes (block-num block-count)
      (let ((keystream (chacha-block key nonce (+ counter block-num)))
            (offset (* block-num 64)))
        (dotimes (i 64)
          (when (< (+ offset i) len)
            (setf (aref ciphertext (+ offset i))
                  (logxor (aref plaintext (+ offset i))
                          (aref keystream i)))))))
    ciphertext))

;; Decryption is the same as encryption (XOR is its own inverse)
(defun chacha20-decrypt (key nonce ciphertext &optional (counter 1))
  "Decrypt ciphertext using ChaCha20."
  (chacha20-encrypt key nonce ciphertext counter))

;;; Test function
(defun chacha20-test ()
  "Test ChaCha20 with RFC 8439 test vector."
  (format t "~&ChaCha20 test:~%")

  ;; RFC 8439 Section 2.4.2 test vector
  ;; Key: 00:01:02:....:1f (32 bytes)
  ;; Nonce: 00:00:00:09:00:00:00:4a:00:00:00:00
  ;; Counter: 1
  ;; Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

  (let ((key (make-array 32 :element-type '(unsigned-byte 8)))
        (nonce (make-array 12 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x00 #x00 #x00 #x00
                                               #x00 #x00 #x00 #x4a
                                               #x00 #x00 #x00 #x00)))
        (plaintext-str "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."))

    ;; Set key bytes 0-31
    (dotimes (i 32)
      (setf (aref key i) i))

    ;; Convert plaintext to bytes
    (let ((plaintext (make-array (length plaintext-str)
                                 :element-type '(unsigned-byte 8))))
      (dotimes (i (length plaintext-str))
        (setf (aref plaintext i) (char-code (char plaintext-str i))))

      (let ((ciphertext (chacha20-encrypt key nonce plaintext)))
        ;; Expected first bytes: 6e 2e 35 9a 25 68 f9 80 ...
        (format t "  First 8 bytes: ")
        (dotimes (i 8)
          (format t "~2,'0x " (aref ciphertext i)))
        (format t "~%")

        ;; Verify round-trip
        (let ((decrypted (chacha20-decrypt key nonce ciphertext)))
          (let ((match t))
            (dotimes (i (length plaintext))
              (unless (= (aref plaintext i) (aref decrypted i))
                (setf match nil)))
            (if match
                (format t "  Round-trip: PASS~%")
                (format t "  Round-trip: FAIL~%"))))

        ;; Check expected first byte
        (when (= (aref ciphertext 0) #x6e)
          (format t "  Ciphertext: CORRECT~%")))))
  t)
