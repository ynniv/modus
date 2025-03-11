;;;; HMAC-SHA256 and HMAC-SHA384 implementation for Movitz
;;;; Based on RFC 2104

(require :muerte/basic-macros)
(require :lib/crypto/sha256)
(require :lib/crypto/sha384)
(provide :lib/crypto/hmac)

(in-package muerte)

;;; HMAC-SHA256
;;; HMAC(K, m) = H((K' xor opad) || H((K' xor ipad) || m))
;;; where K' is key padded to block size (64 bytes for SHA-256)
;;; ipad = 0x36 repeated, opad = 0x5c repeated

(defun hmac-sha256 (key message)
  "Compute HMAC-SHA256 of MESSAGE using KEY. Returns 32-byte hash."
  (let ((block-size 64)
        (key-len (length key))
        (k-prime (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; Prepare K': if key > block-size, hash it; else pad with zeros
    (cond
      ((> key-len block-size)
       ;; Hash the key
       (let ((hashed-key (sha256 key)))
         (dotimes (i 32)
           (setf (aref k-prime i) (aref hashed-key i)))))
      (t
       ;; Copy key directly
       (dotimes (i key-len)
         (setf (aref k-prime i) (aref key i)))))

    ;; Compute inner hash: H((K' xor ipad) || message)
    (let* ((inner-data (make-array (+ block-size (length message))
                                   :element-type '(unsigned-byte 8)))
           (ipad #x36))
      ;; K' xor ipad
      (dotimes (i block-size)
        (setf (aref inner-data i) (logxor (aref k-prime i) ipad)))
      ;; Append message
      (dotimes (i (length message))
        (setf (aref inner-data (+ block-size i)) (aref message i)))

      (let ((inner-hash (sha256 inner-data)))

        ;; Compute outer hash: H((K' xor opad) || inner-hash)
        (let* ((outer-data (make-array (+ block-size 32)
                                       :element-type '(unsigned-byte 8)))
               (opad #x5c))
          ;; K' xor opad
          (dotimes (i block-size)
            (setf (aref outer-data i) (logxor (aref k-prime i) opad)))
          ;; Append inner hash
          (dotimes (i 32)
            (setf (aref outer-data (+ block-size i)) (aref inner-hash i)))

          ;; Return final hash
          (sha256 outer-data))))))

;;; HMAC-SHA384
;;; Same algorithm but with SHA-384 and 128-byte blocks
(defun hmac-sha384 (key message)
  "Compute HMAC-SHA384 of MESSAGE using KEY. Returns 48-byte hash."
  (let ((block-size 128)  ; SHA-384/512 uses 1024-bit (128-byte) blocks
        (key-len (length key))
        (k-prime (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; Prepare K': if key > block-size, hash it; else pad with zeros
    (cond
      ((> key-len block-size)
       ;; Hash the key
       (let ((hashed-key (sha384 key)))
         (dotimes (i 48)
           (setf (aref k-prime i) (aref hashed-key i)))))
      (t
       ;; Copy key directly
       (dotimes (i key-len)
         (setf (aref k-prime i) (aref key i)))))

    ;; Compute inner hash: H((K' xor ipad) || message)
    (let* ((inner-data (make-array (+ block-size (length message))
                                   :element-type '(unsigned-byte 8)))
           (ipad #x36))
      ;; K' xor ipad
      (dotimes (i block-size)
        (setf (aref inner-data i) (logxor (aref k-prime i) ipad)))
      ;; Append message
      (dotimes (i (length message))
        (setf (aref inner-data (+ block-size i)) (aref message i)))

      (let ((inner-hash (sha384 inner-data)))

        ;; Compute outer hash: H((K' xor opad) || inner-hash)
        (let* ((outer-data (make-array (+ block-size 48)
                                       :element-type '(unsigned-byte 8)))
               (opad #x5c))
          ;; K' xor opad
          (dotimes (i block-size)
            (setf (aref outer-data i) (logxor (aref k-prime i) opad)))
          ;; Append inner hash
          (dotimes (i 48)
            (setf (aref outer-data (+ block-size i)) (aref inner-hash i)))

          ;; Return final hash
          (sha384 outer-data))))))

;;; Convenience for string key/message
(defun hmac-sha256-string (key-string message-string)
  "Compute HMAC-SHA256 with string key and message."
  (let ((key (make-array (length key-string) :element-type '(unsigned-byte 8)))
        (msg (make-array (length message-string) :element-type '(unsigned-byte 8))))
    (dotimes (i (length key-string))
      (setf (aref key i) (char-code (char key-string i))))
    (dotimes (i (length message-string))
      (setf (aref msg i) (char-code (char message-string i))))
    (hmac-sha256 key msg)))

;;; Test function
(defun hmac-sha256-test ()
  "Test HMAC-SHA256 with RFC 4231 test vectors."
  (format t "~&HMAC-SHA256 test:~%")

  ;; Test Case 1 from RFC 4231
  ;; Key = 0x0b repeated 20 times
  ;; Data = "Hi There" (0x4869205468657265)
  ;; HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  (let* ((key (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b))
         (data (make-array 8 :element-type '(unsigned-byte 8)
                           :initial-contents '(#x48 #x69 #x20 #x54 #x68 #x65 #x72 #x65)))
         (result (hmac-sha256 key data)))
    (format t "  Test 1: ~A~%" (sha256-hex result))
    ;; Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    (when (and (= (aref result 0) #xb0)
               (= (aref result 1) #x34))
      (format t "  Test 1: PASS~%")))

  ;; Test Case 2: "Jefe" / "what do ya want for nothing?"
  ;; HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
  (let* ((result (hmac-sha256-string "Jefe" "what do ya want for nothing?")))
    (format t "  Test 2: ~A~%" (sha256-hex result))
    (when (and (= (aref result 0) #x5b)
               (= (aref result 1) #xdc))
      (format t "  Test 2: PASS~%")))

  t)
