;;;; SHA-256 implementation for Movitz
;;;; Based on FIPS 180-4
;;;; Uses 16-bit arithmetic internally to stay within 30-bit fixnum limit

(require :muerte/basic-macros)
(provide :lib/crypto/sha256)

(in-package muerte)

;;; SHA-256 needs 32-bit arithmetic but Movitz has 30-bit fixnums.
;;; We represent 32-bit values as pairs: (high16 . low16)

(defun make-u32 (hi lo)
  "Create a 32-bit value from two 16-bit halves."
  (cons (logand hi #xffff) (logand lo #xffff)))

(defun u32-hi (u)
  "Get high 16 bits of u32."
  (car u))

(defun u32-lo (u)
  "Get low 16 bits of u32."
  (cdr u))

(defun u32-from-int (n)
  "Convert integer to u32 pair."
  (make-u32 (logand (ash n -16) #xffff) (logand n #xffff)))

(defun u32-to-int (u)
  "Convert u32 pair to integer (may overflow for large values)."
  (logior (ash (u32-hi u) 16) (u32-lo u)))

(defun u32+ (a b)
  "Add two u32 values."
  (let* ((lo (+ (u32-lo a) (u32-lo b)))
         (carry (ash lo -16))
         (hi (+ (u32-hi a) (u32-hi b) carry)))
    (make-u32 hi lo)))

(defun u32-xor (a b)
  "XOR two u32 values."
  (make-u32 (logxor (u32-hi a) (u32-hi b))
            (logxor (u32-lo a) (u32-lo b))))

(defun u32-and (a b)
  "AND two u32 values."
  (make-u32 (logand (u32-hi a) (u32-hi b))
            (logand (u32-lo a) (u32-lo b))))

(defun u32-not (a)
  "NOT a u32 value."
  (make-u32 (logxor (u32-hi a) #xffff)
            (logxor (u32-lo a) #xffff)))

(defun u32-rotr (x n)
  "Right rotate u32 by N bits (0 < N < 32)."
  (let ((hi (u32-hi x))
        (lo (u32-lo x)))
    (cond
      ((zerop n) x)
      ((< n 16)
       ;; Rotate by less than 16 bits
       (let ((mask (1- (ash 1 n))))
         (make-u32 (logior (ash hi (- n)) (ash (logand lo mask) (- 16 n)))
                   (logior (ash lo (- n)) (ash (logand hi mask) (- 16 n))))))
      ((= n 16)
       ;; Swap halves
       (make-u32 lo hi))
      (t
       ;; Rotate by more than 16 bits = swap + rotate by (n-16)
       (let ((m (- n 16))
             (mask (1- (ash 1 (- n 16)))))
         (make-u32 (logior (ash lo (- m)) (ash (logand hi mask) (- 16 m)))
                   (logior (ash hi (- m)) (ash (logand lo mask) (- 16 m)))))))))

(defun u32-shr (x n)
  "Right shift u32 by N bits."
  (let ((hi (u32-hi x))
        (lo (u32-lo x)))
    (cond
      ((zerop n) x)
      ((< n 16)
       (make-u32 (ash hi (- n))
                 (logior (ash lo (- n)) (ash (logand hi (1- (ash 1 n))) (- 16 n)))))
      ((= n 16)
       (make-u32 0 hi))
      ((< n 32)
       (make-u32 0 (ash hi (- 16 n))))
      (t (make-u32 0 0)))))

;;; SHA-256 Constants (first 32 bits of fractional parts of cube roots of first 64 primes)
(defun sha256-k (i)
  "Get K constant for round I."
  (aref #((#x428a . #x2f98) (#x7137 . #x4491) (#xb5c0 . #xfbcf) (#xe9b5 . #xdba5)
          (#x3956 . #xc25b) (#x59f1 . #x11f1) (#x923f . #x82a4) (#xab1c . #x5ed5)
          (#xd807 . #xaa98) (#x1283 . #x5b01) (#x2431 . #x85be) (#x550c . #x7dc3)
          (#x72be . #x5d74) (#x80de . #xb1fe) (#x9bdc . #x06a7) (#xc19b . #xf174)
          (#xe49b . #x69c1) (#xefbe . #x4786) (#x0fc1 . #x9dc6) (#x240c . #xa1cc)
          (#x2de9 . #x2c6f) (#x4a74 . #x84aa) (#x5cb0 . #xa9dc) (#x76f9 . #x88da)
          (#x983e . #x5152) (#xa831 . #xc66d) (#xb003 . #x27c8) (#xbf59 . #x7fc7)
          (#xc6e0 . #x0bf3) (#xd5a7 . #x9147) (#x06ca . #x6351) (#x1429 . #x2967)
          (#x27b7 . #x0a85) (#x2e1b . #x2138) (#x4d2c . #x6dfc) (#x5338 . #x0d13)
          (#x650a . #x7354) (#x766a . #x0abb) (#x81c2 . #xc92e) (#x9272 . #x2c85)
          (#xa2bf . #xe8a1) (#xa81a . #x664b) (#xc24b . #x8b70) (#xc76c . #x51a3)
          (#xd192 . #xe819) (#xd699 . #x0624) (#xf40e . #x3585) (#x106a . #xa070)
          (#x19a4 . #xc116) (#x1e37 . #x6c08) (#x2748 . #x774c) (#x34b0 . #xbcb5)
          (#x391c . #x0cb3) (#x4ed8 . #xaa4a) (#x5b9c . #xca4f) (#x682e . #x6ff3)
          (#x748f . #x82ee) (#x78a5 . #x636f) (#x84c8 . #x7814) (#x8cc7 . #x0208)
          (#x90be . #xfffa) (#xa450 . #x6ceb) (#xbef9 . #xa3f7) (#xc671 . #x78f2))
        i))

;;; Initial hash values
(defun sha256-h-init ()
  "Create initial hash state."
  (vector (cons #x6a09 #xe667) (cons #xbb67 #xae85)
          (cons #x3c6e #xf372) (cons #xa54f #xf53a)
          (cons #x510e #x527f) (cons #x9b05 #x688c)
          (cons #x1f83 #xd9ab) (cons #x5be0 #xcd19)))

;;; SHA-256 functions
(defun sha256-ch (x y z)
  "Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)"
  (u32-xor (u32-and x y) (u32-and (u32-not x) z)))

(defun sha256-maj (x y z)
  "Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)"
  (u32-xor (u32-xor (u32-and x y) (u32-and x z)) (u32-and y z)))

(defun sha256-sigma0 (x)
  "Big sigma 0: ROTR2(x) XOR ROTR13(x) XOR ROTR22(x)"
  (u32-xor (u32-xor (u32-rotr x 2) (u32-rotr x 13)) (u32-rotr x 22)))

(defun sha256-sigma1 (x)
  "Big sigma 1: ROTR6(x) XOR ROTR11(x) XOR ROTR25(x)"
  (u32-xor (u32-xor (u32-rotr x 6) (u32-rotr x 11)) (u32-rotr x 25)))

(defun sha256-lsigma0 (x)
  "Little sigma 0: ROTR7(x) XOR ROTR18(x) XOR SHR3(x)"
  (u32-xor (u32-xor (u32-rotr x 7) (u32-rotr x 18)) (u32-shr x 3)))

(defun sha256-lsigma1 (x)
  "Little sigma 1: ROTR17(x) XOR ROTR19(x) XOR SHR10(x)"
  (u32-xor (u32-xor (u32-rotr x 17) (u32-rotr x 19)) (u32-shr x 10)))

;;; Message schedule array
(defun sha256-expand-block (block w)
  "Expand 16-word block into 64-word message schedule W."
  ;; First 16 words come from the block (big-endian)
  (dotimes (i 16)
    (let ((j (* i 4)))
      (setf (aref w i)
            (make-u32 (logior (ash (aref block j) 8) (aref block (+ j 1)))
                      (logior (ash (aref block (+ j 2)) 8) (aref block (+ j 3)))))))
  ;; Remaining 48 words are computed
  (do ((i 16 (1+ i)))
      ((>= i 64))
    (setf (aref w i)
          (u32+ (u32+ (sha256-lsigma1 (aref w (- i 2)))
                      (aref w (- i 7)))
                (u32+ (sha256-lsigma0 (aref w (- i 15)))
                      (aref w (- i 16)))))))

;;; Process one 512-bit (64-byte) block
(defun sha256-process-block (block h w)
  "Process one block, updating hash state H. W is workspace."
  (sha256-expand-block block w)

  ;; Initialize working variables
  (let ((a (aref h 0))
        (b (aref h 1))
        (c (aref h 2))
        (d (aref h 3))
        (e (aref h 4))
        (f (aref h 5))
        (g (aref h 6))
        (hh (aref h 7)))

    ;; 64 rounds
    (dotimes (i 64)
      (let* ((t1 (u32+ (u32+ hh (sha256-sigma1 e))
                       (u32+ (sha256-ch e f g)
                             (u32+ (sha256-k i) (aref w i)))))
             (t2 (u32+ (sha256-sigma0 a) (sha256-maj a b c))))
        (setf hh g
              g f
              f e
              e (u32+ d t1)
              d c
              c b
              b a
              a (u32+ t1 t2))))

    ;; Add to hash state
    (setf (aref h 0) (u32+ (aref h 0) a)
          (aref h 1) (u32+ (aref h 1) b)
          (aref h 2) (u32+ (aref h 2) c)
          (aref h 3) (u32+ (aref h 3) d)
          (aref h 4) (u32+ (aref h 4) e)
          (aref h 5) (u32+ (aref h 5) f)
          (aref h 6) (u32+ (aref h 6) g)
          (aref h 7) (u32+ (aref h 7) hh))))

;;; Padding
(defun sha256-pad-message (message)
  "Pad message according to SHA-256 spec. Returns padded byte vector."
  (let* ((msg-len (length message))
         (msg-bits (* msg-len 8))
         ;; Padded length: msg + 1 byte (0x80) + zeros + 8 bytes (length)
         ;; Must be multiple of 64 bytes
         (pad-len (let ((m (mod (+ msg-len 9) 64)))
                    (if (zerop m) 0 (- 64 m))))
         (total-len (+ msg-len 1 pad-len 8))
         (padded (make-array total-len :element-type '(unsigned-byte 8)
                             :initial-element 0)))
    ;; Copy message
    (dotimes (i msg-len)
      (setf (aref padded i) (aref message i)))
    ;; Append 1 bit (as 0x80 byte)
    (setf (aref padded msg-len) #x80)
    ;; Append length as 64-bit big-endian (we only handle <32-bit lengths)
    (setf (aref padded (- total-len 4)) (ldb (byte 8 24) msg-bits)
          (aref padded (- total-len 3)) (ldb (byte 8 16) msg-bits)
          (aref padded (- total-len 2)) (ldb (byte 8 8) msg-bits)
          (aref padded (- total-len 1)) (ldb (byte 8 0) msg-bits))
    padded))

;;; Main SHA-256 function
(defun sha256 (message)
  "Compute SHA-256 hash of MESSAGE (byte vector). Returns 32-byte hash."
  (let ((padded (sha256-pad-message message))
        (h (sha256-h-init))
        (w (make-array 64 :initial-element nil))
        (block (make-array 64 :element-type '(unsigned-byte 8))))

    ;; Process each 64-byte block
    (do ((offset 0 (+ offset 64)))
        ((>= offset (length padded)))
      ;; Copy block
      (dotimes (i 64)
        (setf (aref block i) (aref padded (+ offset i))))
      (sha256-process-block block h w))

    ;; Convert hash state to byte array (big-endian)
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 8)
        (let ((word (aref h i))
              (j (* i 4)))
          (setf (aref result j) (ldb (byte 8 8) (u32-hi word))
                (aref result (+ j 1)) (ldb (byte 8 0) (u32-hi word))
                (aref result (+ j 2)) (ldb (byte 8 8) (u32-lo word))
                (aref result (+ j 3)) (ldb (byte 8 0) (u32-lo word)))))
      result)))

;;; Convenience function for strings
(defun sha256-string (string)
  "Compute SHA-256 hash of STRING. Returns 32-byte hash."
  (let ((bytes (make-array (length string) :element-type '(unsigned-byte 8))))
    (dotimes (i (length string))
      (setf (aref bytes i) (char-code (char string i))))
    (sha256 bytes)))

;;; Helper to print hash as hex
(defun sha256-hex (hash)
  "Convert 32-byte hash to hex string."
  (let ((hex-chars "0123456789abcdef")
        (result (make-array 64 :element-type 'character)))
    (dotimes (i 32)
      (let ((byte (aref hash i)))
        (setf (aref result (* i 2)) (aref hex-chars (ash byte -4)))
        (setf (aref result (1+ (* i 2))) (aref hex-chars (logand byte 15)))))
    result))

;;; Test function
(defun sha256-test ()
  "Test SHA-256 with known test vectors."
  (let* ((empty-hash (sha256 (make-array 0 :element-type '(unsigned-byte 8))))
         (abc-hash (sha256-string "abc")))
    (format t "~&SHA-256 test:~%")
    (format t "  empty: ~A~%" (sha256-hex empty-hash))
    (format t "  'abc': ~A~%" (sha256-hex abc-hash))
    ;; Expected:
    ;; empty: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    ;; abc:   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    t))

;; Note: export not available at runtime, symbols are in muerte package
