;;;; Ed25519 implementation for Movitz
;;;; Based on RFC 8032
;;;; Uses same field arithmetic as X25519 (p = 2^255 - 19)
;;;;
;;;; Ed25519 is EdDSA (Edwards-curve Digital Signature Algorithm) on the
;;;; Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2 where d = -121665/121666

(require :muerte/basic-macros)
(require :lib/crypto/x25519)
(require :lib/crypto/sha512)
(provide :lib/crypto/ed25519)

(in-package muerte)

;;; The Ed25519 curve is birational to Curve25519.
;;; Ed25519: -x^2 + y^2 = 1 + d*x^2*y^2
;;; d = -121665/121666 mod p
;;;
;;; Points are represented in extended coordinates (X, Y, Z, T) where
;;; x = X/Z, y = Y/Z, x*y = T/Z
;;; This allows efficient addition without inversions.

;;; The base point B (generator) has order L where:
;;; L = 2^252 + 27742317777372353535851937790883648493
;;; B.y = 4/5 mod p (or equivalently the compressed form)

;;; d = -121665/121666 mod p
;;; We compute this as -121665 * inv(121666)
(defvar *ed25519-d* nil "Curve parameter d")

;;; Base point B in extended coordinates
(defvar *ed25519-base-x* nil)
(defvar *ed25519-base-y* nil)

;;; Identity point (0, 1) in extended coordinates
(defun ed-identity ()
  "Return the identity point (neutral element) in extended coords."
  (list (fe-from-int 0)   ; X = 0
        (fe-from-int 1)   ; Y = 1
        (fe-from-int 1)   ; Z = 1
        (fe-from-int 0))) ; T = 0

;;; Initialize curve parameters
(defun ed25519-init ()
  "Initialize Ed25519 curve parameters."
  (unless *ed25519-d*
    (format t "~&  ED25519-INIT: computing d = -121665/121666...")
    (multiple-value-bind (t0-lo t0-hi) (read-time-stamp-counter)
      ;; d = -121665/121666 mod p
      ;; = -121665 * inv(121666) mod p
      (let* ((neg-121665 (fe-sub (fe-from-int 0) (fe-from-int 121665)))
             (inv-121666 (fe-invert (fe-from-int 121666))))
        (setf *ed25519-d* (fe-mul neg-121665 inv-121666)))
      (multiple-value-bind (t1-lo t1-hi) (read-time-stamp-counter)
        (format t " ~D cycles~%" (+ (- t1-lo t0-lo) (* (- t1-hi t0-hi) 536870912)))))

    ;; Base point B - use hardcoded values for correctness
    ;; y = 4/5 mod p = 5866666666...66 (little-endian hex)
    ;; x recovered with even sign = 1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921
    (setf *ed25519-base-y*
          (fe-from-bytes
           (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents
                       '(#x58 #x66 #x66 #x66 #x66 #x66 #x66 #x66
                         #x66 #x66 #x66 #x66 #x66 #x66 #x66 #x66
                         #x66 #x66 #x66 #x66 #x66 #x66 #x66 #x66
                         #x66 #x66 #x66 #x66 #x66 #x66 #x66 #x66))))
    (setf *ed25519-base-x*
          (fe-from-bytes
           (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents
                       '(#x1a #xd5 #x25 #x8f #x60 #x2d #x56 #xc9
                         #xb2 #xa7 #x25 #x95 #x60 #xc7 #x2c #x69
                         #x5c #xdc #xd6 #xfd #x31 #xe2 #xa4 #xc0
                         #xfe #x53 #x6e #xcd #xd3 #x36 #x69 #x21))))))

;;; Recover x coordinate from y coordinate
(defun ed-recover-x (y sign)
  "Recover x from y coordinate on Ed25519 curve.
   SIGN: NIL for even x (x mod 2 = 0), T for odd x."
  ;; On the curve: -x^2 + y^2 = 1 + d*x^2*y^2
  ;; Rearranging: x^2 = (y^2 - 1) / (d*y^2 + 1)
  (let* ((y2 (fe-sq y))
         (y2-1 (fe-sub y2 (fe-from-int 1)))
         (dy2 (fe-mul *ed25519-d* y2))
         (dy2-plus-1 (fe-add dy2 (fe-from-int 1)))
         (u (fe-mul y2-1 (fe-invert dy2-plus-1)))
         ;; x = u^((p+3)/8) mod p
         (x (fe-pow-sqrt u)))
    (format t "~&ED-RECOVER-X: u[0:4]=")
    (let ((u-bytes (fe-to-bytes u)))
      (dotimes (i 4) (format t "~2,'0X" (aref u-bytes i))))
    (format t "~%")
    (format t "~&ED-RECOVER-X: sqrt[0:4]=")
    (let ((x-bytes (fe-to-bytes x)))
      (dotimes (i 4) (format t "~2,'0X" (aref x-bytes i))))
    (format t "~%")
    ;; Check if x^2 = u, otherwise multiply by sqrt(-1)
    (let ((x2 (fe-sq x)))
      (format t "~&ED-RECOVER-X: x^2=u? ~A~%" (fe-equal x2 u))
      (unless (fe-equal x2 u)
        (setf x (fe-mul x (fe-sqrt-minus-1)))
        (format t "~&ED-RECOVER-X: after *sqrt(-1): x[0:4]=")
        (let ((x-bytes (fe-to-bytes x)))
          (dotimes (i 4) (format t "~2,'0X" (aref x-bytes i))))
        (format t "~%")))
    ;; Adjust sign if needed
    (let ((x-bytes (fe-to-bytes x)))
      (when (if sign
                (= (logand (aref x-bytes 0) 1) 0)  ; want odd but got even
                (= (logand (aref x-bytes 0) 1) 1)) ; want even but got odd
        (setf x (fe-sub (fe-from-int 0) x))))
    x))

;;; Compute u^((p+3)/8) for square root using binary exponentiation
(defun fe-pow-sqrt (u)
  "Compute u^((p+3)/8) mod p for finding square roots."
  ;; (p+3)/8 = 2^252 - 2
  ;; Use square-and-multiply with pre-computed powers
  ;;
  ;; Strategy: compute u^(2^252 - 2) = u^(2^252) / u^2
  ;; Since u^(2^252) = u^(2^252 mod (p-1)) and p-1 = 2^255 - 20,
  ;; we can compute directly via 252 squarings then divide by u^2.
  ;;
  ;; But simpler: 2^252 - 2 = 2*(2^251 - 1)
  ;; So u^(2^252 - 2) = (u^2)^(2^251 - 1)
  ;;
  ;; Even simpler: just use addition chain for 2^252 - 2
  ;; 2^252 - 2 in binary is 251 ones followed by a zero
  ;; = 1111...1110 (251 ones, 1 zero)

  ;; Use efficient addition chain:
  ;; First compute u^(2^k - 1) for various k, then combine
  (let* ((u1 u)
         (u2 (fe-sq u1))           ; u^2
         (u3 (fe-mul u1 u2))       ; u^3 = u^(2^2 - 1)
         (u6 (fe-sq u3))
         (u7 (fe-mul u1 u6))       ; u^7
         (u14 (fe-sq u7))
         (u15 (fe-mul u1 u14))     ; u^15 = u^(2^4 - 1)
         ;; Compute u^(2^8 - 1) = u^255
         (t0 u15))
    (dotimes (i 4) (setf t0 (fe-sq t0)))  ; u^(15 * 16) = u^240
    (setf t0 (fe-mul t0 u15))             ; u^255 = u^(2^8 - 1)

    ;; Compute u^(2^16 - 1)
    (let ((u255 t0))
      (dotimes (i 8) (setf t0 (fe-sq t0)))
      (setf t0 (fe-mul t0 u255)))         ; u^(2^16 - 1)

    ;; Compute u^(2^32 - 1)
    (let ((u16 t0))
      (dotimes (i 16) (setf t0 (fe-sq t0)))
      (setf t0 (fe-mul t0 u16)))          ; u^(2^32 - 1)

    ;; Compute u^(2^64 - 1)
    (let ((u32 t0))
      (dotimes (i 32) (setf t0 (fe-sq t0)))
      (setf t0 (fe-mul t0 u32)))          ; u^(2^64 - 1)

    ;; Compute u^(2^128 - 1)
    (let ((u64 t0))
      (dotimes (i 64) (setf t0 (fe-sq t0)))
      (setf t0 (fe-mul t0 u64)))          ; u^(2^128 - 1)

    ;; Compute u^(2^251 - 1)
    ;; From u^(2^128 - 1), square 123 times to get u^((2^128-1)*2^123)
    ;; = u^(2^251 - 2^123)
    ;; Then multiply by u^(2^123 - 1) but we don't have that precomputed
    ;;
    ;; Alternative: continue doubling pattern
    ;; Actually let's just square 123 more times and multiply by appropriate power

    ;; Better approach: from u^(2^128 - 1), get to u^(2^252 - 2)
    ;; u^(2^252 - 2) = u^(2*(2^251 - 1)) = (u^(2^251 - 1))^2
    ;;
    ;; u^(2^251 - 1) = u^(2^128 - 1) * u^(2^251 - 2^128)
    ;;              = u^(2^128 - 1) * (u^(2^128))^(2^123 - 1)
    ;; This gets complicated. Let's use direct squaring.

    ;; Simple approach: square 123 times then deal with remainder
    (let ((u128 t0))
      (dotimes (i 123) (setf t0 (fe-sq t0))) ; u^((2^128-1)*2^123) = u^(2^251 - 2^123)
      ;; Need to multiply by u^(2^123 - 1)
      ;; 2^123 - 1 = 2^64 * (2^59 - 1) + 2^64 - 1 + 2^59
      ;; This is getting complex. Let me use a different strategy.
      )

    ;; Actually, simplest correct approach: binary exponentiation
    ;; exp = 2^252 - 2 = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
    ;; Just iterate through bits
    (setf t0 (fe-from-int 1))
    (let ((base u)
          ;; 2^252 - 2 in little-endian nibbles (each nibble is 4 bits)
          ;; = FE FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
          ;;   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 0F
          (exp-nibbles #(#xE #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #xF
                         #xF #xF #xF #xF #xF #xF #xF #x0)))
      (dotimes (nibble-idx 64)
        (let ((nibble (aref exp-nibbles nibble-idx)))
          (dotimes (bit-idx 4)
            (when (logbitp bit-idx nibble)
              (setf t0 (fe-mul t0 base)))
            (setf base (fe-sq base))))))
    t0))

;;; sqrt(-1) mod p
(defun fe-sqrt-minus-1 ()
  "Return sqrt(-1) mod p."
  ;; sqrt(-1) = 2^((p-1)/4) mod p
  ;; = 2^(2^253 - 5)
  ;; Precomputed value:
  ;; 2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
  (fe-from-bytes
   (make-array 32 :element-type '(unsigned-byte 8)
               :initial-contents
               '(#xb0 #xa0 #x0e #x4a #x27 #x1b #xee #xc4
                 #x78 #xe4 #x2f #xad #x06 #x18 #x43 #x2f
                 #xa7 #xd7 #xfb #x3d #x99 #x00 #x4d #x2b
                 #x0b #xdf #xc1 #x4f #x80 #x24 #x83 #x2b))))

;;; Field element equality
(defun fe-equal (a b)
  "Check if two field elements are equal."
  (let ((a-bytes (fe-to-bytes (fe-reduce (fe-carry a))))
        (b-bytes (fe-to-bytes (fe-reduce (fe-carry b)))))
    (let ((equal t))
      (dotimes (i 32)
        (when (/= (aref a-bytes i) (aref b-bytes i))
          (setf equal nil)))
      equal)))

;;; Point doubling in extended coordinates
;;; For Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2 (a = -1)
;;; Using formulas from hyperelliptic.org/EFD/g1p/auto-twisted-extended.html
(defun ed-double (p)
  "Double a point on Ed25519 in extended coordinates."
  (let ((x1 (first p))
        (y1 (second p))
        (z1 (third p)))
    (let* ((a (fe-sq x1))              ; A = X1^2
           (b (fe-sq y1))              ; B = Y1^2
           (c2 (fe-sq z1))             ; temporary
           (c (fe-add c2 c2))          ; C = 2*Z1^2
           (d (fe-sub (fe-from-int 0) a))  ; D = a*A = -A (a=-1 for ed25519)
           (xy1 (fe-add x1 y1))
           (e (fe-sub (fe-sub (fe-sq xy1) a) b))  ; E = (X1+Y1)^2 - A - B
           (g (fe-add d b))            ; G = D + B
           (f (fe-sub g c))            ; F = G - C
           (h (fe-sub d b))            ; H = D - B
           (x3 (fe-mul e f))           ; X3 = E*F
           (y3 (fe-mul g h))           ; Y3 = G*H
           (t3 (fe-mul e h))           ; T3 = E*H
           (z3 (fe-mul f g)))          ; Z3 = F*G
      (list x3 y3 z3 t3))))

;;; Point addition in extended coordinates
(defun ed-add (p q)
  "Add two points on Ed25519 in extended coordinates."
  (let ((x1 (first p)) (y1 (second p)) (z1 (third p)) (t1 (fourth p))
        (x2 (first q)) (y2 (second q)) (z2 (third q)) (t2 (fourth q)))
    (let* ((a (fe-mul (fe-sub y1 x1) (fe-sub y2 x2)))
           (b (fe-mul (fe-add y1 x1) (fe-add y2 x2)))
           ;; k = 2*d
           (k (fe-add *ed25519-d* *ed25519-d*))
           (c (fe-mul (fe-mul t1 k) t2))
           (d (fe-mul z1 z2))
           (d2 (fe-add d d))
           (e (fe-sub b a))
           (f (fe-sub d2 c))
           (g (fe-add d2 c))
           (h (fe-add b a))
           (x3 (fe-mul e f))
           (y3 (fe-mul g h))
           (t3 (fe-mul e h))
           (z3 (fe-mul f g)))
      (list x3 y3 z3 t3))))

;;; Scalar multiplication using double-and-add
(defvar *scalar-mult-progress* t
  "Print progress dots during scalar multiplication")

(defun ed-scalar-mult (s p)
  "Multiply point P by scalar S (256-bit byte array) on Ed25519."
  (ed25519-init)
  (let ((result (ed-identity))
        (temp (list (first p) (second p) (third p) (fourth p)))
        (adds 0)
        (bit-count 0))
    ;; Process bits from low to high with progress every 64 bits
    (dotimes (byte-idx 32)
      (let ((byte (aref s byte-idx)))
        (dotimes (bit-idx 8)
          (when (logbitp bit-idx byte)
            (setf result (ed-add result temp))
            (incf adds))
          (setf temp (ed-double temp))
          (incf bit-count)
          (when (and *scalar-mult-progress*
                     (zerop (mod bit-count 64)))
            (format t ".")))))
    (when *scalar-mult-progress*
      (format t "(~D adds)" adds))
    result))

;;; Convert extended coordinates to affine (x, y)
(defun ed-to-affine (p)
  "Convert extended coordinates to affine (x, y)."
  (let ((x (first p))
        (y (second p))
        (z (third p)))
    (let ((z-inv (fe-invert z)))
      (list (fe-mul x z-inv)
            (fe-mul y z-inv)))))

;;; Encode a point (compressed format: just y with x sign in high bit)
(defun ed-encode-point (p)
  "Encode Ed25519 point in compressed format (32 bytes)."
  (let* ((affine (ed-to-affine p))
         (x (first affine))
         (y (second affine))
         (y-bytes (fe-to-bytes y))
         (x-bytes (fe-to-bytes x)))
    ;; Set high bit of y to sign of x (x mod 2)
    (setf (aref y-bytes 31)
          (logior (aref y-bytes 31)
                  (ash (logand (aref x-bytes 0) 1) 7)))
    y-bytes))

;;; Decode a compressed point
(defun ed-decode-point (bytes)
  "Decode Ed25519 point from compressed format."
  (ed25519-init)
  (let* ((y-bytes (make-array 32 :element-type '(unsigned-byte 8)))
         (x-sign (logbitp 7 (aref bytes 31))))
    ;; Copy y, clearing the sign bit
    (dotimes (i 32)
      (setf (aref y-bytes i) (aref bytes i)))
    (setf (aref y-bytes 31) (logand (aref y-bytes 31) #x7f))
    (let* ((y (fe-from-bytes y-bytes))
           (x (ed-recover-x y x-sign)))
      (format t "~&ED-DECODE: sign=~A, y[0:4]=~2,'0X~2,'0X~2,'0X~2,'0X, x[0:4]="
              x-sign (aref y-bytes 0) (aref y-bytes 1) (aref y-bytes 2) (aref y-bytes 3))
      (let ((x-enc (fe-to-bytes x)))
        (format t "~2,'0X~2,'0X~2,'0X~2,'0X~%"
                (aref x-enc 0) (aref x-enc 1) (aref x-enc 2) (aref x-enc 3)))
      ;; Return in extended coordinates
      (list x y (fe-from-int 1) (fe-mul x y)))))

;;; Base point multiplication
(defun ed-base-mult (s)
  "Multiply base point B by scalar S."
  (ed25519-init)
  (let ((base (list *ed25519-base-x*
                    *ed25519-base-y*
                    (fe-from-int 1)
                    (fe-mul *ed25519-base-x* *ed25519-base-y*))))
    (ed-scalar-mult s base)))

;;; Reduce a 64-byte hash modulo L (the group order)
;;; L = 2^252 + 27742317777372353535851937790883648493
(defun ed-reduce-scalar (hash)
  "Reduce 64-byte hash to scalar mod L."
  (ed-reduce-scalar-fast hash))

;;; Slow but correct reduction (for testing)
(defun ed-reduce-scalar-slow (hash)
  "Reduce 64-byte hash to scalar mod L (slow, ~64 iterations)."
  (ed-reduce-512-mod-l hash))

;;; L in little-endian bytes
(defvar *ed25519-l-bytes*
  #(#xed #xd3 #xf5 #x5c #x1a #x63 #x12 #x58
    #xd6 #x9c #xf7 #xa2 #xde #xf9 #xde #x14
    #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x00
    #x00 #x00 #x00 #x00 #x00 #x00 #x00 #x10))

;;; c = L - 2^252 (the small constant, 125 bits, stored in 16 bytes)
;;; Used for fast reduction: 2^252 ≡ -c (mod L)
(defvar *ed25519-c-bytes*
  #(#xed #xd3 #xf5 #x5c #x1a #x63 #x12 #x58
    #xd6 #x9c #xf7 #xa2 #xde #xf9 #xde #x14))

;;; Fast scalar reduction uses local buffers (created in let bindings)
;;; This is much faster than defvar globals due to stack vs symbol lookup

(defun ed-reduce-scalar-fast (hash)
  "Reduce 64-byte hash to scalar mod L using local buffers."
  ;; Use local buffers to avoid defvar access overhead
  (let ((x-buf (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0))
        (xlow-buf (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (xhigh-buf (make-array 36 :element-type '(unsigned-byte 8) :initial-element 0))
        (prod-buf (make-array 52 :element-type '(unsigned-byte 8) :initial-element 0))
        (out-buf (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (c-bytes *ed25519-c-bytes*)
        (l-bytes *ed25519-l-bytes*)
        (negated nil))

    ;; Copy input to x buffer
    (dotimes (i 64)
      (setf (aref x-buf i) (aref hash i)))

    ;; Iterate reduction
    (dotimes (iter 10)
      (declare (ignore iter))
      ;; Check if x fits in 252 bits
      (let ((fits t))
        (loop for i from 32 below 64
              when (> (aref x-buf i) 0)
              do (setf fits nil) (return))
        (when (and fits (>= (aref x-buf 31) #x10))
          (setf fits nil))
        (when fits (return)))

      ;; Clear product buffer
      (dotimes (i 52)
        (setf (aref prod-buf i) 0))

      ;; Extract x_low (low 252 bits)
      (dotimes (i 31)
        (setf (aref xlow-buf i) (aref x-buf i)))
      (setf (aref xlow-buf 31) (logand (aref x-buf 31) #x0f))

      ;; Extract x_high (bits 252+)
      (dotimes (i 33)
        (let* ((src (+ 31 i))
               (lo (if (< src 64)
                       (ash (aref x-buf src) -4)
                       0))
               (hi (if (< (1+ src) 64)
                       (logand (ash (aref x-buf (1+ src)) 4) #xf0)
                       0)))
          (setf (aref xhigh-buf i) (logior lo hi))))

      ;; Compute product = x_high * c
      (dotimes (i 33)
        (let ((hi-byte (aref xhigh-buf i)))
          (when (> hi-byte 0)
            (let ((carry 0))
              (dotimes (j 16)
                (let* ((k (+ i j))
                       (c-byte (aref c-bytes j))
                       (p-byte (aref prod-buf k))
                       (prod (+ (* hi-byte c-byte) p-byte carry)))
                  (setf (aref prod-buf k) (logand prod #xff))
                  (setf carry (ash prod -8))))
              (loop for k from (+ i 16) below 50
                    while (> carry 0)
                    do (let* ((p-byte (aref prod-buf k))
                              (s (+ p-byte carry)))
                         (setf (aref prod-buf k) (logand s #xff))
                         (setf carry (ash s -8))))))))

      ;; Compare x_low vs product
      (let ((x-low-ge-product t))
        (loop for i from 49 downto 0
              do (let ((p-byte (aref prod-buf i))
                       (xl-byte (if (< i 32) (aref xlow-buf i) 0)))
                   (cond
                     ((> p-byte xl-byte) (setf x-low-ge-product nil) (return))
                     ((< p-byte xl-byte) (return)))))

        ;; Compute x = |x_low - product| and track sign
        (let ((borrow 0))
          ;; Zero x first
          (dotimes (i 64)
            (setf (aref x-buf i) 0))

          (if x-low-ge-product
              ;; x_low >= product
              (dotimes (i 50)
                (let* ((xl-byte (if (< i 32) (aref xlow-buf i) 0))
                       (p-byte (aref prod-buf i))
                       (diff (- xl-byte p-byte borrow)))
                  (if (< diff 0)
                      (progn
                        (setf (aref x-buf i) (+ diff 256))
                        (setf borrow 1))
                      (progn
                        (setf (aref x-buf i) diff)
                        (setf borrow 0)))))
              ;; product > x_low, flip sign
              (progn
                (setf negated (not negated))
                (dotimes (i 50)
                  (let* ((xl-byte (if (< i 32) (aref xlow-buf i) 0))
                         (p-byte (aref prod-buf i))
                         (diff (- p-byte xl-byte borrow)))
                    (if (< diff 0)
                        (progn
                          (setf (aref x-buf i) (+ diff 256))
                          (setf borrow 1))
                        (progn
                          (setf (aref x-buf i) diff)
                          (setf borrow 0))))))))))

    ;; x now fits in 252 bits. Copy to output region and do final reduction.
    (dotimes (i 32)
      (setf (aref out-buf i) (aref x-buf i)))

    ;; Subtract L while out >= L
    (loop
      (let ((ge-l t))
        (loop for i from 31 downto 0
              do (let ((out-byte (aref out-buf i))
                       (l-byte (aref l-bytes i)))
                   (cond
                     ((> out-byte l-byte) (return))
                     ((< out-byte l-byte) (setf ge-l nil) (return)))))
        (unless ge-l (return)))
      (let ((borrow 0))
        (dotimes (i 32)
          (let* ((out-byte (aref out-buf i))
                 (diff (- out-byte (aref l-bytes i) borrow)))
            (if (< diff 0)
                (progn
                  (setf (aref out-buf i) (+ diff 256))
                  (setf borrow 1))
                (progn
                  (setf (aref out-buf i) diff)
                  (setf borrow 0)))))))

    ;; If negated, compute L - out
    (when negated
      (let ((is-zero t))
        (dotimes (i 32)
          (when (/= (aref out-buf i) 0)
            (setf is-zero nil)
            (return)))
        (unless is-zero
          (let ((borrow 0))
            (dotimes (i 32)
              (let* ((out-byte (aref out-buf i))
                     (diff (- (aref l-bytes i) out-byte borrow)))
                (if (< diff 0)
                    (progn
                      (setf (aref out-buf i) (+ diff 256))
                      (setf borrow 1))
                    (progn
                      (setf (aref out-buf i) diff)
                      (setf borrow 0)))))))))

    ;; Copy result to new array for return
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32)
        (setf (aref out i) (aref out-buf i)))
      out)))

;;; Reduction coefficients: 2^(256+64*i) mod L for i = 0..3
;;; Each coefficient is 32 bytes, little-endian
(defvar *ed25519-reduce-coeffs*
  #(;; 2^256 mod L
    #(#x1d #x95 #x98 #x8d #x74 #x31 #xec #xd6
      #x70 #xcf #x7d #x73 #xf4 #x5b #xef #xc6
      #xfe #xff #xff #xff #xff #xff #xff #xff
      #xff #xff #xff #xff #xff #xff #xff #x0f)
    ;; 2^320 mod L
    #(#xed #xd3 #xf5 #x5c #x1a #x63 #x12 #x58
      #x06 #x5e #x9a #xd3 #x38 #xc8 #xb8 #x93
      #x9a #x32 #x86 #xd0 #x15 #x62 #x10 #xb2
      #xfe #xff #xff #xff #xff #xff #xff #x0f)
    ;; 2^384 mod L
    #(#x71 #x62 #x2a #xa0 #x29 #x21 #x82 #x39
      #x95 #xdd #x4f #x5e #x43 #x7f #x4a #xb6
      #x31 #xc1 #xa2 #x30 #x5a #xce #xd9 #x7e
      #x9a #x32 #x86 #xd0 #x15 #x62 #x10 #x02)
    ;; 2^448 mod L
    #(#x65 #xcb #x0a #xa0 #x20 #xf5 #xda #x79
      #xa9 #xd7 #xd1 #x38 #xbe #xab #x4b #xe2
      #x3d #x9a #x30 #x7c #x1b #x41 #x99 #xb3
      #x31 #xc1 #xa2 #x30 #x5a #xce #xd9 #x0e)))

(defun ed-reduce-512-mod-l (x-bytes)
  "Reduce 512-bit X mod L using iterative folding.
   Uses 2^256 mod L to fold high bytes into low bytes."
  ;; Strategy: repeatedly compute x = low256 + high * (2^256 mod L)
  ;; until x fits in 256 bits. This takes ~64 iterations because
  ;; each fold only reduces the value by ~4 bits.

  ;; coeff0 = 2^256 mod L
  (let ((coeff0 (aref *ed25519-reduce-coeffs* 0))
        ;; 40-byte work buffer (enough for 320-bit intermediate)
        (work (make-array 40 :element-type '(unsigned-byte 8) :initial-element 0)))

    ;; First round: process 512-bit input using all 4 coefficients
    (dotimes (i 32)
      (setf (aref work i) (aref x-bytes i)))

    (dotimes (chunk 4)
      (dotimes (mi 8)
        (let ((m-byte (aref x-bytes (+ 32 (* chunk 8) mi))))
          (when (> m-byte 0)
            (let ((coeff (aref *ed25519-reduce-coeffs* chunk))
                  (carry 0))
              (dotimes (j 32)
                (let* ((k (+ mi j))
                       (prod (+ (* m-byte (aref coeff j))
                                (if (< k 40) (aref work k) 0)
                                carry)))
                  (when (< k 40)
                    (setf (aref work k) (logand prod #xff)))
                  (setf carry (ash prod -8))))
              ;; Propagate carry
              (loop for k from (+ mi 32) below 40
                    while (> carry 0)
                    do (let ((s (+ (aref work k) carry)))
                         (setf (aref work k) (logand s #xff))
                         (setf carry (ash s -8)))))))))

    ;; Continue folding until high bytes are zero
    ;; Each iteration: work = work[0:32] + work[32:40] * coeff0
    (dotimes (iter 80)  ; Max 80 iterations to be safe
      ;; Check if high bytes are all zero
      (let ((high-zero t))
        (loop for i from 32 below 40
              when (> (aref work i) 0) do (setf high-zero nil) (return))
        (when high-zero (return)))

      ;; Fold: new = low + high * coeff0
      (let ((new-work (make-array 40 :element-type '(unsigned-byte 8) :initial-element 0)))
        (dotimes (i 32)
          (setf (aref new-work i) (aref work i)))

        ;; Multiply work[32:40] by coeff0 and add to new-work
        (dotimes (mi 8)
          (let ((m-byte (aref work (+ 32 mi))))
            (when (> m-byte 0)
              (let ((carry 0))
                (dotimes (j 32)
                  (let* ((k (+ mi j))
                         (prod (+ (* m-byte (aref coeff0 j))
                                  (if (< k 40) (aref new-work k) 0)
                                  carry)))
                    (when (< k 40)
                      (setf (aref new-work k) (logand prod #xff)))
                    (setf carry (ash prod -8))))
                ;; Propagate carry
                (loop for k from (+ mi 32) below 40
                      while (> carry 0)
                      do (let ((s (+ (aref new-work k) carry)))
                           (setf (aref new-work k) (logand s #xff))
                           (setf carry (ash s -8))))))))

        ;; Copy back
        (dotimes (i 40)
          (setf (aref work i) (aref new-work i)))))

    ;; Extract 32-byte output and do final reduction
    (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
      (dotimes (i 32)
        (setf (aref out i) (aref work i)))

      ;; Subtract L while out >= L
      (loop
        ;; Compare out with L from high byte to low
        (let ((cmp 0))
          (loop for i from 31 downto 0
                when (/= (aref out i) (aref *ed25519-l-bytes* i))
                do (setf cmp (if (> (aref out i) (aref *ed25519-l-bytes* i)) 1 -1))
                   (return))
          ;; If out < L, we're done
          (when (< cmp 0)
            (return))
          ;; out >= L, subtract L
          (let ((borrow 0))
            (dotimes (i 32)
              (let ((diff (- (aref out i) (aref *ed25519-l-bytes* i) borrow)))
                (if (< diff 0)
                    (progn
                      (setf (aref out i) (+ diff 256))
                      (setf borrow 1))
                    (progn
                      (setf (aref out i) diff)
                      (setf borrow 0))))))))
      out)))

;;; Generate Ed25519 public key from private key
(defun ed25519-public-key (private-key)
  "Generate Ed25519 public key from 32-byte private key."
  ;; Hash private key with SHA-512
  (format t "~&    SHA-512...")
  (multiple-value-bind (t0-lo t0-hi) (read-time-stamp-counter)
    (let* ((hash (sha512 private-key))
           (s (make-array 32 :element-type '(unsigned-byte 8))))
      (multiple-value-bind (t1-lo t1-hi) (read-time-stamp-counter)
        (format t " ~D cycles~%" (+ (- t1-lo t0-lo) (* (- t1-hi t0-hi) 536870912))))
      ;; Take first 32 bytes and clamp
      (dotimes (i 32)
        (setf (aref s i) (aref hash i)))
      ;; Clamp: clear bits 0,1,2 of first byte, set bit 254, clear bit 255
      (setf (aref s 0) (logand (aref s 0) #xf8))
      (setf (aref s 31) (logand (aref s 31) #x7f))
      (setf (aref s 31) (logior (aref s 31) #x40))
      ;; Compute A = s*B
      (format t "~&    ed-base-mult...")
      (multiple-value-bind (t2-lo t2-hi) (read-time-stamp-counter)
        (let ((point (ed-base-mult s)))
          (multiple-value-bind (t3-lo t3-hi) (read-time-stamp-counter)
            (format t " ~D cycles~%" (+ (- t3-lo t2-lo) (* (- t3-hi t2-hi) 536870912))))
          (format t "~&    ed-encode-point...")
          (multiple-value-bind (t4-lo t4-hi) (read-time-stamp-counter)
            (let ((result (ed-encode-point point)))
              (multiple-value-bind (t5-lo t5-hi) (read-time-stamp-counter)
                (format t " ~D cycles~%" (+ (- t5-lo t4-lo) (* (- t5-hi t4-hi) 536870912))))
              result)))))))

;;; Sign a message with Ed25519
(defun ed25519-sign (private-key message)
  "Sign MESSAGE with Ed25519 private key. Returns 64-byte signature."
  (ed25519-init)
  (let* ((hash (sha512 private-key))
         (s (make-array 32 :element-type '(unsigned-byte 8)))
         (prefix (make-array 32 :element-type '(unsigned-byte 8))))
    ;; First 32 bytes of hash, clamped -> scalar s
    (dotimes (i 32)
      (setf (aref s i) (aref hash i)))
    (setf (aref s 0) (logand (aref s 0) #xf8))
    (setf (aref s 31) (logand (aref s 31) #x7f))
    (setf (aref s 31) (logior (aref s 31) #x40))

    ;; Second 32 bytes -> prefix for nonce derivation
    (dotimes (i 32)
      (setf (aref prefix i) (aref hash (+ i 32))))

    ;; Public key A = s*B
    (let* ((a-point (ed-base-mult s))
           (a-encoded (ed-encode-point a-point))
           ;; r = SHA-512(prefix || message) mod L
           (r-input (make-array (+ 32 (length message))
                                :element-type '(unsigned-byte 8)))
           (r-hash nil)
           (r nil)
           (r-point nil)
           (r-encoded nil)
           ;; k = SHA-512(R || A || message) mod L
           (k-input nil)
           (k-hash nil)
           (k nil)
           ;; S = (r + k*s) mod L
           (sig-s nil)
           (signature (make-array 64 :element-type '(unsigned-byte 8))))

      ;; Compute r = H(prefix || message)
      (replace r-input prefix :start1 0 :end1 32)
      (replace r-input message :start1 32)
      (setf r-hash (sha512 r-input))
      (setf r (ed-reduce-scalar r-hash))

      ;; R = r*B
      (setf r-point (ed-base-mult r))
      (setf r-encoded (ed-encode-point r-point))

      (format t "~&ED25519-SIGN:~%")
      (format t "  R: ")
      (dotimes (i 16) (format t "~2,'0X" (aref r-encoded i)))
      (format t "...~%")

      ;; Compute k = H(R || A || message)
      (setf k-input (make-array (+ 32 32 (length message))
                                :element-type '(unsigned-byte 8)))
      (replace k-input r-encoded :start1 0 :end1 32)
      (replace k-input a-encoded :start1 32 :end1 64)
      (replace k-input message :start1 64)
      (setf k-hash (sha512 k-input))
      (setf k (ed-reduce-scalar k-hash))

      (format t "  k: ")
      (dotimes (i 16) (format t "~2,'0X" (aref k i)))
      (format t "...~%")

      ;; S = (r + k*s) mod L
      (let ((ks (ed-scalar-mult-mod-l k s)))
        (format t "  k*s: ")
        (dotimes (i 16) (format t "~2,'0X" (aref ks i)))
        (format t "...~%")
        (setf sig-s (ed-scalar-add r ks)))

      (format t "  S: ")
      (dotimes (i 16) (format t "~2,'0X" (aref sig-s i)))
      (format t "...~%")

      ;; Signature = R || S
      (replace signature r-encoded :start1 0 :end1 32)
      (replace signature sig-s :start1 32 :end1 64)
      signature)))

;;; Add two scalars mod L
(defun ed-scalar-add (a b)
  "Add two 32-byte scalars mod L."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (carry 0))
    ;; Add
    (dotimes (i 32)
      (let ((sum (+ (aref a i) (aref b i) carry)))
        (setf (aref result i) (logand sum #xff))
        (setf carry (ash sum -8))))
    ;; Reduce mod L if needed
    (ed-reduce-if-needed result)))

;;; Multiply two scalars mod L (simplified)
(defun ed-scalar-mult-mod-l (a b)
  "Multiply two 32-byte scalars mod L."
  ;; Full 64-byte product, then reduce
  (let ((product (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Schoolbook multiplication
    (dotimes (i 32)
      (let ((carry 0))
        (dotimes (j 32)
          (let* ((idx (+ i j))
                 (p (+ (* (aref a i) (aref b j))
                       (if (< idx 64) (aref product idx) 0)
                       carry)))
            (when (< idx 64)
              (setf (aref product idx) (logand p #xff)))
            (setf carry (ash p -8))))
        ;; Handle final carry
        (loop for idx from (+ i 32) below 64
              while (> carry 0)
              do (let ((sum (+ (aref product idx) carry)))
                   (setf (aref product idx) (logand sum #xff))
                   (setf carry (ash sum -8))))))
    ;; Reduce mod L
    (ed-reduce-scalar product)))

;;; Reduce scalar if >= L
(defun ed-reduce-if-needed (x)
  "Reduce 32-byte scalar mod L if >= L."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32)
      (setf (aref result i) (aref x i)))
    ;; Check if >= L and subtract
    (let ((ge-l t))
      (loop for i from 31 downto 0
            do (cond
                 ((> (aref result i) (aref *ed25519-l-bytes* i))
                  (return))
                 ((< (aref result i) (aref *ed25519-l-bytes* i))
                  (setf ge-l nil)
                  (return))))
      (when ge-l
        (let ((borrow 0))
          (dotimes (i 32)
            (let ((diff (- (aref result i) (aref *ed25519-l-bytes* i) borrow)))
              (if (< diff 0)
                  (progn
                    (setf (aref result i) (+ diff 256))
                    (setf borrow 1))
                  (progn
                    (setf (aref result i) diff)
                    (setf borrow 0))))))))
    result))

;;; Verify an Ed25519 signature
(defun ed25519-verify (public-key signature message)
  "Verify Ed25519 signature. Returns T if valid, NIL if invalid."
  (ed25519-init)
  ;; Extract R and S from signature
  (let ((r-bytes (make-array 32 :element-type '(unsigned-byte 8)))
        (s-bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32)
      (setf (aref r-bytes i) (aref signature i))
      (setf (aref s-bytes i) (aref signature (+ i 32))))

    ;; Decode points
    (let* ((r-point (ed-decode-point r-bytes))
           (a-point (ed-decode-point public-key))
           ;; Compute k = H(R || A || message) mod L
           (k-input (make-array (+ 32 32 (length message))
                                :element-type '(unsigned-byte 8)))
           (k nil)
           ;; Check: [S]B = R + [k]A
           (sb-point nil)
           (ka-point nil)
           (rka-point nil))

      (replace k-input r-bytes :start1 0 :end1 32)
      (replace k-input public-key :start1 32 :end1 64)
      (replace k-input message :start1 64)
      (setf k (ed-reduce-scalar (sha512 k-input)))

      ;; [S]B
      (setf sb-point (ed-base-mult s-bytes))

      ;; [k]A
      (setf ka-point (ed-scalar-mult k a-point))

      (format t "~&ED25519-VERIFY intermediate:~%")
      (format t "  k (8): ")
      (dotimes (i 8) (format t "~2,'0X" (aref k i)))
      (format t "~%")
      (format t "  kA: ")
      (let ((ka-enc (ed-encode-point ka-point)))
        (dotimes (i 16) (format t "~2,'0X" (aref ka-enc i))))
      (format t "...~%")
      (format t "  R: ")
      (let ((r-enc (ed-encode-point r-point)))
        (dotimes (i 16) (format t "~2,'0X" (aref r-enc i))))
      (format t "...~%")

      ;; R + [k]A
      (setf rka-point (ed-add r-point ka-point))

      ;; Compare [S]B with R + [k]A
      (let ((sb-encoded (ed-encode-point sb-point))
            (rka-encoded (ed-encode-point rka-point))
            (equal t))
        (format t "~&ED25519-VERIFY:~%")
        (format t "  SB: ")
        (dotimes (i 16) (format t "~2,'0X" (aref sb-encoded i)))
        (format t "...~%")
        (format t "  R+kA: ")
        (dotimes (i 16) (format t "~2,'0X" (aref rka-encoded i)))
        (format t "...~%")
        (dotimes (i 32)
          (when (/= (aref sb-encoded i) (aref rka-encoded i))
            (setf equal nil)))
        equal))))

;;; Generate a random keypair (for testing - uses weak RNG)
(defun ed25519-keypair ()
  "Generate Ed25519 keypair. Returns (private-key . public-key)."
  (let ((private-key (make-array 32 :element-type '(unsigned-byte 8)))
        (seed (get-internal-run-time))
        (idx 0))
    ;; Generate "random" bytes using simple LCG
    ;; Avoid complex arithmetic - Movitz compiler quirk
    (loop while (< idx 32) do
      (let* ((s1 (logand seed #xffff))
             (s2 (ash seed -16))
             ;; Simplified LCG: seed = (seed * 69069 + 1) mod 2^31
             (t1 (* s1 69069))
             (t2 (* s2 69069))
             (sum (+ t1 (ash t2 16) 1)))
        (setf seed (logand sum #x7fffffff)))
      (setf (aref private-key idx) (logand seed #xff))
      (incf idx))
    (format t "~&  ED25519-KEYPAIR: computing public key...")
    (multiple-value-bind (t0-lo t0-hi) (read-time-stamp-counter)
      (let ((pubkey (ed25519-public-key private-key)))
        (multiple-value-bind (t1-lo t1-hi) (read-time-stamp-counter)
          (format t " ~D cycles~%" (+ (- t1-lo t0-lo) (* (- t1-hi t0-hi) 536870912)))
          (cons private-key pubkey))))))

;;; Print bytes as hex
(defun bytes-to-hex (bytes)
  "Convert byte array to hex string."
  (let ((hex-chars "0123456789abcdef")
        (result (make-array (* (length bytes) 2) :element-type 'character)))
    (dotimes (i (length bytes))
      (let ((byte (aref bytes i)))
        (setf (aref result (* i 2)) (aref hex-chars (ash byte -4)))
        (setf (aref result (1+ (* i 2))) (aref hex-chars (logand byte 15)))))
    result))

;;; Test function
(defun ed25519-test ()
  "Test Ed25519 with RFC 8032 test vectors."
  (format t "~&Ed25519 test:~%")
  (ed25519-init)

  ;; Test vector 1 from RFC 8032
  ;; Private key (seed): all zeros (32 bytes)
  (let ((private-key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (message (make-array 0 :element-type '(unsigned-byte 8))))

    ;; Expected public key:
    ;; 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
    (let ((public-key (ed25519-public-key private-key)))
      (format t "  Public key: ~A~%" (bytes-to-hex public-key))

      ;; Expected signature for empty message:
      ;; e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
      (let ((signature (ed25519-sign private-key message)))
        (format t "  Signature:  ~A~%" (bytes-to-hex signature))

        ;; Verify
        (let ((valid (ed25519-verify public-key signature message)))
          (format t "  Verify:     ~A~%" (if valid "PASS" "FAIL"))

          ;; Test with wrong message
          (let ((wrong-msg (make-array 1 :element-type '(unsigned-byte 8)
                                       :initial-contents '(#x00))))
            (format t "  Wrong msg:  ~A~%"
                    (if (ed25519-verify public-key signature wrong-msg)
                        "FAIL (should reject)"
                        "PASS (correctly rejected)")))
          valid)))))
