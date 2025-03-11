;;;; X25519 implementation for Movitz
;;;; Based on RFC 7748
;;;; Uses 10 x 26-bit limbs for 255-bit arithmetic

(require :muerte/basic-macros)
(provide :lib/crypto/x25519)

(in-package muerte)

;;; X25519 is elliptic curve Diffie-Hellman on Curve25519.
;;; The curve is defined over F_p where p = 2^255 - 19.
;;; We represent 255-bit numbers as 10 x 26-bit limbs.
;;; This gives us 260 bits with room for intermediate carries.

(defconstant +x25519-limb-bits+ 26)
(defconstant +x25519-limb-mask+ (1- (ash 1 26)))  ; #x3ffffff
(defconstant +x25519-limbs+ 10)

;;; Create a field element from 32 bytes (little-endian)
(defun fe-from-bytes (bytes)
  "Convert 32 bytes to 10-limb field element."
  (let ((limbs (make-array 10 :initial-element 0))
        (bit-pos 0)
        (limb-idx 0)
        (acc 0))
    (dotimes (i 32)
      (setf acc (logior acc (ash (aref bytes i) bit-pos)))
      (incf bit-pos 8)
      (do ()
          ((or (< bit-pos +x25519-limb-bits+) (>= limb-idx 10)))
        (setf (aref limbs limb-idx) (logand acc +x25519-limb-mask+))
        (setf acc (ash acc (- +x25519-limb-bits+)))
        (decf bit-pos +x25519-limb-bits+)
        (incf limb-idx)))
    (when (and (< limb-idx 10) (> acc 0))
      (setf (aref limbs limb-idx) (logand acc +x25519-limb-mask+)))
    limbs))

;;; Convert field element to 32 bytes
(defun fe-to-bytes (fe)
  "Convert 10-limb field element to 32 bytes."
  ;; First reduce mod p
  (let ((f (fe-reduce fe))
        (result (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (acc 0)
        (bit-pos 0)
        (byte-idx 0))
    (dotimes (i 10)
      (setf acc (logior acc (ash (aref f i) bit-pos)))
      (incf bit-pos +x25519-limb-bits+)
      (do ()
          ((or (< bit-pos 8) (>= byte-idx 32)))
        (setf (aref result byte-idx) (logand acc #xff))
        (setf acc (ash acc -8))
        (decf bit-pos 8)
        (incf byte-idx)))
    result))

;;; Add two field elements
(defun fe-add (a b)
  "Add two field elements."
  (let ((result (make-array 10 :initial-element 0)))
    (dotimes (i 10)
      (setf (aref result i) (+ (aref a i) (aref b i))))
    result))

;;; Subtract two field elements
(defun fe-sub (a b)
  "Subtract b from a."
  ;; Use signed arithmetic - carry propagation handles negative values
  ;; by wrapping with the modular reduction
  (let ((result (make-array 10 :initial-element 0)))
    (dotimes (i 10)
      (setf (aref result i) (- (aref a i) (aref b i))))
    ;; Carry propagate (handles negative limbs via signed arithmetic)
    (fe-carry-signed result)))

;;; Carry propagation with proper field reduction
(defun fe-carry (h)
  "Propagate carries in field element and reduce mod p."
  ;; First pass: propagate carries through limbs 0-9
  (let ((carry 0))
    (dotimes (i 10)
      (let ((v (+ (aref h i) carry)))
        (setf (aref h i) (logand v +x25519-limb-mask+))
        (setf carry (ash v (- +x25519-limb-bits+)))))
    ;; Any carry from limb 9 wraps: 2^260 = 2^5 * 2^255 = 32 * 19 mod p
    (when (/= carry 0)
      (incf (aref h 0) (* carry 608))))  ; 608 = 32 * 19

  ;; Reduce limb 9: only 21 bits are valid (9*26 + 21 = 255)
  ;; Bits >= 21 represent multiples of 2^255 = 19 mod p
  (let ((overflow (ash (aref h 9) -21)))
    (when (/= overflow 0)
      (setf (aref h 9) (logand (aref h 9) #x1fffff)) ; keep 21 bits
      (incf (aref h 0) (* overflow 19))))

  ;; Second carry pass to handle additions
  (let ((carry 0))
    (dotimes (i 10)
      (let ((v (+ (aref h i) carry)))
        (setf (aref h i) (logand v +x25519-limb-mask+))
        (setf carry (ash v (- +x25519-limb-bits+)))))
    (when (/= carry 0)
      (incf (aref h 0) (* carry 608))))

  ;; Final reduction of limb 9
  (let ((overflow (ash (aref h 9) -21)))
    (when (/= overflow 0)
      (setf (aref h 9) (logand (aref h 9) #x1fffff))
      (incf (aref h 0) (* overflow 19))))
  h)

;;; Signed carry propagation (handles negative limbs)
(defun fe-carry-signed (h)
  "Propagate carries with signed limb handling."
  ;; Use floor division to handle negative values correctly
  (let ((carry 0)
        (radix (ash 1 +x25519-limb-bits+)))
    (dotimes (i 10)
      (let* ((v (+ (aref h i) carry))
             (lo (mod v radix)))
        (setf (aref h i) lo)
        (setf carry (floor v radix))))
    ;; Final carry wraps: 2^260 = 608 mod p
    (when (/= carry 0)
      (incf (aref h 0) (* carry 608))))

  ;; Reduce limb 9 to 21 bits
  (let ((overflow (ash (aref h 9) -21)))
    (when (/= overflow 0)
      (setf (aref h 9) (logand (aref h 9) #x1fffff))
      (incf (aref h 0) (* overflow 19))))

  ;; Second pass for any new carries
  (fe-carry h)
  h)

;;; Full reduction mod p = 2^255 - 19
(defun fe-reduce (h)
  "Fully reduce field element mod p."
  ;; First carry
  (fe-carry h)
  ;; Do another carry for safety
  (fe-carry h)

  ;; Check if h >= p and subtract p if so
  ;; p = 2^255 - 19, so we check if the value >= 2^255 - 19
  ;; In our limb representation with 21 bits in limb 9:
  ;; - If limb 9 >= 2^21, we're definitely >= 2^255 (but fe-carry already reduced this)
  ;; - If limb 9 == 2^21 - 1 (max 21-bit value), need to check lower limbs
  ;; - If limb 9 < 2^21 - 1, we might still be >= p if close

  ;; Simplified check: if limb 9 == max (2^21 - 1) and lower limbs make value >= p
  ;; p in limbs: limb 0 = -19 (or 2^26 - 19 with borrow), all others 0
  ;; Actually, p = 2^255 - 19 in our representation:
  ;;   limb 9 has 2^255/2^234 = 2^21, but we store up to 2^21 - 1
  ;; So p in normalized form with borrows propagated:
  ;;   All limbs at max (2^26-1 for 0-8, 2^21-1 for 9) minus some amount

  ;; Simple approach: check if h >= 2^255 - 19
  ;; h >= p iff h - p >= 0 iff (h + 19) >= 2^255
  ;; Check if adding 19 to limb 0 causes a carry all the way to bit 255
  (let ((h0 (aref h 0))
        (h9 (aref h 9)))
    ;; If limb 9 is at max (2^21 - 1), the value might be >= p
    (when (= h9 (1- (ash 1 21)))  ; 2097151
      ;; Check if limbs 1-8 are all at max (2^26 - 1)
      (let ((all-max t))
        (do ((i 1 (1+ i)))
            ((or (> i 8) (not all-max)))
          (when (/= (aref h i) +x25519-limb-mask+)
            (setf all-max nil)))
        ;; If limbs 1-8 are max and limb 0 >= (2^26 - 19), then h >= p
        ;; p in limbs is: [2^26-19, 2^26-1, 2^26-1, ..., 2^26-1, 2^21-1]
        ;; So h >= p when h0 >= 2^26-19 = 67108845
        (when (and all-max (>= h0 (- (ash 1 26) 19)))
          ;; Subtract p from h:
          ;; h[0] = h[0] - (2^26 - 19)
          ;; h[1..8] = h[i] - (2^26 - 1) = 0 (since they're all max)
          ;; h[9] = h[9] - (2^21 - 1) = 0 (since it's max)
          (setf (aref h 0) (- h0 (- (ash 1 26) 19)))  ; h0 - (2^26 - 19)
          (dotimes (i 8)
            (setf (aref h (1+ i)) 0))
          (setf (aref h 9) 0)))))
  h)

;;; Multiply two field elements mod p
(defun fe-mul (f g)
  "Multiply two field elements mod p."
  ;; Schoolbook multiplication with 10x10 products
  ;; For 10 x 26-bit limbs (260 bits), wrapped products use factor 608
  ;; because 2^260 = 2^5 * 2^255 = 32 * 19 = 608 (mod p)
  (let ((f0 (aref f 0)) (f1 (aref f 1)) (f2 (aref f 2)) (f3 (aref f 3)) (f4 (aref f 4))
        (f5 (aref f 5)) (f6 (aref f 6)) (f7 (aref f 7)) (f8 (aref f 8)) (f9 (aref f 9))
        (g0 (aref g 0)) (g1 (aref g 1)) (g2 (aref g 2)) (g3 (aref g 3)) (g4 (aref g 4))
        (g5 (aref g 5)) (g6 (aref g 6)) (g7 (aref g 7)) (g8 (aref g 8)) (g9 (aref g 9)))

    ;; Precompute g*608 for wrapped products (i+j >= 10)
    ;; 608 = 2^260 mod p = 32 * 19
    (let ((g1-608 (* g1 608)) (g2-608 (* g2 608)) (g3-608 (* g3 608)) (g4-608 (* g4 608))
          (g5-608 (* g5 608)) (g6-608 (* g6 608)) (g7-608 (* g7 608)) (g8-608 (* g8 608))
          (g9-608 (* g9 608)))

      ;; Compute each output coefficient
      ;; Products where i+j >= 10 wrap with factor 608
      (let ((h0 (+ (* f0 g0) (* f1 g9-608) (* f2 g8-608) (* f3 g7-608) (* f4 g6-608)
                   (* f5 g5-608) (* f6 g4-608) (* f7 g3-608) (* f8 g2-608) (* f9 g1-608)))
            (h1 (+ (* f0 g1) (* f1 g0) (* f2 g9-608) (* f3 g8-608) (* f4 g7-608)
                   (* f5 g6-608) (* f6 g5-608) (* f7 g4-608) (* f8 g3-608) (* f9 g2-608)))
            (h2 (+ (* f0 g2) (* f1 g1) (* f2 g0) (* f3 g9-608) (* f4 g8-608)
                   (* f5 g7-608) (* f6 g6-608) (* f7 g5-608) (* f8 g4-608) (* f9 g3-608)))
            (h3 (+ (* f0 g3) (* f1 g2) (* f2 g1) (* f3 g0) (* f4 g9-608)
                   (* f5 g8-608) (* f6 g7-608) (* f7 g6-608) (* f8 g5-608) (* f9 g4-608)))
            (h4 (+ (* f0 g4) (* f1 g3) (* f2 g2) (* f3 g1) (* f4 g0)
                   (* f5 g9-608) (* f6 g8-608) (* f7 g7-608) (* f8 g6-608) (* f9 g5-608)))
            (h5 (+ (* f0 g5) (* f1 g4) (* f2 g3) (* f3 g2) (* f4 g1)
                   (* f5 g0) (* f6 g9-608) (* f7 g8-608) (* f8 g7-608) (* f9 g6-608)))
            (h6 (+ (* f0 g6) (* f1 g5) (* f2 g4) (* f3 g3) (* f4 g2)
                   (* f5 g1) (* f6 g0) (* f7 g9-608) (* f8 g8-608) (* f9 g7-608)))
            (h7 (+ (* f0 g7) (* f1 g6) (* f2 g5) (* f3 g4) (* f4 g3)
                   (* f5 g2) (* f6 g1) (* f7 g0) (* f8 g9-608) (* f9 g8-608)))
            (h8 (+ (* f0 g8) (* f1 g7) (* f2 g6) (* f3 g5) (* f4 g4)
                   (* f5 g3) (* f6 g2) (* f7 g1) (* f8 g0) (* f9 g9-608)))
            (h9 (+ (* f0 g9) (* f1 g8) (* f2 g7) (* f3 g6) (* f4 g5)
                   (* f5 g4) (* f6 g3) (* f7 g2) (* f8 g1) (* f9 g0))))

        (let ((result (make-array 10 :initial-element 0)))
          (setf (aref result 0) h0
                (aref result 1) h1
                (aref result 2) h2
                (aref result 3) h3
                (aref result 4) h4
                (aref result 5) h5
                (aref result 6) h6
                (aref result 7) h7
                (aref result 8) h8
                (aref result 9) h9)
          (fe-carry result))))))

;;; Square a field element
(defun fe-sq (f)
  "Square a field element."
  (fe-mul f f))

;;; Simple exponentiation for testing
(defun fe-pow-simple (base exp-bits)
  "Compute base^exp using binary exponentiation where exp-bits is list of bits (MSB first)."
  (let ((result (fe-from-int 1)))
    (dolist (bit exp-bits)
      (setf result (fe-sq result))
      (when (= bit 1)
        (setf result (fe-mul result base))))
    result))

;;; Invert a field element using Fermat's little theorem
;;; a^(-1) = a^(p-2) mod p
(defun fe-invert (z)
  "Compute multiplicative inverse of z mod p."
  ;; Use addition chain for p-2 = 2^255 - 21
  ;; This is the standard exponentiation method
  (let ((z2 (fe-sq z))
        (z4 nil) (z8 nil) (z9 nil) (z11 nil)
        (z22 nil) (z_5_0 nil) (z_10_5 nil) (z_10_0 nil)
        (z_20_10 nil) (z_20_0 nil) (z_40_20 nil) (z_40_0 nil)
        (z_50_10 nil) (z_50_0 nil) (z_100_50 nil) (z_100_0 nil)
        (z_200_100 nil) (z_200_0 nil) (z_250_50 nil) (z_250_0 nil))

    (setf z4 (fe-sq z2))
    (setf z8 (fe-sq z4))
    (setf z9 (fe-mul z z8))
    (setf z11 (fe-mul z2 z9))
    (setf z22 (fe-sq z11))
    (setf z_5_0 (fe-mul z9 z22))

    ;; z^(2^10 - 2^5)
    (setf z_10_5 z_5_0)
    (dotimes (i 5) (setf z_10_5 (fe-sq z_10_5)))
    (setf z_10_0 (fe-mul z_10_5 z_5_0))

    ;; z^(2^20 - 2^10)
    (setf z_20_10 z_10_0)
    (dotimes (i 10) (setf z_20_10 (fe-sq z_20_10)))
    (setf z_20_0 (fe-mul z_20_10 z_10_0))

    ;; z^(2^40 - 2^20)
    (setf z_40_20 z_20_0)
    (dotimes (i 20) (setf z_40_20 (fe-sq z_40_20)))
    (setf z_40_0 (fe-mul z_40_20 z_20_0))

    ;; z^(2^50 - 2^10)
    (setf z_50_10 z_40_0)
    (dotimes (i 10) (setf z_50_10 (fe-sq z_50_10)))
    (setf z_50_0 (fe-mul z_50_10 z_10_0))

    ;; z^(2^100 - 2^50)
    (setf z_100_50 z_50_0)
    (dotimes (i 50) (setf z_100_50 (fe-sq z_100_50)))
    (setf z_100_0 (fe-mul z_100_50 z_50_0))

    ;; z^(2^200 - 2^100)
    (setf z_200_100 z_100_0)
    (dotimes (i 100) (setf z_200_100 (fe-sq z_200_100)))
    (setf z_200_0 (fe-mul z_200_100 z_100_0))

    ;; z^(2^250 - 2^50)
    (setf z_250_50 z_200_0)
    (dotimes (i 50) (setf z_250_50 (fe-sq z_250_50)))
    (setf z_250_0 (fe-mul z_250_50 z_50_0))

    ;; z^(2^255 - 2^5)
    (let ((tmp z_250_0))
      (dotimes (i 5) (setf tmp (fe-sq tmp)))
      ;; z^(2^255 - 21) = z^(p-2)
      (fe-mul tmp z11))))

;;; Montgomery ladder step
(defun x25519-ladder-step (x1 x2 z2 x3 z3 swap)
  "One step of the Montgomery ladder."
  (declare (ignore swap))  ; Constant time would use swap
  (let* ((a (fe-add x2 z2))
         (aa (fe-sq a))
         (b (fe-sub x2 z2))
         (bb (fe-sq b))
         (e (fe-sub aa bb))
         (c (fe-add x3 z3))
         (d (fe-sub x3 z3))
         (da (fe-mul d a))
         (cb (fe-mul c b))
         (x3-new (fe-sq (fe-add da cb)))
         (z3-new (fe-mul x1 (fe-sq (fe-sub da cb))))
         (x2-new (fe-mul aa bb))
         ;; a24 = 121665 for curve25519
         (a24-e (fe-mul (fe-from-int 121665) e))
         (z2-new (fe-mul e (fe-add aa a24-e))))
    (values x2-new z2-new x3-new z3-new)))

;;; Create field element from integer
(defun fe-from-int (n)
  "Create field element from small integer."
  (let ((result (make-array 10 :initial-element 0)))
    (setf (aref result 0) (logand n +x25519-limb-mask+))
    (when (> n +x25519-limb-mask+)
      (setf (aref result 1) (ash n (- +x25519-limb-bits+))))
    result))

;;; X25519 scalar multiplication
(defun x25519 (k u)
  "Compute X25519(k, u) where k is 32-byte scalar and u is 32-byte u-coordinate."
  ;; Clamp the scalar k
  (let ((k-clamped (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32)
      (setf (aref k-clamped i) (aref k i)))
    (setf (aref k-clamped 0) (logand (aref k-clamped 0) #xf8))
    (setf (aref k-clamped 31) (logand (aref k-clamped 31) #x7f))
    (setf (aref k-clamped 31) (logior (aref k-clamped 31) #x40))

    ;; Montgomery ladder
    (let* ((x1 (fe-from-bytes u))
           (x2 (fe-from-int 1))
           (z2 (fe-from-int 0))
           (x3 (fe-from-bytes u))
           (z3 (fe-from-int 1))
           (swap 0))

      ;; Process bits from high to low
      (do ((pos 254 (1- pos)))
          ((< pos 0))
        (let* ((byte-idx (ash pos -3))
               (bit-idx (logand pos 7))
               (k-t (logand (ash (aref k-clamped byte-idx) (- bit-idx)) 1)))

          ;; Conditional swap: swap if bit differs from previous
          (when (/= k-t swap)
            (let ((tmp-x x2) (tmp-z z2))
              (setf x2 x3 z2 z3 x3 tmp-x z3 tmp-z)))
          (setf swap k-t)

          ;; Ladder step
          (multiple-value-bind (x2-new z2-new x3-new z3-new)
              (x25519-ladder-step x1 x2 z2 x3 z3 0)
            (setf x2 x2-new z2 z2-new x3 x3-new z3 z3-new))))

      ;; Final conditional swap
      (when (/= swap 0)
        (let ((tmp-x x2) (tmp-z z2))
          (setf x2 x3 z2 z3 x3 tmp-x z3 tmp-z)))

      ;; Final inversion: result = x2 * z2^(-1)
      (let ((result-fe (fe-mul x2 (fe-invert z2))))
        (fe-to-bytes result-fe)))))

;;; Generate public key from private key
(defun x25519-public-key (private-key)
  "Generate X25519 public key from 32-byte private key."
  ;; Public key = X25519(private, basepoint)
  ;; Basepoint u = 9
  (let ((basepoint (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref basepoint 0) 9)
    (x25519 private-key basepoint)))

;;; ============================================================
;;; GC-FREE OPTIMIZED VERSION
;;; Pre-allocates all arrays to avoid GC during computation
;;; ============================================================

(defun fe-copy! (dst src)
  "Copy field element src to dst (in-place)."
  (dotimes (i 10) (setf (aref dst i) (aref src i)))
  dst)

(defun fe-add! (dst a b)
  "Add a + b, store result in dst (can be same as a or b)."
  (dotimes (i 10)
    (setf (aref dst i) (+ (aref a i) (aref b i))))
  dst)

(defun fe-sub! (dst a b)
  "Subtract a - b, store result in dst."
  (dotimes (i 10)
    (setf (aref dst i) (- (aref a i) (aref b i))))
  ;; Carry propagate for signed arithmetic
  (fe-carry-signed dst))

(defun fe-mul! (dst f g)
  "Multiply f * g, store result in dst."
  (let ((f0 (aref f 0)) (f1 (aref f 1)) (f2 (aref f 2)) (f3 (aref f 3)) (f4 (aref f 4))
        (f5 (aref f 5)) (f6 (aref f 6)) (f7 (aref f 7)) (f8 (aref f 8)) (f9 (aref f 9))
        (g0 (aref g 0)) (g1 (aref g 1)) (g2 (aref g 2)) (g3 (aref g 3)) (g4 (aref g 4))
        (g5 (aref g 5)) (g6 (aref g 6)) (g7 (aref g 7)) (g8 (aref g 8)) (g9 (aref g 9)))
    (let ((g1-608 (* g1 608)) (g2-608 (* g2 608)) (g3-608 (* g3 608)) (g4-608 (* g4 608))
          (g5-608 (* g5 608)) (g6-608 (* g6 608)) (g7-608 (* g7 608)) (g8-608 (* g8 608))
          (g9-608 (* g9 608)))
      (setf (aref dst 0) (+ (* f0 g0) (* f1 g9-608) (* f2 g8-608) (* f3 g7-608) (* f4 g6-608)
                            (* f5 g5-608) (* f6 g4-608) (* f7 g3-608) (* f8 g2-608) (* f9 g1-608)))
      (setf (aref dst 1) (+ (* f0 g1) (* f1 g0) (* f2 g9-608) (* f3 g8-608) (* f4 g7-608)
                            (* f5 g6-608) (* f6 g5-608) (* f7 g4-608) (* f8 g3-608) (* f9 g2-608)))
      (setf (aref dst 2) (+ (* f0 g2) (* f1 g1) (* f2 g0) (* f3 g9-608) (* f4 g8-608)
                            (* f5 g7-608) (* f6 g6-608) (* f7 g5-608) (* f8 g4-608) (* f9 g3-608)))
      (setf (aref dst 3) (+ (* f0 g3) (* f1 g2) (* f2 g1) (* f3 g0) (* f4 g9-608)
                            (* f5 g8-608) (* f6 g7-608) (* f7 g6-608) (* f8 g5-608) (* f9 g4-608)))
      (setf (aref dst 4) (+ (* f0 g4) (* f1 g3) (* f2 g2) (* f3 g1) (* f4 g0)
                            (* f5 g9-608) (* f6 g8-608) (* f7 g7-608) (* f8 g6-608) (* f9 g5-608)))
      (setf (aref dst 5) (+ (* f0 g5) (* f1 g4) (* f2 g3) (* f3 g2) (* f4 g1)
                            (* f5 g0) (* f6 g9-608) (* f7 g8-608) (* f8 g7-608) (* f9 g6-608)))
      (setf (aref dst 6) (+ (* f0 g6) (* f1 g5) (* f2 g4) (* f3 g3) (* f4 g2)
                            (* f5 g1) (* f6 g0) (* f7 g9-608) (* f8 g8-608) (* f9 g7-608)))
      (setf (aref dst 7) (+ (* f0 g7) (* f1 g6) (* f2 g5) (* f3 g4) (* f4 g3)
                            (* f5 g2) (* f6 g1) (* f7 g0) (* f8 g9-608) (* f9 g8-608)))
      (setf (aref dst 8) (+ (* f0 g8) (* f1 g7) (* f2 g6) (* f3 g5) (* f4 g4)
                            (* f5 g3) (* f6 g2) (* f7 g1) (* f8 g0) (* f9 g9-608)))
      (setf (aref dst 9) (+ (* f0 g9) (* f1 g8) (* f2 g7) (* f3 g6) (* f4 g5)
                            (* f5 g4) (* f6 g3) (* f7 g2) (* f8 g1) (* f9 g0))))
    (fe-carry dst)))

(defun fe-sq! (dst f)
  "Square f, store result in dst."
  (fe-mul! dst f f))

(defun x25519-fast (k u)
  "GC-free X25519 scalar multiplication.
   Pre-allocates all working arrays to avoid GC during the 255-iteration ladder."
  ;; Clamp the scalar k
  (let ((k-clamped (make-array 32 :element-type '(unsigned-byte 8))))
    (dotimes (i 32) (setf (aref k-clamped i) (aref k i)))
    (setf (aref k-clamped 0) (logand (aref k-clamped 0) #xf8))
    (setf (aref k-clamped 31) (logand (aref k-clamped 31) #x7f))
    (setf (aref k-clamped 31) (logior (aref k-clamped 31) #x40))

    ;; Pre-allocate ALL working arrays (the key optimization!)
    (let ((x1 (fe-from-bytes u))
          (x2 (make-array 10 :initial-element 0))
          (z2 (make-array 10 :initial-element 0))
          (x3 (make-array 10 :initial-element 0))
          (z3 (make-array 10 :initial-element 0))
          ;; Temporaries for ladder step
          (a (make-array 10 :initial-element 0))
          (aa (make-array 10 :initial-element 0))
          (b (make-array 10 :initial-element 0))
          (bb (make-array 10 :initial-element 0))
          (e (make-array 10 :initial-element 0))
          (c (make-array 10 :initial-element 0))
          (d (make-array 10 :initial-element 0))
          (da (make-array 10 :initial-element 0))
          (cb (make-array 10 :initial-element 0))
          (t1 (make-array 10 :initial-element 0))
          (t2 (make-array 10 :initial-element 0))
          ;; Constant a24 = 121665 (cached, not recreated each iteration!)
          (a24 (make-array 10 :initial-element 0))
          (swap 0))

      ;; Initialize x2=1, z2=0, x3=u, z3=1
      (setf (aref x2 0) 1)
      (fe-copy! x3 x1)
      (setf (aref z3 0) 1)
      ;; a24 = 121665
      (setf (aref a24 0) (logand 121665 +x25519-limb-mask+))

      ;; Process bits from high to low
      (do ((pos 254 (1- pos)))
          ((< pos 0))
        (let* ((byte-idx (ash pos -3))
               (bit-idx (logand pos 7))
               (k-t (logand (ash (aref k-clamped byte-idx) (- bit-idx)) 1)))

          ;; Conditional swap
          (when (/= k-t swap)
            ;; Swap x2<->x3, z2<->z3 using t1 as temp
            (fe-copy! t1 x2) (fe-copy! x2 x3) (fe-copy! x3 t1)
            (fe-copy! t1 z2) (fe-copy! z2 z3) (fe-copy! z3 t1))
          (setf swap k-t)

          ;; === Ladder step (all in-place) ===
          ;; a = x2 + z2
          (fe-add! a x2 z2)
          ;; aa = a^2
          (fe-sq! aa a)
          ;; b = x2 - z2
          (fe-sub! b x2 z2)
          ;; bb = b^2
          (fe-sq! bb b)
          ;; e = aa - bb
          (fe-sub! e aa bb)
          ;; c = x3 + z3
          (fe-add! c x3 z3)
          ;; d = x3 - z3
          (fe-sub! d x3 z3)
          ;; da = d * a
          (fe-mul! da d a)
          ;; cb = c * b
          (fe-mul! cb c b)
          ;; x3 = (da + cb)^2
          (fe-add! t1 da cb)
          (fe-sq! x3 t1)
          ;; z3 = x1 * (da - cb)^2
          (fe-sub! t1 da cb)
          (fe-sq! t2 t1)
          (fe-mul! z3 x1 t2)
          ;; x2 = aa * bb
          (fe-mul! x2 aa bb)
          ;; z2 = e * (aa + a24*e)
          (fe-mul! t1 a24 e)
          (fe-add! t2 aa t1)
          (fe-mul! z2 e t2)))

      ;; Final conditional swap
      (when (/= swap 0)
        (fe-copy! t1 x2) (fe-copy! x2 x3) (fe-copy! x3 t1)
        (fe-copy! t1 z2) (fe-copy! z2 z3) (fe-copy! z3 t1))

      ;; Final inversion: result = x2 * z2^(-1)
      (let ((result-fe (fe-mul x2 (fe-invert z2))))
        (fe-to-bytes result-fe)))))

(defun x25519-public-key-fast (private-key)
  "Fast X25519 public key generation (GC-free)."
  (let ((basepoint (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref basepoint 0) 9)
    (x25519-fast private-key basepoint)))

;;; Test field operations
(defun fe-test ()
  "Test field element operations."
  (format t "~&Field operations test:~%")
  (let ((all-pass t))
    ;; Basic arithmetic
    (let* ((r1 (fe-to-bytes (fe-mul (fe-from-int 2) (fe-from-int 3))))
           (r2 (fe-to-bytes (fe-carry (fe-add (fe-from-int 5) (fe-from-int 7)))))
           (r3 (fe-to-bytes (fe-sub (fe-from-int 10) (fe-from-int 3))))
           (r4 (fe-to-bytes (fe-sq (fe-from-int 7)))))
      (unless (and (= (aref r1 0) 6)
                   (= (aref r2 0) 12)
                   (= (aref r3 0) 7)
                   (= (aref r4 0) 49))
        (setf all-pass nil)
        (format t "  Basic arithmetic: FAIL~%")))

    ;; Field reduction: 2^256 mod p = 38
    (let ((r (fe-from-int 2)))
      (dotimes (i 8) (setf r (fe-sq r)))
      (unless (= (aref (fe-to-bytes r) 0) 38)
        (setf all-pass nil)
        (format t "  2^256 mod p: FAIL~%")))

    ;; Inversion tests
    (dolist (n '(2 3 7 1000))
      (let* ((x (fe-from-int n))
             (inv-x (fe-invert x))
             (one (fe-mul inv-x x))
             (result (fe-to-bytes one)))
        (unless (= (aref result 0) 1)
          (setf all-pass nil)
          (format t "  1/~d * ~d: FAIL (got ~d)~%" n n (aref result 0)))))

    (if all-pass
        (format t "  Field operations: PASS~%")
        (format t "  Field operations: FAIL~%"))
    all-pass))

;;; Test function
(defun x25519-test ()
  "Test X25519 with RFC 7748 test vectors."
  (format t "~&X25519 test:~%")

  ;; First test field operations
  (fe-test)

  ;; RFC 7748 test vector
  ;; Alice's private key (scalar)
  (let ((alice-private (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-contents
                                   '(#x77 #x07 #x6d #x0a #x73 #x18 #xa5 #x7d
                                     #x3c #x16 #xc1 #x72 #x51 #xb2 #x66 #x45
                                     #xdf #x4c #x2f #x87 #xeb #xc0 #x99 #x2a
                                     #xb1 #x77 #xfb #xa5 #x1d #xb9 #x2c #x2a))))

    ;; Expected public key
    ;; 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    (let ((public-key (x25519-public-key alice-private))
          (expected (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-contents
                               '(#x85 #x20 #xf0 #x09 #x89 #x30 #xa7 #x54
                                 #x74 #x8b #x7d #xdc #xb4 #x3e #xf7 #x5a
                                 #x0d #xbf #x3a #x0d #x26 #x38 #x1a #xf4
                                 #xeb #xa4 #xa9 #x8e #xaa #x9b #x4e #x6a))))
      (format t "  Public key: ")
      (dotimes (i 32)
        (format t "~2,'0x" (aref public-key i)))
      (format t "~%")

      ;; Check all 32 bytes
      (let ((correct t))
        (dotimes (i 32)
          (when (/= (aref public-key i) (aref expected i))
            (setf correct nil)))
        (if correct
            (format t "  X25519: PASS (all 32 bytes match)~%")
            (format t "  X25519: FAIL (mismatch)~%")))))

  t)
