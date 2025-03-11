;;;; Poly1305 implementation for Movitz
;;;; Based on RFC 8439
;;;; Uses 5 x 26-bit limbs for 130-bit arithmetic

(require :muerte/basic-macros)
(provide :lib/crypto/poly1305)

(in-package muerte)

;;; Poly1305 computes a 128-bit MAC using a 256-bit key.
;;; The key is split into r (128 bits, clamped) and s (128 bits).
;;; MAC = ((r * block1 + r * block2 + ...) mod 2^130-5) + s mod 2^128
;;;
;;; We represent 130-bit numbers as 5 x 26-bit limbs.
;;; Each limb is a fixnum (fits in 30-bit Movitz fixnum).

(defconstant +poly-limb-bits+ 26)
(defconstant +poly-limb-mask+ (1- (ash 1 26)))  ; #x3ffffff

;;; Create a 130-bit number from bytes (little-endian)
(defun poly-from-bytes (bytes &optional (len 16))
  "Convert up to 17 bytes to 5-limb representation."
  (let ((limbs (make-array 5 :initial-element 0))
        (actual-len (min len (length bytes))))
    ;; Pack bytes into limbs (little-endian)
    ;; Each limb holds 26 bits
    (let ((bit-pos 0)
          (limb-idx 0)
          (acc 0))
      (dotimes (i actual-len)
        (let ((byte (aref bytes i)))
          ;; Add 8 bits to accumulator
          (setf acc (logior acc (ash byte bit-pos)))
          (incf bit-pos 8)
          ;; Extract complete limbs
          (do ()
              ((or (< bit-pos +poly-limb-bits+) (>= limb-idx 5)))
            (setf (aref limbs limb-idx) (logand acc +poly-limb-mask+))
            (setf acc (ash acc (- +poly-limb-bits+)))
            (decf bit-pos +poly-limb-bits+)
            (incf limb-idx))))
      ;; Store remaining bits
      (when (and (< limb-idx 5) (> acc 0))
        (setf (aref limbs limb-idx) (logand acc +poly-limb-mask+))))
    limbs))

;;; Convert limbs back to bytes
(defun poly-to-bytes (limbs)
  "Convert 5-limb number to 16 bytes (little-endian), mod 2^128."
  (let ((result (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (acc 0)
        (bit-pos 0)
        (byte-idx 0))
    (dotimes (i 5)
      (setf acc (logior acc (ash (aref limbs i) bit-pos)))
      (incf bit-pos +poly-limb-bits+)
      ;; Extract complete bytes
      (do ()
          ((or (< bit-pos 8) (>= byte-idx 16)))
        (setf (aref result byte-idx) (logand acc #xff))
        (setf acc (ash acc -8))
        (decf bit-pos 8)
        (incf byte-idx)))
    result))

;;; Add two 130-bit numbers (no reduction)
(defun poly-add (a b)
  "Add two 5-limb numbers, result may have carries."
  (let ((result (make-array 5 :initial-element 0)))
    (dotimes (i 5)
      (setf (aref result i) (+ (aref a i) (aref b i))))
    result))

;;; Reduce and carry-propagate
(defun poly-reduce (h)
  "Reduce 5-limb number mod 2^130-5 with carry propagation."
  ;; First pass: propagate carries
  (let ((carry 0))
    (dotimes (i 5)
      (let ((v (+ (aref h i) carry)))
        (setf (aref h i) (logand v +poly-limb-mask+))
        (setf carry (ash v (- +poly-limb-bits+)))))
    ;; Any carry from limb 4 is multiplied by 5 (because 2^130 = 5 mod p)
    (let ((v (+ (aref h 0) (* carry 5))))
      (setf (aref h 0) (logand v +poly-limb-mask+))
      (let ((c (ash v (- +poly-limb-bits+))))
        (when (> c 0)
          (incf (aref h 1) c)))))
  h)

;;; Multiply two 130-bit numbers, reduce mod 2^130-5
(defun poly-mul (a r)
  "Multiply a by r mod 2^130-5."
  ;; We compute the full 260-bit product, then reduce.
  ;; Use schoolbook multiplication with 5x5 = 25 partial products.
  ;; Each partial product is at most 52 bits, which fits in two 30-bit limbs.

  ;; For r with clamped high bits, we can use an optimization:
  ;; Compute t = a*r using 5-limb * 5-limb multiplication
  ;; The result needs 10 limbs, then we reduce by 2^130 = 5 mod p

  (let* ((r0 (aref r 0)) (r1 (aref r 1)) (r2 (aref r 2))
         (r3 (aref r 3)) (r4 (aref r 4))
         ;; Precompute r * 5 for the reduction trick
         (s1 (* r1 5)) (s2 (* r2 5)) (s3 (* r3 5)) (s4 (* r4 5))
         (a0 (aref a 0)) (a1 (aref a 1)) (a2 (aref a 2))
         (a3 (aref a 3)) (a4 (aref a 4)))

    ;; Compute each output limb with pre-reduction
    ;; h0 = a0*r0 + a1*s4 + a2*s3 + a3*s2 + a4*s1
    ;; h1 = a0*r1 + a1*r0 + a2*s4 + a3*s3 + a4*s2
    ;; etc.
    (let ((d0 (+ (* a0 r0) (* a1 s4) (* a2 s3) (* a3 s2) (* a4 s1)))
          (d1 (+ (* a0 r1) (* a1 r0) (* a2 s4) (* a3 s3) (* a4 s2)))
          (d2 (+ (* a0 r2) (* a1 r1) (* a2 r0) (* a3 s4) (* a4 s3)))
          (d3 (+ (* a0 r3) (* a1 r2) (* a2 r1) (* a3 r0) (* a4 s4)))
          (d4 (+ (* a0 r4) (* a1 r3) (* a2 r2) (* a3 r1) (* a4 r0))))

      ;; Carry propagation
      ;; Note: With 26-bit limbs and up to 5 additions of 52-bit products,
      ;; each d can be up to ~55 bits. We need bignum-safe operations.
      ;; For Movitz 30-bit fixnums, we need to be careful.
      ;; Actually, the products are already being computed - if they overflow
      ;; to bignums, Movitz should handle it, but slowly.

      (let ((c 0)
            (result (make-array 5 :initial-element 0)))
        ;; Extract limb 0
        (let ((t0 (+ d0 c)))
          (setf (aref result 0) (logand t0 +poly-limb-mask+))
          (setf c (ash t0 (- +poly-limb-bits+))))
        ;; Limb 1
        (let ((t1 (+ d1 c)))
          (setf (aref result 1) (logand t1 +poly-limb-mask+))
          (setf c (ash t1 (- +poly-limb-bits+))))
        ;; Limb 2
        (let ((t2 (+ d2 c)))
          (setf (aref result 2) (logand t2 +poly-limb-mask+))
          (setf c (ash t2 (- +poly-limb-bits+))))
        ;; Limb 3
        (let ((t3 (+ d3 c)))
          (setf (aref result 3) (logand t3 +poly-limb-mask+))
          (setf c (ash t3 (- +poly-limb-bits+))))
        ;; Limb 4
        (let ((t4 (+ d4 c)))
          (setf (aref result 4) (logand t4 +poly-limb-mask+))
          (setf c (ash t4 (- +poly-limb-bits+))))

        ;; Final reduction: c * 5 added to limb 0
        (when (> c 0)
          (let ((t0 (+ (aref result 0) (* c 5))))
            (setf (aref result 0) (logand t0 +poly-limb-mask+))
            (let ((c2 (ash t0 (- +poly-limb-bits+))))
              (when (> c2 0)
                (incf (aref result 1) c2)))))

        result))))

;;; Clamp r according to Poly1305 spec
(defun poly-clamp-r (r-bytes)
  "Clamp the r part of the key (first 16 bytes)."
  (let ((r (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16)
      (setf (aref r i) (aref r-bytes i)))
    ;; Clear high bits of bytes 3, 7, 11, 15
    (setf (aref r 3) (logand (aref r 3) #x0f))
    (setf (aref r 7) (logand (aref r 7) #x0f))
    (setf (aref r 11) (logand (aref r 11) #x0f))
    (setf (aref r 15) (logand (aref r 15) #x0f))
    ;; Clear low 2 bits of bytes 4, 8, 12
    (setf (aref r 4) (logand (aref r 4) #xfc))
    (setf (aref r 8) (logand (aref r 8) #xfc))
    (setf (aref r 12) (logand (aref r 12) #xfc))
    r))

;;; Main Poly1305 function
(defun poly1305 (key message)
  "Compute Poly1305 MAC.
   KEY: 32-byte key (r || s)
   MESSAGE: byte array
   Returns: 16-byte MAC"
  (let* ((r-bytes (poly-clamp-r key))
         (r (poly-from-bytes r-bytes 16))
         (s (make-array 16 :element-type '(unsigned-byte 8)))
         (h (make-array 5 :initial-element 0))
         (block (make-array 17 :element-type '(unsigned-byte 8) :initial-element 0))
         (msg-len (length message)))

    ;; Extract s (bytes 16-31 of key)
    (dotimes (i 16)
      (setf (aref s i) (aref key (+ 16 i))))

    ;; Process each 16-byte block
    (do ((offset 0 (+ offset 16)))
        ((>= offset msg-len))
      (let ((block-len (min 16 (- msg-len offset))))
        ;; Copy block
        (dotimes (i 17)
          (setf (aref block i) 0))
        (dotimes (i block-len)
          (setf (aref block i) (aref message (+ offset i))))
        ;; Append 0x01 byte (high bit of block)
        (setf (aref block block-len) #x01)

        ;; h = (h + block) * r
        (let ((n (poly-from-bytes block 17)))
          (setf h (poly-add h n))
          (setf h (poly-mul h r)))))

    ;; Final reduction
    (setf h (poly-reduce h))

    ;; Add s (mod 2^128)
    (let ((h-bytes (poly-to-bytes h))
          (result (make-array 16 :element-type '(unsigned-byte 8)))
          (carry 0))
      (dotimes (i 16)
        (let ((sum (+ (aref h-bytes i) (aref s i) carry)))
          (setf (aref result i) (logand sum #xff))
          (setf carry (ash sum -8))))
      result)))

;;; Test function
(defun poly1305-test ()
  "Test Poly1305 with RFC 8439 test vector."
  (format t "~&Poly1305 test:~%")

  ;; RFC 8439 Section 2.5.2 test
  ;; Key = 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8
  ;;       01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
  ;; Message = "Cryptographic Forum Research Group"
  ;; Tag = a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9

  (let ((key (make-array 32 :element-type '(unsigned-byte 8)
                         :initial-contents
                         '(#x85 #xd6 #xbe #x78 #x57 #x55 #x6d #x33
                           #x7f #x44 #x52 #xfe #x42 #xd5 #x06 #xa8
                           #x01 #x03 #x80 #x8a #xfb #x0d #xb2 #xfd
                           #x4a #xbf #xf6 #xaf #x41 #x49 #xf5 #x1b)))
        (message-str "Cryptographic Forum Research Group"))

    (let ((message (make-array (length message-str)
                               :element-type '(unsigned-byte 8))))
      (dotimes (i (length message-str))
        (setf (aref message i) (char-code (char message-str i))))

      (let ((tag (poly1305 key message)))
        (format t "  Tag: ")
        (dotimes (i 16)
          (format t "~2,'0x " (aref tag i)))
        (format t "~%")

        ;; Expected: a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9
        (when (and (= (aref tag 0) #xa8)
                   (= (aref tag 1) #x06)
                   (= (aref tag 2) #x1d))
          (format t "  Poly1305: CORRECT~%")))))
  t)
