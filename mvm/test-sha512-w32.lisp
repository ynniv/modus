;;;; test-sha512-w32.lisp — SBCL unit test for 32-bit SHA-512 (crypto-w32.lisp)
;;;;
;;;; Usage: sbcl --script mvm/test-sha512-w32.lisp
;;;;
;;;; Tests the w32/w64 pair arithmetic SHA-512 implementation against
;;;; SBCL's native 64-bit arithmetic to find bugs.

(defvar *state-mem* (make-array #x1000 :element-type '(unsigned-byte 8) :initial-element 0))

(defun e1000-state-base () 0)

;; Simulate mem-ref :u8
(defun mem-ref-u8 (addr)
  (aref *state-mem* addr))

(defun mem-set-u8 (addr val)
  (setf (aref *state-mem* addr) val))

;; Now define the w32 pair arithmetic
(defun w32 (hi lo) (cons hi lo))

(defun w32+ (a b)
  (let ((lo (+ (cdr a) (cdr b))))
    (cons (logand (+ (car a) (+ (car b) (ash lo -16))) #xFFFF)
          (logand lo #xFFFF))))

(defun w32-xor (a b)
  (cons (logxor (car a) (car b))
        (logxor (cdr a) (cdr b))))

(defun w32-and (a b)
  (cons (logand (car a) (car b))
        (logand (cdr a) (cdr b))))

(defun w32-not (a)
  (cons (logxor (car a) #xFFFF)
        (logxor (cdr a) #xFFFF)))

;; w32 byte I/O
(defun w32-from-be (buf off)
  (cons (logior (ash (aref buf off) 8) (aref buf (+ off 1)))
        (logior (ash (aref buf (+ off 2)) 8) (aref buf (+ off 3)))))

(defun w32-to-be (buf off w)
  (let ((hi (car w)) (lo (cdr w)))
    (aset buf off (logand (ash hi -8) #xFF))
    (aset buf (+ off 1) (logand hi #xFF))
    (aset buf (+ off 2) (logand (ash lo -8) #xFF))
    (aset buf (+ off 3) (logand lo #xFF))))

;; Use SBCL's setf aref for aset
(defun aset (arr idx val) (setf (aref arr idx) val))

;; w64 = (w32-hi . w32-lo) pair
(defun w64-add (a b)
  (let ((lo-a (cdr a)) (lo-b (cdr b)))
    (let ((lo-sum-lo (+ (cdr lo-a) (cdr lo-b))))
      (let ((lo-carry1 (ash lo-sum-lo -16))
            (lo-sum-lo16 (logand lo-sum-lo #xFFFF)))
        (let ((lo-sum-hi (+ (car lo-a) (+ (car lo-b) lo-carry1))))
          (let ((lo-carry2 (ash lo-sum-hi -16))
                (lo-sum-hi16 (logand lo-sum-hi #xFFFF)))
            (let ((lo-result (cons lo-sum-hi16 lo-sum-lo16)))
              (let ((hi-a (car a)) (hi-b (car b)))
                (let ((hi-sum-lo (+ (cdr hi-a) (+ (cdr hi-b) lo-carry2))))
                  (let ((hi-carry1 (ash hi-sum-lo -16))
                        (hi-sum-lo16 (logand hi-sum-lo #xFFFF)))
                    (let ((hi-sum-hi (+ (car hi-a) (+ (car hi-b) hi-carry1))))
                      (cons (cons (logand hi-sum-hi #xFFFF) hi-sum-lo16)
                            lo-result))))))))))))

(defun w64-xor (a b)
  (cons (w32-xor (car a) (car b))
        (w32-xor (cdr a) (cdr b))))

(defun w64-and (a b)
  (cons (w32-and (car a) (car b))
        (w32-and (cdr a) (cdr b))))

(defun w64-not (a)
  (cons (w32-not (car a))
        (w32-not (cdr a))))

;; SHA-512 Ch, Maj
(defun sha512-ch (x y z)
  (w64-xor (w64-and x y) (w64-and (w64-not x) z)))

(defun sha512-maj (x y z)
  (w64-xor (w64-xor (w64-and x y) (w64-and x z)) (w64-and y z)))

;; w64 byte I/O
(defun w64-to-bytes (w buf off)
  (w32-to-be buf off (car w))
  (w32-to-be buf (+ off 4) (cdr w)))

(defun w64-from-bytes (buf off)
  (cons (w32-from-be buf off) (w32-from-be buf (+ off 4))))

;; bytes8-rotr: rotate right 8 bytes by n bits
(defun bytes8-rotr (src dst n)
  (dotimes (i 8) (aset dst i 0))
  (let ((byte-shift (ash n -3))
        (bit-shift (logand n 7)))
    (if (zerop bit-shift)
        (dotimes (i 8)
          (let ((di (logand (+ i byte-shift) 7)))
            (aset dst di (aref src i))))
        (dotimes (i 8)
          (let ((di (logand (+ i byte-shift) 7))
                (di1 (logand (+ (+ i byte-shift) 1) 7)))
            (let ((sv (aref src i)))
              (let ((cur-di (aref dst di)))
                (let ((shifted (ash sv (- 0 bit-shift))))
                  (let ((ored (logior cur-di shifted)))
                    (aset dst di (logand ored #xFF)))))
              (let ((cur-di1 (aref dst di1)))
                (let ((mask-val (- (ash 1 bit-shift) 1)))
                  (let ((masked (logand sv mask-val)))
                    (let ((shift-amt (- 8 bit-shift)))
                      (let ((shifted2 (ash masked shift-amt)))
                        (let ((ored2 (logior cur-di1 shifted2)))
                          (aset dst di1 (logand ored2 #xFF))))))))))))))

;; bytes8-shr: shift right 8 bytes by n bits
(defun bytes8-shr (src dst n)
  (dotimes (i 8) (aset dst i 0))
  (let ((byte-shift (ash n -3))
        (bit-shift (logand n 7)))
    (if (zerop bit-shift)
        (let ((i byte-shift))
          (loop
            (when (>= i 8) (return ()))
            (aset dst i (aref src (- i byte-shift)))
            (setq i (+ i 1))))
        (let ((i byte-shift))
          (loop
            (when (>= i 8) (return ()))
            (let ((si (- i byte-shift)))
              (let ((cur (aref dst i)))
                (let ((sv (aref src si)))
                  (let ((shifted (ash sv (- 0 bit-shift))))
                    (let ((ored (logior cur shifted)))
                      (aset dst i (logand ored #xFF))))))
              (when (> si 0)
                (let ((cur2 (aref dst i)))
                  (let ((prev (aref src (- si 1))))
                    (let ((mask-val (- (ash 1 bit-shift) 1)))
                      (let ((masked (logand prev mask-val)))
                        (let ((shift-amt (- 8 bit-shift)))
                          (let ((shifted2 (ash masked shift-amt)))
                            (let ((ored2 (logior cur2 shifted2)))
                              (aset dst i (logand ored2 #xFF)))))))))))
            (setq i (+ i 1)))))))

;; SHA-512 sigma via byte arrays
(defun sha512-sigma-op (x r1 r2 r3 is-shift3)
  (let ((src (make-array 8 :initial-element 0))
        (d1 (make-array 8 :initial-element 0))
        (d2 (make-array 8 :initial-element 0))
        (d3 (make-array 8 :initial-element 0)))
    (w64-to-bytes x src 0)
    (bytes8-rotr src d1 r1)
    (bytes8-rotr src d2 r2)
    (if is-shift3
        (bytes8-shr src d3 r3)
        (bytes8-rotr src d3 r3))
    ;; XOR all three — flattened
    (dotimes (i 8)
      (let ((v1 (aref d1 i)))
        (let ((v2 (aref d2 i)))
          (let ((v3 (aref d3 i)))
            (let ((x23 (logxor v2 v3)))
              (aset d1 i (logxor v1 x23)))))))
    (w64-from-bytes d1 0)))

(defun sha512-sigma0 (x) (sha512-sigma-op x 28 34 39 nil))
(defun sha512-sigma1 (x) (sha512-sigma-op x 14 18 41 nil))
(defun sha512-lsig0 (x) (sha512-sigma-op x 1 8 7 1))
(defun sha512-lsig1 (x) (sha512-sigma-op x 19 61 6 1))

;; SHA-512 K constants — store as raw bytes
(defun sha512-set-k (i b0 b1 b2 b3 b4 b5 b6 b7)
  (let ((addr (+ #x200 (* i 8))))
    (setf (aref *state-mem* addr) b0)
    (setf (aref *state-mem* (+ addr 1)) b1)
    (setf (aref *state-mem* (+ addr 2)) b2)
    (setf (aref *state-mem* (+ addr 3)) b3)
    (setf (aref *state-mem* (+ addr 4)) b4)
    (setf (aref *state-mem* (+ addr 5)) b5)
    (setf (aref *state-mem* (+ addr 6)) b6)
    (setf (aref *state-mem* (+ addr 7)) b7)))

(defun sha512-load-k (i)
  (let ((addr (+ #x200 (* i 8))))
    (cons (cons (logior (ash (aref *state-mem* addr) 8) (aref *state-mem* (+ addr 1)))
                (logior (ash (aref *state-mem* (+ addr 2)) 8) (aref *state-mem* (+ addr 3))))
          (cons (logior (ash (aref *state-mem* (+ addr 4)) 8) (aref *state-mem* (+ addr 5)))
                (logior (ash (aref *state-mem* (+ addr 6)) 8) (aref *state-mem* (+ addr 7)))))))

(defun sha512-init ()
  (sha512-set-k 0 #x42 #x8a #x2f #x98 #xd7 #x28 #xae #x22)
  (sha512-set-k 1 #x71 #x37 #x44 #x91 #x23 #xef #x65 #xcd)
  (sha512-set-k 2 #xb5 #xc0 #xfb #xcf #xec #x4d #x3b #x2f)
  (sha512-set-k 3 #xe9 #xb5 #xdb #xa5 #x81 #x89 #xdb #xbc)
  (sha512-set-k 4 #x39 #x56 #xc2 #x5b #xf3 #x48 #xb5 #x38)
  (sha512-set-k 5 #x59 #xf1 #x11 #xf1 #xb6 #x05 #xd0 #x19)
  (sha512-set-k 6 #x92 #x3f #x82 #xa4 #xaf #x19 #x4f #x9b)
  (sha512-set-k 7 #xab #x1c #x5e #xd5 #xda #x6d #x81 #x18)
  (sha512-set-k 8 #xd8 #x07 #xaa #x98 #xa3 #x03 #x02 #x42)
  (sha512-set-k 9 #x12 #x83 #x5b #x01 #x45 #x70 #x6f #xbe)
  (sha512-set-k 10 #x24 #x31 #x85 #x9d #x4e #xe4 #xb2 #x8c)
  (sha512-set-k 11 #x55 #x0c #x7d #xc3 #xd5 #xff #xb4 #xe2)
  (sha512-set-k 12 #x72 #xbe #x5d #x74 #xf2 #x7b #x89 #x6f)
  (sha512-set-k 13 #x80 #xde #xb1 #xfe #x3b #x16 #x96 #xb1)
  (sha512-set-k 14 #x9b #xdc #x06 #xa7 #x25 #xc7 #x12 #x35)
  (sha512-set-k 15 #xc1 #x9b #xf1 #x74 #xcf #x69 #x26 #x94)
  (sha512-set-k 16 #xe4 #x9b #x69 #xc1 #x9e #xf1 #x4a #xd2)
  (sha512-set-k 17 #xef #xbe #x47 #x86 #x38 #x4f #x25 #xe3)
  (sha512-set-k 18 #x0f #xc1 #x9d #xc6 #x8b #x8c #xd5 #xb5)
  (sha512-set-k 19 #x24 #x0c #xa1 #xcc #x77 #xac #x9c #x65)
  (sha512-set-k 20 #x2d #xe9 #x2c #x6f #x59 #x2b #x02 #x75)
  (sha512-set-k 21 #x4a #x74 #x84 #xaa #x6e #xa6 #xe4 #x83)
  (sha512-set-k 22 #x5c #xb0 #xa9 #xdc #xbd #x41 #xfb #xd4)
  (sha512-set-k 23 #x76 #xf9 #x88 #xda #x83 #x11 #x53 #xb5)
  (sha512-set-k 24 #x98 #x3e #x51 #x52 #xee #x66 #xdf #xab)
  (sha512-set-k 25 #xa8 #x31 #xc6 #x6d #x2d #xb4 #x32 #x10)
  (sha512-set-k 26 #xb0 #x03 #x27 #xc8 #x98 #xfb #x21 #x3f)
  (sha512-set-k 27 #xbf #x59 #x7f #xc7 #xbe #xef #x0e #xe4)
  (sha512-set-k 28 #xc6 #xe0 #x0b #xf3 #x3d #xa8 #x8f #xc2)
  (sha512-set-k 29 #xd5 #xa7 #x91 #x47 #x93 #x0a #xa7 #x25)
  (sha512-set-k 30 #x06 #xca #x63 #x51 #xe0 #x03 #x82 #x6f)
  (sha512-set-k 31 #x14 #x29 #x29 #x67 #x0a #x0e #x6e #x70)
  (sha512-set-k 32 #x27 #xb7 #x0a #x85 #x46 #xd2 #x2f #xfc)
  (sha512-set-k 33 #x2e #x1b #x21 #x38 #x5c #x26 #xc9 #x26)
  (sha512-set-k 34 #x4d #x2c #x6d #xfc #x5a #xc4 #x2a #xed)
  (sha512-set-k 35 #x53 #x38 #x0d #x13 #x9d #x95 #xb3 #xdf)
  (sha512-set-k 36 #x65 #x0a #x73 #x54 #x8b #xaf #x63 #xde)
  (sha512-set-k 37 #x76 #x6a #x0a #xbb #x3c #x77 #xb2 #xa8)
  (sha512-set-k 38 #x81 #xc2 #xc9 #x2e #x47 #xed #xae #xe6)
  (sha512-set-k 39 #x92 #x72 #x2c #x85 #x14 #x82 #x35 #x3b)
  (sha512-set-k 40 #xa2 #xbf #xe8 #xa1 #x4c #xf1 #x03 #x64)
  (sha512-set-k 41 #xa8 #x1a #x66 #x4b #xbc #x42 #x30 #x01)
  (sha512-set-k 42 #xc2 #x4b #x8b #x70 #xd0 #xf8 #x97 #x91)
  (sha512-set-k 43 #xc7 #x6c #x51 #xa3 #x06 #x54 #xbe #x30)
  (sha512-set-k 44 #xd1 #x92 #xe8 #x19 #xd6 #xef #x52 #x18)
  (sha512-set-k 45 #xd6 #x99 #x06 #x24 #x55 #x65 #xa9 #x10)
  (sha512-set-k 46 #xf4 #x0e #x35 #x85 #x57 #x71 #x20 #x2a)
  (sha512-set-k 47 #x10 #x6a #xa0 #x70 #x32 #xbb #xd1 #xb8)
  (sha512-set-k 48 #x19 #xa4 #xc1 #x16 #xb8 #xd2 #xd0 #xc8)
  (sha512-set-k 49 #x1e #x37 #x6c #x08 #x51 #x41 #xab #x53)
  (sha512-set-k 50 #x27 #x48 #x77 #x4c #xdf #x8e #xeb #x99)
  (sha512-set-k 51 #x34 #xb0 #xbc #xb5 #xe1 #x9b #x48 #xa8)
  (sha512-set-k 52 #x39 #x1c #x0c #xb3 #xc5 #xc9 #x5a #x63)
  (sha512-set-k 53 #x4e #xd8 #xaa #x4a #xe3 #x41 #x8a #xcb)
  (sha512-set-k 54 #x5b #x9c #xca #x4f #x77 #x63 #xe3 #x73)
  (sha512-set-k 55 #x68 #x2e #x6f #xf3 #xd6 #xb2 #xb8 #xa3)
  (sha512-set-k 56 #x74 #x8f #x82 #xee #x5d #xef #xb2 #xfc)
  (sha512-set-k 57 #x78 #xa5 #x63 #x6f #x43 #x17 #x2f #x60)
  (sha512-set-k 58 #x84 #xc8 #x78 #x14 #xa1 #xf0 #xab #x72)
  (sha512-set-k 59 #x8c #xc7 #x02 #x08 #x1a #x64 #x39 #xec)
  (sha512-set-k 60 #x90 #xbe #xff #xfa #x23 #x63 #x1e #x28)
  (sha512-set-k 61 #xa4 #x50 #x6c #xeb #xde #x82 #xbd #xe9)
  (sha512-set-k 62 #xbe #xf9 #xa3 #xf7 #xb2 #xc6 #x79 #x15)
  (sha512-set-k 63 #xc6 #x71 #x78 #xf2 #xe3 #x72 #x53 #x2b)
  (sha512-set-k 64 #xca #x27 #x3e #xce #xea #x26 #x61 #x9c)
  (sha512-set-k 65 #xd1 #x86 #xb8 #xc7 #x21 #xc0 #xc2 #x07)
  (sha512-set-k 66 #xea #xda #x7d #xd6 #xcd #xe0 #xeb #x1e)
  (sha512-set-k 67 #xf5 #x7d #x4f #x7f #xee #x6e #xd1 #x78)
  (sha512-set-k 68 #x06 #xf0 #x67 #xaa #x72 #x17 #x6f #xba)
  (sha512-set-k 69 #x0a #x63 #x7d #xc5 #xa2 #xc8 #x98 #xa6)
  (sha512-set-k 70 #x11 #x3f #x98 #x04 #xbe #xf9 #x0d #xae)
  (sha512-set-k 71 #x1b #x71 #x0b #x35 #x13 #x1c #x47 #x1b)
  (sha512-set-k 72 #x28 #xdb #x77 #xf5 #x23 #x04 #x7d #x84)
  (sha512-set-k 73 #x32 #xca #xab #x7b #x40 #xc7 #x24 #x93)
  (sha512-set-k 74 #x3c #x9e #xbe #x0a #x15 #xc9 #xbe #xbc)
  (sha512-set-k 75 #x43 #x1d #x67 #xc4 #x9c #x10 #x0d #x4c)
  (sha512-set-k 76 #x4c #xc5 #xd4 #xbe #xcb #x3e #x42 #xb6)
  (sha512-set-k 77 #x59 #x7f #x29 #x9c #xfc #x65 #x7e #x2a)
  (sha512-set-k 78 #x5f #xcb #x6f #xab #x3a #xd6 #xfa #xec)
  (sha512-set-k 79 #x6c #x44 #x19 #x8c #x4a #x47 #x58 #x17))

;; w64 working array I/O
(defun w64-wstore (arr off w)
  (w32-to-be arr off (car w))
  (w32-to-be arr (+ off 4) (cdr w)))

(defun w64-wload (arr off)
  (cons (w32-from-be arr off) (w32-from-be arr (+ off 4))))

;; SHA-512 block compression
(defun sha512-block (block bo h w)
  ;; Read 16 message words (big-endian u64)
  (dotimes (i 16)
    (let ((j (+ bo (* i 8))))
      (w64-wstore w (* i 8) (w64-from-bytes block j))))
  ;; Expand W[16..79]
  (let ((i 16))
    (loop
      (when (not (< i 80)) (return ()))
      (let ((s1 (sha512-lsig1 (w64-wload w (* (- i 2) 8)))))
        (let ((s0 (sha512-lsig0 (w64-wload w (* (- i 15) 8)))))
          (let ((w7 (w64-wload w (* (- i 7) 8))))
            (let ((w16 (w64-wload w (* (- i 16) 8))))
              (let ((t0 (w64-add s0 w16)))
                (let ((t1 (w64-add w7 t0)))
                  (w64-wstore w (* i 8) (w64-add s1 t1))))))))
      (setq i (+ i 1))))
  ;; Initialize working variables
  (let ((a (w64-wload h 0))
        (b (w64-wload h 8))
        (cc (w64-wload h 16))
        (d (w64-wload h 24))
        (e (w64-wload h 32))
        (f (w64-wload h 40))
        (g (w64-wload h 48))
        (hh (w64-wload h 56)))
    ;; 80 rounds
    (dotimes (i 80)
      (let ((ki (sha512-load-k i)))
        (let ((wi (w64-wload w (* i 8))))
          (let ((sig1 (sha512-sigma1 e)))
            (let ((ch-val (sha512-ch e f g)))
              (let ((s1 (w64-add ki wi)))
              (let ((s2 (w64-add ch-val s1)))
              (let ((s3 (w64-add sig1 s2)))
              (let ((t1 (w64-add hh s3)))
                (let ((sig0 (sha512-sigma0 a)))
                  (let ((maj-val (sha512-maj a b cc)))
                    (let ((t2 (w64-add sig0 maj-val)))
                      (setq hh g)
                      (setq g f)
                      (setq f e)
                      (setq e (w64-add d t1))
                      (setq d cc)
                      (setq cc b)
                      (setq b a)
                      (setq a (w64-add t1 t2))))))))))))))
    ;; Add back
    (w64-wstore h 0 (w64-add (w64-wload h 0) a))
    (w64-wstore h 8 (w64-add (w64-wload h 8) b))
    (w64-wstore h 16 (w64-add (w64-wload h 16) cc))
    (w64-wstore h 24 (w64-add (w64-wload h 24) d))
    (w64-wstore h 32 (w64-add (w64-wload h 32) e))
    (w64-wstore h 40 (w64-add (w64-wload h 40) f))
    (w64-wstore h 48 (w64-add (w64-wload h 48) g))
    (w64-wstore h 56 (w64-add (w64-wload h 56) hh))))

;; SHA-512 hash (byte array → 64-byte hash)
(defun sha512 (msg)
  (let ((msg-len (length msg)))
    (let ((r (mod (+ msg-len 17) 128)))
      (let ((pad-extra (if (zerop r) 0 (- 128 r))))
      (let ((total (+ (+ msg-len 17) pad-extra)))
        (let ((padded (make-array total :initial-element 0)))
          (dotimes (i msg-len) (aset padded i (aref msg i)))
          (aset padded msg-len #x80)
          ;; Bit length
          (let ((bits (* msg-len 8)))
            (aset padded (- total 4) (logand (ash bits -24) #xFF))
            (aset padded (- total 3) (logand (ash bits -16) #xFF))
            (aset padded (- total 2) (logand (ash bits -8) #xFF))
            (aset padded (- total 1) (logand bits #xFF)))
          ;; Initial hash values
          (let ((h (make-array 64 :initial-element 0)))
            (aset h 0 #x6a) (aset h 1 #x09) (aset h 2 #xe6) (aset h 3 #x67)
            (aset h 4 #xf3) (aset h 5 #xbc) (aset h 6 #xc9) (aset h 7 #x08)
            (aset h 8 #xbb) (aset h 9 #x67) (aset h 10 #xae) (aset h 11 #x85)
            (aset h 12 #x84) (aset h 13 #xca) (aset h 14 #xa7) (aset h 15 #x3b)
            (aset h 16 #x3c) (aset h 17 #x6e) (aset h 18 #xf3) (aset h 19 #x72)
            (aset h 20 #xfe) (aset h 21 #x94) (aset h 22 #xf8) (aset h 23 #x2b)
            (aset h 24 #xa5) (aset h 25 #x4f) (aset h 26 #xf5) (aset h 27 #x3a)
            (aset h 28 #x5f) (aset h 29 #x1d) (aset h 30 #x36) (aset h 31 #xf1)
            (aset h 32 #x51) (aset h 33 #x0e) (aset h 34 #x52) (aset h 35 #x7f)
            (aset h 36 #xad) (aset h 37 #xe6) (aset h 38 #x82) (aset h 39 #xd1)
            (aset h 40 #x9b) (aset h 41 #x05) (aset h 42 #x68) (aset h 43 #x8c)
            (aset h 44 #x2b) (aset h 45 #x3e) (aset h 46 #x6c) (aset h 47 #x1f)
            (aset h 48 #x1f) (aset h 49 #x83) (aset h 50 #xd9) (aset h 51 #xab)
            (aset h 52 #xfb) (aset h 53 #x41) (aset h 54 #xbd) (aset h 55 #x6b)
            (aset h 56 #x5b) (aset h 57 #xe0) (aset h 58 #xcd) (aset h 59 #x19)
            (aset h 60 #x13) (aset h 61 #x7e) (aset h 62 #x21) (aset h 63 #x79)
            ;; Process blocks
            (let ((w (make-array 640 :initial-element 0))
                  (bo 0))
              (loop
                (when (>= bo total) (return ()))
                (sha512-block padded bo h w)
                (setq bo (+ bo 128))))
            h)))))))

;; ================================================================
;; Test harness
;; ================================================================

(defun hex-string (arr &optional (start 0) (len (length arr)))
  (with-output-to-string (s)
    (dotimes (i len)
      (format s "~2,'0X" (aref arr (+ start i))))))

(defun test-w64-add ()
  (format t "~&=== w64-add test ===~%")
  ;; 0x6A09E667F3BCC908 + 0xBB67AE8584CAA73B
  (let ((a (cons (cons #x6A09 #xE667) (cons #xF3BC #xC908)))
        (b (cons (cons #xBB67 #xAE85) (cons #x84CA #xA73B))))
    (let ((s (w64-add a b)))
      (let ((result (make-array 8 :initial-element 0)))
        (w64-to-bytes s result 0)
        (let ((hex (hex-string result)))
          (format t "  0x6A09E667F3BCC908 + 0xBB67AE8584CAA73B = ~A~%" hex)
          (format t "  Expected: 257194ED78877043~%")
          (assert (string= hex "257194ED78877043") ()
                  "w64-add failed: got ~A" hex))))))

(defun test-sha512-empty ()
  (format t "~&=== SHA-512(\"\") test ===~%")
  (sha512-init)
  (let ((result (sha512 (make-array 0 :initial-element 0))))
    (let ((hex (hex-string result)))
      (format t "  Result: ~A~%" hex)
      (format t "  Expect: CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E~%")
      (assert (string= hex "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E")
              () "SHA-512('') failed"))))

(defun test-sha512-zeros32 ()
  (format t "~&=== SHA-512(32 zero bytes) test ===~%")
  (sha512-init)
  (let ((result (sha512 (make-array 32 :initial-element 0))))
    (let ((hex (hex-string result)))
      (format t "  Result: ~A~%" hex)
      (format t "  Expect: 5046ADC1DBA838864882488F45A0A0DE96714FC543F74D7B67297B14F5E7A17F0A6A85EAA642DAC835D5D08FBD86C8D56CEB51B4764B90027F498521420B6DD3~%")
      ;; Check each 8-byte segment
      (dotimes (seg 8)
        (let ((seg-hex (hex-string result (* seg 8) 8)))
          (format t "  H~D: ~A~%" seg seg-hex)))
      (assert (string= hex "5046ADC1DBA838864882488F45A0A0DE96714FC543F74D7B67297B14F5E7A17F0A6A85EAA642DAC835D5D08FBD86C8D56CEB51B4764B90027F498521420B6DD3")
              () "SHA-512(32 zeros) failed"))))

(defun test-sha512-one-zero ()
  (format t "~&=== SHA-512(single zero byte) test ===~%")
  (sha512-init)
  (let ((input (make-array 1 :initial-element 0)))
    (let ((result (sha512 input)))
      (let ((hex (hex-string result 0 8)))
        (format t "  First 8 bytes: ~A~%" hex)
        (format t "  Expected:      B8244D028981D693~%")
        (assert (string= hex "B8244D028981D693") ()
                "SHA-512(0x00) first 8 bytes failed: got ~A" hex)))))

;; ================================================================
;; Reference SHA-512 using native 64-bit integers
;; ================================================================

(defconstant +sha512-k+
  #(#x428a2f98d728ae22 #x7137449123ef65cd #xb5c0fbcfec4d3b2f #xe9b5dba58189dbbc
    #x3956c25bf348b538 #x59f111f1b605d019 #x923f82a4af194f9b #xab1c5ed5da6d8118
    #xd807aa98a3030242 #x12835b0145706fbe #x2431859d4ee4b28c #x550c7dc3d5ffb4e2
    #x72be5d74f27b896f #x80deb1fe3b1696b1 #x9bdc06a725c71235 #xc19bf174cf692694
    #xe49b69c19ef14ad2 #xefbe4786384f25e3 #x0fc19dc68b8cd5b5 #x240ca1cc77ac9c65
    #x2de92c6f592b0275 #x4a7484aa6ea6e483 #x5cb0a9dcbd41fbd4 #x76f988da831153b5
    #x983e5152ee66dfab #xa831c66d2db43210 #xb00327c898fb213f #xbf597fc7beef0ee4
    #xc6e00bf33da88fc2 #xd5a79147930aa725 #x06ca6351e003826f #x142929670a0e6e70
    #x27b70a8546d22ffc #x2e1b21385c26c926 #x4d2c6dfc5ac42aed #x53380d139d95b3df
    #x650a73548baf63de #x766a0abb3c77b2a8 #x81c2c92e47edaee6 #x92722c851482353b
    #xa2bfe8a14cf10364 #xa81a664bbc423001 #xc24b8b70d0f89791 #xc76c51a30654be30
    #xd192e819d6ef5218 #xd69906245565a910 #xf40e35855771202a #x106aa07032bbd1b8
    #x19a4c116b8d2d0c8 #x1e376c085141ab53 #x2748774cdf8eeb99 #x34b0bcb5e19b48a8
    #x391c0cb3c5c95a63 #x4ed8aa4ae3418acb #x5b9cca4f7763e373 #x682e6ff3d6b2b8a3
    #x748f82ee5defb2fc #x78a5636f43172f60 #x84c87814a1f0ab72 #x8cc702081a6439ec
    #x90befffa23631e28 #xa4506cebde82bde9 #xbef9a3f7b2c67915 #xc67178f2e372532b
    #xca273eceea26619c #xd186b8c721c0c207 #xeada7dd6cde0eb1e #xf57d4f7fee6ed178
    #x06f067aa72176fba #x0a637dc5a2c898a6 #x113f9804bef90dae #x1b710b35131c471b
    #x28db77f523047d84 #x32caab7b40c72493 #x3c9ebe0a15c9bebc #x431d67c49c100d4c
    #x4cc5d4becb3e42b6 #x597f299cfc657e2a #x5fcb6fab3ad6faec #x6c44198c4a475817))

(defun u64 (x) (logand x #xFFFFFFFFFFFFFFFF))
(defun u64+ (a b) (u64 (+ a b)))
(defun u64-rotr (x n) (u64 (logior (ash x (- n)) (ash x (- 64 n)))))
(defun u64-shr (x n) (ash x (- n)))

(defun ref-sigma0 (x) (logxor (u64-rotr x 28) (u64-rotr x 34) (u64-rotr x 39)))
(defun ref-sigma1 (x) (logxor (u64-rotr x 14) (u64-rotr x 18) (u64-rotr x 41)))
(defun ref-lsig0 (x) (logxor (u64-rotr x 1) (u64-rotr x 8) (u64-shr x 7)))
(defun ref-lsig1 (x) (logxor (u64-rotr x 19) (u64-rotr x 61) (u64-shr x 6)))
(defun ref-ch (e f g) (logxor (logand e f) (logand (u64 (lognot e)) g)))
(defun ref-maj (a b c) (logxor (logand a b) (logand a c) (logand b c)))

(defun ref-sha512 (msg)
  (let* ((msg-len (length msg))
         (r (mod (+ msg-len 17) 128))
         (pad-extra (if (zerop r) 0 (- 128 r)))
         (total (+ msg-len 17 pad-extra))
         (padded (make-array total :initial-element 0)))
    (dotimes (i msg-len) (setf (aref padded i) (aref msg i)))
    (setf (aref padded msg-len) #x80)
    (let ((bits (* msg-len 8)))
      (setf (aref padded (- total 4)) (logand (ash bits -24) #xFF))
      (setf (aref padded (- total 3)) (logand (ash bits -16) #xFF))
      (setf (aref padded (- total 2)) (logand (ash bits -8) #xFF))
      (setf (aref padded (- total 1)) (logand bits #xFF)))
    (let ((h (vector #x6a09e667f3bcc908 #xbb67ae8584caa73b
                     #x3c6ef372fe94f82b #xa54ff53a5f1d36f1
                     #x510e527fade682d1 #x9b05688c2b3e6c1f
                     #x1f83d9abfb41bd6b #x5be0cd19137e2179)))
      (loop for bo from 0 below total by 128 do
        (let ((w (make-array 80 :initial-element 0)))
          ;; Read 16 message words
          (dotimes (i 16)
            (let ((j (+ bo (* i 8))))
              (setf (aref w i)
                    (logior (ash (aref padded j) 56)
                            (ash (aref padded (+ j 1)) 48)
                            (ash (aref padded (+ j 2)) 40)
                            (ash (aref padded (+ j 3)) 32)
                            (ash (aref padded (+ j 4)) 24)
                            (ash (aref padded (+ j 5)) 16)
                            (ash (aref padded (+ j 6)) 8)
                            (aref padded (+ j 7))))))
          ;; Expand
          (loop for i from 16 below 80 do
            (setf (aref w i) (u64+ (ref-lsig1 (aref w (- i 2)))
                                    (u64+ (aref w (- i 7))
                                           (u64+ (ref-lsig0 (aref w (- i 15)))
                                                  (aref w (- i 16)))))))
          ;; Rounds
          (let ((a (aref h 0)) (b (aref h 1)) (cc (aref h 2)) (d (aref h 3))
                (e (aref h 4)) (f (aref h 5)) (g (aref h 6)) (hh (aref h 7)))
            (dotimes (i 80)
              (let* ((t1 (u64+ hh (u64+ (ref-sigma1 e) (u64+ (ref-ch e f g) (u64+ (aref +sha512-k+ i) (aref w i))))))
                     (t2 (u64+ (ref-sigma0 a) (ref-maj a b cc))))
                (setq hh g g f f e e (u64+ d t1) d cc cc b b a a (u64+ t1 t2))))
            (setf (aref h 0) (u64+ (aref h 0) a))
            (setf (aref h 1) (u64+ (aref h 1) b))
            (setf (aref h 2) (u64+ (aref h 2) cc))
            (setf (aref h 3) (u64+ (aref h 3) d))
            (setf (aref h 4) (u64+ (aref h 4) e))
            (setf (aref h 5) (u64+ (aref h 5) f))
            (setf (aref h 6) (u64+ (aref h 6) g))
            (setf (aref h 7) (u64+ (aref h 7) hh)))))
      ;; Convert to bytes
      (let ((result (make-array 64 :initial-element 0)))
        (dotimes (i 8)
          (let ((v (aref h i)))
            (dotimes (j 8)
              (setf (aref result (+ (* i 8) j))
                    (logand (ash v (- (* (- 7 j) 8))) #xFF)))))
        result))))

;; ================================================================
;; Comparative debug: find where w32 and ref diverge
;; ================================================================

(defun w64-to-u64 (w)
  "Convert w64 cons pair to native u64"
  (let ((hi (car w)) (lo (cdr w)))
    (logior (ash (car hi) 48) (ash (cdr hi) 32)
            (ash (car lo) 16) (cdr lo))))

(defun test-sha512-compare ()
  "Run w32 and ref SHA-512 side by side, compare W schedule and round state"
  (format t "~&=== SHA-512 w32 vs reference comparison ===~%")
  (sha512-init)
  (let* ((msg (make-array 32 :initial-element 0))
         (msg-len 32)
         (r (mod (+ msg-len 17) 128))
         (pad-extra (if (zerop r) 0 (- 128 r)))
         (total (+ msg-len 17 pad-extra))
         (padded (make-array total :initial-element 0)))
    (setf (aref padded msg-len) #x80)
    (let ((bits (* msg-len 8)))
      (setf (aref padded (- total 4)) (logand (ash bits -24) #xFF))
      (setf (aref padded (- total 3)) (logand (ash bits -16) #xFF))
      (setf (aref padded (- total 2)) (logand (ash bits -8) #xFF))
      (setf (aref padded (- total 1)) (logand bits #xFF)))

    ;; Reference W schedule
    (let ((ref-w (make-array 80 :initial-element 0)))
      (dotimes (i 16)
        (let ((j (* i 8)))
          (setf (aref ref-w i)
                (logior (ash (aref padded j) 56) (ash (aref padded (+ j 1)) 48)
                        (ash (aref padded (+ j 2)) 40) (ash (aref padded (+ j 3)) 32)
                        (ash (aref padded (+ j 4)) 24) (ash (aref padded (+ j 5)) 16)
                        (ash (aref padded (+ j 6)) 8) (aref padded (+ j 7))))))
      (loop for i from 16 below 80 do
        (setf (aref ref-w i) (u64+ (ref-lsig1 (aref ref-w (- i 2)))
                                    (u64+ (aref ref-w (- i 7))
                                           (u64+ (ref-lsig0 (aref ref-w (- i 15)))
                                                  (aref ref-w (- i 16)))))))

      ;; w32 W schedule
      (let ((w32-w (make-array 640 :initial-element 0)))
        (dotimes (i 16)
          (let ((j (* i 8)))
            (w64-wstore w32-w (* i 8) (w64-from-bytes padded j))))
        ;; Expand
        (let ((i 16))
          (loop
            (when (not (< i 80)) (return ()))
            (let ((s1 (sha512-lsig1 (w64-wload w32-w (* (- i 2) 8)))))
              (let ((s0 (sha512-lsig0 (w64-wload w32-w (* (- i 15) 8)))))
                (let ((w7 (w64-wload w32-w (* (- i 7) 8))))
                  (let ((w16 (w64-wload w32-w (* (- i 16) 8))))
                    (let ((t0 (w64-add s0 w16)))
                      (let ((t1 (w64-add w7 t0)))
                        (w64-wstore w32-w (* i 8) (w64-add s1 t1))))))))
            (setq i (+ i 1))))

        ;; Compare W schedules
        (format t "~&  Comparing W schedule:~%")
        (let ((first-diff nil))
          (dotimes (i 80)
            (let ((ref-val (aref ref-w i))
                  (w32-val (w64-to-u64 (w64-wload w32-w (* i 8)))))
              (when (and (not (= ref-val w32-val)) (not first-diff))
                (setq first-diff i)
                (format t "  FIRST W divergence at W[~D]:~%" i)
                (format t "    ref: ~16,'0X~%" ref-val)
                (format t "    w32: ~16,'0X~%" w32-val)
                ;; Also show inputs
                (when (>= i 16)
                  (format t "    W[~D] ref=~16,'0X w32=~16,'0X~%" (- i 2) (aref ref-w (- i 2)) (w64-to-u64 (w64-wload w32-w (* (- i 2) 8))))
                  (format t "    W[~D] ref=~16,'0X w32=~16,'0X~%" (- i 7) (aref ref-w (- i 7)) (w64-to-u64 (w64-wload w32-w (* (- i 7) 8))))
                  (format t "    W[~D] ref=~16,'0X w32=~16,'0X~%" (- i 15) (aref ref-w (- i 15)) (w64-to-u64 (w64-wload w32-w (* (- i 15) 8))))
                  (format t "    W[~D] ref=~16,'0X w32=~16,'0X~%" (- i 16) (aref ref-w (- i 16)) (w64-to-u64 (w64-wload w32-w (* (- i 16) 8))))
                  ;; Also show intermediate sigma values
                  (let* ((w2 (w64-wload w32-w (* (- i 2) 8)))
                         (w15 (w64-wload w32-w (* (- i 15) 8)))
                         (ls1 (sha512-lsig1 w2))
                         (ls0 (sha512-lsig0 w15)))
                    (format t "    lsig1(W[~D]) w32=~16,'0X ref=~16,'0X~%"
                            (- i 2) (w64-to-u64 ls1) (ref-lsig1 (aref ref-w (- i 2))))
                    (format t "    lsig0(W[~D]) w32=~16,'0X ref=~16,'0X~%"
                            (- i 15) (w64-to-u64 ls0) (ref-lsig0 (aref ref-w (- i 15)))))))))
          (unless first-diff
            (format t "  W schedule: all 80 words match!~%"))

          ;; Compare round state
          (format t "~&  Comparing round state:~%")
          (let ((ref-a #x6a09e667f3bcc908) (ref-b #xbb67ae8584caa73b)
                (ref-c #x3c6ef372fe94f82b) (ref-d #xa54ff53a5f1d36f1)
                (ref-e #x510e527fade682d1) (ref-f #x9b05688c2b3e6c1f)
                (ref-g #x1f83d9abfb41bd6b) (ref-hh #x5be0cd19137e2179))
            ;; Load w32 initial state
            (let ((w32-h (make-array 64 :initial-element 0)))
              ;; Copy IV
              (dolist (pair '((0 #x6a #x09 #xe6 #x67 #xf3 #xbc #xc9 #x08)
                              (8 #xbb #x67 #xae #x85 #x84 #xca #xa7 #x3b)
                              (16 #x3c #x6e #xf3 #x72 #xfe #x94 #xf8 #x2b)
                              (24 #xa5 #x4f #xf5 #x3a #x5f #x1d #x36 #xf1)
                              (32 #x51 #x0e #x52 #x7f #xad #xe6 #x82 #xd1)
                              (40 #x9b #x05 #x68 #x8c #x2b #x3e #x6c #x1f)
                              (48 #x1f #x83 #xd9 #xab #xfb #x41 #xbd #x6b)
                              (56 #x5b #xe0 #xcd #x19 #x13 #x7e #x21 #x79)))
                (loop for j from 0 below 8 do
                  (setf (aref w32-h (+ (car pair) j)) (nth (1+ j) pair))))

              (let ((w32-a (w64-wload w32-h 0))
                    (w32-b (w64-wload w32-h 8))
                    (w32-cc (w64-wload w32-h 16))
                    (w32-d (w64-wload w32-h 24))
                    (w32-e (w64-wload w32-h 32))
                    (w32-f (w64-wload w32-h 40))
                    (w32-g (w64-wload w32-h 48))
                    (w32-hh (w64-wload w32-h 56)))
                (let ((first-round-diff nil))
                  (dotimes (i 80)
                    ;; ref round
                    (let* ((ref-t1 (u64+ ref-hh (u64+ (ref-sigma1 ref-e) (u64+ (ref-ch ref-e ref-f ref-g)
                                                                                 (u64+ (aref +sha512-k+ i) (aref ref-w i))))))
                           (ref-t2 (u64+ (ref-sigma0 ref-a) (ref-maj ref-a ref-b ref-c))))
                      (setq ref-hh ref-g ref-g ref-f ref-f ref-e ref-e (u64+ ref-d ref-t1)
                            ref-d ref-c ref-c ref-b ref-b ref-a ref-a (u64+ ref-t1 ref-t2)))
                    ;; w32 round
                    (let ((ki (sha512-load-k i)))
                      (let ((wi (w64-wload w32-w (* i 8))))
                        (let ((sig1 (sha512-sigma1 w32-e)))
                          (let ((ch-val (sha512-ch w32-e w32-f w32-g)))
                            (let ((s1 (w64-add ki wi)))
                              (let ((s2 (w64-add ch-val s1)))
                                (let ((s3 (w64-add sig1 s2)))
                                  (let ((t1 (w64-add w32-hh s3)))
                                    (let ((sig0 (sha512-sigma0 w32-a)))
                                      (let ((maj-val (sha512-maj w32-a w32-b w32-cc)))
                                        (let ((t2 (w64-add sig0 maj-val)))
                                          (setq w32-hh w32-g)
                                          (setq w32-g w32-f)
                                          (setq w32-f w32-e)
                                          (setq w32-e (w64-add w32-d t1))
                                          (setq w32-d w32-cc)
                                          (setq w32-cc w32-b)
                                          (setq w32-b w32-a)
                                          (setq w32-a (w64-add t1 t2)))))))))))))
                    ;; Compare
                    (when (and (not first-round-diff)
                               (not (= ref-a (w64-to-u64 w32-a))))
                      (setq first-round-diff i)
                      (format t "  FIRST round divergence at round ~D:~%" i)
                      (format t "    ref-a: ~16,'0X  w32-a: ~16,'0X~%" ref-a (w64-to-u64 w32-a))
                      (format t "    ref-e: ~16,'0X  w32-e: ~16,'0X~%" ref-e (w64-to-u64 w32-e)))
                    )
                  (unless first-round-diff
                    (format t "  Round state: all 80 rounds match!~%"))
                  ;; Show final state
                  (format t "  Final state:~%")
                  (format t "    ref-a=~16,'0X w32-a=~16,'0X~%" ref-a (w64-to-u64 w32-a))
                  (format t "    ref-b=~16,'0X w32-b=~16,'0X~%" ref-b (w64-to-u64 w32-b))
                  (format t "    ref-e=~16,'0X w32-e=~16,'0X~%" ref-e (w64-to-u64 w32-e)))))))))))

(defun test-round10-detail ()
  "Replay SHA-512 rounds 0-10 with detailed step-by-step comparison at round 10"
  (format t "~&=== Round 10 detailed comparison ===~%")
  (sha512-init)
  (let* ((msg (make-array 32 :initial-element 0))
         (msg-len 32)
         (total 128)
         (padded (make-array total :initial-element 0)))
    (setf (aref padded msg-len) #x80)
    (setf (aref padded 126) 1) ;; 256 bits = 0x100
    ;; Build W schedule (already verified correct)
    (let ((ref-w (make-array 80 :initial-element 0))
          (w32-w (make-array 640 :initial-element 0)))
      (dotimes (i 16)
        (let ((j (* i 8)))
          (setf (aref ref-w i)
                (logior (ash (aref padded j) 56) (ash (aref padded (+ j 1)) 48)
                        (ash (aref padded (+ j 2)) 40) (ash (aref padded (+ j 3)) 32)
                        (ash (aref padded (+ j 4)) 24) (ash (aref padded (+ j 5)) 16)
                        (ash (aref padded (+ j 6)) 8) (aref padded (+ j 7))))
          (w64-wstore w32-w (* i 8) (w64-from-bytes padded j))))
      (loop for i from 16 below 80 do
        (setf (aref ref-w i) (u64+ (ref-lsig1 (aref ref-w (- i 2)))
                                    (u64+ (aref ref-w (- i 7))
                                           (u64+ (ref-lsig0 (aref ref-w (- i 15)))
                                                  (aref ref-w (- i 16)))))))
      (let ((i 16))
        (loop (when (>= i 80) (return ()))
          (let ((s1 (sha512-lsig1 (w64-wload w32-w (* (- i 2) 8)))))
            (let ((s0 (sha512-lsig0 (w64-wload w32-w (* (- i 15) 8)))))
              (let ((w7 (w64-wload w32-w (* (- i 7) 8))))
                (let ((w16 (w64-wload w32-w (* (- i 16) 8))))
                  (let ((t0 (w64-add s0 w16)))
                    (let ((t1 (w64-add w7 t0)))
                      (w64-wstore w32-w (* i 8) (w64-add s1 t1))))))))
          (setq i (+ i 1))))
      ;; Run rounds 0-10
      (let ((ref-a #x6a09e667f3bcc908) (ref-b #xbb67ae8584caa73b)
            (ref-c #x3c6ef372fe94f82b) (ref-d #xa54ff53a5f1d36f1)
            (ref-e #x510e527fade682d1) (ref-f #x9b05688c2b3e6c1f)
            (ref-g #x1f83d9abfb41bd6b) (ref-hh #x5be0cd19137e2179))
        (let ((w32-a (cons (cons #x6a09 #xe667) (cons #xf3bc #xc908)))
              (w32-b (cons (cons #xbb67 #xae85) (cons #x84ca #xa73b)))
              (w32-cc (cons (cons #x3c6e #xf372) (cons #xfe94 #xf82b)))
              (w32-d (cons (cons #xa54f #xf53a) (cons #x5f1d #x36f1)))
              (w32-e (cons (cons #x510e #x527f) (cons #xade6 #x82d1)))
              (w32-f (cons (cons #x9b05 #x688c) (cons #x2b3e #x6c1f)))
              (w32-g (cons (cons #x1f83 #xd9ab) (cons #xfb41 #xbd6b)))
              (w32-hh (cons (cons #x5be0 #xcd19) (cons #x137e #x2179))))
          (dotimes (round-num 11)
            ;; ref round
            (let* ((ref-t1 (u64+ ref-hh (u64+ (ref-sigma1 ref-e)
                                               (u64+ (ref-ch ref-e ref-f ref-g)
                                                      (u64+ (aref +sha512-k+ round-num) (aref ref-w round-num))))))
                   (ref-t2 (u64+ (ref-sigma0 ref-a) (ref-maj ref-a ref-b ref-c))))
              ;; w32 round - step by step
              (let ((ki (sha512-load-k round-num))
                    (wi (w64-wload w32-w (* round-num 8))))
                (let ((w32-sig1 (sha512-sigma1 w32-e))
                      (w32-ch (sha512-ch w32-e w32-f w32-g)))
                  (let ((w32-s1 (w64-add ki wi)))
                    (let ((w32-s2 (w64-add w32-ch w32-s1)))
                      (let ((w32-s3 (w64-add w32-sig1 w32-s2)))
                        (let ((w32-t1 (w64-add w32-hh w32-s3)))
                          (let ((w32-sig0 (sha512-sigma0 w32-a))
                                (w32-maj (sha512-maj w32-a w32-b w32-cc)))
                            (let ((w32-t2 (w64-add w32-sig0 w32-maj)))
                              ;; Print detailed comparison for round 9 and 10
                              (when (>= round-num 9)
                                (format t "~%  Round ~D:~%" round-num)
                                (format t "    sigma1(e):  ref=~16,'0X w32=~16,'0X ~A~%"
                                        (ref-sigma1 ref-e) (w64-to-u64 w32-sig1)
                                        (if (= (ref-sigma1 ref-e) (w64-to-u64 w32-sig1)) "OK" "MISMATCH"))
                                (format t "    ch(e,f,g):  ref=~16,'0X w32=~16,'0X ~A~%"
                                        (ref-ch ref-e ref-f ref-g) (w64-to-u64 w32-ch)
                                        (if (= (ref-ch ref-e ref-f ref-g) (w64-to-u64 w32-ch)) "OK" "MISMATCH"))
                                (format t "    K[~D]+W[~D]: ref=~16,'0X w32=~16,'0X ~A~%"
                                        round-num round-num
                                        (u64+ (aref +sha512-k+ round-num) (aref ref-w round-num))
                                        (w64-to-u64 w32-s1)
                                        (if (= (u64+ (aref +sha512-k+ round-num) (aref ref-w round-num)) (w64-to-u64 w32-s1)) "OK" "MISMATCH"))
                                (format t "    t1:         ref=~16,'0X w32=~16,'0X ~A~%"
                                        ref-t1 (w64-to-u64 w32-t1)
                                        (if (= ref-t1 (w64-to-u64 w32-t1)) "OK" "MISMATCH"))
                                (format t "    sigma0(a):  ref=~16,'0X w32=~16,'0X ~A~%"
                                        (ref-sigma0 ref-a) (w64-to-u64 w32-sig0)
                                        (if (= (ref-sigma0 ref-a) (w64-to-u64 w32-sig0)) "OK" "MISMATCH"))
                                (format t "    maj(a,b,c): ref=~16,'0X w32=~16,'0X ~A~%"
                                        (ref-maj ref-a ref-b ref-c) (w64-to-u64 w32-maj)
                                        (if (= (ref-maj ref-a ref-b ref-c) (w64-to-u64 w32-maj)) "OK" "MISMATCH"))
                                (format t "    t2:         ref=~16,'0X w32=~16,'0X ~A~%"
                                        ref-t2 (w64-to-u64 w32-t2)
                                        (if (= ref-t2 (w64-to-u64 w32-t2)) "OK" "MISMATCH"))
                                (format t "    a=t1+t2:    ref=~16,'0X w32=~16,'0X ~A~%"
                                        (u64+ ref-t1 ref-t2) (w64-to-u64 (w64-add w32-t1 w32-t2))
                                        (if (= (u64+ ref-t1 ref-t2) (w64-to-u64 (w64-add w32-t1 w32-t2))) "OK" "MISMATCH"))
                                (format t "    e=d+t1:     ref=~16,'0X w32=~16,'0X ~A~%"
                                        (u64+ ref-d ref-t1) (w64-to-u64 (w64-add w32-d w32-t1))
                                        (if (= (u64+ ref-d ref-t1) (w64-to-u64 (w64-add w32-d w32-t1))) "OK" "MISMATCH")))
                              ;; Apply rotation
                              (setq ref-hh ref-g ref-g ref-f ref-f ref-e ref-e (u64+ ref-d ref-t1)
                                    ref-d ref-c ref-c ref-b ref-b ref-a ref-a (u64+ ref-t1 ref-t2))
                              (setq w32-hh w32-g w32-g w32-f w32-f w32-e
                                    w32-e (w64-add w32-d w32-t1)
                                    w32-d w32-cc w32-cc w32-b w32-b w32-a
                                    w32-a (w64-add w32-t1 w32-t2)))))))))))
          ;; After round 10
          (format t "~%  Post-round-10 a: ref=~16,'0X w32=~16,'0X~%" ref-a (w64-to-u64 w32-a))))))))

(defun run-tests ()
  (format t "~&SHA-512 w32/w64 pair arithmetic unit tests~%")
  (format t "==========================================~%")
  (test-w64-add)
  (test-sha512-one-zero)
  (test-sha512-zeros32)
  (test-sha512-empty)
  (format t "~&~%All tests PASSED!~%"))

(run-tests)
