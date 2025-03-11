;;;; SHA-512 implementation for Movitz
;;;; Based on FIPS 180-4
;;;; Uses 16-bit arithmetic internally to stay within 30-bit fixnum limit
;;;;
;;;; SHA-512 uses 64-bit words represented as 4 16-bit values.

(require :muerte/basic-macros)
(provide :lib/crypto/sha512)

(in-package muerte)

;;; SHA-512 needs 64-bit arithmetic but Movitz has 30-bit fixnums.
;;; We represent 64-bit values as 4-element vectors: #(hh hl lh ll)
;;; where hh is the highest 16 bits and ll is the lowest.

(defun make-u64 (hh hl lh ll)
  "Create a 64-bit value from four 16-bit parts (highest to lowest)."
  (vector (logand hh #xffff) (logand hl #xffff)
          (logand lh #xffff) (logand ll #xffff)))

(defun u64-hh (u) (aref u 0))  ; bits 63-48
(defun u64-hl (u) (aref u 1))  ; bits 47-32
(defun u64-lh (u) (aref u 2))  ; bits 31-16
(defun u64-ll (u) (aref u 3))  ; bits 15-0

(defun u64-copy (u)
  "Copy a u64 value."
  (make-u64 (u64-hh u) (u64-hl u) (u64-lh u) (u64-ll u)))

(defun u64+ (a b)
  "Add two u64 values (mod 2^64)."
  (let* ((ll (+ (u64-ll a) (u64-ll b)))
         (c0 (ash ll -16))
         (lh (+ (u64-lh a) (u64-lh b) c0))
         (c1 (ash lh -16))
         (hl (+ (u64-hl a) (u64-hl b) c1))
         (c2 (ash hl -16))
         (hh (+ (u64-hh a) (u64-hh b) c2)))
    (make-u64 hh hl lh ll)))

(defun u64-xor (a b)
  "XOR two u64 values."
  (make-u64 (logxor (u64-hh a) (u64-hh b))
            (logxor (u64-hl a) (u64-hl b))
            (logxor (u64-lh a) (u64-lh b))
            (logxor (u64-ll a) (u64-ll b))))

(defun u64-and (a b)
  "AND two u64 values."
  (make-u64 (logand (u64-hh a) (u64-hh b))
            (logand (u64-hl a) (u64-hl b))
            (logand (u64-lh a) (u64-lh b))
            (logand (u64-ll a) (u64-ll b))))

(defun u64-not (a)
  "NOT a u64 value."
  (make-u64 (logxor (u64-hh a) #xffff)
            (logxor (u64-hl a) #xffff)
            (logxor (u64-lh a) #xffff)
            (logxor (u64-ll a) #xffff)))

(defun u64-rotr (x n)
  "Right rotate u64 by N bits (0 < N < 64)."
  (cond
    ((zerop n) (u64-copy x))
    ((< n 16)
      ;; Rotate within 16-bit boundaries with spillover
      (let ((hh (u64-hh x)) (hl (u64-hl x))
            (lh (u64-lh x)) (ll (u64-ll x))
            (mask (1- (ash 1 n)))
            (shift (- 16 n)))
        (make-u64 (logior (ash hh (- n)) (ash (logand ll mask) shift))
                  (logior (ash hl (- n)) (ash (logand hh mask) shift))
                  (logior (ash lh (- n)) (ash (logand hl mask) shift))
                  (logior (ash ll (- n)) (ash (logand lh mask) shift)))))
    ((= n 16)
      ;; Rotate by exactly 16: shift everything one slot right
      (make-u64 (u64-ll x) (u64-hh x) (u64-hl x) (u64-lh x)))
    ((= n 32)
      ;; Rotate by exactly 32: swap high and low halves
      (make-u64 (u64-lh x) (u64-ll x) (u64-hh x) (u64-hl x)))
    ((= n 48)
      ;; Rotate by exactly 48
      (make-u64 (u64-hl x) (u64-lh x) (u64-ll x) (u64-hh x)))
    ((< n 32)
      ;; Rotate by 16 < n < 32
      (u64-rotr (u64-rotr x 16) (- n 16)))
    ((< n 48)
      ;; Rotate by 32 < n < 48
      (u64-rotr (u64-rotr x 32) (- n 32)))
    (t
      ;; Rotate by 48 < n < 64
      (u64-rotr (u64-rotr x 48) (- n 48)))))

(defun u64-shr (x n)
  "Right shift u64 by N bits."
  (cond
    ((zerop n) (u64-copy x))
    ((< n 16)
      (let ((hh (u64-hh x)) (hl (u64-hl x))
            (lh (u64-lh x)) (ll (u64-ll x))
            (mask (1- (ash 1 n)))
            (shift (- 16 n)))
        (make-u64 (ash hh (- n))
                  (logior (ash hl (- n)) (ash (logand hh mask) shift))
                  (logior (ash lh (- n)) (ash (logand hl mask) shift))
                  (logior (ash ll (- n)) (ash (logand lh mask) shift)))))
    ((= n 16)
      (make-u64 0 (u64-hh x) (u64-hl x) (u64-lh x)))
    ((< n 32)
      (u64-shr (u64-shr x 16) (- n 16)))
    ((= n 32)
      (make-u64 0 0 (u64-hh x) (u64-hl x)))
    ((< n 48)
      (u64-shr (u64-shr x 32) (- n 32)))
    ((= n 48)
      (make-u64 0 0 0 (u64-hh x)))
    ((< n 64)
      (u64-shr (u64-shr x 48) (- n 48)))
    (t (make-u64 0 0 0 0))))

;;; SHA-512 Constants (first 64 bits of fractional parts of cube roots of first 80 primes)
;;; Each constant is stored as (hh hl lh ll)
(defvar *sha512-k*
  #(#(#x428a #x2f98 #xd728 #xae22)
    #(#x7137 #x4491 #x23ef #x65cd)
    #(#xb5c0 #xfbcf #xec4d #x3b2f)
    #(#xe9b5 #xdba5 #x8189 #xdbbc)
    #(#x3956 #xc25b #xf348 #xb538)
    #(#x59f1 #x11f1 #xb605 #xd019)
    #(#x923f #x82a4 #xaf19 #x4f9b)
    #(#xab1c #x5ed5 #xda6d #x8118)
    #(#xd807 #xaa98 #xa303 #x0242)
    #(#x1283 #x5b01 #x4570 #x6fbe)
    #(#x2431 #x85be #x4ee4 #xb28c)
    #(#x550c #x7dc3 #xd5ff #xb4e2)
    #(#x72be #x5d74 #xf27b #x896f)
    #(#x80de #xb1fe #x3b16 #x96b1)
    #(#x9bdc #x06a7 #x25c7 #x1235)
    #(#xc19b #xf174 #xcf69 #x2694)
    #(#xe49b #x69c1 #x9ef1 #x4ad2)
    #(#xefbe #x4786 #x384f #x25e3)
    #(#x0fc1 #x9dc6 #x8b8c #xd5b5)
    #(#x240c #xa1cc #x77ac #x9c65)
    #(#x2de9 #x2c6f #x592b #x0275)
    #(#x4a74 #x84aa #x6ea6 #xe483)
    #(#x5cb0 #xa9dc #xbd41 #xfbd4)
    #(#x76f9 #x88da #x8311 #x53b5)
    #(#x983e #x5152 #xee66 #xdfab)
    #(#xa831 #xc66d #x2db4 #x3210)
    #(#xb003 #x27c8 #x98fb #x213f)
    #(#xbf59 #x7fc7 #xbeef #x0ee4)
    #(#xc6e0 #x0bf3 #x3da8 #x8fc2)
    #(#xd5a7 #x9147 #x930a #xa725)
    #(#x06ca #x6351 #xe003 #x826f)
    #(#x1429 #x2967 #x0a0e #x6e70)
    #(#x27b7 #x0a85 #x46d2 #x2ffc)
    #(#x2e1b #x2138 #x5c26 #xc926)
    #(#x4d2c #x6dfc #x5ac4 #x2aed)
    #(#x5338 #x0d13 #x9d95 #xb3df)
    #(#x650a #x7354 #x8baf #x63de)
    #(#x766a #x0abb #x3c77 #xb2a8)
    #(#x81c2 #xc92e #x47ed #xaee6)
    #(#x9272 #x2c85 #x1482 #x353b)
    #(#xa2bf #xe8a1 #x4cf1 #x0364)
    #(#xa81a #x664b #xbc42 #x3001)
    #(#xc24b #x8b70 #xd0f8 #x9791)
    #(#xc76c #x51a3 #x0654 #xbe30)
    #(#xd192 #xe819 #xd6ef #x5218)
    #(#xd699 #x0624 #x5565 #xa910)
    #(#xf40e #x3585 #x5771 #x202a)
    #(#x106a #xa070 #x32bb #xd1b8)
    #(#x19a4 #xc116 #xb8d2 #xd0c8)
    #(#x1e37 #x6c08 #x5141 #xab53)
    #(#x2748 #x774c #xdf8e #xeb99)
    #(#x34b0 #xbcb5 #xe19b #x48a8)
    #(#x391c #x0cb3 #xc5c9 #x5a63)
    #(#x4ed8 #xaa4a #xe341 #x8acb)
    #(#x5b9c #xca4f #x7763 #xe373)
    #(#x682e #x6ff3 #xd6b2 #xb8a3)
    #(#x748f #x82ee #x5def #xb2fc)
    #(#x78a5 #x636f #x4317 #x2f60)
    #(#x84c8 #x7814 #xa1f0 #xab72)
    #(#x8cc7 #x0208 #x1a64 #x39ec)
    #(#x90be #xfffa #x2363 #x1e28)
    #(#xa450 #x6ceb #xde82 #xbde9)
    #(#xbef9 #xa3f7 #xb2c6 #x7915)
    #(#xc671 #x78f2 #xe372 #x532b)
    #(#xca27 #x3ece #xea26 #x619c)
    #(#xd186 #xb8c7 #x21c0 #xc207)
    #(#xeada #x7dd6 #xcde0 #xeb1e)
    #(#xf57d #x4f7f #xee6e #xd178)
    #(#x06f0 #x67aa #x7217 #x6fba)
    #(#x0a63 #x7dc5 #xa2c8 #x98a6)
    #(#x113f #x9804 #xbef9 #x0dae)
    #(#x1b71 #x0b35 #x131c #x471b)
    #(#x28db #x77f5 #x2304 #x7d84)
    #(#x32ca #xab7b #x40c7 #x2493)
    #(#x3c9e #xbe0a #x15c9 #xbebc)
    #(#x431d #x67c4 #x9c10 #x0d4c)
    #(#x4cc5 #xd4be #xcb3e #x42b6)
    #(#x597f #x299c #xfc65 #x7e2a)
    #(#x5fcb #x6fab #x3ad6 #xfaec)
    #(#x6c44 #x198c #x4a47 #x5817)))

(defun sha512-k (i)
  "Get K constant for round I."
  (let ((k (aref *sha512-k* i)))
    (make-u64 (aref k 0) (aref k 1) (aref k 2) (aref k 3))))

;;; Initial hash values for SHA-512
(defun sha512-h-init ()
  "Create initial hash state for SHA-512."
  (vector (make-u64 #x6a09 #xe667 #xf3bc #xc908)
          (make-u64 #xbb67 #xae85 #x84ca #xa73b)
          (make-u64 #x3c6e #xf372 #xfe94 #xf82b)
          (make-u64 #xa54f #xf53a #x5f1d #x36f1)
          (make-u64 #x510e #x527f #xade6 #x82d1)
          (make-u64 #x9b05 #x688c #x2b3e #x6c1f)
          (make-u64 #x1f83 #xd9ab #xfb41 #xbd6b)
          (make-u64 #x5be0 #xcd19 #x137e #x2179)))

;;; SHA-512 functions
(defun sha512-ch (x y z)
  "Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)"
  (u64-xor (u64-and x y) (u64-and (u64-not x) z)))

(defun sha512-maj (x y z)
  "Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)"
  (u64-xor (u64-xor (u64-and x y) (u64-and x z)) (u64-and y z)))

(defun sha512-sigma0 (x)
  "Big sigma 0: ROTR28(x) XOR ROTR34(x) XOR ROTR39(x)"
  (u64-xor (u64-xor (u64-rotr x 28) (u64-rotr x 34)) (u64-rotr x 39)))

(defun sha512-sigma1 (x)
  "Big sigma 1: ROTR14(x) XOR ROTR18(x) XOR ROTR41(x)"
  (u64-xor (u64-xor (u64-rotr x 14) (u64-rotr x 18)) (u64-rotr x 41)))

(defun sha512-lsigma0 (x)
  "Little sigma 0: ROTR1(x) XOR ROTR8(x) XOR SHR7(x)"
  (u64-xor (u64-xor (u64-rotr x 1) (u64-rotr x 8)) (u64-shr x 7)))

(defun sha512-lsigma1 (x)
  "Little sigma 1: ROTR19(x) XOR ROTR61(x) XOR SHR6(x)"
  (u64-xor (u64-xor (u64-rotr x 19) (u64-rotr x 61)) (u64-shr x 6)))

;;; Message schedule array
(defun sha512-expand-block (block w)
  "Expand 16-word block into 80-word message schedule W."
  ;; First 16 words come from the block (big-endian, 8 bytes each)
  (dotimes (i 16)
    (let ((j (* i 8)))
      (setf (aref w i)
            (make-u64 (logior (ash (aref block j) 8) (aref block (+ j 1)))
                      (logior (ash (aref block (+ j 2)) 8) (aref block (+ j 3)))
                      (logior (ash (aref block (+ j 4)) 8) (aref block (+ j 5)))
                      (logior (ash (aref block (+ j 6)) 8) (aref block (+ j 7)))))))
  ;; Remaining 64 words are computed
  (do ((i 16 (1+ i)))
      ((>= i 80))
    (setf (aref w i)
          (u64+ (u64+ (sha512-lsigma1 (aref w (- i 2)))
                      (aref w (- i 7)))
                (u64+ (sha512-lsigma0 (aref w (- i 15)))
                      (aref w (- i 16)))))))

;;; Process one 1024-bit (128-byte) block
(defun sha512-process-block (block h w)
  "Process one block, updating hash state H. W is workspace."
  (sha512-expand-block block w)

  ;; Initialize working variables
  (let ((a (u64-copy (aref h 0)))
        (b (u64-copy (aref h 1)))
        (c (u64-copy (aref h 2)))
        (d (u64-copy (aref h 3)))
        (e (u64-copy (aref h 4)))
        (f (u64-copy (aref h 5)))
        (g (u64-copy (aref h 6)))
        (hh (u64-copy (aref h 7))))

    ;; 80 rounds
    (dotimes (i 80)
      (let* ((t1 (u64+ (u64+ hh (sha512-sigma1 e))
                       (u64+ (sha512-ch e f g)
                             (u64+ (sha512-k i) (aref w i)))))
             (t2 (u64+ (sha512-sigma0 a) (sha512-maj a b c))))
        (setf hh g
              g f
              f e
              e (u64+ d t1)
              d c
              c b
              b a
              a (u64+ t1 t2))))

    ;; Add to hash state
    (setf (aref h 0) (u64+ (aref h 0) a)
          (aref h 1) (u64+ (aref h 1) b)
          (aref h 2) (u64+ (aref h 2) c)
          (aref h 3) (u64+ (aref h 3) d)
          (aref h 4) (u64+ (aref h 4) e)
          (aref h 5) (u64+ (aref h 5) f)
          (aref h 6) (u64+ (aref h 6) g)
          (aref h 7) (u64+ (aref h 7) hh))))

;;; Padding
(defun sha512-pad-message (message)
  "Pad message according to SHA-512 spec. Returns padded byte vector."
  (let* ((msg-len (length message))
         (msg-bits (* msg-len 8))
         ;; Padded length: msg + 1 byte (0x80) + zeros + 16 bytes (length)
         ;; Must be multiple of 128 bytes
         (pad-len (let ((m (mod (+ msg-len 17) 128)))
                    (if (zerop m) 0 (- 128 m))))
         (total-len (+ msg-len 1 pad-len 16))
         (padded (make-array total-len :element-type '(unsigned-byte 8)
                             :initial-element 0)))
    ;; Copy message
    (dotimes (i msg-len)
      (setf (aref padded i) (aref message i)))
    ;; Append 1 bit (as 0x80 byte)
    (setf (aref padded msg-len) #x80)
    ;; Append length as 128-bit big-endian (we only handle <32-bit lengths)
    ;; High 96 bits are zero, low 32 bits contain length
    (setf (aref padded (- total-len 4)) (ldb (byte 8 24) msg-bits)
          (aref padded (- total-len 3)) (ldb (byte 8 16) msg-bits)
          (aref padded (- total-len 2)) (ldb (byte 8 8) msg-bits)
          (aref padded (- total-len 1)) (ldb (byte 8 0) msg-bits))
    padded))

;;; Main SHA-512 function
(defun sha512 (message)
  "Compute SHA-512 hash of MESSAGE (byte vector). Returns 64-byte hash."
  (let ((padded (sha512-pad-message message))
        (h (sha512-h-init))
        (w (make-array 80 :initial-element nil))
        (block (make-array 128 :element-type '(unsigned-byte 8))))

    ;; Process each 128-byte block
    (do ((offset 0 (+ offset 128)))
        ((>= offset (length padded)))
      ;; Copy block
      (dotimes (i 128)
        (setf (aref block i) (aref padded (+ offset i))))
      (sha512-process-block block h w))

    ;; Convert hash state to byte array (big-endian)
    (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
      (dotimes (i 8)
        (let ((word (aref h i))
              (j (* i 8)))
          (setf (aref result j) (ldb (byte 8 8) (u64-hh word))
                (aref result (+ j 1)) (ldb (byte 8 0) (u64-hh word))
                (aref result (+ j 2)) (ldb (byte 8 8) (u64-hl word))
                (aref result (+ j 3)) (ldb (byte 8 0) (u64-hl word))
                (aref result (+ j 4)) (ldb (byte 8 8) (u64-lh word))
                (aref result (+ j 5)) (ldb (byte 8 0) (u64-lh word))
                (aref result (+ j 6)) (ldb (byte 8 8) (u64-ll word))
                (aref result (+ j 7)) (ldb (byte 8 0) (u64-ll word)))))
      result)))

;;; Convenience function for strings
(defun sha512-string (string)
  "Compute SHA-512 hash of STRING. Returns 64-byte hash."
  (let ((bytes (make-array (length string) :element-type '(unsigned-byte 8))))
    (dotimes (i (length string))
      (setf (aref bytes i) (char-code (char string i))))
    (sha512 bytes)))

;;; Helper to print hash as hex
(defun sha512-hex (hash)
  "Convert 64-byte hash to hex string."
  (let ((hex-chars "0123456789abcdef")
        (result (make-array 128 :element-type 'character)))
    (dotimes (i 64)
      (let ((byte (aref hash i)))
        (setf (aref result (* i 2)) (aref hex-chars (ash byte -4)))
        (setf (aref result (1+ (* i 2))) (aref hex-chars (logand byte 15)))))
    result))

;;; Test function
(defun sha512-test ()
  "Test SHA-512 with known test vectors."
  (let* ((empty-hash (sha512 (make-array 0 :element-type '(unsigned-byte 8))))
         (abc-hash (sha512-string "abc")))
    (format t "~&SHA-512 test:~%")
    (format t "  empty: ~A~%" (sha512-hex empty-hash))
    (format t "  'abc': ~A~%" (sha512-hex abc-hash))
    ;; Expected:
    ;; empty: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    ;; abc:   ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
    t))
