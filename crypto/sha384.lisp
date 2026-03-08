;;;; SHA-384 implementation — reference CL implementation (needs MVM adaptation)
;;;; Based on FIPS 180-4
;;;; SHA-384 is SHA-512 truncated to 384 bits with different initial values
;;;; Uses 16-bit arithmetic internally to stay within 30-bit fixnum limit



;;; SHA-384/512 needs 64-bit arithmetic but the original target had 30-bit fixnums.
;;; We represent 64-bit values as 4 x 16-bit parts: #(w3 w2 w1 w0)
;;; where w3 is most significant

(defun make-u64 (w3 w2 w1 w0)
  "Create a 64-bit value from four 16-bit words (w3 is MSB)."
  (vector (logand w3 #xffff) (logand w2 #xffff)
          (logand w1 #xffff) (logand w0 #xffff)))

(defun u64-w3 (u) (aref u 0))
(defun u64-w2 (u) (aref u 1))
(defun u64-w1 (u) (aref u 2))
(defun u64-w0 (u) (aref u 3))

(defun u64-copy (u)
  "Create a copy of u64."
  (vector (aref u 0) (aref u 1) (aref u 2) (aref u 3)))

(defun u64+ (a b)
  "Add two u64 values, returning new u64."
  (let* ((s0 (+ (u64-w0 a) (u64-w0 b)))
         (c0 (ash s0 -16))
         (s1 (+ (u64-w1 a) (u64-w1 b) c0))
         (c1 (ash s1 -16))
         (s2 (+ (u64-w2 a) (u64-w2 b) c1))
         (c2 (ash s2 -16))
         (s3 (+ (u64-w3 a) (u64-w3 b) c2)))
    (make-u64 s3 s2 s1 s0)))

(defun u64-xor (a b)
  "XOR two u64 values."
  (make-u64 (logxor (u64-w3 a) (u64-w3 b))
            (logxor (u64-w2 a) (u64-w2 b))
            (logxor (u64-w1 a) (u64-w1 b))
            (logxor (u64-w0 a) (u64-w0 b))))

(defun u64-and (a b)
  "AND two u64 values."
  (make-u64 (logand (u64-w3 a) (u64-w3 b))
            (logand (u64-w2 a) (u64-w2 b))
            (logand (u64-w1 a) (u64-w1 b))
            (logand (u64-w0 a) (u64-w0 b))))

(defun u64-not (a)
  "NOT a u64 value."
  (make-u64 (logxor (u64-w3 a) #xffff)
            (logxor (u64-w2 a) #xffff)
            (logxor (u64-w1 a) #xffff)
            (logxor (u64-w0 a) #xffff)))

(defun u64-rotr (x n)
  "Right rotate u64 by N bits (0 <= N < 64)."
  (when (zerop n) (return-from u64-rotr (u64-copy x)))
  ;; Get all 4 words
  (let ((w3 (u64-w3 x))
        (w2 (u64-w2 x))
        (w1 (u64-w1 x))
        (w0 (u64-w0 x)))
    ;; First, handle rotation by whole 16-bit words
    (let ((word-shift (floor n 16))
          (bit-shift (mod n 16)))
      ;; Rotate words
      (dotimes (i word-shift)
        (let ((tmp w0))
          (setf w0 w1 w1 w2 w2 w3 w3 tmp)))
      ;; Now rotate by remaining bits within words
      (if (zerop bit-shift)
          (make-u64 w3 w2 w1 w0)
          (let ((mask (1- (ash 1 bit-shift)))
                (rshift (- 16 bit-shift)))
            (make-u64 (logior (ash w3 (- bit-shift)) (ash (logand w0 mask) rshift))
                      (logior (ash w2 (- bit-shift)) (ash (logand w3 mask) rshift))
                      (logior (ash w1 (- bit-shift)) (ash (logand w2 mask) rshift))
                      (logior (ash w0 (- bit-shift)) (ash (logand w1 mask) rshift))))))))

(defun u64-shr (x n)
  "Right shift u64 by N bits."
  (when (zerop n) (return-from u64-shr (u64-copy x)))
  (when (>= n 64) (return-from u64-shr (make-u64 0 0 0 0)))
  (let ((w3 (u64-w3 x))
        (w2 (u64-w2 x))
        (w1 (u64-w1 x))
        (w0 (u64-w0 x)))
    ;; Handle shift by whole 16-bit words first
    (let ((word-shift (floor n 16))
          (bit-shift (mod n 16)))
      ;; Shift words right (fill with zeros)
      (dotimes (i word-shift)
        (setf w0 w1 w1 w2 w2 w3 w3 0))
      ;; Shift remaining bits
      (if (zerop bit-shift)
          (make-u64 w3 w2 w1 w0)
          (let ((rshift (- 16 bit-shift)))
            (make-u64 (ash w3 (- bit-shift))
                      (logior (ash w2 (- bit-shift)) (ash (logand w3 #xffff) rshift))
                      (logior (ash w1 (- bit-shift)) (ash (logand w2 #xffff) rshift))
                      (logior (ash w0 (- bit-shift)) (ash (logand w1 #xffff) rshift))))))))

;;; SHA-384/512 Constants (first 64 bits of fractional parts of cube roots of first 80 primes)
;;; Each constant is represented as #(w3 w2 w1 w0)
(defparameter *sha512-k*
  (vector
   ;; K[0-9]
   #(#x428a #x2f98 #xd728 #xae22) #(#x7137 #x4491 #x23ef #x65cd)
   #(#xb5c0 #xfbcf #xec4d #x3b2f) #(#xe9b5 #xdba5 #x8189 #xdbbc)
   #(#x3956 #xc25b #xf348 #xb538) #(#x59f1 #x11f1 #xb605 #xd019)
   #(#x923f #x82a4 #xaf19 #x4f9b) #(#xab1c #x5ed5 #xda6d #x8118)
   #(#xd807 #xaa98 #xa303 #x0242) #(#x1283 #x5b01 #x4570 #x6fbe)
   ;; K[10-19]
   #(#x2431 #x85be #x4ee4 #xb28c) #(#x550c #x7dc3 #xd5ff #xb4e2)
   #(#x72be #x5d74 #xf27b #x896f) #(#x80de #xb1fe #x3b16 #x96b1)
   #(#x9bdc #x06a7 #x25c7 #x1235) #(#xc19b #xf174 #xcf69 #x2694)
   #(#xe49b #x69c1 #x9ef1 #x4ad2) #(#xefbe #x4786 #x384f #x25e3)
   #(#x0fc1 #x9dc6 #x8b8c #xd5b5) #(#x240c #xa1cc #x77ac #x9c65)
   ;; K[20-29]
   #(#x2de9 #x2c6f #x592b #x0275) #(#x4a74 #x84aa #x6ea6 #xe483)
   #(#x5cb0 #xa9dc #xbd41 #xfbd4) #(#x76f9 #x88da #x8311 #x53b5)
   #(#x983e #x5152 #xee66 #xdfab) #(#xa831 #xc66d #x2db4 #x3210)
   #(#xb003 #x27c8 #x98fb #x213f) #(#xbf59 #x7fc7 #xbeef #x0ee4)
   #(#xc6e0 #x0bf3 #x3da8 #x8fc2) #(#xd5a7 #x9147 #x930a #xa725)
   ;; K[30-39]
   #(#x06ca #x6351 #xe003 #x826f) #(#x1429 #x2967 #x0a0e #x6e70)
   #(#x27b7 #x0a85 #x46d2 #x2ffc) #(#x2e1b #x2138 #x5c26 #xc926)
   #(#x4d2c #x6dfc #x5ac4 #x2aed) #(#x5338 #x0d13 #x9d95 #xb3df)
   #(#x650a #x7354 #x8baf #x63de) #(#x766a #x0abb #x3c77 #xb2a8)
   #(#x81c2 #xc92e #x47ed #xaee6) #(#x9272 #x2c85 #x1482 #x353b)
   ;; K[40-49]
   #(#xa2bf #xe8a1 #x4cf1 #x0364) #(#xa81a #x664b #xbc42 #x3001)
   #(#xc24b #x8b70 #xd0f8 #x9791) #(#xc76c #x51a3 #x0654 #xbe30)
   #(#xd192 #xe819 #xd6ef #x5218) #(#xd699 #x0624 #x5565 #xa910)
   #(#xf40e #x3585 #x5771 #x202a) #(#x106a #xa070 #x32bb #xd1b8)
   #(#x19a4 #xc116 #xb8d2 #xd0c8) #(#x1e37 #x6c08 #x5141 #xab53)
   ;; K[50-59]
   #(#x2748 #x774c #xdf8e #xeb99) #(#x34b0 #xbcb5 #xe19b #x48a8)
   #(#x391c #x0cb3 #xc5c9 #x5a63) #(#x4ed8 #xaa4a #xe341 #x8acb)
   #(#x5b9c #xca4f #x7763 #xe373) #(#x682e #x6ff3 #xd6b2 #xb8a3)
   #(#x748f #x82ee #x5def #xb2fc) #(#x78a5 #x636f #x4317 #x2f60)
   #(#x84c8 #x7814 #xa1f0 #xab72) #(#x8cc7 #x0208 #x1a64 #x39ec)
   ;; K[60-69]
   #(#x90be #xfffa #x2363 #x1e28) #(#xa450 #x6ceb #xde82 #xbde9)
   #(#xbef9 #xa3f7 #xb2c6 #x7915) #(#xc671 #x78f2 #xe372 #x532b)
   #(#xca27 #x3ece #xea26 #x619c) #(#xd186 #xb8c7 #x21c0 #xc207)
   #(#xeada #x7dd6 #xcde0 #xeb1e) #(#xf57d #x4f7f #xee6e #xd178)
   #(#x06f0 #x67aa #x7217 #x6fba) #(#x0a63 #x7dc5 #xa2c8 #x98a6)
   ;; K[70-79]
   #(#x113f #x9804 #xbef9 #x0dae) #(#x1b71 #x0b35 #x131c #x471b)
   #(#x28db #x77f5 #x2304 #x7d84) #(#x32ca #xab7b #x40c7 #x2493)
   #(#x3c9e #xbe0a #x15c9 #xbebc) #(#x431d #x67c4 #x9c10 #x0d4c)
   #(#x4cc5 #xd4be #xcb3e #x42b6) #(#x597f #x299c #xfc65 #x7e2a)
   #(#x5fcb #x6fab #x3ad6 #xfaec) #(#x6c44 #x198c #x4a47 #x5817)))

(defun sha512-k (i)
  "Get K constant for round I."
  (aref *sha512-k* i))

;;; SHA-384 Initial hash values (from 9th through 16th primes)
(defun sha384-h-init ()
  "Create initial hash state for SHA-384."
  (vector (make-u64 #xcbbb #x9d5d #xc105 #x9ed8)
          (make-u64 #x629a #x292a #x367c #xd507)
          (make-u64 #x9159 #x015a #x3070 #xdd17)
          (make-u64 #x152f #xecd8 #xf70e #x5939)
          (make-u64 #x6733 #x2667 #xffc0 #x0b31)
          (make-u64 #x8eb4 #x4a87 #x6858 #x1511)
          (make-u64 #xdb0c #x2e0d #x64f9 #x8fa7)
          (make-u64 #x47b5 #x481d #xbefa #x4fa4)))

;;; SHA-512 functions (also used by SHA-384)
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

;;; Message schedule expansion
(defun sha512-expand-block (block w)
  "Expand 16-word (128-byte) block into 80-word message schedule W."
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

;;; Padding for SHA-384/512
(defun sha512-pad-message (message)
  "Pad message according to SHA-512 spec. Returns padded byte vector."
  (let* ((msg-len (length message))
         (msg-bits (* msg-len 8))
         ;; Padded length: msg + 1 byte (0x80) + zeros + 16 bytes (length as 128-bit)
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
    ;; Append length as 128-bit big-endian (we only handle <32-bit lengths, so upper 12 bytes are 0)
    (setf (aref padded (- total-len 4)) (ldb (byte 8 24) msg-bits)
          (aref padded (- total-len 3)) (ldb (byte 8 16) msg-bits)
          (aref padded (- total-len 2)) (ldb (byte 8 8) msg-bits)
          (aref padded (- total-len 1)) (ldb (byte 8 0) msg-bits))
    padded))

;;; Main SHA-384 function
(defun sha384 (message)
  "Compute SHA-384 hash of MESSAGE (byte vector). Returns 48-byte hash."
  (let ((padded (sha512-pad-message message))
        (h (sha384-h-init))
        (w (make-array 80 :initial-element nil))
        (block (make-array 128 :element-type '(unsigned-byte 8))))

    ;; Process each 128-byte block
    (do ((offset 0 (+ offset 128)))
        ((>= offset (length padded)))
      ;; Copy block
      (dotimes (i 128)
        (setf (aref block i) (aref padded (+ offset i))))
      (sha512-process-block block h w))

    ;; Convert first 6 words of hash state to byte array (big-endian)
    ;; SHA-384 output is 48 bytes (6 x 64-bit words)
    (let ((result (make-array 48 :element-type '(unsigned-byte 8))))
      (dotimes (i 6)
        (let ((word (aref h i))
              (j (* i 8)))
          (setf (aref result j) (ldb (byte 8 8) (u64-w3 word))
                (aref result (+ j 1)) (ldb (byte 8 0) (u64-w3 word))
                (aref result (+ j 2)) (ldb (byte 8 8) (u64-w2 word))
                (aref result (+ j 3)) (ldb (byte 8 0) (u64-w2 word))
                (aref result (+ j 4)) (ldb (byte 8 8) (u64-w1 word))
                (aref result (+ j 5)) (ldb (byte 8 0) (u64-w1 word))
                (aref result (+ j 6)) (ldb (byte 8 8) (u64-w0 word))
                (aref result (+ j 7)) (ldb (byte 8 0) (u64-w0 word)))))
      result)))

;;; Convenience function for strings
(defun sha384-string (string)
  "Compute SHA-384 hash of STRING. Returns 48-byte hash."
  (let ((bytes (make-array (length string) :element-type '(unsigned-byte 8))))
    (dotimes (i (length string))
      (setf (aref bytes i) (char-code (char string i))))
    (sha384 bytes)))

;;; Helper to print hash as hex
(defun sha384-hex (hash)
  "Convert 48-byte hash to hex string."
  (let ((hex-chars "0123456789abcdef")
        (result (make-array 96 :element-type 'character)))
    (dotimes (i 48)
      (let ((byte (aref hash i)))
        (setf (aref result (* i 2)) (aref hex-chars (ash byte -4)))
        (setf (aref result (1+ (* i 2))) (aref hex-chars (logand byte 15)))))
    result))

;;; Test function
(defun sha384-test ()
  "Test SHA-384 with known test vectors."
  (let* ((empty-hash (sha384 (make-array 0 :element-type '(unsigned-byte 8))))
         (abc-hash (sha384-string "abc")))
    (format t "~&SHA-384 test:~%")
    (format t "  empty: ~A~%" (sha384-hex empty-hash))
    (format t "  'abc': ~A~%" (sha384-hex abc-hash))
    ;; Expected:
    ;; empty: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
    ;; abc:   cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
    t))
