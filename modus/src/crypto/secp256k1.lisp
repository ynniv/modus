;;;; secp256k1 elliptic curve implementation
;;;; For Nostr/Bitcoin Schnorr signatures (BIP-340)
;;;;
;;;; Curve: y² = x³ + 7 (mod p)
;;;; p = 2²⁵⁶ - 2³² - 977
;;;;
;;;; Both signing and verification work. Note: Movitz has a compiler bug where
;;;; local variables can be corrupted during function calls, so we preserve
;;;; critical values as byte arrays during heavy computations.

(in-package :muerte)

;;; Constants - initialized at runtime from byte arrays
(defparameter *secp256k1-p* nil)
(defparameter *secp256k1-n* nil)
(defparameter *secp256k1-gx* nil)
(defparameter *secp256k1-gy* nil)

(defun bytes-to-int (bytes)
  "Convert byte array to integer (big-endian)."
  (let ((result 0))
    (dotimes (i (length bytes))
      (setf result (+ (ash result 8) (aref bytes i))))
    result))

(defun secp-init ()
  "Initialize secp256k1 constants."
  (unless *secp256k1-p*
    (setf *secp256k1-p*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                         #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                         #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                         #xFF #xFF #xFF #xFE #xFF #xFF #xFC #x2F)))
    (setf *secp256k1-n*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                         #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFE
                         #xBA #xAE #xDC #xE6 #xAF #x48 #xA0 #x3B
                         #xBF #xD2 #x5E #x8C #xD0 #x36 #x41 #x41)))
    (setf *secp256k1-gx*
          (bytes-to-int #(#x79 #xBE #x66 #x7E #xF9 #xDC #xBB #xAC
                         #x55 #xA0 #x62 #x95 #xCE #x87 #x0B #x07
                         #x02 #x9B #xFC #xDB #x2D #xCE #x28 #xD9
                         #x59 #xF2 #x81 #x5B #x16 #xF8 #x17 #x98)))
    (setf *secp256k1-gy*
          (bytes-to-int #(#x48 #x3A #xDA #x77 #x26 #xA3 #xC4 #x65
                         #x5D #xA4 #xFB #xFC #x0E #x11 #x08 #xA8
                         #xFD #x17 #xB4 #x48 #xA6 #x85 #x54 #x19
                         #x9C #x47 #xD0 #x8F #xFB #x10 #xD4 #xB8))))
  t)

;;; Point at infinity
(defparameter *secp256k1-infinity* (cons :infinity nil))

;;; Field arithmetic
(defun secp-mod (x) (mod x *secp256k1-p*))
(defun secp-add (a b) (secp-mod (+ a b)))
(defun secp-sub (a b) (secp-mod (- a b)))
(defun secp-mul (a b) (secp-mod (* a b)))
(defun secp-sq (a) (secp-mod (* a a)))
(defun secp-neg (a) (secp-mod (- *secp256k1-p* a)))

(defun secp-inv (a)
  "Modular inverse using extended Euclidean algorithm."
  (let ((t0 0) (t1 1)
        (r0 *secp256k1-p*) (r1 (mod a *secp256k1-p*)))
    (loop while (not (zerop r1)) do
      (let* ((q (floor r0 r1))
             (new-r1 (- r0 (* q r1)))
             (new-t1 (- t0 (* q t1))))
        (setf r0 r1
              r1 new-r1
              t0 t1
              t1 new-t1)))
    (if (< t0 0) (+ t0 *secp256k1-p*) t0)))

;;; Point operations
(defun secp-inf-p (p) (eq (car p) :infinity))
(defun secp-x (p) (car p))
(defun secp-y (p) (cdr p))

(defun secp-double (p)
  "Double a point."
  (when (secp-inf-p p) (return-from secp-double p))
  (let ((x (secp-x p)) (y (secp-y p)))
    (when (zerop y) (return-from secp-double *secp256k1-infinity*))
    (let* ((lam (secp-mul (secp-mul 3 (secp-sq x))
                          (secp-inv (secp-mul 2 y))))
           (x3 (secp-sub (secp-sq lam) (secp-mul 2 x)))
           (y3 (secp-sub (secp-mul lam (secp-sub x x3)) y)))
      (cons x3 y3))))

(defun secp-add-points (p1 p2)
  "Add two points."
  (cond
    ((secp-inf-p p1) p2)
    ((secp-inf-p p2) p1)
    (t
     (let ((x1 (secp-x p1)) (y1 (secp-y p1))
           (x2 (secp-x p2)) (y2 (secp-y p2)))
       (cond
         ((and (= x1 x2) (= y1 (secp-neg y2))) *secp256k1-infinity*)
         ((and (= x1 x2) (= y1 y2)) (secp-double p1))
         (t
          (let* ((lam (secp-mul (secp-sub y2 y1) (secp-inv (secp-sub x2 x1))))
                 (x3 (secp-sub (secp-sub (secp-sq lam) x1) x2))
                 (y3 (secp-sub (secp-mul lam (secp-sub x1 x3)) y1)))
            (cons x3 y3))))))))

(defun secp-mul-point (k p)
  "Scalar multiplication k*P."
  (secp-init)
  (let ((result *secp256k1-infinity*)
        (temp p)
        (n (mod k *secp256k1-n*)))
    (loop while (> n 0) do
      (when (oddp n)
        (setf result (secp-add-points result temp)))
      (setf temp (secp-double temp))
      (setf n (ash n -1)))
    result))

(defun secp-generator ()
  "Return generator point G."
  (secp-init)
  (cons *secp256k1-gx* *secp256k1-gy*))

(defun secp-pubkey (privkey)
  "Compute public key from private key."
  (secp-mul-point privkey (secp-generator)))

(defun secp-on-curve-p (p)
  "Check if point is on curve."
  (secp-init)
  (if (secp-inf-p p) t
      (let ((x (secp-x p)) (y (secp-y p)))
        (= (secp-sq y) (secp-mod (+ (secp-mul x (secp-sq x)) 7))))))

;;; BIP-340 Schnorr Signatures

(defun int-to-bytes32 (n)
  "Convert integer to 32-byte array (big-endian)."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 32)
      (setf (aref result (- 31 i)) (ldb (byte 8 (* i 8)) n)))
    result))

(defun bytes-concat (&rest arrays)
  "Concatenate byte arrays."
  (let* ((total (loop for a in arrays sum (length a)))
         (result (make-array total :element-type '(unsigned-byte 8)))
         (pos 0))
    (dolist (a arrays)
      (dotimes (i (length a))
        (setf (aref result pos) (aref a i))
        (incf pos)))
    result))

(defun tagged-hash (tag msg)
  "BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."
  (let* ((tag-bytes (make-array (length tag) :element-type '(unsigned-byte 8))))
    (dotimes (i (length tag))
      (setf (aref tag-bytes i) (char-code (char tag i))))
    (let ((tag-hash (sha256 tag-bytes)))
      (sha256 (bytes-concat tag-hash tag-hash msg)))))

(defun secp-has-even-y (p)
  "Check if point has even y coordinate."
  (evenp (secp-y p)))

(defun secp-negate-point (p)
  "Negate a point (reflect over x-axis)."
  (if (secp-inf-p p)
      p
      (cons (secp-x p) (secp-neg (secp-y p)))))

(defun schnorr-sign (privkey msg)
  "Sign a 32-byte message with BIP-340 Schnorr signature.
   Returns 64-byte signature (r || s)."
  (secp-init)
  (let* ((d privkey)
         (P (secp-pubkey d))
         ;; If y(P) is odd, negate d
         (d (if (secp-has-even-y P) d (- *secp256k1-n* d)))
         (P (if (secp-has-even-y P) P (secp-negate-point P)))
         ;; Deterministic nonce: k = hash(d || x(P) || m) mod n
         (k-hash (tagged-hash "BIP0340/nonce"
                              (bytes-concat (int-to-bytes32 d)
                                           (int-to-bytes32 (secp-x P))
                                           msg)))
         (k (mod (bytes-to-int k-hash) *secp256k1-n*)))
    ;; k must not be zero
    (when (zerop k)
      (error "Schnorr sign: k is zero"))
    (let* ((R (secp-mul-point k (secp-generator)))
           ;; If y(R) is odd, negate k
           (k (if (secp-has-even-y R) k (- *secp256k1-n* k)))
           (R (if (secp-has-even-y R) R (secp-negate-point R)))
           (r (secp-x R))
           ;; e = hash(r || x(P) || m) mod n
           (e-hash (tagged-hash "BIP0340/challenge"
                                (bytes-concat (int-to-bytes32 r)
                                             (int-to-bytes32 (secp-x P))
                                             msg)))
           (e (mod (bytes-to-int e-hash) *secp256k1-n*))
           ;; s = (k + e*d) mod n
           (s (mod (+ k (* e d)) *secp256k1-n*)))
      ;; Return r || s
      (bytes-concat (int-to-bytes32 r) (int-to-bytes32 s)))))

(defun schnorr-pubkey (privkey)
  "Get the 32-byte x-only public key for a private key."
  (secp-init)
  (let ((P (secp-pubkey privkey)))
    (int-to-bytes32 (secp-x P))))

;;; Modular square root for verification
(defun secp-sqrt (a)
  "Compute square root mod p using p ≡ 3 (mod 4) property.
   Returns sqrt(a) if it exists, or nil."
  (secp-init)
  ;; For p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
  (let* ((exp (ash (+ *secp256k1-p* 1) -2))  ; (p+1)/4
         (r (secp-pow a exp)))
    ;; Verify: r^2 == a (mod p)
    (when (= (secp-sq r) (mod a *secp256k1-p*))
      r)))

(defun secp-pow (base exp)
  "Compute base^exp mod p using square-and-multiply."
  (let ((result 1)
        (b (mod base *secp256k1-p*)))
    (loop while (> exp 0) do
      (when (oddp exp)
        (setf result (secp-mul result b)))
      (setf b (secp-sq b))
      (setf exp (ash exp -1)))
    result))

(defun secp-lift-x (x)
  "Lift x-coordinate to a point with even y (BIP-340 convention).
   Returns point or nil if x is not a valid x-coordinate."
  (secp-init)
  (when (>= x *secp256k1-p*)
    (return-from secp-lift-x nil))
  ;; y^2 = x^3 + 7
  (let* ((y-sq (secp-mod (+ (secp-mul x (secp-sq x)) 7)))
         (y (secp-sqrt y-sq)))
    (when y
      ;; Return point with even y
      (if (evenp y)
          (cons x y)
          (cons x (secp-neg y))))))

(defun schnorr-verify (pubkey-bytes sig msg)
  "Verify a BIP-340 Schnorr signature.
   pubkey-bytes: 32-byte x-only public key
   sig: 64-byte signature (r || s)
   msg: 32-byte message
   Returns T if valid, NIL if invalid."
  (secp-init)
  ;; Extract r and s
  ;; NOTE: No longer need workaround after compiler fix to use binding-extent-env
  (let* ((r-bytes (subseq sig 0 32))  ; still need for e-hash computation
         (r (bytes-to-int r-bytes))
         (s (bytes-to-int (subseq sig 32 64)))
         (px (bytes-to-int pubkey-bytes))
         (P nil) (e nil) (sG nil) (eP nil) (neg-eP nil) (result nil))
    ;; Check bounds
    (when (>= r *secp256k1-p*)
      (return-from schnorr-verify nil))
    (when (>= s *secp256k1-n*)
      (return-from schnorr-verify nil))
    ;; Lift public key x to point P
    (setf P (secp-lift-x px))
    (when (null P)
      (return-from schnorr-verify nil))
    ;; Compute e = hash(r || P_x || m) mod n
    (let ((e-hash (tagged-hash "BIP0340/challenge"
                               (bytes-concat r-bytes pubkey-bytes msg))))
      (setf e (mod (bytes-to-int e-hash) *secp256k1-n*)))
    ;; R = s*G - e*P
    (setf sG (secp-mul-point s (secp-generator)))
    (setf eP (secp-mul-point e P))
    (setf neg-eP (secp-negate-point eP))
    (setf result (secp-add-points sG neg-eP))
    ;; Check result is not infinity
    (when (secp-inf-p result)
      (return-from schnorr-verify nil))
    ;; Check result has even y
    (when (not (secp-has-even-y result))
      (return-from schnorr-verify nil))
    ;; Check x(result) == r (now works without workaround after compiler fix)
    (= (secp-x result) r)))

;;; Test
(defun secp256k1-test ()
  "Test secp256k1."
  (format t "~&secp256k1 Test~%")
  (secp-init)
  (format t "Init done.~%")
  (let ((g (secp-generator)))
    (format t "G on curve: ~a~%" (secp-on-curve-p g)))
  (format t "2*G...~%")
  (let ((g2 (secp-double (secp-generator))))
    (format t "2*G on curve: ~a~%" (secp-on-curve-p g2)))
  (format t "~&secp256k1 test complete.~%"))

(defun gc-bignum-test ()
  "Test GC behavior with large bignums in cons cells."
  (format t "~&GC Bignum Test~%")
  (secp-init)
  ;; Create a 256-bit number (like our curve coordinates)
  (let* ((big1 *secp256k1-p*)
         (big2 *secp256k1-n*)
         ;; Store copies for comparison
         (big1-copy (+ big1 0))  ; Force new bignum
         (big2-copy (+ big2 0))
         ;; Create a cons cell like our point representation
         (point (cons big1 big2)))
    (format t "Created point cons~%")
    (format t "big1 = big1-copy before GC: ~a~%" (= big1 big1-copy))
    (format t "car point = big1 before GC: ~a~%" (= (car point) big1))
    ;; Force GC by allocating lots of garbage
    (format t "Forcing GC...~%")
    (dotimes (i 50000)
      (cons i i))
    (format t "GC should have run~%")
    ;; Now check if values are still correct
    (format t "big1 = big1-copy after GC: ~a~%" (= big1 big1-copy))
    (format t "car point = big1 after GC: ~a~%" (= (car point) big1))
    (format t "car point = big1-copy after GC: ~a~%" (= (car point) big1-copy))
    ;; Check the actual values via byte conversion
    (let ((car-bytes (int-to-bytes32 (car point)))
          (big1-bytes (int-to-bytes32 big1)))
      (format t "Bytes equal: ~a~%" (equalp car-bytes big1-bytes)))
    (format t "~&GC bignum test complete.~%")))

(defun gc-point-test ()
  "Test GC with actual point operations."
  (format t "~&GC Point Test~%")
  (secp-init)
  (let* ((g (secp-generator))
         (g-x (secp-x g))
         (g-y (secp-y g))
         ;; Save copies
         (saved-gx (+ g-x 0))
         (saved-gy (+ g-y 0)))
    (format t "G created, x bits: ~a~%" (integer-length g-x))
    ;; Do some point operations that allocate
    (format t "Computing 2*G...~%")
    (let ((g2 (secp-double g)))
      (format t "2*G computed~%")
      ;; Check original G is still correct
      (format t "g-x = saved-gx: ~a~%" (= g-x saved-gx))
      (format t "g-y = saved-gy: ~a~%" (= g-y saved-gy))
      (format t "(car g) = g-x: ~a~%" (= (car g) g-x))
      ;; Force more allocation
      (format t "Computing 3*G...~%")
      (let ((g3 (secp-add-points g g2)))
        (format t "3*G computed~%")
        (format t "g-x still = saved-gx: ~a~%" (= g-x saved-gx))
        (format t "(car g) still = g-x: ~a~%" (= (car g) g-x))
        ;; Check if g3 is on curve
        (format t "3*G on curve: ~a~%" (secp-on-curve-p g3)))))
  (format t "~&GC point test complete.~%"))

(defun gc-scalar-test (&optional (k 255))
  "Test GC during scalar multiplication (like verification)."
  (format t "~&GC Scalar Test (k=~a)~%" k)
  (secp-init)
  (let* ((g (secp-generator))
         (saved-gx (+ (secp-x g) 0)))
    (format t "Computing k*G for k=~a...~%" k)
    (let ((result (secp-mul-point k g)))
      (format t "k*G computed~%")
      (format t "Result on curve: ~a~%" (secp-on-curve-p result))
      (format t "G-x preserved: ~a~%" (= (secp-x g) saved-gx))
      ;; Now try with a bigger k (like in verification)
      (format t "Testing with 128-bit k...~%")
      (let* ((big-k (bytes-to-int #(#x12 #x34 #x56 #x78 #x9a #xbc #xde #xf0
                                   #x11 #x22 #x33 #x44 #x55 #x66 #x77 #x88)))
             (result2 (secp-mul-point big-k g)))
        (format t "128-bit k*G computed~%")
        (format t "Result2 on curve: ~a~%" (secp-on-curve-p result2))
        (format t "G-x still preserved: ~a~%" (= (secp-x g) saved-gx)))))
  (format t "~&GC scalar test complete.~%"))

(defun gc-verify-test ()
  "Test the specific verification scenario that was failing."
  (format t "~&GC Verify Test~%")
  (secp-init)
  (let* ((privkey 12345)
         (msg (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref msg 0) (char-code #\t))
    ;; Sign a message
    (format t "Signing...~%")
    (let ((sig (schnorr-sign privkey msg)))
      (format t "Signature done~%")
      ;; Extract r and s
      (let* ((r (bytes-to-int (subseq sig 0 32)))
             (s (bytes-to-int (subseq sig 32 64)))
             ;; Save copies
             (saved-r (+ r 0))
             (saved-s (+ s 0)))
        (format t "r,s extracted, bits: ~a, ~a~%" (integer-length r) (integer-length s))
        ;; Now do verification-like computation
        (format t "Computing s*G...~%")
        (let ((sG (secp-mul-point s (secp-generator))))
          (format t "s*G computed, on curve: ~a~%" (secp-on-curve-p sG))
          ;; Check if our saved values survived
          (format t "r = saved-r: ~a~%" (= r saved-r))
          (format t "s = saved-s: ~a~%" (= s saved-s))
          ;; Try byte conversion check
          (let ((r-bytes (int-to-bytes32 r))
                (saved-r-bytes (int-to-bytes32 saved-r)))
            (format t "r bytes = saved-r bytes: ~a~%" (equalp r-bytes saved-r-bytes)))))))
  (format t "~&GC verify test complete.~%"))

(defun schnorr-verify-test ()
  "Test full sign and verify cycle."
  (format t "~&Schnorr Sign+Verify Test~%")
  (secp-init)
  (let* ((privkey 12345)
         (msg (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (pubkey (schnorr-pubkey privkey)))
    (setf (aref msg 0) (char-code #\t)
          (aref msg 1) (char-code #\e)
          (aref msg 2) (char-code #\s)
          (aref msg 3) (char-code #\t))
    (format t "Pubkey: ~a bytes~%" (length pubkey))
    (format t "Signing...~%")
    (let ((sig (schnorr-sign privkey msg)))
      (format t "Signature: ~a bytes~%" (length sig))
      (format t "Verifying...~%")
      (let ((valid (schnorr-verify pubkey sig msg)))
        (format t "Verification result: ~a~%" valid))))
  (format t "~&Schnorr sign+verify test complete.~%"))

(defun schnorr-verify-debug ()
  "Debug version of sign+verify with intermediate output."
  (format t "~&Schnorr Verify Debug~%")
  (secp-init)
  (let* ((privkey 12345)
         (msg (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (pubkey-bytes (schnorr-pubkey privkey))
         (sig nil)
         (sig-r nil) (sig-s nil) (px nil) (r-bytes nil)
         (P-lifted nil) (e nil)
         (sG nil) (eP nil) (neg-eP nil) (result-point nil))
    (setf (aref msg 0) (char-code #\t))
    (format t "Pubkey bytes: ~a~%" (length pubkey-bytes))
    ;; Sign
    (setf sig (schnorr-sign privkey msg))
    (setf sig-r (bytes-to-int (subseq sig 0 32)))
    (setf sig-s (bytes-to-int (subseq sig 32 64)))
    (setf px (bytes-to-int pubkey-bytes))
    (setf r-bytes (int-to-bytes32 sig-r))
    (format t "Sig created~%")
    (format t "sig-r bits: ~a, sig-s bits: ~a~%" (integer-length sig-r) (integer-length sig-s))
    (format t "sig-r type: ~a~%" (type-of sig-r))
    ;; Lift public key
    (setf P-lifted (secp-lift-x px))
    (when (null P-lifted)
      (format t "ERROR: lift_x returned NIL!~%")
      (return-from schnorr-verify-debug nil))
    (format t "P lifted, on curve: ~a~%" (secp-on-curve-p P-lifted))
    ;; Compute e
    (let ((e-hash (tagged-hash "BIP0340/challenge"
                               (bytes-concat r-bytes pubkey-bytes msg))))
      (setf e (mod (bytes-to-int e-hash) *secp256k1-n*)))
    (format t "e bits: ~a~%" (integer-length e))
    (format t "sig-r type after e: ~a~%" (type-of sig-r))
    ;; Compute s*G
    (format t "Computing s*G...~%")
    (setf sG (secp-mul-point sig-s (secp-generator)))
    (format t "s*G on curve: ~a~%" (secp-on-curve-p sG))
    (format t "sig-r type after sG: ~a~%" (type-of sig-r))
    ;; Compute e*P
    (format t "Computing e*P...~%")
    (setf eP (secp-mul-point e P-lifted))
    (setf neg-eP (secp-negate-point eP))
    (format t "e*P on curve: ~a~%" (secp-on-curve-p eP))
    (format t "sig-r type after eP: ~a~%" (type-of sig-r))
    ;; Compute result-point = sG - eP
    (format t "Computing result-point = s*G - e*P...~%")
    (setf result-point (secp-add-points sG neg-eP))
    (format t "result-point infinite: ~a~%" (secp-inf-p result-point))
    (format t "sig-r type after result-point: ~a~%" (type-of sig-r))
    (when (secp-inf-p result-point)
      (format t "ERROR: result-point is infinity~%")
      (return-from schnorr-verify-debug nil))
    (format t "result-point on curve: ~a~%" (secp-on-curve-p result-point))
    (format t "result-point has even y: ~a~%" (secp-has-even-y result-point))
    ;; Compare
    (format t "result-point.x = sig-r: ~a~%" (= (secp-x result-point) sig-r))
    (format t "result-point.x bits: ~a~%" (integer-length (secp-x result-point)))
    (format t "sig-r bits: ~a~%" (integer-length sig-r)))
  (format t "~&Debug complete.~%"))

(defun schnorr-test ()
  "Test Schnorr signing."
  (format t "~&Schnorr Sign Test~%")
  (secp-init)
  (let* ((privkey 12345)
         (msg (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref msg 0) (char-code #\t)
          (aref msg 1) (char-code #\e)
          (aref msg 2) (char-code #\s)
          (aref msg 3) (char-code #\t))
    (format t "Signing...~%")
    (let ((sig (schnorr-sign privkey msg)))
      (format t "Signature: ~a bytes~%" (length sig))
      (let ((r (bytes-to-int (subseq sig 0 32)))
            (s (bytes-to-int (subseq sig 32 64))))
        (format t "r < p: ~a~%" (< r *secp256k1-p*))
        (format t "s < n: ~a~%" (< s *secp256k1-n*)))))
  (format t "~&Schnorr sign test complete.~%"))

(provide :lib/crypto/secp256k1)
