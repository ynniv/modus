;; crypto-32.lisp — 32-bit safe overrides for fe-mul, fe-sq, poly-mul
;; Load AFTER crypto.lisp (last-defun-wins)
;;
;; On 32-bit targets (i386), fixnums are 30-bit positive (31-bit signed).
;; Products of 26-bit limbs reach 52 bits and overflow. This file uses
;; pair arithmetic with 26-bit halves: (hi26 . lo26) represents hi*2^26 + lo.
;;
;; The *19 reduction factor is applied at the pair level using shift-and-add
;; (19 = 16 + 2 + 1) to avoid 26*5=31-bit overflow.

;; ================================================================
;; Pair arithmetic: (hi . lo) with 26-bit halves
;; Total range: 52 bits (enough for products)
;; After accumulation of 10 products: ~56 bits (hi grows beyond 26)
;; ================================================================

;; Multiply two values (each ≤ 27 bits) → (hi26 . lo26)
;; Uses 13-bit split: 4 partial products, each ≤ 28 bits
;; Split into two functions to avoid i386 register pressure bugs
(defun mul26-combine (p0 p1 p2 p3)
  (let ((mid (+ p1 p2)))
    (let ((lo-raw (+ p0 (* (logand mid 8191) 8192))))
      (let ((lo26 (logand lo-raw 67108863))
            (carry (ash lo-raw -26)))
        (let ((hi (+ p3 (+ (ash mid -13) carry))))
          (cons hi lo26))))))

(defun mul26 (a b)
  (let ((al (logand a 8191))
        (ah (ash a -13))
        (bl (logand b 8191))
        (bh (ash b -13)))
    (mul26-combine (* al bl) (* al bh) (* ah bl) (* ah bh))))

;; Pair add: (hi . lo) + (hi . lo) → (hi . lo)
;; lo halves are 26 bits, carry propagates to hi
(defun padd (a b)
  (let ((lo (+ (cdr a) (cdr b))))
    (cons (+ (car a) (+ (car b) (ash lo -26)))
          (logand lo 67108863))))

;; Pair add scalar: (hi . lo) + n → (hi . lo)
(defun padd-s (p n)
  (let ((lo (+ (cdr p) n)))
    (cons (+ (car p) (ash lo -26))
          (logand lo 67108863))))

;; Scale pair by 2: (hi . lo) * 2
(defun pshl1 (p)
  (let ((lo2 (ash (cdr p) 1)))
    (cons (+ (ash (car p) 1) (ash lo2 -26))
          (logand lo2 67108863))))

;; Scale pair by 16: (hi . lo) * 16
;; NOTE: overflows on i386 when hi >= 27 bits. i386 uses triple-based
;; fe-mul override in i386-overrides.lisp instead.
(defun pshl4 (p)
  (let ((lo (cdr p)))
    (cons (+ (ash (car p) 4) (ash lo -22))
          (logand (ash lo 4) 67108863))))

;; Scale pair by 19 = 16 + 2 + 1
;; Uses shift-and-add to avoid overflow
(defun pmul19 (p)
  (padd p (padd (pshl1 p) (pshl4 p))))

;; Extract 26-bit limb and carry from pair
;; Returns (carry . limb26)
(defun pcarry26 (p)
  (cons (+ (ash (car p) 26) (ash (cdr p) -26))
        (logand (cdr p) 67108863)))

;; Whoops — pcarry26 hi computation overflows (ash hi 26 is huge).
;; Instead: carry = hi + (lo >> 26), but lo is already 26-bit so lo>>26=0.
;; The carry is just hi. The limb is lo.
;; But wait, after accumulating 10 products, lo can grow beyond 26 bits
;; if we add carry from previous step. Let me reconsider.
;;
;; After accumulation: pair = (hi_acc . lo_acc) where:
;;   lo_acc ≤ 10 * 2^26 ≈ 2^29.3 (fits in 30-bit fixnum)
;;   hi_acc ≤ 10 * 2^26 ≈ 2^29.3 (fits in 30-bit fixnum)
;; To extract 26-bit limb:
;;   limb = lo_acc & 0x3FFFFFF
;;   carry = hi_acc * 2^26 + (lo_acc >> 26)
;;   But hi_acc * 2^26 doesn't fit in fixnum.
;;
;; Solution: carry is a NEW pair for the next stage.
;; carry_pair = (hi_acc, lo_acc >> 26) → means "hi_acc * 2^26 + (lo_acc >> 26)"
;; Then add carry_pair to next h pair.
;; But the representation is wrong — (hi_acc, lo_acc >> 26) means
;; hi_acc * 2^26 + (lo_acc >> 26), which is the correct carry value.
;; When we add this carry_pair to the next h_pair using padd, we get:
;;   next_lo + (lo_acc >> 26), with carry to next_hi.
;;   next_hi + hi_acc + carry_from_lo.
;; This correctly propagates the full carry! Perfect.

;; Extract carry pair and limb from accumulated pair
;; Returns (carry_pair . limb26) where carry_pair = (hi . lo_overflow)
(defun pextract26 (p)
  (cons (cons (car p) (ash (cdr p) -26))
        (logand (cdr p) 67108863)))

;; Same for 25-bit extraction
(defun pextract25 (p)
  (cons (cons (car p) (ash (cdr p) -25))
        (logand (cdr p) 33554431)))

;; ================================================================
;; Poly1305 multiply a * r mod 2^130-5
;; ================================================================

;; Accumulate 5 products as pairs
(defun poly-acc5 (a0 b0 a1 b1 a2 b2 a3 b3 a4 b4)
  (padd (mul26 a0 b0)
    (padd (mul26 a1 b1)
      (padd (mul26 a2 b2)
        (padd (mul26 a3 b3)
              (mul26 a4 b4))))))

(defun poly-mul (a r)
  (let ((a0 (buf-read-u32 a 0))
        (a1 (buf-read-u32 a 4))
        (a2 (buf-read-u32 a 8))
        (a3 (buf-read-u32 a 12))
        (a4 (buf-read-u32 a 16))
        (r0 (buf-read-u32 r 0))
        (r1 (buf-read-u32 r 4))
        (r2 (buf-read-u32 r 8))
        (r3 (buf-read-u32 r 12))
        (r4 (buf-read-u32 r 16)))
    ;; For poly1305, *5 reduction: si = ri*5
    ;; ri ≤ 26 bits, ri*5 ≤ 28 bits. Fits in 30-bit fixnum!
    (let ((s1 (* r1 5))
          (s2 (* r2 5))
          (s3 (* r3 5))
          (s4 (* r4 5)))
      ;; Accumulate products as pairs
      (let ((d0 (poly-acc5 a0 r0 a1 s4 a2 s3 a3 s2 a4 s1))
            (d1 (poly-acc5 a0 r1 a1 r0 a2 s4 a3 s3 a4 s2))
            (d2 (poly-acc5 a0 r2 a1 r1 a2 r0 a3 s4 a4 s3))
            (d3 (poly-acc5 a0 r3 a1 r2 a2 r1 a3 r0 a4 s4))
            (d4 (poly-acc5 a0 r4 a1 r3 a2 r2 a3 r1 a4 r0)))
        ;; Carry propagation using pair extraction
        (poly-carry32 a d0 d1 d2 d3 d4)))))

(defun poly-carry32 (a d0 d1 d2 d3 d4)
  (let ((e0 (pextract26 d0)))
    (let ((r0 (cdr e0))
          (d1b (padd d1 (car e0))))
      (let ((e1 (pextract26 d1b)))
        (let ((r1 (cdr e1))
              (d2b (padd d2 (car e1))))
          (let ((e2 (pextract26 d2b)))
            (let ((r2 (cdr e2))
                  (d3b (padd d3 (car e2))))
              (let ((e3 (pextract26 d3b)))
                (let ((r3 (cdr e3))
                      (d4b (padd d4 (car e3))))
                  (let ((e4 (pextract26 d4b)))
                    (let ((r4 (cdr e4))
                          (cc-pair (car e4)))
                      ;; cc = carry from d4, multiply by 5 and add to r0
                      ;; cc-pair represents a small value (≤ ~4 bits)
                      ;; cc scalar = cc-pair.hi * 2^26 + cc-pair.lo
                      ;; For poly1305, this is small enough to be scalar
                      (let ((cc (+ (* (car cc-pair) 67108864) (cdr cc-pair))))
                        (when (> cc 0)
                          (let ((f (+ r0 (* cc 5))))
                            (setf r0 (logand f 67108863))
                            (let ((c2 (ash f -26)))
                              (when (> c2 0)
                                (setf r1 (+ r1 c2))))))
                        (buf-write-u32 a 0 r0)
                        (buf-write-u32 a 4 r1)
                        (buf-write-u32 a 8 r2)
                        (buf-write-u32 a 12 r3)
                        (buf-write-u32 a 16 r4)))))))))))))

;; ================================================================
;; Curve25519 field multiply dst = f * g mod 2^255-19
;; ================================================================

;; Accumulate 10 products as pairs
(defun fe-acc10 (a0 b0 a1 b1 a2 b2 a3 b3 a4 b4
                 a5 b5 a6 b6 a7 b7 a8 b8 a9 b9)
  (padd (mul26 a0 b0)
    (padd (mul26 a1 b1)
      (padd (mul26 a2 b2)
        (padd (mul26 a3 b3)
          (padd (mul26 a4 b4)
            (padd (mul26 a5 b5)
              (padd (mul26 a6 b6)
                (padd (mul26 a7 b7)
                  (padd (mul26 a8 b8)
                        (mul26 a9 b9)))))))))))

;; Accumulate 10 products, then scale by 19 (for reduction terms)
(defun fe-acc10-19 (a0 b0 a1 b1 a2 b2 a3 b3 a4 b4
                    a5 b5 a6 b6 a7 b7 a8 b8 a9 b9)
  (pmul19 (fe-acc10 a0 b0 a1 b1 a2 b2 a3 b3 a4 b4
                    a5 b5 a6 b6 a7 b7 a8 b8 a9 b9)))

;; Wait — the donna multiply doesn't have a clean "reduced" vs "non-reduced"
;; split per output limb. Each h[k] is a sum of terms where SOME are wrapped
;; (multiplied by 19) and some aren't. We can't factor out the *19.
;;
;; Instead: for each term that needs *19, we compute mul26(fi, gj) and then
;; pmul19 it individually before adding to the accumulator.
;;
;; But that's 10 pmul19 calls per output limb × 10 limbs = 100 pmul19 calls.
;; Each pmul19 does 3 padd + 2 shifts = ~15 operations. Total ~1500 ops
;; for just the scaling. Combined with 100 mul26 and 100 padd: ~3000 ops total.
;; That's OK for performance.

;; Actually, looking at the donna pattern more carefully:
;; h0 = f0*g0 + 2*f1*g9*19 + f2*g8*19 + 2*f3*g7*19 + f4*g6*19
;;            + 2*f5*g5*19 + f6*g4*19 + 2*f7*g3*19 + f8*g2*19 + 2*f9*g1*19
;;
;; The *2 is on odd f indices, *19 is on wrapped g terms.
;; Combined: 2*fi*gj*19 = fi * (2*gj) * 19 or (2*fi) * gj * 19
;;
;; Simpler: accumulate all raw products first, then apply *19 to the
;; wrapped portion. But the non-wrapped and wrapped terms go to different h[k].
;;
;; Actually the cleanest approach: split fe-mul into helper functions that
;; compute each h[k] separately. For each h[k]:
;;   - Some terms are plain: fi*gj (both ≤ 26 bits, one might be *2 = 27 bits)
;;   - Some terms are wrapped: fi*gj*19
;;
;; For the plain terms, *2 makes the value 27 bits.
;; mul26 with 27-bit input: split at 13 bits, ah = 14 bits.
;; p3 = ah*bh ≤ 14+13 = 27 bits. Fits in 30-bit fixnum!
;; So mul26 handles inputs up to 27 bits.
;;
;; For wrapped terms: compute mul26(fi, gj) → pair, then pmul19(pair).
;; fi may be *2 (27 bits), gj is always 26 bits. mul26 works.
;; pmul19 works on any pair (uses shift-and-add).

;; Helper: compute one product pair, optionally scaled by 19
(defun prod26 (a b)
  (mul26 a b))

(defun prod26-19 (a b)
  (pmul19 (mul26 a b)))

;; Compute h[k] for each output limb
;; Each function takes the needed f and g values and returns a pair
;; Split into two halves (5 terms each) to avoid 18+ nested lets

(defun fe-h-5 (p0 p1 p2 p3 p4)
  (padd p0 (padd p1 (padd p2 (padd p3 p4)))))

(defun fe-h0 (f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g0) (prod26-19 f1-2 g9) (prod26-19 f2 g8)
            (prod26-19 f3-2 g7) (prod26-19 f4 g6))
    (fe-h-5 (prod26-19 f5-2 g5) (prod26-19 f6 g4) (prod26-19 f7-2 g3)
            (prod26-19 f8 g2) (prod26-19 f9-2 g1))))

(defun fe-h1 (f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g1) (prod26 f1 g0) (prod26-19 f2 g9)
            (prod26-19 f3 g8) (prod26-19 f4 g7))
    (fe-h-5 (prod26-19 f5 g6) (prod26-19 f6 g5) (prod26-19 f7 g4)
            (prod26-19 f8 g3) (prod26-19 f9 g2))))

(defun fe-h2 (f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g2) (prod26 f1-2 g1) (prod26 f2 g0)
            (prod26-19 f3-2 g9) (prod26-19 f4 g8))
    (fe-h-5 (prod26-19 f5-2 g7) (prod26-19 f6 g6) (prod26-19 f7-2 g5)
            (prod26-19 f8 g4) (prod26-19 f9-2 g3))))

(defun fe-h3 (f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g3) (prod26 f1 g2) (prod26 f2 g1)
            (prod26 f3 g0) (prod26-19 f4 g9))
    (fe-h-5 (prod26-19 f5 g8) (prod26-19 f6 g7) (prod26-19 f7 g6)
            (prod26-19 f8 g5) (prod26-19 f9 g4))))

(defun fe-h4 (f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g4) (prod26 f1-2 g3) (prod26 f2 g2)
            (prod26 f3-2 g1) (prod26 f4 g0))
    (fe-h-5 (prod26-19 f5-2 g9) (prod26-19 f6 g8) (prod26-19 f7-2 g7)
            (prod26-19 f8 g6) (prod26-19 f9-2 g5))))

(defun fe-h5 (f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g5) (prod26 f1 g4) (prod26 f2 g3)
            (prod26 f3 g2) (prod26 f4 g1))
    (fe-h-5 (prod26 f5 g0) (prod26-19 f6 g9) (prod26-19 f7 g8)
            (prod26-19 f8 g7) (prod26-19 f9 g6))))

(defun fe-h6 (f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g6) (prod26 f1-2 g5) (prod26 f2 g4)
            (prod26 f3-2 g3) (prod26 f4 g2))
    (fe-h-5 (prod26 f5-2 g1) (prod26 f6 g0) (prod26-19 f7-2 g9)
            (prod26-19 f8 g8) (prod26-19 f9-2 g7))))

(defun fe-h7 (f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g7) (prod26 f1 g6) (prod26 f2 g5)
            (prod26 f3 g4) (prod26 f4 g3))
    (fe-h-5 (prod26 f5 g2) (prod26 f6 g1) (prod26 f7 g0)
            (prod26-19 f8 g9) (prod26-19 f9 g8))))

(defun fe-h8 (f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g8) (prod26 f1-2 g7) (prod26 f2 g6)
            (prod26 f3-2 g5) (prod26 f4 g4))
    (fe-h-5 (prod26 f5-2 g3) (prod26 f6 g2) (prod26 f7-2 g1)
            (prod26 f8 g0) (prod26-19 f9-2 g9))))

(defun fe-h9 (f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
              g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (padd
    (fe-h-5 (prod26 f0 g9) (prod26 f1 g8) (prod26 f2 g7)
            (prod26 f3 g6) (prod26 f4 g5))
    (fe-h-5 (prod26 f5 g4) (prod26 f6 g3) (prod26 f7 g2)
            (prod26 f8 g1) (prod26 f9 g0))))

;; Carry propagation: pairs → 26/25-bit limbs
;; Split into two halves to avoid 18+ nested lets

(defun fe-carry-lo32 (h0 h1 h2 h3 h4)
  (let ((e0 (pextract26 h0)))
    (let ((h1b (padd h1 (car e0))))
      (let ((e1 (pextract25 h1b)))
        (let ((h2b (padd h2 (car e1))))
          (let ((e2 (pextract26 h2b)))
            (let ((h3b (padd h3 (car e2))))
              (let ((e3 (pextract25 h3b)))
                (let ((h4b (padd h4 (car e3))))
                  (let ((e4 (pextract26 h4b)))
                    (cons (car e4)
                      (cons (cdr e0) (cons (cdr e1) (cons (cdr e2)
                        (cons (cdr e3) (cons (cdr e4) nil))))))))))))))))

(defun fe-carry-hi32 (c4 h5 h6 h7 h8 h9)
  (let ((h5b (padd h5 c4)))
    (let ((e5 (pextract25 h5b)))
      (let ((h6b (padd h6 (car e5))))
        (let ((e6 (pextract26 h6b)))
          (let ((h7b (padd h7 (car e6))))
            (let ((e7 (pextract25 h7b)))
              (let ((h8b (padd h8 (car e7))))
                (let ((e8 (pextract26 h8b)))
                  (let ((h9b (padd h9 (car e8))))
                    (let ((e9 (pextract25 h9b)))
                      (cons (car e9)
                        (cons (cdr e5) (cons (cdr e6) (cons (cdr e7)
                          (cons (cdr e8) (cons (cdr e9) nil)))))))))))))))))

(defun fe-carry32 (dst h0 h1 h2 h3 h4 h5 h6 h7 h8 h9)
  (let ((lo (fe-carry-lo32 h0 h1 h2 h3 h4)))
    (let ((c4 (car lo))
          (r0 (car (cdr lo)))
          (r1 (car (cdr (cdr lo))))
          (r2 (car (cdr (cdr (cdr lo)))))
          (r3 (car (cdr (cdr (cdr (cdr lo))))))
          (r4 (car (cdr (cdr (cdr (cdr (cdr lo))))))))
      (let ((hi (fe-carry-hi32 c4 h5 h6 h7 h8 h9)))
        (let ((c9p (car hi))
              (r5 (car (cdr hi)))
              (r6 (car (cdr (cdr hi))))
              (r7 (car (cdr (cdr (cdr hi)))))
              (r8 (car (cdr (cdr (cdr (cdr hi))))))
              (r9 (car (cdr (cdr (cdr (cdr (cdr hi))))))))
          ;; c9 is a pair (hi . lo) representing the carry from h9
          ;; For well-reduced inputs, c9 scalar = c9p.hi * 2^26 + c9p.lo
          ;; This should be small (a few bits), so c9p.hi = 0
          (let ((c9 (+ (* (car c9p) 67108864) (cdr c9p))))
            (let ((r0w (+ r0 (* c9 19))))
              (let ((c0b (ash r0w -26))
                    (r0f (logand r0w 67108863)))
                (fe-carry-write dst r0f (+ r1 c0b) r2 r3 r4 r5 r6 r7 r8 r9)))))))))

(defun fe-carry-write (dst r0 r1 r2 r3 r4 r5 r6 r7 r8 r9)
  (buf-write-u32 dst 0 r0)
  (buf-write-u32 dst 4 r1)
  (buf-write-u32 dst 8 r2)
  (buf-write-u32 dst 12 r3)
  (buf-write-u32 dst 16 r4)
  (buf-write-u32 dst 20 r5)
  (buf-write-u32 dst 24 r6)
  (buf-write-u32 dst 28 r7)
  (buf-write-u32 dst 32 r8)
  (buf-write-u32 dst 36 r9))

;; Main fe-mul: read limbs, compute h[0..9], carry-propagate, write
(defun fe-mul (dst f g)
  (let ((f0 (buf-read-u32 f 0))
        (f1 (buf-read-u32 f 4))
        (f2 (buf-read-u32 f 8))
        (f3 (buf-read-u32 f 12))
        (f4 (buf-read-u32 f 16))
        (f5 (buf-read-u32 f 20))
        (f6 (buf-read-u32 f 24))
        (f7 (buf-read-u32 f 28))
        (f8 (buf-read-u32 f 32))
        (f9 (buf-read-u32 f 36)))
    (fe-mul-2 dst f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 g))
  dst)

(defun fe-mul-2 (dst f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 g)
  (let ((g0 (buf-read-u32 g 0))
        (g1 (buf-read-u32 g 4))
        (g2 (buf-read-u32 g 8))
        (g3 (buf-read-u32 g 12))
        (g4 (buf-read-u32 g 16))
        (g5 (buf-read-u32 g 20))
        (g6 (buf-read-u32 g 24))
        (g7 (buf-read-u32 g 28))
        (g8 (buf-read-u32 g 32))
        (g9 (buf-read-u32 g 36)))
    (fe-mul-3 dst f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                  g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)))

(defun fe-mul-3 (dst f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                     g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (let ((f1-2 (* 2 f1))
        (f3-2 (* 2 f3))
        (f5-2 (* 2 f5))
        (f7-2 (* 2 f7))
        (f9-2 (* 2 f9)))
    ;; Compute h[0..4] first
    (let ((h0 (fe-h0 f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
                      g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
          (h1 (fe-h1 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                      g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
          (h2 (fe-h2 f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
                      g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
          (h3 (fe-h3 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                      g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
          (h4 (fe-h4 f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
                      g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)))
      (fe-mul-4 dst h0 h1 h2 h3 h4
                f0 f1 f1-2 f2 f3 f3-2 f4 f5 f5-2 f6
                f7 f7-2 f8 f9 f9-2
                g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))))

(defun fe-mul-4 (dst h0 h1 h2 h3 h4
                 f0 f1 f1-2 f2 f3 f3-2 f4 f5 f5-2 f6
                 f7 f7-2 f8 f9 f9-2
                 g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)
  (let ((h5 (fe-h5 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                    g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
        (h6 (fe-h6 f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
                    g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
        (h7 (fe-h7 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                    g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
        (h8 (fe-h8 f0 f1-2 f2 f3-2 f4 f5-2 f6 f7-2 f8 f9-2
                    g0 g1 g2 g3 g4 g5 g6 g7 g8 g9))
        (h9 (fe-h9 f0 f1 f2 f3 f4 f5 f6 f7 f8 f9
                    g0 g1 g2 g3 g4 g5 g6 g7 g8 g9)))
    (fe-carry32 dst h0 h1 h2 h3 h4 h5 h6 h7 h8 h9)))

(defun fe-sq (dst f)
  (fe-mul dst f f))
