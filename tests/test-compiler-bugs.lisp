;;;; test-compiler-bugs.lisp - TDD tests for MVM compiler bugs
;;;;
;;;; Usage: sbcl --script tests/test-compiler-bugs.lisp
;;;;
;;;; Builds a minimal x64 kernel with test functions that exercise
;;;; known compiler bugs. Boots in QEMU, captures serial output,
;;;; compares against expected values.
;;;;
;;;; Each test prints "TEST-N:RESULT" where RESULT is a decimal number.
;;;; The harness checks against expected values.

;;; ============================================================
;;; Load MVM system
;;; ============================================================

(defvar *modus-base*
  (let* ((test-dir (directory-namestring (truename *load-truename*)))
         (modus-dir (namestring (truename (merge-pathnames "../" test-dir)))))
    (pathname modus-dir)))

(defun mvm-load (relative-path)
  (let ((path (merge-pathnames relative-path *modus-base*)))
    (load path :verbose nil :print nil)))

(mvm-load "cross/packages.lisp")
(mvm-load "cross/x64-asm.lisp")
(mvm-load "mvm/mvm.lisp")
(mvm-load "mvm/target.lisp")
(mvm-load "mvm/compiler.lisp")
(mvm-load "mvm/interp.lisp")
(mvm-load "boot/boot-x64.lisp")
(mvm-load "boot/boot-riscv.lisp")
(mvm-load "boot/boot-aarch64.lisp")
(mvm-load "boot/boot-rpi.lisp")
(mvm-load "boot/boot-ppc64.lisp")
(mvm-load "boot/boot-ppc32.lisp")
(mvm-load "boot/boot-i386.lisp")
(mvm-load "boot/boot-68k.lisp")
(mvm-load "boot/boot-arm32.lisp")
(mvm-load "mvm/translate-x64.lisp")
(mvm-load "mvm/translate-riscv.lisp")
(mvm-load "mvm/translate-aarch64.lisp")
(mvm-load "mvm/translate-ppc.lisp")
(mvm-load "mvm/translate-i386.lisp")
(mvm-load "mvm/translate-68k.lisp")
(mvm-load "mvm/translate-arm32.lisp")
(mvm-load "mvm/cross.lisp")

(in-package :modus.mvm)

;;; ============================================================
;;; Test source — each test-N function returns a value
;;; ============================================================

(defvar *test-source* "

;; Output helpers
(defun print-dec (n)
  (if (< n 10)
      (write-char-serial (+ 48 n))
      (let ((q (/ n 10)))
        (let ((r (- n (* q 10))))
          (print-dec q)
          (write-char-serial (+ 48 r))))))

(defun print-neg-dec (n)
  (write-char-serial 45)
  (print-dec (- 0 n)))

(defun print-result (n val)
  (write-char-serial 84)
  (write-char-serial 69)
  (write-char-serial 83)
  (write-char-serial 84)
  (write-char-serial 45)
  (print-dec n)
  (write-char-serial 58)
  (if (< val 0)
      (print-neg-dec val)
      (print-dec val))
  (write-char-serial 10))

;; ============================================================
;; BUG 1: Nested logior/logand/ash
;; ============================================================

;; Test 1: Simple nested logior (2 levels) — should work
(defun test-1 ()
  (let ((b0 1))
    (let ((b1 2))
      (logior b0 (ash b1 8)))))
;; Expected: 1 | (2 << 8) = 1 | 512 = 513

;; Test 2: Triple nested logior (3 levels) — THE BUG
(defun test-2 ()
  (let ((b0 1))
    (let ((b1 2))
      (let ((b2 3))
        (logior b0 (logior (ash b1 8) (ash b2 16)))))))
;; Expected: 1 | (2<<8) | (3<<16) = 1 | 512 | 196608 = 197121

;; Test 3: Quad nested logior (4 levels) — THE BUG (chacha-setup pattern)
(defun test-3 ()
  (let ((b0 1))
    (let ((b1 2))
      (let ((b2 3))
        (let ((b3 4))
          (logior b0 (logior (ash b1 8) (logior (ash b2 16) (ash b3 24)))))))))
;; Expected: 1 | (2<<8) | (3<<16) | (4<<24) = 1+512+196608+67108864 = 67305985

;; Test 4: Same computation with flat let bindings (the workaround)
(defun test-4 ()
  (let ((b0 1))
    (let ((b1 2))
      (let ((b2 3))
        (let ((b3 4))
          (let ((a (ash b3 24)))
            (let ((b (ash b2 16)))
              (let ((c (logior a b)))
                (let ((d (ash b1 8)))
                  (let ((e (logior c d)))
                    (logior e b0)))))))))))
;; Expected: 67305985 (same as test-3)

;; ============================================================
;; BUG 1b: Nested logior with FUNCTION CALLS as operands
;; This is the real failing pattern — mem-ref calls inside logior
;; ============================================================

;; Helper: identity function (forces a real function call)
(defun ident (x) x)

;; Test 8: Nested logior where operands are function calls
(defun test-8 ()
  (logior (ident 1) (logior (ash (ident 2) 8) (logior (ash (ident 3) 16) (ash (ident 4) 24)))))
;; Expected: 67305985

;; Test 9: Same with flat let bindings (the workaround)
(defun test-9 ()
  (let ((b0 (ident 1)))
    (let ((b1 (ident 2)))
      (let ((b2 (ident 3)))
        (let ((b3 (ident 4)))
          (let ((a (ash b3 24)))
            (let ((b (ash b2 16)))
              (let ((c (logior a b)))
                (let ((d (ash b1 8)))
                  (let ((e (logior c d)))
                    (logior e b0)))))))))))
;; Expected: 67305985

;; Test 10: mem-ref pattern — read bytes from memory, combine with nested logior
;; Store known bytes at scratch address, then read them back
;; Note: mem-ref :u8 store untags (val >> 1), load retags (val << 1)
;; So store tagged value 2 → stores 1, load returns 2 (tagged)
(defun test-10-setup ()
  (setf (mem-ref #x05070000 :u8) 1)
  (setf (mem-ref #x05070001 :u8) 2)
  (setf (mem-ref #x05070002 :u8) 3)
  (setf (mem-ref #x05070003 :u8) 4))

(defun test-10 ()
  (test-10-setup)
  (logior (mem-ref #x05070000 :u8)
          (logior (ash (mem-ref #x05070001 :u8) 8)
                  (logior (ash (mem-ref #x05070002 :u8) 16)
                          (ash (mem-ref #x05070003 :u8) 24)))))
;; mem-ref :u8 returns TAGGED values (shifted left 1)
;; Store 1→byte 0, 2→byte 1, 3→byte 1, 4→byte 2
;; Read back: 0→tagged=0, 1→tagged=2, 1→tagged=2, 2→tagged=4
;; Actually: store untags: 1>>1=0, 2>>1=1, 3>>1=1, 4>>1=2
;; Load retags: 0<<1=0, 1<<1=2, 1<<1=2, 2<<1=4
;; Result: 0 | (2<<8) | (2<<16) | (4<<24) = 0+512+131072+67108864 = 67240448
;; Wait - fixnum shift is 1, so tagged 1 = raw 0, tagged 2 = raw 1...
;; Let's just use even values to avoid confusion
;; Expected: computed at runtime

;; Test 11: Same mem-ref pattern with flat let bindings
(defun test-11 ()
  (test-10-setup)
  (let ((b0 (mem-ref #x05070000 :u8)))
    (let ((b1 (mem-ref #x05070001 :u8)))
      (let ((b2 (mem-ref #x05070002 :u8)))
        (let ((b3 (mem-ref #x05070003 :u8)))
          (let ((a (ash b3 24)))
            (let ((b (ash b2 16)))
              (let ((c (logior a b)))
                (let ((d (ash b1 8)))
                  (let ((e (logior c d)))
                    (logior e b0)))))))))))
;; Expected: same as test-10 (both should match)

;; Test 12: Nested logior with function call operands, only 2 levels deep
(defun test-12 ()
  (logior (ident 1) (ash (ident 2) 8)))
;; Expected: 513

;; Test 13: logior result passed to another function call
(defun test-13 ()
  (ident (logior (ident 1) (logior (ash (ident 2) 8) (ash (ident 3) 16)))))
;; Expected: 197121

;; ============================================================
;; BUG 2: Too many sequential forms (>25)
;; ============================================================

;; Test 5: 30 sequential additions via setq
(defun test-5 ()
  (let ((x 0))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    (setq x (+ x 1))
    x))
;; Expected: 30

;; ============================================================
;; BUG 3: Nested logand + logior (mixed)
;; ============================================================

;; Test 6: logand inside logior — extract byte then combine
(defun test-6 ()
  (let ((val 305419896))
    (let ((b0 (logand val 255)))
      (let ((b1 (logand (ash val -8) 255)))
        (logior b0 (ash b1 8))))))
;; Expected: 305419896 & 0xFF = 0x78 = 120, (305419896 >> 8) & 0xFF = 0x56 = 86
;;           120 | (86 << 8) = 120 | 22016 = 22136

;; Test 7: Deeply nested logior with logand mask
(defun test-7 ()
  (let ((val 305419896))
    (logior (logand val 255)
            (logior (ash (logand (ash val -8) 255) 8)
                    (ash (logand (ash val -16) 255) 16)))))
;; Expected: 0x78 | (0x56 << 8) | (0x34 << 16) = 120 + 22016 + 3407872 = 3430008
;; = 0x345678

;; ============================================================
;; BUG 4: Function arguments clobbered by function calls
;; Args live in registers and are never spilled to stack frame.
;; After calling any function, all arg values are garbage.
;; ============================================================

;; Test 14: test-10 and test-11 should return the same value
;; This proves nested logior with mem-ref matches flat version
(defun test-14 ()
  (let ((a (test-10)))
    (let ((b (test-11)))
      (if (eq a b) 1 0))))
;; Expected: 1 (match)

;; Helper that returns its arg (forces real function call)
(defun add-ten (x) (+ x 10))

;; Test 15: Use arg AFTER a function call (the bug)
;; Without fix: arg1 is clobbered by add-ten call
(defun test-15 (arg1 arg2)
  (let ((result (add-ten arg2)))
    (+ arg1 result)))
;; Called as (test-15 100 5) → should be 100 + 15 = 115

;; Test 16: Use BOTH args after a function call
(defun test-16 (a b)
  (let ((dummy (add-ten 0)))
    (+ a b)))
;; Called as (test-16 30 70) → should be 100
;; dummy=10 is unused, but the call clobbers arg regs

;; Test 17: Multiple function calls, use first arg throughout
(defun test-17 (x)
  (let ((a (add-ten x)))
    (let ((b (add-ten x)))
      (+ a b))))
;; Called as (test-17 5) → should be 15 + 15 = 30
;; Second add-ten call may clobber x if it's still in a register

;; Test 18: Let-bind workaround should always work
(defun test-18 (arg1 arg2)
  (let ((a arg1))
    (let ((b arg2))
      (let ((result (add-ten b)))
        (+ a result)))))
;; Called as (test-18 100 5) → should be 115 (same as test-15)

;; Test 21: Two function calls, THEN use arg
;; The real failing pattern: multiple calls before arg reuse
(defun test-21 (x y)
  (add-ten x)            ;; call 1 — clobbers regs
  (add-ten y)            ;; call 2 — clobbers regs again
  (+ x y))               ;; x and y should still be 100 and 50
;; Called as (test-21 100 50) → should be 150

;; Test 22: Three function calls, then use arg
(defun test-22 (x)
  (add-ten 1)
  (add-ten 2)
  (add-ten 3)
  x)                     ;; x should still be 42
;; Called as (test-22 42) → should be 42

;; Test 23: Use arg in the CALL itself (should always work —
;; arg is consumed before clobber)
(defun double-add (a b) (+ a b))
(defun test-23 (x y)
  (let ((r1 (double-add x y)))  ;; x,y consumed in call args
    (let ((r2 (double-add x y)))  ;; x,y used again — clobbered by first call?
      (+ r1 r2))))
;; Called as (test-23 10 20) → should be 30+30=60

;; Test 24: Arg used after nested let with function call (SSH pattern)
(defun test-24 (ssh payload)
  (let ((data-len (add-ten payload)))   ;; call clobbers ssh
    (let ((result (add-ten data-len)))  ;; another call
      (+ ssh result))))                 ;; ssh should still be 100
;; Called as (test-24 100 5) → should be 100 + 25 = 125

;; Test 25: Same as test-24 but with let-bind workaround
(defun test-25 (ssh payload)
  (let ((s ssh))
    (let ((p payload))
      (let ((data-len (add-ten p)))
        (let ((result (add-ten data-len)))
          (+ s result))))))
;; Called as (test-25 100 5) → should be 125

;; Test 26: Complex SSH-like pattern — multiple calls using arg across long body
(defun make-val (x) (+ x 100))
(defun use-val (base offset) (+ base offset))
(defun test-26 (ssh payload)
  (let ((data-len (make-val payload)))  ;; call clobbers regs
    (let ((result1 (use-val ssh 1)))    ;; ssh reused — safe?
      (let ((result2 (use-val ssh 2)))  ;; ssh reused again
        (let ((result3 (make-val data-len)))
          (+ result1 (+ result2 result3)))))))
;; Called as (test-26 10 5) → data-len=105, r1=11, r2=12, r3=205 → 11+12+205=228

;; ============================================================
;; BUG 5: 25+ sequential forms in function body
;; ============================================================

;; Test 19: 30 sequential print-result-like calls (forms, not setq)
;; Different from test-5 which uses setq — this tests progn-like bodies
(defun add-one (x) (+ x 1))
(defun test-19 ()
  (let ((x 0))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    (setq x (add-one x))
    x))
;; Expected: 30 (same as test-5 but with function calls)

;; ============================================================
;; BUG 7: 18+ nested lets
;; ============================================================

;; Test 27: 20 nested lets — use accumulator pattern (avoids nested + issue)
(defun sum-10a ()
  (let ((a 1))
    (let ((b 2))
      (let ((c 3))
        (let ((d 4))
          (let ((e 5))
            (let ((f 6))
              (let ((g 7))
                (let ((h 8))
                  (let ((i 9))
                    (let ((j 10))
                      (let ((ab (+ a b)))
                        (let ((abc (+ ab c)))
                          (let ((abcd (+ abc d)))
                            (let ((abcde (+ abcd e)))
                              (let ((r1 (+ abcde f)))
                                (let ((r2 (+ r1 g)))
                                  (let ((r3 (+ r2 h)))
                                    (let ((r4 (+ r3 i)))
                                      (+ r4 j))))))))))))))))))))
;; Expected: 1+2+...+10 = 55 (18 nested lets)

(defun sum-10b ()
  (let ((k 11))
    (let ((l 12))
      (let ((m 13))
        (let ((n 14))
          (let ((o 15))
            (let ((p 16))
              (let ((q 17))
                (let ((r 18))
                  (let ((s 19))
                    (let ((t2 20))
                      (let ((kl (+ k l)))
                        (let ((klm (+ kl m)))
                          (let ((klmn (+ klm n)))
                            (let ((r1 (+ klmn o)))
                              (let ((r2 (+ r1 p)))
                                (let ((r3 (+ r2 q)))
                                  (let ((r4 (+ r3 r)))
                                    (let ((r5 (+ r4 s)))
                                      (+ r5 t2))))))))))))))))))))
;; Expected: 11+12+...+20 = 155 (18 nested lets)

(defun test-27 ()
  (+ (sum-10a) (sum-10b)))
;; Expected: 55 + 155 = 210

;; Test 28: 20 nested lets with function calls
(defun test-28 ()
  (let ((a (ident 1)))
    (let ((b (ident 2)))
      (let ((c (ident 3)))
        (let ((d (ident 4)))
          (let ((e (ident 5)))
            (let ((f (ident 6)))
              (let ((g (ident 7)))
                (let ((h (ident 8)))
                  (let ((i (ident 9)))
                    (let ((j (ident 10)))
                      (let ((ab (+ a b)))
                        (let ((abc (+ ab c)))
                          (let ((abcd (+ abc d)))
                            (let ((abcde (+ abcd e)))
                              (let ((r1 (+ abcde f)))
                                (let ((r2 (+ r1 g)))
                                  (let ((r3 (+ r2 h)))
                                    (let ((r4 (+ r3 i)))
                                      (+ r4 j))))))))))))))))))))
;; Expected: 55 (18 nested lets with function calls in init)

;; ============================================================
;; BUG 8: 3-arg + is broken
;; ============================================================

;; Test 29: 3-arg + (documented as broken)
(defun test-29 ()
  (+ 10 20 30))
;; Expected: 60

;; Test 30: 3-arg + with variables
(defun test-30 ()
  (let ((a 10))
    (let ((b 20))
      (let ((c 30))
        (+ a b c)))))
;; Expected: 60

;; ============================================================
;; BUG 9: Variable-index ASET clobber
;; ============================================================

;; Test 31: Heap allocation sanity check
;; cons uses CONS opcode which allocates differently from ALLOC-OBJ
(defun test-31 ()
  (let ((c (cons 42 99)))
    (+ (car c) (cdr c))))
;; Expected: 42 + 99 = 141

;; Test 32: Variable-index aset then constant-index aref
(defun test-32 ()
  (let ((arr (make-array 3)))
    (let ((i 0))
      (aset arr i 42)
      (aref arr 0))))
;; Expected: 42

;; Test 33: Variable-index aset then variable-index aref
(defun test-33 ()
  (let ((arr (make-array 3)))
    (let ((i 0))
      (aset arr i 99)
      (aref arr i))))
;; Expected: 99

;; Test 34: Variable-index aset via function call
(defun test-31-helper (arr n val)
  (aset arr n val))
(defun test-34 ()
  (let ((arr (make-array 5)))
    (test-31-helper arr 0 10)
    (test-31-helper arr 1 20)
    (test-31-helper arr 2 30)
    (+ (aref arr 0) (+ (aref arr 1) (aref arr 2)))))
;; Expected: 10+20+30 = 60

;; ============================================================
;; BUG 6: Nested logxor (now fixed by flatten)
;; ============================================================

;; Test 20: Triple nested logxor
(defun test-20 ()
  (let ((a 255))
    (let ((b 65280))
      (let ((c 16711680))
        (logxor a (logxor b c))))))
;; Expected: 255 ^ 65280 ^ 16711680 = 0xFF ^ 0xFF00 ^ 0xFF0000 = 0xFFFFFF = 16777215

;; ============================================================
;; Test runner
;; ============================================================

(defun kernel-main ()
  (print-result 1 (test-1))
  (print-result 2 (test-2))
  (print-result 3 (test-3))
  (print-result 4 (test-4))
  (print-result 5 (test-5))
  (print-result 6 (test-6))
  (print-result 7 (test-7))
  (print-result 8 (test-8))
  (print-result 9 (test-9))
  (print-result 10 (test-10))
  (print-result 11 (test-11))
  (print-result 12 (test-12))
  (print-result 13 (test-13))
  (print-result 14 (test-14))
  (print-result 15 (test-15 100 5))
  (print-result 16 (test-16 30 70))
  (print-result 17 (test-17 5))
  (print-result 18 (test-18 100 5))
  (print-result 19 (test-19))
  (print-result 20 (test-20))
  (print-result 21 (test-21 100 50))
  (print-result 22 (test-22 42))
  (print-result 23 (test-23 10 20))
  (print-result 24 (test-24 100 5))
  (print-result 25 (test-25 100 5))
  (print-result 26 (test-26 10 5))
  (print-result 27 (test-27))
  (print-result 28 (test-28))
  (print-result 29 (test-29))
  (print-result 30 (test-30))
  (print-result 31 (test-31))
  (print-result 32 (test-32))
  (print-result 33 (test-33))
  (print-result 34 (test-34)))
")

;;; ============================================================
;;; Expected results
;;; ============================================================

(defvar *expected-results*
  '((1 . 513)
    (2 . 197121)
    (3 . 67305985)
    (4 . 67305985)
    (5 . 30)
    (6 . 22136)
    (7 . 3430008)
    (8 . 67305985)
    (9 . 67305985)
    (10 . 0)       ;; mem-ref stores 1>>1=0 to byte 0, reads back 0<<1=0
    (11 . 0)       ;; same — both must match
    (12 . 513)
    (13 . 197121)
    (14 . 1)
    (15 . 115)     ;; arg after call: 100 + (5+10) = 115
    (16 . 100)     ;; both args after call: 30 + 70
    (17 . 30)      ;; arg reused across calls: (5+10) + (5+10)
    (18 . 115)     ;; let-bind workaround: same as test-15
    (19 . 30)      ;; 30 sequential forms with function calls
    (20 . 16777215) ;; nested logxor: 0xFFFFFF
    (21 . 150)     ;; two calls then use both args
    (22 . 42)      ;; three calls then use arg
    (23 . 60)      ;; arg used in call itself, then again
    (24 . 125)     ;; arg after nested let with calls (SSH pattern)
    (25 . 125)     ;; same with let-bind workaround
    (26 . 228)     ;; SSH-like pattern: arg reused across many calls
    (27 . 210)     ;; 20 nested lets with constants
    (28 . 55)      ;; 18 nested lets with function calls
    (29 . 60)      ;; 3-arg + with constants
    (30 . 60)      ;; 3-arg + with variables
    (31 . 141)     ;; cons + car + cdr sanity check
    (32 . 42)      ;; variable-index aset, constant-index aref
    (33 . 99)      ;; variable-index aset + aref
    (34 . 60)))    ;; variable-index aset via function

;;; ============================================================
;;; Build + Run + Check
;;; ============================================================

;;; Skip mem-ref tests (10, 11, 14) on architectures where scratch
;;; address 0x05070000 may not be mapped
(defvar *mem-ref-tests* '(10 11 14))

(defun run-qemu-and-check (arch-name qemu-cmd bin-path expected skip-tests)
  "Run QEMU, parse output, check against expected results.
   Returns (pass . fail) counts."
  (format t "Running ~A in QEMU...~%" arch-name)
  (let* ((output (with-output-to-string (s)
                   (sb-ext:run-program "/usr/bin/timeout"
                     (cons "5" qemu-cmd)
                     :output s :error nil)))
         (lines (remove-if (lambda (l) (= (length l) 0))
                  (mapcar (lambda (l) (string-trim '(#\Return #\Newline) l))
                          (loop for start = 0 then (1+ end)
                                for end = (position #\Newline output :start start)
                                collect (subseq output start (or end (length output)))
                                while end))))
         (pass 0)
         (fail 0))
    (format t "~%=== ~A Test Results ===~%" arch-name)
    (dolist (exp expected)
      (let* ((n (car exp))
             (want (cdr exp)))
        (if (member n skip-tests)
            (format t "  TEST-~D: SKIP (~A)~%" n arch-name)
            (let* ((tag (format nil "TEST-~D:" n))
                   (got-line (find-if (lambda (l) (search tag l)) lines)))
              (if got-line
                  (let* ((val-str (subseq got-line (+ (search tag got-line) (length tag))))
                         (got (parse-integer val-str :junk-allowed t)))
                    (if (eql got want)
                        (progn (format t "  TEST-~D: PASS (~D)~%" n got) (incf pass))
                        (progn (format t "  TEST-~D: FAIL (got ~A, want ~D)~%" n val-str want) (incf fail))))
                  (progn (format t "  TEST-~D: MISSING (no output)~%" n) (incf fail)))))))
    (format t "~%~D/~D passed~%" pass (+ pass fail))
    (when (> fail 0)
      (format t "~%Raw QEMU output:~%~A~%" output))
    (cons pass fail)))

;;; Determine which architectures to test
;;; Usage: sbcl --script tests/test-compiler-bugs.lisp [arch ...]
;;; Default: x64 only. Options: x64, i386, aarch64
(defvar *test-archs*
  (let ((args (cdr sb-ext:*posix-argv*)))
    (if args
        (mapcar (lambda (a) (intern (string-upcase a) :keyword)) args)
        '(:x64))))

(defvar *total-pass* 0)
(defvar *total-fail* 0)

;;; Helper to call install-*-translator by name
;;; Some translators define their own package (x64, i386), others use :modus.mvm
(defun call-install-translator (pkg-name fn-name)
  (let ((pkg (or (find-package pkg-name) (find-package :modus.mvm))))
    (when pkg
      (let ((sym (find-symbol fn-name pkg)))
        (when sym (funcall sym))))))

;;; --- x86-64 ---
(when (member :x64 *test-archs*)
  (call-install-translator :modus.mvm.x64 "INSTALL-X64-TRANSLATOR")
  (format t "~%Building x64 test kernel...~%")
  (let ((image (build-image :target :x86-64 :source-text *test-source*)))
    (write-kernel-image image "/tmp/modus-test-bugs-x64.bin")
    (format t "Built ~D bytes native code.~%" (length (kernel-image-native-code image))))
  (let ((result (run-qemu-and-check "x86-64"
                  '("qemu-system-x86_64" "-m" "512" "-nographic" "-no-reboot"
                    "-kernel" "/tmp/modus-test-bugs-x64.bin")
                  "/tmp/modus-test-bugs-x64.bin"
                  *expected-results*
                  nil)))
    (incf *total-pass* (car result))
    (incf *total-fail* (cdr result))))

;;; --- i386 ---
(when (member :i386 *test-archs*)
  (call-install-translator :modus.mvm.i386 "INSTALL-I386-TRANSLATOR")
  (format t "~%Building i386 test kernel...~%")
  (let ((image (build-image :target :i386 :source-text *test-source*)))
    (write-kernel-image image "/tmp/modus-test-bugs-i386.bin")
    (format t "Built ~D bytes native code.~%" (length (kernel-image-native-code image))))
  (let ((result (run-qemu-and-check "i386"
                  '("qemu-system-i386" "-m" "256" "-nographic" "-no-reboot"
                    "-kernel" "/tmp/modus-test-bugs-i386.bin")
                  "/tmp/modus-test-bugs-i386.bin"
                  *expected-results*
                  *mem-ref-tests*)))
    (incf *total-pass* (car result))
    (incf *total-fail* (cdr result))))

;;; --- AArch64 ---
(when (member :aarch64 *test-archs*)
  (call-install-translator :modus.mvm.aarch64 "INSTALL-AARCH64-TRANSLATOR")
  (format t "~%Building AArch64 test kernel...~%")
  (let ((image (build-image :target :aarch64 :source-text *test-source*)))
    (write-kernel-image image "/tmp/modus-test-bugs-aarch64.bin")
    (format t "Built ~D bytes native code.~%" (length (kernel-image-native-code image))))
  (let ((result (run-qemu-and-check "AArch64"
                  '("qemu-system-aarch64" "-machine" "virt" "-cpu" "cortex-a57"
                    "-m" "512" "-nographic" "-semihosting"
                    "-kernel" "/tmp/modus-test-bugs-aarch64.bin")
                  "/tmp/modus-test-bugs-aarch64.bin"
                  *expected-results*
                  *mem-ref-tests*)))
    (incf *total-pass* (car result))
    (incf *total-fail* (cdr result))))

;;; --- Summary ---
(when (> (length *test-archs*) 1)
  (format t "~%=== TOTAL: ~D/~D passed across ~{~A~^, ~} ===~%"
          *total-pass* (+ *total-pass* *total-fail*)
          (mapcar #'symbol-name *test-archs*)))

(sb-ext:exit :code (if (= *total-fail* 0) 0 1))
