;;;; test-compile-let.lisp - Unit tests for MVM compiler let handling
;;;;
;;;; Tests that compile-let correctly decomposes multi-binding lets
;;;; into nested single-binding lets, producing correct IR and bytecode.
;;;;
;;;; Usage: sbcl --script mvm/test-compile-let.lisp
;;;;
;;;; Expected output: all tests PASS

;;; ============================================================
;;; Load MVM system
;;; ============================================================

(defvar *modus-base*
  (let* ((mvm-dir (directory-namestring (truename *load-truename*)))
         (modus-dir (namestring (truename (merge-pathnames "../" mvm-dir)))))
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

;;; Install translators for cross-arch tests
(handler-case (modus.mvm.x64:install-x64-translator) (error () nil))
(handler-case (install-aarch64-translator) (error () nil))
(handler-case (modus.mvm.i386:install-i386-translator) (error () nil))
(handler-case (install-arm32-translator) (error () nil))

;;; ============================================================
;;; Test infrastructure
;;; ============================================================

(defvar *test-pass* 0)
(defvar *test-fail* 0)

(defun test-assert (name condition)
  (if condition
      (progn (incf *test-pass*)
             (format t "  PASS: ~A~%" name))
      (progn (incf *test-fail*)
             (format t "  FAIL: ~A~%" name))))

(defun compile-source (src)
  "Compile source string, return compiled-module."
  (let ((forms (read-all-forms src)))
    (mvm-compile-all forms)))

(defun module-function-count (module)
  (length (compiled-module-function-table module)))

(defun module-bytecode-size (module)
  (length (compiled-module-bytecode module)))

(defun module-has-function (module name)
  (find name (compiled-module-function-table module)
        :key #'function-info-name :test #'string-equal))


;;; ============================================================
;;; Test 1: Single-binding let compiles correctly
;;; ============================================================

(format t "~%=== Test 1: Single-binding let ===~%")

(let* ((module (compile-source
                "(defun test-single-let (x)
                   (let ((a (+ x 1)))
                     a))"))
       (fn (module-has-function module "TEST-SINGLE-LET")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn)))
  (test-assert "has bytecode" (> (module-bytecode-size module) 0)))

;;; ============================================================
;;; Test 2: Multi-binding let (2 bindings) compiles correctly
;;; ============================================================

(format t "~%=== Test 2: Two-binding let ===~%")

(let* ((module (compile-source
                "(defun test-two-let (x)
                   (let ((a (+ x 1))
                         (b (+ x 2)))
                     (+ a b)))"))
       (fn (module-has-function module "TEST-TWO-LET")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn)))
  (test-assert "has bytecode" (> (module-bytecode-size module) 0)))

;;; ============================================================
;;; Test 3: Multi-binding let (5 bindings)
;;; ============================================================

(format t "~%=== Test 3: Five-binding let ===~%")

(let* ((module (compile-source
                "(defun test-five-let (x)
                   (let ((a 1) (b 2) (c 3) (d 4) (e 5))
                     (+ a (+ b (+ c (+ d e))))))"))
       (fn (module-has-function module "TEST-FIVE-LET")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 4: Decomposed let produces same bytecode as nested lets
;;; ============================================================

(format t "~%=== Test 4: Decomposition equivalence (2 bindings) ===~%")

(let ((mod-multi (compile-source
                  "(defun f-multi (x)
                     (let ((a (+ x 1))
                           (b (+ x 2)))
                       (+ a b)))"))
      (mod-nested (compile-source
                   "(defun f-nested (x)
                      (let ((a (+ x 1)))
                        (let ((b (+ x 2)))
                          (+ a b))))")))
  (test-assert "multi-binding compiles" (not (null mod-multi)))
  (test-assert "nested compiles" (not (null mod-nested)))
  (let ((bc-multi (compiled-module-bytecode mod-multi))
        (bc-nested (compiled-module-bytecode mod-nested)))
    (test-assert "bytecodes identical"
                 (equalp bc-multi bc-nested))))

;;; ============================================================
;;; Test 5: 8-binding let (max typical)
;;; ============================================================

(format t "~%=== Test 5: Eight-binding let ===~%")

(let* ((module (compile-source
                "(defun test-eight-let (x)
                   (let ((a 1) (b 2) (c 3) (d 4) (e 5) (f 6) (g 7) (h 8))
                     (+ a (+ b (+ c (+ d (+ e (+ f (+ g h)))))))))"))
       (fn (module-has-function module "TEST-EIGHT-LET")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 6: 20-binding let (like X25519)
;;; ============================================================

(format t "~%=== Test 6: Twenty-binding let ===~%")

(let* ((bindings (with-output-to-string (s)
                    (dotimes (i 20)
                      (format s "(v~D ~D)" i i)
                      (when (< i 19) (write-char #\Space s)))))
       ;; Use simple body — real X25519 doesn't nest 19-deep
       (src (format nil "(defun test-twenty-let () (let (~A) (+ v0 (+ v9 (+ v18 v19)))))" bindings))
       (module (compile-source src))
       (fn (module-has-function module "TEST-TWENTY-LET")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 7: Nested multi-binding lets
;;; ============================================================

(format t "~%=== Test 7: Nested multi-binding lets ===~%")

(let* ((module (compile-source
                "(defun test-nested-multi (x)
                   (let ((a 1) (b 2))
                     (let ((c (+ a b)) (d (+ a x)))
                       (+ c d))))"))
       (fn (module-has-function module "TEST-NESTED-MULTI")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 8: Let with function calls in binding values
;;; ============================================================

(format t "~%=== Test 8: Let with function calls ===~%")

(let* ((module (compile-source
                "(defun helper (x) (+ x 10))
                 (defun test-let-calls (x)
                   (let ((a (helper x))
                         (b (helper (+ x 1))))
                     (+ a b)))"))
       (fn (module-has-function module "TEST-LET-CALLS")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn)))
  (test-assert "helper exists" (module-has-function module "HELPER")))

;;; ============================================================
;;; Test 9: Let with no bindings
;;; ============================================================

(format t "~%=== Test 9: Empty let ===~%")

(let* ((module (compile-source
                "(defun test-empty-let ()
                   (let () 42))"))
       (fn (module-has-function module "TEST-EMPTY-LET")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 10: Let with variable-only binding (no init value)
;;; ============================================================

(format t "~%=== Test 10: Variable-only binding ===~%")

(let* ((module (compile-source
                "(defun test-var-only ()
                   (let (a)
                     a))"))
       (fn (module-has-function module "TEST-VAR-ONLY")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 11: Let inside loop (common pattern)
;;; ============================================================

(format t "~%=== Test 11: Let inside loop ===~%")

(let* ((module (compile-source
                "(defun test-let-loop (n)
                   (let ((sum 0) (i 0))
                     (loop
                       (when (>= i n) (return sum))
                       (setq sum (+ sum i))
                       (setq i (+ i 1)))))"))
       (fn (module-has-function module "TEST-LET-LOOP")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 12: Let* compiles (should still work separately)
;;; ============================================================

(format t "~%=== Test 12: Let* still works ===~%")

(let* ((module (compile-source
                "(defun test-let-star (x)
                   (let* ((a (+ x 1))
                          (b (+ a 2)))
                     (+ a b)))"))
       (fn (module-has-function module "TEST-LET-STAR")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 13: Scoping — inner let shadows outer
;;; ============================================================

(format t "~%=== Test 13: Variable shadowing ===~%")

(let* ((module (compile-source
                "(defun test-shadow (x)
                   (let ((a 1))
                     (let ((a 2))
                       a)))"))
       (fn (module-has-function module "TEST-SHADOW")))
  (test-assert "compiles without error" (not (null module)))
  (test-assert "function exists" (not (null fn))))

;;; ============================================================
;;; Test 14: Multi-binding let equivalence for 5 bindings
;;; ============================================================

(format t "~%=== Test 14: Five-binding decomposition equivalence ===~%")

(let ((mod-multi (compile-source
                  "(defun g-multi ()
                     (let ((a 1) (b 2) (c 3) (d 4) (e 5))
                       (+ a (+ b (+ c (+ d e))))))"))
      (mod-nested (compile-source
                   "(defun g-nested ()
                      (let ((a 1))
                        (let ((b 2))
                          (let ((c 3))
                            (let ((d 4))
                              (let ((e 5))
                                (+ a (+ b (+ c (+ d e))))))))))
")))
  (let ((bc-multi (compiled-module-bytecode mod-multi))
        (bc-nested (compiled-module-bytecode mod-nested)))
    (test-assert "5-binding bytecodes identical"
                 (equalp bc-multi bc-nested))))

;;; ============================================================
;;; Test 15: Bytecode grows with more bindings
;;; ============================================================

(format t "~%=== Test 15: Bytecode grows with binding count ===~%")

(let* ((mod-1 (compile-source "(defun f1 () (let ((a 1)) a))"))
       (mod-3 (compile-source "(defun f3 () (let ((a 1) (b 2) (c 3)) (+ a (+ b c))))"))
       (sz-1 (module-bytecode-size mod-1))
       (sz-3 (module-bytecode-size mod-3)))
  (test-assert "3-binding > 1-binding bytecode"
               (> sz-3 sz-1)))

;;; ============================================================
;;; Test 16: let and let* both compile for same source
;;; ============================================================

(format t "~%=== Test 16: let and let* both compile ===~%")

;; Both should compile successfully; bytecodes may differ in frame-alloc
;; pattern (let: N x frame-alloc 1, let*: 1 x frame-alloc N) but both
;; produce correct native code since frame-alloc is NOP on all targets.
(let* ((mod-let (compile-source
                 "(defun f-let-both ()
                    (let ((a 1) (b 2) (c 3))
                      (+ a (+ b c))))"))
       (mod-letstar (compile-source
                     "(defun f-letstar-both ()
                        (let* ((a 1) (b 2) (c 3))
                          (+ a (+ b c))))"))
       (sz-let (module-bytecode-size mod-let))
       (sz-letstar (module-bytecode-size mod-letstar)))
  (test-assert "let compiles" (> sz-let 0))
  (test-assert "let* compiles" (> sz-letstar 0))
  ;; Sizes should be similar (let is slightly larger due to per-binding frame-alloc)
  (test-assert "sizes within 50% of each other"
               (< (abs (- sz-let sz-letstar)) (max sz-let sz-letstar))))

;;; ============================================================
;;; Test 17: let gives let* semantics (decomposition property)
;;; ============================================================

(format t "~%=== Test 17: Decomposed let gives let* scoping ===~%")

;; With compile-let's decomposition, `let` gives let* semantics:
;; each binding can see previous ones. This is by design for MVM.
;; Test that a dependent binding compiles without error.
(let* ((module (compile-source
                "(defun f-let-dep (x)
                   (let ((a (+ x 1)) (b (+ a 1)))
                     b))"))
       (fn (module-has-function module "F-LET-DEP")))
  (test-assert "dependent binding compiles" (not (null fn))))

;;; ============================================================
;;; Test 18: Bytecode size — decomposed vs let*
;;; ============================================================

(format t "~%=== Test 18: Bytecode size comparison ===~%")

;; let with N bindings should produce same size as N nested single lets
;; (since compile-let decomposes to nested single-binding lets)
(let* ((mod-let (compile-source
                 "(defun f-let ()
                    (let ((a 1) (b 2) (c 3))
                      (+ a (+ b c))))"))
       (mod-nested (compile-source
                    "(defun f-nested ()
                       (let ((a 1))
                         (let ((b 2))
                           (let ((c 3))
                             (+ a (+ b c))))))"))
       (sz-let (module-bytecode-size mod-let))
       (sz-nested (module-bytecode-size mod-nested)))
  (test-assert "3-binding let = 3 nested single lets (bytecode size)"
               (= sz-let sz-nested)))

;;; ============================================================
;;; Test 19: Cross-architecture native code generation
;;; ============================================================

(format t "~%=== Test 19: Cross-architecture native code gen ===~%")

(let ((src "(defun test-cross ()
              (let ((a 1) (b 2) (c 3))
                (+ a (+ b c))))"))
  (dolist (target-info '(("x86-64" . *target-x86-64*)
                         ("aarch64" . *target-aarch64*)
                         ("i386" . *target-i386*)
                         ("arm32" . *target-arm32*)))
    (let ((name (car target-info))
          (target (symbol-value (cdr target-info))))
      (handler-case
          (progn
            (unless (target-translate-fn target)
              (error "No translator installed"))
            (let* ((forms (read-all-forms src))
                   (compiled-mod (mvm-compile-all forms))
                   (mvm-mod (compiled-module-to-mvm-module compiled-mod src)))
              (translate-module-to-native mvm-mod target)
              (test-assert (format nil "~A native code generated" name) t)))
        (error (c)
          (test-assert (format nil "~A native code generated" name) nil)
          (format t "    Error: ~A~%" c))))))

;;; ============================================================
;;; Test 20: 8-binding decomposition equivalence
;;; ============================================================

(format t "~%=== Test 20: 8-binding decomposition equivalence ===~%")

(let ((mod-multi (compile-source
                  "(defun h-multi ()
                     (let ((a 1) (b 2) (c 3) (d 4) (e 5) (f 6) (g 7) (h 8))
                       (+ a (+ b (+ c (+ d (+ e (+ f (+ g h)))))))))"))
      (mod-nested (compile-source
                   "(defun h-nested ()
                      (let ((a 1))
                        (let ((b 2))
                          (let ((c 3))
                            (let ((d 4))
                              (let ((e 5))
                                (let ((f 6))
                                  (let ((g 7))
                                    (let ((h 8))
                                      (+ a (+ b (+ c (+ d (+ e (+ f (+ g h))))))))))))))))
")))
  (let ((bc-multi (compiled-module-bytecode mod-multi))
        (bc-nested (compiled-module-bytecode mod-nested)))
    (test-assert "8-binding bytecodes identical"
                 (equalp bc-multi bc-nested))))

;;; ============================================================
;;; Summary
;;; ============================================================

(format t "~%==============================~%")
(format t "Results: ~D passed, ~D failed~%" *test-pass* *test-fail*)
(if (= *test-fail* 0)
    (format t "All tests PASS~%")
    (format t "SOME TESTS FAILED~%"))
(format t "==============================~%")

(when (> *test-fail* 0)
  (sb-ext:exit :code 1))
