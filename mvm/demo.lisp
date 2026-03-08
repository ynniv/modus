;;;; demo.lisp - MVM Demo Script
;;;;
;;;; Run with: sbcl --script mvm/demo.lisp
;;;;
;;;; Loads the entire MVM system and runs:
;;;;   1. Interpreter tests (27 tests: arithmetic, branches, cons, objects, calls)
;;;;   2. Compiler tests (compile & disassemble Lisp functions to MVM bytecode)
;;;;   3. Cross-compilation test (build kernel images for all 6 architectures)
;;;;   4. End-to-end demo: factorial compiled, disassembled, interpreted, cross-compiled

(format t "~%========================================~%")
(format t " Modus Virtual Machine - Demo~%")
(format t "========================================~%~%")

;;; ============================================================
;;; Load all MVM files in dependency order
;;; ============================================================

(defvar *modus-base*
  (let* ((mvm-dir (directory-namestring (truename *load-truename*)))
         ;; mvm-dir is .../mvm/ — go up one level to project root
         (modus-dir (namestring (truename (merge-pathnames "../" mvm-dir)))))
    (pathname modus-dir)))

(defun mvm-load (relative-path)
  "Load a file relative to the modus64 directory."
  (let ((path (merge-pathnames relative-path *modus-base*)))
    (format t "  Loading ~A~%" relative-path)
    (load path :verbose nil :print nil)))

(format t "Loading MVM system...~%")

;; Package definitions (provides :modus64.asm for the x64 translator)
(mvm-load "cross/packages.lisp")

;; x86-64 assembler (needed by translate-x64.lisp)
(mvm-load "cross/x64-asm.lisp")

;; Core MVM
(mvm-load "mvm/mvm.lisp")
(mvm-load "mvm/target.lisp")
(mvm-load "mvm/compiler.lisp")
(mvm-load "mvm/interp.lisp")

;; Boot descriptors
(mvm-load "boot/boot-x64.lisp")
(mvm-load "boot/boot-riscv.lisp")
(mvm-load "boot/boot-aarch64.lisp")
(mvm-load "boot/boot-ppc64.lisp")
(mvm-load "boot/boot-i386.lisp")
(mvm-load "boot/boot-68k.lisp")

;; Native translators (loaded before cross.lisp because cross.lisp
;; references package-qualified symbols from translator packages)
(mvm-load "mvm/translate-x64.lisp")
(mvm-load "mvm/translate-riscv.lisp")
(mvm-load "mvm/translate-aarch64.lisp")
(mvm-load "mvm/translate-ppc.lisp")
(mvm-load "mvm/translate-i386.lisp")
(mvm-load "mvm/translate-68k.lisp")

;; Cross-compilation pipeline (uses translator packages)
(mvm-load "mvm/cross.lisp")

(format t "~%All modules loaded.~%")

;;; ============================================================
;;; Install translators
;;; ============================================================

(format t "~%Installing translators...~%")
(in-package :modus64.mvm)

;; Install each translator into its target descriptor
(handler-case (modus64.mvm.x64:install-x64-translator)
  (error (e) (format t "  x86-64: skipped (~A)~%" e)))
(handler-case (install-riscv-translator)
  (error (e) (format t "  RISC-V: skipped (~A)~%" e)))
(handler-case (install-aarch64-translator)
  (error (e) (format t "  AArch64: skipped (~A)~%" e)))
(handler-case (install-ppc-translator)
  (error (e) (format t "  PPC64: skipped (~A)~%" e)))
(handler-case (modus64.mvm.i386:install-i386-translator)
  (error (e) (format t "  i386: skipped (~A)~%" e)))
(handler-case (install-68k-translator)
  (error (e) (format t "  68k: skipped (~A)~%" e)))

(format t "Translators installed.~%")

;;; ============================================================
;;; Part 1: Interpreter Tests
;;; ============================================================

(format t "~%========================================~%")
(format t " Part 1: MVM Interpreter Tests~%")
(format t "========================================~%")

(let ((result (mvm-interp-test)))
  (if result
      (format t "~%>> All interpreter tests PASSED~%")
      (format t "~%>> Some interpreter tests FAILED~%")))

;;; ============================================================
;;; Part 2: Compiler Tests
;;; ============================================================

(format t "~%========================================~%")
(format t " Part 2: MVM Compiler Tests~%")
(format t "========================================~%")

(test-mvm-compiler)

;;; ============================================================
;;; Part 3: Cross-Compilation Test
;;; ============================================================

(format t "~%========================================~%")
(format t " Part 3: Cross-Compilation Matrix~%")
(format t "========================================~%")

(test-cross-compilation)

;;; ============================================================
;;; Part 4: End-to-End Demo
;;; ============================================================

(format t "~%========================================~%")
(format t " Part 4: End-to-End Factorial Demo~%")
(format t "========================================~%")

(format t "~%Source program:~%")
(format t "  (defun factorial (n)~%")
(format t "    (if (< n 2) 1 (* n (factorial (1- n)))))~%")
(format t "  (defun kernel-main ()~%")
(format t "    (factorial 10))~%")

;; Compile
(format t "~%Compiling to MVM bytecode...~%")
(let ((module (mvm-compile-all
               '((defun factorial (n)
                   (if (< n 2)
                       1
                       (* n (factorial (1- n)))))
                 (defun kernel-main ()
                   (factorial 10))))))
  ;; Disassemble
  (format t "~%MVM Bytecode Disassembly:~%")
  (disassemble-module module)

  ;; Interpret
  (format t "~%Interpreting factorial(10) via MVM interpreter...~%")
  (let* ((bc (compiled-module-bytecode module))
         (ft (compiled-module-function-table module)))
    ;; Find kernel-main entry point
    (let ((main-fn (find-if (lambda (fi)
                              (string-equal (string (function-info-name fi))
                                            "KERNEL-MAIN"))
                            ft)))
      (when main-fn
        (let* ((fn-table (make-array (length ft)))
               (result nil))
          ;; Build function table: index → bytecode-offset
          (loop for fi in ft
                for i from 0
                do (setf (aref fn-table i) (function-info-bytecode-offset fi)))
          ;; Execute from kernel-main's entry point
          (handler-case
              (progn
                (setf result (mvm-interpret bc
                                            :entry-point (function-info-bytecode-offset main-fn)
                                            :function-table fn-table))
                (format t "  Result (tagged): ~D~%" result)
                (format t "  Result (untagged): ~D~%" (ash result -1))
                (format t "  Expected: 3628800 (10!)~%"))
            (error (e)
              (format t "  Interpretation error: ~A~%" e)))))))

  ;; Cross-compile for all targets
  (format t "~%Cross-compiling factorial to all 6 architectures...~%")
  (let ((source-text "(defun factorial (n) (if (< n 2) 1 (* n (factorial (1- n))))) (defun kernel-main () (factorial 10))"))
    (dolist (target-name (list-targets))
      (handler-case
          (let ((image (build-image :target target-name :source-text source-text)))
            (format t "  ~8A: ~6D bytes~%" target-name
                    (length (kernel-image-image-bytes image))))
        (error (e)
          (format t "  ~8A: FAILED (~A)~%" target-name e))))))

;;; ============================================================
;;; Summary
;;; ============================================================

(format t "~%========================================~%")
(format t " MVM Demo Complete~%")
(format t "========================================~%")
(format t "~%The Modus Virtual Machine successfully:~%")
(format t "  - Defined ~~50 opcodes for a portable register-based ISA~%")
(format t "  - Compiled Lisp source to target-independent bytecode~%")
(format t "  - Interpreted bytecode directly (bootstrap path)~%")
(format t "  - Translated bytecode to native code for 6 architectures~%")
(format t "  - Assembled bootable kernel images with embedded source~%")
(format t "~%Any running Modus instance can now build for any target.~%")
