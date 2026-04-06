;;;; load-mvm.lisp — Shared MVM system loading boilerplate
;;;;
;;;; Defines *modus-base* and mvm-load, then loads the complete MVM system:
;;;; packages, assembler, ISA, compiler, interpreter, boot descriptors,
;;;; and all architecture translators.
;;;;
;;;; Usage from build scripts:
;;;;   (load "lib/load-mvm.lisp")  ; or via mvm-load after *modus-base* is set

;;; Base directory (parent of mvm/)
(defvar *modus-base*
  (let* ((this-dir (directory-namestring (truename *load-truename*)))
         (modus-dir (namestring (truename (merge-pathnames "../" this-dir)))))
    (pathname modus-dir)))

(defun mvm-load (relative-path)
  (let ((path (merge-pathnames relative-path *modus-base*)))
    (load path :verbose nil :print nil)))

(format t "Loading MVM system...~%")

;; Packages and x86-64 assembler
(mvm-load "mvm/packages.lisp")
(mvm-load "mvm/x64-asm.lisp")

;; MVM core
(mvm-load "mvm/mvm.lisp")
(mvm-load "mvm/target.lisp")
(mvm-load "mvm/compiler.lisp")
(mvm-load "mvm/interp.lisp")

;; Boot descriptors (all architectures)
(mvm-load "boot/boot-x64.lisp")
(mvm-load "boot/boot-riscv.lisp")
(mvm-load "boot/boot-aarch64.lisp")
(mvm-load "boot/boot-rpi.lisp")
(mvm-load "boot/boot-ppc64.lisp")
(mvm-load "boot/boot-ppc32.lisp")
(mvm-load "boot/boot-i386.lisp")
(mvm-load "boot/boot-68k.lisp")
(mvm-load "boot/boot-arm32.lisp")
(mvm-load "boot/boot-uefi-x64.lisp")

;; Architecture translators
(mvm-load "mvm/translate-x64.lisp")
(mvm-load "mvm/translate-riscv.lisp")
(mvm-load "mvm/translate-aarch64.lisp")
(mvm-load "mvm/translate-ppc.lisp")
(mvm-load "mvm/translate-i386.lisp")
(mvm-load "mvm/translate-68k.lisp")
(mvm-load "mvm/translate-arm32.lisp")

;; Cross-compilation pipeline
(mvm-load "mvm/cross.lisp")
