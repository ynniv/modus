;;;; build-fixpoint-test.lisp - Test fixpoint boot (AArch64 with MMU)
;;;;
;;;; Usage: sbcl --script mvm/build-fixpoint-test.lisp
;;;;
;;;; Produces /tmp/modus64-fixpoint.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus64-fixpoint.bin -nographic
;;;;
;;;; This builds an AArch64 REPL kernel using the fixpoint boot
;;;; preamble (with MMU page tables mapping x64-compatible VAs).

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

(format t "Loading MVM system...~%")

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

;;; ============================================================
;;; Load REPL source
;;; ============================================================

(format t "Loading REPL source...~%")
(mvm-load "mvm/repl-source.lisp")

;;; ============================================================
;;; Build fixpoint test image (AArch64 with MMU)
;;; ============================================================

(in-package :modus64.mvm)

;; Install the AArch64 translator
(install-aarch64-translator)

(format t "Building fixpoint test image (AArch64 with MMU)...~%")
(let ((image (build-image :target :fixpoint :source-text *repl-source*)))
  (write-kernel-image image "/tmp/modus64-fixpoint.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel /tmp/modus64-fixpoint.bin -nographic~%"))
