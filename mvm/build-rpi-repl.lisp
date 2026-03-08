;;;; build-rpi-repl.lisp - Build a Raspberry Pi REPL kernel image
;;;;
;;;; Usage: sbcl --script mvm/build-rpi-repl.lisp
;;;;
;;;; Produces /tmp/kernel8.img — boot with:
;;;;   qemu-system-aarch64 -machine raspi3b -kernel /tmp/kernel8.img \
;;;;     -display none -serial stdio

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
;;; Build RPi REPL image
;;; ============================================================

(in-package :modus64.mvm)

;; Install the AArch64 translator (required for :rpi target)
(install-aarch64-translator)

(format t "Building RPi REPL image...~%")
(let ((image (build-image :target :rpi :source-text *repl-source*)))
  (write-kernel-image image "/tmp/kernel8.img")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine raspi3b -kernel /tmp/kernel8.img -display none -serial stdio~%"))
