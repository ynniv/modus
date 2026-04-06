;;;; build-aarch64-repl.lisp - Build AArch64 REPL kernel for QEMU virt
;;;;
;;;; Usage: sbcl --script mvm/build-aarch64-repl.lisp
;;;;
;;;; Produces /tmp/modus-aarch64.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus-aarch64.bin -nographic -semihosting

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)

;; Install the AArch64 translator
(install-aarch64-translator)

(format t "Building AArch64 REPL image (virt)...~%")
(let ((image (build-image :target :aarch64 :source-text *repl-source*)))
  (write-kernel-image image "/tmp/modus-aarch64.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel /tmp/modus-aarch64.bin -nographic -semihosting~%"))
