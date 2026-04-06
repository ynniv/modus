;;;; build-fixpoint-test.lisp - Test fixpoint boot (AArch64 with MMU)
;;;;
;;;; Usage: sbcl --script mvm/build-fixpoint-test.lisp
;;;;
;;;; Produces /tmp/modus-fixpoint.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus-fixpoint.bin -nographic
;;;;
;;;; This builds an AArch64 REPL kernel using the fixpoint boot
;;;; preamble (with MMU page tables mapping x64-compatible VAs).

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)

;; Install the AArch64 translator
(install-aarch64-translator)

(format t "Building fixpoint test image (AArch64 with MMU)...~%")
(let ((image (build-image :target :fixpoint :source-text *repl-source*)))
  (write-kernel-image image "/tmp/modus-fixpoint.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel /tmp/modus-fixpoint.bin -nographic~%"))
