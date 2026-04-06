;;;; build-arm32-repl.lisp - Build ARM32 (ARMv7) REPL kernel for QEMU
;;;;
;;;; Usage: sbcl --script mvm/build-arm32-repl.lisp
;;;;
;;;; Produces /tmp/modus-arm32.bin — boot with:
;;;;   qemu-system-arm -M virt -cpu cortex-a15 -m 256 -kernel /tmp/modus-arm32.bin -nographic

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)

;; Install the ARMv7 translator (ARM32 A32 mode with SDIV/MOVW/MOVT)
(install-armv7-translator)

(format t "Building ARM32 (ARMv7) REPL image...~%")
(let ((image (build-image :target :armv7 :source-text *repl-source*)))
  (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
  (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
  (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
  (write-kernel-image image "/tmp/modus-arm32.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-arm -M virt -cpu cortex-a15 -m 256 -kernel /tmp/modus-arm32.bin -nographic~%"))
