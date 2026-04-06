;;;; build-x64-repl.lisp - Build x86-64 REPL kernel for QEMU
;;;;
;;;; Usage: sbcl --script mvm/build-x64-repl.lisp
;;;;
;;;; Produces /tmp/modus-x64.bin — boot with:
;;;;   qemu-system-x86_64 -kernel /tmp/modus-x64.bin -m 256 -nographic

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)

(modus.mvm.x64:install-x64-translator)

(format t "Building x86-64 REPL image...~%")
(let ((image (build-image :target :x86-64 :source-text *repl-source*)))
  (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
  (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
  (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
  (write-kernel-image image "/tmp/modus-x64.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-x86_64 -kernel /tmp/modus-x64.bin -m 256 -nographic~%"))
