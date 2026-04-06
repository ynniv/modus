;;;; build-rpi-repl.lisp - Build a Raspberry Pi REPL kernel image
;;;;
;;;; Usage: sbcl --script mvm/build-rpi-repl.lisp
;;;;
;;;; Produces /tmp/kernel8.img — boot with:
;;;;   qemu-system-aarch64 -machine raspi3b -kernel /tmp/kernel8.img \
;;;;     -display none -serial stdio

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)

;; Install the AArch64 translator (required for :rpi target)
(install-aarch64-translator)

(format t "Building RPi REPL image...~%")
(let ((image (build-image :target :rpi :source-text *repl-source*)))
  (write-kernel-image image "/tmp/kernel8.img")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine raspi3b -kernel /tmp/kernel8.img -display none -serial stdio~%"))
