;;;; build-uefi-repl.lisp - Build UEFI x86-64 REPL kernel
;;;;
;;;; Usage: sbcl --script mvm/build-uefi-repl.lisp
;;;;
;;;; Produces /tmp/modus-uefi.efi — a PE32+ EFI application.
;;;; Boot with: ./scripts/run-uefi-repl.sh
;;;;
;;;; Includes GOP framebuffer output and PS/2 keyboard input
;;;; for real hardware (ThinkPad T420). Serial I/O always active.

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(defun read-file-text (path)
  "Read entire file as a string."
  (with-open-file (s path :direction :input)
    (let ((text (make-string (file-length s))))
      (let ((n (read-sequence text s)))
        (subseq text 0 n)))))

(defvar *console-source*
  (read-file-text (merge-pathnames "net/uefi-console.lisp" *modus-base*)))

(in-package :modus.mvm)

(modus.mvm.x64:install-x64-translator)

;; Combine: REPL source first, then console overrides.
;; Last-defun-wins: console's write-char-output and read-char-input
;; override the REPL's defaults.
(let ((combined-source (concatenate 'string
                                    *repl-source*
                                    cl-user::*console-source*)))
  (format t "Building UEFI x86-64 REPL image...~%")
  (format t "Combined source: ~D chars~%" (length combined-source))
  (let ((image (build-image :target :uefi-x64 :source-text combined-source)))
    (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
    (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
    (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
    (format t "Image size: ~D~%" (length (kernel-image-image-bytes image)))
    (write-kernel-image image "/tmp/modus-uefi.efi")
    (format t "Done. Boot with:~%")
    (format t "  ./scripts/run-uefi-repl.sh~%")))
