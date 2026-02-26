;;;; test-images.lisp - Build MVM kernel images for all architectures
;;;;
;;;; Run with: sbcl --script lib/modus64/mvm/test-images.lisp
;;;;
;;;; Builds kernel images for all 8 target architectures and writes them
;;;; to /tmp/mvm-test/ for validation by test-arch.sh.
;;;;
;;;; Output files per architecture:
;;;;   <arch>.bin  — full assembled kernel image
;;;;   <arch>.code — native code section only (for clean objdump)

;;; ============================================================
;;; Load MVM system (same as demo.lisp)
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

(format t "Loaded.~%")

;;; ============================================================
;;; Install translators
;;; ============================================================

(in-package :modus64.mvm)

(handler-case (modus64.mvm.x64:install-x64-translator)
  (error (e) (format t "  x64: skip (~A)~%" e)))
(handler-case (install-riscv-translator)
  (error (e) (format t "  rv: skip (~A)~%" e)))
(handler-case (install-aarch64-translator)
  (error (e) (format t "  a64: skip (~A)~%" e)))
(handler-case (install-ppc-translator)
  (error (e) (format t "  ppc64: skip (~A)~%" e)))
(handler-case (install-ppc32-translator)
  (error (e) (format t "  ppc32: skip (~A)~%" e)))
(handler-case (modus64.mvm.i386:install-i386-translator)
  (error (e) (format t "  i386: skip (~A)~%" e)))
(handler-case (install-68k-translator)
  (error (e) (format t "  68k: skip (~A)~%" e)))
(handler-case (install-arm32-translator)
  (error (e) (format t "  arm32: skip (~A)~%" e)))
(handler-case (install-armv7-translator)
  (error (e) (format t "  armv7: skip (~A)~%" e)))

;;; ============================================================
;;; Build images
;;; ============================================================

(defvar *output-dir* "/tmp/mvm-test/")

(ensure-directories-exist *output-dir*)

(defvar *test-source*
  "(defun kernel-main ()
     (print-fixnum (factorial 10))
     (write-char-serial 10)
     (hlt))
   (defun factorial (n)
     (if (< n 2) 1 (* n (factorial (1- n)))))
   (defun print-fixnum (n)
     (if (< n 10)
         (write-char-serial (+ n 48))
         (progn
           (print-fixnum (truncate n 10))
           (write-char-serial (+ (mod n 10) 48)))))")

(defun write-bytes (bytes pathname)
  "Write a byte vector to a file."
  (with-open-file (out pathname :direction :output
                                :element-type '(unsigned-byte 8)
                                :if-exists :supersede)
    (write-sequence bytes out)))

(defvar *results* nil)

(format t "~%Building kernel images...~%")

;; Build for all registered targets plus board-specific variants
(dolist (target-name (append (list-targets) '(:rpi)))
  (let ((bin-path (format nil "~A~(~A~).bin" *output-dir* target-name))
        (code-path (format nil "~A~(~A~).code" *output-dir* target-name)))
    (handler-case
        (let ((image (build-image :target target-name :source-text *test-source*)))
          (let ((image-bytes (kernel-image-image-bytes image))
                (native-code (kernel-image-native-code image)))
            ;; Write full image
            (write-bytes image-bytes bin-path)
            ;; Write native code only
            (write-bytes native-code code-path)
            ;; Record result
            (push (list target-name
                        :pass
                        (length image-bytes)
                        (length native-code)
                        (if (kernel-image-boot-code image)
                            (length (kernel-image-boot-code image))
                            0))
                  *results*)
            (format t "  ~8A: ~6D bytes image, ~5D bytes native code~@[, ~D bytes boot~]~%"
                    target-name
                    (length image-bytes)
                    (length native-code)
                    (let ((bc (kernel-image-boot-code image)))
                      (when (and bc (plusp (length bc)))
                        (length bc))))))
      (error (e)
        (push (list target-name :fail 0 0 0) *results*)
        (format t "  ~8A: FAILED (~A)~%"
                target-name e)))))

;;; ============================================================
;;; Summary
;;; ============================================================

(let ((pass (count :pass *results* :key #'second))
      (fail (count :fail *results* :key #'second)))
  (format t "~%BUILD: ~D/~D images built~%" pass (+ pass fail))
  ;; Write summary for shell script to parse
  (with-open-file (out (format nil "~Asummary.txt" *output-dir*)
                       :direction :output :if-exists :supersede)
    (dolist (r (reverse *results*))
      (format out "~(~A~) ~A ~D ~D ~D~%"
              (first r) (second r) (third r) (fourth r) (fifth r)))))

(format t "Images written to ~A~%" *output-dir*)
