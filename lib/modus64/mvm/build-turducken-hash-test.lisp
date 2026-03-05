;;;; build-turducken-hash-test.lisp - Test hash tables on bare-metal AArch64
;;;;
;;;; Usage: cd lib/modus64 && sbcl --script mvm/build-turducken-hash-test.lisp
;;;;
;;;; Produces /tmp/modus64-turducken-ht.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus64-turducken-ht.bin -nographic
;;;;
;;;; Expected output:
;;;;   42
;;;;   99
;;;;   nil
;;;;   100
;;;;   nil
;;;;   PASS
;;;;

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
;;; Read prelude source
;;; ============================================================

(format t "Reading prelude source...~%")

(defun read-file-as-string (path)
  "Read file contents as a string, trimming to actual length."
  (with-open-file (s path :direction :input)
    (let* ((len (file-length s))
           (buf (make-array len :element-type 'character))
           (actual (read-sequence buf s)))
      (subseq buf 0 actual))))

(defvar *prelude-source*
  (read-file-as-string (merge-pathnames "mvm/prelude.lisp" *modus-base*)))

;;; ============================================================
;;; Hash table test source
;;; ============================================================

(defvar *test-source* "
(defun kernel-main ()
  (let ((ht (make-hash-table)))
    ;; Put two keys
    (puthash 1 ht 42)
    (puthash 2 ht 99)
    ;; Get key 1 => 42
    (print-dec (gethash 1 ht))
    (write-char-serial 10)
    ;; Get key 2 => 99
    (print-dec (gethash 2 ht))
    (write-char-serial 10)
    ;; Get missing key 3 => nil
    (let ((v (gethash 3 ht)))
      (if (null v)
          (progn (write-char-serial 110) (write-char-serial 105) (write-char-serial 108))
          (print-dec v))
      (write-char-serial 10))
    ;; Update key 1 => 100
    (puthash 1 ht 100)
    (print-dec (gethash 1 ht))
    (write-char-serial 10)
    ;; Remove key 2
    (remhash 2 ht)
    (let ((v2 (gethash 2 ht)))
      (if (null v2)
          (progn (write-char-serial 110) (write-char-serial 105) (write-char-serial 108))
          (print-dec v2))
      (write-char-serial 10)))
  ;; PASS
  (write-char-serial 80)
  (write-char-serial 65)
  (write-char-serial 83)
  (write-char-serial 83)
  (write-char-serial 10)
  (loop (hlt)))
")

;;; ============================================================
;;; Build turducken hash table test image
;;; ============================================================

(in-package :modus64.mvm)

;; Install the AArch64 translator
(install-aarch64-translator)

(format t "Building turducken hash table test...~%")

;; kernel-main must be FIRST in source — boot code falls through to first function.
;; Prelude follows (MVM compiler resolves forward references in two-pass approach).
(let* ((full-source (concatenate 'string
                      cl-user::*test-source*
                      cl-user::*prelude-source*))
       (image (build-image :target :turducken :source-text full-source)))
  (write-kernel-image image "/tmp/modus64-turducken-ht.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel /tmp/modus64-turducken-ht.bin -nographic~%"))
