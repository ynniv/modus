;;;; build-fixpoint-array-test.lisp - Test array operations on bare-metal AArch64
;;;;
;;;; Usage: sbcl --script mvm/build-fixpoint-array-test.lisp
;;;;
;;;; Produces /tmp/modus64-fixpoint-arr.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus64-fixpoint-arr.bin -nographic
;;;;
;;;; Expected output:
;;;;   4
;;;;   10
;;;;   20
;;;;   30
;;;;   40
;;;;   100
;;;;   4
;;;;   10
;;;;   20
;;;;   30
;;;;   40
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
;;; Array test source
;;; ============================================================

(defvar *test-source* "
(defun kernel-main ()
  ;; Test 1: Constant-size array (ALLOC-OBJ + OBJ-REF/OBJ-SET)
  (let ((arr (make-array 4)))
    ;; Store values: arr[0]=10, arr[1]=20, arr[2]=30, arr[3]=40
    (aset arr 0 10)
    (aset arr 1 20)
    (aset arr 2 30)
    (aset arr 3 40)
    ;; Print array-length
    (print-dec (array-length arr))
    (write-char-serial 10)
    ;; Read back with constant indices (OBJ-REF)
    (print-dec (aref arr 0))
    (write-char-serial 10)
    (print-dec (aref arr 1))
    (write-char-serial 10)
    (print-dec (aref arr 2))
    (write-char-serial 10)
    (print-dec (aref arr 3))
    (write-char-serial 10)
    ;; Read with variable index (AREF opcode)
    (let ((idx 0))
      (let ((sum 0))
        (loop
          (when (= idx 4) (return nil))
          (setq sum (+ sum (aref arr idx)))
          (setq idx (+ idx 1)))
        ;; sum = 10+20+30+40 = 100
        (print-dec sum)
        (write-char-serial 10))))
  ;; Test 2: Dynamic-size array (ALLOC-ARRAY)
  (let ((n 4))
    (let ((arr2 (make-array n)))
      (aset arr2 0 10)
      (aset arr2 1 20)
      (aset arr2 2 30)
      (aset arr2 3 40)
      (print-dec (array-length arr2))
      (write-char-serial 10)
      ;; Read back with variable indices
      (let ((i 0))
        (loop
          (when (= i 4) (return nil))
          (print-dec (aref arr2 i))
          (write-char-serial 10)
          (setq i (+ i 1))))))
  ;; PASS
  (write-char-serial 80)
  (write-char-serial 65)
  (write-char-serial 83)
  (write-char-serial 83)
  (write-char-serial 10)
  (loop (hlt)))
")

;;; ============================================================
;;; Build fixpoint array test image
;;; ============================================================

(in-package :modus64.mvm)

;; Install the AArch64 translator
(install-aarch64-translator)

(format t "Building fixpoint array test...~%")

(let* ((full-source (concatenate 'string
                      cl-user::*test-source*
                      cl-user::*prelude-source*))
       (image (build-image :target :fixpoint :source-text full-source)))
  (write-kernel-image image "/tmp/modus64-fixpoint-arr.bin")
  (format t "Done. Boot with:~%")
  (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel /tmp/modus64-fixpoint-arr.bin -nographic~%"))
