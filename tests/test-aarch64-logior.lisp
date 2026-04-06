;;;; test-aarch64-logior.lisp — Reproduce nested logior clobber on AArch64
;;;;
;;;; Usage: sbcl --script tests/test-aarch64-logior.lisp
;;;;
;;;; Tests (logior a (ash b 8) (ash c 16) (ash d 24)) on AArch64.
;;;; The bug: "3+ levels nested logior/ash silently produces wrong values."

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)
(install-aarch64-translator)

;;; Helper: build+run a test on AArch64 QEMU, compare output
(defun run-aarch64-test (name source expected)
  (format t "~A: " name)
  (finish-output)
  (handler-case
    (let* ((full-src (concatenate 'string *repl-source* *hex-helpers* source))
           (image (build-image :target :aarch64 :source-text full-src))
           (bin (format nil "/tmp/modus-test-~A.bin" name))
           (out (format nil "/tmp/modus-test-~A.out" name)))
      (write-kernel-image image bin)
      (sb-ext:run-program "/bin/bash"
        (list "-c" (format nil "timeout 5 qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 128 -kernel ~A -nographic -semihosting > ~A 2>/dev/null" bin out))
        :search t :wait t)
      (let ((output (with-open-file (f out :if-does-not-exist nil)
                      (when f (let ((s (make-string (file-length f))))
                                (read-sequence s f) s)))))
        (cond
          ((null output) (format t "FAIL (no output file)~%"))
          ((search expected output) (format t "PASS~%"))
          (t (format t "FAIL — got ~S, want ~S~%"
                     (string-trim '(#\Newline #\Return) output) expected)))))
    (error (e) (format t "ERROR: ~A~%" e))))

;;; Helpers defined inline in each test source
(defvar *hex-helpers* "
(defun phex-nib (n) (if (< n 10) (write-char-serial (+ n 48)) (write-char-serial (+ n 55))))
(defun phex (b) (phex-nib (logand (ash b -4) 15)) (phex-nib (logand b 15)))
")

;; Test 1: logior of constants — expect 0F
(run-aarch64-test "t1-const"
  "(defun kernel-main ()
     (let ((r (logior 1 2 4 8)))
       (write-char-serial 82) (write-char-serial 61)
       (phex r) (write-char-serial 10) 0))"
  "R=0F")

;; Test 2: 4-arg logior with ash from let-bound args
(run-aarch64-test "t2-ash-args"
  "(defun combine4 (b0 b1 b2 b3)
     (let ((a b0)) (let ((b b1)) (let ((c b2)) (let ((d b3))
       (logior a (ash b 8) (ash c 16) (ash d 24)))))))
   (defun kernel-main ()
     (let ((r (combine4 #xAB #xCD #xEF #x12)))
       (write-char-serial 82) (write-char-serial 61)
       (phex (logand (ash r -24) #xFF))
       (phex (logand (ash r -16) #xFF))
       (phex (logand (ash r -8) #xFF))
       (phex (logand r #xFF))
       (write-char-serial 10) 0))"
  "R=12EFCDAB")

;; Test 3: aref + logior — simulates buf-read-u32-le
(run-aarch64-test "t3-aref"
  "(defun read-le (buf off)
     (logior (aref buf off)
             (ash (aref buf (+ off 1)) 8)
             (ash (aref buf (+ off 2)) 16)
             (ash (aref buf (+ off 3)) 24)))
   (defun kernel-main ()
     (let ((buf (make-array 4)))
       (aset buf 0 #xAB) (aset buf 1 #xCD)
       (aset buf 2 #xEF) (aset buf 3 #x12)
       (let ((r (read-le buf 0)))
         (write-char-serial 82) (write-char-serial 61)
         (phex (logand (ash r -24) #xFF))
         (phex (logand (ash r -16) #xFF))
         (phex (logand (ash r -8) #xFF))
         (phex (logand r #xFF))
         (write-char-serial 10) 0)))"
  "R=12EFCDAB")

;; Test 4: flat workaround — should always pass
(run-aarch64-test "t4-flat"
  "(defun read-le-flat (buf off)
     (let ((b0 (aref buf off)))
       (let ((b1 (aref buf (+ off 1))))
         (let ((b2 (aref buf (+ off 2))))
           (let ((b3 (aref buf (+ off 3))))
             (let ((lo (logior b0 (ash b1 8))))
               (let ((hi (logior (ash b2 16) (ash b3 24))))
                 (logior lo hi))))))))
   (defun kernel-main ()
     (let ((buf (make-array 4)))
       (aset buf 0 #xAB) (aset buf 1 #xCD)
       (aset buf 2 #xEF) (aset buf 3 #x12)
       (let ((r (read-le-flat buf 0)))
         (write-char-serial 82) (write-char-serial 61)
         (phex (logand (ash r -24) #xFF))
         (phex (logand (ash r -16) #xFF))
         (phex (logand (ash r -8) #xFF))
         (phex (logand r #xFF))
         (write-char-serial 10) 0)))"
  "R=12EFCDAB")

;; Generate deep nesting tests programmatically to avoid paren errors
(defun make-deep-nest-test (n body)
  "Generate source with N nested lets, each calling (mk I), then BODY at center."
  (let ((s body))
    (loop for i from n downto 1
          do (setf s (format nil "(let ((v~D (mk ~D))) ~A)" i i s)))
    s))

;; Test 5: 20 nested lets — returns sum of first and last
(let ((src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                        (defun deep20 () ~A)~%~
                        (defun kernel-main () (let ((r (deep20)))~
                          (write-char-serial 82) (write-char-serial 61)~
                          (phex r) (write-char-serial 10) 0))"
                   (make-deep-nest-test 20 "(+ (aref v1 0) (aref v20 0))"))))
  (run-aarch64-test "t5-20-lets" src "R=15"))

;; Test 6: 20 nested lets with sequential forms at bottom
(let ((src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                        (defun deep-forms () ~A)~%~
                        (defun kernel-main () (let ((r (deep-forms)))~
                          (write-char-serial 82) (write-char-serial 61)~
                          (phex r) (write-char-serial 10) 0))"
                   (make-deep-nest-test 20
                     "(write-char-serial 65) (write-char-serial 66) (write-char-serial 67) (aref v20 0)"))))
  (run-aarch64-test "t6-deep-forms" src "ABCR=14"))

;; Test 7: 24 nested lets (matching ssh-compute-exchange-hash depth)
(let ((src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                        (defun deep24 () ~A)~%~
                        (defun kernel-main () (let ((r (deep24)))~
                          (write-char-serial 82) (write-char-serial 61)~
                          (phex r) (write-char-serial 10) 0))"
                   (make-deep-nest-test 24
                     "(write-char-serial 65) (write-char-serial 66) (+ (aref v1 0) (aref v24 0))"))))
  (run-aarch64-test "t7-24-lets" src "ABR=19"))

;; Test 8: 24 nested lets + 4 function params (matching ssh-compute-exchange-hash exactly)
(let ((src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                        (defun deep24p (p0 p1 p2 p3) (let ((a p0)) (let ((b p1)) (let ((c p2)) (let ((d p3)) ~A)))))~%~
                        (defun kernel-main () (let ((r (deep24p 10 20 30 40)))~
                          (write-char-serial 82) (write-char-serial 61)~
                          (phex r) (write-char-serial 10) 0))"
                   (make-deep-nest-test 20
                     "(write-char-serial 65) (+ a (+ b (+ (aref v1 0) (aref v20 0))))"))))
  ;; a=10 + b=20 + v1=1 + v20=20 = 51 = 0x33
  (run-aarch64-test "t8-24-lets-4params" src "AR=33"))

;; Bisect: 4 params, varying depth, use ALL 4 params in result
;; Result = a + b + v1 + vN. With a=10,b=20,v1=1,vN=N: 10+20+1+N = 31+N
(dolist (n '(16 18 20 22 24))
  (let* ((body (format nil "(+ a (+ b (+ (aref v1 0) (aref v~D 0))))" n))
         (fn-body (format nil "(let ((a p0)) (let ((b p1)) (let ((c p2)) (let ((d p3)) ~A))))"
                          (make-deep-nest-test n body)))
         (expected (+ 10 20 1 n))
         (src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                           (defun test-fn (p0 p1 p2 p3) ~A)~%~
                           (defun kernel-main () (let ((r (test-fn 10 20 30 40)))~
                             (write-char-serial 82) (write-char-serial 61)~
                             (phex r) (write-char-serial 10) 0))"
                      fn-body)))
    (run-aarch64-test (format nil "t-4p-all+~Dn" n) src
                      (format nil "R=~2,'0X" expected))))

;; Test 9: MINIMAL repro — 4 params, 20 lets, write-char-serial before return
;; The write-char-serial (TRAP) before the return expression corrupts the result
(let* ((body "(write-char-serial 65) (+ a b)")
       (fn-body (format nil "(let ((a p0)) (let ((b p1)) ~A))"
                        (make-deep-nest-test 20 body)))
       (src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                         (defun test-fn (p0 p1 p2 p3) ~A)~%~
                         (defun kernel-main () (let ((r (test-fn 10 20 30 40)))~
                           (write-char-serial 82) (write-char-serial 61)~
                           (phex r) (write-char-serial 10) 0))"
                    fn-body)))
  (run-aarch64-test "t9-trap-clobber" src "AR=1E"))

;; Test 10: Same but WITHOUT write-char-serial — should pass
(let* ((body "(+ a b)")
       (fn-body (format nil "(let ((a p0)) (let ((b p1)) ~A))"
                        (make-deep-nest-test 20 body)))
       (src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                         (defun test-fn (p0 p1 p2 p3) ~A)~%~
                         (defun kernel-main () (let ((r (test-fn 10 20 30 40)))~
                           (write-char-serial 82) (write-char-serial 61)~
                           (phex r) (write-char-serial 10) 0))"
                    fn-body)))
  (run-aarch64-test "t10-no-trap" src "R=1E"))

;; Test 11: function CALL (not trap) before return — does it also clobber?
(let* ((body "(mk 99) (+ a b)")
       (fn-body (format nil "(let ((a p0)) (let ((b p1)) ~A))"
                        (make-deep-nest-test 20 body)))
       (src (format nil "(defun mk (n) (let ((a (make-array 1))) (aset a 0 n) a))~%~
                         (defun test-fn (p0 p1 p2 p3) ~A)~%~
                         (defun kernel-main () (let ((r (test-fn 10 20 30 40)))~
                           (write-char-serial 82) (write-char-serial 61)~
                           (phex r) (write-char-serial 10) 0))"
                    fn-body)))
  (run-aarch64-test "t11-call-clobber" src "R=1E"))

(format t "~%Done.~%")
