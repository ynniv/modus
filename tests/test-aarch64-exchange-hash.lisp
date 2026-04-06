;;;; test-aarch64-exchange-hash.lisp — Reproduce ssh-compute-exchange-hash failure
;;;;
;;;; Usage: sbcl --script tests/test-aarch64-exchange-hash.lisp
;;;;
;;;; Progressively tests chained ssh-make-str + ssh-concat2 patterns
;;;; that match the SSH exchange hash computation.

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)
(install-aarch64-translator)

(defvar *hex-helpers* "
(defun phex-nib (n) (if (< n 10) (write-char-serial (+ n 48)) (write-char-serial (+ n 55))))
(defun phex (b) (phex-nib (logand (ash b -4) 15)) (phex-nib (logand b 15)))
")

;;; Architecture source needed for e1000-state-base (SHA-256 K constants)
(defvar *arch-source*
  (with-open-file (f (merge-pathnames "net/arch-aarch64.lisp" cl-user::*modus-base*))
    (let ((s (make-string (file-length f)))) (read-sequence s f) s)))

;;; Load real source files for crypto and SSH helpers
(defun read-net-file (name)
  (let ((path (merge-pathnames (format nil "net/~A" name) cl-user::*modus-base*)))
    (with-open-file (f path :direction :input)
      (let ((text (make-string (file-length f))))
        (let ((n (read-sequence text f)))
          (subseq text 0 n))))))

(defvar *ip-source* (read-net-file "ip.lisp"))
(defvar *crypto-source* (read-net-file "crypto.lisp"))
(defvar *ssh-source* (read-net-file "ssh.lisp"))

(defvar *ssh-helpers* "
(defun mk1 (v) (let ((a (make-array 1))) (aset a 0 v) a))
")

(defun run-test (name source expected)
  (format t "~A: " name)
  (finish-output)
  (handler-case
    (let* ((full-src (concatenate 'string *arch-source* *ip-source* *crypto-source* *ssh-source*
                                          *repl-source* *hex-helpers* *ssh-helpers* source))
           (image (build-image :target :aarch64 :source-text full-src))
           (bin (format nil "/tmp/modus-exh-~A.bin" name))
           (out (format nil "/tmp/modus-exh-~A.out" name)))
      (write-kernel-image image bin)
      (sb-ext:run-program "/bin/bash"
        (list "-c" (format nil "timeout 5 qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel ~A -nographic -semihosting > ~A 2>/dev/null" bin out))
        :search t :wait t)
      (let ((output (with-open-file (f out :if-does-not-exist nil)
                      (when f (let ((s (make-string (file-length f))))
                                (read-sequence s f) s)))))
        (cond
          ((null output) (format t "FAIL (no output)~%"))
          ((search expected output) (format t "PASS~%"))
          (t (format t "FAIL — got ~S, want ~S~%"
                     (string-trim '(#\Newline #\Return) output) expected)))))
    (simple-error (e) (format t "ERROR: ~A ~A~%" (simple-condition-format-control e)
                                                         (simple-condition-format-arguments e)))
    (error (e) (format t "ERROR: ~A~%" e))))

;;; Helper to generate concat chains programmatically
(defun make-concat-chain (n-values &key (use-make-str t) (params nil) (body-prefix ""))
  "Generate source for a function that makes N values, wraps each as SSH string
   (if use-make-str), then chains ssh-concat2 calls. Returns the concat result.
   If params is a list of (name value) pairs, those are function params let-bound first."
  (let ((lets '())
        (vals '()))
    ;; Build let bindings for each value
    (loop for i from 1 to n-values
          for vname = (format nil "v~D" i)
          for hexval = (+ #x10 i)
          do (if use-make-str
                 (push (format nil "(let ((~A (ssh-make-str (mk1 #x~2,'0X) 1)))" vname hexval) lets)
                 (push (format nil "(let ((~A (mk1 #x~2,'0X)))" vname hexval) lets))
             (push vname vals))
    (setf lets (nreverse lets))
    (setf vals (nreverse vals))
    ;; Build concat chain
    (let ((chain (format nil "~A" (first vals))))
      (loop for v in (rest vals)
            for prev = chain then result
            for result = (format nil "(let ((~A (ssh-concat2 ~A (array-length ~A) ~A (array-length ~A))))"
                                 (format nil "c~D" (position v vals :test #'equal))
                                 prev prev v v)
            do (setf chain result)
            finally (setf chain (or result chain)))
      ;; Now chain is the innermost let with the concat result
      ;; We need to close all the lets and return the final concat var
      (let ((final-var (if (> n-values 1)
                           (format nil "c~D" (1- n-values))
                           (first vals))))
        ;; Build full body
        (let ((body (format nil "~A~A ~{~A ~}~A~A~A"
                            ;; Param lets
                            (if params
                                (format nil "~{(let ((~A ~A)) ~}"
                                        (mapcan (lambda (p) (list (first p) (second p))) params))
                                "")
                            ;; Value lets
                            (format nil "~{~A ~}" lets)
                            ;; Concat lets (need to count them)
                            '()  ; handled inline
                            body-prefix
                            ;; Result expression
                            final-var
                            ;; Close parens
                            (make-string (+ (length lets)
                                           (max 0 (1- n-values))
                                           (if params (length params) 0))
                                         :initial-element #\)))))
          body)))))

;;; Actually, generating with format is error-prone. Let me just build the
;;; source strings directly using simple concatenation.

(defun gen-concat-test (n-values n-params hash-at-end)
  "Generate test source: n-params function params, n-values SSH strings, chained concat.
   If hash-at-end, SHA-256 hash the result. Returns (source . expected)."
  (let ((src (make-string-output-stream))
        (vals (loop for i from 1 to n-values collect (+ #x10 i))))
    ;; Function signature
    (if (> n-params 0)
        (progn
          (format src "(defun test-fn (~{p~D~^ ~}) "
                  (loop for i below n-params collect i))
          ;; Let-bind params
          (loop for i below n-params
                do (format src "(let ((a~D p~D)) " i i)))
        (format src "(defun test-fn () "))
    ;; Make SSH strings
    (loop for v in vals for i from 0
          do (format src "(let ((s~D (ssh-make-str (mk1 #x~2,'0X) 1))) " i v))
    ;; Concat chain
    (when (> n-values 1)
      (format src "(let ((r1 (ssh-concat2 s0 (array-length s0) s1 (array-length s1)))) ")
      (loop for i from 2 below n-values
            do (format src "(let ((r~D (ssh-concat2 r~D (array-length r~D) s~D (array-length s~D)))) "
                       i (1- i) (1- i) i i)))
    ;; Body: either hash or return concat
    (let ((final (if (> n-values 1)
                     (format nil "r~D" (1- n-values))
                     "s0")))
      (if hash-at-end
          (format src "(sha256-init) (sha256 ~A)" final)
          (format src "~A" final)))
    ;; Close all parens
    (let ((n-close (+ n-params            ; param lets
                      n-values            ; make-str lets
                      (max 0 (1- n-values)) ; concat lets
                      1)))                ; defun
      (loop repeat n-close do (write-char #\) src)))
    ;; kernel-main
    (if (> n-params 0)
        (format src "~%(defun kernel-main () (let ((r (test-fn ~{~D~^ ~}))) "
                (loop for i from 1 to n-params collect (* i 10)))
        (format src "~%(defun kernel-main () (let ((r (test-fn))) "))
    ;; Print result info
    (format src "(phex (array-length r)) (write-char-serial 58) (phex (aref r 0)) (phex (aref r 1)) (phex (aref r 2)) (phex (aref r 3)) (write-char-serial 10) 0))")
    ;; Compute expected
    (let* ((str-size (if hash-at-end 32 (* n-values 5)))
           (byte0 (if hash-at-end nil 0))  ; SSH string starts with 00
           (expected-len (format nil "~2,'0X" str-size)))
      (cons (get-output-stream-string src)
            ;; Expected: length:first4bytes
            ;; For non-hash: first bytes are 00 00 00 01 (SSH string prefix)
            (if hash-at-end
                nil  ; computed separately
                (format nil "~A:00000001" expected-len))))))

;;; ================================================================
;;; Run tests with increasing complexity
;;; ================================================================

(format t "~%=== Concat chain tests (no params) ===~%")
(loop for n in '(1 2 3 5 7) do
  (let* ((pair (gen-concat-test n 0 nil))
         (src (car pair))
         (expected (cdr pair)))
    (run-test (format nil "concat-~Dv" n) src expected)))

(format t "~%=== Concat chain + 4 params ===~%")
(loop for n in '(1 2 3 5 7) do
  (let* ((pair (gen-concat-test n 4 nil))
         (src (car pair))
         (expected (cdr pair)))
    (run-test (format nil "concat-4p-~Dv" n) src expected)))

(format t "~%=== Concat chain + SHA-256 hash ===~%")
;; Compute expected SHA-256 for each test using Python
(loop for n in '(1 3 5 7)
      for n-params in '(0 0 0 0) do
  (let* ((pair (gen-concat-test n n-params t))
         (src (car pair)))
    ;; Get expected from Python
    (let* ((py-cmd (format nil "
import hashlib
data = b''
for i in range(1, ~D+1):
    data += bytes([0, 0, 0, 1, 0x10+i])
h = hashlib.sha256(data).hexdigest()[:8].upper()
print('20:' + h[:2] + h[2:4] + h[4:6] + h[6:8], end='')
" n))
           (expected (with-output-to-string (s)
                       (sb-ext:run-program "/usr/bin/python3" (list "-c" py-cmd) :output s :wait t))))
      (run-test (format nil "hash-~Dv" n) src expected))))

(format t "~%=== Concat chain + 4 params + SHA-256 (closest to exchange hash) ===~%")
(loop for n in '(3 5 7) do
  (let* ((pair (gen-concat-test n 4 t))
         (src (car pair)))
    (let* ((py-cmd (format nil "
import hashlib
data = b''
for i in range(1, ~D+1):
    data += bytes([0, 0, 0, 1, 0x10+i])
h = hashlib.sha256(data).hexdigest()[:8].upper()
print('20:' + h[:2] + h[2:4] + h[4:6] + h[6:8], end='')
" n))
           (expected (with-output-to-string (s)
                       (sb-ext:run-program "/usr/bin/python3" (list "-c" py-cmd) :output s :wait t))))
      (run-test (format nil "hash-4p-~Dv" n) src expected))))

(format t "~%Done.~%")
