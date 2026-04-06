;;;; test-aarch64-progn-limit.lisp — Reproduce the ~25 sequential form truncation
;;;;
;;;; Usage: sbcl --script tests/test-aarch64-progn-limit.lisp
;;;;
;;;; The AArch64 MVM translator silently stops executing sequential forms
;;;; after ~25 in a function body. This caused the SSH bug: kernel-main had
;;;; ~40 forms and the ephemeral key writes near form 39 were truncated.
;;;;
;;;; This test writes sequential (setf mem-ref) forms and checks that ALL
;;;; of them execute by reading back the values.

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)
(install-aarch64-translator)

(defvar *hex-helpers* "
(defun phex-nib (n) (if (< n 10) (write-char-serial (+ n 48)) (write-char-serial (+ n 55))))
(defun phex (b) (phex-nib (logand (ash b -4) 15)) (phex-nib (logand b 15)))
")

(defun run (name source expected)
  (format t "~A: " name) (finish-output)
  (handler-case
    (let* ((full (concatenate 'string *repl-source* *hex-helpers* source))
           (img (build-image :target :aarch64 :source-text full))
           (bin (format nil "/tmp/progn-~A.bin" name))
           (out (format nil "/tmp/progn-~A.out" name)))
      (write-kernel-image img bin)
      (sb-ext:run-program "/bin/bash"
        (list "-c" (format nil "timeout 5 qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel ~A -nographic -semihosting > ~A 2>/dev/null" bin out))
        :search t :wait t)
      (let ((output (with-open-file (f out :if-does-not-exist nil)
                      (when f (let ((s (make-string (file-length f)))) (read-sequence s f) s)))))
        (if (and output (search expected output))
            (format t "PASS~%")
            (format t "FAIL — got ~S, want ~S~%"
                    (when output (subseq output 0 (min 80 (length output)))) expected))))
    (error (e) (format t "ERROR: ~A~%" e))))

;;; Generate a function with N sequential (write-char-serial) forms,
;;; then a final form that writes a marker. If the marker appears,
;;; all N forms executed.
(defun gen-seq-test (n)
  "Generate a function with N sequential write-char-serial forms followed by a marker."
  (let ((src (make-string-output-stream)))
    (format src "(defun test-fn ()~%")
    ;; N sequential forms — each writes a dot
    (dotimes (i n)
      (format src "  (write-char-serial 46)~%"))  ; '.'
    ;; Final marker: 'X'
    (format src "  (write-char-serial 88)~%")  ; 'X'
    (format src "  0)~%")
    (format src "(defun kernel-main () (test-fn) 0)~%")
    (get-output-stream-string src)))

;;; Generate a function with N sequential (setf mem-ref :u8) forms
;;; writing to consecutive addresses, then read them all back.
;;; This is closer to the actual kernel-main pattern.
(defun gen-memset-test (n)
  "Generate a function that writes N bytes to memory then reads them back."
  (let ((src (make-string-output-stream))
        ;; Use a safe memory region for testing (e1000-state-base area)
        ;; 0x44100000 is in the cons/heap area, should be writable
        (base "#x44100000"))
    ;; Write function: N sequential setf forms
    (format src "(defun test-write ()~%")
    (dotimes (i n)
      (format src "  (setf (mem-ref (+ ~A ~D) :u8) #x~2,'0X)~%"
              base i (mod (+ i #xA0) 256)))
    (format src "  0)~%")
    ;; Read function: check first, middle, and last byte
    (format src "(defun test-read ()~%")
    (format src "  (phex (mem-ref (+ ~A 0) :u8))~%" base)
    (when (> n 1)
      (let ((mid (floor n 2)))
        (format src "  (phex (mem-ref (+ ~A ~D) :u8))~%" base mid)))
    (format src "  (phex (mem-ref (+ ~A ~D) :u8))~%" base (1- n))
    (format src "  0)~%")
    ;; kernel-main: write then read
    (format src "(defun kernel-main ()~%")
    (format src "  (test-write)~%")
    (format src "  (write-char-serial 82)~%")  ; 'R'
    (format src "  (test-read)~%")
    (format src "  (write-char-serial 10)~%")
    (format src "  0)~%")
    (get-output-stream-string src)))

(format t "~%=== Sequential write-char-serial forms ===~%")
(dolist (n '(10 20 25 30 35 40 50))
  (let ((src (gen-seq-test n))
        (expected (concatenate 'string
                   (make-string n :initial-element #\.)
                   "X")))
    (run (format nil "seq-~D" n) src expected)))

(format t "~%=== Sequential mem-ref writes ===~%")
(dolist (n '(10 20 25 30 35 40 50))
  (let* ((src (gen-memset-test n))
         ;; Expected: first byte = A0+0=A0, mid byte = A0+n/2, last byte = A0+n-1
         (first-byte (mod #xA0 256))
         (mid-byte (mod (+ #xA0 (floor n 2)) 256))
         (last-byte (mod (+ #xA0 (1- n)) 256))
         (expected (format nil "R~2,'0X~2,'0X~2,'0X"
                           first-byte mid-byte last-byte)))
    (run (format nil "mem-~D" n) src expected)))

(format t "~%=== Sequential forms in ONE let body (the kernel-main pattern) ===~%")
;; This matches the exact bug: a let binding followed by many sequential setf forms
(dolist (n '(10 20 25 30 35 40))
  (let ((src (make-string-output-stream))
        (base "#x44100000"))
    (format src "(defun test-fn ()~%")
    (format src "  (let ((base ~A))~%" base)
    ;; N sequential setf forms inside the let body
    (dotimes (i n)
      (format src "    (setf (mem-ref (+ base ~D) :u8) #x~2,'0X)~%"
              i (mod (+ i #xB0) 256)))
    ;; Return value
    (format src "    0))~%")
    ;; Read back
    (format src "(defun kernel-main ()~%")
    (format src "  (test-fn)~%")
    (format src "  (write-char-serial 82)~%")
    (let ((last-byte (mod (+ #xB0 (1- n)) 256)))
      (format src "  (phex (mem-ref (+ ~A ~D) :u8))~%" base (1- n)))
    (format src "  (write-char-serial 10) 0)~%")
    (let* ((source (get-output-stream-string src))
           (last-byte (mod (+ #xB0 (1- n)) 256))
           (expected (format nil "R~2,'0X" last-byte)))
      (run (format nil "let-~D" n) source expected))))

(format t "~%=== Mixed forms: function calls + let blocks + setf (kernel-main pattern) ===~%")
;; This replicates the EXACT pattern from the broken kernel-main:
;; function calls interspersed with write-byte calls, let blocks with setf,
;; dotimes, and more function calls. ~40 top-level forms total.
(dolist (n '(20 25 30 35 40))
  (let ((src (make-string-output-stream))
        (base "#x44100000"))
    ;; Helper function (like sha256-init, dhcp-client, etc.)
    (format src "(defun do-work (x) (let ((y (+ x 1))) y))~%")
    ;; Main function with mixed forms
    (format src "(defun test-fn ()~%")
    ;; Phase 1: function calls + write-char-serial (~12 forms)
    (format src "  (do-work 1) (write-char-serial 46) (write-char-serial 46) (write-char-serial 46)~%")
    (format src "  (do-work 2) (write-char-serial 46) (write-char-serial 46) (write-char-serial 46)~%")
    (format src "  (do-work 3) (write-char-serial 46) (write-char-serial 46) (write-char-serial 46)~%")
    ;; Phase 2: let block with many setf forms (~15 forms inside let = 1 top-level form)
    (format src "  (let ((s ~A))~%" base)
    (dotimes (i 13)
      (format src "    (setf (mem-ref (+ s ~D) :u8) #x~2,'0X)~%" i (+ #xC0 i)))
    (format src "    0)~%")
    ;; Phase 3: more function calls + write-char-serial (~8 forms)
    (format src "  (do-work 4)~%")
    (format src "  (write-char-serial 46) (write-char-serial 46)~%")
    (format src "  (do-work 5) (do-work 6)~%")
    (format src "  (write-char-serial 46) (write-char-serial 46)~%")
    ;; Phase 4: another let block + dotimes + setf — total pushes us over 25
    ;; This is the part that gets truncated in the real bug
    (format src "  (let ((s ~A))~%" base)
    (format src "    (setf (mem-ref (+ s #x20) :u8) #x00)~%")
    (format src "    (dotimes (i ~D)~%" (min n 30))
    (format src "      (setf (mem-ref (+ s (+ #x21 i)) :u8) #x01))~%")
    ;; Write specific marker bytes AFTER the dotimes
    (format src "    (setf (mem-ref (+ s #x40) :u8) #xDE)~%")
    (format src "    (setf (mem-ref (+ s #x41) :u8) #xAD)~%")
    (format src "    0)~%")
    ;; Phase 5: final forms
    (format src "  (write-char-serial 88)~%")  ; 'X' marker
    (format src "  0)~%")
    ;; kernel-main: call test-fn, then verify marker bytes
    (format src "(defun kernel-main ()~%")
    (format src "  (test-fn)~%")
    (format src "  (write-char-serial 82)~%")  ; 'R'
    (format src "  (phex (mem-ref (+ ~A #x40) :u8))~%" base)  ; should be DE
    (format src "  (phex (mem-ref (+ ~A #x41) :u8))~%" base)  ; should be AD
    (format src "  (write-char-serial 10) 0)~%")
    (let ((source (get-output-stream-string src)))
      ;; Expected: dots + X + RDEAD
      (run (format nil "mixed-~D" n) source "XRDEAD"))))

(format t "~%Done.~%")
