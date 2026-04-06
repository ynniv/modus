;;;; build-i386-diag.lisp — Build i386 diagnostic REPL (direct boot, no GRUB)
;;;;
;;;; Usage: sbcl --script mvm/build-i386-diag.lisp
;;;;
;;;; Produces:
;;;;   /tmp/modus-i386-diag.bin   — kernel (Multiboot, works with qemu -kernel)
;;;;   /tmp/modus-i386-diag.img   — disk image (boot sector + kernel, floppy/USB)
;;;;
;;;; Test in QEMU:
;;;;   qemu-system-i386 -kernel /tmp/modus-i386-diag.bin -m 256 -nographic
;;;;   qemu-system-i386 -fda /tmp/modus-i386-diag.img -m 256 -nographic
;;;;   qemu-system-i386 -drive file=/tmp/modus-i386-diag.img,format=raw -m 256 -nographic
;;;;
;;;; Write to USB:
;;;;   sudo dd if=/tmp/modus-i386-diag.img of=/dev/sdX bs=512 status=progress
;;;;
;;;; Write to floppy:
;;;;   sudo dd if=/tmp/modus-i386-diag.img of=/dev/fd0 bs=512

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
  (read-file-text (merge-pathnames "net/i386-console.lisp" *modus-base*)))

;; Load the direct boot code (boot sector emitter + console entry)
;; Must load before in-package since *modus-base* is in CL-USER
(load (merge-pathnames "boot/boot-direct-i386.lisp" *modus-base*))

;;; ============================================================
;;; Auto-generate REPL dispatch for ALL compiled functions
;;; ============================================================
;;; Parses the combined source for defun forms, generates:
;;;   - rcall-NAME wrappers that extract args from cons list and call
;;;   - try-repl-N chain of dispatch functions using symbol-eq matching
;;;   - eval-platform-call override that calls the dispatch chain

(defun extract-defun-info (source-text)
  "Extract (NAME-STRING . PARAM-COUNT) for all defuns in SOURCE-TEXT.
   Deduplicates keeping last occurrence (last-defun-wins)."
  (let ((defuns '())
        (pos 0)
        (len (length source-text))
        (*read-eval* nil)
        (*package* (find-package :cl-user)))
    (loop
      (when (>= pos len) (return))
      (handler-case
          (multiple-value-bind (form new-pos)
              (read-from-string source-text nil :eof :start pos)
            (if (eq form :eof)
                (return)
                (progn
                  (setf pos new-pos)
                  (when (and (consp form)
                             (eq (car form) 'defun)
                             (symbolp (second form))
                             (listp (third form)))
                    (push (cons (symbol-name (second form))
                                (length (third form)))
                          defuns)))))
        (error ()
          (let ((next (position #\( source-text :start (min (1+ pos) len))))
            (if next (setf pos next) (return))))))
    ;; Deduplicate: keep last occurrence of each name
    (let ((seen (make-hash-table :test #'equal))
          (order '()))
      (dolist (pair (nreverse defuns))
        (unless (gethash (car pair) seen)
          (push (car pair) order))
        (setf (gethash (car pair) seen) (cdr pair)))
      (mapcar (lambda (name) (cons name (gethash name seen)))
              (nreverse order)))))

(defun gen-char-codes (name)
  "Generate (cons C1 (cons C2 ... nil)) for NAME string."
  (if (zerop (length name))
      "nil"
      (with-output-to-string (s)
        (loop for c across name do (format s "(cons ~D " (char-code c)))
        (write-string "nil" s)
        (dotimes (i (length name)) (write-char #\) s)))))

(defun gen-nth-cdr (n)
  "Generate nested cdr to reach nth position in list 'a'."
  (if (<= n 0) "a"
      (format nil "(cdr ~A)" (gen-nth-cdr (1- n)))))

(defun gen-nth-car (n)
  "Generate (car (cdr ...)) for nth element of list 'a'."
  (format nil "(car ~A)" (gen-nth-cdr n)))

(defun gen-call-wrapper (name param-count)
  "Generate (defun rcall-NAME (a) ...) wrapper that extracts args and calls NAME."
  (let ((lname (string-downcase name)))
    (with-output-to-string (s)
      (format s "(defun rcall-~A (a) " lname)
      (if (zerop param-count)
          (format s "(let ((r (~A))) (cons r nil))" lname)
          (progn
            ;; Open let bindings for each arg
            (dotimes (i param-count)
              (format s "(let ((a~D ~A)) " i (gen-nth-car i)))
            ;; Call function with extracted args
            (format s "(let ((r (~A" lname)
            (dotimes (i param-count) (format s " a~D" i))
            (format s "))) (cons r nil)")
            ;; Close all let forms
            (dotimes (i (1+ param-count)) (write-char #\) s))))
      (format s ")~%"))))

(defun group-list (lst n)
  "Split LST into sublists of at most N elements."
  (loop for i from 0 below (length lst) by n
        collect (subseq lst i (min (+ i n) (length lst)))))

(defun gen-dispatch-source (defuns)
  "Generate eval-platform-call dispatch source from DEFUNS list.
   Returns Lisp source text string."
  (let* ((filtered (remove-if
                     (lambda (d)
                       (or (string= (car d) "EVAL-PLATFORM-CALL")
                           (> (cdr d) 5)))
                     defuns))
         (groups (group-list filtered 8)))
    (with-output-to-string (s)
      (format s "~%;;; === Auto-generated REPL dispatch (~D functions) ===~%"
              (length filtered))
      ;; Generate call wrappers
      (dolist (fn filtered)
        (write-string (gen-call-wrapper (car fn) (cdr fn)) s))
      ;; Generate dispatch chain
      (loop for group in groups
            for i from 0
            do (format s "(defun try-repl-~D (nm args) (let ((n nm) (a args)) " i)
               (dolist (fn group)
                 (format s "(if (symbol-eq n ~A) (rcall-~A a) "
                         (gen-char-codes (car fn))
                         (string-downcase (car fn))))
               ;; Fallback: next group or nil
               (if (< (1+ i) (length groups))
                   (format s "(try-repl-~D n a)" (1+ i))
                   (format s "nil"))
               ;; Close all the if forms + let + defun
               (dotimes (j (length group)) (write-char #\) s))
               (format s "))~%"))
      ;; Generate eval-platform-call
      (if groups
          (format s "(defun eval-platform-call (name evaled-args) (let ((n name) (a evaled-args)) (try-repl-0 n a)))~%")
          (format s "(defun eval-platform-call (name evaled-args) nil)~%")))))

;;; ============================================================
;;; String literal expansion
;;; ============================================================
;;; MVM constant pool doesn't resolve string addresses at runtime.
;;; Replace (print-str "...") and (print-ln "...") with inline
;;; write-char-output sequences that work without string objects.

(defun gen-chars-cons (text)
  "Generate (cons C1 (cons C2 ... nil)) for TEXT string."
  (if (zerop (length text))
      "nil"
      (with-output-to-string (s)
        (loop for c across text do (format s "(cons ~D " (char-code c)))
        (write-string "nil" s)
        (dotimes (i (length text)) (write-char #\) s)))))

(defun expand-print-str (text)
  "Generate (write-string-codes CONS-LIST) for TEXT."
  (format nil "(write-string-codes ~A)" (gen-chars-cons text)))

(defun expand-print-ln (text)
  "Generate print TEXT + newline."
  (format nil "(progn (write-string-codes ~A) (write-char-output 10) 0)"
          (gen-chars-cons text)))

(defun expand-print-reg-raw (name-text)
  "Generate inline code for (print-reg-raw \"NAME\") — prints name: HEXVALUE\\n."
  (format nil "(progn (write-string-codes ~A) (write-char-output 58) (write-char-output 32) (mmio-print-result) (write-char-output 10) 0)"
          (gen-chars-cons name-text)))

(defun expand-one-pattern (source pattern expander)
  "Replace all occurrences of (PATTERN \"TEXT\"...) using EXPANDER function.
   EXPANDER receives the text between quotes and returns replacement source."
  (let ((result source)
        (pat (concatenate 'string "(" pattern " \"")))
    (loop
      (let ((pos (search pat result)))
        (unless pos (return result))
        (let* ((str-start (+ pos (length pat)))
               (str-end (position #\" result :start str-start)))
          (unless str-end (return result))
          (let* ((close-paren (position #\) result :start (1+ str-end)))
                 (text (subseq result str-start str-end))
                 (expansion (funcall expander text)))
            (setf result (concatenate 'string
                                      (subseq result 0 pos)
                                      expansion
                                      (subseq result (1+ close-paren))))))))))

(defun expand-string-calls (source-text)
  "Replace string-literal print calls with inline character writes."
  (let ((result source-text))
    (setf result (expand-one-pattern result "print-reg-raw" #'expand-print-reg-raw))
    (setf result (expand-one-pattern result "print-ln" #'expand-print-ln))
    (setf result (expand-one-pattern result "print-str" #'expand-print-str))
    result))

;; Expand string literals in console source before compilation
(setf *console-source* (expand-string-calls *console-source*))

;;; ============================================================
;;; Build
;;; ============================================================

(in-package :modus.mvm)

;; Install the i386 translator
(modus.mvm.i386:install-i386-translator)

;; Combine: REPL source first, then console overrides, then auto-dispatch.
(let* ((combined-source (concatenate 'string
                                     *repl-source*
                                     cl-user::*console-source*))
       (defuns (cl-user::extract-defun-info combined-source))
       (dispatch-source (cl-user::gen-dispatch-source defuns))
       (final-source (concatenate 'string combined-source dispatch-source)))
  (format t "Building i386 diagnostic REPL...~%")
  (format t "Combined source: ~D chars (~D from dispatch)~%"
          (length final-source) (length dispatch-source))
  (format t "Functions callable from REPL: ~D~%"
          (length (remove-if (lambda (d)
                               (or (string= (car d) "EVAL-PLATFORM-CALL")
                                   (> (cdr d) 5)))
                             defuns)))
  (let ((image (build-image :target :i386-console :source-text final-source)))
    (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
    (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
    (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
    (let* ((kernel-bytes (kernel-image-image-bytes image))
           (kernel-size (length kernel-bytes))
           (kernel-path "/tmp/modus-i386-diag.bin")
           (image-path "/tmp/modus-i386-diag.img"))

      ;; Write kernel binary (works with qemu -kernel)
      (write-kernel-image image kernel-path)

      ;; Generate boot sector
      (format t "Generating boot sector (kernel: ~D bytes, ~D sectors)...~%"
              kernel-size (ceiling kernel-size 512))
      (let* ((boot-sector (generate-boot-sector kernel-size))
             ;; Pad kernel to sector boundary
             (padded-kernel-size (* (ceiling kernel-size 512) 512))
             ;; Total image: boot sector + padded kernel
             ;; Pad to 1.44MB floppy size so QEMU floppy emulation works
             (raw-size (+ 512 padded-kernel-size))
             (total-size (max raw-size (* 2880 512)))
             (disk-image (make-array total-size
                                     :element-type '(unsigned-byte 8)
                                     :initial-element 0)))
        ;; Copy boot sector
        (replace disk-image boot-sector)
        ;; Copy kernel after boot sector
        (replace disk-image kernel-bytes :start1 512)

        ;; Write disk image
        (with-open-file (out image-path :direction :output
                                        :element-type '(unsigned-byte 8)
                                        :if-exists :supersede)
          (write-sequence disk-image out))
        (format t "Wrote ~D bytes to ~A~%" total-size image-path)
        (format t "~%Kernel (Multiboot):  ~A~%" kernel-path)
        (format t "Disk image (direct): ~A~%" image-path)
        (format t "~%Test:~%")
        (format t "  qemu-system-i386 -kernel ~A -m 256 -nographic~%" kernel-path)
        (format t "  qemu-system-i386 -fda ~A -m 256 -nographic~%" image-path)
        (format t "~%Real hardware:~%")
        (format t "  sudo dd if=~A of=/dev/sdX bs=512 status=progress~%" image-path)))))
