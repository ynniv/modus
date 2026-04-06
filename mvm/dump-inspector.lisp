;;;; dump-inspector.lisp - Analyze fixpoint memory dumps
;;;; Usage: sbcl --script mvm/dump-inspector.lisp <dump-file> [options]

;;; Read U32 LE from byte array
(defun read-u32-le (buf offset)
  (let ((b0 (aref buf (+ offset 0)))
        (b1 (aref buf (+ offset 1)))
        (b2 (aref buf (+ offset 2)))
        (b3 (aref buf (+ offset 3))))
    (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))

;;; Show metadata
(defun show-metadata (buf offset)
  (format t "~%=== Metadata at offset #x~X ===~%" offset)
  (let ((magic (read-u32-le buf (+ offset 0))))
    (format t "  Magic: ~A (~8,'0X)~%"
            (if (= magic #x544D564D) "MVMT" "UNKNOWN") magic))
  (format t "  Version: ~D~%" (read-u32-le buf (+ offset 4)))
  (let ((arch (read-u32-le buf (+ offset 8))))
    (format t "  Architecture: ~D (~A)~%" arch
            (cond ((= arch 0) "x64")
                  ((= arch 1) "aarch64")
                  ((= arch 2) "i386")
                  ((= arch 3) "arm32")
                  (t "unknown"))))
  (format t "  Bytecode offset: #x~X~%" (read-u32-le buf (+ offset #x0C)))
  (format t "  Bytecode length: ~D~%" (read-u32-le buf (+ offset #x10)))
  (format t "  Fn-table offset: #x~X~%" (read-u32-le buf (+ offset #x14)))
  (format t "  Fn-table count: ~D~%" (read-u32-le buf (+ offset #x18)))
  (format t "  Native-code offset: ~D~%" (read-u32-le buf (+ offset #x1C)))
  (format t "  Native-code length: ~D~%" (read-u32-le buf (+ offset #x20)))
  (format t "  Preamble size: ~D~%" (read-u32-le buf (+ offset #x24)))
  (format t "  Kernel-main hash: #x~X~%" (read-u32-le buf (+ offset #x28)))
  (format t "  Kernel-main offset: #x~X~%" (read-u32-le buf (+ offset #x2C)))
  (format t "  Image load addr: #x~X~%" (read-u32-le buf (+ offset #x30)))
  (format t "  Target arch: ~D~%" (read-u32-le buf (+ offset #x34)))
  (format t "  Mode: ~D~%" (read-u32-le buf (+ offset #x38))))

;;; Show function table
(defun show-fn-table (buf fn-offset fn-count)
  (format t "~%=== Function Table: ~D entries at #x~X ===~%" fn-count fn-offset)
  (dotimes (i (min fn-count 50))
    (let* ((entry-offset (+ fn-offset (* i 8)))
           (name-offset (read-u32-le buf entry-offset))
           (code-offset (read-u32-le buf (+ entry-offset 4))))
      (format t "  [~4D] name-idx=~6D code-offset=#x~X~%"
              i name-offset code-offset))))

;;; Main
(let* ((args (rest sb-ext:*posix-argv*))
       (file (car args))
       (opts (cdr args)))
  (unless file
    (format t "Usage: ~A <dump-file> [options]~%" (car sb-ext:*posix-argv*))
    (format t "Options: --metadata, --fn-table, --all~%")
    (return-from nil nil))

  (format t "Loading ~A...~%" file)
  (let* ((buf (with-open-file (s file :element-type '(unsigned-byte 8))
                (let* ((len (file-length s))
                       (arr (make-array len :element-type '(unsigned-byte 8))))
                  (read-sequence arr s)
                  arr)))
         (len (length buf)))
    (format t "  ~D bytes loaded~%" len)

    ;; Detect architecture from file size
    (let ((md-offset (cond ((= len 4653120) #x470000)
                           ((= len 4194368) #x400000)
                           (t #x380000))))
      (format t "  Assuming metadata at #x~X~%" md-offset)

      (when (or (member "--metadata" opts :test #'string=)
                (member "--all" opts :test #'string=))
        (show-metadata buf md-offset))

      (when (or (member "--fn-table" opts :test #'string=)
                (member "--all" opts :test #'string=))
        (let* ((fn-offset (read-u32-le buf (+ md-offset #x14)))
               (fn-count (read-u32-le buf (+ md-offset #x18))))
          (show-fn-table buf fn-offset fn-count)))

      ;; Memory dump: --mem ADDR LEN (hex)
      (let ((mem-pos (position "--mem" opts :test #'string=)))
        (when (and mem-pos (< (+ mem-pos 2) (length opts)))
          (let* ((addr-str (nth (+ mem-pos 1) opts))
                 (len-str (nth (+ mem-pos 2) opts))
                 (addr (if (string-prefix-p "0x" addr-str)
                           (parse-integer addr-str :radix 16 :start 2)
                           (parse-integer addr-str :radix 16)))
                 (dump-len (if (string-prefix-p "0x" len-str)
                               (parse-integer len-str :radix 16 :start 2)
                               (parse-integer len-str :radix 16))))
            (format t "~%=== Memory dump at #x~X for ~D bytes ===~%" addr dump-len)
            (dotimes (i (min dump-len 256))
              (when (zerop (mod i 16))
                (format t "~%~8,'0X: " (+ addr i)))
              (format t "~2,'0X " (aref buf (+ addr i))))
            (format t "~%")))))))