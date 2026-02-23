;;;; print.lisp - Printing for Modus64
;;;;
;;;; Basic printing to serial port for debugging.

(in-package :modus64.runtime)

;;; ============================================================
;;; Serial Port Output
;;; ============================================================

(defconstant +serial-port+ #x3F8)
(defconstant +serial-lsr+ #x3FD)

(defun serial-ready-p ()
  "Is serial transmitter ready?"
  (not (zerop (logand (mem-ref +serial-lsr+ :u8) #x20))))

(defun serial-wait ()
  "Wait for serial to be ready"
  (loop
    (if (serial-ready-p)
        (return nil))))

(defun write-char (c)
  "Write character C to serial"
  (serial-wait)
  (setf (mem-ref +serial-port+ :u8) (char-code c)))

(defun write-byte-raw (b)
  "Write raw byte B to serial"
  (serial-wait)
  (setf (mem-ref +serial-port+ :u8) b))

;;; ============================================================
;;; Printing Primitives
;;; ============================================================

(defun write-string (s)
  "Write string S to serial"
  ;; For now, S is a simple byte array
  (let ((len (length s)))
    (dotimes (i len)
      (write-byte-raw (aref s i)))))

(defun newline ()
  "Write CR LF"
  (write-byte-raw 13)
  (write-byte-raw 10))

;;; ============================================================
;;; Number Printing
;;; ============================================================

(defun print-digit (d)
  "Print digit 0-15 as hex"
  (write-byte-raw (if (< d 10)
                      (+ d 48)    ; '0' = 48
                      (+ d 55)))) ; 'A' - 10 = 55

(defun print-fixnum (n)
  "Print fixnum N in decimal"
  (let ((val (fixnum-value n)))  ; Untag
    (if (< val 0)
        (progn
          (write-byte-raw 45)  ; '-'
          (print-fixnum-unsigned (- val)))
        (print-fixnum-unsigned val))))

(defun print-fixnum-unsigned (n)
  "Print unsigned integer N"
  (if (< n 10)
      (print-digit n)
      (progn
        (print-fixnum-unsigned (truncate n 10))
        (print-digit (mod n 10)))))

(defun print-hex (n)
  "Print N in hexadecimal"
  (write-byte-raw 48)  ; '0'
  (write-byte-raw 120) ; 'x'
  (print-hex-digits n 16))  ; 16 hex digits for 64-bit

(defun print-hex-digits (n count)
  "Print COUNT hex digits of N"
  (when (> count 0)
    (print-hex-digits (ash n -4) (1- count))
    (print-digit (logand n #xF))))

;;; ============================================================
;;; Object Printing
;;; ============================================================

(defun print-object (obj)
  "Print any object"
  (cond
    ((fixnump obj)
     (print-fixnum obj))
    ((null obj)
     (write-string "NIL"))
    ((consp obj)
     (print-cons obj))
    ((symbolp obj)
     (print-symbol obj))
    (t
     (write-string "#<object>")
     (print-hex obj))))

(defun print-cons (c)
  "Print cons cell as list"
  (write-byte-raw 40)  ; '('
  (print-object (car c))
  (print-cons-tail (cdr c))
  (write-byte-raw 41)) ; ')'

(defun print-cons-tail (c)
  "Print rest of list"
  (cond
    ((null c)
     nil)  ; End of proper list
    ((consp c)
     (write-byte-raw 32)  ; ' '
     (print-object (car c))
     (print-cons-tail (cdr c)))
    (t
     ;; Dotted pair
     (write-string " . ")
     (print-object c))))

(defun print-symbol (s)
  "Print symbol name"
  ;; TODO: Get name from symbol
  (write-string "#<sym>"))

;;; ============================================================
;;; REPL Support
;;; ============================================================

(defun print (obj)
  "Print object with newline"
  (print-object obj)
  (newline)
  obj)

(defun prin1 (obj)
  "Print object without newline"
  (print-object obj)
  obj)
