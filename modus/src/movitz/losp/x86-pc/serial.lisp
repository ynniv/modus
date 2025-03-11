;;;;------------------------------------------------------------------
;;;; 
;;;;    Copyright (C) 2001-2005, 
;;;;    Department of Computer Science, University of Tromso, Norway.
;;;; 
;;;;    For distribution policy, see the accompanying file COPYING.
;;;; 
;;;; Filename:      serial.lisp
;;;; Description:   Serial port interfacing.
;;;; Author:        Frode Vatvedt Fjeld <frodef@acm.org>
;;;; Created at:    Fri Oct 11 14:42:12 2002
;;;;                
;;;; $Id: serial.lisp,v 1.3 2005/03/09 07:21:42 ffjeld Exp $
;;;;                
;;;;------------------------------------------------------------------

(require :lib/named-integers)
(provide :x86-pc/serial)

(defpackage muerte.x86-pc.serial
  (:use muerte.cl muerte.lib muerte.x86-pc muerte)
  (:export uart-probe
	   uart-divisor
	   uart-baudrate
	   encode-uart-lcr
	   decode-uart-lcr
	   +uart-probe-addresses+
	   uart-read-char
	   uart-write-char
	   uart-char-ready-p
	   uart-init
	   com
	   serial-stream
	   make-serial-stream
	   enable-serial-console
	   enable-serial-input
	   serial-print
	   *serial-port*
	   ;; Boot log (dmesg-style)
	   *boot-log*
	   boot-log
	   dmesg))

(in-package muerte.x86-pc.serial)

(defconstant +uart-probe-addresses+
    '(#x3f8 #x2f8 #x3e8 #x2e8))

(define-named-integer uart-read (:only-constants t :export-constants t)
  ;; UART register map with DLAB=0
  (0 receiver-buffer)
  (1 ier)				; interrupt enable
  (2 iir)				; interrupt identification
  (3 lcr)				; Line Control
  (4 mcr)				; Modem Control
  (5 lsr)				; Line Status
  (6 msr)				; Modem Status
  (7 scratch))

(define-named-integer uart-dlab1-read (:only-constants t :export-constants t)
  ;; UART register map with DLAB=1
  (0 divisor-latch-lo)
  (1 divisor-latch-hi))

(define-named-integer uart-write (:only-constants t :export-constants t)
  ;; UART register map with DLAB=0
  (0 transmitter-buffer)
  (1 ier)				; interrupt enable
  (2 fcr)				; FIFO Control
  (3 lcr)				; Line Control
  (4 mcr)				; Modem Control
  (7 scratch))

(define-named-integer uart-dlab1-write (:only-constants t :export-constants t)
  ;; UART register map with DLAB=1
  (0 divisor-latch-lo)
  (1 divisor-latch-hi))

(defun uart-probe (io-base)
  "Return NIL if no UART is found. If an UART is found, return three values:
The io-base, the UART's name, and the FIFO size."
  (with-io-register-syntax (uart-io io-base)
    (let ((old-mcr (uart-io +uart-read-mcr+)))
      (setf (uart-io +uart-write-mcr+) #x10)
      (unless (= 0 (ldb (byte 4 4) (uart-io +uart-read-msr+)))
	(return-from uart-probe nil))
      (setf (uart-io +uart-write-mcr+) #x1f)
      (unless (= #xf (ldb (byte 4 4) (uart-io +uart-read-msr+)))
	(return-from uart-probe nil))
      (setf (uart-io +uart-write-mcr+) old-mcr))
    ;; next thing to do is look for the scratch register
    (let ((old-scratch (uart-io +uart-read-scratch+)))
      (when (or (/= (setf (uart-io +uart-write-scratch+) #x55)
		    (uart-io +uart-read-scratch+))
		(/= (setf (uart-io +uart-write-scratch+) #xaa)
		    (uart-io +uart-read-scratch+)))
	(return-from uart-probe 
	  (values io-base :uart-8250 0)))
      (setf (uart-io +uart-write-scratch+) old-scratch))
    ;; then check if there's a FIFO
    (setf (uart-io +uart-write-fcr+) #x21)
    (case (ldb (byte 3 5) (uart-io +uart-read-iir+))
      (0 (values io-base :16450 0)) ; No FIFO
      (4 (values io-base :16550 0)) ; FIFO enabled but unusable
      (6 (values io-base :16550a 16))
      (7 (values io-base :16750 64))
      (t (values io-base :unknown 0)))))

(defun uart-divisor (io-base)
  (with-io-register-syntax (uart-io io-base)
    (setf (ldb (byte 1 7) (uart-io +uart-write-lcr+)) 1)
    (prog1
	(dpb (uart-io +uart-dlab1-read-divisor-latch-hi+)
	     (byte 8 8)
	     (uart-io +uart-dlab1-read-divisor-latch-lo+))
      (setf (ldb (byte 1 7) (uart-io +uart-write-lcr+)) 0))))

(defun (setf uart-divisor) (value io-base)
  (with-io-register-syntax (uart-io io-base)
    (setf (ldb (byte 1 7) (uart-io +uart-write-lcr+)) 1
	  (uart-io +uart-dlab1-read-divisor-latch-hi+) (ldb (byte 8 8) value)
	  (uart-io +uart-dlab1-read-divisor-latch-lo+) (ldb (byte 8 0) value)
	  (ldb (byte 1 7) (uart-io +uart-write-lcr+)) 0))
  value)

(defun uart-baudrate (io-base)
  (truncate 115200 (uart-divisor io-base)))

(defun (setf uart-baudrate) (value io-base)
  (setf (uart-divisor io-base)
    (truncate 115200 value))
  value)

(defun decode-uart-lcr (x)
  "Return word-length, parity mode, stop-bits."
  (values (+ 5 (ldb (byte 2 0) x))
	  (case (ldb (byte 3 3) x)
	    ((0 2 4 6) :none)
	    (1 :odd)
	    (3 :even)
	    (5 :sticky-high)
	    (7 :sticky-low))
	  (if (logbitp 2 x) 2 1)
	  (logbitp 6 x)
	  (logbitp 7 x)))

(defun encode-uart-lcr (word-length parity stop-bits &optional (break nil) (dlab nil))
  (assert (<= 5 word-length 8))
  (assert (<= 1 stop-bits 2))
  (logior (- word-length 5)
	  (ecase parity
	    (:none 0)
	    (:odd  #x08)
	    (:even #x18)
	    (:sticky-high #x28)
	    (:sticky-low #x38))
	  (if (= 1 stop-bits) 0 4)
	  (if break #x40 0)
	  (if dlab #x80 0)))

(defun uart-char-ready-p (io-base)
  "Return T if a character is available to read from the UART."
  (logbitp 0 (io-register8 io-base +uart-read-lsr+)))

(defun uart-read-char (io-base &optional (wait-p t))
  "Read a character from the UART at IO-BASE.
   If WAIT-P is true (default), block until a character is available.
   If WAIT-P is false, return NIL if no character is available."
  (if wait-p
      (progn
        (loop until (uart-char-ready-p io-base))
        (code-char (io-port io-base :unsigned-byte8)))
      (when (uart-char-ready-p io-base)
        (code-char (io-port io-base :unsigned-byte8)))))

(defun uart-write-char (io-base char)
  (loop until (logbitp 5 (io-register8 io-base +uart-read-lsr+)))
  (setf (io-port (+ io-base +uart-write-transmitter-buffer+) :character)
    char))

(defun make-serial-write-char (&key (io-base (or (some #'uart-probe +uart-probe-addresses+)
						 (error "No serial port found.")))
				    (baudrate 9600)
				    (word-length 8)
				    (parity :none)
				    (stop-bits 1))
  (setf (uart-baudrate io-base) baudrate
	(io-register8 io-base +uart-write-lcr+) (encode-uart-lcr word-length parity stop-bits))
  (setf (io-register8 io-base +uart-write-fcr+) 0)
  (lambda (char &optional stream)
    (case char
      (#\newline
       (uart-write-char io-base #\return)))
    (uart-write-char io-base char)
    (muerte::%write-char char (muerte::output-stream-designator stream))))


(defun com (string &key (io-base (or (some #'uart-probe +uart-probe-addresses+)
				     (error "No serial port found.")))
			(baudrate 9600)
			(word-length 8)
			(parity :none)
			(stop-bits 1))
  (setf (uart-baudrate io-base) baudrate
	(io-register8 io-base +uart-write-lcr+) (encode-uart-lcr word-length parity stop-bits))
  (setf (io-register8 io-base +uart-write-fcr+) 0)
  (loop for c across string
      do (uart-write-char io-base c))
  io-base)


;;; Serial stream class for use as *terminal-io*

(defvar *serial-port* nil
  "The currently active serial port IO base address, or NIL if not initialized.")

(defclass serial-stream (simple-stream)
  ((io-base
    :initarg :io-base
    :reader serial-stream-io-base)
   (echo-p
    :initarg :echo-p
    :initform t
    :accessor serial-stream-echo-p))
  (:documentation "A bidirectional stream over a serial port."))

;; DEVICE-OPEN method required by simple-stream
(defmethod device-open ((stream serial-stream) options)
  (declare (ignore options))
  stream)

(defun uart-init (io-base &key (baudrate 115200) (word-length 8) (parity :none) (stop-bits 1))
  "Initialize a UART at IO-BASE with the given parameters."
  (setf (uart-baudrate io-base) baudrate)
  (setf (io-register8 io-base +uart-write-lcr+)
        (encode-uart-lcr word-length parity stop-bits))
  ;; Disable FIFO for simpler operation
  (setf (io-register8 io-base +uart-write-fcr+) 0)
  ;; Enable DTR and RTS
  (setf (io-register8 io-base +uart-write-mcr+) #x03)
  io-base)

(defun make-serial-stream (&key (io-base (or (some #'uart-probe +uart-probe-addresses+)
                                              (error "No serial port found.")))
                                (baudrate 115200)
                                (echo-p t))
  "Create a serial stream on the first available serial port.
   BAUDRATE defaults to 115200 for compatibility with most terminals.
   ECHO-P controls whether input characters are echoed back (default T)."
  (uart-init io-base :baudrate baudrate)
  (setf *serial-port* io-base)
  (make-instance 'serial-stream :io-base io-base :echo-p echo-p))

(defmethod stream-read-char ((stream serial-stream))
  (let ((char (uart-read-char (serial-stream-io-base stream) t)))
    ;; Handle CR -> LF conversion
    (when (eql char #\return)
      (setf char #\newline))
    ;; Echo if enabled
    (when (serial-stream-echo-p stream)
      (stream-write-char stream char))
    char))

(defmethod stream-read-char-no-hang ((stream serial-stream))
  (let ((char (uart-read-char (serial-stream-io-base stream) nil)))
    (when char
      (when (eql char #\return)
        (setf char #\newline))
      (when (serial-stream-echo-p stream)
        (stream-write-char stream char)))
    char))

(defmethod stream-write-char ((stream serial-stream) char)
  (let ((io-base (serial-stream-io-base stream)))
    ;; Convert LF to CR+LF for terminals
    (when (eql char #\newline)
      (uart-write-char io-base #\return))
    (uart-write-char io-base char))
  char)

(defmethod stream-write-string ((stream serial-stream) string &optional (start 0) (end (length string)))
  (loop for i from start below end
        do (stream-write-char stream (char string i)))
  string)

(defmethod stream-fresh-line ((stream serial-stream))
  ;; For serial, we can't know cursor position, so always output newline
  (stream-write-char stream #\newline)
  t)

(defmethod stream-listen ((stream serial-stream))
  (uart-char-ready-p (serial-stream-io-base stream)))

(defmethod stream-line-column ((stream serial-stream))
  ;; We don't track column position
  nil)

(defmethod stream-finish-output ((stream serial-stream))
  ;; Wait for transmitter to be empty
  (loop until (logbitp 6 (io-register8 (serial-stream-io-base stream) +uart-read-lsr+)))
  nil)

(defmethod stream-force-output ((stream serial-stream))
  (stream-finish-output stream))

(defmethod close ((stream serial-stream) &key abort)
  (declare (ignore abort))
  (setf *serial-port* nil)
  t)


;;; Convenience function to switch REPL to serial console

(defvar *serial-console-stream* nil
  "The serial stream used for console I/O when serial console is enabled.")

(defun enable-serial-console (&key (baudrate 115200) (echo-p nil) (dump-boot-log t))
  "Enable serial console output by redirecting write-char to serial port.
   This version properly handles string streams for format nil to work."
  (declare (ignore echo-p dump-boot-log))
  ;; Use COM1 directly - already initialized early in genesis
  (let ((io-base #x3f8))
    (uart-init io-base :baudrate baudrate)
    (setf *serial-port* io-base)
    ;; Redefine write-char to output to serial, but respect string streams
    ;; This allows format nil and with-output-to-string to work correctly
    (setf (symbol-function 'write-char)
          (lambda (char &optional stream)
            ;; Check if we should write to a string instead of serial:
            ;; 1. If stream is explicitly a string
            ;; 2. If stream is nil and *standard-output* is a string
            (let ((target (cond
                            ((stringp stream) stream)
                            ((and (null stream)
                                  (boundp '*standard-output*)
                                  (stringp *standard-output*))
                             *standard-output*)
                            (t nil))))
              (if target
                  ;; Write to string
                  (progn
                    (vector-push-extend char target)
                    char)
                  ;; Write to serial
                  (progn
                    (when (eql char #\newline)
                      (uart-write-char io-base #\return))
                    (uart-write-char io-base char)
                    char)))))
    ;; Output welcome message
    (write-string "Serial console enabled.")
    (terpri)
    io-base))

(defun enable-serial-input ()
  "Enable serial input by redirecting read-key to read from serial port.
   Must be called AFTER enable-serial-console and right before the REPL."
  (let ((io-base (or *serial-port* #x3f8)))
    (setf *serial-port* io-base)
    ;; Override read-key to read from serial
    (setf (symbol-function 'muerte:read-key)
          (lambda (&optional input-stream eof-error-p eof-value recursive-p)
            (declare (ignore input-stream eof-error-p eof-value recursive-p))
            (let ((char (uart-read-char io-base t)))
              ;; Convert CR to newline for terminal compatibility
              (if (eql char #\return)
                  #\newline
                  char))))
    (write-string "Serial input enabled.")
    (terpri)
    io-base))

(defun serial-print (string &key (baudrate 115200))
  "Print STRING to the serial port. Useful for one-off debugging messages."
  (let ((io-base (or *serial-port*
                     (uart-init (or (some #'uart-probe +uart-probe-addresses+)
                                    (error "No serial port found."))
                                :baudrate baudrate))))
    (setf *serial-port* io-base)
    (loop for char across string
          do (when (eql char #\newline)
               (uart-write-char io-base #\return))
             (uart-write-char io-base char))
    string))


;;; Boot log - dmesg style message buffer

(defvar *boot-log* nil
  "List of boot messages, most recent first.")

(defvar *boot-log-max* 100
  "Maximum number of boot log entries to keep.")

(defun boot-log (format-string &rest args)
  "Record a message in the boot log. Also outputs to current *standard-output*.
   Messages are stored for later retrieval via DMESG."
  (let ((message (apply #'format nil format-string args)))
    ;; Add to log (prepend for efficiency, reverse on display)
    (push message *boot-log*)
    ;; Trim if too long
    (when (> (length *boot-log*) *boot-log-max*)
      (setf *boot-log* (subseq *boot-log* 0 *boot-log-max*)))
    ;; Also output normally
    (write-string message)
    (terpri)
    message))

(defun dmesg (&optional (n nil))
  "Display boot log messages, oldest first.
   If N is specified, show only the last N messages."
  (let ((messages (reverse *boot-log*)))
    (when n
      (setf messages (last messages n)))
    (dolist (msg messages)
      (write-string msg)
      (terpri)))
  (values))

