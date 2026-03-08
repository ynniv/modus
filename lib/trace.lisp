;;;;------------------------------------------------------------------
;;;;
;;;;    Tracing and timing utilities — reference CL implementation (needs MVM adaptation)
;;;;
;;;;    Provides simple profiling inspired by Genera's metering system,
;;;;    but adapted — reference CL implementation (needs MVM adaptation)'s constraints (no processes, no hardware
;;;;    traps, bare-metal execution).
;;;;
;;;;------------------------------------------------------------------



;;; ============================================================
;;; Time measurement
;;; ============================================================

(defvar *trace-enabled* t
  "When NIL, tracing macros become no-ops")

(defvar *trace-depth* 0
  "Current nesting depth for indentation")

(defvar *trace-output* nil
  "Stream for trace output. NIL means *standard-output*")

(defun tsc-to-microseconds (tsc-low tsc-mid)
  "Convert TSC counter values to approximate microseconds.
   Assumes ~1GHz CPU (adjust *tsc-per-microsecond* for your hardware)."
  ;; TSC low is 29 bits, mid is 29 bits shifted left by 29
  ;; So total = low + (mid << 29)
  ;; For 1GHz, 1 microsecond = 1000 cycles
  ;; We'll return a rough approximation
  (let ((cycles (+ tsc-low (* tsc-mid 536870912)))) ; 2^29
    (floor cycles 1000)))

(defvar *tsc-per-microsecond* 1000
  "TSC ticks per microsecond. Adjust for your CPU frequency.
   Default assumes 1 GHz. For 2 GHz, use 2000, etc.")

;;; ============================================================
;;; Simple timing macro (like CL's TIME)
;;; ============================================================

(defmacro mtime (form)
  "Time the execution of FORM, printing elapsed cycles and microseconds."
  (let ((start-lo (gensym "START-LO-"))
        (start-hi (gensym "START-HI-"))
        (end-lo (gensym "END-LO-"))
        (end-hi (gensym "END-HI-"))
        (result (gensym "RESULT-")))
    `(if (not *trace-enabled*)
         ,form
         (multiple-value-bind (,start-lo ,start-hi)
             (read-time-stamp-counter)
           (let ((,result (multiple-value-list ,form)))
             (multiple-value-bind (,end-lo ,end-hi)
                 (read-time-stamp-counter)
               (let* ((lo-diff (- ,end-lo ,start-lo))
                      (hi-diff (- ,end-hi ,start-hi))
                      ;; Handle wraparound in low bits
                      (cycles (if (minusp lo-diff)
                                  (+ lo-diff 536870912)  ; 2^29
                                  lo-diff))
                      (hi-cycles (* hi-diff 536870912))
                      (total-cycles (+ cycles hi-cycles))
                      (usecs (floor total-cycles *tsc-per-microsecond*)))
                 (format (or *trace-output* *standard-output*)
                         "~&; Time: ~:D cycles (~:D us)~%"
                         total-cycles usecs))
               (values-list ,result)))))))

;;; ============================================================
;;; Trace printing utilities
;;; ============================================================

(defun trace-indent ()
  "Print indentation for current trace depth"
  (let ((stream (or *trace-output* *standard-output*)))
    (dotimes (i *trace-depth*)
      (declare (ignore i))
      (write-string "  " stream))))

(defun trace-entry (name &rest args)
  "Print trace entry message"
  (let ((stream (or *trace-output* *standard-output*)))
    (trace-indent)
    (format stream "~&> ~A" name)
    (when args
      (format stream " ~{~S~^ ~}" args))
    (terpri stream)))

(defun trace-exit (name result elapsed-cycles)
  "Print trace exit message with result and timing"
  (let ((stream (or *trace-output* *standard-output*))
        (usecs (floor elapsed-cycles *tsc-per-microsecond*)))
    (trace-indent)
    (format stream "~&< ~A = ~S  (~:D cycles, ~:D us)~%"
            name result elapsed-cycles usecs)))

;;; ============================================================
;;; Tracing macro for individual calls
;;; ============================================================

(defmacro mtrace (name form)
  "Trace a single form, printing entry/exit and timing.
   NAME is a symbol or string identifying what we're tracing."
  (let ((start-lo (gensym "START-LO-"))
        (start-hi (gensym "START-HI-"))
        (end-lo (gensym "END-LO-"))
        (end-hi (gensym "END-HI-"))
        (result (gensym "RESULT-")))
    `(if (not *trace-enabled*)
         ,form
         (progn
           (trace-entry ',name)
           (let ((*trace-depth* (1+ *trace-depth*)))
             (multiple-value-bind (,start-lo ,start-hi)
                 (read-time-stamp-counter)
               (let ((,result ,form))
                 (multiple-value-bind (,end-lo ,end-hi)
                     (read-time-stamp-counter)
                   (let* ((lo-diff (- ,end-lo ,start-lo))
                          (hi-diff (- ,end-hi ,start-hi))
                          (cycles (if (minusp lo-diff)
                                      (+ lo-diff 536870912)
                                      lo-diff))
                          (hi-cycles (* hi-diff 536870912))
                          (total-cycles (+ cycles hi-cycles)))
                     (let ((*trace-depth* (1- *trace-depth*)))
                       (trace-exit ',name ,result total-cycles))
                     ,result)))))))))

;;; ============================================================
;;; Simple profiling with timing accumulation
;;; ============================================================

(defvar *profile-data* (make-hash-table :test #'equal)
  "Hash table mapping names to (count . total-cycles)")

(defun reset-profile ()
  "Clear all profiling data"
  (clrhash *profile-data*)
  t)

(defun record-profile (name cycles)
  "Record timing data for NAME"
  (let ((entry (gethash name *profile-data*)))
    (if entry
        (progn
          (incf (car entry))
          (incf (cdr entry) cycles))
        (setf (gethash name *profile-data*) (cons 1 cycles)))))

(defmacro mprofile (name form)
  "Profile FORM, accumulating timing data under NAME.
   Use (show-profile) to display results."
  (let ((start-lo (gensym "START-LO-"))
        (start-hi (gensym "START-HI-"))
        (end-lo (gensym "END-LO-"))
        (end-hi (gensym "END-HI-"))
        (result (gensym "RESULT-")))
    `(if (not *trace-enabled*)
         ,form
         (multiple-value-bind (,start-lo ,start-hi)
             (read-time-stamp-counter)
           (let ((,result ,form))
             (multiple-value-bind (,end-lo ,end-hi)
                 (read-time-stamp-counter)
               (let* ((lo-diff (- ,end-lo ,start-lo))
                      (hi-diff (- ,end-hi ,start-hi))
                      (cycles (if (minusp lo-diff)
                                  (+ lo-diff 536870912)
                                  lo-diff))
                      (hi-cycles (* hi-diff 536870912))
                      (total-cycles (+ cycles hi-cycles)))
                 (record-profile ',name total-cycles)
                 ,result)))))))

(defun show-profile (&optional (stream *standard-output*))
  "Display accumulated profile data, sorted by total time"
  (let ((entries nil))
    ;; Collect entries into a list
    (maphash (lambda (name data)
               (push (list name (car data) (cdr data)) entries))
             *profile-data*)
    ;; Sort by total cycles (descending)
    (setf entries (sort entries #'> :key #'third))
    ;; Display
    (format stream "~&~%=== Profile Results ===~%")
    (format stream "~30A ~10A ~15A ~15A~%"
            "Name" "Count" "Total (us)" "Avg (us)")
    (format stream "~30,,,'-A ~10,,,'-A ~15,,,'-A ~15,,,'-A~%" "" "" "" "")
    (dolist (entry entries)
      (let* ((name (first entry))
             (count (second entry))
             (total-cycles (third entry))
             (total-us (floor total-cycles *tsc-per-microsecond*))
             (avg-us (if (zerop count) 0 (floor total-us count))))
        (format stream "~30A ~10D ~15:D ~15:D~%"
                name count total-us avg-us)))
    (format stream "~%"))
  (values))

;;; ============================================================
;;; Wrap a function with tracing (non-destructive)
;;; ============================================================

(defvar *traced-functions* (make-hash-table :test #'eq)
  "Maps function names to original function objects")

(defun trace-function (name)
  "Enable tracing for function NAME (symbol).
   The function is wrapped to print entry/exit with timing."
  (let ((original (symbol-function name)))
    (unless (gethash name *traced-functions*)
      (setf (gethash name *traced-functions*) original)
      (setf (symbol-function name)
            (lambda (&rest args)
              (if (not *trace-enabled*)
                  (apply original args)
                  (progn
                    (trace-entry name args)
                    (let ((*trace-depth* (1+ *trace-depth*)))
                      (multiple-value-bind (start-lo start-hi)
                          (read-time-stamp-counter)
                        (let ((result (apply original args)))
                          (multiple-value-bind (end-lo end-hi)
                              (read-time-stamp-counter)
                            (let* ((lo-diff (- end-lo start-lo))
                                   (hi-diff (- end-hi start-hi))
                                   (cycles (if (minusp lo-diff)
                                               (+ lo-diff 536870912)
                                               lo-diff))
                                   (hi-cycles (* hi-diff 536870912))
                                   (total-cycles (+ cycles hi-cycles)))
                              (let ((*trace-depth* (1- *trace-depth*)))
                                (trace-exit name result total-cycles))
                              result)))))))))))
  name)

(defun untrace-function (name)
  "Disable tracing for function NAME, restoring original."
  (let ((original (gethash name *traced-functions*)))
    (when original
      (setf (symbol-function name) original)
      (remhash name *traced-functions*)))
  name)

(defun untrace-all ()
  "Disable all function tracing"
  (maphash (lambda (name original)
             (setf (symbol-function name) original))
           *traced-functions*)
  (clrhash *traced-functions*)
  t)

;;; ============================================================
;;; Quick benchmark utility
;;; ============================================================

(defmacro benchmark (n form)
  "Run FORM N times, reporting total and average time."
  (let ((count (gensym "COUNT-"))
        (i (gensym "I-"))
        (start-lo (gensym "START-LO-"))
        (start-hi (gensym "START-HI-"))
        (end-lo (gensym "END-LO-"))
        (end-hi (gensym "END-HI-")))
    `(let ((,count ,n))
       (multiple-value-bind (,start-lo ,start-hi)
           (read-time-stamp-counter)
         (dotimes (,i ,count)
           (declare (ignore ,i))
           ,form)
         (multiple-value-bind (,end-lo ,end-hi)
             (read-time-stamp-counter)
           (let* ((lo-diff (- ,end-lo ,start-lo))
                  (hi-diff (- ,end-hi ,start-hi))
                  (cycles (if (minusp lo-diff)
                              (+ lo-diff 536870912)
                              lo-diff))
                  (hi-cycles (* hi-diff 536870912))
                  (total-cycles (+ cycles hi-cycles))
                  (total-us (floor total-cycles *tsc-per-microsecond*))
                  (avg-us (floor total-us ,count)))
             (format t "~&; Benchmark: ~:D iterations~%" ,count)
             (format t ";   Total: ~:D cycles (~:D us)~%" total-cycles total-us)
             (format t ";   Average: ~:D us per iteration~%" avg-us)
             (values total-cycles ,count)))))))

;;; ============================================================
;;; CPU frequency calibration
;;; ============================================================

(defun calibrate-tsc (&optional (seconds 1))
  "Attempt to calibrate TSC by busy-waiting.
   Returns estimated cycles per microsecond.
   This is a rough approximation - best to set *tsc-per-microsecond* manually."
  ;; We don't have a real-time clock, so this just reports cycles
  ;; for a busy loop. User should adjust *tsc-per-microsecond* accordingly.
  (format t "~&; Running busy loop for calibration...~%")
  (format t "; Count to 10000000 and note elapsed time on host...~%")
  (multiple-value-bind (start-lo start-hi)
      (read-time-stamp-counter)
    (let ((count 0))
      (dotimes (i 10000000)
        (incf count)))
    (multiple-value-bind (end-lo end-hi)
        (read-time-stamp-counter)
      (let* ((lo-diff (- end-lo start-lo))
             (hi-diff (- end-hi start-hi))
             (cycles (if (minusp lo-diff)
                         (+ lo-diff 536870912)
                         lo-diff))
             (hi-cycles (* hi-diff 536870912))
             (total-cycles (+ cycles hi-cycles)))
        (format t "; ~:D cycles for 10M iterations~%" total-cycles)
        (format t "; Set *tsc-per-microsecond* based on your host timing~%")
        total-cycles))))
