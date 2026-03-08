;;;; JSON parser and serializer — reference CL implementation (needs MVM adaptation)
;;;; Supports: objects, arrays, strings, numbers, true, false, null


;;; JSON parsing

(defun json-skip-whitespace (str pos)
  "Skip whitespace, return new position."
  (loop while (and (< pos (length str))
                   (member (char str pos) '(#\space #\tab #\newline #\return)))
        do (incf pos))
  pos)

(defun json-parse-string (str pos)
  "Parse a JSON string starting at pos (after opening quote). Returns (value . new-pos)."
  (let ((result (make-array 64 :element-type 'character :fill-pointer 0 :adjustable t))
        (len (length str)))
    (loop
      (when (>= pos len)
        (error "Unterminated JSON string"))
      (let ((c (char str pos)))
        (cond
          ((char= c #\")
           (return (cons (coerce result 'string) (1+ pos))))
          ((char= c #\\)
           (incf pos)
           (when (>= pos len)
             (error "Unterminated escape in JSON string"))
           (let ((escaped (char str pos)))
             (vector-push-extend
              (case escaped
                (#\n #\newline)
                (#\t #\tab)
                (#\r #\return)
                (#\" #\")
                (#\\ #\\)
                (#\/ #\/)
                (#\b #\backspace)
                (#\f #\page)
                (#\u
                 ;; Unicode escape \uXXXX
                 (let ((code 0))
                   (dotimes (i 4)
                     (incf pos)
                     (when (>= pos len)
                       (error "Unterminated unicode escape"))
                     (let* ((hc (char str pos))
                            (digit (digit-char-p hc 16)))
                       (unless digit
                         (error "Invalid unicode escape"))
                       (setf code (+ (* code 16) digit))))
                   (code-char code)))
                (t escaped))
              result)
             (incf pos)))
          (t
           (vector-push-extend c result)
           (incf pos)))))))

(defun json-parse-number (str pos)
  "Parse a JSON number. Returns (value . new-pos)."
  (let ((start pos)
        (len (length str))
        (negative nil)
        (has-decimal nil)
        (has-exponent nil))
    ;; Optional minus
    (when (and (< pos len) (char= (char str pos) #\-))
      (setf negative t)
      (incf pos))
    ;; Integer part
    (let ((int-start pos))
      (loop while (and (< pos len) (digit-char-p (char str pos)))
            do (incf pos))
      (when (= pos int-start)
        (error "Invalid JSON number")))
    ;; Optional decimal
    (when (and (< pos len) (char= (char str pos) #\.))
      (setf has-decimal t)
      (incf pos)
      (let ((dec-start pos))
        (loop while (and (< pos len) (digit-char-p (char str pos)))
              do (incf pos))
        (when (= pos dec-start)
          (error "Invalid JSON decimal"))))
    ;; Optional exponent
    (when (and (< pos len) (member (char str pos) '(#\e #\E)))
      (setf has-exponent t)
      (incf pos)
      (when (and (< pos len) (member (char str pos) '(#\+ #\-)))
        (incf pos))
      (let ((exp-start pos))
        (loop while (and (< pos len) (digit-char-p (char str pos)))
              do (incf pos))
        (when (= pos exp-start)
          (error "Invalid JSON exponent"))))
    ;; Parse the number
    (let ((num-str (subseq str start pos)))
      (if (or has-decimal has-exponent)
          ;; Float - simplified parsing (no float support, use rational)
          (let ((value (parse-integer (remove #\. (remove #\e (remove #\E num-str))) :junk-allowed t)))
            (cons (or value 0) pos))
          ;; Integer
          (cons (parse-integer num-str) pos)))))

(defun json-parse-value (str pos)
  "Parse a JSON value. Returns (value . new-pos)."
  (setf pos (json-skip-whitespace str pos))
  (when (>= pos (length str))
    (error "Unexpected end of JSON"))
  (let ((c (char str pos)))
    (cond
      ;; String
      ((char= c #\")
       (json-parse-string str (1+ pos)))
      ;; Object
      ((char= c #\{)
       (json-parse-object str (1+ pos)))
      ;; Array
      ((char= c #\[)
       (json-parse-array str (1+ pos)))
      ;; true
      ((and (<= (+ pos 4) (length str))
            (string= "true" str :start2 pos :end2 (+ pos 4)))
       (cons t (+ pos 4)))
      ;; false
      ((and (<= (+ pos 5) (length str))
            (string= "false" str :start2 pos :end2 (+ pos 5)))
       (cons nil (+ pos 5)))
      ;; null
      ((and (<= (+ pos 4) (length str))
            (string= "null" str :start2 pos :end2 (+ pos 4)))
       (cons :null (+ pos 4)))
      ;; Number
      ((or (digit-char-p c) (char= c #\-))
       (json-parse-number str pos))
      (t
       (error "Unexpected character in JSON: ~a" c)))))

(defun json-parse-object (str pos)
  "Parse a JSON object. Returns (alist . new-pos)."
  (setf pos (json-skip-whitespace str pos))
  (let ((result nil))
    ;; Empty object?
    (when (and (< pos (length str)) (char= (char str pos) #\}))
      (return-from json-parse-object (cons result (1+ pos))))
    (loop
      ;; Parse key
      (setf pos (json-skip-whitespace str pos))
      (unless (and (< pos (length str)) (char= (char str pos) #\"))
        (error "Expected string key in JSON object"))
      (let ((key-result (json-parse-string str (1+ pos))))
        (setf pos (cdr key-result))
        ;; Expect colon
        (setf pos (json-skip-whitespace str pos))
        (unless (and (< pos (length str)) (char= (char str pos) #\:))
          (error "Expected ':' in JSON object"))
        (incf pos)
        ;; Parse value
        (let ((val-result (json-parse-value str pos)))
          (push (cons (car key-result) (car val-result)) result)
          (setf pos (cdr val-result))))
      ;; Check for comma or end
      (setf pos (json-skip-whitespace str pos))
      (when (>= pos (length str))
        (error "Unterminated JSON object"))
      (let ((c (char str pos)))
        (cond
          ((char= c #\})
           (return (cons (nreverse result) (1+ pos))))
          ((char= c #\,)
           (incf pos))
          (t
           (error "Expected ',' or '}' in JSON object")))))))

(defun json-parse-array (str pos)
  "Parse a JSON array. Returns (list . new-pos)."
  (setf pos (json-skip-whitespace str pos))
  (let ((result nil))
    ;; Empty array?
    (when (and (< pos (length str)) (char= (char str pos) #\]))
      (return-from json-parse-array (cons result (1+ pos))))
    (loop
      ;; Parse value
      (let ((val-result (json-parse-value str pos)))
        (push (car val-result) result)
        (setf pos (cdr val-result)))
      ;; Check for comma or end
      (setf pos (json-skip-whitespace str pos))
      (when (>= pos (length str))
        (error "Unterminated JSON array"))
      (let ((c (char str pos)))
        (cond
          ((char= c #\])
           (return (cons (nreverse result) (1+ pos))))
          ((char= c #\,)
           (incf pos))
          (t
           (error "Expected ',' or ']' in JSON array")))))))

(defun json-parse (str)
  "Parse a JSON string. Returns the parsed value."
  (car (json-parse-value str 0)))

;;; JSON serialization


(defun json-serialize (value)
  "Serialize a Lisp value to JSON string.
   - alist with string keys -> object
   - list -> array
   - string -> string
   - integer -> number
   - t -> true
   - nil -> false
   - :null -> null"
  (cond
    ((eq value :null) "null")
    ((eq value t) "true")
    ((null value) "false")
    ((stringp value)
     (let ((result "\""))
       (loop for c across value do
         (setf result
               (concatenate 'string result
                            (case c
                              (#\" "\\\"")
                              (#\\ "\\\\")
                              (#\newline "\\n")
                              (#\tab "\\t")
                              (#\return "\\r")
                              (t (string c))))))
       (concatenate 'string result "\"")))
    ((integerp value)
     (format nil "~d" value))
    ;; alist (object) - must be dotted pairs like (("key" . "value") ...)
    ;; NOT a list of lists like (("p" "pubkey") ...) which should be an array
    ((and (consp value)
          (consp (car value))
          (stringp (caar value))
          (not (consp (cdar value))))  ; cdr of pair is not a list = dotted pair
     (let ((result "{"))
       (loop for (pair . rest) on value do
         (setf result (concatenate 'string result
                                   (json-serialize (car pair))
                                   ":"
                                   (json-serialize (cdr pair))))
         (when rest
           (setf result (concatenate 'string result ","))))
       (concatenate 'string result "}")))
    ;; list (array)
    ((consp value)
     (let ((result "["))
       (loop for (item . rest) on value do
         (setf result (concatenate 'string result (json-serialize item)))
         (when rest
           (setf result (concatenate 'string result ","))))
       (concatenate 'string result "]")))
    ;; vector (array)
    ((vectorp value)
     (let ((result "["))
       (loop for i from 0 below (length value) do
         (setf result (concatenate 'string result (json-serialize (aref value i))))
         (when (< i (1- (length value)))
           (setf result (concatenate 'string result ","))))
       (concatenate 'string result "]")))
    (t
     (error "Cannot serialize to JSON: ~a" value))))

;;; Convenience accessors for parsed JSON

(defun json-get (obj key)
  "Get a value from a JSON object (alist) by string key."
  (cdr (assoc key obj :test #'string=)))

(defun json-getf (obj &rest keys)
  "Get a nested value from JSON using a path of keys."
  (loop for key in keys
        do (setf obj (if (integerp key)
                         (nth key obj)
                         (json-get obj key))))
  obj)

;;; Test function
(defun json-test ()
  "Test JSON parsing and serialization."
  (format t "~&JSON Test~%")

  ;; Test parsing
  (format t "Parsing tests:~%")
  (let ((tests '(("\"hello\"" . "hello")
                 ("123" . 123)
                 ("-456" . -456)
                 ("true" . t)
                 ("false" . nil)
                 ("null" . :null)
                 ("[1,2,3]" . (1 2 3))
                 ("{\"a\":1}" . (("a" . 1))))))
    (dolist (test tests)
      (let ((result (json-parse (car test))))
        (format t "  ~a -> ~s ~a~%"
                (car test) result
                (if (equal result (cdr test)) "OK" "FAIL")))))

  ;; Test serialization
  (format t "Serialization tests:~%")
  (let ((tests '(("hello" . "\"hello\"")
                 (123 . "123")
                 (t . "true")
                 (nil . "false")
                 (:null . "null")
                 ((1 2 3) . "[1,2,3]")
                 ((("a" . 1)) . "{\"a\":1}"))))
    (dolist (test tests)
      (let ((result (json-serialize (car test))))
        (format t "  ~s -> ~a ~a~%"
                (car test) result
                (if (string= result (cdr test)) "OK" "FAIL")))))

  ;; Test round-trip
  (format t "Round-trip test:~%")
  (let* ((obj '(("name" . "Modus")
                ("version" . 1)
                ("features" . ("tls" "websocket" "json"))))
         (json (json-serialize obj))
         (parsed (json-parse json)))
    (format t "  Original: ~s~%" obj)
    (format t "  JSON: ~a~%" json)
    (format t "  Parsed: ~s~%" parsed)
    (format t "  Match: ~a~%" (equal obj parsed)))

  (format t "~%JSON test complete.~%"))

