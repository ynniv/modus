;;;; repl-source.lisp - REPL source text for Raspberry Pi (AArch64) bare-metal
;;;;
;;;; Returns a string of MVM-compilable Lisp source that implements an
;;;; interactive Read-Eval-Print Loop over the serial port.
;;;;
;;;; The REPL uses char-code lists to represent symbols, an alist for
;;;; the environment, and a tree-walking evaluator.
;;;;
;;;; Since the MVM compiler has no global variables, mutable state (the
;;;; defun alist) is threaded through as a "globals" cons cell parameter.

(in-package :modus64.mvm)

(defvar *repl-source*
"
;;; ============================================================
;;; Entry point (MUST be first defun — boot code falls through)
;;; ============================================================

(defun kernel-main ()
  (write-string-codes (cons 77 (cons 111 (cons 100 (cons 117 (cons 115 (cons 54 (cons 52 (cons 32 (cons 82 (cons 69 (cons 80 (cons 76 nil)))))))))))))
  (write-newline)
  (let ((globals (cons nil nil)))
    (repl globals)))

;;; ============================================================
;;; Input indirection: read-char-input defaults to serial UART.
;;; HID build overrides this (loaded last wins) to poll USB keyboard.
;;; ============================================================

(defun read-char-input () (read-char-serial))

;;; ============================================================
;;; Output helpers
;;; ============================================================

(defun write-string-codes (chars)
  (if (null chars)
      0
    (progn
      (write-char-serial (car chars))
      (write-string-codes (cdr chars)))))

(defun write-newline ()
  (write-char-serial 13)
  (write-char-serial 10))

;;; ============================================================
;;; Numeric output
;;; ============================================================

(defun print-fixnum-pos (n)
  (when (> n 9)
    (let ((q (truncate n 10)))
      (print-fixnum-pos q)))
  (let ((d (mod n 10)))
    (let ((ch (+ d 48)))
      (write-char-serial ch))))

(defun print-fixnum (n)
  (if (< n 0)
      (progn
        (write-char-serial 45)
        (print-fixnum-pos (- 0 n)))
    (if (= n 0)
        (write-char-serial 48)
      (print-fixnum-pos n))))

;;; ============================================================
;;; S-expression printer
;;; ============================================================

(defun print-list-tail (xs)
  (if (null xs)
      (write-char-serial 41)
    (if (consp xs)
        (progn
          (write-char-serial 32)
          (print-sexp (car xs))
          (print-list-tail (cdr xs)))
      (progn
        (write-char-serial 32)
        (write-char-serial 46)
        (write-char-serial 32)
        (print-sexp xs)
        (write-char-serial 41)))))

(defun print-sexp (x)
  (if (null x)
      (progn
        (write-char-serial 110)
        (write-char-serial 105)
        (write-char-serial 108))
    (if (fixnump x)
        (print-fixnum x)
      (if (consp x)
          (if (= (car x) 9999)
              (write-string-codes (cdr x))
            (progn
              (write-char-serial 40)
              (print-sexp (car x))
              (print-list-tail (cdr x))))
        (write-char-serial 63)))))

;;; ============================================================
;;; Input helpers
;;; ============================================================

(defun is-whitespace (c)
  (or (= c 32) (= c 10) (= c 13) (= c 9)))

(defun is-digit (c)
  (and (>= c 48) (<= c 57)))

(defun is-delimiter (c)
  (or (= c 40) (= c 41) (is-whitespace c)))

(defun halt-loop ()
  (hlt)
  (halt-loop))

(defun read-skip-ws ()
  (let ((c (read-char-input)))
    (if (= c 4)
        (progn
          (write-newline)
          (write-string-codes (cons 72 (cons 97 (cons 108 (cons 116 (cons 101 (cons 100 (cons 46 nil))))))))
          (write-newline)
          (halt-loop))
      (progn
        (write-char-serial c)
        (if (is-whitespace c)
            (read-skip-ws)
          c)))))

;;; ============================================================
;;; Reader
;;; ============================================================
;;; read-number and read-symbol-chars return (value . terminator-char)
;;; where terminator is the delimiter/non-digit that ended the token.

(defun read-number (first-digit)
  (let ((acc (- first-digit 48)))
    (read-number-rest acc)))

(defun read-number-rest (acc)
  (let ((c (read-char-input)))
    (if (is-digit c)
        (progn
          (write-char-serial c)
          (let ((next (- c 48)))
            (let ((new-acc (+ (* acc 10) next)))
              (read-number-rest new-acc))))
      (progn
        (write-char-serial c)
        (cons acc c)))))

(defun upcase (c)
  (if (and (>= c 97) (<= c 122))
      (- c 32)
    c))

(defun read-symbol-chars ()
  (let ((c (read-char-input)))
    (if (is-delimiter c)
        (progn
          (write-char-serial c)
          (cons nil c))
      (progn
        (write-char-serial c)
        (let ((rest-result (read-symbol-chars)))
          (let ((chars (car rest-result))
                (term (cdr rest-result)))
            (cons (cons (upcase c) chars) term)))))))

(defun symbol-eq (a b)
  (if (null a)
      (null b)
    (if (null b)
        nil
      (if (= (car a) (car b))
          (symbol-eq (cdr a) (cdr b))
        nil))))

;;; read-sexp-with-term returns (value . terminator-char)
;;; terminator is 0 when consumed normally (e.g. list read its own ')' )

(defun mksym (chars)
  (cons 9999 chars))

(defun read-sexp-with-term ()
  (let ((c (read-skip-ws)))
    (cond
      ((= c 40)
       (cons (read-list) 0))
      ((= c 39)
       (let ((inner (read-sexp-with-term)))
         (let ((val (car inner))
               (term (cdr inner)))
           (cons (cons (mksym (cons 81 (cons 85 (cons 79 (cons 84 (cons 69 nil)))))) (cons val nil)) term))))
      ((is-digit c)
       (read-number c))
      ((= c 45)
       (let ((c2 (read-char-input)))
         (if (is-digit c2)
             (progn
               (write-char-serial c2)
               (let ((result (read-number c2)))
                 (let ((n (car result))
                       (term (cdr result)))
                   (cons (- 0 n) term))))
           (if (is-delimiter c2)
               (cons (mksym (cons 45 nil)) c2)
             (progn
               (write-char-serial c2)
               (let ((rest-result (read-symbol-chars)))
                 (let ((chars (car rest-result))
                       (term (cdr rest-result)))
                   (cons (mksym (cons 45 (cons (upcase c2) chars))) term))))))))
      (t
       (let ((uc (upcase c)))
         (let ((rest-result (read-symbol-chars)))
           (let ((chars (car rest-result))
                 (term (cdr rest-result)))
             (let ((name (cons uc chars)))
               (if (symbol-eq name (cons 78 (cons 73 (cons 76 nil))))
                   (cons nil term)
                 (cons (mksym name) term))))))))))

(defun read-sexp-inner (c)
  (cond
    ((= c 40)
     (cons (read-list) 0))
    ((= c 39)
     (let ((inner (read-sexp-with-term)))
       (let ((val (car inner))
             (term (cdr inner)))
         (cons (cons (mksym (cons 81 (cons 85 (cons 79 (cons 84 (cons 69 nil)))))) (cons val nil)) term))))
    ((is-digit c)
     (read-number c))
    ((= c 45)
     (let ((c2 (read-char-input)))
       (if (is-digit c2)
           (progn
             (write-char-serial c2)
             (let ((result (read-number c2)))
               (let ((n (car result))
                     (term (cdr result)))
                 (cons (- 0 n) term))))
         (if (is-delimiter c2)
             (cons (mksym (cons 45 nil)) c2)
           (progn
             (write-char-serial c2)
             (let ((rest-result (read-symbol-chars)))
               (let ((chars (car rest-result))
                     (term (cdr rest-result)))
                 (cons (mksym (cons 45 (cons (upcase c2) chars))) term))))))))
    (t
     (let ((uc (upcase c)))
       (let ((rest-result (read-symbol-chars)))
         (let ((chars (car rest-result))
               (term (cdr rest-result)))
           (let ((name (cons uc chars)))
             (if (symbol-eq name (cons 78 (cons 73 (cons 76 nil))))
                 (cons nil term)
               (cons (mksym name) term)))))))))

(defun read-list ()
  (let ((c (read-skip-ws)))
    (if (= c 41)
        nil
      (if (= c 46)
          (let ((result (read-sexp-with-term)))
            (let ((val (car result)))
              (read-skip-ws)
              val))
        (let ((result (read-sexp-inner c)))
          (let ((first-val (car result))
                (term (cdr result)))
            (if (= term 41)
                (cons first-val nil)
              (let ((rest-list (if (and (not (= term 0)) (is-delimiter term))
                                   (read-list-after-ws term)
                                 (read-list))))
                (cons first-val rest-list)))))))))

(defun read-list-after-ws (ws-char)
  (if (= ws-char 41)
      nil
    (read-list)))

(defun read-sexp ()
  (let ((result (read-sexp-with-term)))
    (car result)))

;;; ============================================================
;;; Environment
;;; ============================================================
;;; globals is a cons cell: (anchor . alist)
;;; Functions that modify globals use set-cdr on it.

(defun lookup (sym env globals)
  (if (null env)
      (lookup-in-alist sym (cdr globals))
    (let ((binding (car env)))
      (if (symbol-eq sym (car binding))
          (cdr binding)
        (lookup sym (cdr env) globals)))))

(defun lookup-in-alist (sym alist)
  (if (null alist)
      nil
    (let ((binding (car alist)))
      (if (symbol-eq sym (car binding))
          (cdr binding)
        (lookup-in-alist sym (cdr alist))))))

(defun define-global (globals sym val)
  (let ((new-entry (cons sym val)))
    (let ((old-cdr (cdr globals)))
      (let ((new-cdr (cons new-entry old-cdr)))
        (set-cdr globals new-cdr))))
  val)

;;; ============================================================
;;; Evaluator
;;; ============================================================

(defun sym-name (s)
  (cdr s))

(defun is-sym (x)
  (and (consp x) (= (car x) 9999)))

(defun eval-args (args env globals)
  (if (null args)
      nil
    (let ((v (eval-sexp (car args) env globals)))
      (cons v (eval-args (cdr args) env globals)))))

(defun eval-sexp (x env globals)
  (cond
    ((null x) nil)
    ((fixnump x) x)
    ((is-sym x)
     (lookup (sym-name x) env globals))
    ((not (consp x)) x)
    (t
     (let ((op (car x)))
       (if (not (is-sym op))
           (eval-call op (cdr x) env globals)
         (let ((name (sym-name op)))
           (eval-special name x env globals)))))))

(defun fold-add (vals acc)
  (if (null vals)
      acc
    (fold-add (cdr vals) (+ acc (car vals)))))

(defun fold-sub (vals acc)
  (if (null vals)
      acc
    (fold-sub (cdr vals) (- acc (car vals)))))

(defun fold-mul (vals acc)
  (if (null vals)
      acc
    (fold-mul (cdr vals) (* acc (car vals)))))

(defun make-closure (params body env)
  (let ((c1 (cons env nil)))
    (let ((c2 (cons body c1)))
      (let ((c3 (cons params c2)))
        (cons 8888 c3)))))

(defun eval-defun (x env globals)
  (let ((fname (sym-name (cadr x))))
    (let ((params (cadr (cdr x))))
      (let ((body (cdr (cddr x))))
        (let ((closure (make-closure params body env)))
          (define-global globals fname closure)
          (cons 9999 fname))))))

(defun eval-special (name x env globals)
  (cond
    ;; QUOTE
    ((symbol-eq name (cons 81 (cons 85 (cons 79 (cons 84 (cons 69 nil))))))
     (cadr x))
    ;; IF
    ((symbol-eq name (cons 73 (cons 70 nil)))
     (let ((test-val (eval-sexp (cadr x) env globals)))
       (if test-val
           (eval-sexp (cadr (cdr x)) env globals)
         (if (cdr (cddr x))
             (eval-sexp (cadr (cddr x)) env globals)
           nil))))
    ;; WHEN
    ((symbol-eq name (cons 87 (cons 72 (cons 69 (cons 78 nil)))))
     (let ((test-val (eval-sexp (cadr x) env globals)))
       (if test-val
           (eval-body (cddr x) env globals)
         nil)))
    ;; PROGN
    ((symbol-eq name (cons 80 (cons 82 (cons 79 (cons 71 (cons 78 nil))))))
     (eval-body (cdr x) env globals))
    ;; LET
    ((symbol-eq name (cons 76 (cons 69 (cons 84 nil))))
     (eval-let (cadr x) (cddr x) env globals))
    ;; DEFUN
    ((symbol-eq name (cons 68 (cons 69 (cons 70 (cons 85 (cons 78 nil))))))
     (eval-defun x env globals))
    ;; LAMBDA
    ((symbol-eq name (cons 76 (cons 65 (cons 77 (cons 66 (cons 68 (cons 65 nil)))))))
     (let ((params (cadr x))
           (body (cddr x)))
       (cons 8888 (cons params (cons body (cons env nil))))))
    ;; +
    ((symbol-eq name (cons 43 nil))
     (fold-add (eval-args (cdr x) env globals) 0))
    ;; -
    ((symbol-eq name (cons 45 nil))
     (let ((vals (eval-args (cdr x) env globals)))
       (if (null (cdr vals))
           (- 0 (car vals))
         (fold-sub (cdr vals) (car vals)))))
    ;; *
    ((symbol-eq name (cons 42 nil))
     (fold-mul (eval-args (cdr x) env globals) 1))
    ;; TRUNCATE
    ((symbol-eq name (cons 84 (cons 82 (cons 85 (cons 78 (cons 67 (cons 65 (cons 84 (cons 69 nil)))))))))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (truncate a b)))
    ;; MOD
    ((symbol-eq name (cons 77 (cons 79 (cons 68 nil))))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (mod a b)))
    ;; <
    ((symbol-eq name (cons 60 nil))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (if (< a b) 1 nil)))
    ;; >
    ((symbol-eq name (cons 62 nil))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (if (> a b) 1 nil)))
    ;; =
    ((symbol-eq name (cons 61 nil))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (if (= a b) 1 nil)))
    ;; <=
    ((symbol-eq name (cons 60 (cons 61 nil)))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (if (<= a b) 1 nil)))
    ;; >=
    ((symbol-eq name (cons 62 (cons 61 nil)))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (if (>= a b) 1 nil)))
    ;; CONS
    ((symbol-eq name (cons 67 (cons 79 (cons 78 (cons 83 nil)))))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (cons a b)))
    ;; CAR
    ((symbol-eq name (cons 67 (cons 65 (cons 82 nil))))
     (car (eval-sexp (cadr x) env globals)))
    ;; CDR
    ((symbol-eq name (cons 67 (cons 68 (cons 82 nil))))
     (cdr (eval-sexp (cadr x) env globals)))
    ;; NULL
    ((symbol-eq name (cons 78 (cons 85 (cons 76 (cons 76 nil)))))
     (if (null (eval-sexp (cadr x) env globals)) 1 nil))
    ;; CONSP
    ((symbol-eq name (cons 67 (cons 79 (cons 78 (cons 83 (cons 80 nil))))))
     (if (consp (eval-sexp (cadr x) env globals)) 1 nil))
    ;; ATOM
    ((symbol-eq name (cons 65 (cons 84 (cons 79 (cons 77 nil)))))
     (if (atom (eval-sexp (cadr x) env globals)) 1 nil))
    ;; LIST
    ((symbol-eq name (cons 76 (cons 73 (cons 83 (cons 84 nil)))))
     (eval-args (cdr x) env globals))
    ;; 1+
    ((symbol-eq name (cons 49 (cons 43 nil)))
     (1+ (eval-sexp (cadr x) env globals)))
    ;; 1-
    ((symbol-eq name (cons 49 (cons 45 nil)))
     (1- (eval-sexp (cadr x) env globals)))
    ;; EQ
    ((symbol-eq name (cons 69 (cons 81 nil)))
     (let ((a (eval-sexp (cadr x) env globals))
           (b (eval-sexp (cadr (cdr x)) env globals)))
       (if (eq a b) 1 nil)))
    ;; NOT
    ((symbol-eq name (cons 78 (cons 79 (cons 84 nil))))
     (if (eval-sexp (cadr x) env globals) nil 1))
    ;; AND
    ((symbol-eq name (cons 65 (cons 78 (cons 68 nil))))
     (eval-and (cdr x) env globals))
    ;; OR
    ((symbol-eq name (cons 79 (cons 82 nil)))
     (eval-or (cdr x) env globals))
    ;; COND
    ((symbol-eq name (cons 67 (cons 79 (cons 78 (cons 68 nil)))))
     (eval-cond (cdr x) env globals))
    ;; SETQ  (sets in global env)
    ((symbol-eq name (cons 83 (cons 69 (cons 84 (cons 81 nil)))))
     (let ((var-name (sym-name (cadr x)))
           (val (eval-sexp (cadr (cdr x)) env globals)))
       (define-global globals var-name val)
       val))
    ;; Otherwise: function call via global lookup
    (t
     (let ((fn (lookup name env globals)))
       (if (null fn)
           (progn
             (write-string-codes (cons 69 (cons 82 (cons 82 (cons 58 (cons 32 nil))))))
             (write-string-codes name)
             (write-newline)
             nil)
         (let ((args (eval-args (cdr x) env globals)))
           (apply-closure fn args globals)))))))

(defun eval-call (op args env globals)
  (let ((fn (eval-sexp op env globals))
        (evaled-args (eval-args args env globals)))
    (apply-closure fn evaled-args globals)))

(defun apply-closure (fn args globals)
  (if (and (consp fn) (= (car fn) 8888))
      (let ((params (cadr fn))
            (body (cadr (cdr fn)))
            (closed-env (cadr (cddr fn))))
        (let ((new-env (bind-params params args closed-env)))
          (eval-body body new-env globals)))
    nil))

(defun bind-params (params args env)
  (if (null params)
      env
    (let ((p (car params))
          (a (car args)))
      (let ((name (if (is-sym p) (sym-name p) p)))
        (cons (cons name a) (bind-params (cdr params) (cdr args) env))))))

(defun eval-body (forms env globals)
  (if (null forms)
      nil
    (if (null (cdr forms))
        (eval-sexp (car forms) env globals)
      (progn
        (eval-sexp (car forms) env globals)
        (eval-body (cdr forms) env globals)))))

(defun eval-let (bindings body env globals)
  (let ((new-env (eval-let-bindings bindings env globals)))
    (eval-body body new-env globals)))

(defun eval-let-bindings (bindings env globals)
  (if (null bindings)
      env
    (let ((b (car bindings)))
      (let ((var-name (if (is-sym (car b)) (sym-name (car b)) (car b)))
            (val (eval-sexp (cadr b) env globals)))
        (let ((new-env (cons (cons var-name val) env)))
          (eval-let-bindings (cdr bindings) new-env globals))))))

(defun eval-and (args env globals)
  (if (null args)
      1
    (let ((v (eval-sexp (car args) env globals)))
      (if (null v)
          nil
        (if (null (cdr args))
            v
          (eval-and (cdr args) env globals))))))

(defun eval-or (args env globals)
  (if (null args)
      nil
    (let ((v (eval-sexp (car args) env globals)))
      (if v
          v
        (eval-or (cdr args) env globals)))))

(defun eval-cond (clauses env globals)
  (if (null clauses)
      nil
    (let ((clause (car clauses)))
      (let ((test-val (eval-sexp (car clause) env globals)))
        (if test-val
            (eval-body (cdr clause) env globals)
          (eval-cond (cdr clauses) env globals))))))

;;; ============================================================
;;; REPL
;;; ============================================================

(defun repl (globals)
  (write-char-serial 62)
  (write-char-serial 32)
  (let ((expr (read-sexp)))
    (write-newline)
    (let ((result (eval-sexp expr nil globals)))
      (print-sexp result)
      (write-newline)
      (repl globals))))

")
