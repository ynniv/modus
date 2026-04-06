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

(in-package :modus.mvm)

(defvar *repl-source*
"
;;; ============================================================
;;; Entry point (MUST be first defun — boot code falls through)
;;; ============================================================

(defun spin-delay (n)
  (let ((i n))
    (loop
      (when (<= i 0) (return 0))
      (setq i (- i 1)))))

(defun beep-start ()
  (io-out-byte #x43 #xB6)
  (io-out-byte #x42 #xA9)
  (io-out-byte #x42 #x04)
  (io-out-byte #x61 (logior (io-in-byte #x61) 3)))

(defun beep-stop ()
  (io-out-byte #x61 (logand (io-in-byte #x61) #xFC)))

(defun beep-short ()
  (beep-start)
  (spin-delay 2000000)
  (beep-stop)
  (spin-delay 1500000))

(defun beep-version (n)
  (if (<= n 0) 0
    (progn (beep-short) (beep-version (- n 1)))))

(defun beep-success ()
  (spin-delay 2000000)
  (beep-start)
  (halt-loop))

(defun kernel-main ()
  ;; v31e: Fix BDSM(0xB0) + fill BDSM+DSPASURF + BAR2+DSPASURF (no reprogram)
  (write-newline)
  (let ((globals (cons nil nil)))
    (repl globals)))

;;; ============================================================
;;; I/O indirection: defaults to serial UART.
;;; Override read-char-input for keyboard, write-char-output for framebuffer.
;;; ============================================================

(defun read-char-input () (read-char-serial))
(defun write-char-output (c) (write-char-serial c))

;;; ============================================================
;;; Output helpers
;;; ============================================================

(defun write-string-codes (chars)
  (if (null chars)
      0
    (progn
      (write-char-output (car chars))
      (write-string-codes (cdr chars)))))

(defun write-newline ()
  (write-char-output 13)
  (write-char-output 10))

;;; ============================================================
;;; Numeric output
;;; ============================================================

(defun print-fixnum-pos (n)
  (when (> n 9)
    (let ((q (truncate n 10)))
      (print-fixnum-pos q)))
  (let ((d (mod n 10)))
    (let ((ch (+ d 48)))
      (write-char-output ch))))

(defun print-fixnum (n)
  (if (< n 0)
      (progn
        (write-char-output 45)
        (print-fixnum-pos (- 0 n)))
    (if (= n 0)
        (write-char-output 48)
      (print-fixnum-pos n))))

;;; ============================================================
;;; S-expression printer
;;; ============================================================

(defun print-list-tail (xs)
  (if (null xs)
      (write-char-output 41)
    (if (consp xs)
        (progn
          (write-char-output 32)
          (print-sexp (car xs))
          (print-list-tail (cdr xs)))
      (progn
        (write-char-output 32)
        (write-char-output 46)
        (write-char-output 32)
        (print-sexp xs)
        (write-char-output 41)))))

(defun print-sexp (x)
  (if (null x)
      (progn
        (write-char-output 110)
        (write-char-output 105)
        (write-char-output 108))
    (if (fixnump x)
        (print-fixnum x)
      (if (consp x)
          (if (= (car x) 9999)
              (write-string-codes (cdr x))
            (progn
              (write-char-output 40)
              (print-sexp (car x))
              (print-list-tail (cdr x))))
        (write-char-output 63)))))

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
        (write-char-output c)
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
          (write-char-output c)
          (let ((next (- c 48)))
            (let ((new-acc (+ (* acc 10) next)))
              (read-number-rest new-acc))))
      (progn
        (write-char-output c)
        (cons acc c)))))

(defun upcase (c)
  (if (and (>= c 97) (<= c 122))
      (- c 32)
    c))

(defun read-symbol-chars ()
  (let ((c (read-char-input)))
    (if (is-delimiter c)
        (progn
          (write-char-output c)
          (cons nil c))
      (progn
        (write-char-output c)
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
               (write-char-output c2)
               (let ((result (read-number c2)))
                 (let ((n (car result))
                       (term (cdr result)))
                   (cons (- 0 n) term))))
           (if (is-delimiter c2)
               (cons (mksym (cons 45 nil)) c2)
             (progn
               (write-char-output c2)
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
             (write-char-output c2)
             (let ((result (read-number c2)))
               (let ((n (car result))
                     (term (cdr result)))
                 (cons (- 0 n) term))))
         (if (is-delimiter c2)
             (cons (mksym (cons 45 nil)) c2)
           (progn
             (write-char-output c2)
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
  (let ((s0 sym))
    (let ((g0 globals))
      (if (null env)
          (lookup-in-alist s0 (cdr g0))
        (let ((binding (car env)))
          (if (symbol-eq s0 (car binding))
              (cdr binding)
            (lookup s0 (cdr env) g0)))))))

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
  (let ((aa args))
    (let ((ee env))
      (let ((gg globals))
        (if (null aa)
            nil
          (let ((v (eval-sexp (car aa) ee gg)))
            (cons v (eval-args (cdr aa) ee gg))))))))

(defun eval-sexp (x env globals)
  (let ((xx x))
    (let ((ee env))
      (let ((gg globals))
        (cond
          ((null xx) nil)
          ((fixnump xx) xx)
          ((is-sym xx)
           (lookup (sym-name xx) ee gg))
          ((not (consp xx)) xx)
          (t
           (let ((op (car xx)))
             (if (not (is-sym op))
                 (eval-call op (cdr xx) ee gg)
               (let ((name (sym-name op)))
                 (eval-special name xx ee gg))))))))))

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
  (let ((xx x))
    (let ((ee env))
      (let ((gg globals))
        (let ((fname (sym-name (cadr xx))))
          (let ((params (cadr (cdr xx))))
            (let ((body (cdr (cddr xx))))
              (let ((closure (make-closure params body ee)))
                (define-global gg fname closure)
                (cons 9999 fname)))))))))

(defun eval-special (name x env globals)
  (let ((nm name))
    (let ((xx x))
      (let ((ee env))
        (let ((gg globals))
  (cond
    ;; QUOTE
    ((symbol-eq nm (cons 81 (cons 85 (cons 79 (cons 84 (cons 69 nil))))))
     (cadr xx))
    ;; IF
    ((symbol-eq nm (cons 73 (cons 70 nil)))
     (let ((test-val (eval-sexp (cadr xx) ee gg)))
       (if test-val
           (eval-sexp (cadr (cdr xx)) ee gg)
         (if (cdr (cddr xx))
             (eval-sexp (cadr (cddr xx)) ee gg)
           nil))))
    ;; WHEN
    ((symbol-eq nm (cons 87 (cons 72 (cons 69 (cons 78 nil)))))
     (let ((test-val (eval-sexp (cadr xx) ee gg)))
       (if test-val
           (eval-body (cddr xx) ee gg)
         nil)))
    ;; PROGN
    ((symbol-eq nm (cons 80 (cons 82 (cons 79 (cons 71 (cons 78 nil))))))
     (eval-body (cdr xx) ee gg))
    ;; LET
    ((symbol-eq nm (cons 76 (cons 69 (cons 84 nil))))
     (eval-let (cadr xx) (cddr xx) ee gg))
    ;; DEFUN
    ((symbol-eq nm (cons 68 (cons 69 (cons 70 (cons 85 (cons 78 nil))))))
     (eval-defun xx ee gg))
    ;; LAMBDA
    ((symbol-eq nm (cons 76 (cons 65 (cons 77 (cons 66 (cons 68 (cons 65 nil)))))))
     (let ((params (cadr xx))
           (body (cddr xx)))
       (cons 8888 (cons params (cons body (cons ee nil))))))
    ;; +
    ((symbol-eq nm (cons 43 nil))
     (fold-add (eval-args (cdr xx) ee gg) 0))
    ;; -
    ((symbol-eq nm (cons 45 nil))
     (let ((vals (eval-args (cdr xx) ee gg)))
       (if (null (cdr vals))
           (- 0 (car vals))
         (fold-sub (cdr vals) (car vals)))))
    ;; *
    ((symbol-eq nm (cons 42 nil))
     (fold-mul (eval-args (cdr xx) ee gg) 1))
    ;; TRUNCATE
    ((symbol-eq nm (cons 84 (cons 82 (cons 85 (cons 78 (cons 67 (cons 65 (cons 84 (cons 69 nil)))))))))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (truncate a b)))
    ;; MOD
    ((symbol-eq nm (cons 77 (cons 79 (cons 68 nil))))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (mod a b)))
    ;; <
    ((symbol-eq nm (cons 60 nil))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (if (< a b) 1 nil)))
    ;; >
    ((symbol-eq nm (cons 62 nil))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (if (> a b) 1 nil)))
    ;; =
    ((symbol-eq nm (cons 61 nil))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (if (= a b) 1 nil)))
    ;; <=
    ((symbol-eq nm (cons 60 (cons 61 nil)))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (if (<= a b) 1 nil)))
    ;; >=
    ((symbol-eq nm (cons 62 (cons 61 nil)))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (if (>= a b) 1 nil)))
    ;; CONS
    ((symbol-eq nm (cons 67 (cons 79 (cons 78 (cons 83 nil)))))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (cons a b)))
    ;; CAR
    ((symbol-eq nm (cons 67 (cons 65 (cons 82 nil))))
     (car (eval-sexp (cadr xx) ee gg)))
    ;; CDR
    ((symbol-eq nm (cons 67 (cons 68 (cons 82 nil))))
     (cdr (eval-sexp (cadr xx) ee gg)))
    ;; NULL
    ((symbol-eq nm (cons 78 (cons 85 (cons 76 (cons 76 nil)))))
     (if (null (eval-sexp (cadr xx) ee gg)) 1 nil))
    ;; CONSP
    ((symbol-eq nm (cons 67 (cons 79 (cons 78 (cons 83 (cons 80 nil))))))
     (if (consp (eval-sexp (cadr xx) ee gg)) 1 nil))
    ;; ATOM
    ((symbol-eq nm (cons 65 (cons 84 (cons 79 (cons 77 nil)))))
     (if (atom (eval-sexp (cadr xx) ee gg)) 1 nil))
    ;; LIST
    ((symbol-eq nm (cons 76 (cons 73 (cons 83 (cons 84 nil)))))
     (eval-args (cdr xx) ee gg))
    ;; 1+
    ((symbol-eq nm (cons 49 (cons 43 nil)))
     (1+ (eval-sexp (cadr xx) ee gg)))
    ;; 1-
    ((symbol-eq nm (cons 49 (cons 45 nil)))
     (1- (eval-sexp (cadr xx) ee gg)))
    ;; EQ
    ((symbol-eq nm (cons 69 (cons 81 nil)))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (if (eq a b) 1 nil)))
    ;; NOT
    ((symbol-eq nm (cons 78 (cons 79 (cons 84 nil))))
     (if (eval-sexp (cadr xx) ee gg) nil 1))
    ;; AND
    ((symbol-eq nm (cons 65 (cons 78 (cons 68 nil))))
     (eval-and (cdr xx) ee gg))
    ;; OR
    ((symbol-eq nm (cons 79 (cons 82 nil)))
     (eval-or (cdr xx) ee gg))
    ;; COND
    ((symbol-eq nm (cons 67 (cons 79 (cons 78 (cons 68 nil)))))
     (eval-cond (cdr xx) ee gg))
    ;; SETQ  (sets in global env)
    ((symbol-eq nm (cons 83 (cons 69 (cons 84 (cons 81 nil)))))
     (let ((var-name (sym-name (cadr xx)))
           (val (eval-sexp (cadr (cdr xx)) ee gg)))
       (define-global gg var-name val)
       val))
    ;; LOGAND
    ((symbol-eq nm (cons 76 (cons 79 (cons 71 (cons 65 (cons 78 (cons 68 nil)))))))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (logand a b)))
    ;; LOGIOR
    ((symbol-eq nm (cons 76 (cons 79 (cons 71 (cons 73 (cons 79 (cons 82 nil)))))))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (logior a b)))
    ;; ASH
    ((symbol-eq nm (cons 65 (cons 83 (cons 72 nil))))
     (let ((a (eval-sexp (cadr xx) ee gg))
           (b (eval-sexp (cadr (cdr xx)) ee gg)))
       (ash a b)))
    ;; Otherwise: platform call, then global lookup
    (t
     (let ((evaled (eval-args (cdr xx) ee gg)))
       (let ((pres (eval-platform-call nm evaled)))
         (if (consp pres)
             (car pres)
           (let ((fn (lookup nm ee gg)))
             (if (null fn)
                 (progn
                   (write-string-codes (cons 69 (cons 82 (cons 82 (cons 58 (cons 32 nil))))))
                   (write-string-codes nm)
                   (write-newline)
                   nil)
               (apply-closure fn evaled gg)))))))))))))


(defun eval-call (op args env globals)
  (let ((a0 args))
    (let ((e0 env))
      (let ((g0 globals))
        (let ((fn (eval-sexp op e0 g0)))
          (let ((evaled-args (eval-args a0 e0 g0)))
            (apply-closure fn evaled-args g0)))))))

(defun apply-closure (fn args globals)
  (let ((g0 globals))
    (if (and (consp fn) (= (car fn) 8888))
        (let ((params (cadr fn))
              (body (cadr (cdr fn)))
              (closed-env (cadr (cddr fn))))
          (let ((new-env (bind-params params args closed-env)))
            (eval-body body new-env g0)))
      nil)))

(defun bind-params (params args env)
  (if (null params)
      env
    (let ((p (car params))
          (a (car args)))
      (let ((name (if (is-sym p) (sym-name p) p)))
        (cons (cons name a) (bind-params (cdr params) (cdr args) env))))))

(defun eval-body (forms env globals)
  (let ((ff forms))
    (let ((ee env))
      (let ((gg globals))
        (if (null ff)
            nil
          (if (null (cdr ff))
              (eval-sexp (car ff) ee gg)
            (progn
              (eval-sexp (car ff) ee gg)
              (eval-body (cdr ff) ee gg))))))))

(defun eval-let (bindings body env globals)
  (let ((b0 body))
    (let ((g0 globals))
      (let ((new-env (eval-let-bindings bindings env g0)))
        (eval-body b0 new-env g0)))))

(defun eval-let-bindings (bindings env globals)
  (let ((bb bindings))
    (let ((ee env))
      (let ((gg globals))
        (if (null bb)
            ee
          (let ((b (car bb)))
            (let ((var-name (if (is-sym (car b)) (sym-name (car b)) (car b)))
                  (val (eval-sexp (cadr b) ee gg)))
              (let ((new-env (cons (cons var-name val) ee)))
                (eval-let-bindings (cdr bb) new-env gg)))))))))

(defun eval-and (args env globals)
  (let ((aa args))
    (let ((ee env))
      (let ((gg globals))
        (if (null aa)
            1
          (let ((v (eval-sexp (car aa) ee gg)))
            (if (null v)
                nil
              (if (null (cdr aa))
                  v
                (eval-and (cdr aa) ee gg)))))))))

(defun eval-or (args env globals)
  (let ((aa args))
    (let ((ee env))
      (let ((gg globals))
        (if (null aa)
            nil
          (let ((v (eval-sexp (car aa) ee gg)))
            (if v
                v
              (eval-or (cdr aa) ee gg))))))))

(defun eval-cond (clauses env globals)
  (let ((cc clauses))
    (let ((ee env))
      (let ((gg globals))
        (if (null cc)
            nil
          (let ((clause (car cc)))
            (let ((test-val (eval-sexp (car clause) ee gg)))
              (if test-val
                  (eval-body (cdr clause) ee gg)
                (eval-cond (cdr cc) ee gg)))))))))

;;; ============================================================
;;; Platform call hook (override in platform-specific console source)
;;; Returns (cons result nil) if handled, nil if not handled.
;;; ============================================================

(defun eval-platform-call (name evaled-args)
  nil)

;;; ============================================================
;;; REPL
;;; ============================================================

(defun repl (globals)
  (let ((g globals))
    (write-char-output 62)
    (write-char-output 32)
    (let ((expr (read-sexp)))
      (write-newline)
      (let ((result (eval-sexp expr nil g)))
        (print-sexp result)
        (write-newline)
        (repl g)))))

")
