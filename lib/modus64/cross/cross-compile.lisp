;;;; cross-compile.lisp - Modus64 Cross-Compiler
;;;;
;;;; Compiles Lisp forms to x86-64 machine code.
;;;; Runs on SBCL, produces kernel image for Modus64.
;;;;
;;;; This is a minimal "throwaway" compiler for bootstrap only.
;;;; Once the system is self-hosting, this code is not used.

;; Package defined in packages.lisp

(in-package :modus64.cross)

;;; ============================================================
;;; Tagging Scheme (from 64-bit-master-design.md)
;;; ============================================================
;;;
;;; xxx0 = Fixnum (63-bit signed integer, shifted left 1)
;;; 0001 = Cons pointer
;;; 1001 = Object pointer (general heap object)
;;; 0101 = Immediate (char, single-float)
;;; 1111 = GC forwarding pointer
;;;
;;; NIL is a special symbol at a known address
;;; T is a special symbol at a known address

(defconstant +tag-fixnum+    #b0000)  ; Low bit 0
(defconstant +tag-cons+      #b0001)
(defconstant +tag-object+    #b1001)
(defconstant +tag-immediate+ #b0101)  ; Characters use this
(defconstant +tag-forward+   #b1111)

(defconstant +fixnum-shift+ 1)        ; Fixnums shifted left by 1
(defconstant +char-shift+ 8)          ; Characters: code in bits 8+, tag in low 8 bits
(defconstant +char-tag+ #x05)         ; Character tag in low byte

;; NIL and T will be at fixed addresses in the wired area
;; For now, use placeholders (filled in during image building)
(defconstant +nil-placeholder+ #xDEAD0001)  ; Tagged as cons (special nil)
(defconstant +t-placeholder+   #xDEAD1009)  ; Tagged as object (symbol)

;;; ============================================================
;;; Register Allocation (from calling-convention-design.md)
;;; ============================================================
;;;
;;; Arguments:    RSI (arg0), RDI (arg1), R8 (arg2), R9 (arg3)
;;; Arg count:    RCX (as fixnum, shifted)
;;; Return value: RAX
;;; Function:     R13 (current function pointer)
;;; Allocation:   R12 (allocation pointer)
;;; Alloc limit:  R14 (for GC check)
;;; NIL:          R15 (always points to NIL)
;;; Scratch:      RAX, RDX, R10, R11
;;; Callee-saved: RBX, RBP, R12, R13, R14, R15

(defparameter +arg-regs+ '(rsi rdi r8 r9))
(defparameter +nargs-reg+ 'rcx)
(defparameter +return-reg+ 'rax)
(defparameter +fn-reg+ 'r13)
(defparameter +alloc-reg+ 'r12)
(defparameter +limit-reg+ 'r14)
(defparameter +nil-reg+ 'r15)
(defconstant +nargregs+ 4)

;;; ============================================================
;;; Compilation State
;;; ============================================================

(defvar *code-buffer* nil
  "Current code buffer being compiled into")

(defvar *functions* (make-hash-table :test 'eq)
  "Map from function name to compiled code position")

(defvar *constants* nil
  "List of constants that need to be allocated in the image")

(defvar *current-function* nil
  "Name of function currently being compiled")

;;; ============================================================
;;; Compilation Environment
;;; ============================================================
;;;
;;; Tracks variable bindings during compilation.
;;; Variables can be:
;;;   - In a register (for arguments)
;;;   - On the stack (for locals)

(defstruct binding
  name                 ; Symbol name
  location             ; :reg or :stack
  reg                  ; Register if location = :reg
  stack-offset)        ; Stack offset if location = :stack

(defstruct compile-env
  (bindings nil)       ; List of bindings
  (stack-depth 0)      ; Current stack depth (in 8-byte slots)
  (parent nil))        ; Parent environment

(defun make-empty-env ()
  (make-compile-env))

(defun env-lookup (env name)
  "Find binding for NAME in ENV, or nil"
  (when env
    (or (find name (compile-env-bindings env) :key #'binding-name)
        (env-lookup (compile-env-parent env) name))))

(defun env-extend (env name location &key reg stack-offset)
  "Add a binding to ENV, returning new ENV"
  (let ((new-env (make-compile-env
                  :bindings (cons (make-binding :name name
                                                :location location
                                                :reg reg
                                                :stack-offset stack-offset)
                                  (compile-env-bindings env))
                  :stack-depth (compile-env-stack-depth env)
                  :parent (compile-env-parent env))))
    new-env))

(defun env-with-stack-slot (env name)
  "Allocate a stack slot for NAME"
  (let* ((depth (compile-env-stack-depth env))
         (new-env (make-compile-env
                   :bindings (cons (make-binding :name name
                                                 :location :stack
                                                 ;; Offset from RBP: first local at [rbp-8]
                                                 :stack-offset (* (1+ depth) 8))
                                   (compile-env-bindings env))
                   :stack-depth (1+ depth)
                   :parent (compile-env-parent env))))
    new-env))

;;; ============================================================
;;; Code Generation Helpers
;;; ============================================================

(defun emit-tag-fixnum (buf reg)
  "Tag value in REG as fixnum (shift left 1)"
  (emit-shl-reg-imm buf reg +fixnum-shift+))

(defun emit-untag-fixnum (buf reg)
  "Untag fixnum in REG (arithmetic shift right 1)"
  (emit-sar-reg-imm buf reg +fixnum-shift+))

(defun emit-load-nil (buf dst)
  "Load NIL into DST"
  (emit-mov-reg-reg buf dst +nil-reg+))

(defun emit-load-fixnum (buf dst value)
  "Load a fixnum VALUE into DST (pre-tagged)"
  (emit-mov-reg-imm buf dst (ash value +fixnum-shift+)))

(defun emit-load-constant (buf dst const)
  "Load a constant into DST. Returns a fixup for later patching."
  (cond
    ((null const)
     (emit-load-nil buf dst))
    ((eq const t)
     ;; T is a symbol - for now use placeholder
     (emit-mov-reg-imm buf dst +t-placeholder+))
    ((integerp const)
     (emit-load-fixnum buf dst const))
    (t
     ;; Other constants need to be placed in the constant area
     (push const *constants*)
     (emit-mov-reg-imm buf dst 0)))) ; Placeholder, fixed up later

;;; ============================================================
;;; Form Compilation
;;; ============================================================

(defun compile-form (form env)
  "Compile FORM in environment ENV. Result goes to RAX."
  (cond
    ;; Self-evaluating
    ((null form)
     (emit-load-nil *code-buffer* 'rax))

    ((eq form t)
     (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+))

    ((integerp form)
     (emit-load-fixnum *code-buffer* 'rax form))

    ;; Keywords self-evaluate to themselves (as tagged immediate)
    ((keywordp form)
     ;; Keywords are just encoded as their hash or ordinal
     ;; For simplicity, we use the symbol-hash
     (emit-mov-reg-imm *code-buffer* 'rax (sxhash form)))

    ;; Variable reference
    ((symbolp form)
     (compile-variable-ref form env))

    ;; Special forms and function calls
    ((consp form)
     (let* ((op (car form))
            (op-name (and (symbolp op) (symbol-name op))))
       ;; Use string-equal for cross-package compatibility
       (cond
         ((string-equal op-name "QUOTE")    (compile-quote (cadr form)))
         ((string-equal op-name "IF")       (compile-if (cdr form) env))
         ((string-equal op-name "PROGN")    (compile-progn (cdr form) env))
         ((string-equal op-name "LET")      (compile-let (cadr form) (cddr form) env))
         ((string-equal op-name "LET*")     (compile-let* (cadr form) (cddr form) env))
         ((string-equal op-name "SETQ")     (compile-setq (cadr form) (caddr form) env))
         ((string-equal op-name "LAMBDA")   (compile-lambda (cadr form) (cddr form) env))
         ;; Primitive operations (inline)
         ((string-equal op-name "+")        (compile-binop 'add (cdr form) env))
         ((string-equal op-name "-")        (compile-binop 'sub (cdr form) env))
         ((string-equal op-name "*")        (compile-mul (cdr form) env))
         ((string-equal op-name "1+")       (compile-1+ (cadr form) env))
         ((string-equal op-name "1-")       (compile-1- (cadr form) env))
         ((string-equal op-name "<")        (compile-compare :l (cdr form) env))
         ((string-equal op-name ">")        (compile-compare :g (cdr form) env))
         ((string-equal op-name "=")        (compile-compare :e (cdr form) env))
         ((string-equal op-name "<=")       (compile-compare :le (cdr form) env))
         ((string-equal op-name ">=")       (compile-compare :ge (cdr form) env))
         ((string-equal op-name "EQ")       (compile-eq (cdr form) env))
         ((string-equal op-name "CAR")      (compile-car (cadr form) env))
         ((string-equal op-name "CDR")      (compile-cdr (cadr form) env))
         ((string-equal op-name "SET-CDR")  (compile-set-cdr form env))
         ((string-equal op-name "SET-CAR")  (compile-set-car form env))
         ((string-equal op-name "CAAR")     (compile-caar (cadr form) env))
         ((string-equal op-name "CADR")     (compile-cadr (cadr form) env))
         ((string-equal op-name "CDAR")     (compile-cdar (cadr form) env))
         ((string-equal op-name "CDDR")     (compile-cddr (cadr form) env))
         ((string-equal op-name "CONS")     (compile-cons (cadr form) (caddr form) env))
         ;; Bitwise operations
         ((string-equal op-name "LOGAND")   (compile-logand (cdr form) env))
         ((string-equal op-name "LOGIOR")   (compile-logior (cdr form) env))
         ((string-equal op-name "LOGXOR")   (compile-logxor (cdr form) env))
         ((string-equal op-name "ASH")      (compile-ash (cadr form) (caddr form) env))
         ((string-equal op-name "LDB")      (compile-ldb (cadr form) (caddr form) env))
         ;; Memory operations
         ((string-equal op-name "MEM-REF")  (compile-mem-ref (cadr form) (caddr form) env))
         ((string-equal op-name "SETF")     (compile-setf (cadr form) (caddr form) env))
         ;; I/O port operations
         ((string-equal op-name "IO-OUT-BYTE") (compile-io-out-byte (cadr form) (caddr form) env))
         ((string-equal op-name "IO-IN-BYTE")  (compile-io-in-byte (cadr form) env))
         ((string-equal op-name "IO-OUT-DWORD") (compile-io-out-dword (cadr form) (caddr form) env))
         ((string-equal op-name "IO-IN-DWORD")  (compile-io-in-dword (cadr form) env))
         ;; System registers
         ((string-equal op-name "GET-ALLOC-PTR") (compile-get-alloc-ptr))
         ((string-equal op-name "GET-ALLOC-LIMIT") (compile-get-alloc-limit))
         ((string-equal op-name "SET-ALLOC-PTR") (compile-set-alloc-ptr (cadr form) env))
         ((string-equal op-name "SET-ALLOC-LIMIT") (compile-set-alloc-limit (cadr form) env))
         ((string-equal op-name "UNTAG") (compile-untag (cadr form) env))
         ;; Actor context switch primitives
         ((string-equal op-name "SAVE-CONTEXT") (compile-save-context (cadr form) env))
         ((string-equal op-name "RESTORE-CONTEXT") (compile-restore-context (cadr form) env))
         ;; Call native code: (call-native addr arg1 arg2)
         ((string-equal op-name "CALL-NATIVE") (compile-call-native (cdr form) env))
         ;; Control flow
         ((string-equal op-name "LOOP")     (compile-loop (cdr form) env))
         ((string-equal op-name "RETURN")   (compile-return (cadr form) env))
         ((string-equal op-name "BLOCK")    (compile-block (cadr form) (cddr form) env))
         ((string-equal op-name "TAGBODY")  (compile-tagbody (cdr form) env))
         ((string-equal op-name "GO")       (compile-go (cadr form) env))
         ;; Misc
         ((string-equal op-name "NOT")      (compile-not (cadr form) env))
         ((string-equal op-name "ZEROP")    (compile-zerop (cadr form) env))
         ;; Type predicates
         ((string-equal op-name "NULL")     (compile-null (cadr form) env))
         ((string-equal op-name "CONSP")    (compile-consp (cadr form) env))
         ((string-equal op-name "FIXNUMP")  (compile-fixnump (cadr form) env))
         ((string-equal op-name "ATOM")     (compile-atom (cadr form) env))
         ((string-equal op-name "LISTP")    (compile-listp (cadr form) env))
         ((string-equal op-name "BIGNUMP")  (compile-bignump (cadr form) env))
         ((string-equal op-name "STRINGP") (compile-stringp (cadr form) env))
         ((string-equal op-name "ARRAYP")  (compile-arrayp (cadr form) env))
         ((string-equal op-name "INTEGERP") (compile-integerp (cadr form) env))
         ;; Character operations
         ((string-equal op-name "CHARACTERP") (compile-characterp (cadr form) env))
         ((string-equal op-name "CHAR-CODE")  (compile-char-code (cadr form) env))
         ((string-equal op-name "CODE-CHAR")  (compile-code-char (cadr form) env))
         ;; Division operations
         ((string-equal op-name "TRUNCATE")  (compile-truncate (cdr form) env))
         ((string-equal op-name "MOD")       (compile-mod (cdr form) env))
         ;; Control flow extensions
         ((string-equal op-name "WHEN")      (compile-when (cdr form) env))
         ((string-equal op-name "UNLESS")    (compile-unless (cdr form) env))
         ((string-equal op-name "DOTIMES")   (compile-dotimes (cadr form) (cddr form) env))
         ;; Higher-order functions
         ((string-equal op-name "FUNCTION")  (compile-function-ref (cadr form) env))
         ((string-equal op-name "FUNCALL")   (compile-funcall (cdr form) env))
         ;; SMP primitives
         ((string-equal op-name "XCHG-MEM")  (compile-xchg-mem (cadr form) (caddr form) env))
         ((string-equal op-name "PAUSE")     (compile-pause))
         ((string-equal op-name "MFENCE")    (compile-mfence))
         ((string-equal op-name "HLT")       (compile-hlt))
         ((string-equal op-name "WRMSR")     (compile-wrmsr (cdr form) env))
         ((string-equal op-name "PERCPU-REF") (compile-percpu-ref (cadr form) env))
         ((string-equal op-name "PERCPU-SET") (compile-percpu-set (cadr form) (caddr form) env))
         ;; Interrupt control
         ((string-equal op-name "STI")       (compile-sti))
         ((string-equal op-name "CLI")       (compile-cli))
         ((string-equal op-name "STI-HLT")  (compile-sti-hlt))
         ((string-equal op-name "SWITCH-IDLE-STACK") (compile-switch-idle-stack))
         ((string-equal op-name "SET-RSP")   (compile-set-rsp (cadr form) env))
         ((string-equal op-name "LIDT")      (compile-lidt (cadr form) env))
         ;; Function call
         (t (compile-call op (cdr form) env)))))

    (t
     (error "Cannot compile: ~S" form))))

;;; ============================================================
;;; Variable Reference
;;; ============================================================

(defun compile-variable-ref (name env)
  "Compile a variable reference"
  (let ((binding (env-lookup env name)))
    (unless binding
      (error "Undefined variable: ~A" name))
    (ecase (binding-location binding)
      (:reg
       (unless (eq (binding-reg binding) 'rax)
         (emit-mov-reg-reg *code-buffer* 'rax (binding-reg binding))))
      (:stack
       (emit-mov-reg-mem *code-buffer* 'rax 'rbp (- (binding-stack-offset binding)))))))

;;; ============================================================
;;; Quote
;;; ============================================================

(defun compile-quote (value)
  "Compile (quote VALUE)"
  (emit-load-constant *code-buffer* 'rax value))

;;; ============================================================
;;; If
;;; ============================================================

(defun compile-if (args env)
  "Compile (if test then &optional else)"
  (destructuring-bind (test then &optional else) args
    (let ((else-label (make-label))
          (end-label (make-label)))
      ;; Compile test
      (compile-form test env)
      ;; Compare to NIL
      (emit-cmp-reg-reg *code-buffer* 'rax +nil-reg+)
      (emit-jcc *code-buffer* :e else-label)
      ;; Then branch
      (compile-form then env)
      (emit-jmp *code-buffer* end-label)
      ;; Else branch
      (emit-label *code-buffer* else-label)
      (if else
          (compile-form else env)
          (emit-load-nil *code-buffer* 'rax))
      ;; End
      (emit-label *code-buffer* end-label))))

;;; ============================================================
;;; Progn
;;; ============================================================

(defun compile-progn (forms env)
  "Compile (progn form*)"
  (if (null forms)
      (emit-load-nil *code-buffer* 'rax)
      (dolist (form forms)
        (compile-form form env))))

;;; ============================================================
;;; Let / Let*
;;; ============================================================

(defun compile-let (bindings body env)
  "Compile (let ((var val)*) body*)"
  (let ((new-env env)
        (n-bindings (length bindings))
        (base-depth (compile-env-stack-depth env)))
    ;; Allocate stack space with zeros (PUSH 0 instead of SUB RSP)
    ;; This prevents GC from seeing uninitialized garbage as heap pointers
    ;; when a make-array call triggers GC before all let bindings are evaluated
    (when (> n-bindings 0)
      (dotimes (i n-bindings)
        (emit-bytes *code-buffer* #x6A #x00)))  ; push 0 (8-byte zero)
    ;; Evaluate all values and store them
    ;; Store relative to RBP for consistency with variable loading
    (loop for (var val) in bindings
          for i from 0
          do (compile-form val env)  ; Use original env
             ;; Store at [rbp - (base_depth + i + 1) * 8]
             (emit-mov-mem-reg *code-buffer* 'rbp 'rax (- (* (+ base-depth i 1) 8)))
             (setf new-env (env-with-stack-slot new-env var)))
    ;; Compile body with new environment
    (compile-progn body new-env)
    ;; Deallocate stack space
    (when (> n-bindings 0)
      (emit-add-reg-imm *code-buffer* 'rsp (* n-bindings 8)))))

(defun compile-let* (bindings body env)
  "Compile (let* ((var val)*) body*)"
  (let ((new-env env)
        (n-bindings (length bindings))
        (base-depth (compile-env-stack-depth env)))
    ;; Allocate stack space with zeros (PUSH 0 instead of SUB RSP)
    ;; Prevents GC from seeing uninitialized garbage as heap pointers
    (when (> n-bindings 0)
      (dotimes (i n-bindings)
        (emit-bytes *code-buffer* #x6A #x00)))  ; push 0 (8-byte zero)
    ;; Evaluate values sequentially, extending env each time
    (loop for (var val) in bindings
          for i from 0
          do (compile-form val new-env)  ; Use extending env
             ;; Store at [rbp - (base_depth + i + 1) * 8]
             (emit-mov-mem-reg *code-buffer* 'rbp 'rax (- (* (+ base-depth i 1) 8)))
             (setf new-env (env-with-stack-slot new-env var)))
    ;; Compile body
    (compile-progn body new-env)
    ;; Deallocate
    (when (> n-bindings 0)
      (emit-add-reg-imm *code-buffer* 'rsp (* n-bindings 8)))))

;;; ============================================================
;;; Setq
;;; ============================================================

(defun compile-setq (var val env)
  "Compile (setq var val)"
  (compile-form val env)
  (let ((binding (env-lookup env var)))
    (unless binding
      (error "Undefined variable: ~A" var))
    (ecase (binding-location binding)
      (:reg
       (unless (eq (binding-reg binding) 'rax)
         (emit-mov-reg-reg *code-buffer* (binding-reg binding) 'rax)))
      (:stack
       (emit-mov-mem-reg *code-buffer* 'rbp 'rax (- (binding-stack-offset binding)))))))

;;; ============================================================
;;; Lambda (creates closure)
;;; ============================================================

(defun compile-lambda (params body env)
  "Compile (lambda (args) body*) - creates a closure"
  (declare (ignore env))  ; TODO: Use env for captured variables
  ;; For now, just compile as a nested function
  ;; Full closures need heap allocation
  (let ((fn-label (make-label)))
    ;; Jump over the function body
    (let ((after-label (make-label)))
      (emit-jmp *code-buffer* after-label)
      ;; Function entry point
      (emit-label *code-buffer* fn-label)
      ;; Set up stack frame
      (emit-push *code-buffer* 'rbp)
      (emit-mov-reg-reg *code-buffer* 'rbp 'rsp)
      ;; Build environment with parameters in registers
      (let ((fn-env (make-empty-env)))
        (loop for param in params
              for reg in +arg-regs+
              for i from 0
              while (< i +nargregs+)
              do (setf fn-env (env-extend fn-env param :reg :reg reg)))
        ;; Compile body
        (compile-progn body fn-env))
      ;; Clean up and return
      (emit-mov-reg-reg *code-buffer* 'rsp 'rbp)
      (emit-pop *code-buffer* 'rbp)
      (emit-ret *code-buffer*)
      ;; After the lambda
      (emit-label *code-buffer* after-label))
    ;; Load function address (as closure object - for now just raw address)
    ;; TODO: Proper closure allocation
    (emit-lea *code-buffer* 'rax fn-label)))

;;; ============================================================
;;; Arithmetic Operations
;;; ============================================================

(defun compile-binop (op args env)
  "Compile binary arithmetic: +, -"
  (when (null args)
    (emit-load-fixnum *code-buffer* 'rax 0)
    (return-from compile-binop))
  (when (null (cdr args))
    (compile-form (car args) env)
    (return-from compile-binop))
  ;; Two or more args
  (compile-form (car args) env)
  (emit-push *code-buffer* 'rax)
  (compile-form (cadr args) env)
  (emit-pop *code-buffer* 'rdx)
  ;; For fixnums: (a << 1) op (b << 1) = (a op b) << 1 for +/-
  ;; So we can operate directly on tagged values
  (ecase op
    (add (emit-add-reg-reg *code-buffer* 'rax 'rdx))
    (sub (emit-sub-reg-reg *code-buffer* 'rdx 'rax)
         (emit-mov-reg-reg *code-buffer* 'rax 'rdx)))
  ;; Handle more than 2 args
  (dolist (arg (cddr args))
    (emit-push *code-buffer* 'rax)
    (compile-form arg env)
    (emit-pop *code-buffer* 'rdx)
    (ecase op
      (add (emit-add-reg-reg *code-buffer* 'rax 'rdx))
      (sub (emit-sub-reg-reg *code-buffer* 'rdx 'rax)
           (emit-mov-reg-reg *code-buffer* 'rax 'rdx)))))

(defun compile-1+ (arg env)
  "Compile (1+ x)"
  (compile-form arg env)
  ;; Add 2 (which is fixnum 1)
  (emit-add-reg-imm *code-buffer* 'rax 2))

(defun compile-1- (arg env)
  "Compile (1- x)"
  (compile-form arg env)
  (emit-sub-reg-imm *code-buffer* 'rax 2))

(defun compile-mul (args env)
  "Compile (* a b ...) for tagged fixnums.
   For tagged values: a*b = ((a>>1)*(b>>1))<<1
   Since both inputs are tagged: result = (a*b)>>1"
  (when (null args)
    (emit-load-fixnum *code-buffer* 'rax 1)  ; (* ) = 1
    (return-from compile-mul))
  (when (null (cdr args))
    (compile-form (car args) env)
    (return-from compile-mul))
  ;; Two or more args
  (compile-form (car args) env)
  (emit-push *code-buffer* 'rax)
  (compile-form (cadr args) env)
  (emit-pop *code-buffer* 'rdx)
  ;; IMUL RAX, RDX: RAX = RAX * RDX
  ;; REX.W + 0F AF /r
  (emit-bytes *code-buffer* #x48 #x0F #xAF #xC2)  ; imul rax, rdx
  ;; Fix tagging: shift right by 1
  (emit-sar-reg-imm *code-buffer* 'rax 1)
  ;; Handle more than 2 args
  (dolist (arg (cddr args))
    (emit-push *code-buffer* 'rax)
    (compile-form arg env)
    (emit-pop *code-buffer* 'rdx)
    (emit-bytes *code-buffer* #x48 #x0F #xAF #xC2)  ; imul rax, rdx
    (emit-sar-reg-imm *code-buffer* 'rax 1)))

;;; ============================================================
;;; Division Operations
;;; ============================================================

(defun compile-truncate (args env)
  "Compile (truncate a b) - integer division, quotient in RAX"
  (destructuring-bind (a b) args
    (compile-form a env)
    (emit-push *code-buffer* 'rax)
    (compile-form b env)
    ;; RAX = b (divisor), stack top = a (dividend)
    (emit-sar-reg-imm *code-buffer* 'rax 1)  ; untag divisor
    (emit-bytes *code-buffer* #x48 #x89 #xC1)  ; mov rcx, rax
    (emit-pop *code-buffer* 'rax)
    (emit-sar-reg-imm *code-buffer* 'rax 1)  ; untag dividend
    (emit-bytes *code-buffer* #x48 #x99)      ; cqo (sign-extend RAX -> RDX:RAX)
    (emit-bytes *code-buffer* #x48 #xF7 #xF9) ; idiv rcx
    (emit-shl-reg-imm *code-buffer* 'rax 1))) ; re-tag quotient

(defun compile-mod (args env)
  "Compile (mod a b) - integer division, remainder in RDX -> RAX"
  (destructuring-bind (a b) args
    (compile-form a env)
    (emit-push *code-buffer* 'rax)
    (compile-form b env)
    ;; RAX = b (divisor), stack top = a (dividend)
    (emit-sar-reg-imm *code-buffer* 'rax 1)  ; untag divisor
    (emit-bytes *code-buffer* #x48 #x89 #xC1)  ; mov rcx, rax
    (emit-pop *code-buffer* 'rax)
    (emit-sar-reg-imm *code-buffer* 'rax 1)  ; untag dividend
    (emit-bytes *code-buffer* #x48 #x99)      ; cqo (sign-extend RAX -> RDX:RAX)
    (emit-bytes *code-buffer* #x48 #xF7 #xF9) ; idiv rcx
    (emit-bytes *code-buffer* #x48 #x89 #xD0) ; mov rax, rdx (remainder)
    (emit-shl-reg-imm *code-buffer* 'rax 1))) ; re-tag remainder

;;; ============================================================
;;; Comparisons
;;; ============================================================

(defun compile-compare (cc args env)
  "Compile comparison: <, >, =, <=, >="
  (destructuring-bind (a b) args
    (compile-form a env)
    (emit-push *code-buffer* 'rax)
    (compile-form b env)
    (emit-pop *code-buffer* 'rdx)
    ;; Compare (works on tagged fixnums since same tag)
    (emit-cmp-reg-reg *code-buffer* 'rdx 'rax)
    ;; Set result
    (let ((true-label (make-label))
          (end-label (make-label)))
      (emit-jcc *code-buffer* cc true-label)
      (emit-load-nil *code-buffer* 'rax)
      (emit-jmp *code-buffer* end-label)
      (emit-label *code-buffer* true-label)
      (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
      (emit-label *code-buffer* end-label))))

(defun compile-eq (args env)
  "Compile (eq a b)"
  (destructuring-bind (a b) args
    (compile-form a env)
    (emit-push *code-buffer* 'rax)
    (compile-form b env)
    (emit-pop *code-buffer* 'rdx)
    (emit-cmp-reg-reg *code-buffer* 'rax 'rdx)
    (let ((true-label (make-label))
          (end-label (make-label)))
      (emit-jcc *code-buffer* :e true-label)
      (emit-load-nil *code-buffer* 'rax)
      (emit-jmp *code-buffer* end-label)
      (emit-label *code-buffer* true-label)
      (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
      (emit-label *code-buffer* end-label))))

;;; ============================================================
;;; Cons Operations
;;; ============================================================

(defun compile-car (arg env)
  "Compile (car x)"
  (compile-form arg env)
  ;; CAR is at offset 0 from untagged cons pointer
  ;; Remove tag (subtract 1), load, then we get tagged value
  (emit-mov-reg-mem *code-buffer* 'rax 'rax -1)) ; -1 removes cons tag

(defun compile-cdr (arg env)
  "Compile (cdr x)"
  (compile-form arg env)
  ;; CDR is at offset 8 from untagged cons pointer
  (emit-mov-reg-mem *code-buffer* 'rax 'rax 7)) ; -1 + 8 = 7

(defun compile-set-cdr (form env)
  "Compile (set-cdr cell value) - mutate CDR of a cons cell"
  (let ((cell-arg (cadr form))
        (value-arg (caddr form)))
    (compile-form cell-arg env)              ; cell -> RAX
    (emit-push *code-buffer* 'rax)           ; save cell
    (compile-form value-arg env)             ; value -> RAX
    (emit-pop *code-buffer* 'rdx)            ; cell -> RDX
    ;; Store value (RAX) at CDR location: [RDX + 7] = [raw_addr + 8]
    (emit-mov-mem-reg *code-buffer* 'rdx 'rax 7)))

(defun compile-set-car (form env)
  "Compile (set-car cell value) - mutate CAR of a cons cell"
  (let ((cell-arg (cadr form))
        (value-arg (caddr form)))
    (compile-form cell-arg env)              ; cell -> RAX
    (emit-push *code-buffer* 'rax)           ; save cell
    (compile-form value-arg env)             ; value -> RAX
    (emit-pop *code-buffer* 'rdx)            ; cell -> RDX
    ;; Store value (RAX) at CAR location: [RDX - 1] = [raw_addr + 0]
    (emit-mov-mem-reg *code-buffer* 'rdx 'rax -1)))

(defun compile-cons (car-arg cdr-arg env)
  "Compile (cons x y)"
  ;; Evaluate arguments
  (compile-form car-arg env)
  (emit-push *code-buffer* 'rax)
  (compile-form cdr-arg env)
  (emit-push *code-buffer* 'rax)
  ;; Allocate cons cell (16 bytes from R12)
  (emit-mov-reg-reg *code-buffer* 'rax +alloc-reg+)
  (emit-add-reg-imm *code-buffer* +alloc-reg+ 16)
  ;; TODO: Check against limit and call GC if needed
  ;; Store CDR
  (emit-pop *code-buffer* 'rdx)
  (emit-mov-mem-reg *code-buffer* 'rax 'rdx 8)
  ;; Store CAR
  (emit-pop *code-buffer* 'rdx)
  (emit-mov-mem-reg *code-buffer* 'rax 'rdx 0)
  ;; Tag as cons
  (emit-or-reg-reg *code-buffer* 'rax 'rax)  ; Clear flags
  (emit-add-reg-imm *code-buffer* 'rax +tag-cons+))

;; Compound accessors
(defun compile-caar (arg env)
  "Compile (caar x) = (car (car x))"
  (compile-car arg env)
  (emit-mov-reg-mem *code-buffer* 'rax 'rax -1))

(defun compile-cadr (arg env)
  "Compile (cadr x) = (car (cdr x))"
  (compile-cdr arg env)
  (emit-mov-reg-mem *code-buffer* 'rax 'rax -1))

(defun compile-cdar (arg env)
  "Compile (cdar x) = (cdr (car x))"
  (compile-car arg env)
  (emit-mov-reg-mem *code-buffer* 'rax 'rax 7))

(defun compile-cddr (arg env)
  "Compile (cddr x) = (cdr (cdr x))"
  (compile-cdr arg env)
  (emit-mov-reg-mem *code-buffer* 'rax 'rax 7))

;;; ============================================================
;;; Function Call
;;; ============================================================

(defun compile-call (fn args env)
  "Compile a function call"
  (let ((nargs (length args)))
    ;; Push arguments that don't fit in registers
    ;; Push in reverse order so they end up in correct order on stack
    ;; For args (a1 a2 a3 a4 a5 a6): nthcdr 4 = (a5 a6), reverse = (a6 a5)
    ;; Push a6 then a5, so stack has: a5 (top), a6 (below)
    (when (> nargs +nargregs+)
      (dolist (arg (reverse (nthcdr +nargregs+ args)))
        (compile-form arg env)
        (emit-push *code-buffer* 'rax)))
    ;; Evaluate register arguments right-to-left, push them
    (let ((reg-args (subseq args 0 (min nargs +nargregs+))))
      (dolist (arg (reverse reg-args))
        (compile-form arg env)
        (emit-push *code-buffer* 'rax))
      ;; Pop into argument registers
      (loop for i from 0 below (min nargs +nargregs+)
            for reg in +arg-regs+
            do (emit-pop *code-buffer* reg)))
    ;; Set nargs (as fixnum)
    (emit-mov-reg-imm *code-buffer* +nargs-reg+ (ash nargs +fixnum-shift+))
    ;; Call function
    (cond
      ((symbolp fn)
       ;; Direct call to named function
       (let ((fn-addr (gethash fn *functions*)))
         (if fn-addr
             ;; Known function - direct call
             (emit-call *code-buffer* fn-addr)
             ;; Unknown function - will be patched later
             (progn
               (push (list (code-buffer-position *code-buffer*) fn) *constants*)
               (emit-call *code-buffer* 0)))))  ; Placeholder
      (t
       ;; Computed function - indirect call
       (compile-form fn env)
       (emit-call-reg *code-buffer* 'rax)))
    ;; Clean up stack args
    (when (> nargs +nargregs+)
      (emit-add-reg-imm *code-buffer* 'rsp (* (- nargs +nargregs+) 8)))))

;;; ============================================================
;;; Bitwise Operations
;;; ============================================================

(defun compile-logand (args env)
  "Compile (logand a b)"
  (when (null args)
    (emit-mov-reg-imm *code-buffer* 'rax -1)  ; Identity for AND
    (return-from compile-logand))
  (compile-form (car args) env)
  (dolist (arg (cdr args))
    (emit-push *code-buffer* 'rax)
    (compile-form arg env)
    (emit-pop *code-buffer* 'rdx)
    (emit-and-reg-reg *code-buffer* 'rax 'rdx)))

(defun compile-logior (args env)
  "Compile (logior a b)"
  (when (null args)
    (emit-mov-reg-imm *code-buffer* 'rax 0)  ; Identity for OR
    (return-from compile-logior))
  (compile-form (car args) env)
  (dolist (arg (cdr args))
    (emit-push *code-buffer* 'rax)
    (compile-form arg env)
    (emit-pop *code-buffer* 'rdx)
    (emit-or-reg-reg *code-buffer* 'rax 'rdx)))

(defun compile-logxor (args env)
  "Compile (logxor a b)"
  (when (null args)
    (emit-mov-reg-imm *code-buffer* 'rax 0)
    (return-from compile-logxor))
  (compile-form (car args) env)
  (dolist (arg (cdr args))
    (emit-push *code-buffer* 'rax)
    (compile-form arg env)
    (emit-pop *code-buffer* 'rdx)
    (emit-xor-reg-reg *code-buffer* 'rax 'rdx)))

(defun compile-ash (value count env)
  "Compile (ash value count) - arithmetic shift.
   For tagged fixnums: left shift preserves tag (doubles the number),
   right shift needs AND with ~1 to ensure result has tag bit 0."
  (compile-form value env)
  (cond
    ((integerp count)
     (if (>= count 0)
         ;; Left shift - tag preserved naturally
         (emit-shl-reg-imm *code-buffer* 'rax count)
         ;; Right shift - shift then clear tag bit to maintain fixnum format
         (progn
           (emit-sar-reg-imm *code-buffer* 'rax (- count))
           ;; AND with -2 (i.e., ~1) to clear bit 0, ensuring valid fixnum tag
           (emit-and-reg-imm *code-buffer* 'rax -2))))
    (t
     ;; Variable shift - untag, branch on sign, re-tag
     (emit-push *code-buffer* 'rax)
     (compile-form count env)
     (emit-mov-reg-reg *code-buffer* 'rcx 'rax)  ; Shift count in CL
     (emit-pop *code-buffer* 'rax)
     ;; Untag shift count: sar rcx, 1
     (emit-bytes *code-buffer* #x48 #xD1 #xF9)  ; sar rcx, 1
     ;; Untag value: sar rax, 1
     (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
     ;; Test sign of shift count: test rcx, rcx
     (emit-bytes *code-buffer* #x48 #x85 #xC9)  ; test rcx, rcx
     ;; js .right (skip 5 bytes: shl rax,cl + jmp rel8)
     (emit-bytes *code-buffer* #x78 #x05)        ; js +5
     ;; Left shift: shl rax, cl
     (emit-bytes *code-buffer* #x48 #xD3 #xE0)  ; shl rax, cl
     ;; jmp .done (skip 6 bytes: neg rcx + sar rax,cl)
     (emit-bytes *code-buffer* #xEB #x06)        ; jmp +6
     ;; .right: neg rcx
     (emit-bytes *code-buffer* #x48 #xF7 #xD9)  ; neg rcx
     ;; sar rax, cl
     (emit-bytes *code-buffer* #x48 #xD3 #xF8)  ; sar rax, cl
     ;; .done: re-tag result: shl rax, 1
     (emit-bytes *code-buffer* #x48 #xD1 #xE0)))) ; shl rax, 1

(defun compile-ldb (bytespec value env)
  "Compile (ldb (byte size pos) value)"
  ;; bytespec should be (byte size position)
  (unless (and (consp bytespec) (eq (car bytespec) 'byte))
    (error "LDB requires (byte size pos) form"))
  (let ((size (cadr bytespec))
        (pos (caddr bytespec)))
    (compile-form value env)
    ;; Shift right by position
    (when (and (integerp pos) (> pos 0))
      (emit-shr-reg-imm *code-buffer* 'rax pos))
    ;; Mask to size bits
    (when (integerp size)
      (let ((mask (1- (ash 1 size))))
        (emit-and-reg-imm *code-buffer* 'rax mask)))))

;;; ============================================================
;;; Memory Operations
;;; ============================================================

(defun compile-mem-ref (addr type env)
  "Compile (mem-ref addr :type)"
  (compile-form addr env)
  ;; RAX now has address (as tagged fixnum - need to untag)
  ;; Right-shift by fixnum-shift to get raw address
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1

  ;; Load based on type (type should be a keyword constant)
  (let ((actual-type (if (and (consp type) (eq (car type) 'quote))
                         (cadr type)
                         type)))
    (case actual-type
      ((:u8 u8)
       (emit-bytes *code-buffer* #x48 #x0F #xB6 #x00)    ; movzx rax, byte [rax]
       (emit-bytes *code-buffer* #x48 #xD1 #xE0))        ; shl rax, 1 (tag as fixnum)
      ((:u16 u16)
       (emit-bytes *code-buffer* #x48 #x0F #xB7 #x00)    ; movzx rax, word [rax]
       (emit-bytes *code-buffer* #x48 #xD1 #xE0))        ; shl rax, 1 (tag as fixnum)
      ((:u32 u32)
       (emit-bytes *code-buffer* #x8B #x00)              ; mov eax, [rax] (zero-extends)
       (emit-bytes *code-buffer* #x48 #xD1 #xE0))        ; shl rax, 1 (tag as fixnum)
      ;; u64: NO tagging - used for raw pointers like cons cells
      ((:u64 u64) (emit-mov-reg-mem *code-buffer* 'rax 'rax 0))
      (otherwise
       ;; Default: load as u64, no tagging (raw pointer)
       (emit-mov-reg-mem *code-buffer* 'rax 'rax 0)))))

(defun symbol-name-eq (sym name)
  "Check if SYM has NAME (case-insensitive)"
  (and (symbolp sym)
       (string-equal (symbol-name sym) name)))

(defun compile-setf (place value env)
  "Compile (setf place value)"
  (cond
    ;; (setf (mem-ref addr type) value)
    ((and (consp place) (symbol-name-eq (car place) "MEM-REF"))
     (let* ((addr (cadr place))
            (type-form (caddr place))
            (actual-type (if (and (consp type-form) (eq (car type-form) 'quote))
                             (cadr type-form)
                             type-form)))
       (compile-form value env)
       (emit-push *code-buffer* 'rax)
       (compile-form addr env)
       (emit-mov-reg-reg *code-buffer* 'rdx 'rax)  ; RDX = address (tagged)
       ;; Untag the address
       (emit-bytes *code-buffer* #x48 #xD1 #xFA)   ; sar rdx, 1
       (emit-pop *code-buffer* 'rax)               ; RAX = value (tagged fixnum)
       (case actual-type
         ((:u8 u8)
          ;; Untag the value for byte store
          (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
          (emit-bytes *code-buffer* #x88 #x02))      ; mov [rdx], al
         ((:u16 u16)
          (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
          (emit-bytes *code-buffer* #x66 #x89 #x02)) ; mov [rdx], ax
         ((:u32 u32)
          (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
          (emit-bytes *code-buffer* #x89 #x02))      ; mov [rdx], eax
         ((:u64 u64) (emit-mov-mem-reg *code-buffer* 'rdx 'rax 0))
         (otherwise
          (emit-mov-mem-reg *code-buffer* 'rdx 'rax 0)))))
    ;; (setf var value) - same as setq
    ((symbolp place)
     (compile-setq place value env))
    (t
     (error "Unsupported SETF place: ~S" place))))

;;; ============================================================
;;; I/O Port Operations
;;; ============================================================

(defun compile-io-out-byte (port value env)
  "Compile (io-out-byte port value) - write byte to I/O port"
  ;; Evaluate port and value
  (compile-form value env)
  (emit-push *code-buffer* 'rax)
  (compile-form port env)
  ;; RAX has port (tagged fixnum), untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax) ; DX = port
  (emit-pop *code-buffer* 'rax)
  ;; Untag value
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; out dx, al
  (emit-byte *code-buffer* #xEE))

(defun compile-io-in-byte (port env)
  "Compile (io-in-byte port) - read byte from I/O port"
  (compile-form port env)
  ;; RAX has port (tagged fixnum), untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax) ; DX = port
  ;; Clear RAX then read
  (emit-bytes *code-buffer* #x48 #x31 #xC0)  ; xor rax, rax
  ;; in al, dx
  (emit-byte *code-buffer* #xEC)
  ;; Tag result as fixnum
  (emit-bytes *code-buffer* #x48 #xD1 #xE0)) ; shl rax, 1

(defun compile-io-out-dword (port value env)
  "Compile (io-out-dword port value) - write dword to I/O port"
  ;; Evaluate port and value
  (compile-form value env)
  (emit-push *code-buffer* 'rax)
  (compile-form port env)
  ;; RAX has port (tagged fixnum), untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax) ; DX = port
  (emit-pop *code-buffer* 'rax)
  ;; Untag value
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; out dx, eax
  (emit-byte *code-buffer* #xEF))

(defun compile-io-in-dword (port env)
  "Compile (io-in-dword port) - read dword from I/O port"
  (compile-form port env)
  ;; RAX has port (tagged fixnum), untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax) ; DX = port
  ;; Clear RAX then read
  (emit-bytes *code-buffer* #x48 #x31 #xC0)  ; xor rax, rax
  ;; in eax, dx (32-bit read)
  (emit-byte *code-buffer* #xED)
  ;; Tag result as fixnum
  (emit-bytes *code-buffer* #x48 #xD1 #xE0)) ; shl rax, 1

(defun compile-get-alloc-ptr ()
  "Compile (get-alloc-ptr) - returns the TAGGED value of R12"
  ;; Move R12 to RAX and tag it as a fixnum
  ;; This allows print-hex32 etc. to work correctly
  (emit-mov-reg-reg *code-buffer* 'rax +alloc-reg+)
  ;; Tag as fixnum (shift left by 1)
  (emit-bytes *code-buffer* #x48 #xD1 #xE0))  ; shl rax, 1

(defun compile-get-alloc-limit ()
  "Compile (get-alloc-limit) - returns the TAGGED value of R14"
  ;; Move R14 to RAX and tag it as a fixnum
  (emit-bytes *code-buffer* #x4C #x89 #xF0)       ; mov rax, r14
  (emit-bytes *code-buffer* #x48 #xD1 #xE0))      ; shl rax, 1

(defun compile-set-alloc-ptr (form env)
  "Compile (set-alloc-ptr value) - set R12 from tagged fixnum value"
  (compile-form form env)
  ;; Untag: SAR RAX, 1 to get raw address
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; mov r12, rax
  (emit-bytes *code-buffer* #x49 #x89 #xC4)) ; mov r12, rax

(defun compile-set-alloc-limit (form env)
  "Compile (set-alloc-limit value) - set R14 from tagged fixnum value"
  (compile-form form env)
  ;; Untag: SAR RAX, 1 to get raw address
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; mov r14, rax
  (emit-bytes *code-buffer* #x49 #x89 #xC6)) ; mov r14, rax

(defun compile-untag (form env)
  "Compile (untag value) - convert tagged fixnum to raw value.
   Just SAR by 1, no AND -2. Critical for code addresses that may be odd."
  (compile-form form env)
  (emit-bytes *code-buffer* #x48 #xD1 #xF8))  ; sar rax, 1

;;; ============================================================
;;; Actor Context Switch Primitives
;;; ============================================================
;;;
;;; (save-context addr) - Save RSP, RBX, RBP to memory at addr
;;; (restore-context addr) - Load RSP, RBX, RBP from memory at addr
;;;
;;; Memory layout at addr (6 x 8 bytes = 48 bytes):
;;;   [addr+0]  = RSP
;;;   [addr+8]  = (reserved, was R12)
;;;   [addr+16] = (reserved, was R14)
;;;   [addr+24] = RBX (callee-saved)
;;;   [addr+32] = RBP (callee-saved)
;;;   [addr+40] = continuation RIP
;;;
;;; R12 (alloc pointer) and R14 (alloc limit) are NOT saved/restored
;;; because all actors share the same heap. Saving them per-actor would
;;; cause stale alloc pointers after another actor advances R12.
;;;
;;; addr is a tagged fixnum (raw address << 1).

(defun compile-save-context (addr-form env)
  "Compile (save-context addr) - save registers to actor struct.
   Works like setjmp: returns 0 on initial save, returns 1 (tagged: 2)
   when resumed via restore-context.

   Stores the continuation address in the save area at [addr+40] instead
   of on the stack. This avoids disturbing the compiler's stack tracking.
   restore-context uses JMP (not RET) to resume at the continuation.

   Save area layout:
     [addr+0]  = RSP
     [addr+8]  = (reserved)
     [addr+16] = (reserved)
     [addr+24] = RBX
     [addr+32] = RBP
     [addr+40] = continuation RIP"
  (compile-form addr-form env)
  ;; RAX = tagged address, untag it -> RDX
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)        ; sar rax, 1
  (emit-bytes *code-buffer* #x48 #x89 #xC2)         ; mov rdx, rax

  ;; Compute continuation address (points to 'cont:' label below)
  (emit-bytes *code-buffer* #x48 #x8D #x05)         ; lea rax, [rip+disp32]
  (let ((lea-disp-pos (code-buffer-position *code-buffer*)))
    (emit-u32 *code-buffer* 0)                       ; placeholder disp32

    ;; Store continuation in save area (NOT on the stack!)
    (emit-bytes *code-buffer* #x48 #x89 #x42 #x28)   ; mov [rdx+40], rax

    ;; Save registers to actor struct (RDX = base address)
    ;; RSP is unchanged -- no push, no stack depth change
    ;; R12/R14 saved per-actor for per-actor heaps
    (emit-bytes *code-buffer* #x48 #x89 #x22)        ; mov [rdx+0], rsp
    (emit-bytes *code-buffer* #x4C #x89 #x62 #x08)   ; mov [rdx+8], r12
    (emit-bytes *code-buffer* #x4C #x89 #x72 #x10)   ; mov [rdx+16], r14
    (emit-bytes *code-buffer* #x48 #x89 #x5A #x18)   ; mov [rdx+24], rbx
    (emit-bytes *code-buffer* #x48 #x89 #x6A #x20)   ; mov [rdx+32], rbp
    ;; Save GS:[0x28] (obj-alloc) and GS:[0x30] (obj-limit) per-actor
    ;; Stored at struct+0x70/+0x78 (same slots as initial values from spawn)
    ;; Uses RAX as scratch (about to be zeroed anyway)
    (emit-bytes *code-buffer* #x65 #x48 #x8B #x04 #x25  ; mov rax, GS:[0x28]
                #x28 #x00 #x00 #x00)
    (emit-bytes *code-buffer* #x48 #x89 #x42 #x68)   ; mov [rdx+0x68], rax (struct+0x70)
    (emit-bytes *code-buffer* #x65 #x48 #x8B #x04 #x25  ; mov rax, GS:[0x30]
                #x30 #x00 #x00 #x00)
    (emit-bytes *code-buffer* #x48 #x89 #x42 #x70)   ; mov [rdx+0x70], rax (struct+0x78)

    ;; Initial save path: return 0 (tagged fixnum 0)
    (emit-bytes *code-buffer* #x31 #xC0)             ; xor eax, eax (rax=0)
    (emit-bytes *code-buffer* #xEB #x05)             ; jmp +5 (skip cont code)

    ;; -- cont: (restore-context's JMP jumps here) --
    (let ((cont-pos (code-buffer-position *code-buffer*)))
      ;; Resumed path: return 1 (tagged fixnum 1 = value 2)
      (emit-bytes *code-buffer* #xB8 #x02 #x00 #x00 #x00)  ; mov eax, 2

      ;; -- past_cont: --
      ;; RAX = 0 (saved) or 2 (resumed), compiler's code continues here

      ;; Patch the LEA displacement to point to cont:
      (let ((disp (- cont-pos (+ lea-disp-pos 4))))  ; relative to insn after lea
        (setf (aref (code-buffer-bytes *code-buffer*) lea-disp-pos)
              (logand disp #xFF))
        (setf (aref (code-buffer-bytes *code-buffer*) (+ lea-disp-pos 1))
              (logand (ash disp -8) #xFF))
        (setf (aref (code-buffer-bytes *code-buffer*) (+ lea-disp-pos 2))
              (logand (ash disp -16) #xFF))
        (setf (aref (code-buffer-bytes *code-buffer*) (+ lea-disp-pos 3))
              (logand (ash disp -24) #xFF))))))

(defun compile-restore-context (addr-form env)
  "Compile (restore-context addr) - load registers from actor struct and jump.
   This never returns to the caller! After restoring RSP, it loads the
   continuation address from [addr+40] and JMPs to it.

   CRITICAL SMP FIX: After switching RSP, releases the scheduler lock (0x360400)
   and re-enables interrupts (STI) BEFORE jumping. This eliminates the race where
   the old actor's stack is still in use when another CPU dequeues and restores it.
   All callers hold the scheduler lock. The unlock MUST happen after RSP switch
   (so we're on the new stack) but before JMP (so the old stack is released).

   For resumed actors: jumps to save-context's cont: label.
   For new actors: jumps to the entry function (stored at [addr+40] by spawn)."
  (compile-form addr-form env)
  ;; RAX = tagged address, untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; Load callee-saved registers + R12/R14 for per-actor heaps
  (emit-bytes *code-buffer* #x48 #x8B #x68 #x20)   ; mov rbp, [rax+32]
  (emit-bytes *code-buffer* #x48 #x8B #x58 #x18)   ; mov rbx, [rax+24]
  (emit-bytes *code-buffer* #x4C #x8B #x60 #x08)   ; mov r12, [rax+8]
  (emit-bytes *code-buffer* #x4C #x8B #x70 #x10)   ; mov r14, [rax+16]
  ;; Restore GS:[0x28] (obj-alloc) and GS:[0x30] (obj-limit) per-actor
  ;; Loaded from struct+0x70/+0x78 (base+0x68/+0x70)
  ;; Uses RDX as scratch (free at this point)
  (emit-bytes *code-buffer* #x48 #x8B #x50 #x68)   ; mov rdx, [rax+0x68] (struct+0x70)
  (emit-bytes *code-buffer* #x65 #x48 #x89 #x14 #x25  ; mov GS:[0x28], rdx
              #x28 #x00 #x00 #x00)
  (emit-bytes *code-buffer* #x48 #x8B #x50 #x70)   ; mov rdx, [rax+0x70] (struct+0x78)
  (emit-bytes *code-buffer* #x65 #x48 #x89 #x14 #x25  ; mov GS:[0x30], rdx
              #x30 #x00 #x00 #x00)
  ;; Load continuation address into RCX before changing RSP
  (emit-bytes *code-buffer* #x48 #x8B #x48 #x28)   ; mov rcx, [rax+40]
  ;; Restore RSP — we're now on the NEW actor's stack
  (emit-bytes *code-buffer* #x48 #x8B #x20)         ; mov rsp, [rax]
  ;; Release scheduler lock (0x360400) — old stack is now safe for other CPUs
  ;; mov qword [0x360400], 0
  (emit-bytes *code-buffer* #x48 #xC7 #x04 #x25)   ; mov qword [abs32], imm32
  (emit-u32 *code-buffer* #x360400)                  ; address = 0x360400
  (emit-u32 *code-buffer* 0)                          ; value = 0
  ;; Re-enable interrupts (ap-scheduler uses CLI; other callers already have IF=1)
  (emit-byte *code-buffer* #xFB)                     ; sti
  ;; JMP to continuation (not RET -- continuation is in save area, not on stack)
  (emit-bytes *code-buffer* #xFF #xE1)               ; jmp rcx
  )

(defun compile-call-native (args env)
  "Compile (call-native addr arg1 arg2) - call native code at addr with args"
  ;; Args: first is address (raw, not tagged), rest are arguments (tagged fixnums)
  ;; We'll support up to 2 args for now (RSI, RDI)
  (let ((addr-form (first args))
        (arg-forms (rest args)))
    ;; Save R12 and R15 (they might be clobbered)
    (emit-push *code-buffer* +alloc-reg+)
    (emit-push *code-buffer* +nil-reg+)
    ;; Compile address to RAX - it's a tagged fixnum
    (compile-form addr-form env)
    ;; Untag the address (shift right by 1)
    (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
    ;; Move to RBX
    (emit-mov-reg-reg *code-buffer* 'rbx 'rax)
    ;; Compile first arg to RSI (if any) - args are tagged fixnums
    (when (first arg-forms)
      (compile-form (first arg-forms) env)
      (emit-mov-reg-reg *code-buffer* 'rsi 'rax))
    ;; Compile second arg to RDI (if any)
    (when (second arg-forms)
      (compile-form (second arg-forms) env)
      (emit-mov-reg-reg *code-buffer* 'rdi 'rax))
    ;; Call RBX - the native code
    (emit-bytes *code-buffer* #xFF #xD3)  ; call rbx
    ;; Restore R15 and R12
    (emit-pop *code-buffer* +nil-reg+)
    (emit-pop *code-buffer* +alloc-reg+)
    ;; Result is in RAX
    ))

;;; ============================================================
;;; Control Flow
;;; ============================================================

(defvar *loop-exit-label* nil
  "Label to jump to for (return) in a loop")

(defun compile-loop (body env)
  "Compile (loop forms...) - infinite loop with (return val)"
  (let* ((loop-label (make-label))
         (exit-label (make-label))
         (*loop-exit-label* exit-label)
         ;; Find yield's code buffer offset from the correct package
         (yield-addr (let ((addr nil))
                       (maphash (lambda (k v)
                                  (when (string= (symbol-name k) "YIELD")
                                    (setf addr v)))
                                *functions*)
                       addr)))
    (emit-label *code-buffer* loop-label)
    (compile-progn body env)
    ;; Reduction counter: per-CPU via GS segment (Phase 9.2: SMP)
    ;; Per-CPU struct offset 8 = reduction counter (tagged fixnum)
    ;; GS base is set per-CPU: BSP=0x360000, AP1=0x360040, etc.
    ;; Only if yield has been compiled (functions before yield skip this)
    (when yield-addr
      (let ((skip-label (make-label)))
        ;; MOV RAX, GS:[8]  — load per-CPU reduction counter
        ;; 65 48 8B 04 25 08 00 00 00
        (emit-bytes *code-buffer* #x65 #x48 #x8B #x04 #x25 #x08 #x00 #x00 #x00)
        ;; SUB RAX, 2  — subtract tagged 1
        (emit-bytes *code-buffer* #x48 #x83 #xE8 #x02)
        ;; MOV GS:[8], RAX  — store decremented value back
        ;; 65 48 89 04 25 08 00 00 00
        (emit-bytes *code-buffer* #x65 #x48 #x89 #x04 #x25 #x08 #x00 #x00 #x00)
        ;; JG skip — if counter > 0 (signed), skip yield
        ;; Must use JG not JNZ: LAPIC timer ISR zeroes counter asynchronously,
        ;; causing 0-2=-2 which is not zero but IS negative → must yield
        (emit-jcc *code-buffer* :g skip-label)
        ;; Counter hit zero: reset to 4000 (tagged 2000 iterations)
        ;; MOV QWORD GS:[8], 4000
        ;; 65 48 C7 04 25 08 00 00 00 A0 0F 00 00
        (emit-bytes *code-buffer* #x65 #x48 #xC7 #x04 #x25
                    #x08 #x00 #x00 #x00 #xA0 #x0F #x00 #x00)
        ;; XOR ECX, ECX  — nargs=0 for yield call
        (emit-bytes *code-buffer* #x31 #xC9)
        (emit-call *code-buffer* yield-addr)
        (emit-label *code-buffer* skip-label)))
    (emit-jmp *code-buffer* loop-label)
    (emit-label *code-buffer* exit-label)))

(defun compile-return (value env)
  "Compile (return value) - exit from loop"
  (compile-form value env)
  (when *loop-exit-label*
    (emit-jmp *code-buffer* *loop-exit-label*)))

(defvar *block-labels* nil
  "Alist of (name . exit-label) for blocks")

(defun compile-block (name body env)
  "Compile (block name forms...)"
  (let* ((exit-label (make-label))
         (*block-labels* (cons (cons name exit-label) *block-labels*)))
    (compile-progn body env)
    (emit-label *code-buffer* exit-label)))

(defvar *tagbody-tags* nil
  "Alist of (tag . label) for tagbody")

(defun compile-tagbody (body env)
  "Compile (tagbody {tag | form}*)"
  ;; First pass: collect tags and create labels
  (let ((*tagbody-tags* nil))
    (dolist (item body)
      (when (symbolp item)
        (push (cons item (make-label)) *tagbody-tags*)))
    ;; Second pass: compile
    (dolist (item body)
      (if (symbolp item)
          (emit-label *code-buffer* (cdr (assoc item *tagbody-tags*)))
          (compile-form item env)))
    ;; Return NIL
    (emit-load-nil *code-buffer* 'rax)))

(defun compile-go (tag env)
  "Compile (go tag)"
  (declare (ignore env))
  (let ((label (cdr (assoc tag *tagbody-tags*))))
    (if label
        (emit-jmp *code-buffer* label)
        (error "Unknown GO tag: ~A" tag))))

;;; ============================================================
;;; Misc Operations
;;; ============================================================

(defun compile-not (arg env)
  "Compile (not x)"
  (compile-form arg env)
  (emit-cmp-reg-reg *code-buffer* 'rax +nil-reg+)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-zerop (arg env)
  "Compile (zerop x)"
  (compile-form arg env)
  ;; Fixnum 0 is represented as 0 (tag is also 0)
  (emit-test-reg-reg *code-buffer* 'rax 'rax)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-null (arg env)
  "Compile (null x) - true if x is NIL"
  (compile-form arg env)
  (emit-cmp-reg-reg *code-buffer* 'rax +nil-reg+)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-consp (arg env)
  "Compile (consp x) - true if x has cons tag"
  (compile-form arg env)
  ;; Check if low 4 bits = 0001 (cons tag)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  (emit-and-reg-imm *code-buffer* 'rdx #x0F)  ; Extract low 4 bits
  (emit-cmp-reg-imm *code-buffer* 'rdx +tag-cons+)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-fixnump (arg env)
  "Compile (fixnump x) - true if x has fixnum tag (low bit 0)"
  (compile-form arg env)
  ;; Check if low bit = 0 (fixnum tag)
  (emit-test-reg-imm *code-buffer* 'rax 1)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)  ; ZF=1 means low bit was 0
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-atom (arg env)
  "Compile (atom x) - true if x is not a cons"
  ;; atom is equivalent to (not (consp x))
  (compile-form arg env)
  ;; Check if low 4 bits != 0001 (not cons)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  (emit-and-reg-imm *code-buffer* 'rdx #x0F)
  (emit-cmp-reg-imm *code-buffer* 'rdx +tag-cons+)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :ne true-label)  ; Not equal = not cons = atom
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-bignump (arg env)
  "Compile (bignump x) - true if x has object tag (low 2 bits = 11) and subtag 0x30"
  (compile-form arg env)
  ;; Check if low 2 bits = 11 (object tag)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  (emit-and-reg-imm *code-buffer* 'rdx #x03)
  (emit-cmp-reg-imm *code-buffer* 'rdx #x03)
  (let ((not-obj-label (make-label))
        (true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :ne not-obj-label)
    ;; Has object tag - check subtag at [rax & ~3]
    (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
    (emit-and-reg-imm *code-buffer* 'rdx -4)  ; strip tag bits (AND with ~3)
    (emit-bytes *code-buffer* #x48 #x0F #xB6 #x12)  ; movzx rdx, byte [rdx]
    (emit-cmp-reg-imm *code-buffer* 'rdx #x30)  ; subtag 0x30 = bignum
    (emit-jcc *code-buffer* :e true-label)
    ;; Not bignum (wrong subtag or wrong tag)
    (emit-label *code-buffer* not-obj-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-stringp (arg env)
  "Compile (stringp x) - true if x has object tag (low 2 bits = 11) and subtag 0x31"
  (compile-form arg env)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  (emit-and-reg-imm *code-buffer* 'rdx #x03)
  (emit-cmp-reg-imm *code-buffer* 'rdx #x03)
  (let ((not-obj-label (make-label))
        (true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :ne not-obj-label)
    (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
    (emit-and-reg-imm *code-buffer* 'rdx -4)
    (emit-bytes *code-buffer* #x48 #x0F #xB6 #x12)  ; movzx rdx, byte [rdx]
    (emit-cmp-reg-imm *code-buffer* 'rdx #x31)       ; subtag 0x31 = string
    (emit-jcc *code-buffer* :e true-label)
    (emit-label *code-buffer* not-obj-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-arrayp (arg env)
  "Compile (arrayp x) - true if x has object tag (low 2 bits = 11) and subtag 0x32"
  (compile-form arg env)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  (emit-and-reg-imm *code-buffer* 'rdx #x03)
  (emit-cmp-reg-imm *code-buffer* 'rdx #x03)
  (let ((not-obj-label (make-label))
        (true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :ne not-obj-label)
    (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
    (emit-and-reg-imm *code-buffer* 'rdx -4)
    (emit-bytes *code-buffer* #x48 #x0F #xB6 #x12)  ; movzx rdx, byte [rdx]
    (emit-cmp-reg-imm *code-buffer* 'rdx #x32)       ; subtag 0x32 = array
    (emit-jcc *code-buffer* :e true-label)
    (emit-label *code-buffer* not-obj-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-integerp (arg env)
  "Compile (integerp x) - true if fixnum (low bit 0, non-nil) or bignum (tag 11, subtag 0x30)"
  (compile-form arg env)
  (let ((check-bignum (make-label))
        (false-label (make-label))
        (true-label (make-label))
        (end-label (make-label)))
    ;; Check fixnum: low bit 0
    (emit-test-reg-imm *code-buffer* 'rax 1)
    (emit-jcc *code-buffer* :ne check-bignum)  ; Low bit set - not fixnum
    ;; Low bit 0 - fixnum if non-nil
    (emit-cmp-reg-reg *code-buffer* 'rax +nil-reg+)
    (emit-jcc *code-buffer* :ne true-label)  ; Not nil = fixnum = integer
    (emit-jmp *code-buffer* false-label)     ; nil = not integer
    ;; Check bignum: low 2 bits = 11
    (emit-label *code-buffer* check-bignum)
    (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
    (emit-and-reg-imm *code-buffer* 'rdx #x03)
    (emit-cmp-reg-imm *code-buffer* 'rdx #x03)
    (emit-jcc *code-buffer* :ne false-label)  ; Not tag 11
    ;; Check subtag
    (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
    (emit-and-reg-imm *code-buffer* 'rdx #xFFFFFFFFFFFFFFFC)
    (emit-bytes *code-buffer* #x48 #x0F #xB6 #x12)  ; movzx rdx, byte [rdx]
    (emit-cmp-reg-imm *code-buffer* 'rdx #x30)
    (emit-jcc *code-buffer* :e true-label)
    ;; False
    (emit-label *code-buffer* false-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    ;; True
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-listp (arg env)
  "Compile (listp x) - true if x is NIL or a cons"
  (compile-form arg env)
  ;; First check if NIL
  (emit-cmp-reg-reg *code-buffer* 'rax +nil-reg+)
  (let ((true-label (make-label))
        (check-cons-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)  ; If NIL, it's a list
    ;; Not NIL, check if cons
    (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
    (emit-and-reg-imm *code-buffer* 'rdx #x0F)
    (emit-cmp-reg-imm *code-buffer* 'rdx +tag-cons+)
    (emit-jcc *code-buffer* :e true-label)  ; If cons, it's a list
    ;; Neither NIL nor cons
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

;;; Character operations

(defun compile-characterp (arg env)
  "Compile (characterp x) - true if x is a character"
  (compile-form arg env)
  ;; Check if low byte = #x05 (character tag)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  (emit-and-reg-imm *code-buffer* 'rdx #xFF)  ; Extract low byte
  (emit-cmp-reg-imm *code-buffer* 'rdx +char-tag+)
  (let ((true-label (make-label))
        (end-label (make-label)))
    (emit-jcc *code-buffer* :e true-label)
    (emit-load-nil *code-buffer* 'rax)
    (emit-jmp *code-buffer* end-label)
    (emit-label *code-buffer* true-label)
    (emit-mov-reg-imm *code-buffer* 'rax +t-placeholder+)
    (emit-label *code-buffer* end-label)))

(defun compile-char-code (arg env)
  "Compile (char-code c) - returns character code as fixnum"
  (compile-form arg env)
  ;; Character: code in bits 8+, shift right by 8 to get code
  ;; Then tag as fixnum (shift left by 1)
  ;; Net: shift right by 7
  (emit-sar-reg-imm *code-buffer* 'rax (- +char-shift+ +fixnum-shift+)))

(defun compile-code-char (arg env)
  "Compile (code-char n) - returns character from code"
  (compile-form arg env)
  ;; Input is fixnum (code << 1)
  ;; Output is character (code << 8) | #x05
  ;; So: shift left by 7, then OR with tag
  (emit-shl-reg-imm *code-buffer* 'rax (- +char-shift+ +fixnum-shift+))
  (emit-or-reg-imm *code-buffer* 'rax +char-tag+))

;;; ============================================================
;;; Top-level Function Compilation
;;; ============================================================

(defun compile-function (name params body)
  "Compile a top-level function definition"
  (let ((*current-function* name)
        (start-pos (code-buffer-position *code-buffer*)))
    ;; Record function address
    (setf (gethash name *functions*) start-pos)
    ;; Function prologue
    (emit-push *code-buffer* 'rbp)
    (emit-mov-reg-reg *code-buffer* 'rbp 'rsp)
    ;; Build initial environment with parameters
    ;; Register parameters must be saved to stack since they get clobbered
    ;; when the function body calls other functions
    (let* ((nreg-params (min (length params) +nargregs+))
           ;; Initial env with stack-depth reflecting saved parameters
           (env (make-compile-env :stack-depth nreg-params :bindings nil :parent nil)))
      ;; Allocate stack space for register parameters
      (when (> nreg-params 0)
        (emit-sub-reg-imm *code-buffer* 'rsp (* nreg-params 8)))
      ;; Save register parameters to stack and add to environment
      (loop for param in params
            for reg in +arg-regs+
            for i from 0
            while (< i +nargregs+)
            do (let ((offset (* 8 (1+ i))))
                 ;; Store at [rbp - offset]
                 (emit-mov-mem-reg *code-buffer* 'rbp reg (- offset))
                 ;; Add binding (stack-offset must be positive, compile-variable-ref negates it)
                 (push (make-binding :name param :location :stack :stack-offset offset)
                       (compile-env-bindings env))))
      ;; Handle extra args (already on stack from caller)
      ;; These are ABOVE rbp (positive offsets), so use negative stack-offset
      ;; since compile-variable-ref negates it: [rbp - (-16)] = [rbp + 16]
      (loop for param in (nthcdr +nargregs+ params)
            for i from 0
            do (push (make-binding :name param :location :stack
                                   :stack-offset (- (+ 16 (* i 8))))
                     (compile-env-bindings env)))
      ;; Compile body
      (compile-progn body env))
    ;; Function epilogue
    (emit-mov-reg-reg *code-buffer* 'rsp 'rbp)
    (emit-pop *code-buffer* 'rbp)
    (emit-ret *code-buffer*)
    ;; Return function info
    (list name start-pos (code-buffer-position *code-buffer*))))

(defun compile-toplevel (form)
  "Compile a top-level form"
  (cond
    ((and (consp form) (eq (car form) 'defun))
     (destructuring-bind (name params &body body) (cdr form)
       (compile-function name params body)))
    ((and (consp form) (eq (car form) 'defvar))
     ;; TODO: Handle defvar
     nil)
    ((and (consp form) (eq (car form) 'defconstant))
     ;; TODO: Handle defconstant
     nil)
    (t
     ;; Other top-level forms get wrapped in a thunk
     (compile-function (gensym "TOPLEVEL") nil (list form)))))

;;; ============================================================
;;; When / Unless / Dotimes (Phase 5.9)
;;; ============================================================

(defun compile-when (args env)
  "Compile (when test body...) → (if test (progn body...) nil)"
  (let ((test (car args))
        (body (cdr args)))
    (compile-if (list test (cons 'progn body)) env)))

(defun compile-unless (args env)
  "Compile (unless test body...) → (if test nil (progn body...))"
  (let ((test (car args))
        (body (cdr args)))
    (compile-if (list test nil (cons 'progn body)) env)))

(defun compile-dotimes (spec body env)
  "Compile (dotimes (var count) body...) → counted loop"
  (let* ((var (car spec))
         (count-form (cadr spec)))
    ;; Implement as: (let ((var 0)) (loop (if (< var <count>) (progn body... (setq var (1+ var))) (return nil))))
    (compile-let (list (list var 0))
                 (list (list 'loop
                             (list 'if (list '< var count-form)
                                   (append (cons 'progn body) (list (list 'setq var (list '1+ var))))
                                   (list 'return nil))))
                 env)))

;;; ============================================================
;;; Higher-Order Functions (Phase 5.7)
;;; ============================================================

(defun compile-function-ref (name env)
  "Compile (function fname) - look up function address, return as fixnum"
  (declare (ignore env))
  (let ((fn-addr (gethash name *functions*)))
    (if fn-addr
        ;; Known function - return address as tagged fixnum
        (emit-mov-reg-imm *code-buffer* 'rax (ash fn-addr +fixnum-shift+))
        ;; Unknown function - will need patching
        (progn
          (push (list (code-buffer-position *code-buffer*) name :function-ref) *constants*)
          (emit-mov-reg-imm *code-buffer* 'rax 0)))))

(defun compile-funcall (args env)
  "Compile (funcall f arg1 arg2 ...) - indirect call"
  (let ((fn-form (car args))
        (call-args (cdr args))
        (nargs (length (cdr args))))
    ;; Compile function expression and save
    (compile-form fn-form env)
    (emit-push *code-buffer* 'rax)
    ;; Compile arguments right-to-left, push them
    (let ((reg-args (subseq call-args 0 (min nargs +nargregs+))))
      (dolist (arg (reverse reg-args))
        (compile-form arg env)
        (emit-push *code-buffer* 'rax))
      ;; Pop into argument registers
      (loop for i from 0 below (min nargs +nargregs+)
            for reg in +arg-regs+
            do (emit-pop *code-buffer* reg)))
    ;; Pop function address, untag, call
    (emit-pop *code-buffer* 'rax)
    (emit-sar-reg-imm *code-buffer* 'rax +fixnum-shift+)  ; untag
    (emit-mov-reg-reg *code-buffer* 'rbx 'rax)
    (emit-bytes *code-buffer* #xFF #xD3)))  ; call rbx

;;; ============================================================
;;; SMP Primitives (Phase 9)
;;; ============================================================

(defun compile-xchg-mem (addr-form val-form env)
  "Compile (xchg-mem addr val) - atomic exchange.
   Returns old value at addr, stores val.
   Both addr and val are tagged fixnums."
  (compile-form addr-form env)
  (emit-push *code-buffer* 'rax)           ; save addr
  (compile-form val-form env)              ; val -> RAX
  (emit-pop *code-buffer* 'rdx)           ; addr -> RDX
  ;; Untag both
  (emit-sar-reg-imm *code-buffer* 'rdx 1) ; untag addr
  (emit-sar-reg-imm *code-buffer* 'rax 1) ; untag val
  ;; XCHG [RDX], RAX — atomic exchange (implicit LOCK prefix)
  ;; REX.W 87 02 = xchg [rdx], rax
  (emit-bytes *code-buffer* #x48 #x87 #x02)
  ;; Re-tag result
  (emit-shl-reg-imm *code-buffer* 'rax 1))

(defun compile-pause ()
  "Compile (pause) - spin-wait hint. Returns 0."
  ;; F3 90 = PAUSE
  (emit-bytes *code-buffer* #xF3 #x90)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-mfence ()
  "Compile (mfence) - full memory barrier. Returns 0."
  ;; 0F AE F0 = MFENCE
  (emit-bytes *code-buffer* #x0F #xAE #xF0)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-hlt ()
  "Compile (hlt) - HLT instruction. Returns 0."
  ;; F4 = HLT
  (emit-byte *code-buffer* #xF4)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-sti ()
  "Compile (sti) - enable interrupts. Returns 0."
  ;; FB = STI
  (emit-byte *code-buffer* #xFB)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-cli ()
  "Compile (cli) - disable interrupts. Returns 0."
  ;; FA = CLI
  (emit-byte *code-buffer* #xFA)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-sti-hlt ()
  "Compile (sti-hlt) - atomic STI+HLT. x86 guarantees interrupts are enabled
   only after the instruction following STI, so STI;HLT is effectively atomic:
   a pending IPI causes HLT to return immediately rather than sleeping forever.
   Returns 0."
  ;; FB = STI, F4 = HLT — must be adjacent, no instructions between them
  (emit-bytes *code-buffer* #xFB #xF4)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-switch-idle-stack ()
  "Compile (switch-idle-stack) - switch RSP to the current CPU's per-CPU idle stack.
   Reads the pre-computed idle stack top from GS:[0x38] and sets RSP to it.
   This MUST be called before entering ap-scheduler to prevent two CPUs from
   sharing the same actor/kernel stack. Each CPU gets its own 4KB idle stack.
   Returns 0."
  ;; mov rsp, gs:[0x38]
  ;; 65 = GS prefix, 48 = REX.W, 8B = MOV r64,r/m64
  ;; ModRM 24 = mod=00 reg=rsp(100) r/m=100(SIB)
  ;; SIB 25 = scale=00 index=100(none) base=101(disp32)
  ;; 38 00 00 00 = displacement 0x38
  (emit-bytes *code-buffer* #x65 #x48 #x8B #x24 #x25 #x38 #x00 #x00 #x00)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-set-rsp (addr-form env)
  "Compile (set-rsp addr) - set RSP to the given address.
   addr is a tagged fixnum. Used to switch the boot context to actor 1's stack
   so that GC stack scanning covers the correct range."
  (compile-form addr-form env)
  ;; RAX = tagged address, untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; mov rsp, rax
  (emit-bytes *code-buffer* #x48 #x89 #xC4)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))    ; xor eax, eax

(defun compile-lidt (addr-form env)
  "Compile (lidt addr) - load IDT register from 10-byte descriptor at addr.
   addr is a tagged fixnum pointing to the IDTR descriptor (limit:u16 + base:u64)."
  (compile-form addr-form env)
  ;; RAX = tagged address, untag it
  (emit-bytes *code-buffer* #x48 #xD1 #xF8)  ; sar rax, 1
  ;; LIDT [RAX] = 0F 01 18
  (emit-bytes *code-buffer* #x0F #x01 #x18)
  ;; Return 0 (tagged fixnum)
  (emit-bytes *code-buffer* #x31 #xC0))       ; xor eax, eax

(defun compile-wrmsr (args env)
  "Compile (wrmsr ecx-val eax-val edx-val) - write to MSR.
   All args are tagged fixnums, untagged before WRMSR.
   ECX = MSR number, EDX:EAX = 64-bit value."
  (compile-form (first args) env)
  (emit-push *code-buffer* 'rax)             ; save ecx-val
  (compile-form (second args) env)
  (emit-push *code-buffer* 'rax)             ; save eax-val
  (compile-form (third args) env)
  ;; RAX = edx-val (tagged), untag → RDX
  (emit-sar-reg-imm *code-buffer* 'rax 1)
  (emit-mov-reg-reg *code-buffer* 'rdx 'rax)
  ;; Pop eax-val, untag → RAX
  (emit-pop *code-buffer* 'rax)
  (emit-sar-reg-imm *code-buffer* 'rax 1)
  ;; Pop ecx-val, untag → RCX
  (emit-pop *code-buffer* 'rcx)
  (emit-sar-reg-imm *code-buffer* 'rcx 1)
  ;; WRMSR: 0F 30
  (emit-bytes *code-buffer* #x0F #x30)
  ;; Return 0
  (emit-bytes *code-buffer* #x31 #xC0))     ; xor eax, eax

(defun compile-percpu-ref (offset-form env)
  "Compile (percpu-ref offset) — read 64-bit tagged value from gs:[offset].
   Offset is a tagged fixnum (untagged for addressing).
   The value stored at gs:[offset] is a tagged Lisp value."
  (compile-form offset-form env)
  ;; RAX = tagged offset, untag for use as address
  (emit-sar-reg-imm *code-buffer* 'rax 1)
  ;; MOV RAX, GS:[RAX]  — 65 48 8B 00
  (emit-bytes *code-buffer* #x65 #x48 #x8B #x00))

(defun compile-percpu-set (offset-form val-form env)
  "Compile (percpu-set offset value) — write 64-bit tagged value to gs:[offset].
   Offset is a tagged fixnum (untagged for addressing).
   Value is stored as-is (tagged)."
  (compile-form offset-form env)
  (emit-push *code-buffer* 'rax)             ; save offset
  (compile-form val-form env)
  ;; RAX = value (tagged, stored as-is)
  ;; Pop offset → RDX, untag
  (emit-pop *code-buffer* 'rdx)
  (emit-sar-reg-imm *code-buffer* 'rdx 1)
  ;; MOV GS:[RDX], RAX  — 65 48 89 02
  (emit-bytes *code-buffer* #x65 #x48 #x89 #x02))
  ;; Return value stays in RAX

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-cross-compiler ()
  "Basic test of cross-compilation"
  (let ((*code-buffer* (make-code-buffer))
        (*functions* (make-hash-table :test 'eq))
        (*constants* nil))
    ;; Compile a simple function
    (format t "~%Compiling (defun add1 (x) (1+ x))...~%")
    (compile-toplevel '(defun add1 (x) (1+ x)))
    (fixup-labels *code-buffer*)
    (format t "Generated ~D bytes~%" (code-buffer-position *code-buffer*))
    (format t "Code: ~{~2,'0X ~}~%"
            (coerce (subseq (code-buffer-bytes *code-buffer*) 0
                           (min 32 (code-buffer-position *code-buffer*)))
                    'list))

    ;; Compile fibonacci
    (format t "~%Compiling fibonacci...~%")
    (setf *code-buffer* (make-code-buffer))
    (compile-toplevel '(defun fib (n)
                        (if (< n 2)
                            n
                            (+ (fib (1- n))
                               (fib (- n 2))))))
    (fixup-labels *code-buffer*)
    (format t "Generated ~D bytes~%" (code-buffer-position *code-buffer*))

    ;; Show functions
    (format t "~%Functions compiled:~%")
    (maphash (lambda (k v) (format t "  ~A @ ~D~%" k v)) *functions*)

    *code-buffer*))
