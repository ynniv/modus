;;;; compiler.lisp - MVM Compiler: Source Lisp -> MVM Bytecode
;;;;
;;;; The main compiler for the Modus Virtual Machine. Replaces both
;;;; cross-compile.lisp (x86-64 cross-compiler) and the rt-compile-*
;;;; runtime compilation modules. Produces target-independent MVM bytecode
;;;; that is later translated to native code by the AOT or JIT backends.
;;;;
;;;; Three phases:
;;;;   Phase 1: Frontend    - Source forms -> AST (macro expansion, recognition)
;;;;   Phase 2: IR Gen      - AST -> MVM IR (register allocation, control flow)
;;;;   Phase 3: Bytecode    - MVM IR -> compact bytecode (encoding, fixups)
;;;;
;;;; Register usage:
;;;;   V0-V3:  argument passing (caller places args here before call)
;;;;   V4-V8:  temporaries for expression evaluation
;;;;   V9-V15: available for spill / longer-lived values
;;;;   VR:     return value register
;;;;   VN:     NIL constant register
;;;;   VA:     allocation pointer
;;;;   VL:     allocation limit
;;;;   VSP:    stack pointer
;;;;   VFP:    frame pointer

(in-package :modus64.mvm)

;;; ============================================================
;;; Tagging Constants (mirror cross-compile.lisp)
;;; ============================================================
;;;
;;; xxx0 = Fixnum (63-bit signed, shifted left 1)
;;; 0001 = Cons pointer
;;; 1001 = Object pointer (general heap object)
;;; 0101 = Immediate (char, single-float)
;;; 1111 = GC forwarding pointer

(defconstant +tag-fixnum+    #b0000)
(defconstant +tag-cons+      #b0001)
(defconstant +tag-object+    #b1001)
(defconstant +tag-immediate+ #b0101)
(defconstant +tag-forward+   #b1111)

(defconstant +fixnum-shift+ 1)
(defconstant +char-shift+ 8)
(defconstant +char-tag+ #x05)

;;; Subtag constants for heap objects
(defconstant +subtag-bignum+ #x30)
(defconstant +subtag-string+ #x31)
(defconstant +subtag-array+  #x32)

;;; Placeholder addresses for NIL and T (patched during image build)
(defconstant +nil-value+ #xDEAD0001)
(defconstant +t-value+   #xDEAD1009)

;;; Maximum number of register arguments
(defconstant +max-reg-args+ 4)

;;; ============================================================
;;; Compilation State
;;; ============================================================

(defvar *ir-buffer* nil
  "Current IR instruction list being built (in reverse order)")

(defvar *functions* (make-hash-table :test 'equal)
  "Map from function name (string) to function-info")

(defvar *function-table* nil
  "Ordered list of function-info structs for the compiled module")

(defvar *constant-table* nil
  "List of constants needing allocation in the image")

(defvar *current-function-name* nil
  "Name of the function currently being compiled")

(defvar *macro-table* (make-hash-table :test 'equal)
  "Hash table of macro-name (string) -> expander function")

(defvar *label-counter* 0
  "Monotonic counter for generating unique labels")

(defvar *loop-exit-label* nil
  "Label for (return) to jump to in a loop")

(defvar *block-labels* nil
  "Alist of (name . exit-label) for block/return-from")

(defvar *tagbody-tags* nil
  "Alist of (tag . label) for tagbody/go")

(defvar *function-return-label* nil
  "Label for early return from function body (return outside loop)")

(defvar *temp-reg-counter* 0
  "Next temporary register to allocate (cycles through V4-V15)")

;;; ============================================================
;;; Structures
;;; ============================================================

(defstruct function-info
  name            ; symbol or string
  param-count     ; number of formal parameters
  bytecode-offset ; offset in the module bytecode vector
  bytecode-length ; length of this function's bytecode
  stack-frame-size) ; number of stack slots used

(defstruct compile-env
  (bindings nil)       ; list of binding structs
  (stack-depth 0)      ; current stack depth (in slots)
  (parent nil))        ; parent environment for nested scopes

(defstruct binding
  name               ; symbol name
  location           ; :reg or :stack
  reg                ; virtual register number if :reg
  stack-slot)        ; stack slot index if :stack

(defstruct compiled-module
  (bytecode (make-array 0 :element-type '(unsigned-byte 8)))
  (function-table nil)   ; list of function-info
  (constant-table nil))  ; list of constant values

;;; ============================================================
;;; Label Generation
;;; ============================================================

(defun make-compiler-label ()
  "Generate a unique label ID for the compiler"
  (incf *label-counter*))

;;; ============================================================
;;; Temporary Register Allocation
;;; ============================================================
;;;
;;; Simple linear allocation of V4-V8 for expression temporaries.
;;; Resets at the start of each expression statement.

(defun reset-temp-regs ()
  "Reset the temporary register counter"
  (setf *temp-reg-counter* 0))

(defun alloc-temp-reg ()
  "Allocate the next temporary register (V4-V15).
   V4-V8 map to physical registers; V9-V15 are spill slots that the
   translator automatically maps to stack frame locations."
  (let ((reg (+ +vreg-v4+ *temp-reg-counter*)))
    (when (> reg +vreg-v15+)
      (error "MVM compiler: out of temporary registers (need >12)"))
    (incf *temp-reg-counter*)
    reg))

(defun free-temp-reg ()
  "Free the most recently allocated temporary register"
  (when (> *temp-reg-counter* 0)
    (decf *temp-reg-counter*)))

(defun current-temp-count ()
  "Return how many temp regs are currently in use"
  *temp-reg-counter*)

;;; ============================================================
;;; IR Instruction Representation
;;; ============================================================
;;;
;;; IR instructions are simple lists:
;;;   (:op arg1 arg2 ...)
;;; Labels are represented as:
;;;   (:label label-id)
;;; Register operands are integers (virtual register numbers).
;;; Immediates are tagged with :imm:
;;;   (:imm value)

(defun emit-ir (op &rest args)
  "Emit an IR instruction to the current buffer"
  (push (cons op args) *ir-buffer*))

(defun emit-ir-label (label-id)
  "Emit a label marker in the IR stream"
  (push (list :label label-id) *ir-buffer*))

(defun get-ir-instructions ()
  "Return the IR instructions in forward order"
  (nreverse *ir-buffer*))

;;; ============================================================
;;; Environment Operations
;;; ============================================================

(defun make-empty-env ()
  "Create a fresh empty compilation environment"
  (make-compile-env))

(defun env-lookup (env name)
  "Find binding for NAME in ENV, searching parent chain. Returns binding or nil."
  (when env
    (or (find name (compile-env-bindings env)
              :key #'binding-name :test #'equal)
        (env-lookup (compile-env-parent env) name))))

(defun env-extend-reg (env name reg)
  "Add a register binding for NAME to ENV"
  (make-compile-env
   :bindings (cons (make-binding :name name :location :reg :reg reg)
                   (compile-env-bindings env))
   :stack-depth (compile-env-stack-depth env)
   :parent (compile-env-parent env)))

(defun env-extend-stack (env name)
  "Allocate a stack slot for NAME, return (values new-env slot-index)"
  (let* ((slot (compile-env-stack-depth env))
         (new-env (make-compile-env
                   :bindings (cons (make-binding :name name
                                                  :location :stack
                                                  :stack-slot slot)
                                   (compile-env-bindings env))
                   :stack-depth (1+ slot)
                   :parent (compile-env-parent env))))
    (values new-env slot)))

(defun env-child (env)
  "Create a child environment inheriting from ENV"
  (make-compile-env
   :bindings nil
   :stack-depth (compile-env-stack-depth env)
   :parent env))

;;; ============================================================
;;; Name Normalization
;;; ============================================================
;;;
;;; Cross-package compatibility: we compare operator names as
;;; uppercase strings, matching cross-compile.lisp's string-equal approach.

(defun normalize-name (sym)
  "Convert a symbol to its uppercase name string for comparison"
  (if (symbolp sym)
      (symbol-name sym)
      (string-upcase (princ-to-string sym))))

(defun name-eq (sym name-string)
  "Check if SYM's name matches NAME-STRING (case-insensitive)"
  (and (symbolp sym)
       (string-equal (symbol-name sym) name-string)))

;;; ============================================================
;;; Phase 1: Frontend (Source -> AST)
;;; ============================================================
;;;
;;; The frontend reads already-parsed s-expressions, expands macros,
;;; and produces an AST. For this compiler the AST is simply the
;;; expanded s-expression itself -- special forms, builtins, and calls
;;; are recognized during IR generation. Macro expansion is the key
;;; transformation in this phase.

(defun macroexpand-1-mvm (form)
  "Expand one level of macro in FORM, using the MVM macro table.
   Returns (values expanded-form expanded-p)."
  (if (and (consp form) (symbolp (car form)))
      (let* ((name (normalize-name (car form)))
             (expander (gethash name *macro-table*)))
        (if expander
            (values (funcall expander form) t)
            (values form nil)))
      (values form nil)))

(defun macroexpand-mvm (form)
  "Fully expand macros in FORM"
  (loop
    (multiple-value-bind (expanded expanded-p) (macroexpand-1-mvm form)
      (unless expanded-p
        (return form))
      (setf form expanded))))

(defun mvm-define-macro (name expander)
  "Register a macro with NAME (string) and EXPANDER function.
   EXPANDER takes the whole form (including the operator) and returns
   the expansion."
  (setf (gethash (string-upcase name) *macro-table*) expander))

(defun register-mvm-bootstrap-macros ()
  "Register standard CL macros needed to compile *runtime-functions*."
  ;; COND → nested IF
  (mvm-define-macro "COND"
    (lambda (form)
      (let ((clauses (cdr form)))
        (if (null clauses) nil
            (let ((clause (car clauses)))
              (if (and (symbolp (car clause))
                       (string-equal (symbol-name (car clause)) "T"))
                  `(progn ,@(cdr clause))
                  `(if ,(car clause)
                       (progn ,@(cdr clause))
                       (cond ,@(cdr clauses)))))))))
  ;; AND → nested IF
  (mvm-define-macro "AND"
    (lambda (form)
      (let ((args (cdr form)))
        (cond ((null args) t)
              ((null (cdr args)) (car args))
              (t `(if ,(car args) (and ,@(cdr args)) nil))))))
  ;; OR → LET + IF
  (mvm-define-macro "OR"
    (lambda (form)
      (let ((args (cdr form)))
        (cond ((null args) nil)
              ((null (cdr args)) (car args))
              (t (let ((tmp (gensym "OR")))
                   `(let ((,tmp ,(car args)))
                      (if ,tmp ,tmp (or ,@(cdr args)))))))))))

;;; ============================================================
;;; Phase 2: IR Generation (AST -> MVM IR)
;;; ============================================================
;;;
;;; Walks the AST (expanded s-expressions) and emits MVM IR instructions.
;;; The result of every expression ends up in a destination register,
;;; which defaults to VR (the return value register).

;;; ------ Main Dispatch ------

(defun compile-form (form env dest)
  "Compile FORM in environment ENV, placing result in register DEST.
   DEST is a virtual register number."
  ;; Macro expand first
  (let ((form (macroexpand-mvm form)))
    (cond
      ;; NIL
      ((null form)
       (compile-nil dest))

      ;; T
      ((eq form t)
       (compile-t dest))

      ;; Integer literal
      ((integerp form)
       (compile-integer form dest))

      ;; Character literal
      ((characterp form)
       (compile-character form dest))

      ;; String literal (docstrings become no-ops; no heap strings in bare-metal)
      ((stringp form)
       (compile-nil dest))

      ;; Keyword (self-evaluating)
      ((keywordp form)
       (compile-keyword form dest))

      ;; Variable reference
      ((symbolp form)
       (compile-variable-ref form env dest))

      ;; Compound forms (special forms, builtins, calls)
      ((consp form)
       (compile-compound form env dest))

      ;; Unrecognized
      (t
       (error "MVM compiler: cannot compile ~S" form)))))

;;; ------ Self-Evaluating Literals ------

(defun compile-nil (dest)
  "Load NIL into DEST"
  (emit-ir :mov dest +vreg-vn+))

(defun compile-t (dest)
  "Load T into DEST"
  (emit-ir :li dest +t-value+))

(defun compile-integer (value dest)
  "Load an integer literal (pre-tagged as fixnum) into DEST"
  (let ((tagged (ash value +fixnum-shift+)))
    (if (zerop tagged)
        (emit-ir :li dest 0)
        (emit-ir :li dest tagged))))

(defun compile-character (ch dest)
  "Load a character literal into DEST"
  (let ((tagged (logior (ash (char-code ch) +char-shift+) +char-tag+)))
    (emit-ir :li dest tagged)))

(defun compile-keyword (kw dest)
  "Load a keyword (as its hash) into DEST"
  (emit-ir :li dest (sxhash kw)))

;;; ------ Variable Reference ------

(defun compile-variable-ref (name env dest)
  "Compile a variable reference, placing result in DEST"
  (let ((binding (env-lookup env name)))
    (unless binding
      (error "MVM compiler: undefined variable ~A" name))
    (ecase (binding-location binding)
      (:reg
       (let ((src (binding-reg binding)))
         (unless (= src dest)
           (emit-ir :mov dest src))))
      (:stack
       ;; Load from stack slot: load [VFP - (slot+1)*8]
       (emit-ir :stack-load dest (binding-stack-slot binding))))))

;;; ------ Compound Form Dispatch ------

(defun compile-compound (form env dest)
  "Compile a compound form (operator . args)"
  (let* ((op (car form))
         (op-name (and (symbolp op) (normalize-name op))))
    (cond
      ;; --- Special Forms ---
      ((string-equal op-name "QUOTE")    (compile-quote (cadr form) dest))
      ((string-equal op-name "IF")       (compile-if (cdr form) env dest))
      ((string-equal op-name "PROGN")    (compile-progn (cdr form) env dest))
      ((string-equal op-name "LET")      (compile-let (cadr form) (cddr form) env dest))
      ((string-equal op-name "LET*")     (compile-let* (cadr form) (cddr form) env dest))
      ((string-equal op-name "SETQ")     (compile-setq (cadr form) (caddr form) env dest))
      ((string-equal op-name "LAMBDA")   (compile-lambda (cadr form) (cddr form) env dest))
      ((string-equal op-name "WHEN")     (compile-when (cdr form) env dest))
      ((string-equal op-name "UNLESS")   (compile-unless (cdr form) env dest))
      ((string-equal op-name "LOOP")     (compile-loop (cdr form) env dest))
      ((string-equal op-name "RETURN")   (compile-return (cadr form) env dest))
      ((string-equal op-name "BLOCK")    (compile-block (cadr form) (cddr form) env dest))
      ((string-equal op-name "TAGBODY")  (compile-tagbody (cdr form) env dest))
      ((string-equal op-name "GO")       (compile-go (cadr form) env dest))
      ((string-equal op-name "DOTIMES")  (compile-dotimes (cadr form) (cddr form) env dest))
      ((string-equal op-name "FUNCTION") (compile-function-ref (cadr form) env dest))
      ((string-equal op-name "FUNCALL")  (compile-funcall (cdr form) env dest))

      ;; --- Arithmetic ---
      ((string-equal op-name "+")        (compile-add (cdr form) env dest))
      ((string-equal op-name "-")        (compile-sub (cdr form) env dest))
      ((string-equal op-name "*")        (compile-mul (cdr form) env dest))
      ((string-equal op-name "/")        (compile-div (cdr form) env dest))
      ((string-equal op-name "1+")       (compile-1+ (cadr form) env dest))
      ((string-equal op-name "1-")       (compile-1- (cadr form) env dest))
      ((string-equal op-name "TRUNCATE") (compile-truncate (cdr form) env dest))
      ((string-equal op-name "MOD")      (compile-mod (cdr form) env dest))

      ;; --- Comparisons ---
      ((string-equal op-name "<")        (compile-compare :blt (cdr form) env dest))
      ((string-equal op-name ">")        (compile-compare :bgt (cdr form) env dest))
      ((string-equal op-name "=")        (compile-compare :beq (cdr form) env dest))
      ((string-equal op-name "<=")       (compile-compare :ble (cdr form) env dest))
      ((string-equal op-name ">=")       (compile-compare :bge (cdr form) env dest))
      ((string-equal op-name "EQ")       (compile-eq (cdr form) env dest))

      ;; --- List Operations ---
      ((string-equal op-name "CAR")      (compile-car (cadr form) env dest))
      ((string-equal op-name "CDR")      (compile-cdr (cadr form) env dest))
      ((string-equal op-name "CONS")     (compile-cons (cadr form) (caddr form) env dest))
      ((string-equal op-name "SET-CAR")  (compile-set-car (cadr form) (caddr form) env dest))
      ((string-equal op-name "SET-CDR")  (compile-set-cdr (cadr form) (caddr form) env dest))
      ((string-equal op-name "CAAR")     (compile-caar (cadr form) env dest))
      ((string-equal op-name "CADR")     (compile-cadr (cadr form) env dest))
      ((string-equal op-name "CDAR")     (compile-cdar (cadr form) env dest))
      ((string-equal op-name "CDDR")     (compile-cddr (cadr form) env dest))

      ;; --- Bitwise Operations ---
      ((string-equal op-name "LOGAND")   (compile-logand (cdr form) env dest))
      ((string-equal op-name "LOGIOR")   (compile-logior (cdr form) env dest))
      ((string-equal op-name "LOGXOR")   (compile-logxor (cdr form) env dest))
      ((string-equal op-name "ASH")      (compile-ash (cadr form) (caddr form) env dest))
      ((string-equal op-name "LDB")      (compile-ldb (cadr form) (caddr form) env dest))

      ;; --- Type Predicates ---
      ((string-equal op-name "NULL")     (compile-null (cadr form) env dest))
      ((string-equal op-name "NOT")      (compile-null (cadr form) env dest))
      ((string-equal op-name "CONSP")    (compile-consp (cadr form) env dest))
      ((string-equal op-name "FIXNUMP")  (compile-fixnump (cadr form) env dest))
      ((string-equal op-name "ATOM")     (compile-atom-p (cadr form) env dest))
      ((string-equal op-name "LISTP")    (compile-listp (cadr form) env dest))
      ((string-equal op-name "BIGNUMP")  (compile-bignump (cadr form) env dest))
      ((string-equal op-name "STRINGP")  (compile-stringp (cadr form) env dest))
      ((string-equal op-name "ARRAYP")   (compile-arrayp (cadr form) env dest))
      ((string-equal op-name "INTEGERP") (compile-integerp (cadr form) env dest))
      ((string-equal op-name "ZEROP")    (compile-zerop (cadr form) env dest))
      ((string-equal op-name "CHARACTERP") (compile-characterp (cadr form) env dest))

      ;; --- Character Operations ---
      ((string-equal op-name "CHAR-CODE") (compile-char-code (cadr form) env dest))
      ((string-equal op-name "CODE-CHAR") (compile-code-char (cadr form) env dest))

      ;; --- Memory Operations ---
      ((string-equal op-name "MEM-REF")  (compile-mem-ref (cadr form) (caddr form) env dest))
      ((string-equal op-name "SETF")     (compile-setf (cadr form) (caddr form) env dest))

      ;; --- I/O Port Operations ---
      ((string-equal op-name "IO-OUT-BYTE")  (compile-io-out-byte (cadr form) (caddr form) env dest))
      ((string-equal op-name "IO-IN-BYTE")   (compile-io-in-byte (cadr form) env dest))
      ((string-equal op-name "IO-OUT-DWORD") (compile-io-out-dword (cadr form) (caddr form) env dest))
      ((string-equal op-name "IO-IN-DWORD")  (compile-io-in-dword (cadr form) env dest))

      ;; --- Serial Console ---
      ((string-equal op-name "WRITE-CHAR-SERIAL") (compile-write-char-serial (cdr form) env dest))
      ((string-equal op-name "READ-CHAR-SERIAL")  (compile-read-char-serial dest))

      ;; --- System Registers ---
      ((string-equal op-name "GET-ALLOC-PTR")   (compile-get-alloc-ptr dest))
      ((string-equal op-name "GET-ALLOC-LIMIT") (compile-get-alloc-limit dest))
      ((string-equal op-name "SET-ALLOC-PTR")   (compile-set-alloc-ptr (cadr form) env dest))
      ((string-equal op-name "SET-ALLOC-LIMIT") (compile-set-alloc-limit (cadr form) env dest))
      ((string-equal op-name "UNTAG")           (compile-untag (cadr form) env dest))

      ;; --- Actor/Context Primitives ---
      ((string-equal op-name "SAVE-CONTEXT")    (compile-save-context (cadr form) env dest))
      ((string-equal op-name "RESTORE-CONTEXT") (compile-restore-context (cadr form) env dest))
      ((string-equal op-name "CALL-NATIVE")     (compile-call-native (cdr form) env dest))

      ;; --- SMP Primitives ---
      ((string-equal op-name "XCHG-MEM") (compile-xchg-mem (cadr form) (caddr form) env dest))
      ((string-equal op-name "PAUSE")    (compile-pause dest))
      ((string-equal op-name "MFENCE")   (compile-mfence dest))
      ((string-equal op-name "HLT")      (compile-hlt dest))
      ((string-equal op-name "WRMSR")    (compile-wrmsr (cdr form) env dest))
      ((string-equal op-name "STI")      (compile-sti dest))
      ((string-equal op-name "CLI")      (compile-cli dest))
      ((string-equal op-name "STI-HLT")  (compile-sti-hlt dest))

      ;; --- Per-CPU Data ---
      ((string-equal op-name "PERCPU-REF")       (compile-percpu-ref (cadr form) env dest))
      ((string-equal op-name "PERCPU-SET")       (compile-percpu-set (cadr form) (caddr form) env dest))
      ((string-equal op-name "SWITCH-IDLE-STACK") (compile-switch-idle-stack dest))
      ((string-equal op-name "SET-RSP")          (compile-set-rsp (cadr form) env dest))
      ((string-equal op-name "LIDT")             (compile-lidt (cadr form) env dest))

      ;; --- Function Call (default) ---
      (t (compile-call op (cdr form) env dest)))))

;;; ============================================================
;;; Quote
;;; ============================================================

(defun compile-quote (value dest)
  "Compile (quote VALUE)"
  (cond
    ((null value)
     (compile-nil dest))
    ((eq value t)
     (compile-t dest))
    ((integerp value)
     (compile-integer value dest))
    ((characterp value)
     (compile-character value dest))
    ((keywordp value)
     (compile-keyword value dest))
    (t
     ;; Complex constant: add to constant table, load placeholder
     (let ((idx (length *constant-table*)))
       (push value *constant-table*)
       (emit-ir :li-const dest idx)))))

;;; ============================================================
;;; If
;;; ============================================================

(defun compile-if (args env dest)
  "Compile (if test then &optional else)"
  (destructuring-bind (test then &optional else) args
    (let ((else-label (make-compiler-label))
          (end-label (make-compiler-label)))
      ;; Compile test into dest
      (compile-form test env dest)
      ;; Branch to else if nil
      (emit-ir :bnull dest else-label)
      ;; Then branch
      (compile-form then env dest)
      (emit-ir :br end-label)
      ;; Else branch
      (emit-ir-label else-label)
      (if else
          (compile-form else env dest)
          (compile-nil dest))
      ;; Join
      (emit-ir-label end-label))))

;;; ============================================================
;;; Progn
;;; ============================================================

(defun compile-progn (forms env dest)
  "Compile (progn form*). Result of last form goes to DEST."
  (if (null forms)
      (compile-nil dest)
      (loop for (form . rest) on forms
            do (if rest
                   ;; Not the last form: compile for effect, result discarded
                   (compile-form form env dest)
                   ;; Last form: result goes to DEST
                   (compile-form form env dest)))))

;;; ============================================================
;;; Let / Let*
;;; ============================================================

(defun compile-let (bindings body env dest)
  "Compile (let ((var val)*) body*).
   All values are evaluated in the outer environment, then bound."
  (let ((n-bindings (length bindings))
        (new-env env)
        (save-temps nil))
    ;; Phase 1: Evaluate all values in original env, store to temp regs
    ;; We use a set of temp regs (or stack slots for > 5 bindings)
    (when (> n-bindings 0)
      ;; Allocate stack frame space for local variables
      (emit-ir :frame-alloc n-bindings))
    ;; Evaluate each binding value and store it to a stack slot
    (loop for (var val) in bindings
          for i from 0
          do (let ((temp (alloc-temp-reg)))
               (compile-form val env temp)
               ;; Store to stack slot
               (let ((slot (+ (compile-env-stack-depth env) i)))
                 (emit-ir :stack-store temp slot))
               (free-temp-reg)))
    ;; Phase 2: Build new environment with stack bindings
    (loop for (var val) in bindings
          for i from 0
          do (setf new-env
                   (make-compile-env
                    :bindings (cons (make-binding
                                     :name var
                                     :location :stack
                                     :stack-slot (+ (compile-env-stack-depth env) i))
                                   (compile-env-bindings new-env))
                    :stack-depth (+ (compile-env-stack-depth env) n-bindings)
                    :parent (compile-env-parent new-env))))
    ;; Fix stack-depth in the final env
    (setf (compile-env-stack-depth new-env)
          (+ (compile-env-stack-depth env) n-bindings))
    ;; Compile body in new environment
    (compile-progn body new-env dest)
    ;; Deallocate frame space
    (when (> n-bindings 0)
      (emit-ir :frame-free n-bindings))))

(defun compile-let* (bindings body env dest)
  "Compile (let* ((var val)*) body*).
   Values are evaluated sequentially; each can see earlier bindings."
  (let ((n-bindings (length bindings))
        (new-env env))
    (when (> n-bindings 0)
      (emit-ir :frame-alloc n-bindings))
    ;; Evaluate sequentially, extending env each time
    (loop for (var val) in bindings
          for i from 0
          do (let ((temp (alloc-temp-reg))
                   (slot (+ (compile-env-stack-depth env) i)))
               (compile-form val new-env temp)
               (emit-ir :stack-store temp slot)
               (free-temp-reg)
               ;; Extend environment with this new binding
               (setf new-env
                     (make-compile-env
                      :bindings (cons (make-binding
                                        :name var
                                        :location :stack
                                        :stack-slot slot)
                                      (compile-env-bindings new-env))
                      :stack-depth (+ (compile-env-stack-depth env) (1+ i))
                      :parent (compile-env-parent new-env)))))
    ;; Final env has correct stack depth
    (setf (compile-env-stack-depth new-env)
          (+ (compile-env-stack-depth env) n-bindings))
    ;; Compile body
    (compile-progn body new-env dest)
    ;; Deallocate
    (when (> n-bindings 0)
      (emit-ir :frame-free n-bindings))))

;;; ============================================================
;;; Setq
;;; ============================================================

(defun compile-setq (var val env dest)
  "Compile (setq var val)"
  (compile-form val env dest)
  (let ((binding (env-lookup env var)))
    (unless binding
      (error "MVM compiler: undefined variable ~A in setq" var))
    (ecase (binding-location binding)
      (:reg
       (unless (= (binding-reg binding) dest)
         (emit-ir :mov (binding-reg binding) dest)))
      (:stack
       (emit-ir :stack-store dest (binding-stack-slot binding))))))

;;; ============================================================
;;; Lambda
;;; ============================================================

(defun compile-lambda (params body env dest)
  "Compile (lambda (params) body*).
   Creates a closure-like function. For now, compiles as a nested function
   reference (full closures would need heap allocation for captured vars)."
  (declare (ignore env))
  (let* ((lambda-name (format nil "~A$$LAMBDA~D"
                               (or *current-function-name* "ANON")
                               (make-compiler-label)))
         (fn-info (mvm-compile-function-internal lambda-name params body)))
    ;; Load function reference into dest
    ;; This will be resolved to a bytecode offset during linking
    (emit-ir :li-func dest lambda-name)))

;;; ============================================================
;;; When / Unless
;;; ============================================================

(defun compile-when (args env dest)
  "Compile (when test body...) -> (if test (progn body...) nil)"
  (let ((test (car args))
        (body (cdr args)))
    (compile-if (list test (cons 'progn body)) env dest)))

(defun compile-unless (args env dest)
  "Compile (unless test body...) -> (if test nil (progn body...))"
  (let ((test (car args))
        (body (cdr args)))
    (compile-if (list test nil (cons 'progn body)) env dest)))

;;; ============================================================
;;; Loop / Return
;;; ============================================================

(defun compile-loop (body env dest)
  "Compile (loop forms...) - infinite loop with (return val) to exit"
  (let* ((loop-label (make-compiler-label))
         (exit-label (make-compiler-label))
         (*loop-exit-label* exit-label))
    ;; Loop entry
    (emit-ir-label loop-label)
    ;; Compile loop body
    (compile-progn body env dest)
    ;; Yield/preemption check
    (emit-ir :yield)
    ;; Jump back to loop start
    (emit-ir :br loop-label)
    ;; Exit label (target of return)
    (emit-ir-label exit-label)))

(defun compile-return (value env dest)
  "Compile (return value) - exit from enclosing loop or function.
   If inside a loop, jumps to loop exit. Otherwise, compiles the value
   into VR and jumps to the function return epilogue."
  (cond
    (*loop-exit-label*
     (compile-form value env dest)
     (emit-ir :br *loop-exit-label*))
    (*function-return-label*
     ;; Function-level return: result goes to VR, jump to epilogue
     (compile-form value env +vreg-vr+)
     (emit-ir :br *function-return-label*))
    (t
     (error "MVM compiler: RETURN outside of LOOP or function"))))

;;; ============================================================
;;; Block / Tagbody / Go
;;; ============================================================

(defun compile-block (name body env dest)
  "Compile (block name forms...)"
  (let* ((exit-label (make-compiler-label))
         (*block-labels* (cons (cons name exit-label) *block-labels*)))
    (compile-progn body env dest)
    (emit-ir-label exit-label)))

(defun compile-tagbody (body env dest)
  "Compile (tagbody {tag | form}*)"
  (let ((*tagbody-tags* nil))
    ;; First pass: collect tags and create labels
    (dolist (item body)
      (when (symbolp item)
        (push (cons item (make-compiler-label)) *tagbody-tags*)))
    ;; Second pass: compile
    (dolist (item body)
      (if (symbolp item)
          ;; It's a tag: emit label
          (emit-ir-label (cdr (assoc item *tagbody-tags*)))
          ;; It's a form: compile it
          (compile-form item env dest)))
    ;; Tagbody returns nil
    (compile-nil dest)))

(defun compile-go (tag env dest)
  "Compile (go tag)"
  (declare (ignore env dest))
  (let ((entry (assoc tag *tagbody-tags*)))
    (unless entry
      (error "MVM compiler: unknown GO tag ~A" tag))
    (emit-ir :br (cdr entry))))

;;; ============================================================
;;; Dotimes
;;; ============================================================

(defun compile-dotimes (spec body env dest)
  "Compile (dotimes (var count) body...).
   Expands to: (let ((var 0)) (loop (if (< var count) (progn body (setq var (1+ var))) (return nil))))"
  (let* ((var (car spec))
         (count-form (cadr spec)))
    (compile-let
     (list (list var 0))
     (list (list 'loop
                 (list 'if (list '< var count-form)
                       (append (list 'progn)
                               body
                               (list (list 'setq var (list '1+ var))))
                       (list 'return nil))))
     env dest)))

;;; ============================================================
;;; Higher-Order: function / funcall
;;; ============================================================

(defun compile-function-ref (name env dest)
  "Compile (function fname) - return function address as tagged value"
  (declare (ignore env))
  ;; Emit a load-function-ref IR that will be resolved during linking
  (emit-ir :li-func dest (normalize-name name)))

(defun compile-funcall (args env dest)
  "Compile (funcall f arg1 arg2 ...) - indirect function call"
  (let ((fn-form (car args))
        (call-args (cdr args))
        (nargs (length (cdr args))))
    ;; Push overflow args FIRST (before populating V0-V3), because
    ;; evaluating overflow args may involve function calls that clobber V0-V3.
    (when (> nargs +max-reg-args+)
      (dolist (arg (reverse (nthcdr +max-reg-args+ call-args)))
        (let ((temp (alloc-temp-reg)))
          (compile-form arg env temp)
          (emit-ir :push temp)
          (free-temp-reg))))
    ;; Compile function expression into a temp, push on top of overflow args
    (let ((fn-reg (alloc-temp-reg)))
      (compile-form fn-form env fn-reg)
      (emit-ir :push fn-reg)
      (free-temp-reg))
    ;; Now compile register args using push/pop pattern (safe from clobbering)
    (let ((reg-count (min nargs +max-reg-args+)))
      (dotimes (i reg-count)
        (let ((temp (alloc-temp-reg)))
          (compile-form (nth i call-args) env temp)
          (emit-ir :push temp)
          (free-temp-reg)))
      (loop for i from (1- reg-count) downto 0
            do (emit-ir :pop (+ +vreg-v0+ i))))
    ;; Pop function address (on top of overflow args) and call indirect
    (let ((fn-call-reg (alloc-temp-reg)))
      (emit-ir :pop fn-call-reg)
      (emit-ir :call-indirect fn-call-reg nargs)
      (free-temp-reg))
    ;; Move result to dest
    (unless (= dest +vreg-vr+)
      (emit-ir :mov dest +vreg-vr+))
    ;; Clean up overflow args with POP (frame-free is NOP in translator)
    (when (> nargs +max-reg-args+)
      (let ((temp (alloc-temp-reg)))
        (dotimes (i (- nargs +max-reg-args+))
          (emit-ir :pop temp))
        (free-temp-reg)))))

;;; ============================================================
;;; Arithmetic Operations
;;; ============================================================

(defun compile-add (args env dest)
  "Compile (+ args...). Fixnum addition preserves tags for 2-arg case.
   Push/pop dest around each operand to survive function calls."
  (cond
    ((null args)
     ;; (+) = 0
     (compile-integer 0 dest))
    ((null (cdr args))
     ;; (+ x) = x
     (compile-form (car args) env dest))
    (t
     ;; (+ a b ...) -- evaluate pairwise, push/pop to preserve accumulator
     ;; across function calls in later args.
     (compile-form (car args) env dest)
     (dolist (arg (cdr args))
       (let ((temp (alloc-temp-reg)))
         (emit-ir :push dest)
         (compile-form arg env temp)
         (emit-ir :pop dest)
         ;; Tagged fixnum add: (a<<1) + (b<<1) = (a+b)<<1
         (emit-ir :add dest dest temp)
         (free-temp-reg))))))

(defun compile-sub (args env dest)
  "Compile (- args...). Handles unary negation and multi-arg subtraction.
   Push/pop dest around each operand to survive function calls."
  (cond
    ((null args)
     (compile-integer 0 dest))
    ((null (cdr args))
     ;; Unary minus: (- x) = negate
     (compile-form (car args) env dest)
     (emit-ir :neg dest dest))
    (t
     ;; (- a b ...) -- subtract pairwise, push/pop to preserve accumulator
     ;; across function calls in later args.
     (compile-form (car args) env dest)
     (dolist (arg (cdr args))
       (let ((temp (alloc-temp-reg)))
         (emit-ir :push dest)
         (compile-form arg env temp)
         (emit-ir :pop dest)
         (emit-ir :sub dest dest temp)
         (free-temp-reg))))))

(defun compile-mul (args env dest)
  "Compile (* args...). For tagged fixnums: result = (a*b)>>1 to fix double-tag.
   Push/pop dest around each operand to survive function calls."
  (cond
    ((null args)
     ;; (*) = 1
     (compile-integer 1 dest))
    ((null (cdr args))
     ;; (* x) = x
     (compile-form (car args) env dest))
    (t
     ;; (* a b ...) -- multiply pairwise, push/pop to preserve accumulator
     ;; across function calls in later args.
     (compile-form (car args) env dest)
     (dolist (arg (cdr args))
       (let ((temp (alloc-temp-reg)))
         (emit-ir :push dest)
         (compile-form arg env temp)
         (emit-ir :pop dest)
         (emit-ir :mul dest dest temp)
         (free-temp-reg))))))

(defun compile-div (args env dest)
  "Compile (/ a b). Truncating integer division for tagged fixnums.
   Push/pop dest around divisor to survive function calls."
  (when (null args) (error "/ requires at least one argument"))
  (if (null (cdr args))
      ;; (/ x) = 1/x (not meaningful for integers, just return x)
      (compile-form (car args) env dest)
      ;; (/ a b ...) -- divide pairwise
      (progn
        (compile-form (car args) env dest)
        (dolist (arg (cdr args))
          (let ((temp (alloc-temp-reg)))
            (emit-ir :push dest)
            (compile-form arg env temp)
            (emit-ir :pop dest)
            (emit-ir :div dest dest temp)
            (free-temp-reg))))))

(defun compile-1+ (arg env dest)
  "Compile (1+ x) -> add tagged 1 (which is 2)"
  (compile-form arg env dest)
  (emit-ir :inc dest))

(defun compile-1- (arg env dest)
  "Compile (1- x) -> subtract tagged 1 (which is 2)"
  (compile-form arg env dest)
  (emit-ir :dec dest))

(defun compile-truncate (args env dest)
  "Compile (truncate a b) - integer division, quotient to DEST.
   Push/pop dest around second operand to survive function calls."
  (destructuring-bind (a b) args
    (let ((temp (alloc-temp-reg)))
      (compile-form a env dest)
      (emit-ir :push dest)
      (compile-form b env temp)
      (emit-ir :pop dest)
      (emit-ir :div dest dest temp)
      (free-temp-reg))))

(defun compile-mod (args env dest)
  "Compile (mod a b) - integer modulus, remainder to DEST.
   Push/pop dest around second operand to survive function calls."
  (destructuring-bind (a b) args
    (let ((temp (alloc-temp-reg)))
      (compile-form a env dest)
      (emit-ir :push dest)
      (compile-form b env temp)
      (emit-ir :pop dest)
      (emit-ir :mod dest dest temp)
      (free-temp-reg))))

;;; ============================================================
;;; Comparison Operations
;;; ============================================================

(defun compile-compare (branch-op args env dest)
  "Compile a comparison (<, >, =, <=, >=) producing T or NIL.
   BRANCH-OP is the branch instruction keyword to use when the comparison
   is true (:blt, :bgt, :beq, :ble, :bge).
   Push/pop dest around second operand to survive function calls."
  (destructuring-bind (a b) args
    (let ((temp (alloc-temp-reg))
          (true-label (make-compiler-label))
          (end-label (make-compiler-label)))
      (compile-form a env dest)
      (emit-ir :push dest)
      (compile-form b env temp)
      (emit-ir :pop dest)
      ;; Compare dest vs temp
      (emit-ir :cmp dest temp)
      ;; Branch if true
      (emit-ir branch-op true-label)
      ;; False: load NIL
      (compile-nil dest)
      (emit-ir :br end-label)
      ;; True: load T
      (emit-ir-label true-label)
      (compile-t dest)
      ;; Join
      (emit-ir-label end-label)
      (free-temp-reg))))

(defun compile-eq (args env dest)
  "Compile (eq a b) - pointer equality.
   Push/pop dest around second operand to survive function calls."
  (destructuring-bind (a b) args
    (let ((temp (alloc-temp-reg))
          (true-label (make-compiler-label))
          (end-label (make-compiler-label)))
      (compile-form a env dest)
      (emit-ir :push dest)
      (compile-form b env temp)
      (emit-ir :pop dest)
      (emit-ir :cmp dest temp)
      (emit-ir :beq true-label)
      ;; Not equal: NIL
      (compile-nil dest)
      (emit-ir :br end-label)
      ;; Equal: T
      (emit-ir-label true-label)
      (compile-t dest)
      (emit-ir-label end-label)
      (free-temp-reg))))

;;; ============================================================
;;; List Operations
;;; ============================================================

(defun compile-car (arg env dest)
  "Compile (car x) -> MVM car instruction"
  (compile-form arg env dest)
  (emit-ir :car dest dest))

(defun compile-cdr (arg env dest)
  "Compile (cdr x) -> MVM cdr instruction"
  (compile-form arg env dest)
  (emit-ir :cdr dest dest))

(defun compile-cons (car-arg cdr-arg env dest)
  "Compile (cons x y) -> MVM cons instruction (allocating).
   Saves car result to stack before evaluating cdr to prevent
   temp register exhaustion with deeply nested cons expressions."
  ;; Evaluate car into dest, save to stack
  (compile-form car-arg env dest)
  (emit-ir :push dest)
  ;; Evaluate cdr into dest (car is safe on stack)
  (compile-form cdr-arg env dest)
  ;; Move cdr to temp, restore car
  (let ((temp (alloc-temp-reg)))
    (emit-ir :mov temp dest)
    (emit-ir :pop dest)
    ;; GC check before allocation
    (emit-ir :gc-check)
    ;; Cons: dest = cons(dest, temp)
    (emit-ir :cons dest dest temp)
    (free-temp-reg)))

(defun compile-set-car (cell-arg value-arg env dest)
  "Compile (set-car cell value)"
  (let ((temp (alloc-temp-reg)))
    (compile-form cell-arg env dest)
    (compile-form value-arg env temp)
    (emit-ir :setcar dest temp)
    ;; Write barrier for GC
    (emit-ir :write-barrier dest)
    ;; Return the value
    (emit-ir :mov dest temp)
    (free-temp-reg)))

(defun compile-set-cdr (cell-arg value-arg env dest)
  "Compile (set-cdr cell value)"
  (let ((temp (alloc-temp-reg)))
    (compile-form cell-arg env dest)
    (compile-form value-arg env temp)
    (emit-ir :setcdr dest temp)
    (emit-ir :write-barrier dest)
    (emit-ir :mov dest temp)
    (free-temp-reg)))

;; Compound accessors

(defun compile-caar (arg env dest)
  "Compile (caar x) = (car (car x))"
  (compile-form arg env dest)
  (emit-ir :car dest dest)
  (emit-ir :car dest dest))

(defun compile-cadr (arg env dest)
  "Compile (cadr x) = (car (cdr x))"
  (compile-form arg env dest)
  (emit-ir :cdr dest dest)
  (emit-ir :car dest dest))

(defun compile-cdar (arg env dest)
  "Compile (cdar x) = (cdr (car x))"
  (compile-form arg env dest)
  (emit-ir :car dest dest)
  (emit-ir :cdr dest dest))

(defun compile-cddr (arg env dest)
  "Compile (cddr x) = (cdr (cdr x))"
  (compile-form arg env dest)
  (emit-ir :cdr dest dest)
  (emit-ir :cdr dest dest))

;;; ============================================================
;;; Bitwise Operations
;;; ============================================================

(defun compile-logand (args env dest)
  "Compile (logand args...).
   Push/pop dest around each operand to survive function calls."
  (cond
    ((null args)
     ;; (logand) = -1
     (emit-ir :li dest -1))
    ((null (cdr args))
     (compile-form (car args) env dest))
    (t
     (compile-form (car args) env dest)
     (dolist (arg (cdr args))
       (let ((temp (alloc-temp-reg)))
         (emit-ir :push dest)
         (compile-form arg env temp)
         (emit-ir :pop dest)
         (emit-ir :and dest dest temp)
         (free-temp-reg))))))

(defun compile-logior (args env dest)
  "Compile (logior args...).
   Push/pop dest around each operand to survive function calls."
  (cond
    ((null args)
     (compile-integer 0 dest))
    ((null (cdr args))
     (compile-form (car args) env dest))
    (t
     (compile-form (car args) env dest)
     (dolist (arg (cdr args))
       (let ((temp (alloc-temp-reg)))
         (emit-ir :push dest)
         (compile-form arg env temp)
         (emit-ir :pop dest)
         (emit-ir :or dest dest temp)
         (free-temp-reg))))))

(defun compile-logxor (args env dest)
  "Compile (logxor args...).
   Push/pop dest around each operand to survive function calls."
  (cond
    ((null args)
     (compile-integer 0 dest))
    ((null (cdr args))
     (compile-form (car args) env dest))
    (t
     (compile-form (car args) env dest)
     (dolist (arg (cdr args))
       (let ((temp (alloc-temp-reg)))
         (emit-ir :push dest)
         (compile-form arg env temp)
         (emit-ir :pop dest)
         (emit-ir :xor dest dest temp)
         (free-temp-reg))))))

(defun compile-ash (value-form count-form env dest)
  "Compile (ash value count) - arithmetic shift.
   Positive count = left shift, negative = right shift.
   Handles both constant and variable shift counts."
  (compile-form value-form env dest)
  (cond
    ;; Constant shift count
    ((integerp count-form)
     (if (>= count-form 0)
         ;; Left shift
         (emit-ir :shl dest dest count-form)
         ;; Right shift, then fix tag
         (progn
           (emit-ir :sar dest dest (- count-form))
           ;; AND with ~1 to ensure fixnum tag (low bit 0)
           (let ((temp (alloc-temp-reg)))
             (emit-ir :li temp -2)
             (emit-ir :and dest dest temp)
             (free-temp-reg)))))
    ;; Variable shift count
    (t
     (let ((count-reg (alloc-temp-reg))
           (pos-label (make-compiler-label))
           (neg-label (make-compiler-label))
           (done-label (make-compiler-label)))
       ;; Push/pop dest around count evaluation to survive function calls
       (emit-ir :push dest)
       (compile-form count-form env count-reg)
       (emit-ir :pop dest)
       ;; Untag both: sar by 1
       (emit-ir :sar dest dest 1)
       (emit-ir :sar count-reg count-reg 1)
       ;; Test sign of count
       (let ((zero-reg (alloc-temp-reg)))
         (emit-ir :li zero-reg 0)
         (emit-ir :cmp count-reg zero-reg)
         (free-temp-reg))
       (emit-ir :bge pos-label)
       ;; Negative (right shift): negate count, sar
       (emit-ir :neg count-reg count-reg)
       (emit-ir :sar-var dest dest count-reg)
       (emit-ir :br done-label)
       ;; Positive (left shift): shl
       (emit-ir-label pos-label)
       (emit-ir :shl-var dest dest count-reg)
       ;; Done: re-tag
       (emit-ir-label done-label)
       (emit-ir :shl dest dest 1)
       (free-temp-reg)))))

(defun compile-ldb (bytespec value-form env dest)
  "Compile (ldb (byte size pos) value) - extract bit field"
  (unless (and (consp bytespec)
               (name-eq (car bytespec) "BYTE"))
    (error "MVM compiler: LDB requires (byte size pos) form, got ~S" bytespec))
  (let ((size (cadr bytespec))
        (pos (caddr bytespec)))
    (compile-form value-form env dest)
    ;; Shift right by position
    (when (and (integerp pos) (> pos 0))
      (emit-ir :shr dest dest pos))
    ;; Mask to size bits
    (when (integerp size)
      (let ((mask (1- (ash 1 size)))
            (temp (alloc-temp-reg)))
        (emit-ir :li temp mask)
        (emit-ir :and dest dest temp)
        (free-temp-reg)))))

;;; ============================================================
;;; Type Predicates
;;; ============================================================
;;;
;;; Each predicate compiles to: test + conditional branch -> T or NIL.

(defun compile-type-predicate-branch (dest true-label end-label)
  "Helper: emit the false->NIL, true->T pattern for type predicates"
  ;; Fall through = false
  (compile-nil dest)
  (emit-ir :br end-label)
  ;; True path
  (emit-ir-label true-label)
  (compile-t dest)
  (emit-ir-label end-label))

(defun compile-null (arg env dest)
  "Compile (null x) or (not x) - true if x is NIL"
  (let ((true-label (make-compiler-label))
        (end-label (make-compiler-label)))
    (compile-form arg env dest)
    (emit-ir :bnull dest true-label)
    ;; Not nil -> return NIL
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; Was nil -> return T
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)))

(defun compile-consp (arg env dest)
  "Compile (consp x) - true if x has cons tag.
   The MVM consp instruction produces a tagged boolean (T or NIL) in dest."
  (compile-form arg env dest)
  ;; MVM consp: dest = (consp? src) -> T or NIL
  (emit-ir :consp dest dest))

(defun compile-fixnump (arg env dest)
  "Compile (fixnump x) - true if low bit is 0"
  (let ((temp (alloc-temp-reg))
        (true-label (make-compiler-label))
        (end-label (make-compiler-label)))
    (compile-form arg env dest)
    ;; Test low bit: AND with 1
    (emit-ir :li temp 1)
    (emit-ir :test dest temp)
    ;; If zero flag set (low bit is 0), it's a fixnum
    (emit-ir :beq true-label)
    (compile-type-predicate-branch dest true-label end-label)
    (free-temp-reg)))

(defun compile-atom-p (arg env dest)
  "Compile (atom x) - true if x is not a cons.
   The MVM atom instruction produces a tagged boolean (T or NIL) in dest."
  (compile-form arg env dest)
  ;; MVM atom: dest = (atom? src) -> T or NIL
  (emit-ir :atom dest dest))

(defun compile-listp (arg env dest)
  "Compile (listp x) - true if x is NIL or a cons"
  (let ((true-label (make-compiler-label))
        (check-cons-label (make-compiler-label))
        (end-label (make-compiler-label)))
    (compile-form arg env dest)
    ;; Check for nil first
    (emit-ir :bnull dest true-label)
    ;; Not nil: check if cons
    (let ((temp (alloc-temp-reg)))
      (emit-ir :consp temp dest)
      (emit-ir :bnnull temp true-label)
      (free-temp-reg))
    ;; Neither nil nor cons
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; Is a list (nil or cons)
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)))

(defun compile-bignump (arg env dest)
  "Compile (bignump x) - true if object tag with bignum subtag"
  (let ((true-label (make-compiler-label))
        (end-label (make-compiler-label))
        (false-label (make-compiler-label))
        (temp (alloc-temp-reg))
        (temp2 (alloc-temp-reg)))
    (compile-form arg env dest)
    ;; Extract tag: AND with #x0F
    (emit-ir :li temp #x0F)
    (emit-ir :and temp dest temp)
    ;; Compare to object tag (#x09)
    (emit-ir :li temp2 +tag-object+)
    (emit-ir :cmp temp temp2)
    (emit-ir :bne false-label)  ; wrong tag -> false
    ;; Has object tag: check subtag
    ;; Extract subtag from header at [obj & ~0xF]
    (emit-ir :obj-subtag temp dest)
    (emit-ir :li temp2 +subtag-bignum+)
    (emit-ir :cmp temp temp2)
    (emit-ir :beq true-label)
    ;; False
    (emit-ir-label false-label)
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; True
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)
    (free-temp-reg)
    (free-temp-reg)))

(defun compile-object-subtype-p (arg env dest expected-subtag)
  "Helper: compile a predicate that checks for object tag + specific subtag"
  (let ((true-label (make-compiler-label))
        (end-label (make-compiler-label))
        (false-label (make-compiler-label))
        (temp (alloc-temp-reg))
        (temp2 (alloc-temp-reg)))
    (compile-form arg env dest)
    ;; Check object tag
    (emit-ir :obj-tag temp dest)
    (emit-ir :li temp2 +tag-object+)
    (emit-ir :cmp temp temp2)
    (emit-ir :bne false-label)
    ;; Check subtag
    (emit-ir :obj-subtag temp dest)
    (emit-ir :li temp2 expected-subtag)
    (emit-ir :cmp temp temp2)
    (emit-ir :beq true-label)
    ;; False
    (emit-ir-label false-label)
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; True
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)
    (free-temp-reg)
    (free-temp-reg)))

(defun compile-stringp (arg env dest)
  "Compile (stringp x)"
  (compile-object-subtype-p arg env dest +subtag-string+))

(defun compile-arrayp (arg env dest)
  "Compile (arrayp x)"
  (compile-object-subtype-p arg env dest +subtag-array+))

(defun compile-integerp (arg env dest)
  "Compile (integerp x) - true if fixnum or bignum"
  (let ((check-bignum-label (make-compiler-label))
        (true-label (make-compiler-label))
        (false-label (make-compiler-label))
        (end-label (make-compiler-label))
        (temp (alloc-temp-reg))
        (temp2 (alloc-temp-reg)))
    (compile-form arg env dest)
    ;; Check fixnum: low bit 0
    (emit-ir :li temp 1)
    (emit-ir :test dest temp)
    (emit-ir :bne check-bignum-label)
    ;; Low bit 0: fixnum if not nil
    (emit-ir :bnull dest false-label)
    (emit-ir :br true-label)
    ;; Check bignum
    (emit-ir-label check-bignum-label)
    (emit-ir :obj-tag temp dest)
    (emit-ir :li temp2 +tag-object+)
    (emit-ir :cmp temp temp2)
    (emit-ir :bne false-label)
    ;; Check subtag
    (emit-ir :obj-subtag temp dest)
    (emit-ir :li temp2 +subtag-bignum+)
    (emit-ir :cmp temp temp2)
    (emit-ir :beq true-label)
    ;; False
    (emit-ir-label false-label)
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; True
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)
    (free-temp-reg)
    (free-temp-reg)))

(defun compile-zerop (arg env dest)
  "Compile (zerop x) - true if x is fixnum zero"
  (let ((true-label (make-compiler-label))
        (end-label (make-compiler-label))
        (temp (alloc-temp-reg)))
    (compile-form arg env dest)
    ;; Tagged fixnum 0 is 0
    (emit-ir :li temp 0)
    (emit-ir :cmp dest temp)
    (emit-ir :beq true-label)
    ;; Not zero
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; Zero
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)
    (free-temp-reg)))

(defun compile-characterp (arg env dest)
  "Compile (characterp x) - true if low byte = #x05"
  (let ((true-label (make-compiler-label))
        (end-label (make-compiler-label))
        (temp (alloc-temp-reg))
        (temp2 (alloc-temp-reg)))
    (compile-form arg env dest)
    ;; Extract low byte
    (emit-ir :li temp #xFF)
    (emit-ir :and temp dest temp)
    ;; Compare to char tag
    (emit-ir :li temp2 +char-tag+)
    (emit-ir :cmp temp temp2)
    (emit-ir :beq true-label)
    ;; Not character
    (compile-nil dest)
    (emit-ir :br end-label)
    ;; Is character
    (emit-ir-label true-label)
    (compile-t dest)
    (emit-ir-label end-label)
    (free-temp-reg)
    (free-temp-reg)))

;;; ============================================================
;;; Character Operations
;;; ============================================================

(defun compile-char-code (arg env dest)
  "Compile (char-code c) - extract character code as fixnum.
   Character: code in bits 8+. Fixnum: value << 1.
   Net shift: right by (char-shift - fixnum-shift) = 7."
  (compile-form arg env dest)
  (emit-ir :sar dest dest (- +char-shift+ +fixnum-shift+)))

(defun compile-code-char (arg env dest)
  "Compile (code-char n) - create character from code.
   Input: fixnum (code << 1). Output: (code << 8) | #x05.
   Net shift: left by 7, then OR with char tag."
  (compile-form arg env dest)
  (emit-ir :shl dest dest (- +char-shift+ +fixnum-shift+))
  (let ((temp (alloc-temp-reg)))
    (emit-ir :li temp +char-tag+)
    (emit-ir :or dest dest temp)
    (free-temp-reg)))

;;; ============================================================
;;; Memory Operations
;;; ============================================================

(defun memory-width-code (type-form)
  "Convert a type keyword to an MVM memory width code.
   Returns (values width-code needs-tag-p)"
  (let ((actual-type (if (and (consp type-form)
                               (name-eq (car type-form) "QUOTE"))
                          (cadr type-form)
                          type-form)))
    (cond
      ((or (eq actual-type :u8)  (name-eq actual-type "U8"))
       (values +width-u8+ t))
      ((or (eq actual-type :u16) (name-eq actual-type "U16"))
       (values +width-u16+ t))
      ((or (eq actual-type :u32) (name-eq actual-type "U32"))
       (values +width-u32+ t))
      ((or (eq actual-type :u64) (name-eq actual-type "U64"))
       (values +width-u64+ nil))
      (t
       ;; Default: u64, no tagging (raw pointer)
       (values +width-u64+ nil)))))

(defun compile-mem-ref (addr-form type-form env dest)
  "Compile (mem-ref addr type) - raw memory read.
   Address is a tagged fixnum. Type controls width and tagging."
  (compile-form addr-form env dest)
  ;; Untag address: sar by 1
  (emit-ir :sar dest dest +fixnum-shift+)
  ;; Load from memory
  (multiple-value-bind (width needs-tag) (memory-width-code type-form)
    (emit-ir :load dest dest width)
    ;; Tag result as fixnum if needed (u8/u16/u32)
    (when needs-tag
      (emit-ir :shl dest dest +fixnum-shift+))))

(defun compile-setf (place value-form env dest)
  "Compile (setf place value)"
  (cond
    ;; (setf (mem-ref addr type) value)
    ((and (consp place) (name-eq (car place) "MEM-REF"))
     (let ((addr-form (cadr place))
           (type-form (caddr place)))
       (multiple-value-bind (width needs-untag) (memory-width-code type-form)
         (let ((addr-reg (alloc-temp-reg)))
           ;; Compile value first
           (compile-form value-form env dest)
           ;; Save value across address evaluation (may involve function calls
           ;; that clobber caller-saved regs including dest)
           (emit-ir :push dest)
           ;; Compile address
           (compile-form addr-form env addr-reg)
           ;; Restore value
           (emit-ir :pop dest)
           ;; Untag address
           (emit-ir :sar addr-reg addr-reg +fixnum-shift+)
           ;; Untag value for sub-64-bit stores
           (when needs-untag
             (emit-ir :sar dest dest +fixnum-shift+))
           ;; Store
           (emit-ir :store addr-reg dest width)
           ;; Re-tag value in dest if we untagged it (for return value)
           (when needs-untag
             (emit-ir :shl dest dest +fixnum-shift+))
           (free-temp-reg)))))

    ;; (setf var value) = (setq var value)
    ((symbolp place)
     (compile-setq place value-form env dest))

    (t
     (error "MVM compiler: unsupported SETF place ~S" place))))

;;; ============================================================
;;; I/O Port Operations
;;; ============================================================

(defun compile-io-out-byte (port-form value-form env dest)
  "Compile (io-out-byte port value) - write byte to I/O port.
   Port must be a compile-time constant (embedded as imm16 in bytecode)."
  (unless (integerp port-form)
    (error "MVM compiler: io-out-byte requires constant port, got ~S" port-form))
  (compile-form value-form env dest)
  ;; io-write: port(imm16), value(reg), width(u8)
  (emit-ir :io-write port-form dest +width-u8+)
  ;; Return 0
  (emit-ir :li dest 0))

(defun compile-io-in-byte (port-form env dest)
  "Compile (io-in-byte port) - read byte from I/O port.
   Port must be a compile-time constant (embedded as imm16 in bytecode)."
  (unless (integerp port-form)
    (error "MVM compiler: io-in-byte requires constant port, got ~S" port-form))
  ;; io-read: dest(reg), port(imm16), width(u8)
  (emit-ir :io-read dest port-form +width-u8+))

(defun compile-io-out-dword (port-form value-form env dest)
  "Compile (io-out-dword port value) - write dword to I/O port.
   Port must be a compile-time constant."
  (unless (integerp port-form)
    (error "MVM compiler: io-out-dword requires constant port, got ~S" port-form))
  (compile-form value-form env dest)
  (emit-ir :io-write port-form dest +width-u32+)
  (emit-ir :li dest 0))

(defun compile-io-in-dword (port-form env dest)
  "Compile (io-in-dword port) - read dword from I/O port.
   Port must be a compile-time constant."
  (unless (integerp port-form)
    (error "MVM compiler: io-in-dword requires constant port, got ~S" port-form))
  (emit-ir :io-read dest port-form +width-u32+))

;;; ============================================================
;;; System Register Operations
;;; ============================================================

(defun compile-get-alloc-ptr (dest)
  "Compile (get-alloc-ptr) - return VA tagged as fixnum"
  (emit-ir :mov dest +vreg-va+)
  (emit-ir :shl dest dest +fixnum-shift+))

(defun compile-get-alloc-limit (dest)
  "Compile (get-alloc-limit) - return VL tagged as fixnum"
  (emit-ir :mov dest +vreg-vl+)
  (emit-ir :shl dest dest +fixnum-shift+))

(defun compile-set-alloc-ptr (form env dest)
  "Compile (set-alloc-ptr value) - set VA from tagged fixnum"
  (compile-form form env dest)
  (emit-ir :sar dest dest +fixnum-shift+)
  (emit-ir :mov +vreg-va+ dest))

(defun compile-set-alloc-limit (form env dest)
  "Compile (set-alloc-limit value) - set VL from tagged fixnum"
  (compile-form form env dest)
  (emit-ir :sar dest dest +fixnum-shift+)
  (emit-ir :mov +vreg-vl+ dest))

(defun compile-untag (form env dest)
  "Compile (untag value) - remove fixnum tag"
  (compile-form form env dest)
  (emit-ir :sar dest dest +fixnum-shift+))

;;; ============================================================
;;; Actor/Context Primitives
;;; ============================================================

(defun compile-save-context (addr-form env dest)
  "Compile (save-context addr) - save registers to actor struct.
   Returns 0 on initial save, 1 when resumed via restore-context."
  (compile-form addr-form env dest)
  ;; The save-ctx MVM instruction handles the actual save.
  ;; It stores the continuation point internally.
  (emit-ir :save-ctx dest)
  ;; Result is in dest: 0 for initial save, tagged 1 for resume
  )

(defun compile-restore-context (addr-form env dest)
  "Compile (restore-context addr) - restore registers from actor struct.
   This never returns to the caller."
  (compile-form addr-form env dest)
  (emit-ir :restore-ctx dest)
  ;; restore-ctx never returns, but we need dest for type consistency
  )

(defun compile-call-native (args env dest)
  "Compile (call-native addr arg1 arg2) - call native code at address.
   Address is a tagged fixnum. Up to 2 arguments supported."
  (let ((addr-form (first args))
        (arg-forms (rest args)))
    ;; Compile address
    (compile-form addr-form env dest)
    ;; Untag address
    (emit-ir :sar dest dest +fixnum-shift+)
    ;; Place arguments in V0, V1
    (loop for arg-form in arg-forms
          for i from 0
          for areg = (+ +vreg-v0+ i)
          while (< i 2)
          do (let ((temp (alloc-temp-reg)))
               (compile-form arg-form env temp)
               (emit-ir :mov areg temp)
               (free-temp-reg)))
    ;; Indirect call
    (emit-ir :call-native dest (length arg-forms))
    ;; Result is in VR
    (unless (= dest +vreg-vr+)
      (emit-ir :mov dest +vreg-vr+))))

;;; ============================================================
;;; SMP Primitives
;;; ============================================================

(defun compile-xchg-mem (addr-form val-form env dest)
  "Compile (xchg-mem addr val) - atomic exchange.
   Both addr and val are tagged fixnums."
  (let ((addr-reg (alloc-temp-reg))
        (val-reg (alloc-temp-reg)))
    (compile-form addr-form env addr-reg)
    (compile-form val-form env val-reg)
    ;; Untag both
    (emit-ir :sar addr-reg addr-reg +fixnum-shift+)
    (emit-ir :sar val-reg val-reg +fixnum-shift+)
    ;; Atomic exchange: dest = old value at [addr], [addr] = val
    (emit-ir :atomic-xchg dest addr-reg val-reg)
    ;; Re-tag result
    (emit-ir :shl dest dest +fixnum-shift+)
    (free-temp-reg)
    (free-temp-reg)))

(defun compile-pause (dest)
  "Compile (pause) - spin-wait hint. Returns 0."
  (emit-ir :nop)  ; PAUSE maps to NOP in the VM (native backend converts to PAUSE)
  (emit-ir :li dest 0))

(defun compile-mfence (dest)
  "Compile (mfence) - full memory barrier. Returns 0."
  (emit-ir :fence)
  (emit-ir :li dest 0))

(defun compile-hlt (dest)
  "Compile (hlt) - halt CPU. Returns 0."
  (emit-ir :halt)
  (emit-ir :li dest 0))

(defun compile-write-char-serial (args env dest)
  "Compile (write-char-serial char-code) — write character to serial port.
   The argument is a fixnum containing the ASCII code.
   Uses TRAP #x0300 with the value in V0."
  (compile-form (car args) env +vreg-v0+)
  (emit-ir :trap #x0300)
  (emit-ir :li dest 0))

(defun compile-read-char-serial (dest)
  "Compile (read-char-serial) — read a character from the serial port.
   Uses TRAP #x0301; result is a tagged fixnum char code in V0."
  (emit-ir :trap #x0301)
  (emit-ir :mov dest +vreg-v0+))

(defun compile-sti (dest)
  "Compile (sti) - enable interrupts. Returns 0."
  (emit-ir :sti)
  (emit-ir :li dest 0))

(defun compile-cli (dest)
  "Compile (cli) - disable interrupts. Returns 0."
  (emit-ir :cli)
  (emit-ir :li dest 0))

(defun compile-sti-hlt (dest)
  "Compile (sti-hlt) - atomic STI+HLT. Returns 0."
  (emit-ir :sti)
  (emit-ir :halt)
  (emit-ir :li dest 0))

(defun compile-wrmsr (args env dest)
  "Compile (wrmsr ecx-val eax-val edx-val) - write to MSR.
   All args are tagged fixnums. Emits as a trap with args in V0-V2."
  (loop for arg in args
        for i from 0
        for areg = (+ +vreg-v0+ i)
        while (< i 3)
        do (compile-form arg env areg))
  ;; WRMSR is a privileged system operation, emit as trap
  (emit-ir :trap 1)  ; trap code 1 = WRMSR
  (emit-ir :li dest 0))

;;; ============================================================
;;; Per-CPU Data
;;; ============================================================

(defun compile-percpu-ref (offset-form env dest)
  "Compile (percpu-ref offset) - read per-CPU data.
   Offset must be a compile-time constant (embedded as imm16 in bytecode)."
  (unless (integerp offset-form)
    (error "MVM compiler: percpu-ref requires constant offset, got ~S" offset-form))
  ;; Read per-CPU slot with constant offset
  (emit-ir :percpu-ref dest offset-form))

(defun compile-percpu-set (offset-form val-form env dest)
  "Compile (percpu-set offset value) - write per-CPU data.
   Offset must be a compile-time constant."
  (unless (integerp offset-form)
    (error "MVM compiler: percpu-set requires constant offset, got ~S" offset-form))
  (compile-form val-form env dest)
  ;; Write per-CPU slot (value stays tagged)
  (emit-ir :percpu-set offset-form dest))

(defun compile-switch-idle-stack (dest)
  "Compile (switch-idle-stack) - switch to per-CPU idle stack. Returns 0."
  ;; This is implemented as a special percpu-ref that loads the stack pointer
  (emit-ir :trap 2)  ; trap code 2 = switch-idle-stack
  (emit-ir :li dest 0))

(defun compile-set-rsp (addr-form env dest)
  "Compile (set-rsp addr) - set stack pointer from tagged fixnum"
  (compile-form addr-form env dest)
  (emit-ir :sar dest dest +fixnum-shift+)
  ;; Move to stack pointer register
  (emit-ir :mov +vreg-vsp+ dest)
  (emit-ir :li dest 0))

(defun compile-lidt (addr-form env dest)
  "Compile (lidt addr) - load IDT register. Returns 0."
  (compile-form addr-form env dest)
  (emit-ir :sar dest dest +fixnum-shift+)
  (emit-ir :trap 3)  ; trap code 3 = LIDT
  (emit-ir :li dest 0))

;;; ============================================================
;;; Function Call
;;; ============================================================

(defun compile-call (fn args env dest)
  "Compile a function call (fn arg1 arg2 ...).
   Register args are saved to the stack during evaluation to avoid
   exhausting temp registers when args contain nested function calls."
  (let ((nargs (length args)))
    ;; Push overflow args FIRST (before populating V0-V3), because
    ;; evaluating overflow args may involve function calls that clobber V0-V3.
    ;; These end up deeper on the stack, which is correct: after CALL+frame-enter,
    ;; they'll be at [RBP+16+k*8] where the callee expects them.
    (when (> nargs +max-reg-args+)
      (dolist (arg (reverse (nthcdr +max-reg-args+ args)))
        (let ((temp (alloc-temp-reg)))
          (compile-form arg env temp)
          (emit-ir :push temp)
          (free-temp-reg))))

    (let ((reg-count (min nargs +max-reg-args+)))
      ;; Evaluate each register arg into a temp, push to stack, free temp.
      ;; This uses only 1 temp at a time, preventing temp exhaustion when
      ;; args are themselves function calls (which allocate their own temps).
      (dotimes (i reg-count)
        (let ((temp (alloc-temp-reg)))
          (compile-form (nth i args) env temp)
          (emit-ir :push temp)
          (free-temp-reg)))
      ;; Pop into arg registers (LIFO: last pushed = highest reg, pop first)
      (loop for i from (1- reg-count) downto 0
            do (emit-ir :pop (+ +vreg-v0+ i))))

    ;; Emit the call
    (cond
      ;; Direct call to named function
      ((symbolp fn)
       (let ((fn-name (normalize-name fn)))
         (emit-ir :call fn-name nargs)))
      ;; Other callable expression (rare in this system)
      (t
       (let ((fn-reg (alloc-temp-reg)))
         (compile-form fn env fn-reg)
         (emit-ir :call-indirect fn-reg nargs)
         (free-temp-reg))))

    ;; Result is in VR, move to dest
    (unless (= dest +vreg-vr+)
      (emit-ir :mov dest +vreg-vr+))

    ;; Clean up overflow stack args with POP (frame-free is NOP in translator)
    (when (> nargs +max-reg-args+)
      (let ((temp (alloc-temp-reg)))
        (dotimes (i (- nargs +max-reg-args+))
          (emit-ir :pop temp))
        (free-temp-reg)))))

;;; ============================================================
;;; Phase 2.5: Internal Function Compilation
;;; ============================================================
;;;
;;; Compiles a single function's body, producing IR instructions.

(defun mvm-compile-function-internal (name params body)
  "Compile a single function into IR. Returns function-info.
   Does NOT produce bytecode; that happens in phase 3."
  (let* ((*ir-buffer* nil)
         (*current-function-name* (if (symbolp name) (symbol-name name)
                                      (string name)))
         (*temp-reg-counter* 0)
         (return-label (make-compiler-label))
         (*function-return-label* return-label))
    ;; Function prologue: push frame pointer, set up frame
    (emit-ir :frame-enter (length params))

    ;; Build initial environment with parameter bindings.
    ;; Parameters arrive in V0-V3 (for the first 4), rest on stack.
    ;; Register params must be saved to stack since they get clobbered
    ;; during function body execution.
    (let* ((nreg-params (min (length params) +max-reg-args+))
           (env (make-compile-env :stack-depth nreg-params
                                  :bindings nil
                                  :parent nil)))
      ;; Save register params to stack and build environment
      (loop for param in params
            for i from 0
            while (< i +max-reg-args+)
            for areg = (+ +vreg-v0+ i)
            do ;; Store arg register to stack slot
               (emit-ir :stack-store areg i)
               ;; Add binding to environment
               (push (make-binding :name param
                                    :location :stack
                                    :stack-slot i)
                     (compile-env-bindings env)))

      ;; Handle excess arguments (already on caller's stack)
      (loop for param in (nthcdr +max-reg-args+ params)
            for i from +max-reg-args+
            do (push (make-binding :name param
                                    :location :stack
                                    :stack-slot i)
                     (compile-env-bindings env))
               (setf (compile-env-stack-depth env) (1+ i)))

      ;; Compile body, result goes to VR
      (compile-progn body env +vreg-vr+))

    ;; Function return label (for early return via (return value))
    (emit-ir-label return-label)

    ;; Function epilogue
    (emit-ir :frame-leave)
    (emit-ir :ret)

    ;; Build function-info
    (let ((ir (get-ir-instructions)))
      ;; Store the IR on the function-info for later bytecode emission
      (let ((info (make-function-info
                    :name (if (symbolp name) (symbol-name name) (string name))
                    :param-count (length params)
                    :bytecode-offset 0
                    :bytecode-length 0
                    :stack-frame-size 0)))
        ;; Stash IR in the constant table temporarily (will be consumed by phase 3)
        ;; Actually, we return a pair: (info . ir)
        (cons info ir)))))

;;; ============================================================
;;; Phase 3: Bytecode Emission (MVM IR -> Bytecode)
;;; ============================================================
;;;
;;; Two-pass approach:
;;;   Pass 1: Measure instruction sizes, compute label positions
;;;   Pass 2: Emit bytecode with resolved branch offsets

;;; ------ Instruction Size Calculation ------

(defun ir-instruction-size (insn)
  "Return the encoded bytecode size (in bytes) for a single IR instruction"
  (let ((op (car insn)))
    (case op
      ;; Labels take 0 bytes
      (:label 0)

      ;; No-operand instructions: 1 byte opcode
      (:nop   1)
      (:ret   1)
      (:halt  1)
      (:fence 1)
      (:cli   1)
      (:sti   1)
      (:gc-check 1)
      (:yield 1)

      ;; 1-reg instructions: 1 opcode + 1 reg = 2 bytes
      (:push  2)
      (:pop   2)
      (:inc   2)
      (:dec   2)
      (:write-barrier 2)

      ;; 2-reg instructions: 1 opcode + 2 regs = 3 bytes
      (:mov   3)
      (:car   3)
      (:cdr   3)
      (:setcar 3)
      (:setcdr 3)
      (:consp 3)
      (:atom  3)
      (:neg   3)
      (:cmp   3)
      (:test  3)
      (:obj-tag 3)
      (:obj-subtag 3)

      ;; 3-reg instructions: 1 opcode + 3 regs = 4 bytes
      (:add   4)
      (:sub   4)
      (:mul   4)
      (:div   4)
      (:mod   4)
      (:and   4)
      (:or    4)
      (:xor   4)
      (:cons  4)
      (:atomic-xchg 4)

      ;; reg + imm8 shift: 1 opcode + 2 regs + 1 imm8 = 4 bytes
      (:shl   4)
      (:shr   4)
      (:sar   4)

      ;; Variable shift: 2 regs + 1 reg (shift amount) = 4 bytes
      (:shl-var 4)
      (:sar-var 4)

      ;; Load immediate: 1 opcode + 1 reg + 8 imm64 = 10 bytes
      (:li    10)
      (:li-const 10)
      (:li-func 10)

      ;; Branch (unconditional): 1 opcode + 2 off16 = 3 bytes
      (:br    3)

      ;; Conditional branches: 1 opcode + 2 off16 = 3 bytes
      (:beq   3)
      (:bne   3)
      (:blt   3)
      (:bge   3)
      (:ble   3)
      (:bgt   3)

      ;; Branch-null: 1 opcode + 1 reg + 2 off16 = 4 bytes
      (:bnull  4)
      (:bnnull 4)

      ;; Call: 1 opcode + 4 imm32 = 5 bytes
      (:call  5)

      ;; Call indirect: 1 opcode + 1 reg = 2 bytes
      (:call-indirect 2)

      ;; Call native: 1 opcode + 1 reg = 2 bytes
      (:call-native 2)

      ;; Memory load/store: 1 opcode + 2 regs + 1 width = 4 bytes
      (:load  4)
      (:store 4)

      ;; I/O: 1 opcode + 1 reg + 2 port + 1 width = 5 bytes
      ;; For register-based port, use different encoding:
      (:io-read  5)
      (:io-write 5)

      ;; Per-CPU: 1 opcode + 1 reg + 2 imm16 = 4 bytes
      (:percpu-ref 4)
      (:percpu-set 4)

      ;; Frame: 1 opcode + 2 imm16 = 3 bytes
      (:frame-enter 3)
      (:frame-leave 1)
      (:frame-alloc 3)
      (:frame-free  3)

      ;; Stack load/store: 1 opcode + 1 reg + 2 imm16 = 4 bytes
      (:stack-load  4)
      (:stack-store 4)

      ;; Context save/restore: 1 opcode, no operands = 1 byte
      ;; (the register in the IR is not encoded in bytecode)
      (:save-ctx  1)
      (:restore-ctx 1)

      ;; Trap: 1 opcode + 2 imm16 = 3 bytes
      (:trap  3)

      ;; Default (unknown): assume 4 bytes
      (otherwise
       (warn "MVM compiler: unknown IR instruction ~A, assuming 4 bytes" op)
       4))))

;;; ------ Pass 1: Measure and Compute Label Positions ------

(defun compute-label-positions (ir-list)
  "Compute the byte offset for each label in the IR instruction list.
   Returns a hash table mapping label-id -> byte offset."
  (let ((labels (make-hash-table :test 'eql))
        (offset 0))
    (dolist (insn ir-list)
      (if (eq (car insn) :label)
          ;; Label: record position, takes 0 bytes
          (setf (gethash (second insn) labels) offset)
          ;; Instruction: advance offset
          (incf offset (ir-instruction-size insn))))
    labels))

;;; ------ Pass 2: Emit Bytecode ------

(defun emit-bytecode-for-ir (buf ir-list label-positions)
  "Emit MVM bytecode for a list of IR instructions.
   BUF is an mvm-buffer. LABEL-POSITIONS maps label-id -> byte offset."
  (let ((current-offset 0))
    (dolist (insn ir-list)
      (when (eq (car insn) :label)
        ;; Labels emit nothing
        (go next))

      (let ((op (car insn)))
        (case op
          ;; ---- No-operand instructions ----
          (:nop
           (mvm-nop buf))
          (:ret
           (mvm-ret buf))
          (:halt
           (mvm-halt buf))
          (:fence
           (mvm-fence buf))
          (:cli
           (mvm-cli buf))
          (:sti
           (mvm-sti buf))
          (:gc-check
           (mvm-gc-check buf))
          (:yield
           (mvm-yield buf))
          (:frame-leave
           ;; Frame teardown: the native backend handles restoring VSP/VFP.
           ;; In bytecode, emit as NOP (frame management is a higher-level concept).
           (mvm-nop buf))

          ;; ---- 1-reg instructions ----
          (:push
           (mvm-push buf (second insn)))
          (:pop
           (mvm-pop buf (second insn)))
          (:inc
           (mvm-inc buf (second insn)))
          (:dec
           (mvm-dec buf (second insn)))
          (:write-barrier
           (mvm-write-barrier buf (second insn)))

          ;; ---- 2-reg instructions ----
          (:mov
           (mvm-mov buf (second insn) (third insn)))
          (:car
           (mvm-car buf (second insn) (third insn)))
          (:cdr
           (mvm-cdr buf (second insn) (third insn)))
          (:setcar
           (mvm-setcar buf (second insn) (third insn)))
          (:setcdr
           (mvm-setcdr buf (second insn) (third insn)))
          (:consp
           (mvm-consp buf (second insn) (third insn)))
          (:atom
           (mvm-atom buf (second insn) (third insn)))
          (:neg
           (mvm-neg buf (second insn) (third insn)))
          (:cmp
           (mvm-cmp buf (second insn) (third insn)))
          (:test
           (mvm-test buf (second insn) (third insn)))
          (:obj-tag
           (mvm-obj-tag buf (second insn) (third insn)))
          (:obj-subtag
           (mvm-obj-subtag buf (second insn) (third insn)))

          ;; ---- 3-reg instructions ----
          (:add
           (mvm-add buf (second insn) (third insn) (fourth insn)))
          (:sub
           (mvm-sub buf (second insn) (third insn) (fourth insn)))
          (:mul
           (mvm-mul buf (second insn) (third insn) (fourth insn)))
          (:div
           (mvm-div buf (second insn) (third insn) (fourth insn)))
          (:mod
           (mvm-mod buf (second insn) (third insn) (fourth insn)))
          (:and
           (mvm-and buf (second insn) (third insn) (fourth insn)))
          (:or
           (mvm-or buf (second insn) (third insn) (fourth insn)))
          (:xor
           (mvm-xor buf (second insn) (third insn) (fourth insn)))
          (:cons
           (mvm-cons buf (second insn) (third insn) (fourth insn)))
          (:atomic-xchg
           (mvm-atomic-xchg buf (second insn) (third insn) (fourth insn)))

          ;; ---- Shift instructions (reg + reg + imm8) ----
          (:shl
           (mvm-shl buf (second insn) (third insn) (fourth insn)))
          (:shr
           (mvm-shr buf (second insn) (third insn) (fourth insn)))
          (:sar
           (mvm-sar buf (second insn) (third insn) (fourth insn)))

          ;; ---- Variable shift (reg + reg + reg) ----
          (:shl-var
           (mvm-shlv buf (second insn) (third insn) (fourth insn)))
          (:sar-var
           (mvm-sarv buf (second insn) (third insn) (fourth insn)))

          ;; ---- Load Immediate ----
          (:li
           (mvm-li buf (second insn) (third insn)))
          (:li-const
           ;; Load constant by index (placeholder, resolved during linking)
           (mvm-li buf (second insn) (third insn)))
          (:li-func
           ;; Load function address (placeholder, resolved during linking)
           ;; Encode function name index as the immediate
           (let* ((fn-name (third insn))
                  (fn-info (gethash fn-name *functions*)))
             (mvm-li buf (second insn)
                     (if fn-info
                         (function-info-bytecode-offset fn-info)
                         0))))

          ;; ---- Branches ----
          (:br
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-br buf rel-offset)))

          (:beq
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-beq buf rel-offset)))
          (:bne
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-bne buf rel-offset)))
          (:blt
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-blt buf rel-offset)))
          (:bge
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-bge buf rel-offset)))
          (:ble
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-ble buf rel-offset)))
          (:bgt
           (let* ((target-label (second insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 3))
                  (rel-offset (- target-pos insn-end)))
             (mvm-bgt buf rel-offset)))

          ;; ---- Branch-null (reg + offset) ----
          (:bnull
           (let* ((reg (second insn))
                  (target-label (third insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 4))
                  (rel-offset (- target-pos insn-end)))
             (mvm-bnull buf reg rel-offset)))
          (:bnnull
           (let* ((reg (second insn))
                  (target-label (third insn))
                  (target-pos (gethash target-label label-positions))
                  (insn-end (+ current-offset 4))
                  (rel-offset (- target-pos insn-end)))
             (mvm-bnnull buf reg rel-offset)))

          ;; ---- Call ----
          (:call
           (let* ((fn-name (second insn))
                  (fn-info (gethash fn-name *functions*))
                  (target (if fn-info
                              (function-info-bytecode-offset fn-info)
                              0)))
             (mvm-call buf target)))

          (:call-indirect
           (mvm-call-ind buf (second insn)))

          (:call-native
           ;; Emit as call-indirect
           (mvm-call-ind buf (second insn)))

          ;; ---- Memory ----
          (:load
           (mvm-load buf (second insn) (third insn) (fourth insn)))
          (:store
           (mvm-store buf (second insn) (third insn) (fourth insn)))

          ;; ---- I/O ----
          (:io-read
           ;; (io-read dest port-imm16 width)
           (mvm-io-read buf (second insn) (third insn) (fourth insn)))
          (:io-write
           ;; (io-write port-imm16 value-reg width)
           (mvm-io-write buf (second insn) (third insn) (fourth insn)))

          ;; ---- Per-CPU ----
          (:percpu-ref
           ;; (percpu-ref dest offset-imm16)
           (mvm-percpu-ref buf (second insn) (third insn)))
          (:percpu-set
           ;; (percpu-set offset-imm16 value-reg)
           (mvm-percpu-set buf (second insn) (third insn)))

          ;; ---- Frame management ----
          (:frame-enter
           ;; Emit as: push VFP; mov VFP, VSP; sub VSP, N*8
           ;; Encoded as trap with frame size
           (mvm-trap buf (second insn)))
          (:frame-alloc
           ;; sub VSP, N*8
           (mvm-trap buf (+ #x100 (second insn))))
          (:frame-free
           ;; add VSP, N*8
           (mvm-trap buf (+ #x200 (second insn))))

          ;; ---- Stack load/store ----
          (:stack-load
           ;; load dest from stack slot
           ;; Encoded as: load dest, VFP, slot-offset
           ;; Use obj-ref as a proxy: dest = [VFP + slot*8]
           (let ((dest-reg (second insn))
                 (slot (third insn)))
             (mvm-obj-ref buf dest-reg +vreg-vfp+ slot)))
          (:stack-store
           ;; store src to stack slot
           (let ((src-reg (second insn))
                 (slot (third insn)))
             (mvm-obj-set buf +vreg-vfp+ slot src-reg)))

          ;; ---- Context ----
          (:save-ctx
           (mvm-save-ctx buf))
          (:restore-ctx
           (mvm-restore-ctx buf))

          ;; ---- Trap ----
          (:trap
           (mvm-trap buf (second insn)))

          ;; ---- Unknown ----
          (otherwise
           (warn "MVM bytecode: unknown IR op ~A, emitting NOP" op)
           (mvm-nop buf))))

      ;; Advance offset
      (incf current-offset (ir-instruction-size insn))

      next)))

;;; ============================================================
;;; Top-Level API
;;; ============================================================

(defun mvm-compile-function (name params body)
  "Compile a named function to MVM bytecode.
   Returns function-info with bytecode embedded in the module buffer."
  (let ((result (mvm-compile-function-internal name params body)))
    ;; result is (function-info . ir-list)
    (let ((info (car result))
          (ir (cdr result)))
      ;; Register in function table
      (setf (gethash (function-info-name info) *functions*) info)
      (push info *function-table*)
      ;; Return the info and IR for later bytecode emission
      (values info ir))))

(defun mvm-compile-toplevel (form)
  "Compile a top-level form.
   Handles defun, defvar, defconstant, defmacro, and bare expressions."
  (cond
    ;; (defun name (params) body...)
    ((and (consp form) (name-eq (car form) "DEFUN"))
     (destructuring-bind (name params &body body) (cdr form)
       (mvm-compile-function name params body)))

    ;; (defvar name &optional value)
    ((and (consp form) (name-eq (car form) "DEFVAR"))
     (let ((name (cadr form))
           (value (caddr form)))
       ;; Compile as a thunk that initializes the variable
       (when value
         (mvm-compile-function
          (format nil "INIT-~A" (normalize-name name))
          nil
          (list value)))))

    ;; (defconstant name value)
    ((and (consp form) (name-eq (car form) "DEFCONSTANT"))
     ;; Constants are folded at compile time, no runtime code needed
     nil)

    ;; (defmacro name (params) body...)
    ((and (consp form) (name-eq (car form) "DEFMACRO"))
     (let ((name (cadr form))
           (params (caddr form))
           (body (cdddr form)))
       ;; Register macro expander
       ;; The expander is a host-side function (runs at compile time)
       (let ((expander (eval `(lambda (form)
                                 (destructuring-bind (,@params) (cdr form)
                                   ,@body)))))
         (mvm-define-macro (normalize-name name) expander))
       nil))

    ;; Other top-level forms: wrap in anonymous function
    (t
     (let ((thunk-name (format nil "TOPLEVEL-~D" (make-compiler-label))))
       (mvm-compile-function thunk-name nil (list form))))))

(defun mvm-compile-all (forms)
  "Compile a list of top-level forms into a complete MVM module.
   Returns a compiled-module containing bytecode, function table,
   and constant table."
  (let ((*functions* (make-hash-table :test 'equal))
        (*function-table* nil)
        (*constant-table* nil)
        (*label-counter* 0)
        (*macro-table* (make-hash-table :test 'equal))
        (*loop-exit-label* nil)
        (*block-labels* nil)
        (*tagbody-tags* nil)
        (all-ir nil))

    ;; Register standard macros (cond, and, or) for this compilation
    (register-mvm-bootstrap-macros)

    ;; Phase 1 & 2: Compile all forms to IR
    (dolist (form forms)
      (multiple-value-bind (info ir) (mvm-compile-toplevel form)
        (when (and info ir)
          (push (cons info ir) all-ir))))

    ;; Reverse to get compilation order
    (setf all-ir (nreverse all-ir))

    ;; Phase 3: Emit bytecode
    (let ((buf (make-mvm-buffer)))
      ;; First pass: compute label positions for each function and assign
      ;; bytecode offsets
      (let ((global-offset 0))
        (dolist (entry all-ir)
          (let* ((info (car entry))
                 (ir (cdr entry))
                 (label-positions (compute-label-positions ir))
                 ;; Compute total size of this function's bytecode
                 (fn-size (loop for insn in ir
                                sum (ir-instruction-size insn))))
            ;; Record bytecode offset and length
            (setf (function-info-bytecode-offset info) global-offset)
            (setf (function-info-bytecode-length info) fn-size)
            ;; Update function in hash table so calls can resolve
            (setf (gethash (function-info-name info) *functions*) info)
            (incf global-offset fn-size))))

      ;; Second pass: emit bytecode with resolved offsets
      ;; Note: label-positions are LOCAL to each function (starting at 0).
      ;; This matches current-offset in emit-bytecode-for-ir which also
      ;; starts at 0, so branch offsets are computed correctly.
      ;; CALL targets use global offsets from *functions*, not label-positions.
      (dolist (entry all-ir)
        (let* ((ir (cdr entry))
               (label-positions (compute-label-positions ir)))
          (emit-bytecode-for-ir buf ir label-positions)))

      ;; Build module
      (make-compiled-module
       :bytecode (mvm-buffer-bytes buf)
       :function-table (nreverse *function-table*)
       :constant-table (nreverse *constant-table*)))))

;;; ============================================================
;;; Disassembly / Debug Support
;;; ============================================================

(defun disassemble-module (module)
  "Print a human-readable disassembly of a compiled MVM module"
  (format t "~&=== MVM Module ===~%")
  (format t "Bytecode size: ~D bytes~%" (length (compiled-module-bytecode module)))
  (format t "Functions: ~D~%" (length (compiled-module-function-table module)))
  (format t "Constants: ~D~%~%" (length (compiled-module-constant-table module)))

  ;; Print function table
  (dolist (fn (compiled-module-function-table module))
    (format t "Function ~A (~D params) @ offset ~D (~D bytes):~%"
            (function-info-name fn)
            (function-info-param-count fn)
            (function-info-bytecode-offset fn)
            (function-info-bytecode-length fn))
    ;; Disassemble this function's bytecode
    (disassemble-mvm (compiled-module-bytecode module)
                     :start (function-info-bytecode-offset fn)
                     :end (+ (function-info-bytecode-offset fn)
                             (function-info-bytecode-length fn)))
    (format t "~%"))

  ;; Print constant table
  (when (compiled-module-constant-table module)
    (format t "Constants:~%")
    (loop for const in (compiled-module-constant-table module)
          for i from 0
          do (format t "  [~D] ~S~%" i const))))

(defun dump-ir (ir-list &optional (stream *standard-output*))
  "Print IR instructions in a human-readable format for debugging"
  (dolist (insn ir-list)
    (if (eq (car insn) :label)
        (format stream "L~D:~%" (second insn))
        (format stream "  ~{~A~^ ~}~%" insn))))

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-mvm-compiler ()
  "Basic test of the MVM compiler"
  ;; Test 1: Simple function
  (format t "~%=== Test 1: (defun add1 (x) (1+ x)) ===~%")
  (let ((module (mvm-compile-all
                 '((defun add1 (x) (1+ x))))))
    (disassemble-module module))

  ;; Test 2: Fibonacci
  (format t "~%=== Test 2: fibonacci ===~%")
  (let ((module (mvm-compile-all
                 '((defun fib (n)
                     (if (< n 2)
                         n
                         (+ (fib (1- n))
                            (fib (- n 2)))))))))
    (disassemble-module module))

  ;; Test 3: List manipulation
  (format t "~%=== Test 3: list operations ===~%")
  (let ((module (mvm-compile-all
                 '((defun list-length (lst)
                     (let ((count 0))
                       (loop
                         (if (null lst)
                             (return count)
                             (progn
                               (setq count (1+ count))
                               (setq lst (cdr lst)))))))))))
    (disassemble-module module))

  ;; Test 4: Multiple functions
  (format t "~%=== Test 4: multiple functions ===~%")
  (let ((module (mvm-compile-all
                 '((defun double (x) (* x 2))
                   (defun quadruple (x) (double (double x)))))))
    (disassemble-module module))

  (format t "~%All MVM compiler tests passed.~%")
  t)
