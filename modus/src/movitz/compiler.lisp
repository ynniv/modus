;;;;------------------------------------------------------------------
;;;; 
;;;;    Copyright (C) 2001,2000, 2002-2005,
;;;;    Department of Computer Science, University of Tromso, Norway
;;;; 
;;;; Description:   A simple lisp compiler.
;;;; Author:        Frode Vatvedt Fjeld <frodef@acm.org>
;;;; Created at:    Wed Oct 25 12:30:49 2000
;;;; Distribution:  See the accompanying file COPYING.
;;;;                
;;;; $Id: compiler.lisp,v 1.205 2008-04-27 19:07:33 ffjeld Exp $
;;;;                
;;;;------------------------------------------------------------------

(in-package movitz)

(defvar *warn-function-change-p* t
  "Emit a warning whenever a named function's code-vector changes size.")

(defvar *compiler-verbose-p* nil)

(defvar *compiler-do-optimize* t
  "Apply the peephole optimizer to function code.")

(defvar *explain-peephole-optimizations* nil
  "Emit some cryptic information about which peephole optimization
heuristics that fire. Used for debugging the optimizer.")

(defvar *compiler-use-cmov-p* nil
  "Allow the compiler to emit CMOV instructions, making the code
incompatible with pre-pentium CPUs.")
  
(defvar *compiler-auto-stack-checks-p* t
  "Make every compiled function check upon entry that the
stack-pointer is within bounds. Costs 3 code-bytes and a few cycles.")

(defvar *compiler-allow-transients* t
  "Allow the compiler to keep function arguments solely in registers.
Hurst debugging, improves performance.")

(defvar *compiler-local-segment-prefix* '(:fs-override)
  "Use these assembly-instruction prefixes when accessing the thread-local
run-time context.")

(defvar *compiler-global-segment-prefix* nil
  "Use these assembly-instruction prefixes when accessing the global
run-time context.")

(defparameter *compiler-physical-segment-prefix* '(:gs-override)
  "Use this instruction prefix when accessing a physical memory location (i.e. typically some memory-mapped hardware device).")

(defparameter *compiler-nonlocal-lispval-read-segment-prefix* '()
  "Use this segment prefix when reading a lispval at (potentially)
non-local locations.")

(defparameter *compiler-nonlocal-lispval-write-segment-prefix* '(:es-override)
  "Use this segment prefix when writing a lispval at (potentially)
non-local locations.")

(defparameter *compiler-use-cons-reader-segment-protocol-p* nil)

(defparameter *compiler-cons-read-segment-prefix* '(:gs-override)
  "Use this segment prefix for CAR and CDR, when using cons-reader protocol.")

(defvar *compiler-allow-untagged-word-bits* 0
  "Allow (temporary) untagged values of this bit-size to exist, because
the system ensures one way or another that there can be no pointers below
this size.")

(defvar *compiler-use-into-unbound-protocol* t
  "Use #x7fffffff as the <unbound-value> and thereby the INTO
instruction for checking whether a value is the unbound value.")

(defvar *compiler-compile-eval-whens* t
  "When encountering (eval-when (:compile-toplevel) <code>),
compile, using the host compiler, the code rather than just using eval.")

(defvar *compiler-compile-macro-expanders* t
  "For macros of any kind, compile the macro-expanders using the host compiler.")

(defvar *compiler-do-type-inference* t
  "Spend time and effort performing type inference and optimization.")

(defvar *compiler-produce-defensive-code* t
  "Try to make code be extra cautious.")

(defvar *compiler-relink-recursive-funcall* t
  "If true, also recursive function calls look up the function through the function name,
which enables tracing of recursive functions.")

(defvar *compiler-trust-user-type-declarations-p* t)

(defvar *compiling-function-name* nil)
(defvar muerte.cl:*compile-file-pathname* nil)

(defvar *extended-code-expanders*
    (make-hash-table :test #'eq))

(defvar *extended-code-find-write-binding-and-type*
    (make-hash-table :test #'eq))


(defparameter +enter-stack-frame-code+
    '((:pushl :ebp)
      (:movl :esp :ebp)
      (:pushl :esi)))

(defun duplicatesp (list)
  "Returns TRUE iff at least one object occurs more than once in LIST."
  (if (null list)
      nil
    (or (member (car list) (cdr list))
	(duplicatesp (cdr list)))))

(defun compute-call-extra-prefix (pc size)
  (let* ((return-pointer-tag (ldb (byte 3 0)
				  (+ pc size))))
    (cond
      ((or (= (tag :even-fixnum) return-pointer-tag)
	   (= (tag :odd-fixnum) return-pointer-tag))
       ;; Insert a NOP
       '(#x90))
;;;     ((= 3 return-pointer-tag)
;;;      ;; Insert two NOPs, 3 -> 5
;;;      '(#x90 #x90))
      ((= (tag :character) return-pointer-tag)
       ;; Insert three NOPs, 2 -> 5
       '(#x90 #x90 #x90)
       '(#x90)))))

(defun make-compiled-primitive (form environment top-level-p docstring)
  "Primitive functions have no funobj, no stack-frame, and no implied
   parameter/return value passing conventions."
  (declare (ignore top-level-p docstring))
  (let* ((env (make-local-movitz-environment environment nil))
	 (body-code (compiler-call #'compile-form
		      :form form
		      :funobj nil
		      :env env
		      :top-level-p nil
		      :result-mode :ignore))
	 ;; (ignmore (format t "~{~S~%~}" body-code))
	 (resolved-code (finalize-code body-code nil nil)))

    (multiple-value-bind (code-vector symtab)
	(let ((asm-x86:*cpu-mode* :32-bit)
	      (asm:*instruction-compute-extra-prefix-map*
	       '((:call . compute-call-extra-prefix))))
	  (asm:assemble-proglist (translate-program resolved-code :muerte.cl :cl)
				 :symtab (list (cons :nil-value (image-nil-word *image*)))))
      (values (make-movitz-vector (length code-vector)
				  :element-type 'code
				  :initial-contents code-vector)
	      symtab))))

(defun register-function-code-size (funobj)
  (let* ((name (movitz-print (movitz-funobj-name funobj)))
	 (hash-name name)
	 (new-size (length (movitz-vector-symbolic-data (movitz-funobj-code-vector funobj)))))
    (assert name)
    (let ((old-size (gethash hash-name (function-code-sizes *image*))))
      (cond
       ((not old-size))
       ((not *warn-function-change-p*))
       ((> new-size old-size)
	(warn "~S grew from ~D to ~D bytes." name old-size new-size))
       ((< new-size old-size)
	(warn "~S shrunk from ~D to ~D bytes" name old-size new-size))))
    (setf (gethash hash-name (function-code-sizes *image*)) new-size))
  funobj)

(defclass movitz-funobj-pass1 ()
  ((name
    :initarg :name
    :accessor movitz-funobj-name)
   (lambda-list
    :initarg :lambda-list
    :accessor movitz-funobj-lambda-list)
   (function-envs
    :accessor function-envs)
   (funobj-env
    :initarg :funobj-env
    :accessor funobj-env)
   (extent
    :initarg :extent
    :initform :unused
    :accessor movitz-funobj-extent)
   (allocation
    :initform nil
    :accessor movitz-allocation)
   (entry-protocol
    :initform :default
    :initarg :entry-protocol
    :reader funobj-entry-protocol))
  (:documentation "This class is used for funobjs during the first compiler pass.
Before the second pass, such objects will be change-class-ed to proper movitz-funobjs.
This way, we ensure that no undue side-effects on the funobj occur during pass 1."))

(defmethod print-object ((object movitz-funobj-pass1) stream)
  (print-unreadable-object (object stream :type t :identity t)
    (when (slot-boundp object 'name)
      (write (movitz-funobj-name object) :stream stream)))
  object)

(defun movitz-macro-expander-make-function (lambda-form &key name (type :unknown))
  "Make a lambda-form that is a macro-expander into a proper function.
Gensym a name whose symbol-function is set to the macro-expander, and return that symbol."
  (let ((function-name (gensym (format nil "~A-expander-~@[~A-~]" type name))))
    (if *compiler-compile-macro-expanders*
	(with-host-environment ()
	  (compile function-name lambda-form))
      (setf (symbol-function function-name)
	(coerce lambda-form 'function)))
    function-name))

(defun make-compiled-funobj (name lambda-list declarations form env top-level-p &key funobj)
  "Compiler entry-point for making a (lexically) top-level function."
  (handler-bind (((or warning error)
		  (lambda (c)
		    (declare (ignore c))
		    (if (not (boundp 'muerte.cl:*compile-file-pathname*))
			(format *error-output*
				"~&;; While Movitz compiling ~S:" name)
		      (format *error-output*
			      "~&;; While Movitz compiling ~S in ~A:"
			      name muerte.cl:*compile-file-pathname*)))))
    (with-retries-until-true (retry-funobj "Retry compilation of ~S." name)
      (make-compiled-funobj-pass2
       (make-compiled-funobj-pass1 name lambda-list declarations
				   form env top-level-p :funobj funobj)))))

(defun make-compiled-funobj-pass1 (name lambda-list declarations form env top-level-p
				   &key funobj)
  "Per funobj (i.e. not necessarily top-level) entry-point for first-pass compilation.
If funobj is provided, its identity will be kept, but its type (and values) might change."
  ;; The ability to provide funobj's identity is important when a
  ;; function must be referenced before it can be compiled, e.g. for
  ;; mutually recursive (lexically bound) functions.
  (multiple-value-bind (required-vars optional-vars rest-var key-vars aux-vars allow-p min max edx-var)
      (decode-normal-lambda-list lambda-list)
    (declare (ignore aux-vars allow-p min max))
    ;; There are several main branches through the function
    ;; compiler, and this is where we decide which one to take.
    (funcall (cond
	       ((let ((sub-form (cddr form)))
		  (and (consp (car sub-form))
		       (eq 'muerte::numargs-case (caar sub-form))))
		'make-compiled-function-pass1-numarg-case)
	       ((and (= 1 (length required-vars)) ; (x &optional y)
		     (= 1 (length optional-vars))
		     (movitz-constantp (nth-value 1 (decode-optional-formal (first optional-vars)))
				       env)
		     (null key-vars)
		     (not rest-var)
		     (not edx-var))
		'make-compiled-function-pass1-1req1opt)
	       (t 'make-compiled-function-pass1))
	     name
	     lambda-list
	     declarations
	     form
	     env
	     top-level-p
	     funobj)))

(defun ensure-pass1-funobj (funobj class &rest init-args)
  "If funobj is nil, return a fresh funobj of class.
Otherwise coerce funobj to class."
  (apply #'reinitialize-instance
	 (if funobj
	     (change-class funobj class)
	   (make-instance class))
	 init-args))

(defun make-compiled-function-pass1-numarg-case (name lambda-list declarations form env top-level-p funobj)
  (let* ((funobj (ensure-pass1-funobj funobj 'movitz-funobj-pass1
				      :entry-protocol :numargs-case
				      :name name
				      :lambda-list (movitz-read (lambda-list-simplify lambda-list))))
	 (funobj-env (make-local-movitz-environment env funobj :type 'funobj-env)))
    (setf (funobj-env funobj) funobj-env
	  (function-envs funobj) nil)
    (loop for (numargs lambda-list . clause-body) in (cdr (caddr form))
	do (when (duplicatesp lambda-list)
	     (error "There are duplicates in lambda-list ~S." lambda-list))
	   (multiple-value-bind (clause-body clause-declarations)
	       (parse-declarations-and-body clause-body)
	     (let* ((function-env
		     (add-bindings-from-lambda-list lambda-list
						    (make-local-movitz-environment
						     funobj-env funobj
						     :type 'function-env
						     :declaration-context :funobj
						     :declarations 
						     (append clause-declarations
							     declarations))))
		    (function-form (list* 'muerte.cl::block
					  (compute-function-block-name name)
					  clause-body)))
	       (multiple-value-bind (arg-init-code need-normalized-ecx-p)
		   (make-function-arguments-init funobj function-env)
		 (setf (extended-code function-env)
		   (append arg-init-code
			   (compiler-call #'compile-form
                             :form (make-special-funarg-shadowing function-env function-form)
			     :funobj funobj
			     :env function-env
			     :top-level-p top-level-p
			     :result-mode :function)))
		 (setf (need-normalized-ecx-p function-env) need-normalized-ecx-p))
	       (push (cons numargs function-env)
		     (function-envs funobj)))))
    funobj))

(defun make-compiled-function-pass1-1req1opt (name lambda-list declarations form env top-level-p funobj)
  "Returns funobj."
  (when (duplicatesp lambda-list)
    (error "There are duplicates in lambda-list ~S." lambda-list))
  (let* ((funobj (ensure-pass1-funobj funobj 'movitz-funobj-pass1
				      :entry-protocol :1req1opt
				      :name name
				      :lambda-list (movitz-read (lambda-list-simplify lambda-list))))
	 (funobj-env (make-local-movitz-environment env funobj :type 'funobj-env))
	 (function-env (add-bindings-from-lambda-list
			lambda-list
			(make-local-movitz-environment funobj-env funobj
						       :type 'function-env
						       :need-normalized-ecx-p nil
						       :declaration-context :funobj
						       :declarations declarations)))
	 (optional-env (make-local-movitz-environment function-env funobj
						      :type 'function-env)))
    (setf (funobj-env funobj) funobj-env)
    ;; (print-code 'arg-init-code arg-init-code)
    (setf (extended-code optional-env)
      (compiler-call #'compile-form
	:form (optional-function-argument-init-form
	       (movitz-binding (first (optional-vars function-env)) function-env nil))
	:funobj funobj
	:env optional-env
	:result-mode :ebx))
    (setf (extended-code function-env)
      (append #+ignore arg-init-code
	      (compiler-call #'compile-form
		:form (make-special-funarg-shadowing function-env form)
		:funobj funobj
		:env function-env
		:top-level-p top-level-p
		:result-mode :function)))
    (setf (function-envs funobj)
      (list (cons 'muerte.cl::t function-env)
	    (cons :optional optional-env)))
    funobj))

(defun make-compiled-function-pass1 (name lambda-list declarations form env top-level-p funobj)
  "Returns funobj."
  (when (duplicatesp lambda-list)
    (error "There are duplicates in lambda-list ~S." lambda-list))
  (let* ((funobj (ensure-pass1-funobj funobj 'movitz-funobj-pass1
				      :name name
				      :lambda-list (movitz-read (lambda-list-simplify lambda-list))))
	 (funobj-env (make-local-movitz-environment env funobj :type 'funobj-env))
	 (function-env (add-bindings-from-lambda-list
			lambda-list
			(make-local-movitz-environment funobj-env funobj
						       :type 'function-env
						       :declaration-context :funobj
						       :declarations declarations))))
    (setf (funobj-env funobj) funobj-env
	  (function-envs funobj) (list (cons 'muerte.cl::t function-env)))
    (multiple-value-bind (arg-init-code need-normalized-ecx-p)
	(make-function-arguments-init funobj function-env)
      (setf (need-normalized-ecx-p function-env) need-normalized-ecx-p)
      (setf (extended-code function-env)
	(append arg-init-code
		(compiler-call #'compile-form
		  :form (make-special-funarg-shadowing function-env form)
		  :funobj funobj
		  :env function-env
		  :top-level-p top-level-p
		  :result-mode :function))))
    funobj))


(defun make-compiled-funobj-pass2 (toplevel-funobj-pass1)
  "This is the entry-poing for second pass compilation for each top-level funobj."
  (check-type toplevel-funobj-pass1 movitz-funobj-pass1)
  (let ((toplevel-funobj (change-class toplevel-funobj-pass1 'movitz-funobj)))
    (multiple-value-bind (toplevel-funobj function-binding-usage)
	(resolve-borrowed-bindings toplevel-funobj)
      (complete-funobj
       (layout-stack-frames
	(analyze-bindings
	 (resolve-sub-functions toplevel-funobj function-binding-usage)))))))

(defstruct (type-analysis (:type list))
  (thunks)
  (binding-types)
  (encoded-type
   (multiple-value-list (type-specifier-encode nil)))
  (declared-encoded-type
   (multiple-value-list (type-specifier-encode t))))

(defun make-type-analysis-with-declaration (binding)
  (let ((declared-type
	 (if (not (and *compiler-trust-user-type-declarations-p*
		       (movitz-env-get (binding-name binding) :variable-type
				       nil (binding-env binding) nil)))
	     (multiple-value-list (type-specifier-encode t))
	   (multiple-value-list
	    (type-specifier-encode (movitz-env-get (binding-name binding) :variable-type
						   t (binding-env binding) nil))))))
    ;; (warn "~S decl: ~A" binding (apply #'encoded-type-decode declared-type))
    (make-type-analysis :declared-encoded-type declared-type)))

(defun analyze-bindings (toplevel-funobj)
  "Figure out usage of bindings in a toplevel funobj.
Side-effects each binding's binding-store-type."
  (if (not *compiler-do-type-inference*)
      (labels
	  ((analyze-code (code)
	     (dolist (instruction code)
	       (when (listp instruction)
		 (let ((binding
			(find-written-binding-and-type instruction)))
		   (when binding
		     (setf (binding-store-type binding)
		       (multiple-value-list (type-specifier-encode t)))))
		 (analyze-code (instruction-sub-program instruction)))))
	   (analyze-funobj (funobj)
	     (loop for (nil . function-env) in (function-envs funobj)
		 do (analyze-code (extended-code function-env)))
	     (loop for function-binding in (sub-function-binding-usage funobj) by #'cddr
		 do (analyze-funobj (function-binding-funobj function-binding)))
	     funobj))
	(analyze-funobj toplevel-funobj))
    (let ((binding-usage (make-hash-table :test 'eq)))
      (labels ((binding-resolved-p (binding)
		 (or (typep binding 'constant-object-binding)
		     (typep binding 'function-argument)
		     (let ((analysis (gethash binding binding-usage)))
		       (and analysis
			    (null (type-analysis-thunks analysis))))))
	       (binding-resolve (binding)
		 (cond
		  ((not (bindingp binding))
		   binding)
		  ((typep binding 'constant-object-binding)
		   (apply #'encoded-type-decode
			  (binding-store-type binding)))
		  ((typep binding 'function-argument)
		   t)
		  ((let ((analysis (gethash binding binding-usage)))
		     (assert (and (and analysis
				       (null (type-analysis-thunks analysis))))
			 (binding)
		       "Can't resolve unresolved binding ~S." binding)))
		  (*compiler-trust-user-type-declarations-p*
		   (let ((analysis (gethash binding binding-usage)))
		     (multiple-value-call #'encoded-type-decode
		       (apply #'encoded-types-and
			      (append (type-analysis-declared-encoded-type analysis)
				      (type-analysis-encoded-type analysis))))))
		  (t (let ((analysis (gethash binding binding-usage)))
		       (apply #'encoded-type-decode
			      (type-analysis-encoded-type analysis))))))
	       (type-is-t (type-specifier)
		 (or (eq type-specifier t)
		     (and (listp type-specifier)
			  (eq 'or (car type-specifier))
			  (some #'type-is-t (cdr type-specifier)))))
	       (analyze-store (binding type thunk thunk-args)
		 (assert (not (null type)) ()
		   "store-lexical with empty type.")
		 (assert (or (typep type 'binding)
			     (eql 1 (type-specifier-num-values type))) ()
		   "store-lexical with multiple-valued type: ~S for ~S" type binding)
		 #+ignore (warn "store ~S type ~S, thunk ~S" binding type thunk)
		 (let ((analysis (or (gethash binding binding-usage)
				     (setf (gethash binding binding-usage)
				       (make-type-analysis-with-declaration binding)))))
		   (cond
		    (thunk
		     (assert (some #'bindingp thunk-args))
		     (push (cons thunk thunk-args) (type-analysis-thunks analysis)))
		    ((and (bindingp type)
			  (binding-eql type binding))
		     (break "got binding type")
		     nil)
		    (t (setf (type-analysis-encoded-type analysis)
			 (multiple-value-list
			  (multiple-value-call
			      #'encoded-types-or 
			    (values-list (type-analysis-encoded-type analysis))
			    (type-specifier-encode type))))))))
	       (analyze-code (code)
		 #+ignore (print-code 'analyze code)
		 (dolist (instruction code)
		   (when (listp instruction)
		     (multiple-value-bind (store-binding store-type thunk thunk-args)
			 (find-written-binding-and-type instruction)
		       (when store-binding
			 #+ignore (warn "store: ~S binding ~S type ~S thunk ~S"
					instruction store-binding store-type thunk)
			 (analyze-store store-binding store-type thunk thunk-args)))
		     (analyze-code (instruction-sub-program instruction)))))
	       (analyze-funobj (funobj)
		 (loop for (nil . function-env) in (function-envs funobj)
		     do (analyze-code (extended-code function-env)))
		 (loop for function-binding in (sub-function-binding-usage funobj) by #'cddr
		     do (analyze-funobj (function-binding-funobj function-binding)))
		 funobj))
	;; 1. Examine each store to lexical bindings.
	(analyze-funobj toplevel-funobj)
	;; 2.
	(flet ((resolve-thunks ()
		 (loop with more-thunks-p = t
		     repeat 20
		     while more-thunks-p
		     do (setf more-thunks-p nil)
			(maphash (lambda (binding analysis)
				   (declare (ignore binding))
				   (setf (type-analysis-thunks analysis)
				     (loop for (thunk . thunk-args) in (type-analysis-thunks analysis)
					 if (not (every #'binding-resolved-p thunk-args))
					 collect (cons thunk thunk-args)
					 else
					 do #+ignore
					 (warn "because ~S=>~S->~S completing ~S: ~S and ~S"
					       thunk thunk-args
					       (mapcar #'binding-resolve thunk-args)
					       binding
					       (type-analysis-declared-encoded-type analysis)
					       (multiple-value-list
						(multiple-value-call
						    #'encoded-types-or
						  (values-list
						   (type-analysis-encoded-type analysis))
						  (type-specifier-encode
						   (apply thunk (mapcar #'binding-resolve
									thunk-args))))))
					 (setf (type-analysis-encoded-type analysis)
					   (multiple-value-list
					       (multiple-value-call
						   #'encoded-types-and
						 (values-list
						  (type-analysis-declared-encoded-type analysis))
						 (multiple-value-call
						     #'encoded-types-or
						   (values-list
						    (type-analysis-encoded-type analysis))
						   (type-specifier-encode
						    (apply thunk (mapcar #'binding-resolve
									 thunk-args)))))))
					 (setf more-thunks-p t))))
				 binding-usage))))
	  (resolve-thunks)
	  (when *compiler-trust-user-type-declarations-p*
	    ;; For each unresolved binding, just use the declared type.
	    (maphash (lambda (binding analysis)
		       (declare (ignore binding))
		       (when (and (not (null (type-analysis-thunks analysis)))
				  (not (apply #'encoded-allp
					      (type-analysis-declared-encoded-type analysis))))
			 #+ignore
			 (warn "Trusting ~S, was ~S, because ~S [~S]"
			       binding
			       (type-analysis-encoded-type analysis)
			       (type-analysis-thunks analysis)
			       (loop for (thunk . thunk-args) in (type-analysis-thunks analysis)
				   collect (mapcar #'binding-resolved-p thunk-args)))
			 (setf (type-analysis-encoded-type analysis)
			   (type-analysis-declared-encoded-type analysis))
			 (setf (type-analysis-thunks analysis) nil))) ; Ignore remaining thunks.
		     binding-usage)
	    ;; Try one more time to resolve thunks.
	    (resolve-thunks)))
	#+ignore
	(maphash (lambda (binding analysis)
		   (when (type-analysis-thunks analysis)
		     (warn "Unable to infer type for ~S: ~S" binding
			   (type-analysis-thunks analysis))))
		 binding-usage)
	;; 3.
	(maphash (lambda (binding analysis)
		   (setf (binding-store-type binding)
		     (cond
		      ((and (not (null (type-analysis-thunks analysis)))
			    *compiler-trust-user-type-declarations-p*
			    (movitz-env-get (binding-name binding) :variable-type nil
					    (binding-env binding) nil))
		       (multiple-value-list
			(type-specifier-encode (movitz-env-get (binding-name binding) :variable-type
							       t (binding-env binding) nil))))
		      ((and *compiler-trust-user-type-declarations-p*
			    (movitz-env-get (binding-name binding) :variable-type nil
					    (binding-env binding) nil))
		       (multiple-value-list
			(multiple-value-call #'encoded-types-and
			  (type-specifier-encode (movitz-env-get (binding-name binding) :variable-type
								 t (binding-env binding) nil))
			  (values-list (type-analysis-encoded-type analysis)))))
		      ((not (null (type-analysis-thunks analysis)))
		       (multiple-value-list (type-specifier-encode t)))
		      (t (type-analysis-encoded-type analysis))))
		   #+ignore (warn "Finally: ~S" binding))
		 binding-usage))))
  toplevel-funobj)

(defun resolve-borrowed-bindings (toplevel-funobj)
  "For <funobj>'s code, for every non-local binding used we create
a borrowing-binding in the funobj-env. This process must be done
recursively, depth-first wrt. sub-functions. Also, return a plist
of all function-bindings seen."
  (check-type toplevel-funobj movitz-funobj)
  (let ((function-binding-usage ()))
    (labels ((process-binding (funobj binding usages)
	       (when (typep binding 'function-binding)
		 (dolist (usage usages)
		   (pushnew usage
			    (getf (sub-function-binding-usage (function-binding-parent binding))
				  binding))
		   (pushnew usage (getf function-binding-usage binding))))
	       (cond
                 ((typep binding 'constant-object-binding))
                 ((not (eq funobj (binding-funobj binding)))
                  (let ((borrowing-binding
                         (or (find binding (borrowed-bindings funobj)
				   :key #'borrowed-binding-target)
                             (car (push (movitz-env-add-binding (funobj-env funobj)
                                                                (make-instance 'borrowed-binding
									       :name (binding-name binding)
									       :target-binding binding))
                                        (borrowed-bindings funobj))))))
                    ;; We don't want to borrow a forwarding-binding..
                    (when (typep (borrowed-binding-target borrowing-binding)
                                 'forwarding-binding)
                      (change-class (borrowed-binding-target borrowing-binding)
                                    'located-binding))
;;;		     (warn "binding ~S of ~S is not local to ~S, replacing with ~S of ~S."
;;;			   binding (binding-env binding) funobj
;;;			   borrowing-binding (binding-env borrowing-binding))
;;;		     (pushnew borrowing-binding 
;;;			      (getf (binding-lended-p binding) :lended-to))
                    (dolist (usage usages)
                      (pushnew usage (borrowed-binding-usage borrowing-binding)))
                    borrowing-binding))
                 (t ; Binding is local to this funobj
                  (typecase binding
                    (forwarding-binding
                     (process-binding funobj (forwarding-binding-target binding) usages))
                    (t binding)))))
	     (resolve-sub-funobj (funobj sub-funobj)
	       (dolist (binding-we-lend (borrowed-bindings (resolve-funobj-borrowing sub-funobj)))
		 #+ignore
		 (warn "Lending from ~S to ~S: ~S <= ~S"
		       funobj sub-funobj
		       (borrowed-binding-target binding-we-lend)
		       binding-we-lend)
		 (process-binding funobj
				  (borrowed-binding-target binding-we-lend)
				  (borrowed-binding-usage binding-we-lend))))
	     (resolve-code (funobj code)
	       (dolist (instruction code)
		 (when (listp instruction)
		   (let ((store-binding (find-written-binding-and-type instruction)))
		     (when store-binding
		       (process-binding funobj store-binding '(:write))))
		   (dolist (load-binding (find-read-bindings instruction))
		     (process-binding funobj load-binding '(:read)))
		   (case (car instruction)
		     (:call-lexical
		      (process-binding funobj (second instruction) '(:call)))
		     (:stack-cons
		      (destructuring-bind (proto-cons dynamic-scope)
			  (cdr instruction)
			(push proto-cons (dynamic-extent-scope-members dynamic-scope))))
		     (:load-lambda
		      (destructuring-bind (lambda-binding lambda-result-mode capture-env)
			  (cdr instruction)
			(declare (ignore lambda-result-mode))
			(assert (eq funobj (binding-funobj lambda-binding)) ()
			  "A non-local lambda doesn't make sense. There must be a bug.")
			(let ((lambda-funobj (function-binding-funobj lambda-binding)))
			  (let ((dynamic-scope (find-dynamic-extent-scope capture-env)))
			    (when dynamic-scope
			      ;; (warn "Adding ~S to ~S/~S" lambda-funobj dynamic-extent dynamic-scope)
			      (setf (movitz-funobj-extent lambda-funobj) :dynamic-extent
				    (movitz-allocation lambda-funobj) dynamic-scope)
			      (push lambda-funobj (dynamic-extent-scope-members dynamic-scope))
			      (process-binding funobj (base-binding dynamic-scope) '(:read))))
			  (resolve-sub-funobj funobj lambda-funobj)
			  (process-binding funobj lambda-binding '(:read))
			  ;; This funobj is effectively using every binding that the lambda
			  ;; is borrowing..
			  (map nil (lambda (borrowed-binding)
				     (process-binding funobj
						      (borrowed-binding-target borrowed-binding)
						      '(:read)))
			       (borrowed-bindings (function-binding-funobj lambda-binding))))))
		     (:local-function-init
		      (let ((function-binding (second instruction)))
			(assert (eq funobj (binding-funobj function-binding)) ()
			  "Initialization of a non-local function doesn't make sense.")
			(resolve-sub-funobj funobj (function-binding-funobj (second instruction)))
			(map nil (lambda (borrowed-binding)
				   (process-binding funobj
						    (borrowed-binding-target borrowed-binding)
						    '(:read)))
			     (borrowed-bindings (function-binding-funobj (second instruction)))))))
		   (resolve-code funobj (instruction-sub-program instruction)))))
	     (resolve-funobj-borrowing (funobj)
	       (let ((funobj (change-class funobj 'movitz-funobj :borrowed-bindings nil)))
		 (loop for (nil . function-env) in (function-envs funobj)
		     do (resolve-code funobj (extended-code function-env)))
		 ;; (warn "~S borrows ~S." funobj (borrowed-bindings funobj))
		 funobj)))
      (values (resolve-funobj-borrowing toplevel-funobj)
	      function-binding-usage))))

(defun resolve-sub-functions (toplevel-funobj function-binding-usage)
  (assert (null (borrowed-bindings toplevel-funobj)) ()
    "Can't deal with toplevel closures yet. Borrowed: ~S"
    (borrowed-bindings toplevel-funobj))
  (setf (movitz-funobj-extent toplevel-funobj) :indefinite-extent)
  (let ((sub-funobj-index 0))
    (loop for (function-binding usage) on function-binding-usage by #'cddr
	do (let ((sub-funobj (function-binding-funobj function-binding)))
	     ;; (warn "USage: ~S => ~S" sub-funobj usage)
	     (case (car (movitz-funobj-name sub-funobj))
	       ((muerte.cl:lambda)
		(setf (movitz-funobj-name sub-funobj)
		  (list 'muerte.cl:lambda
			(movitz-funobj-name toplevel-funobj)
			(post-incf sub-funobj-index)))))
	     (loop for borrowed-binding in (borrowed-bindings sub-funobj)
		 do (pushnew borrowed-binding
			     (getf (binding-lending (borrowed-binding-target borrowed-binding))
				   :lended-to)))
	     ;; (warn "old extent: ~S" (movitz-funobj-extent sub-funobj))
	     (cond
	      ((or (null usage)
		   (null (borrowed-bindings sub-funobj)))
	       (when (null usage)
		 (warn "null usage for ~S" sub-funobj))
	       (change-class function-binding 'funobj-binding)
	       (setf (movitz-funobj-extent sub-funobj)
		 :indefinite-extent))
	      ((equal usage '(:call))
	       (change-class function-binding 'closure-binding)
	       (setf (movitz-funobj-extent sub-funobj)
		 :lexical-extent))
	      ((eq :dynamic-extent (movitz-funobj-extent sub-funobj))
	       (change-class function-binding 'closure-binding))
	      (t (change-class function-binding 'closure-binding)
		 (setf (movitz-funobj-extent sub-funobj)
		   :indefinite-extent))))))
  ;; Each time we change a function-binding to funobj-binding, that binding
  ;; no longer needs to be borrowed (because it doesn't share lexical bindings),
  ;; and therefore should be removed from any borrowed-binding list, which in
  ;; turn can cause the borrowing funobj to become a funobj-binding, and so on.
  (loop for modified-p = nil
     do (loop for function-binding in function-binding-usage by #'cddr
	   do (let ((sub-funobj (function-binding-funobj function-binding)))
		(when (not (null (borrowed-bindings sub-funobj)))
		  (check-type function-binding closure-binding)
		  (when (null (setf (borrowed-bindings sub-funobj)
				    (delete-if (lambda (b)
						 (when (typep (borrowed-binding-target b) 'funobj-binding)
						   (setf modified-p t)))
					       (borrowed-bindings sub-funobj))))
		    (change-class function-binding 'funobj-binding)))))
     while modified-p)
  (loop for function-binding in function-binding-usage by #'cddr
      do (finalize-funobj (function-binding-funobj function-binding)))
  (finalize-funobj toplevel-funobj))

(defun finalize-funobj (funobj)
  "Calculate funobj's constants, jumpers."
  (loop with all-key-args-constants = nil
      with all-constants-plist = () and all-jumper-sets = ()
      for (nil . function-env) in (function-envs funobj)
				  ;; (borrowed-bindings body-code) in code-specs
      as body-code = (extended-code function-env)
      as (const-plist jumper-sets key-args-constants) =
	(multiple-value-list (find-code-constants-and-jumpers body-code))
      do (when key-args-constants
	   (assert (not all-key-args-constants) ()
	     "only one &key parsing allowed per funobj.")
	   (setf all-key-args-constants key-args-constants))
	 (loop for (constant usage) on const-plist by #'cddr
	     do (incf (getf all-constants-plist constant 0) usage))
	 (loop for (name set) on jumper-sets by #'cddr
	     do (assert (not (getf all-jumper-sets name)) ()
		  "Jumper-set ~S multiply defined." name)
		(setf (getf all-jumper-sets name) set))
      finally
	(multiple-value-bind (const-list num-jumpers jumpers-map borrower-map)
	    (layout-funobj-vector all-constants-plist
				  all-key-args-constants
				  #+ignore (mapcar (lambda (x)
						     (cons (movitz-read x) 1))
						   '(:a :b :c :d))
				  all-jumper-sets
				  (borrowed-bindings funobj))
	  (setf (movitz-funobj-num-jumpers funobj) num-jumpers
		(movitz-funobj-const-list funobj) const-list
		(movitz-funobj-num-constants funobj) (length const-list)
		(movitz-funobj-jumpers-map funobj) jumpers-map)
	  (loop for (binding . pos) in borrower-map
	      do (setf (borrowed-binding-reference-slot binding) pos))
	  (return funobj))))
    
(defun layout-stack-frames (funobj)
  "Lay out the stack-frame (i.e. create a frame-map) for funobj
and all its local functions. This must be done breadth-first, because
a (lexical-extent) sub-function might care about its parent frame-map."
  (loop for (nil . function-env) in (function-envs funobj)
      do (assert (not (slot-boundp function-env 'frame-map)))
	 (setf (frame-map function-env)
	   (funobj-assign-bindings (extended-code function-env)
				   function-env)))
  (loop for (sub-function-binding) on (sub-function-binding-usage funobj) by #'cddr
      do (layout-stack-frames (function-binding-funobj sub-function-binding)))
  funobj)

(defun complete-funobj (funobj)
  (case (funobj-entry-protocol funobj)
    (:1req1opt 
     (complete-funobj-1req1opt funobj))
    (t (complete-funobj-default funobj)))
  (loop for (sub-function-binding) on (sub-function-binding-usage funobj) by #'cddr
      do (complete-funobj (function-binding-funobj sub-function-binding)))
  (register-function-code-size funobj))

(defun complete-funobj-1req1opt (funobj)
  (assert (= 2 (length (function-envs funobj))))
  (let* ((function-env (cdr (assoc 'muerte.cl::t (function-envs funobj))))
	 (optional-env (cdr (assoc :optional (function-envs funobj))))
	 (frame-map (frame-map function-env))
	 (resolved-code (finalize-code (extended-code function-env) funobj frame-map))
	 (resolved-optional-code (finalize-code (extended-code optional-env) funobj frame-map))
	 (stack-frame-size (frame-map-size (frame-map function-env)))
	 (use-stack-frame-p (or (plusp stack-frame-size)
				(tree-search resolved-code
					     '(:pushl :popl :ebp :esp :call :leave))
				(some (lambda (x)
					(and (not (equal '(:movl (:ebp -4) :esi) x))
					     (tree-search x ':esi)))
				      resolved-code))))
    (let* ((function-code
	    (let* ((req-binding (movitz-binding (first (required-vars function-env))
						function-env nil))
		   (req-location (cdr (assoc req-binding frame-map)))
		   (opt-binding (movitz-binding (first (optional-vars function-env))
						function-env nil))
		   (opt-location (cdr (assoc opt-binding frame-map)))
		   (optp-binding (movitz-binding (optional-function-argument-supplied-p-var opt-binding)
						 function-env nil))
		   (optp-location (cdr (assoc optp-binding frame-map)))
		   (stack-setup-pre 0))
	      (append `((:jmp (:edi ,(global-constant-offset 'trampoline-cl-dispatch-1or2))))
		      '(entry%1op)
		      (unless (eql nil opt-location)
			resolved-optional-code)
		      (when optp-location
			`((:movl :edi :edx)
			  (:jmp 'optp-into-edx-ok)))
		      '(entry%2op)
		      (when optp-location
			`((,*compiler-global-segment-prefix*
			   :movl (:edi ,(global-constant-offset 't-symbol)) :edx)
			  optp-into-edx-ok))
		      (when use-stack-frame-p
			+enter-stack-frame-code+)
		      '(start-stack-frame-setup)
		      (cond
		       ((and (eql 1 req-location)
			     (eql 2 opt-location))
			(incf stack-setup-pre 2)
			`((:pushl :eax)
			  (:pushl :ebx)))
		       ((and (eql 1 req-location)
			     (eql nil opt-location))
			(incf stack-setup-pre 1)
			`((:pushl :eax)))
		       ((and (member req-location '(nil :eax))
			     (eql 1 opt-location))
			(incf stack-setup-pre 1)
			`((:pushl :ebx)))
		       ((and (member req-location '(nil :eax))
			     (member opt-location '(nil :ebx)))
			nil)
		       (t (error "Can't deal with req ~S opt ~S."
				 req-location opt-location)))
		      (cond
		       ((not optp-location)
			(make-stack-setup-code (- stack-frame-size stack-setup-pre)))
		       ((and (integerp optp-location)
			     (= optp-location (1+ stack-setup-pre)))
			(append `((:pushl :edx))
				(make-stack-setup-code (- stack-frame-size stack-setup-pre 1))))
		       ((integerp optp-location)
			(append (make-stack-setup-code (- stack-frame-size stack-setup-pre))
				`((:movl :edx (:ebp ,(stack-frame-offset optp-location))))))
		       (t (error "Can't deal with optional-p at ~S, after (~S ~S)."
				 optp-location req-location opt-location)))
		      (flet ((make-lending (location lended-cons-position)
			       (etypecase req-location
				 (integer
				  `((:movl (:ebp ,(stack-frame-offset location)) :edx)
				    (:movl :edi (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr 
				    (:movl :edx (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
				    (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position)))
					   :edx)
				    (:movl :edx (:ebp ,(stack-frame-offset location))))))))
			(append
			 (when (binding-lended-p req-binding)
			   (make-lending req-location (getf (binding-lending req-binding)
							    :stack-cons-location)))
			 (when (binding-lended-p opt-binding)
			   (make-lending opt-location (getf (binding-lending opt-binding)
							    :stack-cons-location)))
			 (when (and optp-binding (binding-lended-p optp-binding))
			   (make-lending optp-location (getf (binding-lending optp-binding)
							     :stack-cons-location)))))
		      resolved-code
		      (make-compiled-function-postlude funobj function-env
						       use-stack-frame-p)))))
      (let ((optimized-function-code
	     (optimize-code function-code
			    :keep-labels (append (subseq (movitz-funobj-const-list funobj)
							 0 (movitz-funobj-num-jumpers funobj))
						 '(entry%1op entry%2op)))))
	(assemble-funobj funobj optimized-function-code)))))

(defun complete-funobj-default (funobj)
  (let ((code-specs
	 (loop for (numargs . function-env) in (function-envs funobj)
	     collecting
	       (let* ((frame-map (frame-map function-env))
		      (resolved-code (finalize-code (extended-code function-env) funobj frame-map))
		      (stack-frame-size (frame-map-size (frame-map function-env)))
		      (use-stack-frame-p (or (plusp stack-frame-size)
					     (tree-search resolved-code
							  '(:push :pop :ebp :esp :call :leave))
					     (some (lambda (x)
						     (and (not (equal '(:movl (:ebp -4) :esi) x))
							  (tree-search x ':esi)))
						   resolved-code))))
		 (multiple-value-bind (prelude-code have-normalized-ecx-p)
		     (make-compiled-function-prelude stack-frame-size function-env use-stack-frame-p
						     (need-normalized-ecx-p function-env) frame-map
						     :do-check-stack-p (or (<= 32 stack-frame-size)
									   (tree-search resolved-code
											'(:call))))
		   (let ((function-code
			  (install-arg-cmp (append prelude-code
						   resolved-code
						   (make-compiled-function-postlude funobj function-env
										    use-stack-frame-p))
					   have-normalized-ecx-p)))
		     (let ((optimized-function-code
			    (optimize-code function-code
					   :keep-labels (append
							 (subseq (movitz-funobj-const-list funobj)
								 0 (movitz-funobj-num-jumpers funobj))
							 '(entry%1op
							   entry%2op
							   entry%3op)))))
		       (cons numargs optimized-function-code))))))))
    (let ((code1 (cdr (assoc 1 code-specs)))
	  (code2 (cdr (assoc 2 code-specs)))
	  (code3 (cdr (assoc 3 code-specs)))
	  (codet (cdr (assoc 'muerte.cl::t code-specs))))
      (assert codet () "A default numargs-case is required.") 
      ;; (format t "codet:~{~&~A~}" codet)
      (let ((combined-code
	     (delete 'start-stack-frame-setup
		     (append
		      (when code1
			`((:cmpb 1 :cl)
			  (:jne 'not-one-arg)
			  ,@(unless (find 'entry%1op code1)
			      '(entry%1op (:movb 1 :cl)))
			  ,@code1
			  not-one-arg))
		      (when code2
			`((:cmpb 2 :cl)
			  (:jne 'not-two-args)
			  ,@(unless (find 'entry%2op code2)
			      '(entry%2op (:movb 2 :cl)))
			  ,@code2
			  not-two-args))
		      (when code3
			`((:cmpb 3 :cl)
			  (:jne 'not-three-args)
			  ,@(unless (find 'entry%3op code3)
			      '(entry%3op (:movb 3 :cl)))
			  ,@code3
			  not-three-args))
		      (delete-if (lambda (x)
				   (or (and code1 (eq x 'entry%1op))
				       (and code2 (eq x 'entry%2op))
				       (and code3 (eq x 'entry%3op))))
				 codet)))))
	;; (print-code funobj combined-code)
	(assemble-funobj funobj combined-code))))
  funobj)

(defun assemble-funobj (funobj combined-code &key extra-prefix-computers)
  (multiple-value-bind (code code-symtab)
      (let ((asm-x86:*cpu-mode* :32-bit)
	    (asm:*instruction-compute-extra-prefix-map*
	     (append extra-prefix-computers
		     '((:call . compute-call-extra-prefix)))))
	(asm:assemble-proglist combined-code
			       :symtab (list* (cons :nil-value (image-nil-word *image*))
					      (loop for (label . set) in (movitz-funobj-jumpers-map funobj)
						 collect (cons label
							       (* 4 (or (search set (movitz-funobj-const-list funobj)
										:end2 (movitz-funobj-num-jumpers funobj))
									(error "Jumper for ~S missing." label))))))))
    (let ((code-length (- (length code) 3 -3)))
      (let ((locate-inconsistencies (check-locate-concistency code code-length)))
	(when locate-inconsistencies
	  (when (rassoc 'compute-extra-prefix-locate-inconsistencies
			extra-prefix-computers)
	    (error "~S failed to fix locate-inconsistencies. This should not happen."
		   'compute-extra-prefix-locate-inconsistencies))
	  (return-from assemble-funobj
	    (assemble-funobj funobj combined-code
			     :extra-prefix-computers (list (cons t (lambda (pc size)
								     (loop for bad-pc in locate-inconsistencies
									when (<= pc bad-pc (+ pc size))
									return '(#x90)))))))
			     
	  (break "locate-inconsistencies: ~S" locate-inconsistencies)))
      (setf (movitz-funobj-symtab funobj) code-symtab)
      (let ((code-vector (make-array code-length
				     :initial-contents code
				     :fill-pointer t)))
	(setf (fill-pointer code-vector) code-length)
	;; debug info
	(setf (ldb (byte 1 5) (slot-value funobj 'debug-info))
	      1 #+ignore (if use-stack-frame-p 1 0))
	(let ((x (cdr (assoc 'start-stack-frame-setup code-symtab))))
	  (cond
	    ((not x)
	     #+ignore (warn "No start-stack-frame-setup label for ~S." name))
	    ((<= 0 x 30)
	     (setf (ldb (byte 5 0) (slot-value funobj 'debug-info)) x))
	    (t (warn "Can't encode start-stack-frame-setup label ~D into debug-info for ~S."
		     x (movitz-funobj-name funobj)))))
	(let* ((a (or (cdr (assoc 'entry%1op code-symtab)) 0))
	       (b (or (cdr (assoc 'entry%2op code-symtab)) a))
	       (c (or (cdr (assoc 'entry%3op code-symtab)) b)))
	  (unless (<= a b c)
	    (warn "Weird code-entries: ~D, ~D, ~D." a b c))
	  (unless (<= 0 a 255)
	    (break "entry%1: ~D" a))
	  (unless (<= 0 b 2047)
	    (break "entry%2: ~D" b))
	  (unless (<= 0 c 4095)
	    (break "entry%3: ~D" c)))
	(loop for (entry-label slot-name) in '((entry%1op code-vector%1op)
					       (entry%2op code-vector%2op)
					       (entry%3op code-vector%3op))
	   do (when (assoc entry-label code-symtab)
		(let ((offset (cdr (assoc entry-label code-symtab))))
		  (setf (slot-value funobj slot-name)
			(cons offset funobj)))))
	(setf (movitz-funobj-code-vector funobj)
	      (make-movitz-vector (length code-vector)
				  :fill-pointer code-length
				  :element-type 'code
				  :initial-contents code-vector)))))
  funobj)

(defun check-locate-concistency (code code-vector-length)
  "The run-time function muerte::%find-code-vector sometimes needs to find a code-vector by
searching through the machine-code for an object header signature. This function is to
make sure that no machine code accidentally forms such a header signature."
  (loop for (x0 x1 x2 x3) on code by (lambda (l) (nthcdr 8 l))
     for pc upfrom 0 by 8
     when (and (= x0 (tag :basic-vector))
	       (= x1 (enum-value 'movitz-vector-element-type :code))
	       (or (<= #x4000 code-vector-length)
		   (and (= x2 (ldb (byte 8 0) code-vector-length))
			(= x3 (ldb (byte 8 8) code-vector-length)))))
     collect pc
     and do (warn "Code-vector (length ~D) can break %find-code-vector at ~D: #x~2,'0X~2,'0X ~2,'0X~2,'0X."
		  code-vector-length
		  pc x0 x1 x2 x3)))


(defun make-2req (binding0 binding1 frame-map)
  (let ((location-0 (new-binding-location binding0 frame-map))
	(location-1 (new-binding-location binding1 frame-map)))
    (cond
     ((and (eq :eax location-0)
	   (eq :ebx location-1))
      (values nil 0))
     ((and (eq :ebx location-0)
	   (eq :eax location-1))
      (values '((:xchgl :eax :ebx)) 0))
     ((and (eql 1 location-0)
	   (eql 2 location-1))
      (values '((:pushl :eax)
		(:pushl :ebx))
	      2))
     ((and (eq :eax location-0)
	   (eql 1 location-1))
      (values '((:pushl :ebx))
	      1))
     (t (error "make-2req confused by loc0: ~W, loc1: ~W" location-0 location-1)))))


(defun movitz-compile-file (path &key ((:image *image*) *image*)
                            load-priority
                            (delete-file-p nil))
  (handler-bind
      (#+sbcl (sb-ext:defconstant-uneql #'continue))
    (unwind-protect
         (let ((*movitz-host-features* *features*)
               (*features* (image-movitz-features *image*)))
           (multiple-value-prog1
               (movitz-compile-file-internal path load-priority)
             (unless (equalp *features* (image-movitz-features *image*))
               (warn "*features* changed from ~S to ~S." (image-movitz-features *image*) *features*)
               (setf (image-movitz-features *image*) *features*))))
      (when delete-file-p
	(assert (equal (pathname-directory "/tmp/")
		       (pathname-directory path))
                (path)
                "Refusing to delete file not in /tmp.")
	(delete-file path)))))

(defun movitz-compile-file-internal (path &optional (*default-load-priority*
                                                     (and (boundp '*default-load-priority*)
                                                          (symbol-value '*default-load-priority*)
                                                          (1+ (symbol-value '*default-load-priority*)))))
  (declare (special *default-load-priority*))
  (with-simple-restart (continue "Skip Movitz compilation of ~S." path)
    (with-retries-until-true (retry "Restart Movitz compilation of ~S." path)
      (with-open-file (stream path :direction :input)
        (let ((*package* (find-package :muerte)))
          (movitz-compile-stream-internal stream :path path))))))

(defun movitz-compile-stream (stream &key (path "unknown-toplevel.lisp") (package :muerte))
  (handler-bind
      (#+sbcl (sb-ext:defconstant-uneql #'continue))
    (unwind-protect
         (let ((*package* (find-package package))
               (*movitz-host-features* *features*)
               (*features* (image-movitz-features *image*)))
           (multiple-value-prog1
               (movitz-compile-stream-internal stream :path path)
             (unless (equalp *features* (image-movitz-features *image*))
               (warn "*features* changed from ~S to ~S." (image-movitz-features *image*) *features*)
               (setf (image-movitz-features *image*) *features*)))))))

(defun movitz-compile-stream-internal (stream &key (path "unknown-toplevel.lisp"))
  (let* ((muerte.cl::*compile-file-pathname* path)
         (funobj (make-instance 'movitz-funobj-pass1
                  :name (intern (format nil "~A" path) :muerte)
                  :lambda-list (movitz-read nil)))
         (funobj-env (make-local-movitz-environment nil funobj
                      :type 'funobj-env
                      :declaration-context :funobj))
         (function-env (make-local-movitz-environment funobj-env funobj
                        :type 'function-env
                        :declaration-context :funobj))
         (file-code
          (with-compilation-unit ()
            (add-bindings-from-lambda-list () function-env)
            (setf (funobj-env funobj) funobj-env)
            (loop for form = (with-movitz-syntax ()
                               (read stream nil '#0=#:eof))
               until (eq form '#0#)
               appending
                 (with-simple-restart (skip-toplevel-form
                                       "Skip the compilation of top-level form~{ ~A~}."
                                       (cond
                                         ((symbolp form)
                                          (list form))
                                         ((symbolp (car form))
                                          (list (car form)
                                                (cadr form)))))
                   (when *compiler-verbose-p*
                     (format *query-io* "~&Movitz Compiling ~S..~%"
                             (cond
                               ((symbolp form) form)
                               ((symbolp (car form))
                                (xsubseq form 0 2)))))
                   (compiler-call #'compile-form
                    :form form
                    :funobj funobj
                    :env function-env
                    :top-level-p t
                    :result-mode :ignore))))))
    (cond
      ((null file-code)
       (setf (image-load-time-funobjs *image*)
             (delete funobj (image-load-time-funobjs *image*) :key #'first))
       'muerte::constantly-true)
      (t (setf (extended-code function-env) file-code
               (need-normalized-ecx-p function-env) nil
               (function-envs funobj) (list (cons 'muerte.cl::t function-env))
               (funobj-env funobj) funobj-env)
         (make-compiled-funobj-pass2 funobj)
         (let ((name (funobj-name funobj)))
           (setf (movitz-env-named-function name) funobj)
           name)))))

;;;;

(defun print-code (x code)
  (let ((*print-level* 4))
    (format t "~&~A code:~{~&  ~A~}" x code))
  code)

(defun layout-program (pc)
  "For the program in pc, layout sub-programs at the top-level program."
  (do ((previous-subs nil)
       (pending-subs nil)
       (new-program nil))
      ((endp pc)
       (assert (not pending-subs) ()
	 "pending sub-programs: ~S" pending-subs)
       (nreverse new-program))
    (let ((i (pop pc)))
      (multiple-value-bind (sub-prg sub-opts)
	  (instruction-sub-program i)
	(if (null sub-prg)
	    (push i new-program)
	  (destructuring-bind (&optional (label (gensym "sub-prg-label-")))
	      sub-opts
	    (let ((x (cons label sub-prg)))
	      (unless (find x previous-subs :test #'equal)
		(push x pending-subs)
		(push x previous-subs)))
	    (unless (instruction-is i :jnever)
	      (push `(,(car i) ',label)
		    new-program))))
	(when (or (instruction-uncontinues-p i)
		  (endp pc))
	  (let* ((match-label (and (eq (car i) :jmp)
				   (consp (second i))
				   (eq (car (second i)) 'quote)
				   (symbolp (second (second i)))
				   (second (second i))))
		 (matching-sub (assoc match-label pending-subs)))
	    (unless (and match-label
			 (or (eq match-label (first pc))
			     (and (symbolp (first pc))
				  (eq match-label (second pc)))))
	      (if matching-sub
		  (setf pc (append (cdr matching-sub) pc)
			pending-subs (delete matching-sub pending-subs))
		(setf pc (append (reduce #'append (nreverse pending-subs)) pc)
		      pending-subs nil)))))))))


(defun optimize-code (unoptimized-code &rest args)
  #+ignore (print-code 'to-optimize unoptimized-code)
  (if (not *compiler-do-optimize*)
      (layout-program (optimize-code-unfold-branches unoptimized-code))
      (apply #'optimize-code-internal
             (optimize-code-dirties
              (layout-program (optimize-code-unfold-branches unoptimized-code)))
             0 args)))

(defun optimize-code-unfold-branches (unoptimized-code)
  "This particular optimization should be done before code layout:
   (:jcc 'label) (:jmp 'foo) label  => (:jncc 'foo) label"
  (flet ((explain (always format &rest args)
	 (when (or always *explain-peephole-optimizations*)
	   (warn "Peephole: ~?~&----------------------------" format args)))
	 (branch-instruction-label (i &optional jmp (branch-types '(:je :jne :jb :jnb :jbe :jz
								    :jl :jnz :jle :ja :jae :jg
								    :jge :jnc :jc :js :jns)))
 	   "If i is a branch, return the label."
	   (when jmp (push :jmp branch-types))
	   (let ((i (ignore-instruction-prefixes i)))
	     (or (and (listp i) (member (car i) branch-types)
		      (listp (second i)) (member (car (second i)) '(quote muerte.cl::quote))
		      (second (second i))))))
	 (negate-branch (branch-type)
	   (ecase branch-type
	     (:jb :jnb) (:jnb :jb)
	     (:jbe :ja) (:ja :jbe)
	     (:jz :jnz) (:jnz :jz)
	     (:je :jne) (:jne :je)
	     (:jc :jnc) (:jnc :jc)
	     (:jl :jge) (:jge :jl)
	     (:jle :jg) (:jg :jle))))
    (loop with next-pc = 'auto-next
			 ;; initially (warn "opt: ~{   ~A~%~}" unoptimized-code)
	for pc = unoptimized-code then (prog1 (if (eq 'auto-next next-pc) auto-next-pc next-pc)
					 (setq next-pc 'auto-next))
	as auto-next-pc = (cdr unoptimized-code) then (cdr pc)
	as p = (list (car pc))		; will be appended.
	as i1 = (first pc)		; current instruction, collected by default.
	and i2 = (second pc) and i3 = (third pc)
	while pc
 	do (when (and (branch-instruction-label i1)
		      (branch-instruction-label i2 t nil)
		      (symbolp i3)
		      (eq i3 (branch-instruction-label i1)))
	     (setf p (list `(,(negate-branch (car i1)) ',(branch-instruction-label i2 t nil))
			   i3)
		   next-pc (nthcdr 3 pc))
	     (explain nil "Got a sit: ~{~&~A~} => ~{~&~A~}" (subseq pc 0 3) p))
	nconc p)))

(defun optimize-code-dirties (unoptimized-code)
  "These optimizations may rearrange register usage in a way that is incompatible
with other optimizations that track register usage. So this is performed just once,
initially."
  unoptimized-code
  #+ignore
  (labels				; This stuff doesn't work..
      ((explain (always format &rest args)
	 (when (or always *explain-peephole-optimizations*)
	   (warn "Peephole: ~?~&----------------------------" format args)))
       (twop-p (c &optional op)
	 (let ((c (ignore-instruction-prefixes c)))
	   (and (listp c) (= 3 (length c))
		(or (not op) (eq op (first c)))
		(cdr c))))
       (twop-dst (c &optional op src)
	 (let ((c (ignore-instruction-prefixes c)))
	   (and (or (not src)
		    (equal src (first (twop-p c op))))
		(second (twop-p c op)))))
       (twop-src (c &optional op dest)
	 (let ((c (ignore-instruction-prefixes c)))
	   (and (or (not dest)
		    (equal dest (second (twop-p c op))))
		(first (twop-p c op)))))
       (register-operand (op)
	 (and (member op '(:eax :ebx :ecx :edx :edi))
	      op)))
    (loop with next-pc = 'auto-next
			 ;; initially (warn "opt: ~{   ~A~%~}" unoptimized-code)
	for pc = unoptimized-code then (prog1 (if (eq 'auto-next next-pc) auto-next-pc next-pc)
					 (setq next-pc 'auto-next))
	as auto-next-pc = (cdr unoptimized-code) then (cdr pc)
	as p = (list (car pc))		; will be appended.
	as i1 = (first pc)		; current instruction, collected by default.
	and i2 = (second pc) and i3 = (third pc)
	while pc
 	do (let ((regx (register-operand (twop-src i1 :movl)))
		 (regy (register-operand (twop-dst i1 :movl))))
	     (when (and regx regy
			(eq regx (twop-dst i2 :movl))
			(eq regx (twop-src i3 :cmpl))
			(eq regy (twop-dst i3 :cmpl)))
	       (setq p (list `(:cmpl ,(twop-src i2) ,regx) i1)
		     next-pc (nthcdr 3 pc))
	       (explain t "4: ~S for ~S [regx ~S, regy ~S]" p (subseq pc 0 5) regx regy)))
	nconc p)))

(defun xsubseq (sequence start end)
  (subseq sequence start (min (length sequence) end)))

(defun optimize-code-internal (unoptimized-code recursive-count &rest key-args
			       &key keep-labels stack-frame-size)
  "Peephole optimizer. Based on a lot of rather random heuristics."
  (declare (ignore stack-frame-size))
  (when (<= 20 recursive-count)
    (error "Peephole-optimizer recursive count reached ~D.
There is (propably) a bug in the peephole optimizer." recursive-count))
  ;; (warn "==================OPTIMIZE: ~{~&~A~}" unoptimized-code)
  (macrolet ((explain (always format &rest args)
	       `(when (or *explain-peephole-optimizations* ,always)
		  (warn "Peephole: ~@?~&----------------------------" ,format ,@args))))
    (labels
	(#+ignore
	 (explain (always format &rest args)
	   (when (or always *explain-peephole-optimizations*)
	     (warn "Peephole: ~?~&----------------------------" format args)))
	 (twop-p (c &optional op)
	   (let ((c (ignore-instruction-prefixes c)))
	     (and (listp c) (= 3 (length c))
		  (or (not op) (eq op (first c)))
		  (cdr c))))
	 (twop-dst (c &optional op src)
	   (let ((c (ignore-instruction-prefixes c)))
	     (and (or (not src)
		      (equal src (first (twop-p c op))))
		  (second (twop-p c op)))))
	 (twop-src (c &optional op dest)
	   (let ((c (ignore-instruction-prefixes c)))
	     (and (or (not dest)
		      (equal dest (second (twop-p c op))))
		  (first (twop-p c op)))))
	 (isrc (c)
	   (let ((c (ignore-instruction-prefixes c)))
	     (ecase (length (cdr c))
	       (0 nil)
	       (1 (cadr c))
	       (2 (twop-src c)))))
	 (idst (c)
	   (let ((c (ignore-instruction-prefixes c)))
	     (ecase (length (cdr c))
	       (0 nil)
	       (1 (cadr c))
	       (2 (twop-dst c)))))
	 (non-destructive-p (c)
	   (let ((c (ignore-instruction-prefixes c)))
	     (and (consp c)
		  (member (car c) '(:testl :testb :cmpl :cmpb :frame-map :std)))))
	 (simple-instruction-p (c)
	   (let ((c (ignore-instruction-prefixes c)))
	     (and (listp c)
		  (member (car c)
			  '(:movl :xorl :popl :pushl :cmpl :leal :andl :addl :subl)))))
	 (register-indirect-operand (op base)
	   (multiple-value-bind (reg off)
	       (when (listp op)
		 (loop for x in op
		     if (integerp x) sum x into off
		     else collect x into reg
		     finally (return (values reg off))))
	     (and (eq base (car reg))
		  (not (rest reg))
		  off)))
	 (stack-frame-operand (op)
	   (register-indirect-operand op :ebp))
	 (funobj-constant-operand (op)
	   (register-indirect-operand op :esi))
	 (global-constant-operand (op)
	   (register-indirect-operand op :edi))
	 (global-funcall-p (op &optional funs)
	   (let ((op (ignore-instruction-prefixes op)))
	     (when (instruction-is op :call)
	       (let ((x (global-constant-operand (second op))))
		 (flet ((try (name)
			  (and (eql x (slot-offset 'movitz-run-time-context name))
			       name)))
		   (cond
		    ((not x) nil)
		    ((null funs) t)
		    ((atom funs) (try funs))
		    (t (some #'try funs))))))))
	 (preserves-stack-location-p (i stack-location)
	   (let ((i (ignore-instruction-prefixes i)))
	     (and (not (atom i))
		  (or (global-funcall-p i)
		      (instruction-is i :frame-map)
		      (branch-instruction-label i)
		      (non-destructive-p i)
		      (and (simple-instruction-p i)
			   (not (eql stack-location (stack-frame-operand (idst i)))))))))
	 (preserves-register-p (i register)
	   (let ((i (ignore-instruction-prefixes i)))
	     (and (not (atom i))
		  (not (and (eq register :esp)
			    (member (instruction-is i)
				    '(:pushl :popl))))
		  (or (and (simple-instruction-p i)
			   (not (eq register (idst i))))
		      (instruction-is i :frame-map)
		      (branch-instruction-label i)
		      (non-destructive-p i)
		      (and (member register '(:edx))
			   (member (global-funcall-p i)
				   '(fast-car fast-cdr fast-car-ebx fast-cdr-ebx)))
		      (and (not (eq register :esp))
			   (instruction-is i :pushl))))))
	 (operand-register-indirect-p (operand register)
	   (and (consp operand)
		(tree-search operand register)))
	 (doesnt-read-register-p (i register)
	   (let ((i (ignore-instruction-prefixes i)))
	     (or (symbolp i)
		 (and (simple-instruction-p i)
		      (if (member (instruction-is i) '(:movl))
			  (and (not (eq register (twop-src i)))
			       (not (operand-register-indirect-p (twop-src i) register))
			       (not (operand-register-indirect-p (twop-dst i) register)))
			(not (or (eq register (isrc i))
				 (operand-register-indirect-p (isrc i) register)
				 (eq register (idst i))
				 (operand-register-indirect-p (idst i) register)))))
		 (instruction-is i :frame-map)
		 (and (member register '(:edx))
		      (member (global-funcall-p i)
			      '(fast-car fast-cdr fast-car-ebx fast-cdr-ebx))))))
	 (register-operand (op)
	   (and (member op '(:eax :ebx :ecx :edx :edi))
		op))
	 (true-and-equal (x &rest more)
	   (declare (dynamic-extent more))
	   (and x (dolist (y more t)
		    (unless (equal x y)
		      (return nil)))))
	 (uses-stack-frame-p (c)
	   (and (consp c)
		(some #'stack-frame-operand (cdr (ignore-instruction-prefixes c)))))
	 (load-stack-frame-p (c &optional (op :movl))
	   (stack-frame-operand (twop-src c op)))
	 (store-stack-frame-p (c &optional (op :movl))
	   (stack-frame-operand (twop-dst c op)))
	 (read-stack-frame-p (c)
	   (or (load-stack-frame-p c :movl)
	       (load-stack-frame-p c :addl)
	       (load-stack-frame-p c :subl)
	       (load-stack-frame-p c :cmpl)
	       (store-stack-frame-p c :cmpl)
	       (and (consp c)
		    (eq :pushl (car c))
		    (stack-frame-operand (second c)))))
	 (in-stack-frame-p (c reg)
	   "Does c ensure that reg is in some particular stack-frame location?"
	   (or (and (load-stack-frame-p c)
		    (eq reg (twop-dst c))
		    (stack-frame-operand (twop-src c)))
	       (and (store-stack-frame-p c)
		    (eq reg (twop-src c))
		    (stack-frame-operand (twop-dst c)))))
	 (load-funobj-constant-p (c)
	   (funobj-constant-operand (twop-src c :movl)))
	 #+ignore
	 (sub-program-label-p (l)
	   (and (consp l)
		(eq :sub-program (car l))))
	 (local-load-p (c)
	   (if (or (load-stack-frame-p c)
		   (load-funobj-constant-p c))
	       (twop-src c)
	     nil))
	 (label-here-p (label code)
	   "Is <label> at this point in <code>?"
	   (loop for i in code
	       while (or (symbolp i)
			 (instruction-is i :frame-map))
	       thereis (eq label i)))
	 (negate-branch (branch-type)
	   (ecase branch-type
	     (:jbe :ja) (:ja :jbe)
	     (:jz :jnz) (:jnz :jz)
	     (:je :jne) (:jne :je)
	     (:jc :jnc) (:jnc :jc)
	     (:jl :jge) (:jge :jl)
	     (:jle :jg) (:jg :jle)))
	 (branch-instruction-label (i &optional jmp (branch-types '(:je :jne :jb :jnb :jbe :jz :jl :jnz
								    :jle :ja :jae :jg :jge :jnc :jc :js :jns)))
	   "If i is a branch, return the label."
	   (when jmp (push :jmp branch-types))
	   (let ((i (ignore-instruction-prefixes i)))
	     (or (and (listp i)
		      (listp (second i))
		      (member (car (second i)) '(quote muerte.cl::quote))
		      (member (car i) branch-types)
		      (second (second i)))
		 #+ignore
		 (and (listp i)
		      branch-types
		      (symbolp (car i))
		      (not (member (car i) '(:jmp :jecxz)))
		      (char= #\J (char (symbol-name (car i)) 0))
		      (warn "Not a branch: ~A / ~A   [~A]" i (symbol-package (caadr i)) branch-types)))))
	 (find-branches-to-label (start-pc label &optional (context-size 0))
	   "Context-size is the number of instructions _before_ the branch you want returned."
	   (dotimes (i context-size)
	     (push nil start-pc))
	   (loop for pc on start-pc
	       as i = (nth context-size pc)
	       as i-label = (branch-instruction-label i t)
	       if (or (eq label i-label)
		      (and (consp i-label)
			   (eq :label-plus-one (car i-label))))
	       nconc (list pc)
	       else if (let ((sub-program i-label))
			 (and (consp sub-program)
			      (eq :sub-program (car sub-program))))
	       nconc (find-branches-to-label (cddr (branch-instruction-label i t))
					     label context-size)
	       else if (and (not (atom i))
			    (tree-search i label))
	       nconc (list 'unknown-label-usage)))
	 (optimize-trim-stack-frame (unoptimized-code)
	   "Any unused local variables on the stack-frame?"
	   unoptimized-code
	   ;; BUILD A MAP OF USED STACK-VARS AND REMAP THEM!	 
	   #+ignore (if (not (and stack-frame-size
				  (find 'start-stack-frame-setup unoptimized-code)))
			unoptimized-code
		      (let ((old-code unoptimized-code)
			    (new-code ()))
			;; copy everything upto start-stack-frame-setup
			(loop for i = (pop old-code)
			    do (push i new-code)
			    while old-code
			    until (eq i 'start-stack-frame-setup))
			(assert (eq (car new-code) 'start-stack-frame-setup) ()
			  "no start-stack-frame-setup label, but we already checked!")
			(loop for pos downfrom -8 by 4
			    as i = (pop old-code)
			    if (and (consp i) (eq :pushl (car i)) (symbolp (cadr i)))
			    collect (cons pos (cadr i))
			    and do (unless (find pos old-code :key #'read-stack-frame-p)
				     (cond
				      ((find pos old-code :key #'store-stack-frame-p)
				       (warn "Unused local but stored var: ~S" pos))
				      ((find pos old-code :key #'uses-stack-frame-p)
				       (warn "Unused BUT USED local var: ~S" pos))
				      (t (warn "Unused local var: ~S" pos))))
			    else do
				 (push i old-code)
				 (loop-finish))))
	   unoptimized-code)
	 (frame-map-code (unoptimized-code)
	   "After each label in unoptimized-code, insert a (:frame-map <full-map> <branch-map> <sticky>)
that says which registers are known to hold which stack-frame-locations.
A branch-map is the map that is guaranteed after every branch to the label, i.e. not including
falling below the label."
	   #+ignore (warn "unmapped:~{~&~A~}" unoptimized-code)
	   (flet ((rcode-map (code)
		    #+ignore (when (instruction-is (car code) :testb)
			       (warn "rcoding ~A" code))
		    (loop with modifieds = nil
			with registers = (list :eax :ebx :ecx :edx)
			with local-map = nil
			for ii in code
			while registers
			do (flet ((add-map (stack reg)
				    (when (and (not (member stack modifieds))
					       (member reg registers))
				      (push (cons stack reg)
					    local-map))))
			     (cond ((instruction-is ii :frame-map)
				    (dolist (m (second ii))
				      (add-map (car m) (cdr m))))
				   ((load-stack-frame-p ii)
				    (add-map (load-stack-frame-p ii)
					     (twop-dst ii)))
				   ((store-stack-frame-p ii)
				    (add-map (store-stack-frame-p ii)
					     (twop-src ii))
				    (pushnew (store-stack-frame-p ii)
					     modifieds))
				   ((non-destructive-p ii))
				   ((branch-instruction-label ii))
				   ((simple-instruction-p ii)
				    (let ((op (idst ii)))
				      (cond
				       ((stack-frame-operand op)
					(pushnew (stack-frame-operand op) modifieds))
				       ((symbolp op)
					(setf registers (delete op registers))))))
				   (t #+ignore (when (instruction-is (car code) :testb)
						 (warn "stopped at ~A" ii))
				      (loop-finish))))
			   (setf registers
			     (delete-if (lambda (r)
					  (not (preserves-register-p ii r)))
					registers))
			finally
			  #+ignore (when (instruction-is (car code) :testb)
				     (warn "..map ~A" local-map))
			  (return local-map))))
	     (loop with next-pc = 'auto-next
				  ;; initially (warn "opt: ~{   ~A~%~}" unoptimized-code)
		 for pc = unoptimized-code then (prog1 (if (eq 'auto-next next-pc) auto-next-pc next-pc)
						  (setq next-pc 'auto-next))
		 as auto-next-pc = (cdr unoptimized-code) then (cdr pc)
		 as p = (list (car pc))	; will be appended.
		 as i1 = (first pc)	; current instruction, collected by default.
		 and i2 = (second pc)
		 while pc
		 do (when (and (symbolp i1)
			       (not (and (instruction-is i2 :frame-map)
					 (fourth i2))))
		      (let* ((label i1)
			     (branch-map (reduce (lambda (&optional x y)
						   (intersection x y :test #'equal))
						 (mapcar (lambda (lpc)
							   (if (eq 'unknown-label-usage lpc)
							       nil
							     (rcode-map (nreverse (xsubseq lpc 0 9)))))
							 (find-branches-to-label unoptimized-code label 9))))
			     (full-map (let ((rcode (nreverse (let* ((pos (loop for x on unoptimized-code
									      as pos upfrom 0
									      until (eq x pc)
									      finally (return pos)))
								     (back9 (max 0 (- pos 9))))
								(subseq unoptimized-code
									back9 pos)))))
					 (if (instruction-uncontinues-p (car rcode))
					     branch-map
					   (intersection branch-map (rcode-map rcode) :test #'equal)))))
			(when (or full-map branch-map nil)
			  #+ignore
			  (explain nil "Inserting at ~A frame-map ~S branch-map ~S."
				   label full-map branch-map))
			(setq p (list label `(:frame-map ,full-map ,branch-map))
			      next-pc (if (instruction-is i2 :frame-map)
					  (cddr pc)
					(cdr pc)))))
		 nconc p)))
	 (optimize-stack-frame-init (unoptimized-code)
	   "Look at the function's stack-frame initialization code, and see
          if we can optimize that, and/or immediately subsequent loads/stores."
	   (if (not (find 'start-stack-frame-setup unoptimized-code))
	       unoptimized-code
	     (let ((old-code unoptimized-code)
		   (new-code ()))
	       ;; copy everything upto start-stack-frame-setup
	       (loop for i = (pop old-code)
		   do (push i new-code)
		   while old-code
		   until (eq i 'start-stack-frame-setup))
	       (assert (eq (car new-code) 'start-stack-frame-setup) ()
		 "no start-stack-frame-setup label, but we already checked!")
	       (let* ((frame-map (loop with pos = -8
				     as i = (pop old-code)
                                     if (instruction-is i :frame-map)
                                     do (progn :nothing)
				     else if
                                      (and (consp i) (eq :pushl (car i)) (symbolp (cadr i)))
				     collect
                                      (cons pos (cadr i))
				     and do
                                      (decf pos 4)
                                      (push i new-code)
				     else do
                                      (push i old-code)
                                      (loop-finish)))
		      (mod-p (loop with mod-p = nil
				 for i = `(:frame-map ,(copy-list frame-map) nil t)
				 then (pop old-code)
				 while i
                                 do (let ((new-i (cond
                                                   ((let ((store-pos (store-stack-frame-p i)))
                                                      (and store-pos
                                                           (eq (cdr (assoc store-pos frame-map))
                                                               (twop-src i))))
                                                    (explain nil "removed stack-init store: ~S" i)
                                                    nil)
                                                   ((let ((load-pos (load-stack-frame-p i)))
                                                      (and load-pos
                                                           (eq (cdr (assoc load-pos frame-map))
                                                               (twop-dst i))))
                                                    (explain nil "removed stack-init load: ~S" i)
                                                    nil)
                                                   ((and (load-stack-frame-p i)
                                                         (assoc (load-stack-frame-p i) frame-map))
                                                    (let ((old-reg (cdr (assoc (load-stack-frame-p i)
                                                                               frame-map))))
                                                      (explain nil "load ~S already in ~S."
                                                               i old-reg)
                                                      `(:movl ,old-reg ,(twop-dst i))))
                                                   ((and (instruction-is i :pushl)
                                                         (stack-frame-operand (idst i))
                                                         (assoc (stack-frame-operand (idst i))
                                                                frame-map))
                                                    (let ((old-reg
                                                           (cdr (assoc (stack-frame-operand (idst i))
                                                                       frame-map))))
                                                      (explain nil "push ~S already in ~S."
                                                               i old-reg)
                                                      `(:pushl ,old-reg)))
                                                   (t i))))
				      (unless (eq new-i i)
					(setf mod-p t))
				      (when (branch-instruction-label new-i t)
					(setf mod-p t)
					(push `(:frame-map ,(copy-list frame-map) nil t)
					      new-code))
				      (when new-i
					(push new-i new-code)
					;; (warn "new-i: ~S, fm: ~S" new-i frame-map)
					(setf frame-map
                                              (delete-if (lambda (map)
                                                           ;; (warn "considering: ~S" map)
                                                           (not (and (preserves-register-p new-i (cdr map))
                                                                     (preserves-stack-location-p new-i
                                                                                                 (car map)))))
                                                         frame-map))
					;; (warn "Frame-map now: ~S" frame-map)
					(when (store-stack-frame-p new-i)
					  (loop for map in frame-map
					      do (when (= (store-stack-frame-p new-i)
							  (car map))
						   (setf (cdr map) (twop-src new-i)))))))
				 while frame-map
				 finally (return mod-p))))
		 (if (not mod-p)
		     unoptimized-code
		   (append (nreverse new-code)
			   old-code))))))
         (remove-frame-maps (code)
           (remove-if (lambda (x)
                        (typep x '(cons (eql :frame-map) *)))
                      code)))
      (let* ((unoptimized-code (frame-map-code (optimize-stack-frame-init unoptimized-code)))
	     (code-modified-p nil)
	     (stack-frame-used-map (loop with map = nil
				       for i in unoptimized-code
				       do (let ((x (read-stack-frame-p i)))
					    (when x (pushnew x map)))
					  (when (and (instruction-is i :leal)
						     (stack-frame-operand (twop-src i)))
					    (let ((x (stack-frame-operand (twop-src i))))
					      (when (= (tag :cons) (ldb (byte 2 0) x))
						(pushnew (+ x -1) map)
						(pushnew (+ x 3) map))))
				       finally (return map)))
	     (optimized-code
	      ;; This loop applies a set of (hard-coded) heuristics on unoptimized-code.
	      (loop with next-pc = 'auto-next
				   ;; initially (warn "opt: ~{   ~A~%~}" unoptimized-code)
		  for pc = unoptimized-code then (prog1 (if (eq 'auto-next next-pc) auto-next-pc next-pc)
						   (setq next-pc 'auto-next))
		  as auto-next-pc = (cdr unoptimized-code) then (cdr pc)
		  as p = (list (car pc)) ; will be appended.
		  as original-p = p
		  as i = (first pc)	; current instruction, collected by default.
		  and i2 = (second pc) and i3 = (third pc) and i4 = (fourth pc) and i5 = (fifth pc)
		  while pc
		  do (cond
		      ((and (instruction-is i :frame-map)
			    (instruction-is i2 :frame-map)
			    (not (fourth i))
			    (not (fourth i2)))
		       (let ((map (union (second i) (second i2) :test #'equal)))
			 (explain nil "Merged maps:~%~A + ~A~% => ~A"
				  (second i) (second i2) map)
			 (setq p `((:frame-map ,map))
			       next-pc (cddr pc))))
		      ((let ((x (store-stack-frame-p i)))
			 (and x (not (member x stack-frame-used-map))))
		       (setq p nil)
		       (explain nil "Removed store of unused local var: ~S" i))
		      ((and (global-funcall-p i2 '(fast-car))
			    (global-funcall-p i5 '(fast-cdr))
			    (true-and-equal (in-stack-frame-p i :eax)
					    (in-stack-frame-p i4 :eax)))
		       (let ((call-prefix (if (consp (car i2)) (car i2) nil)))
			 (cond
			  ((equal i3 '(:pushl :eax))
			   (explain nil "merge car,push,cdr to cdr-car,push")
			   (setf p (list i
					 `(,call-prefix :call
							(:edi ,(global-constant-offset 'fast-cdr-car)))
					 `(:pushl :ebx))
				 next-pc (nthcdr 5 pc)))
			  ((and (store-stack-frame-p i3)
				(eq :eax (twop-src i3)))
			   (explain nil "merge car,store,cdr to cdr-car,store")
			   (setf p (list i
					 `(,call-prefix :call
							(:edi ,(global-constant-offset 'fast-cdr-car)))
					 `(:movl :ebx ,(twop-dst i3)))
				 next-pc (nthcdr 5 pc)))
			  (t (error "can't deal with cdr-car here: ~{~&~A~}" (subseq pc 0 8))))))
		      ((flet ((try (place register &optional map reason)
				"See if we can remove a stack-frame load below current pc,
                              given the knowledge that <register> is equal to <place>."
				(let ((next-load
				       (and place
					    (dolist (si (cdr pc))
					      (when (and (twop-p si :cmpl)
							 (equal place (twop-src si)))
						(warn "Reverse cmp not yet dealed with.."))
					      (cond
					       ((and (twop-p si :cmpl)
						     (equal place (twop-dst si)))
						(return si))
					       ((equal place (local-load-p si))
						(return si))
					       ((or (not (consp si))
						    (not (preserves-register-p si register))
						    (equal place (twop-dst si)))
						(return nil)))
					      (setf map
						(remove-if (lambda (m)
							     (not (preserves-register-p si (cdr m))))
							   map))))))
				  (case (instruction-is next-load)
				    (:movl
				     (let ((pos (position next-load pc)))
				       (setq p (append (subseq pc 0 pos)
						       (if (or (eq register (twop-dst next-load))
							       (find-if (lambda (m)
									  (and (eq (twop-dst next-load) (cdr m))
									       (= (car m) (stack-frame-operand place))))
									map))
							   nil
							   (list `(:movl ,register ,(twop-dst next-load)))))
					     next-pc (nthcdr (1+ pos) pc))
				       (explain nil "preserved load/store .. load ~S of place ~S because ~S."
						next-load place reason)))
				    (:cmpl
				     (let ((pos (position next-load pc)))
				       (setq p (nconc (subseq pc 0 pos)
						      (list `(:cmpl ,(twop-src next-load) ,register)))
					     next-pc (nthcdr (1+ pos) pc))
				       (explain nil "preserved load/store..cmp: ~S" p next-load))))
				  (if next-load t nil))))
			 (or (when (instruction-is i :frame-map)
			       (loop for (place . register) in (second i)
;;;				 do (warn "map try ~S ~S: ~S" place register
;;;					  (try place register))
				   thereis (try `(:ebp ,place) register (second i) :frame-map)))
			     (try (or (local-load-p i)
				      (and (store-stack-frame-p i)
					   (twop-dst i)))
				  (if (store-stack-frame-p i)
				      (twop-src i)
				    (twop-dst i))
				  nil i))))
		      ((and (symbolp i)
			    (instruction-is i2 :frame-map)
			    (load-stack-frame-p i3)
			    (eq (twop-dst i3)
				(cdr (assoc (load-stack-frame-p i3) (third i2))))
			    (not (assoc (load-stack-frame-p i3) (second i2))))
		       (let ((reg (cdr (assoc (load-stack-frame-p i3) (third i2)))))
			 (explain nil "factor out load from loop: ~S" i3)
			 (assert (eq reg (twop-dst i3)))
			 (setq p (if (eq reg (twop-dst i3))
				     (list i3 i i2)
				   (append (list i3 i i2)
					   `((:movl ,reg ,(twop-dst i3)))))
			       next-pc (cdddr pc))))
		      ;; ((:movl <foo> <bar>) label (:movl <zot> <bar>))
		      ;; => (label (:movl <zot> <bar>))
		      ((and (instruction-is i :movl)
			    (or (symbolp i2)
				(and (not (branch-instruction-label i2))
				     (symbolp (twop-dst i))
				     (doesnt-read-register-p i2 (twop-dst i))))
			    (instruction-is i3 :frame-map)
			    (instruction-is i4 :movl)
			    (equal (twop-dst i) (twop-dst i4))
			    (not (and (symbolp (twop-dst i))
				      (operand-register-indirect-p (twop-src i4)
								   (twop-dst i)))))
		       (setq p (list i2 i3 i4)
			     next-pc (nthcdr 4 pc))
		       (explain nil "Removed redundant store before ~A: ~A"
				i2 (subseq pc 0 4)))
		      ((and (instruction-is i :movl)
			    (not (branch-instruction-label i2))
			    (symbolp (twop-dst i))
			    (doesnt-read-register-p i2 (twop-dst i))
			    (instruction-is i3 :movl)
			    (equal (twop-dst i) (twop-dst i3))
			    (not (and (symbolp (twop-dst i))
				      (operand-register-indirect-p (twop-src i3)
								   (twop-dst i)))))
		       (setq p (list i2 i3)
			     next-pc (nthcdr 3 pc))
		       (explain nil "Removed redundant store before ~A: ~A"
				i2 (subseq pc 0 3)))
		      #+ignore
		      ((let ((stack-pos (store-stack-frame-p i))) 
			 (and stack-pos
			      (loop with search-pc = (cdr pc)
				  while search-pc
				  repeat 10
				  for ii = (pop search-pc)
				  thereis (eql stack-pos 
					       (store-stack-frame-p ii))
				  while (or (global-funcall-p ii)
					    (and (simple-instruction-p ii)
						 (not (eql stack-pos
							   (uses-stack-frame-p ii))))))
			      #+ignore
			      (eql stack-pos 
				   (store-stack-frame-p i4))
			      #+ignore
			      (every (lambda (ii)
				       (or (global-funcall-p ii)
					   (and (simple-instruction-p ii)
						(not (eql stack-pos
							  (uses-stack-frame-p ii))))))
				     (list i2 i3))))
		       (setf p nil
			     next-pc (cdr pc))
		       (explain t "removing redundant store at ~A"
				(subseq pc 0 (min 10 (length pc)))))
		      ((and (member (instruction-is i)
				    '(:cmpl :cmpb :cmpw :testl :testb :testw))
			    (member (instruction-is i2)
				    '(:cmpl :cmpb :cmpw :testl :testb :testw)))
		       (setq p (list i2)
			     next-pc (nthcdr 2 pc))
		       (explain nil "Trimmed double test: ~A" (subseq pc 0 4)))
		      ;; ((:jmp x) ...(no labels).... x ..)
		      ;; => (x ...)
		      ((let ((x (branch-instruction-label i t nil)))
			 (and (position x (cdr pc))
			      (not (find-if #'symbolp (cdr pc) :end (position x (cdr pc))))))
		       (explain nil "jmp x .. x: ~W"
				(subseq pc 0 (1+ (position (branch-instruction-label i t nil)
							   pc))))
		       (setq p nil
			     next-pc (member (branch-instruction-label i t nil) pc)))
		      ;; (:jcc 'x) .... x (:jmp 'y) ..
		      ;; => (:jcc 'y) .... x (:jmp 'y) ..
		      ((let* ((from (branch-instruction-label i t))
			      (dest (member (branch-instruction-label i t)
					    unoptimized-code))
			      (to (branch-instruction-label (if (instruction-is (second dest) :frame-map)
								(third dest)
							      (second dest))
							    t nil)))
			 (when (and from to (not (eq from to)))
			   (setq p (list `(,(car i) ',to)))
			   (explain nil "branch redirect from ~S to ~S" from to)
			   t)))
		      ;; remove back-to-back std/cld
		      ((and (instruction-is i :cld)
			    (instruction-is i2 :std))
		       (explain nil "removing back-to-back cld, std.")
		       (setq p nil next-pc (cddr pc)))
		      ;; remove branch no-ops.
		      ((and (branch-instruction-label i t)
			    (label-here-p (branch-instruction-label i t)
					  (cdr pc)))
		       (explain nil "branch no-op: ~A" i)
		       (setq p nil))
		      ((and (symbolp i)
			    (null (symbol-package i))
			    (null (find-branches-to-label unoptimized-code i))
			    (not (member i keep-labels)))
		       (setq p nil
			     next-pc (if (instruction-is i2 :frame-map)
					 (cddr pc)
				       (cdr pc)))
		       (explain nil "unused label: ~S" i))
		      ;; ((:jcc 'label) (:jmp 'y) label) => ((:jncc 'y) label)
		      ((and (branch-instruction-label i)
			    (branch-instruction-label i2 t nil)
			    (symbolp i3)
			    (eq (branch-instruction-label i) i3))
		       (setq p (list `(,(negate-branch (first i))
				       ',(branch-instruction-label i2 t nil)))
			     next-pc (nthcdr 2 pc))
		       (explain nil "collapsed double negative branch to ~S: ~A." i3 p))
		      ((and (branch-instruction-label i)
			    (instruction-is i2 :frame-map)
			    (branch-instruction-label i3 t nil)
			    (symbolp i4)
			    (eq (branch-instruction-label i) i4))
		       (setq p (list `(,(negate-branch (first i))
				       ',(branch-instruction-label i3 t nil)))
			     next-pc (nthcdr 3 pc))
		       (explain nil "collapsed double negative branch to ~S: ~A." i4 p))
		      ((and (twop-p i :movl)
			    (register-operand (twop-src i))
			    (register-operand (twop-dst i))
			    (twop-p i2 :movl)
			    (eq (twop-dst i) (twop-dst i2))
			    (register-indirect-operand (twop-src i2) (twop-dst i)))
		       (setq p (list `(:movl (,(twop-src i)
					      ,(register-indirect-operand (twop-src i2)
									  (twop-dst i)))
					     ,(twop-dst i2)))
			     next-pc (nthcdr 2 pc))
		       (explain nil "(movl edx eax) (movl (eax <z>) eax) => (movl (edx <z>) eax: ~S"
				p))
		      ((and (twop-p i :movl)
			    (instruction-is i2 :pushl)
			    (eq (twop-dst i) (second i2))
			    (twop-p i3 :movl)
			    (eq (twop-dst i) (twop-dst i3)))
		       (setq p (list `(:pushl ,(twop-src i)))
			     next-pc (nthcdr 2 pc))
		       (explain nil "(movl <z> :eax) (pushl :eax) => (pushl <z>): ~S" p))
		      ((and (instruction-uncontinues-p i)
			    (not (or (symbolp i2)
				     #+ignore (member (instruction-is i2) '(:foobar)))))
		       (do ((x (cdr pc) (cdr x)))
			   (nil)
			 (cond
			  ((not (or (symbolp (car x))
				    #+ignore (member (instruction-is (car x)) '(:foobar))))
			   (explain nil "Removing unreachable code ~A after ~A." (car x) i))
			  (t (setf p (list i)
				   next-pc x)
			     (return)))))
		      ((and (store-stack-frame-p i)
			    (load-stack-frame-p i2)
			    (load-stack-frame-p i3)
			    (= (store-stack-frame-p i)
			       (load-stack-frame-p i3))
			    (not (eq (twop-dst i2) (twop-dst i3))))
		       (setq p (list i `(:movl ,(twop-src i) ,(twop-dst i3)) i2)
			     next-pc (nthcdr 3 pc))
		       (explain nil "store, z, load => store, move, z: ~A" p))
		      ((and (instruction-is i :movl)
			    (member (twop-dst i) '(:eax :ebx :ecx :edx))
			    (instruction-is i2 :pushl)
			    (not (member (second i2) '(:eax :ebx :ecx :edx)))
			    (equal (twop-src i) (second i2)))
		       (setq p (list i `(:pushl ,(twop-dst i)))
			     next-pc (nthcdr 2 pc))
		       (explain t "load, push => load, push reg."))
		      ((and (instruction-is i :movl)
			    (member (twop-src i) '(:eax :ebx :ecx :edx))
			    (instruction-is i2 :pushl)
			    (not (member (second i2) '(:eax :ebx :ecx :edx)))
			    (equal (twop-dst i) (second i2)))
		       (setq p (list i `(:pushl ,(twop-src i)))
			     next-pc (nthcdr 2 pc))
		       (explain nil "store, push => store, push reg: ~S ~S" i i2))
;;;		      ((and (instruction-is i :cmpl)
;;;			    (true-and-equal (stack-frame-operand (twop-dst i))
;;;					    (load-stack-frame-p i3))
;;;			    (branch-instruction-label i2))
;;;		       (setf p (list i3
;;;				     `(:cmpl ,(twop-src i) ,(twop-dst i3))
;;;				     i2)
;;;			     next-pc (nthcdr 3 pc))
;;;		       (explain t "~S ~S ~S => ~S" i i2 i3 p))
		      ((and (instruction-is i :pushl)
			    (instruction-is i3 :popl)
			    (store-stack-frame-p i2)
			    (store-stack-frame-p i4)
			    (eq (idst i3) (twop-src i4)))
		       (setf p (list i2
				     `(:movl ,(idst i) ,(twop-dst i4))
				     `(:movl ,(idst i) ,(idst i3)))
			     next-pc (nthcdr 4 pc))
		       (explain nil "~S => ~S" (subseq pc 0 4) p))
		      #+ignore
		      ((let ((i6 (nth 6 pc)))
			 (and (global-funcall-p i2 '(fast-car))
			      (global-funcall-p i6 '(fast-cdr))
			      (load-stack-frame-p i)
			      (eq :eax (twop-dst i))
			      (equal i i4))))
		      ((and (equal i '(:movl :ebx :eax))
			    (global-funcall-p i2 '(fast-car fast-cdr)))
		       (let ((newf (ecase (global-funcall-p i2 '(fast-car fast-cdr))
				     (fast-car 'fast-car-ebx)
				     (fast-cdr 'fast-cdr-ebx))))
			 (setq p `((:call (:edi ,(global-constant-offset newf))))
			       next-pc (nthcdr 2 pc))
			 (explain nil "Changed [~S ~S] to ~S" i i2 newf)))
		      #+ignore
		      ((and (global-funcall-p i '(fast-cdr))
			    (global-funcall-p i2 '(fast-cdr))
			    (global-funcall-p i3 '(fast-cdr)))
		       (setq p `((:call (:edi ,(global-constant-offset 'fast-cdddr))))
			     next-pc (nthcdr 3 pc))
		       (explain nil "Changed (cdr (cdr (cdr :eax))) to (cdddr :eax)."))
		      ((and (global-funcall-p i '(fast-cdr))
			    (global-funcall-p i2 '(fast-cdr)))
		       (setq p `((:call (:edi ,(global-constant-offset 'fast-cddr))))
			     next-pc (nthcdr 2 pc))
		       (explain nil "Changed (cdr (cdr :eax)) to (cddr :eax)."))
		      ((and (load-stack-frame-p i) (eq :eax (twop-dst i))
			    (global-funcall-p i2 '(fast-car fast-cdr))
			    (preserves-stack-location-p i3 (load-stack-frame-p i))
			    (preserves-register-p i3 :ebx)
			    (eql (load-stack-frame-p i)
				 (load-stack-frame-p i4)))
		       (let ((newf (ecase (global-funcall-p i2 '(fast-car fast-cdr))
				     (fast-car 'fast-car-ebx)
				     (fast-cdr 'fast-cdr-ebx))))
			 (setq p `((:movl ,(twop-src i) :ebx)
				   (:call (:edi ,(global-constant-offset newf)))
				   ,i3
				   ,@(unless (eq :ebx (twop-dst i4))
				       `((:movl :ebx ,(twop-dst i4)))))
			       next-pc (nthcdr 4 pc))
			 (explain nil "load around ~A: ~{~&~A~}~%=>~% ~{~&~A~}"
				  newf (subseq pc 0 5) p))))
		  do (unless (eq p original-p) ; auto-detect whether any heuristic fired..
		       #+ignore (warn "at ~A, ~A inserted ~A" i i2 p)
		       #+ignore (warn "modified at ~S ~S ~S" i i2 i3)
		       (setf code-modified-p t))
		  nconc p)))
	(if code-modified-p
	    (apply #'optimize-code-internal optimized-code (1+ recursive-count) key-args)
            (optimize-trim-stack-frame (remove-frame-maps unoptimized-code)))))))
;;;; Compiler internals  

(defclass binding ()
  ((name
    :initarg :name
    :accessor binding-name)
   (env
    :accessor binding-env)
   (declarations
    :initarg :declarations
    :accessor binding-declarations)
   (extent-env
    :accessor binding-extent-env
    :initform nil)))

(defmethod (setf binding-env) :after (env (binding binding))
  (unless (binding-extent-env binding)
    (setf (binding-extent-env binding) env)))

(defmethod print-object ((object binding) stream)
  (print-unreadable-object (object stream :type t :identity t)
    (when (slot-boundp object 'name)
      (format stream "name: ~S~@[->~S~]~@[ %~A~]"
	      (and (slot-boundp object 'name)
		   (binding-name object))
	      (when (and (binding-target object)
			 (not (eq object (binding-target object))))
		(binding-name (forwarding-binding-target object)))
	      (when (and (slot-exists-p object 'store-type)
			 (slot-boundp object 'store-type)
			 (binding-store-type object))
		(or (apply #'encoded-type-decode
			   (binding-store-type object))
		    'empty))))))

(defclass constant-object-binding (binding)
  ((object
    :initarg :object
    :reader constant-object)))

(defmethod binding-lended-p ((binding constant-object-binding)) nil)
(defmethod binding-store-type ((binding constant-object-binding))
  (multiple-value-list (type-specifier-encode `(eql ,(constant-object binding)))))


(defclass operator-binding (binding) ())

(defclass macro-binding (operator-binding)
  ((expander
    :initarg :expander
    :accessor macro-binding-expander)))

(defclass symbol-macro-binding (binding)
  ((expander
    :initarg :expander
    :accessor macro-binding-expander)))

(defclass variable-binding (binding)
  ((lending				; a property-list
    :initform nil
    :accessor binding-lending)
   (store-type				; union of all types ever stored here
    :initform nil
    ;; :initarg :store-type
    :accessor binding-store-type)))

(defmethod binding-lended-p ((binding variable-binding))
  (and (getf (binding-lending binding) :lended-to)
       (not (eq :unused (getf (binding-lending binding) :lended-to)))))

(defclass lexical-binding (variable-binding) ())
(defclass located-binding (lexical-binding) ())

(defclass function-binding (operator-binding located-binding)
  ((funobj
    :initarg :funobj
    :accessor function-binding-funobj)
   (parent-funobj
    :initarg :parent-funobj
    :reader function-binding-parent)))

(defclass funobj-binding (function-binding) ())
(defclass closure-binding (function-binding located-binding) ())
(defclass lambda-binding (function-binding) ())

(defclass temporary-name (located-binding)
  ())

(defclass borrowed-binding (located-binding)
  ((reference-slot
    :initarg :reference-slot
    :accessor borrowed-binding-reference-slot)
   (target-binding
    :initarg :target-binding
    :reader borrowed-binding-target)
   (usage
    :initarg :usage
    :initform nil
    :accessor borrowed-binding-usage)))

(defclass lexical-borrowed-binding (borrowed-binding)
  ((stack-frame-distance
    :initarg :stack-frame-distance
    :reader stack-frame-distance))
  (:documentation "A closure with lexical extent borrows bindings using this class."))

(defclass indefinite-borrowed-binding (borrowed-binding)
  ((reference-slot
    :initarg :reference-slot
    :reader borrowed-binding-reference-slot)))

#+ignore
(defclass constant-reference-binding (lexical-binding)
  ((object
    :initarg :object
    :reader constant-reference-object)))

#+ignore
(defmethod print-object ((object constant-reference-binding) stream)
  (print-unreadable-object (object stream :type t :identity t)
    (format stream "object: ~S" (constant-reference-object object)))
  object)

(defclass forwarding-binding (lexical-binding)
  ((target-binding
    :initarg :target-binding
    :accessor forwarding-binding-target)))

(defmethod binding-funobj ((binding binding))
  (movitz-environment-funobj (binding-env binding)))

(defmethod binding-funobj ((binding forwarding-binding))
  (movitz-environment-funobj (binding-env (forwarding-binding-target binding))))

(defclass function-argument (located-binding) ())
(defclass edx-function-argument (function-argument) ())

(defclass positional-function-argument (function-argument)
  ((argnum
    :initarg :argnum
    :reader function-argument-argnum)))

(defclass required-function-argument (positional-function-argument) ())

(defclass register-required-function-argument (required-function-argument) ())
(defclass fixed-required-function-argument (required-function-argument)
  ((numargs
    :initarg :numargs
    :reader binding-numargs)))
(defclass floating-required-function-argument (required-function-argument) ())

(defclass non-required-function-argument (function-argument)
  ((init-form
    :initarg init-form
    :reader optional-function-argument-init-form)
   (supplied-p-var
    :initarg supplied-p-var
    :reader optional-function-argument-supplied-p-var)))

(defclass optional-function-argument (non-required-function-argument positional-function-argument) ())

(defclass supplied-p-function-argument (function-argument) ())

(defclass rest-function-argument (positional-function-argument) ())

(defclass keyword-function-argument (non-required-function-argument)
  ((keyword-name
    :initarg :keyword-name
    :reader keyword-function-argument-keyword-name)))

(defclass dynamic-binding (variable-binding) ())

(defclass shadowing-binding (binding) ())

(defclass shadowing-dynamic-binding (dynamic-binding shadowing-binding)
  ((shadowed-variable
    :initarg :shadowed-variable
    :reader shadowed-variable)
   (shadowing-variable
    :initarg :shadowing-variable
    :reader shadowing-variable)))

(defmethod binding-store-type ((binding dynamic-binding))
  (multiple-value-list (type-specifier-encode t)))

(defun stack-frame-offset (stack-frame-position)
  (* -4 (1+ stack-frame-position)))

(defun argument-stack-offset (binding)
  (check-type binding fixed-required-function-argument)
  (argument-stack-offset-shortcut (binding-numargs binding)
				  (function-argument-argnum binding)))

(defun argument-stack-offset-shortcut (numargs argnum)
  "For a function of <numargs> arguments, locate the ebp-relative position
of argument <argnum>."
  (* 4 (- numargs -1 argnum)))

;;;

;;; New style of locating bindings. The point is to not side-effect the binding objects.

(defun new-binding-location (binding map &key (default nil default-p))
  (check-type binding (or binding (cons keyword binding)))
  (let ((x (assoc binding map)))
    (cond
     (x (cdr x))
     (default-p default)
     (t (error "No location for ~S." binding)))))

(defun make-binding-map () nil)

(defun new-binding-located-p (binding map)
  (check-type binding (or null binding (cons keyword binding)))
  (and (assoc binding map) t))

(defun frame-map-size (map)
  (reduce #'max map
	  :initial-value 0
	  :key (lambda (x)
		 (if (integerp (cdr x))
		     (cdr x)
		   0))))

(defun frame-map-next-free-location (frame-map env &optional (size 1))
  (labels ((stack-location (binding)
	     (if (typep binding 'forwarding-binding)
		 (stack-location (forwarding-binding-target binding))
	       (new-binding-location binding frame-map :default nil)))
	   (env-extant (env1 env2)
	     "Is env1 active whenever env2 is active?"
	     (cond
	      ((null env2)
	       nil)
	      ((eq env1 env2)
	       ;; (warn "~S shadowed by ~S" env env2)
	       t)
	      (t (env-extant env1 (movitz-environment-extent-uplink env2))))))
    (let ((frame-size (frame-map-size frame-map)))
      (or (loop for location from 1 to frame-size
	      when
		(loop for sub-location from location below (+ location size)
		    never
		      (find-if (lambda (b-loc)
				 (destructuring-bind (binding . binding-location)
				     b-loc
				   (or (and (eq binding nil) ; nil means "back off!"
					    (eql sub-location binding-location))
				       (and (not (bindingp binding))
					    (eql sub-location binding-location))
				       (and (bindingp binding)
					    (eql sub-location (stack-location binding))
					    (labels
						((z (b)
						   (when b
						     ;; Use binding-extent-env for lifetime comparison,
						     ;; not binding-env (which may differ after fix-extent)
						     (or (env-extant (binding-extent-env b) env)
							 (env-extant env (binding-extent-env b))
							 (when (typep b 'forwarding-binding)
							   (z (forwarding-binding-target b)))))))
					      (z binding))))))
			       frame-map))
	      return location)
	  (1+ frame-size)))))		; no free location found, so grow frame-size.

(define-setf-expander new-binding-location (binding map-place &environment env)
  (multiple-value-bind (temps values stores setter getter)
      (get-setf-expansion map-place env)
    (let ((new-value (gensym))
	  (binding-var (gensym)))
      (values (append temps (list binding-var))
	      (append values (list binding))
	      (list new-value)
	      `(let ((,(car stores) (progn
				      (assert (or (null binding)
						  (not (new-binding-located-p ,binding-var ,getter))))
				      (check-type ,new-value (or keyword
								 binding
								 (integer 0 *)
								 (cons (eql :argument-stack) *)))
				      (acons ,binding-var ,new-value ,getter))))
		 ,setter
		 ,new-value)
	      `(new-binding-location ,binding-var ,getter)))))

;;; Objects with dynamic extent may be located on the stack-frame, which at
;;; compile-time is represented with this structure.

;;;(defclass stack-allocated-object ()
;;;  ((size
;;;    ;; Size in words (4 octets) this object occupies in the stack-frame.
;;;    :initarg :size
;;;    :accessor size)
;;;   (location
;;;    ;; Stack-frame offset (in words) this object is allocated to.
;;;    :accessor location)))
  

;;;


(defun ignore-instruction-prefixes (instruction)
  (if (and (consp instruction)
	   (listp (car instruction)))
      (cdr instruction)
    instruction))

(defun instruction-sub-program (instruction)
  "When an instruction contains a sub-program, return that program, and 
the sub-program options (&optional label) as secondary value."
  (let ((instruction (ignore-instruction-prefixes instruction)))
    (and (consp instruction)
	 (consp (second instruction))
	 (symbolp (car (second instruction)))
	 (string= 'quote (car (second instruction)))
	 (let ((x (second (second instruction))))
	   (and (consp x)
		(eq :sub-program (car x))
		(values (cddr x)
			(second x)))))))

(defun instruction-is (instruction &optional operator)
  (and (listp instruction)
       (if (member (car instruction) '(:globally :locally))
	   (instruction-is (second instruction) operator)
	 (let ((instruction (ignore-instruction-prefixes instruction)))
	   (if operator
	       (eq operator (car instruction))
	     (car instruction))))))

(defun instruction-uncontinues-p (instruction)
  "Is it impossible for control to return after instruction?"
  (or (member (instruction-is instruction)
	      '(:jmp :ret))
      (member instruction
	      '((:int 100))
	      :test #'equalp)))
  
#+ignore (defun sub-environment-p (env1 env2)
	   (cond
	    ((eq env1 env2) t)
	    ((null env1) nil)
	    (t (sub-environment-p (movitz-environment-uplink env1) env2))))

(defun find-code-constants-and-jumpers (code &key include-programs)
  "Return code's constants (a plist of constants and their usage-counts) and jumper-sets."
  (let (jumper-sets constants key-args-set)
    (labels ((process-binding (binding)
	       "Some bindings are really references to constants."
	       (typecase binding
		 (constant-object-binding
		  (let ((object (movitz-read (constant-object binding))))
		    (when (typep object 'movitz-heap-object)
		      (incf (getf constants object 0)))))
		 (forwarding-binding
		  (process-binding (forwarding-binding-target binding)))
		 (funobj-binding
		  (let ((funobj (function-binding-funobj binding)))
		    (incf (getf constants funobj 0))))
		 (closure-binding)
		 (function-binding
		  (error "No function-binding now..: ~S" binding))))
	     (process (sub-code)
	       "This local function side-effects the variables jumper-sets and constants."
	       (loop for instruction in sub-code
		   do (case (instruction-is instruction)
			((:local-function-init :load-lambda)
			 (let* ((binding (second instruction))
				(funobj (function-binding-funobj binding)))
			   (unless (eq :unused (movitz-funobj-extent funobj))
			     (incf (getf constants funobj 0))
			     (dolist (binding (borrowed-bindings funobj))
			       (process-binding binding)))))
			((:load-lexical :lend-lexical :call-lexical)
			 (process-binding (second instruction)))
			(:load-constant
			 (let ((object (movitz-read (second instruction))))
			   (when (typep object 'movitz-heap-object)
			     (incf (getf constants object 0)))))
			(:declare-label-set
			 (destructuring-bind (name set)
			     (cdr instruction)
			   (assert (not (getf jumper-sets name)) ()
			     "Duplicate jumper declaration for ~S." name)
			   (setf (getf jumper-sets name) set)))
			(:declare-key-arg-set
			 (setf key-args-set (cdr instruction)))
			(t (when (listp instruction)
			     (dolist (binding (find-read-bindings instruction))
			       (process-binding binding)))))
		   do (let ((sub (instruction-sub-program instruction)))
			(when sub (process sub))))))
      (process code)
      (map nil #'process include-programs))
    (loop for key-arg in key-args-set
	do (remf constants key-arg))
    (values constants jumper-sets key-args-set)))

(defun layout-funobj-vector (constants key-args-constants jumper-sets borrowing-bindings)
  (let* ((jumpers (loop with x
		      for set in (cdr jumper-sets) by #'cddr
		      unless (search set x)
		      do (setf x (nconc x (copy-list set)))
		      finally (return x)))
	 (num-jumpers (length jumpers))
	 (stuff (append (mapcar (lambda (c)
				  (cons c 1))
				key-args-constants)
			(when key-args-constants
			  (list (cons (movitz-read 0)
				      1)))
			(sort (loop for (constant count) on constants by #'cddr
				  unless (or (eq constant *movitz-nil*)
					     (eq constant (image-t-symbol *image*)))
				  collect (cons constant count))
			      #'< :key #'cdr))))
    (values (append jumpers
		    (mapcar (lambda (x)
			      (movitz-read (car x)))
			    stuff)
		    (make-list (length borrowing-bindings)
			       :initial-element *movitz-nil*))
	    num-jumpers
	    (loop for (name set) on jumper-sets by #'cddr
		collect (cons name set))
	    (loop for borrowing-binding in borrowing-bindings
		as pos upfrom (+ num-jumpers (length stuff))
		collect (cons borrowing-binding pos)))))

(defun movitz-funobj-intern-constant (funobj obj)
  ;; (error "XXXXX")
  (let ((cobj (movitz-read obj)))
    (+ (slot-offset 'movitz-funobj 'constant0)
       (* (sizeof 'word)
	  (let* ((pos (position cobj (movitz-funobj-const-list funobj)
				:start (movitz-funobj-num-jumpers funobj))))
	    (assert pos ()
	      "Couldn't find constant ~S in ~S's set of constants ~S."
	      obj funobj (movitz-funobj-const-list funobj))
	    pos)))))

(defun compute-free-registers (pc distance funobj frame-map
			       &key (free-registers '(:ecx :eax :ebx :edx)))
  "Return set of free register, and whether there may be more registers
   free later, with a more specified frame-map."
  (loop with free-so-far = free-registers
      repeat distance for i in pc
      while (not (null free-so-far))
      doing
	(cond
	 ((and (instruction-is i :init-lexvar)
	       (typep (second i) 'required-function-argument)) ; XXX
	  (destructuring-bind (binding &key init-with-register init-with-type
					    protect-registers protect-carry)
	      (cdr i)
	    (declare (ignore protect-carry init-with-type))
	    (when init-with-register
	      (setf free-so-far (remove-if (lambda (x)
					     (if (new-binding-located-p binding frame-map)
						 (eq x (new-binding-location binding frame-map))
					       (or (eq x init-with-register)
						   (member x protect-registers))))
					   free-so-far)))))
	 (t (case (instruction-is i)
	      ((nil)
	       (return nil))		; a label, most likely
	      ((:declare-key-arg-set :declare-label-set)
	       nil)
	      ((:lexical-control-transfer :load-lambda)
	       (return nil))		; not sure about these.
	      ((:call)
	       (setf free-so-far
		 (remove-if (lambda (r)
			      (not (eq r :push)))
			    free-so-far)))
	      ((:arg-cmp)
	       (setf free-so-far
		 (remove :ecx free-so-far)))
	      ((:cld :std)
	       (setf free-so-far
		 (set-difference free-so-far '(:eax :edx))))
	      ((:into :clc :stc :int))
	      ((:jmp :jnz :je :jne :jz :jge :jae :jnc :jbe)
	       (setf free-so-far
		 (remove :push free-so-far)))
	      ((:pushl :popl)
	       (setf free-so-far
		 (remove-if (lambda (r)
			      (or (eq r :push)
				  (tree-search i r)))
			    free-so-far)))
	      ((:outb :inb)
	       (setf free-so-far
		 (set-difference free-so-far '(:eax :edx))))
	      ((:movb :testb :andb :cmpb)
	       (setf free-so-far
		 (remove-if (lambda (r)
			      (and (not (eq r :push))
				   (or (tree-search i r)
				       (tree-search i (register32-to-low8 r)))))
			    free-so-far)))
	      ((:sarl :shrl :shll :xorl :cmpl :leal :btl :sbbl :cdq
		:movl :movzxw :movzxb :testl :andl :addl :subl :imull :idivl)
	       (setf free-so-far
		 (remove-if (lambda (r)
			      (tree-search i r))
			    free-so-far)))
	      ((:load-constant :load-lexical :store-lexical :cons-get :endp :incf-lexvar :init-lexvar)
	       (assert (gethash (instruction-is i) *extended-code-expanders*))
	       (cond
		((and (instruction-is i :init-lexvar) ; special case..
		      (typep (second i) 'forwarding-binding)))
		(t (unless (can-expand-extended-p i frame-map)
		     ;; (warn "can't expand ~A from ~A" i frame-map)
		     (return (values nil t)))
		   (let ((exp (expand-extended-code i funobj frame-map)))
		     (when (tree-search exp '(:call :local-function-init))
		       (setf free-so-far
			 (remove-if (lambda (r)
				      (not (eq r :push)))
				    free-so-far)))
		     (setf free-so-far
		       (remove-if (lambda (r)
				    (and (not (eq r :push))
					 (or (tree-search exp r)
					     (tree-search exp (register32-to-low8 r)))))
				  free-so-far))))))
	      ((:local-function-init)
	       (destructuring-bind (binding)
		   (cdr i)
		 (unless (typep binding 'funobj-binding)
		   (return nil))))
	      (t #+ignore (warn "Dist ~D stopped by ~A"
				distance i)
		 (return nil)))))
      ;; do (warn "after ~A: ~A" i free-so-far)
      finally (return free-so-far)))

(defun try-locate-in-register (binding var-counts funobj frame-map)
  "Try to locate binding in a register. Return a register, or
   nil and :not-now, or :never.
   This function is factored out from assign-bindings."
  (assert (not (typep binding 'forwarding-binding)))
  (let* ((count-init-pc (gethash binding var-counts))
	 (count (car count-init-pc))
	 (init-pc (second count-init-pc)))
    #+ignore (warn "b ~S: count: ~D, init-pc: ~{~&~A~}" binding count init-pc)
    (cond
     ((and (not *compiler-allow-transients*)
	   (typep binding 'function-argument))
      (values nil :never))
     ((binding-lended-p binding)
      ;; We can't lend a register.
      (values nil :never))
     ((and (= 1 count)
	   init-pc)
      (assert (instruction-is (first init-pc) :init-lexvar))
      (destructuring-bind (init-binding &key init-with-register init-with-type
					protect-registers protect-carry shared-reference-p)
	  (cdr (first init-pc))
	(declare (ignore protect-registers protect-carry init-with-type shared-reference-p))
	(assert (eq binding init-binding))
	(multiple-value-bind (load-instruction binding-destination distance)
	    (loop for i in (cdr init-pc) as distance upfrom 0
		do (when (not (instruction-is i :init-lexvar))
		     (multiple-value-bind (read-bindings read-destinations)
			 (find-read-bindings i)
		       (let ((pos (position binding read-bindings :test #'binding-eql)))
			 (when pos
			   (return (values i (nth pos read-destinations) distance)))))))
	  (declare (ignore load-instruction))
	  (multiple-value-bind (free-registers more-later-p)
	      (and distance (compute-free-registers (cdr init-pc) distance funobj frame-map))
	    #+ignore
	    (when (string= 'num-jumpers (binding-name binding))
	      (warn "load: ~S, dist: ~S, dest: ~S" load-instruction distance binding-destination)
	      (warn "free: ~S, more: ~S" free-registers more-later-p))
	    (let ((free-registers-no-ecx (remove :ecx free-registers)))
	      (cond
	       ((member binding-destination free-registers-no-ecx)
		binding-destination)
	       ((and (not (typep binding '(or fixed-required-function-argument
					   register-required-function-argument)))
		     (member binding-destination free-registers))
		binding-destination)
	       ((member init-with-register free-registers)
		init-with-register)
	       ((and (member :ecx free-registers)
		     (not (typep binding 'function-argument))
		     (or (eq :untagged-fixnum-ecx binding-destination)
			 (eq :untagged-fixnum-ecx init-with-register)))
		:untagged-fixnum-ecx)
	       ((and (binding-store-type binding)
		     (member :ecx free-registers)
		     (not (typep binding '(or fixed-required-function-argument
					   register-required-function-argument)))
		     (multiple-value-call #'encoded-subtypep
		       (values-list (binding-store-type binding))
		       (type-specifier-encode '(or integer character))))
		:ecx)
	       ((not (null free-registers-no-ecx))
		(first free-registers-no-ecx))
	       (more-later-p
		(values nil :not-now))
	       ((and distance (typep binding 'temporary-name))
		;; We might push/pop this variable
		(multiple-value-bind (push-available-p maybe-later)
		    (compute-free-registers (cdr init-pc) distance funobj frame-map
					    :free-registers '(:push))
		  ;; (warn "pushing.. ~S ~A ~A" binding push-available-p maybe-later)
		  (cond
		   (push-available-p
		    (values :push))
		   (maybe-later
		    (values nil :not-now))
		   (t (values nil :never)))))
	       (t (values nil :never))))))))
     (t (values nil :never)))))

(defun discover-variables (code function-env)
  "Iterate over CODE, and take note in the hash-table VAR-COUNTER which ~
   variables CODE references that are lexically bound in ENV."
  (check-type function-env function-env)
  ;; (print-code 'discover code)
  (let ((var-counter (make-hash-table :test #'eq :size 40)))
    (labels ((record-binding-used (binding)
	       (let ((count-init-pc (or (gethash binding var-counter)
					(setf (gethash binding var-counter)
					  (list 0 nil t)))))
		 (setf (third count-init-pc) t)
		 (when (typep binding 'forwarding-binding)
		   (record-binding-used (forwarding-binding-target binding)))))
	     (take-note-of-binding (binding &optional storep init-pc)
	       (let ((count-init-pc (or (gethash binding var-counter)
					(setf (gethash binding var-counter)
					  (list 0 nil (not storep))))))
		 (when init-pc
		   (assert (not (second count-init-pc)))
		   (setf (second count-init-pc) init-pc))
		 (unless storep
		   (unless (eq binding (binding-target binding))
		     ;; (break "ewfew: ~S" (gethash (binding-target binding) var-counter))
		     (take-note-of-binding (binding-target binding)))
		   (setf (third count-init-pc) t)
		   (incf (car count-init-pc))))
	       #+ignore
	       (when (typep binding 'forwarding-binding)
		 (take-note-of-binding (forwarding-binding-target binding) storep)))
	     (take-note-of-init (binding init-pc)
	       (let ((count-init-pc (or (gethash binding var-counter)
					(setf (gethash binding var-counter)
					  (list 0 nil nil)))))
		 (assert (not (second count-init-pc)))
		 (setf (second count-init-pc) init-pc)))
	     (do-discover-variables (code env)
	       (loop for pc on code as instruction in code
		   when (listp instruction)
		   do (flet ((lend-lexical (borrowing-binding dynamic-extent-p)
			       (let ((lended-binding
				      (borrowed-binding-target borrowing-binding)))
				 (assert (not (typep lended-binding 'forwarding-binding)) ()
				   "Can't lend a forwarding-binding.")
				 (pushnew lended-binding
					  (potentially-lended-bindings function-env))
				 (take-note-of-binding lended-binding)
				 (symbol-macrolet ((p (binding-lending lended-binding)))
				   (incf (getf p :lended-count 0))
				   (setf (getf p :dynamic-extent-p) (and (getf p :dynamic-extent-p t)
									 dynamic-extent-p))))))
			(case (instruction-is instruction)
			  ((:local-function-init :load-lambda)
			   (let ((function-binding (second instruction)))
			     (take-note-of-binding function-binding)
			     (let ((sub-funobj (function-binding-funobj function-binding)))
			       #+ignore
			       (warn "fun-ext: ~S ~S ~S"
				     sub-funobj
				     (movitz-funobj-extent sub-funobj)
				     (movitz-allocation sub-funobj))
			       (when (typep (movitz-allocation sub-funobj)
					    'with-dynamic-extent-scope-env)
				 (take-note-of-binding (base-binding (movitz-allocation sub-funobj)))))
			     (let ((closure-funobj (function-binding-funobj function-binding)))
			       (dolist (borrowing-binding (borrowed-bindings closure-funobj))
				 (lend-lexical borrowing-binding nil)))))
			  (:call-lexical
			   (destructuring-bind (binding num-args)
			       (cdr instruction)
			     (declare (ignore num-args))
			     (etypecase binding
			       (function-binding
				(take-note-of-binding binding))
			       (funobj-binding))))
			  (:init-lexvar
			   (destructuring-bind (binding &key init-with-register init-with-type
							     protect-registers protect-carry
							     shared-reference-p)
			       (cdr instruction)
			     (declare (ignore protect-registers protect-carry init-with-type
					      shared-reference-p))
			     (cond
			      ((not init-with-register)
			       (take-note-of-init binding pc))
			      (init-with-register
			       (take-note-of-binding binding t pc)
			       (when (and (typep init-with-register 'binding)
					  (not (typep binding 'forwarding-binding))
					  (not (typep binding 'keyword-function-argument))) ; XXX
				 (take-note-of-binding init-with-register))))))
			  (t (mapcar #'take-note-of-binding 
				     (find-read-bindings instruction))
			     (mapcar #'record-binding-used ; This is just concerning "unused variable"
				     (find-used-bindings instruction)) ; warnings!
			     (let ((store-binding (find-written-binding-and-type instruction)))
			       (when store-binding
				 (take-note-of-binding store-binding t)))
			     (do-discover-variables (instruction-sub-program instruction) env)))))))
      (do-discover-variables code function-env))
    (values var-counter)))

(defun assign-bindings (code function-env &optional (initial-stack-frame-position 1)
						    (frame-map (make-binding-map)))
  "Assign locations to all lexical variables in CODE. Recurses into any
   sub-environments found in CODE. A frame-map which is an assoc from
   bindings to stack-frame locations."
  ;; Then assign them to locations in the stack-frame.
  #+ignore (warn "assigning code:~%~{~&    ~A~}" code)
  (check-type function-env function-env)
  (assert (= initial-stack-frame-position
	     (1+ (frame-map-size frame-map))))
  (let* ((env-assigned-p nil)		; memoize result of assign-env-bindings
	 (flat-program code)
	 (var-counts (discover-variables flat-program function-env)))
    (labels
	((assign-env-bindings (env)
	   (unless (member env env-assigned-p)
	     (unless (eq env function-env)
	       (assign-env-bindings (movitz-environment-extent-uplink env)))
	     (let* ((bindings-to-locate
		     (loop for binding being the hash-keys of var-counts
			 when
			   (and (eq env (binding-extent-env binding))
				(not (let ((variable (binding-name binding)))
				       (cond
					((not (typep binding 'lexical-binding)))
					((typep binding 'lambda-binding))
					((typep binding 'constant-object-binding))
					((typep binding 'forwarding-binding)
					 (when (plusp (or (car (gethash binding var-counts)) 0))
					   (assert (new-binding-located-p binding frame-map)))
					 t)
					((typep binding 'borrowed-binding))
					((typep binding 'funobj-binding))
					((and (typep binding 'fixed-required-function-argument)
					      (plusp (or (car (gethash binding var-counts)) 0)))
					 (prog1 nil ; may need lending-cons
					   (setf (new-binding-location binding frame-map)
					     `(:argument-stack ,(function-argument-argnum binding)))))
					((unless (or (movitz-env-get variable 'ignore nil
								     (binding-env binding) nil)
						     (movitz-env-get variable 'ignorable nil
								     (binding-env binding) nil)
						     (third (gethash binding var-counts)))
					   (warn "Unused variable: ~S"
						 (binding-name binding))))
					((not (plusp (or (car (gethash binding var-counts)) 0))))))))
			 collect binding))
		    (bindings-fun-arg-sorted
		     (when (eq env function-env)
		       (sort (copy-list bindings-to-locate) #'<
			     :key (lambda (binding)
				    (etypecase binding
				      (edx-function-argument 3)
				      (positional-function-argument
				       (* 2 (function-argument-argnum binding)))
				      (binding 100000))))))
		    (bindings-register-goodness-sort
		     (sort (copy-list bindings-to-locate) #'<
			   ;; Sort so as to make the most likely
			   ;; candidates for locating to registers
			   ;; be assigned first (i.e. maps to
			   ;; a smaller value).
			   :key (lambda (b)
				  (etypecase b
				    ((or constant-object-binding
				      forwarding-binding
				      borrowed-binding)
				     1000)
				    (fixed-required-function-argument
				     (+ 100 (function-argument-argnum b)))
				    (located-binding
				     (let* ((count-init (gethash b var-counts))
					    (count (car count-init))
					    (init-pc (second count-init)))
				       (if (not (and count init-pc))
					   50
					 (truncate
					  (or (position-if (lambda (i)
							     (member b (find-read-bindings i)))
							   (cdr init-pc))
					      15)
					  count)))))))))
	       ;; First, make several passes while trying to locate bindings
	       ;; into registers.
	       (loop repeat 100 with try-again = t and did-assign = t
		   do (unless (and try-again did-assign)
			(return))
		   do (setf try-again nil did-assign nil)
		      (loop for binding in bindings-fun-arg-sorted
			  while (or (typep binding 'register-required-function-argument)
				    (typep binding 'floating-required-function-argument)
				    (and (typep binding 'positional-function-argument)
					 (< (function-argument-argnum binding)
					    2)))
			  do (unless (new-binding-located-p binding frame-map)
			       (multiple-value-bind (register status)
				   (try-locate-in-register binding var-counts
							   (movitz-environment-funobj function-env)
							   frame-map)
				 (cond
				  (register
				   (setf (new-binding-location binding frame-map)
				     register)
				   (setf did-assign t))
				  ((eq status :not-now)
				   ;; (warn "Wait for ~S map ~A" binding frame-map)
				   (setf try-again t))
				  (t (assert (eq status :never)))))))
		      (dolist (binding bindings-register-goodness-sort)
			(unless (and (binding-lended-p binding)
				     (not (typep binding 'borrowed-binding))
				     (not (getf (binding-lending binding) :stack-cons-location)))
			  (unless (new-binding-located-p binding frame-map)
			    (check-type binding located-binding)
			    (multiple-value-bind (register status)
				(try-locate-in-register binding var-counts
							(movitz-environment-funobj function-env)
							frame-map)
			      (cond
			       (register
				(setf (new-binding-location binding frame-map)
				  register)
				(setf did-assign t))
			       ((eq status :not-now)
				(setf try-again t))
			       (t (assert (eq status :never))))))))
		   do (when (and try-again (not did-assign))
			(let ((binding (or (find-if (lambda (b)
						      (and (typep b 'positional-function-argument)
							   (= 0 (function-argument-argnum b))
							   (not (new-binding-located-p b frame-map))))
						    bindings-fun-arg-sorted)
					   (find-if (lambda (b)
						      (and (typep b 'positional-function-argument)
							   (= 1 (function-argument-argnum b))
							   (not (new-binding-located-p b frame-map))))
						    bindings-fun-arg-sorted)
					   (find-if (lambda (b)
						      (and (not (new-binding-located-p b frame-map))
							   (not (typep b 'function-argument))))
						    bindings-register-goodness-sort
						    :from-end t))))
			  (when binding
			    (setf (new-binding-location binding frame-map)
			      (frame-map-next-free-location frame-map (binding-extent-env binding)))
			    (setf did-assign t))))
		   finally (break "100 iterations didn't work"))
	       ;; Then, make one pass assigning bindings to stack-frame.
	       (loop for binding in bindings-fun-arg-sorted
		   while (or (typep binding 'register-required-function-argument)
			     (typep binding 'floating-required-function-argument)
			     (and (typep binding 'positional-function-argument)
				  (< (function-argument-argnum binding)
				     2)))
		   do (unless (new-binding-located-p binding frame-map)
			(setf (new-binding-location binding frame-map)
			  (frame-map-next-free-location frame-map (binding-extent-env binding)))))
	       (dolist (binding bindings-register-goodness-sort)
		 (when (and (binding-lended-p binding)
			    (not (typep binding 'borrowed-binding))
			    (not (getf (binding-lending binding) :stack-cons-location)))
		   #+ignore
		   (assert (not (typep binding 'keyword-function-argument)) ()
		     "Can't lend keyword binding ~S." binding)
		   ;; (warn "assigning lending-cons for ~W at ~D" binding stack-frame-position)
		   (let ((cons-pos (frame-map-next-free-location frame-map function-env 2)))
		     (setf (new-binding-location (cons :lended-cons binding) frame-map)
		       cons-pos)
		     (setf (new-binding-location (cons :lended-cons binding) frame-map)
		       (1+ cons-pos))
		     (setf (getf (binding-lending binding) :stack-cons-location)
		       cons-pos)))
		 (unless (new-binding-located-p binding frame-map)
		   (etypecase binding
		     (constant-object-binding) ; no location needed.
		     (forwarding-binding) ; will use the location of target binding.
		     (borrowed-binding)	; location is predetermined
		     (fixed-required-function-argument
		      (setf (new-binding-location binding frame-map)
			`(:argument-stack ,(function-argument-argnum binding))))
		     (located-binding
		      (setf (new-binding-location binding frame-map)
			(frame-map-next-free-location frame-map (binding-extent-env binding)))))))
	       (push env env-assigned-p)))))
      ;; First, "assign" each forwarding binding to their target.
      (loop for binding being the hash-keys of var-counts
	  do (when (and (typep binding 'forwarding-binding)
			(plusp (car (gethash binding var-counts '(0)))))
	       (setf (new-binding-location binding frame-map)
		 (forwarding-binding-target binding))))	     
      ;; Keyword bindings
      (flet ((set-exclusive-location (binding location)
	       (assert (not (rassoc location frame-map))
		   () "Fixed location ~S for ~S is taken by ~S."
		   location binding (rassoc location frame-map))
	       (setf (new-binding-location binding frame-map) location)))
	(when (key-vars-p function-env)
	  (when (= 0 (rest-args-position function-env))
	    (set-exclusive-location (loop for var in (required-vars function-env)
					as binding = (movitz-binding var function-env nil)
					thereis (when (= 0 (function-argument-argnum binding))
						  binding))
				    1))
	  (when (>= 1 (rest-args-position function-env))
	    (set-exclusive-location (loop for var in (required-vars function-env)
					as binding = (movitz-binding var function-env nil)
					thereis (when (= 1 (function-argument-argnum binding))
						  binding))
				    2)))
	(loop for key-var in (key-vars function-env)
	    as key-binding = (or (movitz-binding key-var function-env nil)
				 (error "No binding for key-var ~S." key-var))
	    as used-key-binding =
	      (when (plusp (car (gethash key-binding var-counts '(0))))
		key-binding)
	    as used-supplied-p-binding =
	      (when (optional-function-argument-supplied-p-var key-binding)
		(let ((b (or (movitz-binding (optional-function-argument-supplied-p-var key-binding)
					     function-env nil)
			     (error "No binding for supplied-p-var ~S."
				    (optional-function-argument-supplied-p-var key-binding)))))
		  (when (plusp (car (gethash key-binding var-counts '(0))))
		    b)))
	    as location upfrom 3 by 2
	    do (set-exclusive-location used-key-binding location)
	       (set-exclusive-location used-supplied-p-binding (1+ location))))
      ;; Now, use assing-env-bindings on the remaining bindings.
      (loop for env in
	    (loop with z = nil
		for b being the hash-keys of var-counts using (hash-value c)
		as env = (binding-env b)
		when (sub-env-p env function-env)
		do (incf (getf z env 0) (car c))
		finally
		  (return (sort (loop for x in z by #'cddr
				    collect x)
				#'>
				:key (lambda (env)
				       (getf z env)))))
	  do (assign-env-bindings env))
      #+ignore (warn "Frame-map ~D:~{~&~A~}"
		     (frame-map-size frame-map)
		     (stable-sort (sort (loop for (b . l) in frame-map
					    collect (list b l (car (gethash b var-counts nil))))
					#'string<
					:key (lambda (x)
					       (and (bindingp (car x))
						    (binding-name (car x)))))
				  #'<
				  :key (lambda (x)
					 (if (integerp (cadr x))
					     (cadr x)
					   1000))))
      frame-map)))


(defun operators-present-in-code-p (code operators operands &key (operand-test #'eql)
								 (test #'identity))
  "A simple tree search for `(<one of operators> ,operand) in CODE."
  ;; (break "Deprecated operators-present-in-code-p")
  (cond
   ((atom code)
    nil)
   ((and (member (first code) operators)
	 (or (null operands)
	     (if (atom operands)
		 (funcall operand-test (second code) operands)
	       (member (second code) operands :test operand-test)))
	 (funcall test code)
	 code))
   (t (or (operators-present-in-code-p (car code) operators operands
				       :operand-test operand-test
				       :test test)
	  (operators-present-in-code-p (cdr code) operators operands
				       :operand-test operand-test
				       :test test)))))


(defun code-uses-binding-p (code binding &key (load t) store call)
  "Does extended <code> potentially read/write/call <binding>?"
  (labels ((search-funobj (funobj binding load store call path)
	     ;; If this is a recursive lexical call (i.e. labels),
	     ;; the function-envs might not be bound, but then this
	     ;; code is searched already.
	     (if (member funobj path)
		 nil
		 (when (slot-boundp funobj 'function-envs)
		   (some (lambda (function-env-spec)
			   (or (not (slot-boundp (cdr function-env-spec) 'extended-code)) ; Don't know yet, assume yes.
			       (code-search (extended-code (cdr function-env-spec)) binding
					    load store call
					    (cons funobj path))))
			 (function-envs funobj))))
	     #+ignore
	     (if (member funobj path)
		 nil
		 (let* ((memo (assoc funobj memos))
			(x (cdr (or memo
				    (car (push (cons funobj
						     (when (slot-boundp funobj 'function-envs)
						       (some (lambda (function-env-spec)
							       (or (not (slot-boundp (cdr function-env-spec) 'extended-code)) ; Don't know yet, assume yes.
								   (code-search (extended-code (cdr function-env-spec))
										binding
										load store call
										(cons funobj path))))
							     (function-envs funobj))))
					       memos))))))
		   (warn "search ~S ~S: ~S" funobj binding x)
		   x)))
	   (code-search (code binding load store call path)
	     (dolist (instruction code)
	       (when (consp instruction)
		 (let ((x (or (when load
				(some (lambda (read-binding)
					(binding-eql read-binding binding))
				      (find-read-bindings instruction)))
			      (when store
				(let ((store-binding (find-written-binding-and-type instruction)))
				  (when store-binding
				    (binding-eql binding store-binding))))
			      (case (car instruction)
				(:local-function-init
				 (search-funobj (function-binding-funobj (second instruction))
						binding
						load store call
						path))
				(:load-lambda
				 (or (when load
				       (binding-eql binding (second instruction)))
				     (let ((allocation (movitz-allocation
							(function-binding-funobj (second instruction)))))
				       (when (and load
						  (typep allocation 'with-dynamic-extent-scope-env))
					 (binding-eql binding (base-binding allocation))))
				     (search-funobj (function-binding-funobj (second instruction))
						    binding
						    load store call
						    path)))
				(:call-lexical
				 (or (when call
				       (binding-eql binding (second instruction)))
				     (search-funobj (function-binding-funobj (second instruction))
						    binding
						    load store call
						    path))))
			      (code-search (instruction-sub-program instruction)
					   binding
					   load store call
					   path))))
		   (when x (return t)))))))
    (code-search code binding load store call nil)))

(defun bindingp (x)
  (typep x 'binding))

(defun binding-target (binding)
  "Resolve a binding in terms of forwarding."
  (etypecase binding
    (forwarding-binding
     (binding-target (forwarding-binding-target binding)))
    (binding
     binding)))

(defun binding-eql (x y)
  (check-type x binding)
  (check-type y binding)
  (or (eql x y)
      (and (typep x 'forwarding-binding)
	   (binding-eql (forwarding-binding-target x) y))
      (and (typep y 'forwarding-binding)
	   (binding-eql x (forwarding-binding-target y)))))

(defun tree-search (tree items)
  (if (and (atom items)			; make common case fast(er), hopefully.
	   (not (numberp items)))
      (labels ((tree-search* (tree item)
		 (etypecase tree
		   (null nil)
		   (cons
		    (or (tree-search* (car tree) item)
			(tree-search* (cdr tree) item)))
		   (t (eq tree item)))))
	(tree-search* tree items))
    (etypecase tree
      (atom
       (if (atom items)
	   (eql tree items)
	 (member tree items)))
      (cons
       (or (tree-search (car tree) items)
	   (tree-search (cdr tree) items))))))

(defun operator (x)
  (if (atom x) x (car x)))

(defun result-mode-type (x)
  (etypecase x
    (symbol x)
    (cons (car x))
    (constant-object-binding :constant-binding)
    (lexical-binding :lexical-binding)
    (dynamic-binding :dynamic-binding)))

(defun operands (x)
  (if (symbolp x) nil (cdr x)))

(defun funobj-assign-bindings (code env &optional (stack-frame-position 1)
						  (frame-map (make-binding-map)))
  "This wrapper around assign-bindings checks if the first instructions of CODE
are load-lexicals of the first two function arguments, and if possible these
bindings are located in the appropriate register, so no stack location is needed."
  (check-type env function-env)
  (assign-bindings (append (when (first (required-vars env))
			     (let ((binding (movitz-binding (first (required-vars env))
							    env nil)))
			       (check-type binding required-function-argument)
			       `((:init-lexvar ,binding :init-with-register :eax :init-with-type t))))
			   (when (second (required-vars env))
			     (let ((binding (movitz-binding (second (required-vars env))
							    env nil)))
			       (check-type binding required-function-argument)
			       `((:init-lexvar ,binding :init-with-register :ebx :init-with-type t))))
			   code)
		   env stack-frame-position frame-map))

(defun single-value-register (mode)
  (ecase mode
    ((:eax :single-value :multiple-values :function) :eax)
    ((:ebx :ecx :edx :esi :esp :ebp) mode)))

(defun result-mode-register (mode)
  (case mode
    ((:eax :single-value) :eax)
    ((:ebx :ecx :edx :esi :esp) mode)
    (t mode)))

(defun accept-register-mode (mode &optional (default-mode :eax))
  (case mode
    ((:eax :ebx :ecx :edx)
     mode)
    (t default-mode)))

(defun chose-free-register (unfree-registers &optional (preferred-register :eax))
  (cond
   ((not (member preferred-register unfree-registers))
    preferred-register)
   ((find-if (lambda (r) (not (member r unfree-registers)))
	     '(:eax :ebx :ecx :edx)))
   (t (error "Unable to find a free register."))))

(defun make-indirect-reference (base-register offset)
  "Make the shortest possible assembly indirect reference, explointing the constant edi register."
  (if (<= #x-80 offset #x7f)
      (list base-register offset)
    (let ((edi (image-nil-word *image*)))
      (cond
       ((<= #x-80 (- offset edi) #x7f)
	`(,base-register :edi ,(- offset edi)))
       ((<= #x-80 (- offset (* 2 edi)) #x7f)
	`(,base-register (:edi 2) ,(- offset (* 2 edi))))
       ((<= #x-80 (- offset (* 4 edi)) #x7f)
	`(,base-register (:edi 4) ,(- offset (* 4 edi))))
       ((<= #x-80 (- offset (* 8 edi)) #x7f)
	`(,base-register (:edi 8) ,(- offset (* 8 edi))))
       (t (list base-register offset))))))

(defun make-load-lexical (binding result-mode funobj shared-reference-p frame-map
			  &key tmp-register protect-registers override-binding-type)
  "When tmp-register is provided, use that for intermediate storage required when
loading borrowed bindings."
  #+ignore
  (when (eq :ecx result-mode)
    ;; (warn  "loading to ecx: ~S" binding)
    (unless (or (null (binding-store-type binding))
		(movitz-subtypep (apply #'encoded-type-decode
					(binding-store-type binding)) 
				 'integer))
      (warn "ecx from ~S" binding)))
  (when (movitz-env-get (binding-name binding) 'ignore nil (binding-env binding))
    (warn "The variable ~S is used even if it was declared ignored."
	  (binding-name binding)))
  (let ((binding (ensure-local-binding binding funobj))
	(protect-registers (cons :edx protect-registers)))
    (labels ((chose-tmp-register (&optional preferred)
	       (or tmp-register
		   (unless (member preferred protect-registers)
		     preferred)
		   (first (set-difference '(:eax :ebx :edx)
					  protect-registers))
		   (error "Unable to chose a temporary register.")))
	     (install-for-single-value (lexb lexb-location result-mode indirect-p
					&optional binding-type)
	       (let ((decoded-type (when binding-type
				     (apply #'encoded-type-decode binding-type))))
		 (cond
		  ((and (eq result-mode :untagged-fixnum-ecx)
			(integerp lexb-location))
		   (cond
		    ((and binding-type
			  (type-specifier-singleton decoded-type))
		     #+ignore (warn "Immloadlex: ~S"
				    (type-specifier-singleton decoded-type))
		     (make-immediate-move (movitz-fixnum-value
					   (car (type-specifier-singleton decoded-type)))
					  :ecx))
		    ((and binding-type
			  (movitz-subtypep decoded-type '(and fixnum (unsigned-byte 32))))
		     (assert (not indirect-p))
		     (append (install-for-single-value lexb lexb-location :ecx nil)
			     `((:shrl ,+movitz-fixnum-shift+ :ecx))))
		    #+ignore ((warn "utecx ~S binary-types: ~S" lexb decoded-type))
		    (t
		     (assert (not indirect-p))
		     (assert (not (member :eax protect-registers)))
		     (append (install-for-single-value lexb lexb-location :eax nil)
			     `((,*compiler-global-segment-prefix*
				:call (:edi ,(global-constant-offset 'unbox-u32))))))))
		  ((integerp lexb-location)
		   (append `((:movl ,(make-indirect-reference :ebp (stack-frame-offset lexb-location))
				    ,(single-value-register result-mode)))
			   (when indirect-p
			     `((:movl (-1 ,(single-value-register result-mode))
				      ,(single-value-register result-mode))))))
		  ((eq lexb-location result-mode)
		   ())
		  (t (when (and (eq result-mode :untagged-fixnum-ecx)
				binding-type
				(type-specifier-singleton decoded-type))
		       (break "xxx Immloadlex: ~S ~S"
			     (operator lexb-location)
			     (type-specifier-singleton decoded-type)))
		     (ecase (operator lexb-location)
		       (:push
			(assert (member result-mode '(:eax :ebx :ecx :edx)))
			(assert (not indirect-p))
			`((:popl ,result-mode)))
		       (:eax
			(assert (not indirect-p))
			(ecase result-mode
			  ((:ebx :ecx :edx :esi) `((:movl :eax ,result-mode)))
			  ((:eax :single-value) nil)
			  (:untagged-fixnum-ecx
			   `((,*compiler-global-segment-prefix*
			      :call (:edi ,(global-constant-offset 'unbox-u32)))))))
		       ((:ebx :ecx :edx)
			(assert (not indirect-p))
			(unless (eq result-mode lexb-location)
			  (ecase result-mode
			    ((:eax :single-value) `((:movl ,lexb-location :eax)))
			    ((:ebx :ecx :edx :esi) `((:movl ,lexb-location ,result-mode)))
			    (:untagged-fixnum-ecx
			     `((:movl ,lexb-location :ecx)
			       (:sarl ,movitz:+movitz-fixnum-shift+ :ecx))))))
		       (:argument-stack
			(assert (<= 2 (function-argument-argnum lexb)) ()
			  "lexical :argument-stack argnum can't be ~A." (function-argument-argnum lexb))
			(cond
			 ((eq result-mode :untagged-fixnum-ecx)
			  (assert (not indirect-p))
			  `((:movl (:ebp ,(argument-stack-offset lexb)) :ecx)
			    (:sarl ,+movitz-fixnum-shift+ :ecx)))
			 (t (append `((:movl (:ebp ,(argument-stack-offset lexb))
					     ,(single-value-register result-mode)))
				    (when indirect-p
				      `((:movl (-1 ,(single-value-register result-mode))
					       ,(single-value-register result-mode))))))))
		       (:untagged-fixnum-ecx
			(ecase result-mode
			  ((:eax :ebx :ecx :edx)
			   `((:leal ((:ecx ,+movitz-fixnum-factor+)) ,result-mode)))
			  (:untagged-fixnum-ecx
			   nil)))))))))
      (etypecase binding
	(forwarding-binding
	 (assert (not (binding-lended-p binding)) (binding)
	   "Can't lend a forwarding-binding ~S." binding)
	 (make-load-lexical (forwarding-binding-target binding)
			    result-mode funobj shared-reference-p frame-map
			    :override-binding-type (binding-store-type binding)))
	(constant-object-binding
	 (assert (not (binding-lended-p binding)) (binding)
	   "Can't lend a constant-reference-binding ~S." binding)
	 (make-load-constant (constant-object binding)
			     result-mode
			     funobj frame-map))
	(funobj-binding
	 (make-load-constant (function-binding-funobj binding)
			     result-mode funobj frame-map))
	(borrowed-binding
	 (let ((slot (borrowed-binding-reference-slot binding)))
	   (cond
	    (shared-reference-p
	     (ecase (result-mode-type result-mode)
	       ((:eax :ebx :ecx :edx)
		`((:movl (:esi ,(+ (slot-offset 'movitz-funobj 'constant0) (* 4 slot)))
			 ,(result-mode-type result-mode))))))
	    ((not shared-reference-p)
	     (case result-mode
	       ((:single-value :eax :ebx :ecx :edx :esi)
		(let ((tmp-register (chose-tmp-register (single-value-register result-mode))))
		  `((:movl (:esi ,(+ (slot-offset 'movitz-funobj 'constant0) (* 4 slot)))
			   ,tmp-register)
		    (:movl (,tmp-register -1)
			   ,(single-value-register result-mode)))))
	       (:push
		(let ((tmp-register (chose-tmp-register :eax)))
		  `((:movl (:esi ,(+ (slot-offset 'movitz-funobj 'constant0) (* 4 slot)))
			   ,tmp-register)
		    (:pushl (,tmp-register -1)))))
	       (t (let ((tmp-register (chose-tmp-register :eax)))
		    (make-result-and-returns-glue
		     result-mode tmp-register
		     `((:movl (:esi ,(+ (slot-offset 'movitz-funobj 'constant0) (* 4 slot)))
			      ,tmp-register)
		       (:movl (,tmp-register -1) ,tmp-register))))))))))
	(located-binding
	 (let ((binding-type (or override-binding-type
				 (binding-store-type binding)))
	       (binding-location (new-binding-location binding frame-map)))
	   #+ignore (warn "~S type: ~S ~:[~;lended~]"
			  binding
			  binding-type 
			  (binding-lended-p binding))
	   (cond
	    ((and (binding-lended-p binding)
		  (not shared-reference-p))
	     (case (result-mode-type result-mode)
	       ((:single-value :eax :ebx :ecx :edx :esi :esp)
		(install-for-single-value binding binding-location
					  (single-value-register result-mode) t))
	       (:push
		(if (integerp binding-location)
		    `((:movl (:ebp ,(stack-frame-offset binding-location)) :eax)
		      (:pushl (:eax -1)))
		  (ecase (operator binding-location)
		    (:argument-stack
		     (assert (<= 2 (function-argument-argnum binding)) ()
		       ":load-lexical argnum can't be ~A." (function-argument-argnum binding))
		     `((:movl (:ebp ,(argument-stack-offset binding)) :eax)
		       (:pushl (:eax -1)))))))
	       (t (make-result-and-returns-glue
		   result-mode :eax
		   (install-for-single-value binding binding-location :eax t)))))
	    (t (when (integerp result-mode)
		 (break "result-mode: ~S" result-mode))
	     (case (result-mode-type result-mode)
		 ((:single-value :eax :ebx :ecx :edx :esi :esp :ebp)
		  (install-for-single-value binding binding-location
					    (single-value-register result-mode) nil))
		 (:push
		  (if (integerp binding-location)
		      `((:pushl (:ebp ,(stack-frame-offset binding-location))))
		    (ecase (operator binding-location)
		      ((:eax :ebx :ecx :edx)
		       `((:pushl ,binding-location)))
		      (:untagged-fixnum-ecx
		       `((,*compiler-local-segment-prefix*
			  :call (:edi ,(global-constant-offset 'box-u32-ecx)))
			 (:pushl :eax)))
		      (:argument-stack
		       (assert (<= 2 (function-argument-argnum binding)) ()
			 ":load-lexical argnum can't be ~A." (function-argument-argnum binding))
		       `((:pushl (:ebp ,(argument-stack-offset binding))))))))
		 (:boolean-branch-on-true
		  (if (integerp binding-location)
		      `((:cmpl :edi (:ebp ,(stack-frame-offset binding-location)))
			(:jne ',(operands result-mode)))
		    (ecase (operator binding-location)
		      ((:eax :ebx :edx)
		       `((:cmpl :edi ,binding-location)
			 (:jne ',(operands result-mode))))
		      (:argument-stack
		       `((:cmpl :edi (:ebp ,(argument-stack-offset binding)))
			 (:jne ',(operands result-mode)))))))
		 (:boolean-branch-on-false
		  (if (integerp binding-location)
		      `((:cmpl :edi (:ebp ,(stack-frame-offset binding-location)))
			(:je ',(operands result-mode)))
		    (ecase (operator binding-location)
		      ((:eax :ebx :edx)
		       `((:cmpl :edi ,binding-location)
			 (:je ',(operands result-mode))))
		      (:argument-stack
		       `((:cmpl :edi (:ebp ,(argument-stack-offset binding)))
			 (:je ',(operands result-mode)))))))
		 (:untagged-fixnum-ecx
		  (install-for-single-value binding binding-location :untagged-fixnum-ecx nil
					    binding-type))
		 (:lexical-binding
		  (let* ((destination result-mode)
			 (dest-location (new-binding-location destination frame-map :default nil)))
		    (cond
		     ((not dest-location) ; unknown, e.g. a borrowed-binding.
		      (append (install-for-single-value binding binding-location :edx nil)
			      (make-store-lexical result-mode :edx nil funobj frame-map)))
		     ((equal binding-location dest-location)
		      nil)
		     ((member binding-location '(:eax :ebx :ecx :edx))
		      (make-store-lexical destination binding-location nil funobj frame-map))
		     ((member dest-location '(:eax :ebx :ecx :edx))
		      (install-for-single-value binding binding-location dest-location nil))
		     (t #+ignore (warn "binding => binding: ~A => ~A~% => ~A ~A"
				       binding-location
				       dest-location
				       binding
				       destination)
			(append (install-for-single-value binding binding-location :eax nil)
				(make-store-lexical result-mode :eax nil funobj frame-map))))))
		 (t (make-result-and-returns-glue
		     result-mode :eax
		     (install-for-single-value binding binding-location :eax nil)))
		 )))))))))


(defun make-store-lexical (binding source shared-reference-p funobj frame-map
			   &key protect-registers)
  (let ((binding (ensure-local-binding binding funobj)))
    (assert (not (and shared-reference-p
		      (not (binding-lended-p binding))))
	    (binding)
	    "funny binding: ~W" binding)
    (if (and nil (typep source 'constant-object-binding))
	(make-load-constant (constant-object source) binding funobj frame-map)
	(let ((protect-registers (list* source protect-registers)))
	  (unless (or (eq source :untagged-fixnum-ecx)
		      (and (binding-store-type binding)
			   (multiple-value-call #'encoded-subtypep
			     (values-list (binding-store-type binding))
			     (type-specifier-encode '(or integer character)))))
	    (push :ecx protect-registers))
	  (cond
	    ((eq :untagged-fixnum-ecx source)
	     (if (eq :untagged-fixnum-ecx
		     (new-binding-location binding frame-map))
		 nil
		 (append (make-result-and-returns-glue :ecx :untagged-fixnum-ecx)
			 (make-store-lexical binding :ecx shared-reference-p funobj frame-map
					     :protect-registers protect-registers))))
	    ((typep binding 'borrowed-binding)
	     (let ((slot (borrowed-binding-reference-slot binding)))
	       (if (not shared-reference-p)
		   (let ((tmp-reg (chose-free-register protect-registers)
			   #+ignore(if (eq source :eax) :ebx :eax)))
		     (when (eq :ecx source)
		       (break "loading a word from ECX?"))
		     `((:movl (:esi ,(+ (slot-offset 'movitz-funobj 'constant0) (* 4 slot)))
			      ,tmp-reg)
		       (:movl ,source (-1 ,tmp-reg))))
		   `((:movl ,source (:esi ,(+ (slot-offset 'movitz-funobj 'constant0) (* 4 slot))))))))
	    ((typep binding 'forwarding-binding)
	     (assert (not (binding-lended-p binding)) (binding))
	     (make-store-lexical (forwarding-binding-target binding)
				 source shared-reference-p funobj frame-map))
	    ((not (new-binding-located-p binding frame-map))
	     ;; (warn "Can't store to unlocated binding ~S." binding)
	     nil)
	    ((and (binding-lended-p binding)
		  (not shared-reference-p))
	     (let ((tmp-reg (chose-free-register protect-registers)
		     #+ignore (if (eq source :eax) :ebx :eax))
		   (location (new-binding-location binding frame-map)))
	       (if (integerp location)
		   `((:movl (:ebp ,(stack-frame-offset location)) ,tmp-reg)
		     (:movl ,source (,tmp-reg -1)))
		   (ecase (operator location)
		     (:argument-stack
		      (assert (<= 2 (function-argument-argnum binding)) ()
			      "store-lexical argnum can't be ~A." (function-argument-argnum binding))
		      `((:movl (:ebp ,(argument-stack-offset binding)) ,tmp-reg)
			(:movl ,source (,tmp-reg -1))))))))
	    (t (let ((location (new-binding-location binding frame-map)))
		 (cond
		   ((member source '(:eax :ebx :ecx :edx :edi :esp))
		    (if (integerp location)
			`((:movl ,source (:ebp ,(stack-frame-offset location))))
			(ecase (operator location)
			  ((:push)
			   `((:pushl ,source)))
			  ((:eax :ebx :ecx :edx)
			   (unless (eq source location)
			     `((:movl ,source ,location))))
			  (:argument-stack
			   (assert (<= 2 (function-argument-argnum binding)) ()
				   "store-lexical argnum can't be ~A." (function-argument-argnum binding))
			   `((:movl ,source (:ebp ,(argument-stack-offset binding)))))
			  (:untagged-fixnum-ecx
			   (assert (not (eq source :edi)))
			   (cond
			     ((eq source :untagged-fixnum-ecx)
			      nil)
			     ((eq source :eax)
			      `((,*compiler-global-segment-prefix*
				 :call (:edi ,(global-constant-offset 'unbox-u32)))))
			     (t `((:movl ,source :eax)
				  (,*compiler-global-segment-prefix*
				   :call (:edi ,(global-constant-offset 'unbox-u32))))))))))
		   ((eq source :boolean-cf=1)
		    (let ((tmp (chose-free-register protect-registers)))
		      `((:sbbl :ecx :ecx)
			(,*compiler-local-segment-prefix*
			 :movl (:edi (:ecx 4) ,(global-constant-offset 'not-not-nil)) ,tmp)
			,@(make-store-lexical binding tmp shared-reference-p funobj frame-map
					      :protect-registers protect-registers))))
		   ((eq source :boolean-cf=0)
		    (let ((tmp (chose-free-register protect-registers)))
		      `((:sbbl :ecx :ecx)
			(,*compiler-local-segment-prefix*
			 :movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-zero)) ,tmp)
			,@(make-store-lexical binding tmp shared-reference-p funobj frame-map
					      :protect-registers protect-registers))))
		   ((and *compiler-use-cmov-p*
			 (member source +boolean-modes+))
		    (let ((tmp (chose-free-register protect-registers)))
		      (append `((:movl :edi ,tmp))
			      (list (cons *compiler-local-segment-prefix*
					  (make-cmov-on-boolean source
								`(:edi ,(global-constant-offset 't-symbol))
								tmp)))
			      (make-store-lexical binding tmp shared-reference-p funobj frame-map
						  :protect-registers protect-registers))))
		   ((member source +boolean-modes+)
		    (let ((tmp (chose-free-register protect-registers))
			  (label (gensym "store-lexical-bool-")))
		      (append `((:movl :edi ,tmp))
			      (list (make-branch-on-boolean source label :invert t))
			      `((,*compiler-local-segment-prefix*
				 :movl (:edi ,(global-constant-offset 't-symbol)) ,tmp))
			      (list label)
			      (make-store-lexical binding tmp shared-reference-p funobj frame-map
						  :protect-registers protect-registers))))
		   ((not (bindingp source))
		    (error "Unknown source for store-lexical: ~S" source))
		   ((binding-singleton source)
		    (assert (not shared-reference-p))
		    (let ((value (car (binding-singleton source))))
		      (etypecase value
			(movitz-fixnum
			 (let ((immediate (movitz-immediate-value value)))
			   (if (integerp location)
			       (let ((tmp (chose-free-register protect-registers)))
				 (append (make-immediate-move immediate tmp)
					 `((:movl ,tmp (:ebp ,(stack-frame-offset location))))))
			       #+ignore (if (= 0 immediate)
					    (let ((tmp (chose-free-register protect-registers)))
					      `((:xorl ,tmp ,tmp)
						(:movl ,tmp (:ebp ,(stack-frame-offset location)))))
					    `((:movl ,immediate (:ebp ,(stack-frame-offset location)))))
			       (ecase (operator location)
				 ((:argument-stack)
				  `((:movl ,immediate (:ebp ,(argument-stack-offset binding)))))
				 ((:eax :ebx :ecx :edx)
				  (make-immediate-move immediate location))
				 ((:untagged-fixnum-ecx)
				  (make-immediate-move (movitz-fixnum-value value) :ecx))))))
			(movitz-character
			 (let ((immediate (movitz-immediate-value value)))
			   (if (integerp location)
			       (let ((tmp (chose-free-register protect-registers)))
				 (append (make-immediate-move immediate tmp)
					 `((:movl ,tmp (:ebp ,(stack-frame-offset location))))))
			       (ecase (operator location)
				 ((:argument-stack)
				  `((:movl ,immediate (:ebp ,(argument-stack-offset binding)))))
				 ((:eax :ebx :ecx :edx)
				  (make-immediate-move immediate location))))))
			(movitz-heap-object
			 (etypecase location
			   ((member :eax :ebx :edx)
			    (make-load-constant value location funobj frame-map))
			   (integer
			    (let ((tmp (chose-free-register protect-registers)))
			      (append (make-load-constant value tmp funobj frame-map)
				      (make-store-lexical binding tmp shared-reference-p
							  funobj frame-map
							  :protect-registers protect-registers))))
			   ((eql :untagged-fixnum-ecx)
			    (check-type value movitz-bignum)
			    (let ((immediate (movitz-bignum-value value)))
			      (check-type immediate (unsigned-byte 32))
			      (make-immediate-move immediate :ecx)))
			   )))))	       
		   (t (error "Generalized lexb source for store-lexical not implemented: ~S" source))))))))))

(defun finalize-code (code funobj frame-map)
  ;; (print-code 'to-be-finalized code)
  ;; (warn "frame-map: ~A" frame-map)
  (labels ((actual-binding (b)
	     (if (typep b 'borrowed-binding)
		 (borrowed-binding-target b)
	       b))
	   (make-lend-lexical (borrowing-binding funobj-register dynamic-extent-p)
	     (let ((lended-binding (ensure-local-binding
				    (borrowed-binding-target borrowing-binding))))
	       #+ignore (warn "LB: in ~S ~S from ~S"
			      funobj
			      lended-binding borrowing-binding)
	       (assert (eq funobj (binding-funobj lended-binding)))
	       (assert (plusp (getf (binding-lending (actual-binding lended-binding))
				    :lended-count 0)) ()
		 "Asked to lend ~S of ~S to ~S of ~S with no lended-count."
		 lended-binding (binding-env lended-binding)
		 borrowing-binding (binding-env borrowing-binding))
	       (assert (eq funobj-register :edx))
	       (when (getf (binding-lending lended-binding) :dynamic-extent-p)
		 (assert dynamic-extent-p))
	       #+ignore
	       (warn "lending: ~W: ~S"
		     lended-binding
		     (mapcar #'movitz-funobj-extent
			     (mapcar #'binding-funobj 
				     (getf (binding-lending lended-binding) :lended-to))))
	       (when (typep lended-binding 'funobj-binding)
		 (break "Lending ~S from ~S: ~S" lended-binding funobj (binding-lending lended-binding)))
	       (append (make-load-lexical lended-binding :eax funobj t frame-map)
		       (unless (or (typep lended-binding 'borrowed-binding)
				   (getf (binding-lending lended-binding) :dynamic-extent-p)
				   (every (lambda (borrower)
					    (member (movitz-funobj-extent (binding-funobj borrower))
						    '(:lexical-extent :dynamic-extent)))
					  (getf (binding-lending lended-binding) :lended-to)))
			 (append `((:pushl :edx)
				   (:globally (:call (:edi (:edi-offset ensure-heap-cons-variable))))
				   (:popl :edx))
				 (make-store-lexical lended-binding :eax t funobj frame-map)))
		       `((:movl :eax
				(,funobj-register
				 ,(+ (slot-offset 'movitz-funobj 'constant0)
				     (* 4 (borrowed-binding-reference-slot borrowing-binding)))))))))
	   (ensure-local-binding (binding)
	     (if (eq funobj (binding-funobj binding))
		 binding
	       (or (find binding (borrowed-bindings funobj)
			 :key #'borrowed-binding-target)
		   (error "Can't install non-local binding ~S for ~S." binding funobj)))))
    (labels ((fix-edi-offset (tree)
	       (cond
		((atom tree)
		 tree)
		((eq :edi-offset (car tree))
		 (check-type (cadr tree) symbol "a Movitz run-time-context label")
		 (+ (global-constant-offset (cadr tree))
		    (reduce #'+ (cddr tree))))
		(t (cons (fix-edi-offset (car tree))
			 (fix-edi-offset (cdr tree)))))))
      (loop for instruction in code
	  appending
	    (cond
	     ((atom instruction) 
	      (list instruction))
	     ((and (= 2 (length instruction))
		   (let ((operand (second instruction)))
		     (and (listp operand)
			  (symbolp (first operand))
			  (string= 'quote (first operand))
			  (listp (second operand)))))
	      ;;(break "op: ~S" (second (second instruction)))
	      ;; recurse into program-to-append..
	      (list (list (first instruction)
			  (list 'quote (finalize-code (second (second instruction))
						      funobj frame-map)))))
	   
	     (t ;; (warn "finalizing ~S" instruction)
	      (case (first instruction)
		((:locally :globally)
		 (destructuring-bind (sub-instr)
		     (cdr instruction)
		   (let ((pf (ecase (first instruction)
			       (:locally *compiler-local-segment-prefix*)
			       (:globally *compiler-global-segment-prefix*))))
		     (list (fix-edi-offset
			    (cond
			     ((atom sub-instr)
			      sub-instr)
			     ((consp (car sub-instr))
			      (list* (append pf (car sub-instr))
				     (cdr sub-instr)))
			     (t (list* pf sub-instr))))))))
		((:declare-label-set
		  :declare-key-arg-set)
		 nil)
		(:local-function-init
		 (destructuring-bind (function-binding)
		     (operands instruction)
		   #+ignore
		   (warn "local-function-init: init ~S at ~S"
			 function-binding
			 (new-binding-location function-binding frame-map))
		   (finalize-code 
		    (let* ((sub-funobj (function-binding-funobj function-binding)))
		      (cond
		       ((eq (movitz-funobj-extent sub-funobj) :unused)
			(unless (or (movitz-env-get (binding-name function-binding)
						    'ignore nil
						    (binding-env function-binding) nil)
				    (movitz-env-get (binding-name function-binding)
						    'ignorable nil
						    (binding-env function-binding) nil))
			  (warn "Unused local function: ~S"
				(binding-name function-binding)))
			nil)
		       ((typep function-binding 'funobj-binding)
			nil)
		       #+ignore
		       ((member (movitz-funobj-extent sub-funobj)
				'(:dynamic-extent :lexical-extent))
			(check-type function-binding closure-binding)
			(when (plusp (movitz-funobj-num-jumpers sub-funobj))
			  (break "Don't know yet how to stack a funobj with jumpers."))
			(let ((words (+ (movitz-funobj-num-constants sub-funobj)
					(/ (sizeof 'movitz-funobj) 4))))
			  (break "words for ~S: ~S" words sub-funobj)
			  (append `((:movl :esp :eax)
				    (:testl 4 :eax)
				    (:jz 'no-alignment-needed)
				    (:pushl :edi)
				    no-alignment-needed)
				  (make-load-constant sub-funobj :eax funobj frame-map)
				  )))
		       (t (assert (not (null (borrowed-bindings sub-funobj))) ()
				  "Binding ~S with ~S borrows no nothing, which makes no sense." function-binding sub-funobj)
			  (append (make-load-constant sub-funobj :eax funobj frame-map)
				  `((:movl (:edi ,(global-constant-offset 'copy-funobj)) :esi)
				    (:call (:esi ,(binary-types:slot-offset 'movitz-funobj 'code-vector%1op)))
				    (:movl :eax :edx))
				  (make-store-lexical function-binding :eax nil funobj frame-map)
				  (loop for bb in (borrowed-bindings sub-funobj)
				     append (make-lend-lexical bb :edx nil))))))
		    funobj frame-map)))
		(:load-lambda
		 (destructuring-bind (function-binding register capture-env)
		     (operands instruction)
		   (declare (ignore capture-env))
		   (finalize-code
		    (let* ((sub-funobj (function-binding-funobj function-binding))
			   (lend-code (loop for bb in (borrowed-bindings sub-funobj)
					 appending
					    (make-lend-lexical bb :edx nil))))
		      (cond
		       ((null lend-code)
			;; (warn "null lambda lending")
			(append (make-load-constant sub-funobj register funobj frame-map)))
		       ((typep (movitz-allocation sub-funobj)
			       'with-dynamic-extent-scope-env)
			(setf (headers-on-stack-frame-p funobj) t)
			(let ((dynamic-scope (movitz-allocation sub-funobj)))
			  (append (make-load-lexical (base-binding dynamic-scope) :edx
						     funobj nil frame-map)
				  `((:leal (:edx ,(tag :other)
						 ,(dynamic-extent-object-offset dynamic-scope
										sub-funobj))
					   :edx))
				  lend-code
				  `((:movl :edx ,register)))))
		       (t (append (make-load-constant sub-funobj :eax funobj frame-map)
				  `((:movl (:edi ,(global-constant-offset 'copy-funobj)) :esi)
				    (:call (:esi ,(binary-types:slot-offset 'movitz-funobj 'code-vector%1op)))
				    (:movl :eax :edx))
				  lend-code
				  `((:movl :edx ,register))))))
		    funobj frame-map)))
		(:load-constant
		 (destructuring-bind (object result-mode &key (op :movl))
		     (cdr instruction)
		   (make-load-constant object result-mode funobj frame-map :op op)))
		(:lexical-control-transfer
		 (destructuring-bind (return-code return-mode from-env to-env &optional to-label)
		     (cdr instruction)
		   (declare (ignore return-code))
		   (let ((x (apply #'make-compiled-lexical-control-transfer
				   nil
				   return-mode from-env to-env
				   (when to-label (list to-label)))))
		     (finalize-code x funobj frame-map))))
		(:call-lexical
		 (destructuring-bind (binding num-args)
		     (operands instruction)
		   (append (etypecase binding
			     (closure-binding
			      (make-load-lexical (ensure-local-binding binding)
						 :esi funobj nil frame-map
						 :tmp-register :edx))
			     (funobj-binding
			      (make-load-constant (function-binding-funobj binding)
						  :esi funobj frame-map)))
			   (make-compiled-funcall-by-esi num-args))))
		(t (expand-extended-code instruction funobj frame-map)))))))))


(defun image-t-symbol-p (x)
  (eq x (image-t-symbol *image*)))

(deftype movitz-t ()
  `(satisfies image-t-symbol-p))

(defun make-load-constant (object result-mode funobj frame-map &key (op :movl))
  (let ((movitz-obj (movitz-read object)))
    (case op
      (:movl
       (etypecase movitz-obj
	 (movitz-null
	  (ecase (result-mode-type result-mode)
	    (:lexical-binding
	     (make-store-lexical result-mode :edi nil funobj frame-map))
	    (:push
	     '((:pushl :edi)))
	    ((:eax :ebx :ecx :edx)
	     `((:movl :edi ,result-mode)))
	    (:boolean-branch-on-true
	     ;; (warn "branch-on-true for nil!")
	     nil)
	    (:boolean-branch-on-false
	     ;; (warn "branch-on-false for nil!")
	     `((:jmp ',(operands result-mode))))
	    ((:multiple-values :function)
	     '((:movl :edi :eax)
	       (:clc)))
	    #+ignore
	    (t (when (eq :boolean result-mode)
		 (warn "Compiling ~S for mode ~S." object result-mode))
	       (make-result-and-returns-glue result-mode :edi nil)
	       #+ignore '((:movl :edi :eax)))))
	 (movitz-t
	  (ecase (result-mode-type result-mode)
	    (:push
	     `((:pushl (:edi ,(global-constant-offset 't-symbol)))))
	    ((:eax :ebx :ecx :edx)
	     `((:movl (:edi ,(global-constant-offset 't-symbol)) ,result-mode)))
	    (:boolean-branch-on-false
	     ;; (warn "boolean-branch-on-false T")
	     nil)
	    (:boolean-branch-on-true
	     ;; (warn "boolean-branch-on-true T")
	     `((:jmp ',(operands result-mode))))
	    ((:multiple-values :function)
	     `((:movl (:edi ,(global-constant-offset 't-symbol))
		      :eax)
	       (:clc)))
	    (:lexical-binding
	     (append `((:movl (:edi ,(global-constant-offset 't-symbol))
			      :eax))
		     (make-store-lexical result-mode :eax nil funobj frame-map)))
	    #+ignore
	    (t (when (eq :boolean result-mode)
		 (warn "Compiling ~S for mode ~S." object result-mode))
	       (make-result-and-returns-glue result-mode :eax
					     `((:movl (:edi ,(global-constant-offset 't-symbol))
						      :eax))))))
	 (movitz-immediate-object
	  (let ((x (movitz-immediate-value movitz-obj)))
	    (ecase (result-mode-type result-mode)
	      (:lexical-binding
	       (append (make-immediate-move x :eax)
		       (make-store-lexical result-mode :eax nil funobj frame-map)))
	      (:untagged-fixnum-ecx
	       (let ((value (movitz-fixnum-value object)))
		 (check-type value (unsigned-byte 32))
		 (make-immediate-move value :ecx)))
	      (:push
	       `((:pushl ,x)))
	      ((:eax :ebx :ecx :edx)
	       (make-immediate-move x result-mode))
	      ((:multiple-values :function)
	       (append (make-immediate-move x :eax)
		       '((:clc)))))))
	 (movitz-heap-object
	  (ecase (result-mode-type result-mode)
	    (:untagged-fixnum-ecx
	     (let ((value (movitz-bignum-value object)))
	       (make-immediate-move (ldb (byte 32 0) value) :ecx)))
	    (:lexical-binding
	     (cond
	      ((and (typep movitz-obj 'movitz-bignum)
		    (eq :untagged-fixnum-ecx
			(new-binding-location result-mode frame-map :default nil)))
	       (unless (typep (movitz-bignum-value movitz-obj) '(unsigned-byte 32))
		 (warn "Loading non-u32 ~S into ~S."
		       (movitz-bignum-value movitz-obj)
		       result-mode))
	       (make-immediate-move (ldb (byte 32 0) (movitz-bignum-value movitz-obj))
				    :ecx))
	      (t (when (member (new-binding-location result-mode frame-map :default nil)
			       '(:ebx :ecx :edx :esi))
		   (warn "load to ~S at ~S from ~S"
			 result-mode (new-binding-location result-mode frame-map) movitz-obj))
		 (append `((:movl ,(new-make-compiled-constant-reference movitz-obj funobj)
				  :eax))
			 (make-store-lexical result-mode :eax nil funobj frame-map)))))
	    (:push
	     `((:pushl ,(new-make-compiled-constant-reference movitz-obj funobj))))
	    ((:eax :ebx :ecx :edx :esi)
	     `((,op ,(new-make-compiled-constant-reference movitz-obj funobj)
		    ,result-mode)))
	    ((:edi)
	     (assert (eq op :cmpl))
	     `((,op ,(new-make-compiled-constant-reference movitz-obj funobj)
		    ,result-mode)))
	    ((:function :multiple-values)
	     (assert (eq op :movl))
	     `((,op ,(new-make-compiled-constant-reference movitz-obj funobj)
		    :eax)
	       (:clc)))))))
      (t (ecase result-mode
	   ((:eax :ebx :ecx :edx :esi)
	    `((,op ,(new-make-compiled-constant-reference movitz-obj funobj)
		   ,result-mode)))
	   ((:edi)
	    (assert (eq op :cmpl))
	    `((,op ,(new-make-compiled-constant-reference movitz-obj funobj)
		   ,result-mode))))))))

(defparameter +movitz-lambda-list-keywords+
    '(muerte.cl:&OPTIONAL
      muerte.cl:&REST
      muerte.cl:&KEY
      muerte.cl:&AUX
      muerte.cl:&BODY
      muerte.cl:&WHOLE
      muerte.cl:&ALLOW-OTHER-KEYS
      muerte.cl:&ENVIRONMENT))

(defun add-bindings-from-lambda-list (lambda-list env)
  "From a (normal) <lambda-list>, add bindings to <env>."
  (let ((arg-pos 0))
    (multiple-value-bind (required-vars optional-vars rest-var key-vars auxes allow-p min-args max-args edx-var oddeven key-vars-p)
	(decode-normal-lambda-list lambda-list)
      (setf (min-args env) min-args
	    (max-args env) max-args
	    (oddeven-args env) oddeven
            (aux-vars env) auxes
	    (allow-other-keys-p env) allow-p)
      (flet ((shadow-when-special (formal env)
	       "Iff <formal> is special, return a fresh variable-name that takes <formal>'s place
as the lexical variable-name, and add a new shadowing dynamic binding for <formal> in <env>."
	       (if (not (movitz-env-get formal 'special nil env))
		   formal
		 (let* ((shadowed-formal (gensym (format nil "shady-~A-" formal)))
			(shadowing-binding (make-instance 'shadowing-dynamic-binding
					     :name shadowed-formal
					     :shadowing-variable formal
					     :shadowed-variable shadowed-formal)))
		   (movitz-env-add-binding env shadowing-binding formal)
		   (push (list formal shadowed-formal)
			 (special-variable-shadows env))
		   shadowed-formal))))
	(when edx-var
	  (movitz-env-add-binding env
			       (setf (edx-var env)
				 (make-instance 'edx-function-argument
				   :name edx-var))))
	(setf (required-vars env)
	  (loop for formal in required-vars
	      do (check-type formal symbol)
	      do (setf formal
		   (shadow-when-special formal env))
	      do (movitz-env-add-binding env (cond
					   ((< arg-pos 2)
					    (make-instance 'register-required-function-argument
					      :name formal
					      :argnum arg-pos))
					   ((and max-args (= min-args max-args))
					    (make-instance 'fixed-required-function-argument
					      :name formal
					      :argnum arg-pos
					      :numargs min-args))
					   (t (make-instance 'floating-required-function-argument
						:name formal
						:argnum arg-pos))))
	      do (incf arg-pos)
	      collect formal))
	(setf (optional-vars env)
	  (loop for spec in optional-vars
	      collect
		(multiple-value-bind (formal init-form supplied-p-parameter)
		    (decode-optional-formal spec)
		  (setf formal (shadow-when-special formal env))
		  (movitz-env-add-binding env (make-instance 'optional-function-argument
					     :name formal
					     :argnum (post-incf arg-pos)
					     'init-form init-form
					     'supplied-p-var supplied-p-parameter))
		  (when supplied-p-parameter
		    (setf supplied-p-parameter
		      (shadow-when-special supplied-p-parameter env))
		    (movitz-env-add-binding env (make-instance 'supplied-p-function-argument
					       :name supplied-p-parameter)))
		  formal)))
	(when (or rest-var key-vars-p)
	  (setf (rest-args-position env) arg-pos))
	(when rest-var
	  (check-type rest-var symbol)
	  (let ((formal (shadow-when-special rest-var env)))
	    (setf (rest-var env) formal)
	    (movitz-env-add-binding env (make-instance 'rest-function-argument
				       :name formal
				       :argnum (post-incf arg-pos)))))
	(when key-vars-p
	  (setf (key-vars-p env) t)
	  (when (>= 1 (rest-args-position env))
	    (let ((name (gensym "save-ebx-for-keyscan")))
	      (setf (required-vars env)
		(append (required-vars env)
			(list name)))
	      (movitz-env-add-binding env (make-instance 'register-required-function-argument
					    :name name
					    :argnum 1
					    :declarations '(muerte.cl:ignore)))
	      (setf (movitz-env-get name 'ignore nil env) t)))
	  (when (= 0 (rest-args-position env))
	    (let ((name (gensym "save-eax-for-keyscan")))
	      (push name (required-vars env))
	      (movitz-env-add-binding env (make-instance 'register-required-function-argument
					    :name name
					    :argnum 0))
	      (setf (movitz-env-get name 'ignore nil env) t))))
	(setf (key-vars env)
	  (loop for spec in key-vars
	      collect
		(multiple-value-bind (formal keyword-name init-form supplied-p)
		    (decode-keyword-formal spec)
		  (let ((formal (shadow-when-special formal env))
			(supplied-p-parameter supplied-p))
		    (movitz-env-add-binding env (make-instance 'keyword-function-argument
						  :name formal
						  'init-form init-form
						  'supplied-p-var supplied-p-parameter
						  :keyword-name keyword-name))
		    (when supplied-p-parameter
		      (movitz-env-add-binding env (make-instance 'supplied-p-function-argument
						    :name (shadow-when-special supplied-p-parameter env))))
		    formal))))
	#+ignore
	(multiple-value-bind (key-decode-map key-decode-shift)
	    (best-key-encode (key-vars env))  
	  (setf (key-decode-map env) key-decode-map
		(key-decode-shift env) key-decode-shift))
	#+ignore
	(when key-vars
	  (warn "~D waste, keys: ~S, shift ~D, map: ~S"
		(- (length (key-decode-map env))
		   (length key-vars))
		(key-vars env)
		(key-decode-shift env)
		(key-decode-map env))))))
  env)

(defun make-compiled-function-prelude-numarg-check (min-args max-args)
  "The prelude is compiled after the function's body."
  (assert (or (not max-args) (<= 0 min-args max-args)))
  (assert (<= 0 min-args (or max-args min-args) #xffff) ()
    "Lambda lists longer than #xffff are not yet implemented.")
  (let ((wrong-numargs (make-symbol "wrong-numargs")))
    (cond
     ((and (zerop min-args)		; any number of arguments is
	   (not max-args))		; acceptable, no check necessary.
      nil)
     ((not max-args)
      ;; only minimum
      (if (< min-args #x80)
	  `((:cmpb ,min-args :cl)
	    (:jb '(:sub-program (,wrong-numargs) (:int 100))))
	`((:cmpl ,(dpb min-args (byte 24 8) #x80) :ecx)
	  (:jb '(:sub-program (,wrong-numargs) (:int 100))))))
     ((and max-args (= 0 min-args max-args))
      ;; exactly zero
      `((:testb :cl :cl)
	(:jnz '(:sub-program (,wrong-numargs) (:int 100)))))
     ((and max-args (= min-args max-args))
      ;; exact number
      (cond
       ((= 1 min-args max-args)
	`((:call (:edi ,(global-constant-offset 'assert-1arg)))))
       ((= 2 min-args max-args)
	`((:call (:edi ,(global-constant-offset 'assert-2args)))))
       ((= 3 min-args max-args)
	`((:call (:edi ,(global-constant-offset 'assert-3args)))))
       ((< min-args #x80)
	`((:cmpb ,min-args :cl)
	  (:jne '(:sub-program (,wrong-numargs) (:int 100)))))
       (t `((:cmpl ,(dpb min-args (byte 24 8) #x80) :ecx)
	    (:jne '(:sub-program (,wrong-numargs) (:int 100)))))))
     ((and max-args (/= min-args max-args) (= 0 min-args))
      ;; only maximum
      (if (< max-args #x80)
	  `((:cmpb ,max-args :cl)
	    (:ja '(:sub-program (,wrong-numargs) (:int 100))))
	`((:cmpl ,(dpb max-args (byte 24 8) #x80) :ecx)
	  (:ja '(:sub-program (,wrong-numargs) (:int 100))))))
     ((and max-args (/= min-args max-args))
      ;; both max and min
      (append (if (< min-args #x80)
		  `((:cmpb ,min-args :cl)
		    (:jb '(:sub-program (,wrong-numargs) (:int 100))))
		`((:cmpl ,(dpb min-args (byte 24 8) #x80) :ecx)
		  (:jb '(:sub-program (,wrong-numargs) (:int 100)))))
	      (if (< max-args #x80)
		  `((:cmpb ,max-args :cl)
		    (:ja '(:sub-program (,wrong-numargs) (:int 100))))
		`((:cmpl ,(dpb max-args (byte 24 8) #x80) :ecx)
		  (:ja '(:sub-program (,wrong-numargs) (:int 100)))))))
     (t (error "Don't know how to compile checking for ~A to ~A arguments."
	       min-args max-args)))))

(defun make-stack-setup-code (stack-setup-size)
  (loop repeat stack-setup-size
      collect '(:pushl :edi))
  #+ignore
  (case stack-setup-size
    (0 nil)
    (1 '((:pushl :edi)))
    (2 '((:pushl :edi) (:pushl :edi)))
    (3 '((:pushl :edi) (:pushl :edi) (:pushl :edi)))
    (t `((:subl ,(* 4 stack-setup-size) :esp)))))

(defun make-compiled-function-prelude (stack-frame-size env use-stack-frame-p
				       need-normalized-ecx-p frame-map
				       &key do-check-stack-p)
  "The prelude is compiled after the function's body is."
  (when (without-function-prelude-p env)
    (return-from make-compiled-function-prelude
      (when use-stack-frame-p
	`((:pushl :ebp)
	  (:movl :esp :ebp)
	  (:pushl :esi)))))
  (let ((required-vars (required-vars env))
	(min-args (min-args env))
	(max-args (max-args env)))
    (let ((stack-setup-size stack-frame-size)
	  (edx-needs-saving-p (and (edx-var env)
				   (new-binding-location (edx-var env) frame-map :default nil))))
      (multiple-value-bind (eax-ebx-code eax-ebx-code-post-stackframe)
	  (let* ((map0 (find-if (lambda (bb)
				  (and (typep (car bb) '(or required-function-argument
							 optional-function-argument))
				       (= 0 (function-argument-argnum (car bb)))))
				frame-map))
		 (location-0 (cdr map0))
		 (map1 (find-if (lambda (bb)
				  (and (typep (car bb) '(or required-function-argument
							 optional-function-argument))
				       (= 1 (function-argument-argnum (car bb)))))
				frame-map))
		 (location-1 (cdr map1))
		 (edx-location
		  (and (edx-var env)
		       (new-binding-location (edx-var env) frame-map :default nil))))
	    #+ignore (warn "l0: ~S, l1: ~S" location-0 location-1)
	    (assert (not (and location-0
			      (eql location-0 location-1))) ()
	      "Compiler bug: two bindings in same location.")
	    (cond
	     ((and (eq :ebx location-0) (eq :eax location-1))
	      `((:xchgl :eax :ebx)))
	     ((and (eql 1 location-0) (eql 2 location-1))
	      (decf stack-setup-size 2)
	      (when (eql 3 edx-location)
		(decf stack-setup-size 1)
		(setf edx-needs-saving-p nil))
	      (let (before-code after-code)
		(setf before-code
		  (append
		   `((:pushl :eax)
		     (:pushl :ebx))
		   (when (eql 3 edx-location)
		     `((:pushl :edx)))
		   ;; Keep pushing any sequentially following floating requireds.
		   ;; NB: Fixed-floats are used in-place, e.g above the stack-frame,
		   ;; so no need to worry about them.
		   (loop with expected-location = 2
		       for var in (cddr required-vars)
		       as binding = (movitz-binding var env)
		       if (and expected-location
			       (typep binding 'floating-required-function-argument)
			       (new-binding-located-p binding frame-map)
			       (= expected-location
				  (new-binding-location binding frame-map)))
		       do (decf stack-setup-size)
		       and do (incf expected-location)
		       and do (setq need-normalized-ecx-p t)
		       and collect
			   `(:pushl (:ebp (:ecx 4)
					  ,(* -4 (1- (function-argument-argnum binding)))))
		       else do (setf expected-location nil)
		       and do (when (and (typep binding 'floating-required-function-argument)
					 (new-binding-located-p binding frame-map))
				(setq need-normalized-ecx-p t)
				(setf after-code
				  (append
				   after-code
				   `((:movl (:ebp (:ecx 4)
						  ,(* -4 (1- (function-argument-argnum binding))))
					    :edx)
				     (:movl :edx (:ebp ,(stack-frame-offset
							 (new-binding-location binding frame-map)))))))))))
		(values before-code after-code)))
	     (t (values (append
			 (cond
			  ((and (eq :ebx location-0)
				(eql 1 location-1))
			   (decf stack-setup-size)
			   `((:pushl :ebx)
			     (:xchgl :eax :ebx)))
			  ((and (eq :ebx location-0)
				(eq :edx location-1))
			   `((:movl :ebx :edx)
			     (:movl :eax :ebx)))
			  (t (append
			      (cond
			       ((eql 1 location-0)
				(decf stack-setup-size)
				'((:pushl :eax)))
			       (t (ecase location-0
				    ((nil :eax) nil)
				    (:ebx (assert (not location-1))
					  '((:movl :eax :ebx)))
				    (:edx (assert (not edx-location))
					  '((:movl :eax :edx))))))
			      (cond
			       ((eql 1 location-1)
				(decf stack-setup-size)
				'((:pushl :ebx)))
			       ((eql 2 location-1)
				(decf stack-setup-size 2)
				`((:pushl :edi)
				  (:pushl :ebx)))
			       (t (ecase location-1
				    ((nil :ebx) nil)
				    (:edx '((:movl :ebx :edx)))
				    (:eax `((:movl :ebx :eax)))))))))
			 (cond
			  ((or (and (or (eql 1 location-0)
					(eql 1 location-1))
				    (eql 2 edx-location))
			       (and (not (integerp location-0))
				    (not (integerp location-1))
				    (eql 1 edx-location)))
			   (decf stack-setup-size)
			   (setf edx-needs-saving-p nil)
			   `((:pushl :edx)))))
			(loop for var in (cddr required-vars)
			    as binding = (movitz-binding var env)
			    when (and (typep binding 'floating-required-function-argument)
				      (new-binding-located-p binding frame-map))
			    append
			      `((:movl (:ebp (:ecx 4)
					     ,(* -4 (1- (function-argument-argnum binding))))
				       :edx)
				(:movl :edx (:ebp ,(stack-frame-offset
						    (new-binding-location binding frame-map)))))
			    and do
				(setq need-normalized-ecx-p t))))))
	(assert (not (minusp stack-setup-size)))
	(let ((stack-frame-init-code
	       (append (when (and do-check-stack-p use-stack-frame-p
				  *compiler-auto-stack-checks-p*
				  (not (without-check-stack-limit-p env)))
			 `((,*compiler-local-segment-prefix*
			    :bound (:edi ,(global-constant-offset 'stack-bottom)) :esp)))
		       (when use-stack-frame-p
			 `((:pushl :ebp)
			   (:movl :esp :ebp)
			   (:pushl :esi))))))
	  (values
	   (append
	    (cond
	     ((and (eql 1 min-args)
		   (eql 1 max-args))
	      (append (make-compiled-function-prelude-numarg-check min-args max-args)
		      '(entry%1op)
		      stack-frame-init-code))
	     ((and (eql 2 min-args)
		   (eql 2 max-args))
	      (append (make-compiled-function-prelude-numarg-check min-args max-args)
		      '(entry%2op)
		      stack-frame-init-code))
	     ((and (eql 3 min-args)
		   (eql 3 max-args))
	      (append (make-compiled-function-prelude-numarg-check min-args max-args)
		      '(entry%3op)
		      stack-frame-init-code))
	     (t (append stack-frame-init-code
			(make-compiled-function-prelude-numarg-check min-args max-args))))
	    '(start-stack-frame-setup)
	    eax-ebx-code
	    (make-stack-setup-code stack-setup-size)
	    (when need-normalized-ecx-p
	      (append (cond
		       ;; normalize arg-count in ecx..
		       ((and max-args (= min-args max-args))
			(error "huh? max: ~S, min: ~S" max-args min-args))
		       ((and max-args (<= 0 min-args max-args #x7f))
			`((:andl #x7f :ecx)))
		       ((>= min-args #x80)
			`((:shrl 8 :ecx)))
		       (t (let ((normalize (make-symbol "normalize-ecx"))
				(normalize-done (make-symbol "normalize-ecx-done")))
			    `((:testb :cl :cl)
			      (:js '(:sub-program (,normalize)
				     (:shrl 8 :ecx)
				     (:jmp ',normalize-done)))
			      (:andl #x7f :ecx)
			      ,normalize-done))))))
	    (when edx-needs-saving-p
	      `((:movl :edx (:ebp ,(stack-frame-offset (new-binding-location (edx-var env) frame-map))))))
	    eax-ebx-code-post-stackframe
	    (loop for binding in (potentially-lended-bindings env)
		as lended-cons-position = (getf (binding-lending binding) :stack-cons-location)
		as location = (new-binding-location binding frame-map :default nil)
		when (and (not (typep binding 'borrowed-binding))
			  lended-cons-position
			  location)
		append
		  (typecase binding
		    (required-function-argument
		     ;; (warn "lend: ~W => ~W" binding lended-cons-position)
		     (etypecase (operator location)
		       ((eql :eax)
			(warn "lending EAX..")
			`((:movl :edi
				 (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr
			  (:movl :eax
				 (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			  (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position)))
				 :eax)))
		       ((eql :argument-stack)
			`((:movl (:ebp ,(argument-stack-offset binding)) :edx)
			  (:movl :edi
				 (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr
			  (:movl :edx
				 (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			  (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position)))
				 :edx)
			  (:movl :edx
				 (:ebp ,(argument-stack-offset binding)))))
		       (integer
			`((:movl (:ebp ,(stack-frame-offset location))
				 :edx)
			  (:movl :edi
				 (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr 
			  (:movl :edx
				 (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			  (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position)))
				 :edx)
			  (:movl :edx
				 (:ebp ,(stack-frame-offset location)))))))
		    (closure-binding
		     ;; (warn "lend closure-binding: ~W => ~W" binding lended-cons-position)
		     (etypecase (operator location)
		       ((eql :argument-stack)
			`((:movl (:edi ,(global-constant-offset 'unbound-function)) :edx)
			  (:movl :edi (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr
			  (:movl :edx (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			  (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position))) :edx)
			  (:movl :edx (:ebp ,(argument-stack-offset binding)))))
		       (integer
			`((:movl (:edi ,(global-constant-offset 'unbound-function)) :edx)
			  (:movl :edi (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr
			  (:movl :edx (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			  (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position))) :edx)
			  (:movl :edx (:ebp ,(stack-frame-offset location)))))))
		    #+ignore
		    (t (etypecase location
			 ((eql :argument-stack)
			  `((:movl :edi (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr
			    (:movl :edi (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			    (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position))) :edx)
			    (:movl :edx (:ebp ,(argument-stack-offset binding)))))
			 (integer
			  `((:movl :edi (:ebp ,(stack-frame-offset lended-cons-position))) ; cdr
			    (:movl :edi (:ebp ,(stack-frame-offset (1+ lended-cons-position)))) ; car
			    (:leal (:ebp 1 ,(stack-frame-offset (1+ lended-cons-position))) :edx)
			    (:movl :edx (:ebp ,(stack-frame-offset location))))))))))
	   need-normalized-ecx-p))))))

(defparameter *restify-stats* (make-hash-table :test #'eql))

(defparameter *ll* (make-array 20 :initial-element 0))
(defparameter *xx* (make-array 20))

(defun install-arg-cmp (code have-normalized-ecx-p)
  (loop for i in code
      collecting
	(if (not (and (listp i) (eq :arg-cmp (car i))))
	    i
	  (let ((arg-count (second i)))
	    (cond
	     (have-normalized-ecx-p
	      `(:cmpl ,arg-count :ecx))
	     ((< arg-count #x80)
	      `(:cmpb ,arg-count :cl))
	     (t `(:cmpl ,(dpb arg-count (byte 24 8) #x80) :ecx)))))))

(defun make-function-arguments-init (funobj env)
  "The arugments-init is compiled before the function's body is.
Return arg-init-code, need-normalized-ecx-p."
  (when (without-function-prelude-p env)
    (return-from make-function-arguments-init
      (values nil nil)))
  (let ((need-normalized-ecx-p nil)
	(required-vars (required-vars env))
	(optional-vars (optional-vars env))
	(rest-var (rest-var env))
	(key-vars (key-vars env)))
    (values
     (append
      (loop for optional in optional-vars
	  as optional-var = (decode-optional-formal optional)
	  as binding = (movitz-binding optional-var env)
	  as last-optional-p = (and (null key-vars)
				    (not rest-var)
				    (= 1 (- (+ (length optional-vars) (length required-vars))
					    (function-argument-argnum binding))))
	  as supplied-p-var = (optional-function-argument-supplied-p-var binding)
	  as supplied-p-binding = (movitz-binding supplied-p-var env)
	  as not-present-label = (make-symbol (format nil "optional-~D-not-present" 
						      (function-argument-argnum binding)))
	  and optional-ok-label = (make-symbol (format nil "optional-~D-ok" 
						       (function-argument-argnum binding)))
	  unless (movitz-env-get optional-var 'ignore nil env nil) ; XXX
	  append
	    (cond
	     ((= 0 (function-argument-argnum binding))
	      `((:init-lexvar ,binding :init-with-register :eax :init-with-type t)))
	     ((= 1 (function-argument-argnum binding))
	      `((:init-lexvar ,binding :init-with-register :ebx :init-with-type t)))
	     (t `((:init-lexvar ,binding))))
	  when supplied-p-binding
	  append `((:init-lexvar ,supplied-p-binding))
	  append
	    (compiler-values-bind (&code init-code-edx &producer producer)
		(compiler-call #'compile-form
		  :form (optional-function-argument-init-form binding)
		  :funobj funobj
		  :env env
		  :result-mode :edx)
	      (cond
	       ((and (eq 'compile-self-evaluating producer)
		     (member (function-argument-argnum binding) '(0 1)))
		;; The binding is already preset with EAX or EBX.
		(check-type binding lexical-binding)
		(append
		 (when supplied-p-var
		   `((:load-constant ,(movitz-read t) :edx)
		     (:store-lexical ,supplied-p-binding :edx :type (member t))))
		 `((:arg-cmp ,(function-argument-argnum binding))
		   (:ja ',optional-ok-label))
		 (compiler-call #'compile-form
		   :form (optional-function-argument-init-form binding)
		   :funobj funobj
		   :env env
		   :result-mode binding)
		 (when supplied-p-var
		   `((:store-lexical ,supplied-p-binding :edi :type null)))
		 `(,optional-ok-label)))
	       ((eq 'compile-self-evaluating producer)
		`(,@(when supplied-p-var
		      `((:store-lexical ,supplied-p-binding :edi :type null)))
		    ,@(if (optional-function-argument-init-form binding)
			  (append init-code-edx `((:store-lexical ,binding :edx :type t)))
			`((:store-lexical ,binding :edi :type null)))
		    (:arg-cmp ,(function-argument-argnum binding))
		    (:jbe ',not-present-label)
		    ,@(case (function-argument-argnum binding)
			(0 `((:store-lexical ,binding :eax :type t)))
			(1 `((:store-lexical ,binding :ebx :type t)))
			(t (cond
			    (last-optional-p
			     `((:movl (:ebp  ,(* 4 (- (1+ (function-argument-argnum binding))
						      -1 (function-argument-argnum binding))))
				      :eax)
			       (:store-lexical ,binding :eax :type t)))
			    (t (setq need-normalized-ecx-p t)
			       `((:movl (:ebp (:ecx 4)
					      ,(* -4 (1- (function-argument-argnum binding))))
					:eax)
				 (:store-lexical ,binding :eax :type t))))))
		    ,@(when supplied-p-var
			`((:movl (:edi ,(global-constant-offset 't-symbol)) :eax)
			  (:store-lexical ,supplied-p-binding :eax
					  :type (eql ,(image-t-symbol *image*)))))
		    ,not-present-label))
	       (t `((:arg-cmp ,(function-argument-argnum binding))
		    (:jbe ',not-present-label)
		    ,@(when supplied-p-var
			`((:movl (:edi ,(global-constant-offset 't-symbol)) :eax)
			  (:store-lexical ,supplied-p-binding :eax
					  :type (eql ,(image-t-symbol *image*)))))
		    ,@(case (function-argument-argnum binding)
			(0 `((:store-lexical ,binding :eax :type t)))
			(1 `((:store-lexical ,binding :ebx :type t)))
			(t (cond
			    (last-optional-p
			     `((:movl (:ebp  ,(* 4 (- (1+ (function-argument-argnum binding))
						      -1 (function-argument-argnum binding))))
				      :eax)
			       (:store-lexical ,binding :eax :type t)))
			    (t (setq need-normalized-ecx-p t)
			       `((:movl (:ebp (:ecx 4)
					      ,(* -4 (1- (function-argument-argnum binding))))
					:eax)
				 (:store-lexical ,binding :eax :type t))))))
		    (:jmp ',optional-ok-label)
		    ,not-present-label
		    ,@(when supplied-p-var
			`((:store-lexical ,supplied-p-binding :edi :type null)))
		    ,@(when (and (= 0 (function-argument-argnum binding))
				 (not last-optional-p))
			`((:pushl :ebx))) ; protect ebx
		    ,@(if (optional-function-argument-init-form binding)
			  (append `((:shll ,+movitz-fixnum-shift+ :ecx)
				    (:pushl :ecx))
				  (when (= 0 (function-argument-argnum binding))
				    `((:pushl :ebx)))
				  init-code-edx
				  `((:store-lexical ,binding :edx :type t))
				  (when (= 0 (function-argument-argnum binding))
				    `((:popl :ebx)))
				  `((:popl :ecx)
				    (:shrl ,+movitz-fixnum-shift+ :ecx)))
			(progn (error "Unsupported situation.")
			       #+ignore `((:store-lexical ,binding :edi :type null))))
		    ,@(when (and (= 0 (function-argument-argnum binding))
				 (not last-optional-p))
			`((:popl :ebx))) ; protect ebx
		    ,optional-ok-label)))))
      (when rest-var
	(let* ((rest-binding (movitz-binding rest-var env)))
	  `((:init-lexvar ,rest-binding
			  :init-with-register :edx
			  :init-with-type list))))
      (when key-vars
	(play-with-keys key-vars))
      (when (key-vars-p env)
       ;; &key processing..
	(setq need-normalized-ecx-p t)
	(append
	 `((:declare-key-arg-set ,@(mapcar (lambda (k)
					     (movitz-read
					      (keyword-function-argument-keyword-name
					       (movitz-binding (decode-keyword-formal k) env))))
					   key-vars)))
	 (make-immediate-move (* +movitz-fixnum-factor+
				 (rest-args-position env))
			      :edx)
	 `((:call (:edi ,(global-constant-offset 'decode-keyargs-default))))
	 (unless (allow-other-keys-p env)
	   `((:testl :eax :eax)
	     (:jnz '(:sub-program (unknown-keyword)
		     (:int 72)))))
	 (loop for key-var in key-vars
	     as key-location upfrom 3 by 2
	     as key-var-name =
	       (decode-keyword-formal key-var)
	     as binding =
	       (movitz-binding key-var-name env)
	     as supplied-p-binding =
	       (when (optional-function-argument-supplied-p-var binding)
		 (movitz-binding (optional-function-argument-supplied-p-var binding)
				 env))
	     as keyword-ok-label = (make-symbol (format nil "keyword-~A-ok" key-var-name))
	     do (assert binding)
	     ;;  (not (movitz-constantp (optional-function-argument-init-form binding)))
	     append
	       (append `((:init-lexvar ,binding
				       :init-with-register ,binding
				       :init-with-type t
				       :shared-reference-p t))
		       (when supplied-p-binding
			 `((:init-lexvar ,supplied-p-binding
					 :init-with-register ,supplied-p-binding
					 :init-with-type t
					 :shared-reference-p t)))
		       (when (optional-function-argument-init-form binding)
			 `((:cmpl :edi (:ebp ,(stack-frame-offset (1+ key-location))))
			   (:jne ',keyword-ok-label)
			   ,@(compiler-call #'compile-form
			       :form (optional-function-argument-init-form binding)
			       :env env
			       :funobj funobj
			       :result-mode binding)
			   ,keyword-ok-label)))
;;;	     else append
;;;		  nil
		  #+ignore
		  (append (when supplied-p-var
			    `((:init-lexvar ,supplied-p-binding
					    :init-with-register :edi
					    :init-with-type null)))
			  (compiler-call #'compile-form
			    :form (list 'muerte.cl:quote
					(eval-form (optional-function-argument-init-form binding)
						   env))
			    :env env
			    :funobj funobj
			    :result-mode :eax)
			  `((:load-constant
			     ,(movitz-read (keyword-function-argument-keyword-name binding)) :ecx)
			    (:load-lexical ,rest-binding :ebx)
			    (:call (:edi ,(global-constant-offset 'keyword-search))))
			  (when supplied-p-var
			    `((:jz ',keyword-not-supplied-label)
			      (:movl (:edi ,(global-constant-offset 't-symbol)) :ebx)
			      (:store-lexical ,supplied-p-binding :ebx
					      :type (eql ,(image-t-symbol *image*)))
			      ,keyword-not-supplied-label))
			  `((:init-lexvar ,binding
					  :init-with-register :eax
					  :init-with-type t)))))))
     need-normalized-ecx-p)))

(defun old-key-encode (vars &key (size (ash 1 (integer-length (1- (length vars)))))
			     (byte (byte 16 0)))
  (assert (<= (length vars) size))
  (if (null vars)
      (values nil 0)
    (loop with h = (make-array size)
	with crash
	for var in (sort (copy-list vars) #'<
			 :key (lambda (v)
				(mod (ldb byte (movitz-sxhash (movitz-read v)))
				     (length h))))
	do (let ((pos (mod (ldb byte (movitz-sxhash (movitz-read var)))
			   (length h))))
	     (loop while (aref h pos)
		 do (push var crash)
		    (setf pos (mod (1+ pos) (length h))))
	     (setf (aref h pos) var))
	finally (return (values (subseq h 0 (1+ (position-if-not #'null h :from-end t)))
				(length crash))))))

(define-condition key-encoding-failed () ())

(defun key-cuckoo (x shift table &optional path old-position)
  (if (member x path)
      (error 'key-encoding-failed)
    (let* ((pos1 (mod (ash (movitz-sxhash (movitz-read x)) (- shift))
		      (length table)))
	   (pos2 (mod (ash (movitz-sxhash (movitz-read x)) (- 0 shift 9))
		      (length table)))
	   (pos (if (eql pos1 old-position) pos2 pos1))
	   (kickout (aref table pos)))
      (setf (aref table pos)
	x)
      (when kickout
	(key-cuckoo kickout shift table (cons x path) pos)))))

(defun key-encode (vars &key (size (ash 1 (integer-length (1- (length vars)))))
			     (shift 0))
  (declare (ignore byte))
  (assert (<= (length vars) size))
  (if (null vars)
      (values nil 0)
    (loop with table = (make-array size)
	for var in (sort (copy-list vars) #'<
			 :key (lambda (v)
				(mod (movitz-sxhash (movitz-read v))
				     (length table))))
	do (key-cuckoo var shift table)
	finally
	  (return (values table
			  (- (length vars)
			     (count-if (lambda (v)
					 (eq v (aref table (mod (ash (movitz-sxhash (movitz-read v))
								     (- shift))
								(length table)))))
				       vars)))))))

(defun best-key-encode (vars)
  (when vars
    (loop with best-encoding = nil
	with best-shift
	with best-crashes
	for size = (ash 1 (integer-length (1- (length vars))))
	then (* size 2)
	     ;; from (length vars) to (+ 8 (ash 1 (integer-length (1- (length vars)))))
	while (<= size (max 16 (ash 1 (integer-length (1- (length vars))))))
	do (loop for shift from 0 to 9 by 3
	       do (handler-case
		      (multiple-value-bind (encoding crashes)
			  (key-encode vars :size size :shift shift)
			(when (or (not best-encoding)
				  (< crashes best-crashes)
				  (and (= crashes best-crashes)
				       (or (< shift best-shift)
					   (and (= shift best-shift)
						(< (length encoding)
						   (length best-encoding))))))
			  (setf best-encoding encoding
				best-shift shift
				best-crashes crashes)))
		    (key-encoding-failed ())))
	finally 
	  (unless best-encoding
	    (warn "Key-encoding failed for ~S: ~S."
		   vars
		   (mapcar (lambda (v)
			     (list (movitz-sxhash (movitz-read v))
				   (ldb (byte (+ 3 (integer-length (1- (length vars)))) 0)
					(movitz-sxhash (movitz-read v)))
				   (ldb (byte (+ 3 (integer-length (1- (length vars)))) 9)
					(movitz-sxhash (movitz-read v)))))
			   vars)))
	  #+ignore
	  (warn "~D waste for ~S"
		(- (length best-encoding)
		   (length vars))
		vars)
	  (return (values best-encoding best-shift best-crashes)))))



(defun play-with-keys (key-vars)
  #+ignore
  (let* ((vars (mapcar #'decode-keyword-formal key-vars)))
    (multiple-value-bind (encoding shift crashes)
	(best-key-encode vars)
      (when (or (plusp crashes)
		#+ignore (>= shift 3)
		(>= (- (length encoding) (length vars))
		    8))
	(warn "KEY vars: ~S, crash ~D, shift ~D, waste: ~D hash: ~S"
	      vars crashes shift
	      (- (length encoding) (length vars))
	      (mapcar (lambda (s)
			(movitz-sxhash (movitz-read s)))
		      vars))))))
	 

(defun make-special-funarg-shadowing (env function-body)
  "Wrap function-body in a let, if we need to.
We need to when the function's lambda-list binds a special variable,
or when there's a non-dynamic-extent &rest binding."
  (if (without-function-prelude-p env)
      function-body
    (let ((shadowing
	   (append (special-variable-shadows env)
                   (aux-vars env)
		   (when (and (rest-var env)
			      (not (movitz-env-get (rest-var env) 'dynamic-extent nil env nil))
			      (not (movitz-env-get (rest-var env) 'ignore nil env nil)))
		     (movitz-env-load-declarations `((muerte.cl:dynamic-extent ,(rest-var env)))
						   env :funobj)
		     `((,(rest-var env) (muerte.cl:copy-list ,(rest-var env))))))))
      (if (null shadowing)
	  function-body
	`(muerte.cl::let ,shadowing ,function-body)))))

(defun make-compiled-function-postlude (funobj env use-stack-frame-p)
  (declare (ignore funobj env))
  (let ((p '((:movl (:ebp -4) :esi)
	     (:ret))))
    (if use-stack-frame-p
	(cons '(:leave) p)
      p)))

(defun complement-boolean-result-mode (mode)
  (etypecase mode
    (keyword
     (ecase mode
       (:boolean-greater       :boolean-less-equal)
       (:boolean-less          :boolean-greater-equal)
       (:boolean-greater-equal :boolean-less)
       (:boolean-less-equal    :boolean-greater)
       (:boolean-below         :boolean-above-equal)
       (:boolean-above         :boolean-below-equal)
       (:boolean-below-equal   :boolean-above)
       (:boolean-above-equal   :boolean-below)
       (:boolean-zf=1          :boolean-zf=0)
       (:boolean-zf=0          :boolean-zf=1)
       (:boolean-cf=1          :boolean-cf=0)
       (:boolean-cf=0          :boolean-cf=1)
       (:boolean-overflow      :boolean-no-overflow)
       (:boolean-no-overflow   :boolean-overflow)))
    (cons
     (let ((args (cdr mode)))
       (ecase (car mode)
	 (:boolean-ecx
	  (list :boolean-ecx (second args) (first args)))
	 (:boolean-branch-on-true
	  (cons :boolean-branch-on-false args))
	 (:boolean-branch-on-false
	  (cons :boolean-branch-on-true args)))))))

(defun make-branch-on-boolean (mode label &key invert)
  (list (ecase (if invert (complement-boolean-result-mode mode) mode)
	  (:boolean-greater       :jg)	; ZF=0 and SF=OF
	  (:boolean-greater-equal :jge)	; SF=OF
	  (:boolean-less          :jl)	; SF!=OF
	  (:boolean-less-equal    :jle)	; ZF=1 or SF!=OF
	  (:boolean-below         :jb)
	  (:boolean-above         :ja)
	  (:boolean-below-equal   :jbe)
	  (:boolean-above-equal   :jae)
	  (:boolean-zf=1          :jz)
	  (:boolean-zf=0          :jnz)
	  (:boolean-cf=1          :jc)
	  (:boolean-cf=0          :jnc)
	  (:boolean-true          :jmp)
	  (:boolean-overflow      :jo)
	  (:boolean-no-overflow   :jno))
	(list 'quote label)))


(defun make-cmov-on-boolean (mode src dst &key invert)
  (list (ecase (if invert (complement-boolean-result-mode mode) mode)
	  (:boolean-greater       :cmovg) ; ZF=0 and SF=OF
	  (:boolean-greater-equal :cmovge) ; SF=OF
	  (:boolean-less          :cmovl) ; SF!=OF
	  (:boolean-less-equal    :cmovle) ; ZF=1 or SF!=OF
	  (:boolean-zf=1          :cmovz)
	  (:boolean-zf=0          :cmovnz)
	  (:boolean-cf=1          :cmovc)
	  (:boolean-cf=0          :cmovnc))
	src dst))

(defun return-satisfies-result-p (desired-result returns-provided)
  (or (eq desired-result returns-provided)
      (case desired-result
	(:ignore t)
	((:eax :single-value)
	 (member returns-provided '(:eax :multiple-values :single-value)))
	(:function
	 (member returns-provided '(:multiple-values :function)))
	(:boolean
	 (member returns-provided +boolean-modes+)))))
  
(defun make-result-and-returns-glue (desired-result returns-provided
				     &optional code
				     &key (type t) provider really-desired)
  "Returns new-code and new-returns-provided, and glue-side-effects-p."
  (declare (optimize (debug 3)))
  (case returns-provided
    (:non-local-exit
     ;; when CODE does a non-local exit, we certainly don't need any glue.
     (return-from make-result-and-returns-glue
       (values code :non-local-exit))))
  (multiple-value-bind (new-code new-returns-provided glue-side-effects-p)
      (case (result-mode-type desired-result)
	((:lexical-binding)
	 (case (result-mode-type returns-provided)
	   (:lexical-binding
	    (if (eq desired-result returns-provided)
		(values code returns-provided)
	      (values (append code `((:load-lexical ,returns-provided ,desired-result)))
		      returns-provided)))
	   ((:eax :multiple-values)
	    (values (append code
			    `((:store-lexical ,desired-result :eax
					      :type ,(type-specifier-primary type))))
		    desired-result
		    t))
	   ((:ebx :ecx)
	    (values (append code
			    `((:store-lexical ,desired-result
					      ,(result-mode-type returns-provided)
					      :type ,(type-specifier-primary type))))
		    desired-result
		    t))))
	(:ignore (values code :nothing))
	((:boolean-ecx)
	 (let ((true (first (operands desired-result)))
	       (false (second (operands desired-result))))
	   (etypecase (operator returns-provided)
	     ((eql :boolean-ecx)
	      (if (equal (operands desired-result)
			 (operands returns-provided))
		  (values code desired-result)
		))
	     ((eql :boolean-cf=1)
	      (cond
	       ((and (= -1 true) (= 0 false))
		(values (append code
				`((:sbbl :ecx :ecx)))
			'(:boolean-ecx -1 0)))
	       ((and (= 0 true) (= -1 false))
		(values (append code
				`((:sbbl :ecx :ecx)
				  (:notl :ecx)))
			'(:boolean-ecx 0 -1)))
	       (t (error "Don't know modes ~S => ~S." returns-provided desired-result))))
	     ((eql :eax)
	      (make-result-and-returns-glue desired-result
					    :boolean-cf=1
					    (append code
						    `((:leal (:eax ,(- (image-nil-word *image*)))
							     :ecx)
						      (:subl 1 :ecx)))
					    :type type
					    :provider provider
					    :really-desired desired-result)))))
	(:boolean-branch-on-true
	 ;; (warn "rm :b-true with ~S." returns-provided)
	 (etypecase (operator returns-provided)
	   ((member :boolean-branch-on-true)
	    (assert (eq (operands desired-result) (operands returns-provided)))
	    (values code returns-provided))
	   ((member :eax :multiple-values)
	    (values (append code
			    `((:cmpl :edi :eax)
			      (:jne ',(operands desired-result))))
		    desired-result))
	   ((member :ebx :ecx :edx)
	    (values (append code
			    `((:cmpl :edi ,returns-provided)
			      (:jne ',(operands desired-result))))
		    desired-result))
	   ((member :nothing)
	    ;; no branch, nothing is nil is false.
	    (values code desired-result))
	   ((member . #.+boolean-modes+)
	    (values (append code
			    (list (make-branch-on-boolean returns-provided (operands desired-result))))
		    desired-result))
	   (lexical-binding
	    (values (append code
			    `((:load-lexical ,returns-provided ,desired-result)))
		    desired-result))
	   (constant-object-binding
	    (values (if (eq *movitz-nil* (constant-object returns-provided))
			nil
		      `((:jmp ',(operands desired-result))))
		    desired-result))))
	(:boolean-branch-on-false
	 (etypecase (operator returns-provided)
	   ((member :boolean-branch-on-false)
	    (assert (eq (operands desired-result)
			(operands returns-provided)))
	    (values code desired-result))
	   ((member :nothing)
	    (values (append code
			    `((:jmp ',(operands desired-result))))
		    desired-result))
	   ((member . #.+boolean-modes+)
	    (values (append code
			    (list (make-branch-on-boolean returns-provided (operands desired-result)
							  :invert t)))
		    desired-result))
	   ((member :ebx :ecx :edx)
	    (values (append code
			    `((:cmpl :edi ,returns-provided)
			      (:je ',(operands desired-result))))
		    desired-result))
	   ((member :eax :multiple-values)
	    (values (append code
			    `((:cmpl :edi :eax)
			      (:je ',(operands desired-result))))
		    desired-result))
	   (lexical-binding
	    (values (append code
			    `((:load-lexical ,returns-provided ,desired-result)))
		    desired-result))
	   (constant-object-binding
	    (values (if (not (eq *movitz-nil* (constant-object returns-provided)))
			nil
		      `((:jmp ',(operands desired-result))))
		    desired-result))))
	(:untagged-fixnum-ecx
	 (case (result-mode-type returns-provided)
	   (:untagged-fixnum-ecx
	    (values code :untagged-fixnum-ecx))
	   ((:eax :single-value :multiple-values :function)
	    (values (append code
			    `((,*compiler-global-segment-prefix*
			       :call (:edi ,(global-constant-offset 'unbox-u32)))))
		    :untagged-fixnum-ecx))
	   (:ecx
	    ;; In theory (at least..) ECX can only hold non-pointers, so don't check.
	    (values (append code
			    `((:shrl ,+movitz-fixnum-shift+ :ecx)))
		    :untagged-fixnum-ecx))
	   ((:ebx :edx)
	    (values (append code
			    `((:movl ,returns-provided :eax)
			      (,*compiler-global-segment-prefix*
			       :call (:edi ,(global-constant-offset 'unbox-u32)))))
		    :untagged-fixnum-ecx))
	   (:lexical-binding
	    (values (append code
			    `((:load-lexical ,returns-provided :untagged-fixnum-ecx)))
		    :untagged-fixnum-ecx))))
	((:single-value :eax)
	 (cond
	  ((eq returns-provided :eax)
	   (values code :eax))
	  ((typep returns-provided 'lexical-binding)
	   (values (append code `((:load-lexical ,returns-provided :eax)))
		   :eax))
	  (t (case (operator returns-provided)
	       (:untagged-fixnum-eax
		(values (append code `((:shll ,+movitz-fixnum-shift+ :eax))) :eax))
	       (:values
		(case (first (operands returns-provided))
		  (0 (values (append code '((:movl :edi :eax)))
			     :eax))
		  (t (values code :eax))))
	       ((:single-value :eax :function :multiple-values)
		(values code :eax))
	       (:nothing
		(values (append code '((:movl :edi :eax)))
			:eax))
	       ((:ebx :ecx :edx :edi)
		(values (append code `((:movl ,returns-provided :eax)))
			:eax))
	       (:boolean-ecx
		(let ((true-false (operands returns-provided)))
		  (cond
		   ((equal '(0 1) true-false)
		    (values (append code `((:movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-zero))
						  :eax)))
			    :eax))
		   ((equal '(1 0) true-false)
		    (values (append code `((:movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-one))
						  :eax)))
			    :eax))
		   (t (error "Don't know ECX mode ~S." returns-provided)))))
	       (:boolean-cf=1
		(values (append code
				`((:sbbl :ecx :ecx) ; T => -1, NIL => 0
				  (:movl (:edi (:ecx 4) ,(global-constant-offset 'not-not-nil))
					 :eax)))
			:eax))
	       (#.+boolean-modes+
		;; (warn "bool for ~S" returns-provided)
		(let ((boolean-false-label (make-symbol "boolean-false-label")))
		  (values (append code
				  '((:movl :edi :eax))
				  (if *compiler-use-cmov-p*
				      `(,(make-cmov-on-boolean returns-provided
							       `(:edi ,(global-constant-offset 't-symbol))
							       :eax
							       :invert nil))
				    `(,(make-branch-on-boolean returns-provided
							       boolean-false-label
							       :invert t)
				      (:movl (:edi ,(global-constant-offset 't-symbol))
					     :eax)
				      ,boolean-false-label)))
			  :eax)))))))
	((:ebx :ecx :edx :esp :esi)
	 (cond
	  ((eq returns-provided desired-result)
	   (values code returns-provided))
	  ((typep returns-provided 'lexical-binding)
	   (values (append code `((:load-lexical ,returns-provided ,desired-result)))
		   desired-result))
	  (t (case (operator returns-provided)
	       (:nothing
		(values (append code
				`((:movl :edi ,desired-result)))
			desired-result))
	       ((:ebx :ecx :edx :esp)
		(values (append code
				`((:movl ,returns-provided ,desired-result)))
			desired-result))
	       ((:eax :single-value :multiple-values :function)
		(values (append code
				`((:movl :eax ,desired-result)))
			desired-result))
	       (:boolean-ecx
		(let ((true-false (operands returns-provided)))
		  (cond
		   ((equal '(0 1) true-false)
		    (values (append code `((:movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-zero))
						  ,desired-result)))
			    desired-result))
		   ((equal '(1 0) true-false)
		    (values (append code `((:movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-one))
						  ,desired-result)))
			    desired-result))
		   (t (error "Don't know ECX mode ~S." returns-provided)))))
;;;	     (:boolean-ecx=0
;;;	      (values (append code `((:movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-zero))
;;;					    ,desired-result)))
;;;		      desired-result))
;;;	     (:boolean-ecx=1
;;;	      (values (append code `((:movl (:edi (:ecx 4) ,(global-constant-offset 'boolean-one))
;;;					    ,desired-result)))
;;;		      desired-result))
	       (:boolean-cf=1
		(values (append code
				`((:sbbl :ecx :ecx)
				  (:movl (:edi (:ecx 4) ,(global-constant-offset 'not-not-nil))
					 ,desired-result)))
			desired-result))
	       (#.+boolean-modes+
		;; (warn "bool to ~S for ~S" desired-result returns-provided)
		(values (append code
				(cond
				 (*compiler-use-cmov-p*
				  `((:movl :edi ,desired-result)
				    ,(make-cmov-on-boolean returns-provided
							   `(:edi ,(global-constant-offset 't-symbol))
							   desired-result)))
				 ((not *compiler-use-cmov-p*)
				  (let ((boolean-false-label (make-symbol "boolean-false-label")))
				    `((:movl :edi ,desired-result)
				      ,(make-branch-on-boolean returns-provided
							       boolean-false-label
							       :invert t)
				      (:movl (:edi ,(global-constant-offset 't-symbol))
					     ,desired-result)
				      ,boolean-false-label)))))
			desired-result))))))
	(:push
	 (typecase returns-provided
	   ((member :push) (values code :push))
	   ((member :nothing)
	    (values (append code '((:pushl :edi)))
		    :push))
	   ((member :single-value :eax :multiple-values :function)
	    (values (append code `((:pushl :eax)))
		    :push))
	   ((member :ebx :ecx :edx)
	    (values (append code `((:pushl ,returns-provided)))
		    :push))
	   (lexical-binding
	    (values (append code `((:load-lexical ,returns-provided :push)))
		    :push))))
	(:values
	 (case (operator returns-provided)
	   (:values
	    (values code returns-provided))
	   (:multiple-values
	    (values code :values))
	   (t (values (make-result-and-returns-glue :eax returns-provided code
						    :type type)
		      '(:values 1)))))
	((:multiple-values :function)
	 (case (operator returns-provided)
	   ((:multiple-values :function)
	    (values code :multiple-values))
	   (:values
	    (case (first (operands returns-provided))
	      (0 (values (append code '((:movl :edi :eax) (:xorl :ecx :ecx) (:stc)))
			 :multiple-values))
	      (1 (values (append code '((:clc)))
			 :multiple-values))
	      ((nil) (values code :multiple-values))
	      (t (values (append code
				 (make-immediate-move (first (operands returns-provided)) :ecx)
				 '((:stc)))
			 :multiple-values))))
	   (t (values (append (make-result-and-returns-glue :eax
							    returns-provided
							    code
							    :type type
							    :provider provider
							    :really-desired desired-result)
			      '((:clc)))
		      :multiple-values)))))
    (unless new-returns-provided
      (multiple-value-setq (new-code new-returns-provided glue-side-effects-p)
	(ecase (result-mode-type returns-provided)
	  (:constant-binding
	   (case (result-mode-type desired-result)
	     ((:eax :ebx :ecx :edx :push :lexical-binding)
	      (values (append code
			      `((:load-constant ,(constant-object returns-provided)
						,desired-result)))
		      desired-result))))
	  (#.+boolean-modes+
	   (make-result-and-returns-glue desired-result :eax
					 (make-result-and-returns-glue :eax returns-provided code
								       :type type
								       :provider provider
								       :really-desired desired-result)
					 :type type
					 :provider provider))
	  (:untagged-fixnum-ecx
	   (let ((fixnump (subtypep type `(integer 0 ,+movitz-most-positive-fixnum+))))
	     (cond
	      ((and fixnump
		    (member (result-mode-type desired-result) '(:eax :ebx :ecx :edx)))
	       (values (append code
			       `((:leal ((:ecx ,+movitz-fixnum-factor+))
					,(result-mode-type desired-result))))
		       desired-result))
	      ((and (not fixnump)
		    (member (result-mode-type desired-result) '(:eax :single-value)))
	       (values (append code
			       `((:call (:edi ,(global-constant-offset 'box-u32-ecx)))))
		       desired-result))
	      (t (make-result-and-returns-glue
		  desired-result :eax
		  (make-result-and-returns-glue :eax :untagged-fixnum-ecx code
						:provider provider
						:really-desired desired-result
						:type type)
		  :provider provider
		  :type type)))))
	  #+ignore
	  (:untagged-fixnum-eax
	   (make-result-and-returns-glue desired-result :eax
					 (make-result-and-returns-glue :eax :untagged-fixnum-eax code
								       :provider provider
								       :really-desired desired-result)
					 :provider provider)))))
    (assert new-returns-provided ()
      "Don't know how to match desired-result ~S with returns-provided ~S~@[ from ~S~]."
      (or really-desired desired-result) returns-provided provider)
    (values new-code new-returns-provided glue-side-effects-p)))

(define-compiler compile-form (&all form-info &result-mode result-mode)
  "3.1.2.1 Form Evaluation. Guaranteed to honor RESULT-MODE."
  (compiler-values-bind (&all unprotected-values &code form-code &returns form-returns
			 &producer producer &type form-type &functional-p functional-p)
      (compiler-call #'compile-form-unprotected :forward form-info)
    (multiple-value-bind (new-code new-returns-provided glue-side-effects-p)
	(make-result-and-returns-glue result-mode form-returns form-code
				      :provider producer
				      :type form-type)
      (compiler-values (unprotected-values)
	:type form-type
	:functional-p (and functional-p (not glue-side-effects-p))
	:producer producer
	:code new-code
	:returns new-returns-provided))))

(define-compiler compile-form-selected (&all form-info &result-mode result-modes)
  "3.1.2.1 Form Evaluation. Guaranteed to honor one of RESULT-MODE, which
for this call (exclusively!) is a list of the acceptable result-modes, where
the first one takes preference. Note that :non-local-exit might also be returned."
  (check-type result-modes list "a list of result-modes")
  (compiler-values-bind (&all unprotected-values &code form-code &returns form-returns
			 &producer producer &type form-type)
      (compiler-call #'compile-form-unprotected
	:result-mode (car result-modes)
	:forward form-info)
    (if (member form-returns result-modes)
	(compiler-values (unprotected-values))
      (compiler-call #'compile-form
	:result-mode (car result-modes)
	:forward form-info))))

(define-compiler compile-form-to-register (&all form-info)
  (compiler-values-bind (&all unprotected-values &code form-code &returns form-returns
			 &final-form final-form &producer producer &type form-type)
      (compiler-call #'compile-form-unprotected
	:result-mode :eax
	:forward form-info)
    (cond
     #+ignore
     ((and (typep final-form 'required-function-argument)
	   (= 1 (function-argument-argnum final-form)))
      (compiler-call #'compile-form
	:result-mode :ebx
	:forward form-info))
     ((member form-returns '(:eax :ebx :ecx :edx :edi :untagged-fixnum-ecx))
      (compiler-values (unprotected-values)))
     (t (compiler-call #'compile-form
	  :result-mode :eax
	  :forward form-info)))))
  
(define-compiler compile-form-unprotected (&all downstream &form form &result-mode result-mode
						&extent extent)
  "3.1.2.1 Form Evaluation. May not honor RESULT-MODE.
That is, RESULT-MODE is taken to be a suggestion, not an imperative."
  (compiler-values-bind (&all upstream)
      (typecase form
	(symbol (compiler-call #'compile-symbol :forward downstream))
 	(cons   (compiler-call #'compile-cons :forward downstream))
	(t      (compiler-call #'compile-self-evaluating :forward downstream)))
    (when (typep (upstream :final-form) 'lexical-binding)
      (labels ((fix-extent (binding)
		 (cond
		  ((sub-env-p extent (binding-extent-env binding))
		   #+ignore (warn "Binding ~S OK in ~S wrt. ~S."
				  binding
				  (binding-extent-env binding)
				  (downstream :env)))
		  (t #+ignore (break "Binding ~S escapes from ~S to ~S"
				     binding (binding-extent-env binding)
				     extent)
		      (setf (binding-extent-env binding) extent)))
		 (when (typep binding 'forwarding-binding)
		   (fix-extent (forwarding-binding-target binding)))))
	(when extent
	  (fix-extent (upstream :final-form)))))
    (compiler-values (upstream))))

(defun lambda-form-p (form)
  (and (listp form)
       (eq 'muerte.cl:lambda (first form))))

(defun function-name-p (operator)
  (or (and (symbolp operator) operator)
      (setf-name operator)))

(define-compiler compile-cons (&all all &form form &env env)
  "3.1.2.1.2 Conses as Forms"
  (let ((operator (car form)))
    (if (and (symbolp operator) (movitz-special-operator-p operator))
	(compiler-call (movitz-special-operator-compiler operator) :forward all)
      (let* ((compiler-macro-function (movitz-compiler-macro-function operator env))
	     (compiler-macro-expansion (and compiler-macro-function
					    (handler-case
						(funcall *movitz-macroexpand-hook*
							 compiler-macro-function
							 form env)
					      (error (c)
						(warn "Compiler-macro for ~S failed: ~A" operator c)
						form)))))
	(cond
	 ((and compiler-macro-function
	       (not (movitz-env-get operator 'notinline nil env))
	       (not (eq form compiler-macro-expansion)))
	  (compiler-call #'compile-form-unprotected :forward all :form compiler-macro-expansion))
	 ((movitz-constantp form env)
	  (compiler-call #'compile-constant-compound :forward all))
	 ((lambda-form-p operator)	; 3.1.2.1.2.4
	  (compiler-call #'compile-lambda-form :forward all))
	 ((symbolp operator)
	  (cond
	   ((movitz-special-operator-p operator)
	    (compiler-call (movitz-special-operator-compiler operator) :forward all))
	   ((movitz-macro-function operator env)
	    (compiler-call #'compile-macro-form :forward all))
	   ((movitz-operator-binding operator env)
	    (compiler-call #'compile-apply-lexical-funobj :forward all))
	   (t (compiler-call #'compile-apply-symbol :forward all))))
	 (t (error "Don't know how to compile compound form ~A" form)))))))

(define-compiler compile-compiler-macro-form (&all all &form form &env env)
  (compiler-call #'compile-form-unprotected
    :forward all
    :form (funcall *movitz-macroexpand-hook*
		   (movitz-compiler-macro-function (car form) env)
		   form env)))

(define-compiler compile-macro-form (&all all &form form &env env)
  "3.1.2.1.2.2 Macro Forms"
  (let* ((operator (car form))
	 (macro-function (movitz-macro-function operator env)))
    (compiler-call #'compile-form-unprotected
      :forward all
      :form (funcall *movitz-macroexpand-hook* macro-function form env))))

(define-compiler compile-lexical-macro-form (&all all &form form &env env)
  "Compiles MACROLET and SYMBOL-MACROLET forms."
  (compiler-call #'compile-form-unprotected
    :forward all
    :form (funcall *movitz-macroexpand-hook*
		   (macro-binding-expander (movitz-operator-binding form env))
		   form env)))

(defun like-compile-macroexpand-form (form env)
  (typecase form
    ;; (symbol (compile-macroexpand-symbol form funobj env top-level-p result-mode))
    (cons   (like-compile-macroexpand-cons form env))
    (t      (values form nil))))

(defun like-compile-macroexpand-cons (form env)
  "3.1.2.1.2 Conses as Forms"
  (let* ((operator (car form))
	 (notinline (movitz-env-get operator 'notinline nil env))
	 (compiler-macro-function (movitz-compiler-macro-function operator env))
	 (compiler-macro-expansion (and compiler-macro-function
					(funcall *movitz-macroexpand-hook*
						 compiler-macro-function
						 form env))))
    (cond
     ((and (not notinline)
	   compiler-macro-function
	   (not (eq form compiler-macro-expansion)))
      (values compiler-macro-expansion t))
     ((symbolp operator)
      (cond
       ((movitz-macro-function operator env)
	(values (funcall *movitz-macroexpand-hook*
			 (movitz-macro-function operator env)
			 form env)
		t))
       (t form)))
     (t form))))

(defun make-compiled-stack-restore (stack-displacement result-mode returns)
  "Return the code required to reset the stack according to stack-displacement,
result-mode, and returns (which specify the returns-mode of the immediately
preceding code). As secondary value, returns the new :returns value."
  (flet ((restore-by-pop (scratch)
	   (case stack-displacement
	     (1 `((:popl ,scratch)))
	     (2 `((:popl ,scratch) (:popl ,scratch))))))
    (if (zerop stack-displacement)
	(values nil returns)
      (ecase (result-mode-type result-mode)
	(:function
	 (values nil returns))
	((:multiple-values :values)
	 (ecase returns
	   (:multiple-values
	    (values `((:leal (:esp ,(* 4 stack-displacement)) :esp))
		    :multiple-values))
	   ((:single-value :eax :ebx)
	    (values `((:addl ,(* 4 stack-displacement) :esp))
		    :multiple-values)))) ; assume this addl will set CF=0
	((:single-value :eax :ebx :ecx :edx :push :lexical-binding :untagged-fixnum-ecx
	  :boolean :boolean-branch-on-false :boolean-branch-on-true)
	 (ecase returns
	   (#.+boolean-modes+
	    (values (or (restore-by-pop :eax)
			`((:leal (:esp ,(* 4 stack-displacement)) :esp))) ; preserve all flags
		    returns))
	   (:ebx
	    (values (or (restore-by-pop :eax)
			`((:addl ,(* 4 stack-displacement) :esp)))
		    :ebx))
	   ((:multiple-values :single-value :eax)
	    (values (or (restore-by-pop :ebx)
			`((:addl ,(* 4 stack-displacement) :esp)))
		    :eax))))
	(:ignore
	 (values (or (restore-by-pop :eax)
		     `((:addl ,(* 4 stack-displacement) :esp)))
		 :nothing))))))

(define-compiler compile-apply-symbol (&form form &funobj funobj &env env
					     &result-mode result-mode)
  "3.1.2.1.2.3 Function Forms"
  (destructuring-bind (operator &rest arg-forms)
      form
    #+ignore (when (and (eq result-mode :function)
			(eq operator (movitz-print (movitz-funobj-name funobj))))
	       (warn "Tail-recursive call detected."))
    (when (eq operator 'muerte.cl::declare)
      (break "Compiling funcall to ~S" 'muerte.cl::declare))
    (pushnew (cons operator muerte.cl::*compile-file-pathname*)
	     (image-called-functions *image*)
	     :key #'first)
    (multiple-value-bind (arguments-code stack-displacement arguments-modifies)
	(make-compiled-argument-forms arg-forms funobj env)
      (multiple-value-bind (stack-restore-code new-returns)
	  (make-compiled-stack-restore stack-displacement result-mode :multiple-values)
	(compiler-values ()
	  :returns new-returns
	  :functional-p nil
	  :modifies arguments-modifies
	  :code (append arguments-code
			(if (and (not *compiler-relink-recursive-funcall*)
				 (eq (movitz-read operator)
				     (movitz-read (movitz-funobj-name funobj)))) ; recursive?
			    (make-compiled-funcall-by-esi (length arg-forms))
			  (make-compiled-funcall-by-symbol operator (length arg-forms) funobj))
			stack-restore-code))))))
	  
(define-compiler compile-apply-lexical-funobj (&all all &form form &funobj funobj &env env
						    &result-mode result-mode)
  "3.1.2.1.2.3 Function Forms"
  (destructuring-bind (operator &rest arg-forms)
      form
    (let ((binding (movitz-operator-binding operator env)))
      (multiple-value-bind (arguments-code stack-displacement)
	  (make-compiled-argument-forms arg-forms funobj env)
	(multiple-value-bind (stack-restore-code new-returns)
	    (make-compiled-stack-restore stack-displacement result-mode :multiple-values)
	  (compiler-values ()
	    :returns new-returns
	    :functional-p nil
	    :code (append arguments-code
			  (if (eq funobj (function-binding-funobj binding))
			      (make-compiled-funcall-by-esi (length arg-forms)) ; call ourselves
			    `((:call-lexical ,binding ,(length arg-forms))))
			  stack-restore-code)))))))

(defun make-compiled-funcall-by-esi (num-args)
  (case num-args
    (1 `((:call (:esi ,(slot-offset 'movitz-funobj 'code-vector%1op)))))
    (2 `((:call (:esi ,(slot-offset 'movitz-funobj 'code-vector%2op)))))
    (3 `((:call (:esi ,(slot-offset 'movitz-funobj 'code-vector%3op)))))
    (t (append (if (< num-args #x80)
		   `((:movb ,num-args :cl))
		 (make-immediate-move (dpb num-args (byte 24 8) #x80) :ecx))
					; call new ESI's code-vector
	       `((:call (:esi ,(slot-offset 'movitz-funobj 'code-vector))))))))
  
(defun make-compiled-funcall-by-symbol (apply-symbol num-args funobj)
  (declare (ignore funobj))
  (check-type apply-symbol symbol)
  `((:load-constant ,(movitz-read apply-symbol) :edx) ; put function symbol in EDX
    (:movl (:edx ,(slot-offset 'movitz-symbol 'function-value))
	   :esi)			; load new funobj from symbol into ESI
    ,@(make-compiled-funcall-by-esi num-args)))

(defun make-compiled-funcall-by-funobj (apply-funobj num-args funobj)
  (declare (ignore funobj))
  (check-type apply-funobj movitz-funobj)
  (compiler-values ()
    :returns :multiple-values
    :functional-p :nil
    :code `(				; put function funobj in ESI
	    (:load-constant ,apply-funobj :esi)
	    ,@(make-compiled-funcall-by-esi num-args))))

(defun make-compiled-argument-forms (argument-forms funobj env)
  "Return code as primary value, and stack displacement as secondary value.
Return the set of modified lexical bindings third. Fourth, a list of the individual
compile-time types of each argument. Fifth: The combined functional-p."
  ;; (incf (aref *args* (min (length argument-forms) 9)))
  (case (length argument-forms)	;; "optimized" versions for 0, 1, 2, and 3 aruments.
    (0 (values nil 0 nil () t))
    (1 (compiler-values-bind (&code code &type type &functional-p functional-p)
	   (compiler-call #'compile-form
	     :form (first argument-forms)
	     :funobj funobj
	     :env env
	     :result-mode :eax)
	 (values code 0 t (list (type-specifier-primary type)) functional-p)))
    (2 (multiple-value-bind (code functional-p modified first-values second-values)
	   (make-compiled-two-forms-into-registers (first argument-forms) :eax
						   (second argument-forms) :ebx
						   funobj env)
	 (values code 0 modified
		 (list (type-specifier-primary (compiler-values-getf first-values :type))
		       (type-specifier-primary (compiler-values-getf second-values :type)))
		 functional-p)))
    (t (let* ((arguments-self-evaluating-p t)
	      (arguments-are-load-lexicals-p t)
	      (arguments-lexical-variables ())
	      (arguments-modifies nil)
	      (arguments-functional-p t)
	      (arguments-types nil)
	      (producers nil)
	      (stack-pos 0)
	      (arguments-code
	       (loop for form in (nthcdr 2 argument-forms)
		   appending
		     (compiler-values-bind (&code code &producer producer &modifies modifies &type type
					    &functional-p functional-p)
			 (compiler-call #'compile-form
			   :form form
			   :funobj funobj
			   :env env
			   :result-mode :push
			   :with-stack-used (post-incf stack-pos))
		       ;; (incf (stack-used arg-env))
		       (unless functional-p
			 (setf arguments-functional-p nil))
		       (push producer producers)
		       (push (type-specifier-primary type)
			     arguments-types)
		       (setf arguments-modifies
			 (modifies-union arguments-modifies modifies))
		       (case producer
			 (compile-self-evaluating)
			 (compile-lexical-variable
			  (setf arguments-self-evaluating-p nil)
			  (assert (eq :load-lexical (caar code)) ()
			    "comp-lex-var produced for ~S~% ~S" form code)
			  (pushnew (cadar code) arguments-lexical-variables))
			 (t (setf arguments-self-evaluating-p nil
				  arguments-are-load-lexicals-p nil)))
			 code))))
	 (multiple-value-bind (code01 functionalp01 modifies01 all0 all1)
	     (make-compiled-two-forms-into-registers (first argument-forms) :eax
						     (second argument-forms) :ebx
						     funobj env)
	   (unless functionalp01
	     (setf arguments-functional-p nil))
	   (let ((final0 (compiler-values-getf all0 :final-form))
		 (final1 (compiler-values-getf all1 :final-form))
		 (types (list* (type-specifier-primary (compiler-values-getf all0 :type))
			       (type-specifier-primary (compiler-values-getf all1 :type))
			       (nreverse arguments-types))))
	     (cond
	      ((or arguments-self-evaluating-p
		   (and (typep final0 'lexical-binding)
			(typep final1 'lexical-binding)))
	       (values (append arguments-code code01)
		       ;; restore stack..
		       (+ -2 (length argument-forms))
		       nil
		       types
		       arguments-functional-p))
	      ((and arguments-are-load-lexicals-p
		    (typep final0 '(or lexical-binding movitz-object))
		    (typep final1 '(or lexical-binding movitz-object)))
	       (values (append arguments-code code01)
		       (+ -2 (length argument-forms))
		       nil
		       types
		       arguments-functional-p))
	      ((and arguments-are-load-lexicals-p
		    (not (some (lambda (arg-binding)
				 (code-uses-binding-p code01 arg-binding :store t :load nil))
			       arguments-lexical-variables)))
	       (values (append arguments-code code01)
		       (+ -2 (length argument-forms))
		       nil
		       types
		       arguments-functional-p))
	      (t ;; (warn "fail: ~S by ~S" argument-forms (nreverse producers))
	       (let ((stack-pos 0))
		 (values (append (compiler-call #'compile-form
				   :form (first argument-forms)
				   :funobj funobj
				   :env env
				   :top-level-p nil
				   :result-mode :push
				   :with-stack-used (post-incf stack-pos))
				 ;; (prog1 nil (incf (stack-used arg-env)))
				 (compiler-call #'compile-form
				   :form (second argument-forms)
				   :funobj funobj
				   :env env
				   :top-level-p nil
				   :result-mode :push
				   :with-stack-used (post-incf stack-pos))
				 ;; (prog1 nil (incf (stack-used arg-env)))
				 (loop for form in (nthcdr 2 argument-forms)
				     appending
				       (compiler-call #'compile-form
					 :form form
					 :funobj funobj
					 :env env
					 :result-mode :push
					 :with-stack-used (post-incf stack-pos)))
				 `((:movl (:esp ,(* 4 (- (length argument-forms) 1))) :eax)
				   (:movl (:esp ,(* 4 (- (length argument-forms) 2))) :ebx)))
			 ;; restore-stack.. don't mess up CF!
			 (prog1 (length argument-forms)
			   #+ignore (assert (= (length argument-forms) (stack-used arg-env))))
			 (modifies-union modifies01 arguments-modifies)
			 types
			 arguments-functional-p))))))))))

(defun program-is-load-lexical-of-binding (prg)
  (and (not (cdr prg))
       (instruction-is-load-lexical-of-binding (car prg))))

(defun instruction-is-load-lexical-of-binding (instruction)
  (and (listp instruction)
       (eq :load-lexical (car instruction))
       (destructuring-bind (binding destination &key &allow-other-keys)
	   (operands instruction)
	 (values binding destination))))

(defun program-is-load-constant (prg)
  (and (not (cdr prg))
       (let ((i (car prg)))
	 (when (and (listp i)
		    (eq :load-constant (car i)))
	   (values (third i)
		   (second i))))))


(defun make-compiled-two-forms-into-registers (form0 reg0 form1 reg1 funobj env)
  "Returns first: code that does form0 into reg0, form1 into reg1.
second: whether code is functional-p,
third: combined set of modified bindings
fourth: all compiler-values for form0, as a list.
fifth:  all compiler-values for form1, as a list."
  (assert (not (eq reg0 reg1)))
  (compiler-values-bind (&all all0 &code code0 &functional-p functional0
			 &final-form final0 &type type0)
      (compiler-call #'compile-form
	:form form0
	:funobj funobj
	:env env
	:result-mode reg0)
    (compiler-values-bind (&all all1 &code code1 &functional-p functional1
			   &final-form final1 &type type1)
	(compiler-call #'compile-form
	  :form form1
	  :funobj funobj
	  :env env
	  :result-mode reg1)
      (values (cond
		((and (typep final0 'binding)
		      (not (code-uses-binding-p code1 final0 :load nil :store t)))
		 (append (compiler-call #'compile-form-unprotected
					:form form0
					:result-mode :ignore
					:funobj funobj
					:env env)
			 code1
			 `((:load-lexical ,final0 ,reg0 :protect-registers (,reg1)))))
		((program-is-load-lexical-of-binding code1)
		 (destructuring-bind (src dst &key protect-registers shared-reference-p)
		     (cdar code1)
		   (assert (eq reg1 dst))
		   (append code0
			   `((:load-lexical ,src ,reg1
					    :protect-registers ,(union protect-registers
								       (list reg0))
					    :shared-reference-p ,shared-reference-p)))))
		((eq reg1 (program-is-load-constant code1))
		 (append code0
			 code1))
		;; XXX if we knew that code1 didn't mess up reg0, we could do more..
		(t
;; 		 (when (and (not (tree-search code1 reg0))
;; 			    (not (tree-search code1 :call)))
;; 		   (warn "got b: ~S ~S for ~S: ~{~&~A~}" form0 form1 reg0 code1))
		 (let ((binding (make-instance 'temporary-name :name (gensym "tmp-")))
		       (xenv (make-local-movitz-environment env funobj)))
		   (movitz-env-add-binding xenv binding)
		   (append (compiler-call #'compile-form
					  :form form0
					  :funobj funobj
					  :env env
					  :result-mode reg0)
			   `((:init-lexvar ,binding :init-with-register ,reg0
						    :init-with-type ,(type-specifier-primary type0)))
			   (compiler-call #'compile-form
					  :form form1
					  :funobj funobj
					  :env xenv
					  :result-mode reg1)
			   `((:load-lexical ,binding ,reg0))))))
	      (and functional0 functional1)
	      t
	      (compiler-values-list (all0))
	      (compiler-values-list (all1))))))

(define-compiler compile-symbol (&all all &form form &env env &result-mode result-mode)
  "3.1.2.1.1 Symbols as Forms"
  (if (movitz-constantp form env)
      (compiler-call #'compile-self-evaluating
	:forward all
	:form (eval-form form env))
    (let ((binding (movitz-binding form env)))
      (cond
       ((typep binding 'lexical-binding)
	#+ignore (make-compiled-lexical-variable form binding result-mode env)
	(compiler-call #'compile-lexical-variable :forward all))
       ((typep binding 'symbol-macro-binding)
	(compiler-call #'compile-form-unprotected
	  :forward all
	  :form (funcall *movitz-macroexpand-hook*
			 (macro-binding-expander (movitz-binding form env)) form env)))
       (t (compiler-call #'compile-dynamic-variable :forward all))))))

(define-compiler compile-lexical-variable (&form variable &result-mode result-mode &env env)
  (let ((binding (movitz-binding variable env)))
    (check-type binding lexical-binding)
    (case (operator result-mode)
      (:ignore
       (compiler-values ()
	 :final-form binding))
      (t (compiler-values ()
	   :code nil
	   :final-form binding
	   :returns binding
	   :functional-p t)))))

(defun make-compiled-lexical-load (binding result-mode &rest key-args)
  "Do what is necessary to load lexical binding <binding>."
  `((:load-lexical ,binding ,result-mode ,@key-args)))

(define-compiler compile-dynamic-variable (&form form &env env &result-mode result-mode)
  "3.1.2.1.1.2 Dynamic Variables"
  (if (eq :ignore result-mode)
      (compiler-values ())
    (let ((binding (movitz-binding form env)))
      (cond
       ((not binding)
	(unless (movitz-env-get form 'special nil env)
	  #+ignore (cerror "Compile like a special." "Undeclared variable: ~S." form)
	  (warn "Undeclared variable: ~S." form))
	(compiler-values ()
	  :returns :eax
	  :functional-p t
	  :modifies nil
	  :final-form form
	  :code (if *compiler-use-into-unbound-protocol*
		    `((:load-constant ,form :ebx)
		      (,*compiler-local-segment-prefix*
		       :call (:edi ,(global-constant-offset 'dynamic-variable-lookup)))
		      (:cmpl -1 :eax)
		      (:into))
		  (let ((not-unbound (gensym "not-unbound-")))
		    `((:load-constant ,form :ebx)
		      (,*compiler-local-segment-prefix*
		       :call (:edi ,(global-constant-offset 'dynamic-variable-lookup)))
		      (,*compiler-local-segment-prefix*
		       :cmpl :eax (:edi ,(global-constant-offset 'unbound-value)))
		      (:jne ',not-unbound)
		      (:int 99)
		      ,not-unbound)))))
       (t (check-type binding dynamic-binding)
	  (compiler-values ()
	    :returns :eax
	    :functional-p t
	    :modifies nil
	    :final-form form
	    :code (if *compiler-use-into-unbound-protocol*
		    `((:load-constant ,form :ebx)
		      (,*compiler-local-segment-prefix*
		       :call (:edi ,(global-constant-offset 'dynamic-variable-lookup)))
		      (:cmpl -1 :eax)
		      (:into))
		  (let ((not-unbound (gensym "not-unbound-")))
		    `((:load-constant ,form :ebx)
		      (,*compiler-local-segment-prefix*
		       :call (:edi ,(global-constant-offset 'dynamic-variable-lookup)))
		      (,*compiler-local-segment-prefix*
		       :cmpl :eax (:edi ,(global-constant-offset 'unbound-value)))
		      (:jne ',not-unbound)
		      (:int 99)
		      ,not-unbound)))))))))

(define-compiler compile-lambda-form (&form form &all all)
  "3.1.2.2.4 Lambda Forms"
  (let ((lambda-expression (car form))
	(lambda-args (cdr form)))
    (compiler-call #'compile-form-unprotected
      :forward all
      :form `(muerte.cl:funcall ,lambda-expression ,@lambda-args))))

(define-compiler compile-constant-compound (&all all &form form &env env &top-level-p top-level-p)
  (compiler-call #'compile-self-evaluating
    :forward all
    :form (eval-form form env top-level-p)))

(defun register32-to-low8 (register)
  (ecase register
    (:eax :al)
    (:ebx :bl)
    (:ecx :cl)
    (:edx :dl)))

(defun make-immediate-move (value destination-register)
  (cond
   ((zerop value)
    `((:xorl ,destination-register ,destination-register)))
   ((= value (image-nil-word *image*))
    `((:movl :edi ,destination-register)))
   ((<= #x-80 (- value (image-nil-word *image*)) #x7f)
    `((:leal (:edi ,(- value (image-nil-word *image*))) ,destination-register)))
   ((<= #x-80 (- value (* 2 (image-nil-word *image*))) #x7f)
    `((:leal (:edi (:edi 1) ,(- value (* 2 (image-nil-word *image*)))) ,destination-register)))
   ((<= #x-80 (- value (* 3 (image-nil-word *image*))) #x7f)
    `((:leal (:edi (:edi 2) ,(- value (* 3 (image-nil-word *image*)))) ,destination-register)))
   ((<= #x-80 (- value (* 5 (image-nil-word *image*))) #x7f)
    `((:leal (:edi (:edi 4) ,(- value (* 5 (image-nil-word *image*)))) ,destination-register)))
   ((<= #x-80 (- value (* 9 (image-nil-word *image*))) #x7f)
    `((:leal (:edi (:edi 8) ,(- value (* 9 (image-nil-word *image*)))) ,destination-register)))
   ((<= 0 value #xff)
    `((:xorl ,destination-register ,destination-register)
      (:movb ,value ,(register32-to-low8 destination-register))))
   (t `((:movl ,value ,destination-register)))))

(defparameter *prev-self-eval* nil)

(define-compiler compile-self-evaluating (&form form &result-mode result-mode &funobj funobj)
  "3.1.2.1.3 Self-Evaluating Objects"
  (let* ((object form)
	 (movitz-obj (image-read-intern-constant *image* object))
	 (funobj-env (funobj-env funobj))
	 (binding (or (cdr (assoc movitz-obj (movitz-environment-bindings funobj-env)))
		      (let ((binding (make-instance 'constant-object-binding
				       :name (gensym "self-eval-")
				       :object movitz-obj)))
			(setf (binding-env binding) funobj-env)
			(push (cons movitz-obj binding)
			      (movitz-environment-bindings funobj-env))
			binding))))
    (compiler-values-bind (&all self-eval)
	(compiler-values (nil :abstract t)
	  :producer (default-compiler-values-producer)
	  :type  `(eql ,movitz-obj)
	  :final-form binding
	  :functional-p t)	
      (case  (operator result-mode)
	(:ignore
	 (compiler-values (self-eval)
	   :returns :nothing
	   :type nil))
	(t (compiler-values (self-eval)
	     :returns binding))))))

(define-compiler compile-implicit-progn (&all all &form forms &top-level-p top-level-p
					      &result-mode result-mode)
  "Compile all the elements of the list <forms> as a progn."
  (check-type forms list)
  (case (length forms)
    (0 (compiler-values ()))
    (1 (compiler-call #'compile-form-unprotected
	 :forward all
	 :form (first forms)))
    (t (loop with no-side-effects-p = t
	   with progn-codes = nil
	   for (sub-form . more-forms-p) on forms
	   as current-result-mode = (if more-forms-p :ignore result-mode)
	   do (compiler-values-bind (&code code &returns sub-returns-mode
				     &functional-p no-sub-side-effects-p
				     &type type &final-form final-form &producer sub-producer)
		  (compiler-call (if (not more-forms-p)
				     #'compile-form-unprotected
				   #'compile-form)
		    :defaults all
		    :form sub-form
		    :top-level-p top-level-p
		    :result-mode current-result-mode)
		(assert sub-returns-mode ()
		  "~S produced no returns-mode for form ~S." sub-producer sub-form)
		(unless no-sub-side-effects-p
		  (setf no-side-effects-p nil))
		(push (if (and no-sub-side-effects-p (eq current-result-mode :ignore))
			  nil
			code)
		      progn-codes)
		(when (not more-forms-p)
		  (return (compiler-values ()
			    :returns sub-returns-mode
			    :functional-p no-side-effects-p
			    :final-form final-form
			    :type type
			    :code (reduce #'append (nreverse progn-codes))))))))))


(defun new-make-compiled-constant-reference (obj funobj)
  (let ((movitz-obj (movitz-read obj)))
    (if (eq movitz-obj (image-t-symbol *image*))
	(make-indirect-reference :edi (global-constant-offset 't-symbol))
      (etypecase movitz-obj
	(movitz-null :edi)
	(movitz-immediate-object (movitz-immediate-value movitz-obj))
	(movitz-heap-object 
	 (make-indirect-reference :esi (movitz-funobj-intern-constant funobj movitz-obj)))))))

(defun make-compiled-lexical-control-transfer (return-code return-mode from-env to-env
					       &optional (to-label (exit-label to-env)))
  "<return-code> running in <from-env> produces <return-mode>, and we need to
generate code that transfers control (and unwinds dynamic bindings, runs unwind-protect
cleanup-forms etc.) to <to-env> with <return-code>'s result intact."
  (check-type to-env lexical-exit-point-env)
  (multiple-value-bind (stack-distance num-dynamic-slots unwind-protects)
      (stack-delta from-env to-env)
    (assert stack-distance)
    (assert (null unwind-protects) ()
      "Lexical unwind-protect not implemented, to-env: ~S. (this is not supposed to happen)"
      to-env)
    ;; (warn "dist: ~S, slots: ~S" stack-distance num-dynamic-slots)
    (assert (not (eq t num-dynamic-slots)) ()
      "Don't know how to make lexical-control-transfer across unknown number of dynamic slots.")
    (cond
     ((and (eq t stack-distance)
	   (eql 0 num-dynamic-slots))
      (compiler-values ()
	:returns :non-local-exit
	:code (append return-code
		      (unless (eq :function (exit-result-mode to-env))
			`((:load-lexical ,(movitz-binding (save-esp-variable to-env) to-env nil) :esp)))
		      `((:jmp ',to-label)))))
     ((eq t stack-distance)
      (compiler-values ()
	:returns :non-local-exit
	:code (append return-code
		      (compiler-call #'special-operator-with-cloak
			:env to-env
			:result-mode (exit-result-mode to-env)
			:form `(muerte::with-cloak (,return-mode)
				 (muerte::with-inline-assembly (:returns :nothing)
				   ;; Compute target dynamic-env
				   (:locally (:movl (:edi (:edi-offset dynamic-env)) :eax))
				   ,@(loop repeat num-dynamic-slots
					 collect `(:movl (:eax 12) :eax))
				   (:locally (:call (:edi (:edi-offset dynamic-unwind-next))))
				   (:locally (:movl :eax (:edi (:edi-offset dynamic-env))))
				   (:jc '(:sub-program () (:int 63))))))
		      `((:load-lexical ,(movitz-binding (save-esp-variable to-env) to-env nil) :esp)
			(:jmp ',to-label)))))
     ((zerop num-dynamic-slots)
      (compiler-values ()
	:returns :non-local-exit
	:code (append return-code
		      (make-compiled-stack-restore stack-distance
						   (exit-result-mode to-env)
						   return-mode)
		      `((:jmp ',to-label)))))
     ((plusp num-dynamic-slots)
      ;; (warn "num-dynamic-slots: ~S, distance: ~D" num-dynamic-slots stack-distance)
      (compiler-values ()
	:returns :non-local-exit
	:code (append return-code
		      (compiler-call #'special-operator-with-cloak
			:env to-env
			:result-mode (exit-result-mode to-env)
			:form `(muerte::with-cloak (,return-mode)
				 (muerte::with-inline-assembly (:returns :nothing)
				   ;; Compute target dynamic-env
				   (:locally (:movl (:edi (:edi-offset dynamic-env)) :eax))
				   ,@(loop repeat num-dynamic-slots
					 collect `(:movl (:eax 12) :eax))
				   (:locally (:call (:edi (:edi-offset dynamic-unwind-next))))
				   (:locally (:movl :eax (:edi (:edi-offset dynamic-env))))
				   (:jc '(:sub-program () (:int 63))))))
		      `((:leal (:esp ,(* 4 stack-distance)) :esp)
			(:jmp ',to-label)))))
     (t (error "unknown!")))))

(defun make-compiled-push-current-values ()
  "Return code that pushes the current values onto the stack, and returns
in ECX the number of values (as fixnum)."
  (let ((not-single-value (gensym "not-single-value-"))
	(push-values-done (gensym "push-values-done-"))
	(push-values-loop (gensym "push-values-loop-")))
    `((:jc ',not-single-value)
      (:movl 4 :ecx)
      (:pushl :eax)
      (:jmp ',push-values-done)
      ,not-single-value
      (:shll ,+movitz-fixnum-shift+ :ecx)
      (:jz ',push-values-done)
      (:xorl :edx :edx)
      (:pushl :eax)
      (:addl 4 :edx)
      (:cmpl :edx :ecx)
      (:je ',push-values-done)
      (:pushl :ebx)
      (:addl 4 :edx)
      (:cmpl :edx :ecx)
      (:je ',push-values-done)
      ,push-values-loop
      (:locally (:pushl (:edi (:edi-offset values) :edx -8)))
      (:addl 4 :edx)
      (:cmpl :edx :ecx)
      (:jne ',push-values-loop)
      ,push-values-done)))

(defun stack-add (x y)
  (if (and (integerp x) (integerp y))
      (+ x y)
    t))

(define-modify-macro stack-incf (&optional (delta 1)) stack-add)

(defun stack-delta (inner-env outer-env)
  "Calculate the amount of stack-space used (in 32-bit stack slots) at the time
of <inner-env> since <outer-env>,
the number of intervening dynamic-slots (special bindings, unwind-protects, and catch-tags),
and a list of any intervening unwind-protect environment-slots."
  (labels 
      ((find-stack-delta (env stack-distance num-dynamic-slots unwind-protects)
	 #+ignore (warn "find-stack-delta: ~S dist ~S, slots ~S" env
			(stack-used env) (num-dynamic-slots env))
	 (cond
	  ((eq outer-env env)
	   ;; Each dynamic-slot is 4 stack-distances, so let's check that..
	   (assert (or (eq t stack-distance)
		       (>= stack-distance (* 4 num-dynamic-slots))) ()
	     "The stack-distance ~D is smaller than number of dynamic-slots ~D, which is inconsistent."
	     stack-distance num-dynamic-slots)
	   (values stack-distance num-dynamic-slots unwind-protects))
	  ((null env)
	   (values nil 0 nil))
	  (t (find-stack-delta (movitz-environment-uplink env)
			       (stack-add stack-distance (stack-used env))
			       (stack-add num-dynamic-slots (num-dynamic-slots env))
			       (if (typep env 'unwind-protect-env)
				   (cons env unwind-protects)
				 unwind-protects))))))
    (find-stack-delta inner-env 0 0 nil)))

(defun print-stack-delta (inner-env outer-env)
  (labels ((print-stack-delta (env)
	     (cond
	      ((or (eq outer-env env)
		   (null env)))
	      (t (format t "~&Env: ~S used: ~S, slots: ~S"
			 env (stack-used env) (num-dynamic-slots env))
		 (print-stack-delta (movitz-environment-uplink env))))))
    (print-stack-delta inner-env)))

;;;;;;;
;;;;;;; Extended-code declarations
;;;;;;;

(defvar *extended-code-find-read-binding*
    (make-hash-table :test #'eq))

(defvar *extended-code-find-used-bindings*
    (make-hash-table :test #'eq))

(defmacro define-find-read-bindings (name lambda-list &body body)
  (let ((defun-name (intern
		     (with-standard-io-syntax
		       (format nil "~A-~A" 'find-read-bindings name)))))
    `(progn
       (setf (gethash ',name *extended-code-find-read-binding*) ',defun-name)
       (defun ,defun-name (instruction)
	 (destructuring-bind ,lambda-list
	     (cdr instruction)
	   ,@body)))))

(defmacro define-find-used-bindings (name lambda-list &body body)
  (let ((defun-name (intern
		     (with-standard-io-syntax
		       (format nil "~A-~A" 'find-used-bindings name)))))
    `(progn
       (setf (gethash ',name *extended-code-find-used-bindings*) ',defun-name)
       (defun ,defun-name (instruction)
	 (destructuring-bind ,lambda-list
	     (cdr instruction)
	   ,@body)))))

(defun find-used-bindings (extended-instruction)
  "Return zero, one or two bindings that this instruction reads."
  (when (listp extended-instruction)
    (let* ((operator (car extended-instruction))
	   (finder (or (gethash operator *extended-code-find-used-bindings*)
		       (gethash operator *extended-code-find-read-binding*))))
      (when finder
	(let ((result (funcall finder extended-instruction)))
	  (check-type result list "a list of read bindings")
	  result)))))

(defun find-read-bindings (extended-instruction)
  "Return zero, one or two bindings that this instruction reads."
  (when (listp extended-instruction)
    (let* ((operator (car extended-instruction))
	   (finder (gethash operator *extended-code-find-read-binding*)))
      (when finder
	(funcall finder extended-instruction)))))

(defmacro define-find-write-binding-and-type (name lambda-list &body body)
  (let ((defun-name (intern
		     (with-standard-io-syntax
		       (format nil "~A-~A" 'find-write-binding-and-type name)))))
    `(progn
       (setf (gethash ',name *extended-code-find-write-binding-and-type*) ',defun-name)
       (defun ,defun-name ,lambda-list ,@body))))

(defun find-written-binding-and-type (extended-instruction)
  (when (listp extended-instruction)
    (let* ((operator (car extended-instruction))
	   (finder (gethash operator *extended-code-find-write-binding-and-type*)))
      (when finder
	(funcall finder extended-instruction)))))

(defmacro define-extended-code-expander (name lambda-list &body body)
  (let ((defun-name (intern
		     (with-standard-io-syntax
		       (format nil "~A-~A" 'extended-code-expander- name)))))
    `(progn
       (setf (gethash ',name *extended-code-expanders*) ',defun-name)
       (defun ,defun-name ,lambda-list ,@body))))

(defun can-expand-extended-p (extended-instruction frame-map)
  "Given frame-map, can we expand i at this point?"
  (and (every (lambda (b)
		(or (typep (binding-target b) 'constant-object-binding)
		    (new-binding-located-p (binding-target b) frame-map)))
	      (find-read-bindings extended-instruction))
       (let ((written-binding (find-written-binding-and-type extended-instruction)))
	 (or (not written-binding)
	     (new-binding-located-p (binding-target written-binding) frame-map)))))

(defun expand-extended-code (extended-instruction funobj frame-map)
  (if (not (listp extended-instruction))
      (list extended-instruction)
    (let* ((operator (car extended-instruction))
	   (expander (gethash operator *extended-code-expanders*)))
      (if (not expander)
	  (list extended-instruction)
	(let ((expansion (funcall expander extended-instruction funobj frame-map)))
	  (mapcan (lambda (e)
		    (expand-extended-code e funobj frame-map))
		  expansion))))))

(defun ensure-local-binding (binding funobj)
  "When referencing binding in funobj, ensure we have the binding local to funobj."
  (if (typep binding '(or (not binding) constant-object-binding funobj-binding))
      binding ; Never mind if "binding" isn't a binding, or is a constant-binding.
      (let ((target-binding (binding-target binding)))
        (cond
          ((eq funobj (binding-funobj target-binding))
           binding)
          (t (or (find target-binding (borrowed-bindings funobj)
                  :key (lambda (binding)
                         (borrowed-binding-target binding)))
                 (error "Can't install non-local binding ~W." binding)))))))

(defun binding-store-subtypep (binding type-specifier)
  "Is type-specifier a supertype of all values ever stored to binding?
   (Assuming analyze-bindings has put this information into binding-store-type.)"
  (if (not (binding-store-type binding))
      nil
    (multiple-value-call #'encoded-subtypep
      (values-list (binding-store-type binding))
      (type-specifier-encode type-specifier))))

(defun binding-singleton (binding)
  (let ((btype (binding-store-type binding)))
    (when btype
      (type-specifier-singleton (apply #'encoded-type-decode btype)))))

;;;;;;;
;;;;;;; Extended-code handlers
;;;;;;;


;;;;;;;;;;;;;;;;;; Load-lexical

(define-find-write-binding-and-type :load-lexical (instruction)
  (destructuring-bind (source destination &key &allow-other-keys)
      (cdr instruction)
    (when (typep destination 'binding)
      (values destination t #+ignore (binding-type-specifier source)
	      (lambda (source-type)
		source-type)
	      (list source)))))

(define-find-read-bindings :load-lexical (source destination &key &allow-other-keys)
  (check-type source binding)
  (values (list source)
	  (list destination)))

(define-extended-code-expander :load-lexical (instruction funobj frame-map)
  (destructuring-bind (source destination &key shared-reference-p tmp-register protect-registers)
      (cdr instruction)
    (make-load-lexical (ensure-local-binding source funobj)
		       (ensure-local-binding destination funobj)
		       funobj shared-reference-p frame-map
		       :tmp-register tmp-register
		       :protect-registers protect-registers)))


;;;;;;;;;;;;;;;;;; Lisp-move

(define-find-write-binding-and-type :lmove (instruction)
  (destructuring-bind (source destination)
      (cdr instruction)
    (values destination source)))

(define-find-read-bindings :lmove (source destination)
  (declare (ignore destination))
  (list source))

;;;;;;;;;;;;;;;;;; Store-lexical

(define-find-write-binding-and-type :store-lexical (instruction)
  (destructuring-bind (destination source &key (type (error "No type")) &allow-other-keys)
      (cdr instruction)
    (declare (ignore source))
    (check-type destination binding)
    (values destination type)))

(define-find-read-bindings :store-lexical (destination source &key &allow-other-keys)
  (declare (ignore destination))
  (when (typep source 'binding)
    (list source)))

(define-extended-code-expander :store-lexical (instruction funobj frame-map)
  (destructuring-bind (destination source &key shared-reference-p type protect-registers)
      (cdr instruction)
    (declare (ignore type))
    (make-store-lexical (ensure-local-binding destination funobj)
			(ensure-local-binding source funobj)
			shared-reference-p funobj frame-map
			:protect-registers protect-registers)))

;;;;;;;;;;;;;;;;;; Init-lexvar

(define-find-write-binding-and-type :init-lexvar (instruction)
  (destructuring-bind (binding &key init-with-register init-with-type
				    protect-registers protect-carry
				    shared-reference-p)
      (cdr instruction)
    (declare (ignore protect-registers protect-carry shared-reference-p))
    (cond
     (init-with-register
      (cond
       ((not (typep init-with-register 'binding))
	(assert init-with-type)
	(values binding init-with-type)	)
       ((and init-with-type (not (bindingp init-with-type)))
	(values binding init-with-type))
       ((and init-with-type
	     (bindingp init-with-type)
	     (binding-store-type init-with-type))
	(apply #'encoded-type-decode (binding-store-type init-with-type)))
       (t (values binding t
		  (lambda (x) x)
		  (list init-with-register)))))
     ((not (typep binding 'temporary-name))
      (values binding t)))))

(define-find-read-bindings :init-lexvar (binding &key init-with-register &allow-other-keys)
  (declare (ignore binding))
  (when (typep init-with-register 'binding)
    (list init-with-register)))

(define-extended-code-expander :init-lexvar (instruction funobj frame-map)
  (destructuring-bind (binding &key protect-registers protect-carry
				    init-with-register init-with-type
				    shared-reference-p)
      (cdr instruction)
    (declare (ignore protect-carry))	; nothing modifies carry anyway.
    ;; (assert (eq binding (ensure-local-binding binding funobj)))
    (assert (eq funobj (binding-funobj binding)))
    (cond
     ((not (new-binding-located-p binding frame-map))
      (unless (or (movitz-env-get (binding-name binding) 'ignore nil (binding-env binding))
		  (movitz-env-get (binding-name binding) 'ignorable nil (binding-env binding)))))
     ((typep binding 'forwarding-binding)
      ;; No need to do any initialization because the target will be initialized.
      (assert (not (binding-lended-p binding)))
      nil)
     (t (when (movitz-env-get (binding-name binding) 'ignore nil (binding-env binding))
	  (warn "Variable ~S used while declared ignored." (binding-name binding)))
	(append
	 (cond
	  ((typep binding 'rest-function-argument)
	   (assert (eq :edx init-with-register))
	   (assert (movitz-env-get (binding-name binding)
				   'dynamic-extent nil (binding-env binding))
	       ()
	     "&REST variable ~S must be dynamic-extent." (binding-name binding))
	   (setf (need-normalized-ecx-p (find-function-env (binding-env binding)
							   funobj))
	     t)
	   (let ((restify-alloca-loop (gensym "alloca-loop-"))
		 (restify-done (gensym "restify-done-"))
		 (restify-at-one (gensym "restify-at-one-"))
		 (restify-loop (gensym "restify-loop-"))
		 (save-ecx-p (key-vars-p (find-function-env (binding-env binding)
							    funobj))))
	     (append
	      ;; (make-immediate-move (function-argument-argnum binding) :edx)
	      ;; `((:call (:edi ,(global-constant-offset 'restify-dynamic-extent))))
	      ;; Make space for (1+ (* 2 (- ECX rest-pos))) words on the stack.
	      ;; Factor two is for one cons-cell per word, 1 is for 8-byte alignment.
	      (when save-ecx-p
		`((,*compiler-local-segment-prefix*
		   :movl :ecx (:edi ,(global-constant-offset 'raw-scratch0)))))
	      `((:movl :edi :edx)
		(:subl ,(function-argument-argnum binding) :ecx)
		(:jbe ',restify-done)
		(:leal ((:ecx 8) 4) :edx) ; EDX is fixnum counter
		,restify-alloca-loop
		(:pushl :edi)
		(:subl 4 :edx)
		(:jnz ',restify-alloca-loop)
		,@(when *compiler-auto-stack-checks-p*
		    `((,*compiler-local-segment-prefix*
		       :bound (:edi ,(global-constant-offset 'stack-bottom)) :esp)))
		(:leal (:esp 5) :edx)
		(:andl -7 :edx))	; Make EDX a proper consp into the alloca area.
	      (cond
	       ((= 0 (function-argument-argnum binding))
		`((:movl :eax (:edx -1))
		  (:movl :edx :eax)
		  (:subl 1 :ecx)
		  (:jz ',restify-done)
		  (:addl 8 :eax)
		  (:movl :eax (:eax -5))))
	       (t `((:movl :edx :eax))))
	      (when (>= 1 (function-argument-argnum binding))
		`((:jmp ',restify-at-one)))
	      `(,restify-loop
		(:movl (:ebp (:ecx 4) 4) :ebx)
		,restify-at-one
		(:movl :ebx (:eax -1))
		(:subl 1 :ecx)
		(:jz ',restify-done)
		(:addl 8 :eax)
		(:movl :eax (:eax -5))
		(:jmp ',restify-loop)
		,restify-done)
	      (when save-ecx-p
		`((,*compiler-local-segment-prefix*
		   :movl (:edi ,(global-constant-offset 'raw-scratch0)) :ecx)))
	      ))))
	 (cond
	  ((binding-lended-p binding)
	   (let* ((cons-position (getf (binding-lending binding)
				       :stack-cons-location))
		  (init-register (etypecase init-with-register
				   ((or lexical-binding constant-object-binding)
				    (or (find-if (lambda (r)
						   (not (member r protect-registers)))
						 '(:edx :ebx :eax))
					(error "Unable to get a register.")))
				   (keyword init-with-register)
				   (null :edi)))
		  (tmp-register (find-if (lambda (r)
					   (and (not (member r protect-registers))
						(not (eq r init-register))))
					 '(:edx :ebx :eax))))
	     (when init-with-register
	       (assert (not (null init-with-type))))
	     (assert tmp-register ()	; solve this with push eax .. pop eax if ever needed.
	       "Unable to find a tmp-register for ~S." instruction)
	     (append (when (typep init-with-register 'binding)
		       (make-load-lexical init-with-register init-register funobj
					  shared-reference-p frame-map
					  :protect-registers protect-registers))
		     `((:leal (:ebp ,(1+ (stack-frame-offset (1+ cons-position))))
			      ,tmp-register)
		       (:movl :edi (,tmp-register 3)) ; cdr
		       (:movl ,init-register (,tmp-register -1)) ; car
		       (:movl ,tmp-register
			      (:ebp ,(stack-frame-offset
				      (new-binding-location binding frame-map))))))))
	  ((typep init-with-register 'lexical-binding)
	   (make-load-lexical init-with-register binding funobj nil frame-map))
	  (init-with-register
	   (make-store-lexical binding init-with-register nil funobj frame-map))))))))

;;;;;;;;;;;;;;;;;; car

(define-find-read-bindings :cons-get (op cell dst)
  (declare (ignore op dst protect-registers))
  (when (typep cell 'binding)
    (list cell)))

(define-extended-code-expander :cons-get (instruction funobj frame-map)
  (destructuring-bind (op cell dst)
      (cdr instruction)
    (check-type dst (member :eax :ebx :ecx :edx))
    (multiple-value-bind (op-offset fast-op fast-op-ebx cl-op)
	(ecase op
	  (:car (values (binary-types:slot-offset 'movitz-cons 'car)
			'fast-car
			'fast-car-ebx
			'movitz-car))
	  (:cdr (values (binary-types:slot-offset 'movitz-cons 'cdr)
			'fast-cdr
			'fast-cdr-ebx
			'movitz-cdr)))
      (let ((binding (binding-target (ensure-local-binding (binding-target cell) funobj))))
	(etypecase binding
	  (constant-object-binding
	   (let ((x (constant-object binding)))
	     (typecase x
	       (movitz-null
		(make-load-constant *movitz-nil* dst funobj frame-map))
	       (movitz-cons
		(append (make-load-constant x dst funobj frame-map)
			`((:movl (,dst ,op-offset) ,dst))))
	       (t `(,@(make-load-lexical binding :eax funobj nil frame-map)
		      (,*compiler-global-segment-prefix* 
		       :call (:edi ,(global-constant-offset fast-op)))
		      ,@(when (not (eq dst :eax))
			  `((:movl :eax ,dst))))))))
	  (lexical-binding
	   (let ((location (new-binding-location (binding-target binding) frame-map))
		 (binding-is-list-p (binding-store-subtypep binding 'list)))
	     #+ignore (warn "~A of loc ~A bind ~A" op location binding)
	     (cond
	      ((and binding-is-list-p
		    (member location '(:eax :ebx :ecx :edx)))
	       `((,*compiler-nonlocal-lispval-read-segment-prefix*
		  :movl (,location ,op-offset) ,dst)))
	      (binding-is-list-p
	       `(,@(make-load-lexical binding dst funobj nil frame-map)
		   (,*compiler-nonlocal-lispval-read-segment-prefix*
		    :movl (,dst ,op-offset) ,dst)))
	      ((not *compiler-use-cons-reader-segment-protocol-p*)
	       (cond
		((eq location :ebx)
		 `((,*compiler-global-segment-prefix*
		    :call (:edi ,(global-constant-offset fast-op-ebx)))
		   ,@(when (not (eq dst :eax))
		       `((:movl :eax ,dst)))))
		(t `(,@(make-load-lexical binding :eax funobj nil frame-map)
		       (,*compiler-global-segment-prefix* 
			:call (:edi ,(global-constant-offset fast-op)))
		       ,@(when (not (eq dst :eax))
			   `((:movl :eax ,dst)))))))
	      (t (cond
		  ((member location '(:ebx :ecx :edx))
		   `((,(or *compiler-cons-read-segment-prefix*
			   *compiler-nonlocal-lispval-read-segment-prefix*)
		      :movl (:eax ,op-offset) ,dst)))
		  (t (append (make-load-lexical binding :eax funobj nil frame-map)
			     `((,(or *compiler-cons-read-segment-prefix*
				     *compiler-nonlocal-lispval-read-segment-prefix*)
				:movl (:eax ,op-offset) ,dst))))))))))))))


;;;;;;;;;;;;;;;;;; endp

(define-find-read-bindings :endp (cell result-mode)
  (declare (ignore result-mode))
  (when (typep cell 'binding)
    (list cell)))

(define-extended-code-expander :endp (instruction funobj frame-map)
  (destructuring-bind (cell result-mode)
      (cdr instruction)
    (let ((binding (binding-target (ensure-local-binding (binding-target cell) funobj))))
      (etypecase binding
	(constant-object-binding
	 (let ((x (constant-object binding)))
	   (typecase x
	     (movitz-cons
	      (make-load-constant *movitz-nil* result-mode funobj frame-map))
	     (movitz-null
	      (make-load-constant (image-t-symbol *image*) result-mode funobj frame-map))
	     (t '((:int 61))))))
	(lexical-binding
	 (let* ((location (new-binding-location (binding-target binding) frame-map))
		(binding-is-list-p (binding-store-subtypep binding 'list))
		(tmp-register (case location
				((:eax :ebx :ecx :edx)
				 location))))
	   ;; (warn "endp of loc ~A bind ~A" location binding)
	   (cond
	    ((and binding-is-list-p
		  (member location '(:eax :ebx :ecx :edx)))
	     (make-result-and-returns-glue result-mode :boolean-zf=1
					   `((:cmpl :edi ,location))))
	    ((eq :boolean-branch-on-true (result-mode-type result-mode))
	     (let ((tmp-register (or tmp-register :ecx)))
	       (append (make-load-lexical binding
					  (cons :boolean-branch-on-false
						(cdr result-mode))
					  funobj nil frame-map)
		       (unless binding-is-list-p
			 (append (make-load-lexical binding tmp-register funobj nil frame-map)
				 `((:leal (,tmp-register -1) :ecx)
				   (:testb 3 :cl)
				   (:jnz '(:sub-program (,(gensym "endp-not-list-"))
					   (:int 61)))))))))
	    (t (let ((tmp-register (or tmp-register :eax)))
		 (append (make-load-lexical binding tmp-register funobj nil frame-map)
			 (unless binding-is-list-p
			   `((:leal (,tmp-register -1) :ecx)
			     (:testb 3 :cl)
			     (:jnz '(:sub-program (,(gensym "endp-not-list-"))
				     (:int 61)))))
			 `((:cmpl :edi ,tmp-register))
			 (make-result-and-returns-glue result-mode :boolean-zf=1)))))))))))
	  

;;;;;;;;;;;;;;;;;; incf-lexvar

(define-find-write-binding-and-type :incf-lexvar (instruction)
  (destructuring-bind (binding delta &key protect-registers)
      (cdr instruction)
    (declare (ignore delta protect-registers))
    (values binding 'integer)))

(define-find-read-bindings :incf-lexvar (binding delta &key protect-registers)
  (declare (ignore delta protect-registers binding))
  nil)

(define-extended-code-expander :incf-lexvar (instruction funobj frame-map)
  (break "incf-lexvar??")
  (destructuring-bind (binding delta &key protect-registers)
      (cdr instruction)
    (check-type binding binding)
    (check-type delta integer)
    (let* ((binding (binding-target binding))
	   (location (new-binding-location binding frame-map :default nil))
	   (binding-type (binding-store-type binding)))
;;;      (warn "incf b ~A, loc: ~A, typ: ~A" binding location binding-type)
      (cond
       ((and binding-type
	     location
	     (not (binding-lended-p binding))
	     (binding-store-subtypep binding 'integer))
	;; This is an optimized incf that doesn't have to do type-checking.
	(check-type location (integer 1 *))
	`((:addl ,(* delta +movitz-fixnum-factor+)
		 (:ebp ,(stack-frame-offset location)))
	  (:into)))
       ((binding-store-subtypep binding 'integer)
	(let ((register (chose-free-register protect-registers)))
	  `(,@(make-load-lexical (ensure-local-binding binding funobj) 
				 register funobj nil frame-map
				 :protect-registers protect-registers)
	      (:addl ,(* delta +movitz-fixnum-factor+) :eax)
	      (:into)
	      ,@(make-store-lexical (ensure-local-binding binding funobj)
				    register nil funobj frame-map
				    :protect-registers protect-registers))))
       (t (let ((register (chose-free-register protect-registers)))
	    `(,@(make-load-lexical (ensure-local-binding binding funobj)
				   register funobj nil frame-map
				   :protect-registers protect-registers)
		(:testb ,+movitz-fixnum-zmask+ ,(register32-to-low8 register))
		(:jnz '(:sub-program (,(gensym "not-integer-"))
			(:int 107)
			(:jmp (:pc+ -4))))
		(:addl ,(* delta +movitz-fixnum-factor+) ,register)
		(:into)
		,@(make-store-lexical (ensure-local-binding binding funobj)
				      register nil funobj frame-map
				      :protect-registers protect-registers))))))))

;;;;; Load-constant

(define-find-write-binding-and-type :load-constant (instruction)
  (destructuring-bind (object result-mode &key (op :movl))
      (cdr instruction)
    (when (and (eq op :movl) (typep result-mode 'binding))
      (check-type result-mode lexical-binding)
      (values result-mode `(eql ,object)))))

(define-extended-code-expander :load-constant (instruction funobj frame-map)
  (destructuring-bind (object result-mode &key (op :movl))
      (cdr instruction)
    (make-load-constant object result-mode funobj frame-map :op op)))

;;;;; Add

(define-find-write-binding-and-type :add (instruction)
  (destructuring-bind (term0 term1 destination)
      (cdr instruction)
    (when (typep destination 'binding)
      (assert (and (bindingp term0) (bindingp term1)))
      (values destination
	      t
	      (lambda (type0 type1)
		(let ((x (multiple-value-call #'encoded-integer-types-add
			   (type-specifier-encode type0)
			   (type-specifier-encode type1))))
		  #+ignore (warn "thunked: ~S ~S -> ~S" term0 term1 x)
		  x))
	      (list term0 term1)
	      ))))

(define-find-used-bindings :add (term0 term1 destination)
  (if (bindingp destination)
      (list term0 term1 destination)
    (list term0 term1)))

(define-find-read-bindings :add (term0 term1 destination)
  (declare (ignore destination))
  (let* ((type0 (and (binding-store-type term0)
		     (apply #'encoded-type-decode (binding-store-type term0))))
	 (type1 (and (binding-store-type term1)
		     (apply #'encoded-type-decode (binding-store-type term1))))
	 (singleton0 (and type0 (type-specifier-singleton type0)))
	 (singleton1 (and type1 (type-specifier-singleton type1)))
	 (singleton-sum (and singleton0 singleton1
			     (type-specifier-singleton
			      (apply #'encoded-integer-types-add
				     (append (binding-store-type term0)
					     (binding-store-type term1)))))))
    (cond
     (singleton-sum
      (let ((b (make-instance 'constant-object-binding
		 :name (gensym "constant-sum")
		 :object (car singleton-sum))))
	(movitz-env-add-binding (binding-env term0) b)
	(list b)))
     (t (append (unless (and singleton0 (typep (car singleton0) 'movitz-fixnum))
		  (list term0))
		(unless (and singleton1 (typep (car singleton1) 'movitz-fixnum))
		  (list term1)))))))

(define-extended-code-expander :add (instruction funobj frame-map)
  (destructuring-bind (term0 term1 destination)
      (cdr instruction)
    (assert (and (bindingp term0)
		 (bindingp term1)
		 (member (result-mode-type destination)
			 '(:lexical-binding :function :multple-values :eax :ebx :ecx :edx))))
    (let* ((destination (ensure-local-binding destination funobj))
	   (term0 (ensure-local-binding term0 funobj))
	   (term1 (ensure-local-binding term1 funobj))
	   (destination-location (if (or (not (bindingp destination))
					 (typep destination 'borrowed-binding))
				     destination
				   (new-binding-location (binding-target destination)
							 frame-map
							 :default nil)))
	   (type0 (apply #'encoded-type-decode (binding-store-type term0)))
	   (type1 (apply #'encoded-type-decode (binding-store-type term1)))
	   (result-type (multiple-value-call #'encoded-integer-types-add
			  (values-list (binding-store-type term0))
			  (values-list (binding-store-type term1)))))
      ;; A null location means the binding is unused, in which
      ;; case there's no need to perform the addition.
      (when destination-location
	(let ((loc0 (new-binding-location (binding-target term0) frame-map :default nil))
	      (loc1 (new-binding-location (binding-target term1) frame-map :default nil)))
	  #+ignore
	  (warn "add: ~A for ~A" instruction result-type)
	  #+ignore
	  (warn "add for: ~S is ~A, from ~A/~A and ~A/~A."
		destination result-type
		term0 loc0
		term1 loc1)
	  #+ignore
	  (when (eql destination-location 9)
	    (warn "add for: ~S/~S~%= ~A/~A in ~S~&~A/~A in ~S."
		  destination destination-location
		  term0 loc0 (binding-extent-env (binding-target term0))
		  term1 loc1 (binding-extent-env (binding-target term1)))
	    (print-code 'load-term1 (make-load-lexical term1 :eax funobj nil frame-map))
	    (print-code 'load-dest (make-load-lexical destination :eax funobj nil frame-map)))
	  (flet ((make-store (source destination)
		   (cond
		    ((eq source destination)
		     nil)
		    ((member destination '(:eax :ebx :ecx :edx))
		     `((:movl ,source ,destination)))
		    (t (make-store-lexical destination source nil funobj frame-map))))
		 (make-default-add ()
		   (when (movitz-subtypep result-type '(unsigned-byte 32))
		     (warn "Defaulting u32 ADD: ~A/~S = ~A/~S + ~A/~S"
			   destination-location
			   destination
			   loc0 term0
			   loc1 term1))
		   (append (cond
			    ((type-specifier-singleton type0)
			     (append (make-load-lexical term1 :eax funobj nil frame-map)
				     (make-load-constant (car (type-specifier-singleton type0))
							 :ebx funobj frame-map)))
			    ((type-specifier-singleton type1)
			     (append (make-load-lexical term0 :eax funobj nil frame-map)
				     (make-load-constant (car (type-specifier-singleton type1))
							 :ebx funobj frame-map)))
			    ((and (eq :eax loc0) (eq :ebx loc1))
			     nil)
			    ((and (eq :ebx loc0) (eq :eax loc1))
			     nil)	; terms order isn't important
			    ((eq :eax loc1)
			     (append
			      (make-load-lexical term0 :ebx funobj nil frame-map)))
			    (t (append
				(make-load-lexical term0 :eax funobj nil frame-map)
				(make-load-lexical term1 :ebx funobj nil frame-map))))
			   `((:movl (:edi ,(global-constant-offset '+)) :esi))
			   (make-compiled-funcall-by-esi 2)
			   (etypecase destination
			     (symbol
			      (unless (eq destination :eax)
				`((:movl :eax ,destination))))
			     (binding
			      (make-store-lexical destination :eax nil funobj frame-map))))))
	    (let ((constant0 (let ((x (type-specifier-singleton type0)))
			       (when (and x (typep (car x) 'movitz-fixnum))
				 (movitz-immediate-value (car x)))))
		  (constant1 (let ((x (type-specifier-singleton type1)))
			       (when (and x (typep (car x) 'movitz-fixnum))
				 (movitz-immediate-value (car x))))))
	      (cond
	       ((type-specifier-singleton result-type)
		;; (break "constant add: ~S" instruction)
		(make-load-constant (car (type-specifier-singleton result-type))
				    destination funobj frame-map))
	       ((movitz-subtypep type0 '(integer 0 0))
		(cond
		 ((eql destination loc1)
		  #+ignore (break "NOP add: ~S" instruction)
		  nil)
		 ((and (member destination-location '(:eax :ebx :ecx :edx))
		       (member loc1 '(:eax :ebx :ecx :edx)))
		  `((:movl ,loc1 ,destination-location)))
		 ((integerp loc1)
		  (make-load-lexical term1 destination funobj nil frame-map))
		 #+ignore
		 ((integerp destination-location)
		  (make-store-lexical destination-location loc1 nil funobj frame-map))
		 (t (break "Unknown X zero-add: ~S" instruction))))
	       ((movitz-subtypep type1 '(integer 0 0))
		;; (warn "zero-add ~S => ~S [~S]" loc0 destination-location result-type)
		(cond
		 ((eql destination-location loc0)
		  #+ignore (break "NOP add: ~S" instruction)
		  nil)
		 ((and (member destination-location '(:eax :ebx :ecx :edx))
		       (member loc0 '(:eax :ebx :ecx :edx)))
		  `((:movl ,loc0 ,destination-location)))
		 ((member loc0 '(:eax :ebx :ecx :edx))
		  (make-store-lexical destination loc0 nil funobj frame-map))
		 ((integerp loc0)
		  (make-load-lexical term0 destination funobj nil frame-map))
		 ((type-specifier-singleton type0)
		  (make-load-lexical term0 destination funobj nil frame-map))
		 (t (break "Unknown Y zero-add: ~S for ~S/~S => ~S" instruction term0 loc0 destination))))
	       ((and (movitz-subtypep type0 'fixnum)
		     (movitz-subtypep type1 'fixnum)
		     (movitz-subtypep result-type 'fixnum))
		(assert (not (and constant0 (zerop constant0))))
		(assert (not (and constant1 (zerop constant1))))
		(cond
		 ((and (not (binding-lended-p (binding-target term0)))
		       (not (binding-lended-p (binding-target term1)))
		       (not (and (bindingp destination)
				 (binding-lended-p (binding-target destination)))))
		  (cond
		   ((and constant0
			 (equal loc1 destination-location))
		    (cond
		     ((member destination-location '(:eax :ebx :ecx :edx))
		      `((:addl ,constant0 ,destination-location)))
		     ((integerp loc1)
		      `((:addl ,constant0 (:ebp ,(stack-frame-offset loc1)))))
		     ((eq :argument-stack (operator loc1))
		      `((:addl ,constant0
			       (:ebp ,(argument-stack-offset (binding-target term1))))))
		     ((eq :untagged-fixnum-ecx (operator loc1))
		      `((:addl ,(truncate constant0 +movitz-fixnum-factor+) :ecx)))
		     (t (error "Don't know how to add this for loc1 ~S" loc1))))
		   ((and constant0
			 (integerp destination-location)
			 (eql term1 destination-location))
		    (break "untested")
		    `((:addl ,constant0 (:ebp ,(stack-frame-offset destination-location)))))
		   ((and constant0
			 (integerp destination-location)
			 (member loc1 '(:eax :ebx :ecx :edx)))
		    `((:addl ,constant0 ,loc1)
		      (:movl ,loc1 (:ebp ,(stack-frame-offset destination-location)))))
		   ((and (integerp loc0)
			 (integerp loc1)
			 (member destination-location '(:eax :ebx :ecx :edx)))
		    (append `((:movl (:ebp ,(stack-frame-offset loc0)) ,destination-location)
			      (:addl (:ebp ,(stack-frame-offset loc1)) ,destination-location))))
		   ((and (integerp destination-location)
			 (eql loc0 destination-location)
			 constant1)
		    `((:addl ,constant1 (:ebp ,(stack-frame-offset destination-location)))))
		   ((and (integerp destination-location)
			 (eql loc1 destination-location)
			 constant0)
		    `((:addl ,constant0 (:ebp ,(stack-frame-offset destination-location)))))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 (eq loc0 :untagged-fixnum-ecx)
			 constant1)
		    `((:leal ((:ecx ,+movitz-fixnum-factor+) ,constant1)
			     ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 (integerp loc1)
			 constant0)
		    `((:movl (:ebp ,(stack-frame-offset loc1)) ,destination-location)
		      (:addl ,constant0 ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 (integerp loc0)
			 constant1)
		    `((:movl (:ebp ,(stack-frame-offset loc0)) ,destination-location)
		      (:addl ,constant1 ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 (integerp loc0)
			 (member loc1 '(:eax :ebx :ecx :edx))
			 (not (eq destination-location loc1)))
		    `((:movl (:ebp ,(stack-frame-offset loc0)) ,destination-location)
		      (:addl ,loc1 ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 constant0
			 (member loc1 '(:eax :ebx :ecx :edx)))
		    `((:leal (,loc1 ,constant0) ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 constant1
			 (member loc0 '(:eax :ebx :ecx :edx)))
		    `((:leal (,loc0 ,constant1) ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 constant0
			 (eq :argument-stack (operator loc1)))
		    `((:movl (:ebp ,(argument-stack-offset (binding-target term1)))
			     ,destination-location)
		      (:addl ,constant0 ,destination-location)))
		   ((and (member destination-location '(:eax :ebx :ecx :edx))
			 constant1
			 (eq :argument-stack (operator loc0)))
		    `((:movl (:ebp ,(argument-stack-offset (binding-target term0)))
			     ,destination-location)
		      (:addl ,constant1 ,destination-location)))
		   (constant0
		    (append (make-load-lexical term1 :eax funobj nil frame-map)
			    `((:addl ,constant0 :eax))
			    (make-store :eax destination)))
		   (constant1
		    (append (make-load-lexical term0 :eax funobj nil frame-map)
			    `((:addl ,constant1 :eax))
			    (make-store :eax destination)))
		   ((eql loc0 loc1)
		    (append (make-load-lexical term0 :eax funobj nil frame-map)
			    `((:addl :eax :eax))
			    (make-store :eax destination)))
		   ((and (integerp loc0)
			 (integerp loc1)
			 (integerp destination-location)
			 (/= loc0 loc1 destination-location))
		    `((:movl (:ebp ,(stack-frame-offset loc0))
			     :ecx)
		      (:addl (:ebp ,(stack-frame-offset loc1))
			     :ecx)
		      (:movl :ecx (:ebp ,(stack-frame-offset destination-location)))))
		   (t (warn "Unknown fixnum ADD: ~A/~S = ~A/~S + ~A/~S"
			    destination-location
			    destination
			    loc0 term0
			    loc1 term1)
		      #+ignore (warn "map: ~A" frame-map)
;;; 	    (warn "ADDI: ~S" instruction)
		      (append (cond
			       ((type-specifier-singleton type0)
				(append (make-load-lexical term1 :eax funobj nil frame-map)
					(make-load-constant (car (type-specifier-singleton type0))
							    :ebx funobj frame-map)))
			       ((type-specifier-singleton type1)
				(append (make-load-lexical term0 :eax funobj nil frame-map)
					(make-load-constant (car (type-specifier-singleton type1))
							    :ebx funobj frame-map)))
			       ((and (eq :eax loc0) (eq :ebx loc1))
				nil)
			       ((and (eq :ebx loc0) (eq :eax loc1))
				nil)	; terms order isn't important
			       ((eq :eax loc1)
				(append
				 (make-load-lexical term0 :ebx funobj nil frame-map)))
			       (t (append
				   (make-load-lexical term0 :eax funobj nil frame-map)
				   (make-load-lexical term1 :ebx funobj nil frame-map))))
			      `((:movl (:edi ,(global-constant-offset '+)) :esi))
			      (make-compiled-funcall-by-esi 2)
			      (etypecase destination
				(symbol
				 (unless (eq destination :eax)
				   `((:movl :eax ,destination))))
				(binding
				 (make-store-lexical destination :eax nil funobj frame-map)))))))
		 ((and constant0
		       (integerp destination-location)
		       (eql loc1 destination-location)
		       (binding-lended-p (binding-target destination)))
		  (assert (binding-lended-p (binding-target term1)))
		  (append (make-load-lexical destination :eax funobj t frame-map)
			  `((:addl ,constant0 (-1 :eax)))))
		 ((warn "~S" (list (and (bindingp destination)
					(binding-lended-p (binding-target destination)))
				   (binding-lended-p (binding-target term0))
				   (binding-lended-p (binding-target term1)))))
		 (t (warn "Unknown fixnum add: ~S" instruction)
		    (make-default-add))))
	       ((and (movitz-subtypep type0 'fixnum)
		     (movitz-subtypep type1 'fixnum))
		(flet ((mkadd-into (src destreg)
			 (assert (eq destreg :eax) (destreg)
			   "Movitz' INTO protocol says the overflowed value must be in EAX, ~
but it's requested to be in ~S."
			   destreg)
			 (let ((srcloc (new-binding-location (binding-target src) frame-map)))
			   (unless (eql srcloc loc1)
			     #+ignore (break)
			     (warn "add srcloc: ~S, loc1: ~S" srcloc loc1))
			   (if (integerp srcloc)
			       `((:addl (:ebp ,(stack-frame-offset srcloc))
					,destreg)
				 (:into))
			     (ecase (operator srcloc)
			       ((:eax :ebx :ecx :edx)
				`((:addl ,srcloc ,destreg)
				  (:into)))
			       ((:argument-stack)
				`((:addl (:ebx ,(argument-stack-offset src))
					 ,destreg)
				  (:into)))
			       )))))
		  (cond
		   ((and (not constant0)
			 (not constant1)
			 (not (binding-lended-p (binding-target term0)))
			 (not (binding-lended-p (binding-target term1)))
			 (not (and (bindingp destination)
				   (binding-lended-p (binding-target destination)))))
		    (cond
		     ((and (not (eq loc0 :untagged-fixnum-ecx))
			   (not (eq loc1 :untagged-fixnum-ecx))
			   (not (eq destination-location :untagged-fixnum-ecx)))
		      (append (cond
			       ((and (eq loc0 :eax) (eq loc1 :eax))
				`((:addl :eax :eax)
				  (:into)))
			       ((eq loc0 :eax)
				(mkadd-into term1 :eax))
			       ((eq loc1 :eax)
				(mkadd-into term0 :eax))
			       (t (append (make-load-lexical term0 :eax funobj nil frame-map
							     :protect-registers (list loc1))
					  (mkadd-into term1 :eax))))
			      (make-store :eax destination)))
		     (t (make-default-add)
			#+ignore
			(append (make-load-lexical term0 :untagged-fixnum-ecx funobj nil frame-map)
				`((,*compiler-local-segment-prefix*
				   :movl :ecx (:edi ,(global-constant-offset 'raw-scratch0))))
				(make-load-lexical term1 :untagged-fixnum-ecx funobj nil frame-map)
				`((,*compiler-local-segment-prefix*
				   :addl (:edi ,(global-constant-offset 'raw-scratch0)) :ecx))
				(if (integerp destination-location)
				    `((,*compiler-local-segment-prefix*
				       :call (:edi ,(global-constant-offset 'box-u32-ecx)))
				      (:movl :eax (:ebp ,(stack-frame-offset destination-location))))
				  (ecase (operator destination-location)
				    ((:untagged-fixnum-ecx)
				     nil)
				    ((:eax)
				     `((,*compiler-local-segment-prefix*
					:call (:edi ,(global-constant-offset 'box-u32-ecx)))))
				    ((:ebx :ecx :edx)
				     `((,*compiler-local-segment-prefix*
					:call (:edi ,(global-constant-offset 'box-u32-ecx)))
				       (:movl :eax ,destination-location)))
				    ((:argument-stack)
				     `((,*compiler-local-segment-prefix*
					:call (:edi ,(global-constant-offset 'box-u32-ecx)))
				       (:movl :eax (:ebp ,(argument-stack-offset
							   (binding-target destination))))))))))))
		   (t (make-default-add)))))
	       (t (make-default-add))))))))))

;;;;;;;

(defun movitz-eql (x y)
  "Emulate EQL on movitz-objects."
  (etypecase x
    (movitz-immediate-object
     (and (typep y 'movitz-immediate-object)
	  (eql (movitz-immediate-value x)
	       (movitz-immediate-value y))))
    ((or movitz-symbol movitz-null movitz-cons movitz-basic-vector)
     (eq x y))
    (movitz-struct
     (cond
       ((not (typep y 'movitz-struct))
	nil)
       ((eq (movitz-struct-class x)
	    (muerte::movitz-find-class 'muerte.cl:complex))
	(and (eq (movitz-struct-class x)
		 (muerte::movitz-find-class 'muerte.cl:complex))
	     (movitz-eql (first (movitz-struct-slot-values x))
			 (first (movitz-struct-slot-values y)))
	     (movitz-eql (second (movitz-struct-slot-values x))
			 (second (movitz-struct-slot-values y)))))
       (t (error "movitz-eql unknown movitz-struct: ~S" x))))))

(define-find-read-bindings :eql (x y mode)
  (declare (ignore mode))
  (list x y))

(define-extended-code-expander :eql (instruction funobj frame-map)
  (destructuring-bind (x y return-mode)
      (cdr instruction)
    (let* ((x-type (apply #'encoded-type-decode (binding-store-type x)))
	   (y-type (apply #'encoded-type-decode (binding-store-type y)))
	   (x-singleton (type-specifier-singleton x-type))
	   (y-singleton (type-specifier-singleton y-type)))
      (when (and y-singleton (not x-singleton))
	(rotatef x y)
	(rotatef x-type y-type)
	(rotatef x-singleton y-singleton))
      (let (#+ignore (x-loc (new-binding-location (binding-target x) frame-map :default nil))
	    (y-loc (new-binding-location (binding-target y) frame-map :default nil)))
	#+ignore
	(warn "eql ~S/~S xx~Xxx ~S/~S: ~S"
	      x x-loc (binding-target y)
	      y y-loc
	      instruction)
	(flet ((make-branch ()
		 (ecase (operator return-mode)
		   (:boolean-branch-on-false
		    `((:jne ',(operands return-mode))))
		   (:boolean-branch-on-true
		    `((:je ',(operands return-mode))))
		   (:boolean-zf=1)))
	       (make-load-eax-ebx ()
		 (if (eq :eax y-loc)
		     (make-load-lexical x :ebx funobj nil frame-map)
		   (append (make-load-lexical x :eax funobj nil frame-map)
			   (make-load-lexical y :ebx funobj nil frame-map)))))
	  (cond
	   ((and x-singleton y-singleton)
	    (let ((eql (movitz-eql (car x-singleton)
				   (car y-singleton))))
	      (case (operator return-mode)
		(:boolean-branch-on-false
		 (when (not eql)
		   `((:jmp ',(operands return-mode)))))
		(t (warn "Constant EQL: ~S ~S" (car x-singleton) (car y-singleton))))))
	   ((and x-singleton
		 (eq :untagged-fixnum-ecx y-loc))
	    (let ((value (etypecase (car x-singleton)
			   (movitz-fixnum
			    (movitz-fixnum-value (car x-singleton)))
			   (movitz-bignum
			    (movitz-bignum-value (car x-singleton))))))
	      (check-type value (unsigned-byte 32))
	      `((:cmpl ,value :ecx)
		,@(make-branch))))
	   ((and x-singleton
		 (typep (car x-singleton) '(or movitz-immediate-object movitz-null)))
	    (let ((value (if (typep (car x-singleton) 'movitz-null)
			     :edi
			   (movitz-immediate-value (car x-singleton)))))
	      (append (cond
		       ((and (eql value 0)
			     (member y-loc '(:eax :ebx :ecx :edx)))
			`((:testl ,y-loc ,y-loc)))
		       ((and (member y-loc '(:eax :ebx :ecx :edx))
			     (not (binding-lended-p y)))
			`((:cmpl ,value ,y-loc)))
		       ((and (integerp y-loc)
			     (not (binding-lended-p y)))
			`((:cmpl ,value (:ebp ,(stack-frame-offset y-loc)))))
		       ((and (eq :argument-stack (operator y-loc))
			     (not (binding-lended-p y)))
			`((:cmpl ,value (:ebp ,(argument-stack-offset (binding-target y))))))
		       (t (break "x-singleton: ~S with loc ~S"
				 (movitz-immediate-value (car x-singleton))
				 y-loc)))
		      (make-branch))))
	   ((and x-singleton
		 (typep (car x-singleton) 'movitz-symbol)
		 (member y-loc '(:eax :ebx :edx)))
	    (append (make-load-constant (car x-singleton) y-loc funobj frame-map :op :cmpl)
		    (make-branch)))
	   (y-singleton
	    (break "y-singleton"))
	   ((and (not (eq t x-type))	; this is for bootstrapping purposes.
		 (not (eq t y-type))	; ..
		 (or (movitz-subtypep x-type '(or fixnum character symbol vector))
		     (movitz-subtypep y-type '(or fixnum character symbol vector))))
	    (append (make-load-eax-ebx)
		    `((:cmpl :eax :ebx))
		    (make-branch)))
	   #+ignore
	   ((warn "eql ~S/~S ~S/~S"
		  x x-loc
		  y y-loc))
	   ((eq :boolean-branch-on-false (operator return-mode))
	    (let ((eql-done (gensym "eql-done-"))
		  (on-false-label (operands return-mode)))
	      (append (make-load-eax-ebx)
		      `((:cmpl :eax :ebx)
			(:je ',eql-done)
			(,*compiler-global-segment-prefix*
			 :movl (:edi ,(global-constant-offset 'complicated-eql)) :esi)
			(:call (:esi ,(binary-types:slot-offset 'movitz-funobj 'code-vector%2op)))
			(:jne ',on-false-label)
			,eql-done))))
	   ((eq :boolean-branch-on-true (operator return-mode))
	    (let ((on-true-label (operands return-mode)))
	      (append (make-load-eax-ebx)
		      `((:cmpl :eax :ebx)
			(:je ',on-true-label)
			(,*compiler-global-segment-prefix*
			 :movl (:edi ,(global-constant-offset 'complicated-eql)) :esi)
			(:call (:esi ,(binary-types:slot-offset 'movitz-funobj 'code-vector%2op)))
			(:je ',on-true-label)))))
	   ((eq return-mode :boolean-zf=1)
	    (append (make-load-eax-ebx)
		    (let ((eql-done (gensym "eql-done-")))
		      `((:cmpl :eax :ebx)
			(:je ',eql-done)
			(,*compiler-global-segment-prefix*
			 :movl (:edi ,(global-constant-offset 'complicated-eql)) :esi)
			(:call (:esi ,(binary-types:slot-offset 'movitz-funobj 'code-vector%2op)))
			,eql-done))))
	   (t (error "unknown eql: ~S" instruction))))))))

(define-find-read-bindings :load-lambda (lambda-binding result-mode capture-env)
  (declare (ignore result-mode capture-env))
  (let ((allocation (movitz-allocation (function-binding-funobj lambda-binding))))
    (when (typep allocation 'with-dynamic-extent-scope-env)
      (values (list (base-binding allocation))
	      (list :edx)))))

(define-find-write-binding-and-type :enter-dynamic-scope (instruction)
  (destructuring-bind (scope-env)
      (cdr instruction)
    (if (null (dynamic-extent-scope-members scope-env))
	(values nil)
      (values (base-binding scope-env) 'fixnum))))

(define-extended-code-expander :enter-dynamic-scope (instruction funobj frame-map)
  (declare (ignore funobj frame-map))
  (destructuring-bind (scope-env)
      (cdr instruction)
    (if (null (dynamic-extent-scope-members scope-env))
	nil
      (append `((:pushl :edi)
		(:movl :esp :eax)
		(:andl 4 :eax)
		(:addl :eax :esp))
	      (loop for object in (reverse (dynamic-extent-scope-members scope-env))
		  appending
		    (etypecase object
		      (movitz-cons
		       `((:pushl :edi)
			 (:pushl :edi)))
		      (movitz-funobj
		       (append (unless (zerop (mod (sizeof object) 8))
				 `((:pushl :edi)))
			       `((:load-constant ,object :eax))
			       (loop for i from (1- (movitz-funobj-num-constants object))
				   downto (movitz-funobj-num-jumpers object)
				   collect `(:pushl (:eax ,(slot-offset 'movitz-funobj 'constant0)
							  ,(* 4 i))))
			       (loop repeat (movitz-funobj-num-jumpers object)
				   collect `(:pushl 0))
			       `((:pushl (:eax ,(slot-offset 'movitz-funobj 'num-jumpers)))
				 (:pushl (:eax ,(slot-offset 'movitz-funobj 'name)))
				 (:pushl (:eax ,(slot-offset 'movitz-funobj 'lambda-list)))
				 
				 (:pushl 0) ; %3op
				 (:pushl 0) ; %2op
				 (:pushl 0) ; %1op
				 (:pushl 2) ; (default) 2 is recognized by map-header-vals as non-initialized funobj.
				 
				 (:pushl (:eax ,(slot-offset 'movitz-funobj 'type)))
				 (:leal (:esp ,(tag :other)) :ebx)
				 (,*compiler-local-segment-prefix*
				  :call (:edi ,(global-constant-offset 'copy-funobj-code-vector-slots)))
				 )))))))))

;;;(define-extended-code-expander :exit-dynamic-scope (instruction funobj frame-map)
;;;  nil)

(define-find-read-bindings :lexical-control-transfer (return-code return-mode from-env to-env
								  &optional to-label)
  (declare (ignore return-code return-mode to-label))
  (let ((distance (stack-delta from-env to-env)))
    (when (eq t distance)
      (values (list (movitz-binding (save-esp-variable to-env) to-env nil))
	      (list :esp)))))

(define-find-read-bindings :stack-cons (proto-cons scope-env)
  (declare (ignore proto-cons))
  (values (list (base-binding scope-env))
	  (list :edx)))

(define-extended-code-expander :stack-cons (instruction funobj frame-map)
  (destructuring-bind (proto-cons dynamic-scope)
      (cdr instruction)
    (append (make-load-lexical (base-binding dynamic-scope) :edx
			       funobj nil frame-map)
	    `((:movl :eax (:edx ,(dynamic-extent-object-offset dynamic-scope proto-cons)))
	      (:movl :ebx (:edx ,(+ 4 (dynamic-extent-object-offset dynamic-scope proto-cons))))
	      (:leal (:edx ,(+ (tag :cons) (dynamic-extent-object-offset dynamic-scope proto-cons)))
		     :eax)))))

