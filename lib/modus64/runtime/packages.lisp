;;;; packages.lisp - Runtime package definition for Modus64
;;;;
;;;; This defines the runtime package. These files are compiled
;;;; by the cross-compiler and become part of the kernel image.

(defpackage :modus64.runtime
  (:use)  ; Use nothing - we define everything from scratch
  (:export
   ;; Tag constants
   #:+tag-mask+
   #:+tag-fixnum+
   #:+tag-cons+
   #:+tag-object+
   #:+tag-immediate+
   #:+tag-forward+
   #:+fixnum-shift+
   ;; Subtags
   #:+subtag-symbol+
   #:+subtag-function+
   #:+subtag-closure+
   #:+subtag-simple-vector+
   #:+subtag-string+
   ;; Tag predicates
   #:tag-of
   #:fixnump
   #:consp
   #:objectp
   #:immediatep
   #:characterp
   #:symbolp
   #:functionp
   #:vectorp
   #:stringp
   #:null
   #:atom
   #:listp
   ;; Pointer ops
   #:untag-cons
   #:untag-object
   #:tag-cons
   #:tag-object
   #:make-fixnum
   #:fixnum-value
   ;; Memory regions
   #:+cons-start+
   #:+general-start+
   ;; Allocation
   #:alloc-cons
   #:alloc-object
   #:make-object
   #:make-simple-vector
   #:make-string
   #:make-symbol
   #:init-allocator
   ;; Cons operations
   #:cons
   #:car
   #:cdr
   #:rplaca
   #:rplacd
   #:caar #:cadr #:cdar #:cddr
   #:list
   #:length
   #:nth
   #:nthcdr
   #:last
   #:append
   #:reverse
   #:nreverse
   #:member
   #:assoc
   #:mapcar
   #:mapc
   ;; Memory access
   #:mem-ref))
