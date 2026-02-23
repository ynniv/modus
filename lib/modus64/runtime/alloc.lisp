;;;; alloc.lisp - Memory Allocator for Modus64
;;;;
;;;; Simple bump allocator. GC will be added later.
;;;;
;;;; Memory layout (from 64-bit-allocator-design.md):
;;;;   0x02000000 (32MB)  - Wired area (kernel, never moves)
;;;;   0x03000000 (48MB)  - Pinned area (DMA buffers)
;;;;   0x03800000 (56MB)  - Function area
;;;;   0x04000000 (64MB)  - Cons area
;;;;   0x05000000 (80MB)  - General area

(in-package :modus64.runtime)

;;; ============================================================
;;; Memory Regions
;;; ============================================================

(defconstant +wired-start+    #x02000000)
(defconstant +pinned-start+   #x03000000)
(defconstant +function-start+ #x03800000)
(defconstant +cons-start+     #x04000000)
(defconstant +general-start+  #x05000000)

(defconstant +cons-size+ 16)         ; 2 * 8 bytes
(defconstant +min-object-size+ 16)   ; Minimum allocation

;;; Allocation pointers (stored in registers at runtime):
;;;   R12 = general allocation pointer
;;;   R14 = general allocation limit
;;; For cons area, we use memory variables.

(defvar *cons-ptr* +cons-start+)
(defvar *cons-limit* (+ +cons-start+ (* 4 1024 1024)))  ; 4MB initial

(defvar *general-ptr* +general-start+)
(defvar *general-limit* (+ +general-start+ (* 16 1024 1024)))  ; 16MB initial

;;; ============================================================
;;; Cons Allocation
;;; ============================================================

(defun alloc-cons ()
  "Allocate a cons cell from cons area. Returns untagged pointer."
  (let ((ptr *cons-ptr*))
    (setf *cons-ptr* (+ ptr +cons-size+))
    (when (>= *cons-ptr* *cons-limit*)
      (gc-collect-cons))  ; TODO: Implement
    ptr))

(defun cons (car cdr)
  "Create a new cons cell"
  (let ((ptr (alloc-cons)))
    (setf (mem-ref ptr :u64) car)
    (setf (mem-ref (+ ptr 8) :u64) cdr)
    (tag-cons ptr)))

;;; ============================================================
;;; General Allocation
;;; ============================================================

(defun alloc-object (size)
  "Allocate SIZE bytes from general area. Returns untagged pointer.
   SIZE should include header and be 16-byte aligned."
  (let* ((aligned-size (logand (+ size 15) -16))
         (ptr *general-ptr*))
    (setf *general-ptr* (+ ptr aligned-size))
    (when (>= *general-ptr* *general-limit*)
      (gc-collect-general))  ; TODO: Implement
    ptr))

(defun make-object (subtag element-count)
  "Allocate an object with given subtag and element count.
   Returns tagged object pointer."
  (let* ((data-size (* element-count 8))
         (total-size (+ 8 data-size))  ; Header + data
         (ptr (alloc-object total-size)))
    ;; Write header
    (setf (mem-ref ptr :u64)
          (logior subtag (ash element-count 16)))
    (tag-object ptr)))

;;; ============================================================
;;; Vector Allocation
;;; ============================================================

(defun make-simple-vector (length)
  "Allocate a simple-vector of given length"
  (let ((obj (make-object +subtag-simple-vector+ length)))
    ;; Initialize to NIL (0 for now, will be proper NIL later)
    (let ((data-ptr (+ (untag-object obj) 8)))
      (dotimes (i length)
        (setf (mem-ref (+ data-ptr (* i 8)) :u64) 0)))
    obj))

(defun make-string (length)
  "Allocate a string of given length (in bytes)"
  (let* ((word-count (ceiling length 8))
         (obj (make-object +subtag-string+ word-count)))
    ;; Zero initialize
    (let ((data-ptr (+ (untag-object obj) 8)))
      (dotimes (i word-count)
        (setf (mem-ref (+ data-ptr (* i 8)) :u64) 0)))
    obj))

;;; ============================================================
;;; Symbol Allocation
;;; ============================================================

;;; Symbol layout:
;;;   +0: Header (subtag=0x50, count=4)
;;;   +8: name (string)
;;;  +16: value
;;;  +24: function
;;;  +32: plist

(defun make-symbol (name)
  "Allocate a symbol with given name (a string)"
  (let ((obj (make-object +subtag-symbol+ 4)))
    (let ((data-ptr (+ (untag-object obj) 8)))
      (setf (mem-ref data-ptr :u64) name)         ; name
      (setf (mem-ref (+ data-ptr 8) :u64) 0)      ; value = unbound
      (setf (mem-ref (+ data-ptr 16) :u64) 0)     ; function = unbound
      (setf (mem-ref (+ data-ptr 24) :u64) 0))    ; plist = nil
    obj))

;;; ============================================================
;;; GC Stubs (TODO)
;;; ============================================================

(defun gc-collect-cons ()
  "Collect cons area - STUB"
  (error "Out of cons memory"))

(defun gc-collect-general ()
  "Collect general area - STUB"
  (error "Out of general memory"))

;;; ============================================================
;;; Memory Access Primitives
;;; ============================================================

;;; These will be compiled to direct memory operations

(defun mem-ref (addr type)
  "Read from memory at ADDR with TYPE (:u8, :u16, :u32, :u64)"
  (declare (ignore type))
  ;; This is a primitive - the cross-compiler handles it specially
  addr)

(defun (setf mem-ref) (value addr type)
  "Write VALUE to memory at ADDR with TYPE"
  (declare (ignore addr type))
  value)

;;; ============================================================
;;; Initialization
;;; ============================================================

(defun init-allocator ()
  "Initialize the allocator (called at boot)"
  (setf *cons-ptr* +cons-start+)
  (setf *cons-limit* (+ +cons-start+ (* 4 1024 1024)))
  (setf *general-ptr* +general-start+)
  (setf *general-limit* (+ +general-start+ (* 16 1024 1024)))
  t)
