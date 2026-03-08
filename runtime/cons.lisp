;;;; cons.lisp - Cons Cell Operations for Modus64
;;;;
;;;; Cons cell layout (16 bytes):
;;;;   +0: CAR (8 bytes, tagged value)
;;;;   +8: CDR (8 bytes, tagged value)

(in-package :modus64.runtime)

;;; ============================================================
;;; Basic Accessors
;;; ============================================================

(defun car (x)
  "Return the CAR of cons cell X"
  (if (consp x)
      (mem-ref (untag-cons x) :u64)
      (if (null x)
          x  ; (car nil) = nil
          (error "CAR of non-cons"))))

(defun cdr (x)
  "Return the CDR of cons cell X"
  (if (consp x)
      (mem-ref (+ (untag-cons x) 8) :u64)
      (if (null x)
          x  ; (cdr nil) = nil
          (error "CDR of non-cons"))))

(defun rplaca (x val)
  "Replace the CAR of X with VAL"
  (if (consp x)
      (progn
        (setf (mem-ref (untag-cons x) :u64) val)
        x)
      (error "RPLACA of non-cons")))

(defun rplacd (x val)
  "Replace the CDR of X with VAL"
  (if (consp x)
      (progn
        (setf (mem-ref (+ (untag-cons x) 8) :u64) val)
        x)
      (error "RPLACD of non-cons")))

;;; ============================================================
;;; Derived Accessors
;;; ============================================================

(defun caar (x) (car (car x)))
(defun cadr (x) (car (cdr x)))
(defun cdar (x) (cdr (car x)))
(defun cddr (x) (cdr (cdr x)))

(defun caaar (x) (car (car (car x))))
(defun caadr (x) (car (car (cdr x))))
(defun cadar (x) (car (cdr (car x))))
(defun caddr (x) (car (cdr (cdr x))))
(defun cdaar (x) (cdr (car (car x))))
(defun cdadr (x) (cdr (car (cdr x))))
(defun cddar (x) (cdr (cdr (car x))))
(defun cdddr (x) (cdr (cdr (cdr x))))

;;; ============================================================
;;; Predicates
;;; ============================================================

(defun null (x)
  "Is X nil?"
  (eq x nil))

(defun atom (x)
  "Is X an atom (not a cons)?"
  (not (consp x)))

(defun listp (x)
  "Is X a list (cons or nil)?"
  (or (consp x) (null x)))

;;; ============================================================
;;; List Construction
;;; ============================================================

(defun list (&rest args)
  "Create a list from arguments"
  (if (null args)
      nil
      (cons (car args) (apply #'list (cdr args)))))

(defun list* (&rest args)
  "Create a list with last arg as final CDR"
  (if (null (cdr args))
      (car args)
      (cons (car args) (apply #'list* (cdr args)))))

;;; ============================================================
;;; List Operations
;;; ============================================================

(defun length (list)
  "Return the length of LIST"
  (if (null list)
      0
      (1+ (length (cdr list)))))

(defun nthcdr (n list)
  "Return the Nth cdr of LIST"
  (if (= n 0)
      list
      (nthcdr (1- n) (cdr list))))

(defun nth (n list)
  "Return the Nth element of LIST"
  (car (nthcdr n list)))

(defun last (list)
  "Return the last cons of LIST"
  (if (null (cdr list))
      list
      (last (cdr list))))

(defun append (list1 list2)
  "Append LIST2 to LIST1"
  (if (null list1)
      list2
      (cons (car list1) (append (cdr list1) list2))))

(defun reverse (list)
  "Return a reversed copy of LIST"
  (let ((result nil))
    (loop while list do
      (setf result (cons (car list) result))
      (setf list (cdr list)))
    result))

(defun nreverse (list)
  "Destructively reverse LIST"
  (let ((prev nil)
        (current list)
        (next nil))
    (loop while current do
      (setf next (cdr current))
      (rplacd current prev)
      (setf prev current)
      (setf current next))
    prev))

;;; ============================================================
;;; Membership
;;; ============================================================

(defun member (item list)
  "Find ITEM in LIST using EQ"
  (cond
    ((null list) nil)
    ((eq item (car list)) list)
    (t (member item (cdr list)))))

(defun assoc (key alist)
  "Find (KEY . value) pair in ALIST"
  (cond
    ((null alist) nil)
    ((eq key (caar alist)) (car alist))
    (t (assoc key (cdr alist)))))

;;; ============================================================
;;; Mapping
;;; ============================================================

(defun mapcar (fn list)
  "Apply FN to each element of LIST, return results"
  (if (null list)
      nil
      (cons (funcall fn (car list))
            (mapcar fn (cdr list)))))

(defun mapc (fn list)
  "Apply FN to each element of LIST for side effects"
  (let ((l list))
    (loop while l do
      (funcall fn (car l))
      (setf l (cdr l))))
  list)
