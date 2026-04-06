;;;; hash.lisp — Dual-FNV-1a symbol hashing
;;;;
;;;; Shared between cross-compiler (modus.build) and MVM (modus.mvm).
;;;; Computes a 60-bit collision-resistant hash from a name string.
;;;; Used for function lookup, symbol comparison, and function tables.

(defpackage :modus.hash
  (:use :cl)
  (:export #:compute-name-hash
           #:normalize-name
           #:name-eq))

(in-package :modus.hash)

(defun compute-name-hash (name-string)
  "Compute dual-FNV-1a hash for a name string. 60-bit collision-resistant.
   Two independent FNV-1a-32 hashes combined into a single 60-bit value.
   Collision probability ~4e-10 with ~200 functions."
  (let ((name (string-upcase (string name-string)))
        (h1 2166136261) (h2 3735928559))
    (loop for c across name
          do (setq h1 (logand (* (logxor h1 (char-code c)) 16777619) #xFFFFFFFF))
             (setq h2 (logand (* (logxor h2 (char-code c)) 805306457) #xFFFFFFFF)))
    (let ((combined (logior (ash (logand h1 #x3FFFFFFF) 30)
                            (logand h2 #x3FFFFFFF))))
      (if (zerop combined) 1 combined))))

(defun normalize-name (sym)
  "Convert a symbol to its name hash for comparison."
  (if (integerp sym)
      sym
      (compute-name-hash (symbol-name sym))))

(defun name-eq (sym name-string)
  "Check if SYM's name matches NAME-STRING via hash comparison."
  (and (symbolp sym)
       (= (compute-name-hash (symbol-name sym))
          (compute-name-hash name-string))))
