;;;; test-cross.lisp - Test the Modus cross-compiler
;;;;
;;;; Run with: sbcl --load test-cross.lisp

(require :asdf)

;; Add current directory to ASDF search path
(push (make-pathname :directory (pathname-directory *load-truename*))
      asdf:*central-registry*)

;; Load the system
(format t "~%Loading modus system...~%")
(asdf:load-system :modus)

;; Run tests
(format t "~%=== Running cross-compiler tests ===~%")

;; Test 1: Assembler basics
(format t "~%--- Test 1: Assembler ---~%")
(modus.asm:test-assembler)

;; Test 2: Cross-compiler basics
(format t "~%--- Test 2: Cross-compiler ---~%")
(modus.cross:test-cross-compiler)

;; Test 3: Compile more complex code
(format t "~%--- Test 3: Complex compilation ---~%")
(let ((modus.cross:*code-buffer* (modus.asm:make-code-buffer))
      (modus.cross:*functions* (make-hash-table :test 'eq))
      (modus.cross:*constants* nil))

  ;; Compile a let expression
  (format t "~%Compiling let expression...~%")
  (modus.cross:compile-toplevel
   '(defun test-let (x)
     (let ((a (1+ x))
           (b (+ x x)))  ; Use + instead of * (not implemented yet)
       (+ a b))))

  ;; Compile nested if
  (format t "Compiling nested if...~%")
  (modus.cross:compile-toplevel
   '(defun classify (n)
     (if (< n 0)
         'negative
         (if (= n 0)
             'zero
             'positive))))

  ;; Fix up labels
  (modus.asm:fixup-labels modus.cross:*code-buffer*)

  ;; Show results
  (format t "~%Total code: ~D bytes~%"
          (modus.asm:code-buffer-position modus.cross:*code-buffer*))
  (format t "Functions:~%")
  (maphash (lambda (k v)
             (format t "  ~A @ offset ~D~%" k v))
           modus.cross:*functions*))

(format t "~%=== All tests passed ===~%")
