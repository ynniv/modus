;;;; test-cross.lisp - Test the Modus64 cross-compiler
;;;;
;;;; Run with: sbcl --load test-cross.lisp

(require :asdf)

;; Add current directory to ASDF search path
(push (make-pathname :directory (pathname-directory *load-truename*))
      asdf:*central-registry*)

;; Load the system
(format t "~%Loading modus64 system...~%")
(asdf:load-system :modus64)

;; Run tests
(format t "~%=== Running cross-compiler tests ===~%")

;; Test 1: Assembler basics
(format t "~%--- Test 1: Assembler ---~%")
(modus64.asm:test-assembler)

;; Test 2: Cross-compiler basics
(format t "~%--- Test 2: Cross-compiler ---~%")
(modus64.cross:test-cross-compiler)

;; Test 3: Compile more complex code
(format t "~%--- Test 3: Complex compilation ---~%")
(let ((modus64.cross:*code-buffer* (modus64.asm:make-code-buffer))
      (modus64.cross:*functions* (make-hash-table :test 'eq))
      (modus64.cross:*constants* nil))

  ;; Compile a let expression
  (format t "~%Compiling let expression...~%")
  (modus64.cross:compile-toplevel
   '(defun test-let (x)
     (let ((a (1+ x))
           (b (+ x x)))  ; Use + instead of * (not implemented yet)
       (+ a b))))

  ;; Compile nested if
  (format t "Compiling nested if...~%")
  (modus64.cross:compile-toplevel
   '(defun classify (n)
     (if (< n 0)
         'negative
         (if (= n 0)
             'zero
             'positive))))

  ;; Fix up labels
  (modus64.asm:fixup-labels modus64.cross:*code-buffer*)

  ;; Show results
  (format t "~%Total code: ~D bytes~%"
          (modus64.asm:code-buffer-position modus64.cross:*code-buffer*))
  (format t "Functions:~%")
  (maphash (lambda (k v)
             (format t "  ~A @ offset ~D~%" k v))
           modus64.cross:*functions*))

(format t "~%=== All tests passed ===~%")
