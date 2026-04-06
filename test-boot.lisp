;;;; test-boot.lisp - Test boot code generation

(require :asdf)
(push (make-pathname :directory (pathname-directory *load-truename*))
      asdf:*central-registry*)
(asdf:load-system :modus)

(format t "~%=== Testing Boot Code ===~%")

(format t "~%--- Multiboot2 Header ---~%")
(modus.cross:test-multiboot2-header)

(format t "~%--- 32-bit Boot Stub ---~%")
(modus.cross:test-boot32)

(format t "~%--- 64-bit Kernel Entry ---~%")
(modus.cross:test-kernel64)

(format t "~%--- Build Complete Image ---~%")
(modus.cross:test-build-image)

(format t "~%=== All boot tests passed ===~%")
