;;;; modus64.asd - ASDF system definition for Modus64 cross-compiler
;;;;
;;;; Load with: (asdf:load-system :modus64)
;;;; Test with: (modus64.cross:test-cross-compiler)

(asdf:defsystem :modus64
  :description "Modus64 - 64-bit Lisp OS cross-compiler"
  :version "0.1.0"
  :author "Modus Project"
  :license "MIT"
  :depends-on ()
  :serial t
  :components
  ((:module "cross"
    :serial t
    :components
    ((:file "packages")
     (:file "x64-asm")
     (:file "cross-compile")
     (:file "build")))
   (:module "boot"
    :serial t
    :depends-on ("cross")
    :components
    ((:file "multiboot")
     (:file "boot32")
     (:file "kernel64")
     (:file "multiboot1")))))
