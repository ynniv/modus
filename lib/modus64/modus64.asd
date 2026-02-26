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
  ((:module "cross-base"
    :serial t
    :pathname "cross"
    :components
    ((:file "packages")
     (:file "x64-asm")))
   (:module "mvm"
    :serial t
    :depends-on ("cross-base")
    :components
    ((:file "mvm")
     (:file "target")
     (:file "compiler")))
   (:module "mvm-x64"
    :depends-on ("cross-base" "mvm")
    :pathname "mvm"
    :components
    ((:file "translate-x64")))
   (:module "cross"
    :serial t
    :depends-on ("cross-base")
    :pathname "cross"
    :components
    ((:file "cross-compile")
     (:file "build")))
   (:module "boot"
    :serial t
    :depends-on ("cross")
    :components
    ((:file "multiboot")
     (:file "boot32")
     (:file "kernel64")
     (:file "multiboot1")))))
