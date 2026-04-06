;;;; modus.asd - ASDF system definition for Modus
;;;;
;;;; This loads only the MVM core (compiler, translators) and the
;;;; shared assembler. The full build system is invoked via:
;;;;   sbcl --script mvm/build-fixpoint.lisp
;;;;   sbcl --script mvm/build-{x64,i386,aarch64,arm32}-{repl,ssh}.lisp

(asdf:defsystem :modus
  :description "Modus - bare-metal Lisp OS via MVM"
  :version "0.2.0"
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
     (:file "compiler")
     (:file "interp")))
   (:module "mvm-translators"
    :depends-on ("cross-base" "mvm")
    :pathname "mvm"
    :components
    ((:file "translate-x64")
     (:file "translate-aarch64")
     (:file "translate-i386")
     (:file "translate-arm32")))))
