(asdf:defsystem #:modus
  :description "Modus: Bare Metal Lisp Environment"
  :author "Modus Development Team"
  :license "MIT"
  :version "0.1.0"
  :depends-on (#:binary-types)
  :components ((:file "package")
              (:file "version" :depends-on ("package"))
              (:module "src"
                :depends-on ("package" "version")
                :components
                ((:module "core"
                  :components ((:file "package")
                             (:file "hardware" :depends-on ("package"))
                             (:file "memory" :depends-on ("package" "hardware"))))
                 (:module "compiler"
                  :components ((:file "package")))
                 (:module "runtime"
                  :components ((:file "package")))
                 (:module "security"
                  :components ((:file "package")))
                 (:module "ui"
                  :components ((:file "package"))))))
  :in-order-to ((test-op (test-op "modus/tests"))))

(asdf:defsystem #:modus/image
  :description "Build a bootable Modus image"
  :depends-on (#:modus)
  :components ((:file "build-image")))

(asdf:defsystem #:modus/tests
  :description "Test suite for Modus"
  :depends-on (#:modus)
  :components ((:module "tests"
                :components ((:file "package")))))