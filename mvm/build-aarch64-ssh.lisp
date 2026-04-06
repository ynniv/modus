;;;; build-aarch64-ssh.lisp - Build AArch64 REPL+SSH kernel for QEMU virt
;;;;
;;;; Usage: sbcl --script mvm/build-aarch64-ssh.lisp
;;;;
;;;; Produces /tmp/modus-aarch64-ssh.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus-aarch64-ssh.bin -nographic -semihosting \
;;;;     -device 'e1000,netdev=net0,romfile=,rombar=0' \
;;;;     -netdev 'user,id=net0,hostfwd=tcp::2222-:22'

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(defun read-file-text (path)
  "Read entire file as a string."
  (with-open-file (s path :direction :input)
    (let ((text (make-string (file-length s))))
      (let ((n (read-sequence text s)))
        (subseq text 0 n)))))

(defvar *net-dir*
  (merge-pathnames "net/" *modus-base*))

(defvar *net-source*
  (format nil "~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%"
          (read-file-text (merge-pathnames "arch-aarch64.lisp" *net-dir*))
          (read-file-text (merge-pathnames "e1000.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ip.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto-fast.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ssh.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ssh-profile.lisp" *net-dir*))
          (read-file-text (merge-pathnames "aarch64-overrides.lisp" *net-dir*))))

;;; ============================================================
;;; Build AArch64 SSH image (virt + E1000)
;;; ============================================================

(in-package :modus.mvm)

;; Install the AArch64 translator
(install-aarch64-translator)
;; Enable GICv2 + virtual timer init for setup-irq
(setf *aarch64-setup-irq-enable* t)

;; Combine: net source first (defines primitives), then REPL source,
;; then SSH kernel-main that overrides the REPL's kernel-main.
;; The LAST defun named kernel-main is the entry point.
(let* ((ssh-main (format nil "~{~A~%~}"
                        (list
                         ;; Split kernel-main to stay under ~25 sequential forms per function
                         "(defun km-init-crypto ()"
                         "  (write-byte 91) (write-byte 49) (write-byte 93) (sha256-init)"
                         "  (write-byte 91) (write-byte 50) (write-byte 93) (sha512-init)"
                         "  (write-byte 91) (write-byte 51) (write-byte 93) (ed25519-init)"
                         "  (write-byte 91) (write-byte 52) (write-byte 93) (ssh-seed-random) 0)"
                         "(defun km-init-net ()"
                         "  (write-byte 91) (write-byte 53) (write-byte 93) (dhcp-client)"
                         "  (write-byte 91) (write-byte 54) (write-byte 93) (ssh-seed-random)"
                         "  (ssh-init-strings) 0)"
                         "(defun km-set-host-key ()"
                         "  (let ((state (e1000-state-base)))"
                         "    (setf (mem-ref (+ state #x710) :u64) 0)"
                         "    (setf (mem-ref (+ state #x718) :u64) 0)"
                         "    (setf (mem-ref (+ state #x720) :u64) 0)"
                         "    (setf (mem-ref (+ state #x728) :u64) 0)"
                         "    (setf (mem-ref (+ state #x730) :u32) #xBC276A3B)"
                         "    (setf (mem-ref (+ state #x734) :u32) #x2DA4B6CE)"
                         "    (setf (mem-ref (+ state #x738) :u32) #xD0A8A362)"
                         "    (setf (mem-ref (+ state #x73C) :u32) #x730D6F2A)"
                         "    (setf (mem-ref (+ state #x740) :u32) #x77153265)"
                         "    (setf (mem-ref (+ state #x744) :u32) #xA643E21D)"
                         "    (setf (mem-ref (+ state #x748) :u32) #xA148C03A)"
                         "    (setf (mem-ref (+ state #x74C) :u32) #x29DA598B)"
                         "    (setf (mem-ref (+ state #x624) :u32) 1)) 0)"
                         "(defun km-set-eph-priv ()"
                         "  (let ((state (e1000-state-base)))"
                         "    (setf (mem-ref (+ state #x6C4) :u8) #x00)"
                         "    (dotimes (i 30)"
                         "      (setf (mem-ref (+ state (+ #x6C5 i)) :u8) #x01))"
                         "    (setf (mem-ref (+ state #x6E3) :u8) #x41)) 0)"
                         ;; Use :u32 writes for ephemeral public key (8 writes instead of 32)
                         "(defun km-set-eph-pub ()"
                         "  (let ((state (e1000-state-base)))"
                         "    (setf (mem-ref (+ state #x6E4) :u32) #x9292E0A4)"
                         "    (setf (mem-ref (+ state #x6E8) :u32) #x78C251B6)"
                         "    (setf (mem-ref (+ state #x6EC) :u32) #x562C77B9)"
                         "    (setf (mem-ref (+ state #x6F0) :u32) #xBBA95F9F)"
                         "    (setf (mem-ref (+ state #x6F4) :u32) #xB406D913)"
                         "    (setf (mem-ref (+ state #x6F8) :u32) #x9D8CB66A)"
                         "    (setf (mem-ref (+ state #x6FC) :u32) #x442BDCF9)"
                         "    (setf (mem-ref (+ state #x700) :u32) #x09A2F809)) 0)"
                         "(defun km-init-conns ()"
                         "  (setf (mem-ref (+ (ssh-ipc-base) #x60438) :u32) 22)"
                         "  (let ((i 0))"
                         "    (loop"
                         "      (when (>= i 4) (return 0))"
                         "      (setf (mem-ref (conn-base i) :u32) 0)"
                         "      (setq i (+ i 1)))) 0)"
                         "(defun kernel-main ()"
                         "  (setf (mem-ref (+ (ssh-ipc-base) #x14) :u32) 0)"
                         "  (pci-assign-bars)"
                         "  (e1000-probe)"
                         "  (km-init-crypto)"
                         "  (km-init-net)"
                         "  (km-set-host-key)"
                         "  (pre-compute-host-sign)"
                         "  (write-byte 83) (write-byte 83) (write-byte 72)"
                         "  (write-byte 58) (print-dec 22) (write-byte 10)"
                         "  (km-init-conns)"
                         "  (km-set-eph-priv) (km-set-eph-pub)"
                         "  (enable-gic-timer)"
                         "  (net-actor-main))")))
       ;; SSH kernel-main MUST be LAST: "last-defun-wins" makes it the entry point.
       (combined-source (concatenate 'string
                                      cl-user::*net-source*
                                      *repl-source*
                                      ssh-main)))
  (format t "Building AArch64 SSH image (virt + E1000)...~%")
  (format t "Combined source: ~D chars~%" (length combined-source))
  (let ((image (build-image :target :aarch64 :source-text combined-source)))
    ;; Debug: show entry point info
    (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
    (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
    (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
    (write-kernel-image image "/tmp/modus-aarch64-ssh.bin")
    (format t "Done. Boot with:~%")
    (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \\~%")
    (format t "    -kernel /tmp/modus-aarch64-ssh.bin -nographic -semihosting \\~%")
    (format t "    -device 'e1000,netdev=net0,romfile=,rombar=0' \\~%")
    (format t "    -netdev 'user,id=net0,hostfwd=tcp::2222-:22'~%")))
