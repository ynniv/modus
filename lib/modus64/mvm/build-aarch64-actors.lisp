;;;; build-aarch64-actors.lisp - Build AArch64 SSH kernel with actor system
;;;;
;;;; Usage: cd lib/modus64 && sbcl --script mvm/build-aarch64-actors.lisp
;;;;
;;;; Produces /tmp/modus64-aarch64-actors.bin — boot with:
;;;;   qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
;;;;     -kernel /tmp/modus64-aarch64-actors.bin -nographic -semihosting \
;;;;     -device 'e1000,netdev=net0,romfile=,rombar=0' \
;;;;     -netdev 'user,id=net0,hostfwd=tcp::2222-:22'

;;; ============================================================
;;; Load MVM system
;;; ============================================================

(defvar *modus-base*
  (let* ((mvm-dir (directory-namestring (truename *load-truename*)))
         (modus-dir (namestring (truename (merge-pathnames "../" mvm-dir)))))
    (pathname modus-dir)))

(defun mvm-load (relative-path)
  (let ((path (merge-pathnames relative-path *modus-base*)))
    (load path :verbose nil :print nil)))

(format t "Loading MVM system...~%")

(mvm-load "cross/packages.lisp")
(mvm-load "cross/x64-asm.lisp")
(mvm-load "mvm/mvm.lisp")
(mvm-load "mvm/target.lisp")
(mvm-load "mvm/compiler.lisp")
(mvm-load "mvm/interp.lisp")
(mvm-load "boot/boot-x64.lisp")
(mvm-load "boot/boot-riscv.lisp")
(mvm-load "boot/boot-aarch64.lisp")
(mvm-load "boot/boot-rpi.lisp")
(mvm-load "boot/boot-ppc64.lisp")
(mvm-load "boot/boot-ppc32.lisp")
(mvm-load "boot/boot-i386.lisp")
(mvm-load "boot/boot-68k.lisp")
(mvm-load "boot/boot-arm32.lisp")
(mvm-load "mvm/translate-x64.lisp")
(mvm-load "mvm/translate-riscv.lisp")
(mvm-load "mvm/translate-aarch64.lisp")
(mvm-load "mvm/translate-ppc.lisp")
(mvm-load "mvm/translate-i386.lisp")
(mvm-load "mvm/translate-68k.lisp")
(mvm-load "mvm/translate-arm32.lisp")
(mvm-load "mvm/cross.lisp")

;;; ============================================================
;;; Load REPL source + networking + actor source
;;; ============================================================

(format t "Loading REPL + networking + actor source...~%")
(mvm-load "mvm/repl-source.lisp")

(defun read-file-text (path)
  "Read entire file as a string."
  (with-open-file (s path :direction :input)
    (let ((text (make-string (file-length s))))
      (let ((n (read-sequence text s)))
        (subseq text 0 n)))))

(defvar *net-dir*
  (merge-pathnames "net/" *modus-base*))

;; Source load order (actor-aware):
;; 1. arch-aarch64.lisp     - PCI, E1000, alloc primitives, actor address hooks
;; 2. actors.lisp            - shared actor system (per-CPU, smp-init, scheduling)
;; 3. e1000.lisp             - E1000 driver
;; 4. ip.lisp                - ARP/IP/TCP/DHCP
;; 5. crypto.lisp            - SHA, ChaCha20, Poly1305, X25519, Ed25519
;; 6. ssh.lisp               - SSH server
;; 7. aarch64-overrides.lisp - line editor, buffer reader, SSH overrides
;; 8. actors-net-overrides.lisp - actor-aware receive/spawn/exit overrides
(defvar *net-source*
  (format nil "~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%"
          (read-file-text (merge-pathnames "arch-aarch64.lisp" *net-dir*))
          (read-file-text (merge-pathnames "actors.lisp" *net-dir*))
          (read-file-text (merge-pathnames "e1000.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ip.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ssh.lisp" *net-dir*))
          (read-file-text (merge-pathnames "http.lisp" *net-dir*))
          (read-file-text (merge-pathnames "http-client.lisp" *net-dir*))
          (read-file-text (merge-pathnames "aarch64-overrides.lisp" *net-dir*))
          (read-file-text (merge-pathnames "actors-net-overrides.lisp" *net-dir*))))

;;; ============================================================
;;; Build AArch64 Actors+SSH image (virt + E1000)
;;; ============================================================

(in-package :modus64.mvm)

(install-aarch64-translator)

;; Set scheduler lock address for RESTORE-CONTEXT unlock sequence
(setf *aarch64-sched-lock-addr* #x41200200)

;; kernel-main: init SMP + actors, spawn net-actor-main, idle yield loop
(let* ((ssh-main (format nil "~{~A~%~}"
                        (list
                         "(defun kernel-main ()"
                         "  (smp-init)"
                         "  (actor-init)"
                         ;; Clear eval globals pointer — uninitialized RAM causes hang
                         "  (setf (mem-ref (+ (ssh-ipc-base) #x60000) :u64) 0)"
                         "  (pci-assign-bars)"
                         "  (e1000-probe)"
                         "  (write-byte 91) (write-byte 49) (write-byte 93)"
                         "  (sha256-init)"
                         "  (write-byte 91) (write-byte 50) (write-byte 93)"
                         "  (sha512-init)"
                         "  (write-byte 91) (write-byte 51) (write-byte 93)"
                         "  (ed25519-init)"
                         "  (write-byte 91) (write-byte 52) (write-byte 93)"
                         "  (ssh-seed-random)"
                         "  (write-byte 91) (write-byte 53) (write-byte 93)"
                         "  (dhcp-discover)"
                         "  (write-byte 91) (write-byte 54) (write-byte 93)"
                         "  (ssh-seed-random)"
                         "  (ssh-init-strings)"
                         ;; Embed pre-computed Ed25519 host key
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
                         "    (setf (mem-ref (+ state #x624) :u32) 1))"
                         ;; Pre-compute ed25519 host key derivatives (s, prefix)
                         "  (pre-compute-host-sign)"
                         "  (write-byte 83) (write-byte 83) (write-byte 72)"
                         "  (write-byte 58) (print-dec 22) (write-byte 10)"
                         "  (setf (mem-ref (+ (ssh-ipc-base) #x60438) :u32) 22)"
                         "  (let ((i 0))"
                         "    (loop"
                         "      (when (>= i 4) (return 0))"
                         "      (setf (mem-ref (conn-base i) :u32) 0)"
                         "      (setq i (+ i 1))))"
                         ;; Pre-compute server ephemeral X25519 key pair
                         "  (pre-compute-server-eph (conn-ssh 0))"
                         ;; Spawn net-actor-main as actor 2
                         "  (actor-spawn (fn-addr net-actor-main))"
                         ;; Primordial actor: idle yield loop
                         "  (loop (yield)))")))       (combined-source (concatenate 'string
                                      ssh-main
                                      cl-user::*net-source*
                                      *repl-source*)))
  (format t "Building AArch64 Actors+SSH image...~%")
  (format t "Combined source: ~D chars~%" (length combined-source))
  (let ((image (build-image :target :aarch64 :source-text combined-source)))
    (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
    (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
    (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
    (write-kernel-image image "/tmp/modus64-aarch64-actors.bin")
    (format t "Done. Boot with:~%")
    (format t "  qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \\~%")
    (format t "    -kernel /tmp/modus64-aarch64-actors.bin -nographic -semihosting \\~%")
    (format t "    -device 'e1000,netdev=net0,romfile=,rombar=0' \\~%")
    (format t "    -netdev 'user,id=net0,hostfwd=tcp::2222-:22'~%")))
