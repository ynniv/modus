;;;; build-x64-ssh.lisp - Build x86-64 SSH kernel for QEMU via MVM
;;;;
;;;; Usage: sbcl --script mvm/build-x64-ssh.lisp
;;;;
;;;; Produces /tmp/modus-x64-ssh.bin — boot with:
;;;;   qemu-system-x86_64 -m 512 -nographic -no-reboot \
;;;;     -kernel /tmp/modus-x64-ssh.bin \
;;;;     -device 'e1000,netdev=net0,romfile=,rombar=0' \
;;;;     -netdev 'user,id=net0,hostfwd=tcp::2222-:22'
;;;;
;;;; Uses E1000 PCI NIC (same as AArch64 virt build).
;;;; 64-bit crypto via crypto-fast.lisp (mem-ref :u32 direct limb access).

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

;;; Source load order:
;;;   arch-x86 → e1000 → ip → crypto → crypto-fast → ssh →
;;;   aarch64-overrides → mvm-ssh-fixes
;;;
;;; crypto-fast.lisp: mem-ref :u32 field element ops (correct on x64 via MVM).
;;; mvm-ssh-fixes.lisp: safe overrides for variable-index ASET/AREF bugs in
;;;   ssh-put-u32, ssh-concat2, ssh-make-str, ssh-mem-store, ssh-mem-load,
;;;   ssh-derive-key, chacha20-crypt, ssh-dispatch-msg, etc.
;;;   Also arena-based fe-pow-sqrt/ed-recover-x to prevent heap exhaustion.
;;;   Must load LAST (after aarch64-overrides) for last-defun-wins.
(defvar *net-source*
  (format nil "~A~%~A~%~A~%~A~%~A~%~A~%~A~%"
          (read-file-text (merge-pathnames "arch-x86.lisp" *net-dir*))
          (read-file-text (merge-pathnames "e1000.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ip.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ssh.lisp" *net-dir*))
          (read-file-text (merge-pathnames "aarch64-overrides.lisp" *net-dir*))
          (read-file-text (merge-pathnames "mvm-ssh-fixes.lisp" *net-dir*))))

;;; ============================================================
;;; Build x86-64 SSH image (E1000 PCI NIC)
;;; ============================================================

(in-package :modus.mvm)

;; Install the x64 translator
(modus.mvm.x64:install-x64-translator)

(let* ((ssh-main (format nil "~{~A~%~}"
                        (list
                         ;; Fix ssh-receive-version: (when 0 ...) is truthy on x64 (nil=0xDEAD0001)
                         "(defun ssh-receive-version (ssh)"
                         "  (let ((got-version 0))"
                         "    (let ((tries 0))"
                         "      (loop"
                         "        (when (not (zerop got-version)) (return 1))"
                         "        (when (> tries 50) (return 0))"
                         "        (let ((msg (receive)))"
                         "          (when (zerop msg) (return 0)))"
                         "        (let ((blen (mem-ref (+ ssh #x6D4) :u32)))"
                         "          (when (> blen 8)"
                         "            (let ((buf-base (+ ssh #x6D8)))"
                         "              (when (eq (mem-ref buf-base :u8) 83)"
                         "                (when (eq (mem-ref (+ buf-base 1) :u8) 83)"
                         "                  (when (eq (mem-ref (+ buf-base 2) :u8) 72)"
                         "                    (let ((end 0))"
                         "                      (let ((i 3))"
                         "                        (loop"
                         "                          (when (not (zerop end)) (return 0))"
                         "                          (when (> i blen) (return 0))"
                         "                          (when (eq (mem-ref (+ buf-base i) :u8) 10)"
                         "                            (setq end i))"
                         "                          (setq i (+ i 1))))"
                         "                      (when (not (zerop end))"
                         "                        (let ((vlen end))"
                         "                          (when (> end 0)"
                         "                            (when (eq (mem-ref (+ buf-base (- end 1)) :u8) 13)"
                         "                              (setq vlen (- end 1))))"
                         "                          (let ((ver-base (+ ssh #x650)))"
                         "                            (dotimes (j vlen)"
                         "                              (setf (mem-ref (+ ver-base j) :u8)"
                         "                                    (mem-ref (+ buf-base j) :u8))))"
                         "                          (setf (mem-ref (+ ssh #x6D0) :u32) vlen)"
                         "                          (ssh-buf-consume ssh (+ end 1))"
                         "                          (setq got-version 1))))))))))"
                         "        (setq tries (+ tries 1))))))"
                         ;; Override ssh-copy-host-key: use pre-computed keys from state
                         "(defun ssh-copy-host-key (conn)"
                         "  (let ((ssh (conn-ssh conn)))"
                         "    (let ((state (e1000-state-base)))"
                         "      (let ((src-priv (+ state #x710)))"
                         "        (let ((dst-priv (+ ssh #x110)))"
                         "          (dotimes (i 32)"
                         "            (setf (mem-ref (+ dst-priv i) :u8)"
                         "                  (mem-ref (+ src-priv i) :u8)))))"
                         "      (let ((src-pub (+ state #x730)))"
                         "        (let ((dst-pub (+ ssh #x130)))"
                         "          (dotimes (i 32)"
                         "            (setf (mem-ref (+ dst-pub i) :u8)"
                         "                  (mem-ref (+ src-pub i) :u8))))))))"
                         ;; No-op usb-keepalive for x86 (no USB, E1000 NIC)
                         "(defun usb-keepalive () 0)"
                         ;; Override ssh-handle-kex: safe version with pre-computed keys
                         "(defun ssh-handle-kex (ssh kex-init-payload kex-init-len)"
                         "  (let ((cli-eph (make-array 32)))"
                         "    (let ((ci 0))"
                         "      (loop"
                         "        (when (>= ci 32) (return 0))"
                         "        (let ((src-idx (+ 5 ci)))"
                         "          (let ((val (aref kex-init-payload src-idx)))"
                         "            (let ((dummy (aset cli-eph ci val))) dummy)))"
                         "        (setq ci (+ ci 1))))"
                         "    (let ((state (e1000-state-base)))"
                         "      (let ((srv-priv (make-array 32)))"
                         "        (safe-copy-mem-to-arr srv-priv (+ state #x6C4) 32)"
                         "        (let ((srv-eph (make-array 32)))"
                         "          (safe-copy-mem-to-arr srv-eph (+ state #x6E4) 32)"
                         "          (let ((shared (x25519 srv-priv cli-eph)))"
                         "            (ssh-mem-store (+ ssh #x070) shared 32)"
                         "            (let ((h (ssh-compute-exchange-hash ssh cli-eph srv-eph shared)))"
                         "              (ssh-mem-store (+ ssh #x050) h 32)"
                         "              (when (zerop (mem-ref ssh :u32))"
                         "                (ssh-mem-store (+ ssh #x030) h 32)"
                         "                (setf (mem-ref ssh :u32) 1))"
                         "              (let ((sig (ed25519-sign-fast h 32)))"
                         "                (ssh-send-kex-reply ssh sig srv-eph)))))))))"
                         ;; Override ssh-handle-connection: nil-safe checks (nil != 0 on x64)
                         "(defun ssh-handle-connection (ssh)"
                         "  (let ((cb (- ssh #x20)))"
                         "    (ssh-send-version ssh)"
                         "    (when (zerop (ssh-receive-version ssh)) (return ()))"
                         "    (let ((kexinit (ssh-build-kexinit ssh)))"
                         "      (ssh-send-payload ssh kexinit (array-length kexinit)))"
                         "    (let ((cli-kex (ssh-receive-packet ssh 50000)))"
                         "      (when (not cli-kex) (return ()))"
                         "      (let ((cli-kex-payload (car cli-kex)))"
                         "        (let ((cli-kex-len (cdr cli-kex)))"
                         "          (when (not (eq (aref cli-kex-payload 0) 20)) (return ()))"
                         "          (ssh-mem-store (+ cb #x1F00) cli-kex-payload cli-kex-len)"
                         "          (setf (mem-ref (+ ssh #x20) :u32) cli-kex-len)"
                         "          (let ((kex-init (ssh-receive-packet ssh 50000)))"
                         "            (when (not kex-init) (return ()))"
                         "            (let ((kex-payload (car kex-init)))"
                         "              (when (not (eq (aref kex-payload 0) 30)) (return ()))"
                         "              (ssh-handle-kex ssh kex-payload (cdr kex-init))"
                         "              (ssh-send-newkeys ssh)"
                         "              (let ((nk (ssh-receive-packet ssh 50000)))"
                         "                (when (not nk) (return ()))"
                         "                (when (not (eq (aref (car nk) 0) 21)) (return ()))"
                         "                (ssh-derive-keys ssh)"
                         "                (ssh-message-loop ssh)))))))))"
                         ;; Split kernel-main into phases to stay under ~25 sequential forms limit
                         "(defun km-init-crypto ()"
                         "  (write-byte 91) (write-byte 49) (write-byte 93)"
                         "  (sha256-init)"
                         "  (write-byte 91) (write-byte 50) (write-byte 93)"
                         "  (sha512-init)"
                         "  (write-byte 91) (write-byte 51) (write-byte 93)"
                         "  (ed25519-init)"
                         "  (write-byte 91) (write-byte 52) (write-byte 93)"
                         "  (ssh-seed-random) 0)"
                         "(defun km-init-net ()"
                         "  (write-byte 91) (write-byte 53) (write-byte 93)"
                         "  (dhcp-client)"
                         "  (write-byte 91) (write-byte 54) (write-byte 93)"
                         "  (ssh-seed-random)"
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
                         ;; kernel-main: init hardware + crypto, then delegate to ssh-server
                         "(defun kernel-main ()"
                         "  (write-byte 90) (write-byte 90) (write-byte 90) (write-byte 10)"
                         "  (setf (mem-ref (+ (ssh-ipc-base) #x14) :u32) 0)"
                         "  (pci-assign-bars)"
                         "  (e1000-probe)"
                         "  (km-init-crypto)"
                         "  (km-init-net)"
                         "  (setup-irq)"
                         "  (setf (mem-ref #x600010 :u32) 1)"
                         "  (km-set-host-key)"
                         "  (pre-compute-host-sign)"
                         "  (pre-compute-server-eph (conn-ssh 0))"
                         "  (ssh-server 22))"
                         )))
       ;; SSH kernel-main MUST be LAST: "last-defun-wins" makes it the entry point.
       (combined-source (concatenate 'string
                                      cl-user::*net-source*
                                      *repl-source*
                                      ssh-main)))
  (format t "Building x86-64 SSH image (E1000 PCI)...~%")
  (format t "Combined source: ~D chars~%" (length combined-source))
  (format t "ssh-main length: ~D~%" (length ssh-main))
  (format t "ssh-handle-kex in source: ~A~%" (search "ssh-handle-kex" combined-source))
  ;; Count forms to make sure reader processes all source
  (let ((test-forms (read-all-forms combined-source)))
    (format t "Total forms read: ~D~%" (length test-forms))
    (format t "Last form: ~A~%" (first (last test-forms))))
  (let ((image (build-image :target :x86-64 :source-text combined-source)))
    (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
    (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
    (format t "Boot code size: ~D~%" (length (kernel-image-boot-code image)))
    (write-kernel-image image "/tmp/modus-x64-ssh.bin")
    (format t "Done. Boot with:~%")
    (format t "  qemu-system-x86_64 -m 512 -nographic -no-reboot \\~%")
    (format t "    -kernel /tmp/modus-x64-ssh.bin \\~%")
    (format t "    -device 'e1000,netdev=net0,romfile=,rombar=0' \\~%")
    (format t "    -netdev 'user,id=net0,hostfwd=tcp::2222-:22'~%")))
