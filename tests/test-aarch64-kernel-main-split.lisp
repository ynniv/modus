;;;; test-aarch64-kernel-main-split.lisp — Verify the kernel-main split fix
;;;;
;;;; Usage: sbcl --script tests/test-aarch64-kernel-main-split.lisp
;;;;
;;;; Builds two AArch64 SSH images:
;;;;   A) BROKEN: monolithic kernel-main (~40 sequential forms)
;;;;   B) FIXED: split into helper functions (<25 forms each)
;;;; Boots each in QEMU, runs ssh-kex-dump.py, checks if signature verifies.

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(in-package :modus.mvm)
(install-aarch64-translator)
(setf *aarch64-setup-irq-enable* t)

(defun read-file (name)
  (let ((path (merge-pathnames name cl-user::*modus-base*)))
    (with-open-file (f path :direction :input)
      (let ((text (make-string (file-length f))))
        (let ((n (read-sequence text f))) (subseq text 0 n))))))

(defvar *net-source*
  (format nil "~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%"
          (read-file "net/arch-aarch64.lisp")
          (read-file "net/e1000.lisp")
          (read-file "net/ip.lisp")
          (read-file "net/crypto.lisp")
          (read-file "net/crypto-fast.lisp")
          (read-file "net/ssh.lisp")
          (read-file "net/ssh-profile.lisp")
          (read-file "net/aarch64-overrides.lisp")))

;;; Shared: host key + ephemeral key bytes (same for both builds)
(defvar *key-setup* "
(defun km-set-host-key ()
  (let ((state (e1000-state-base)))
    (setf (mem-ref (+ state #x710) :u64) 0) (setf (mem-ref (+ state #x718) :u64) 0)
    (setf (mem-ref (+ state #x720) :u64) 0) (setf (mem-ref (+ state #x728) :u64) 0)
    (setf (mem-ref (+ state #x730) :u32) #xBC276A3B) (setf (mem-ref (+ state #x734) :u32) #x2DA4B6CE)
    (setf (mem-ref (+ state #x738) :u32) #xD0A8A362) (setf (mem-ref (+ state #x73C) :u32) #x730D6F2A)
    (setf (mem-ref (+ state #x740) :u32) #x77153265) (setf (mem-ref (+ state #x744) :u32) #xA643E21D)
    (setf (mem-ref (+ state #x748) :u32) #xA148C03A) (setf (mem-ref (+ state #x74C) :u32) #x29DA598B)
    (setf (mem-ref (+ state #x624) :u32) 1)) 0)
(defun km-set-eph-key ()
  (let ((state (e1000-state-base)))
    (setf (mem-ref (+ state #x6C4) :u8) #x00)
    (dotimes (i 30) (setf (mem-ref (+ state (+ #x6C5 i)) :u8) #x01))
    (setf (mem-ref (+ state #x6E3) :u8) #x41)
    (setf (mem-ref (+ state #x6E4) :u8) #xA4) (setf (mem-ref (+ state #x6E5) :u8) #xE0)
    (setf (mem-ref (+ state #x6E6) :u8) #x92) (setf (mem-ref (+ state #x6E7) :u8) #x92)
    (setf (mem-ref (+ state #x6E8) :u8) #xB6) (setf (mem-ref (+ state #x6E9) :u8) #x51)
    (setf (mem-ref (+ state #x6EA) :u8) #xC2) (setf (mem-ref (+ state #x6EB) :u8) #x78)
    (setf (mem-ref (+ state #x6EC) :u8) #xB9) (setf (mem-ref (+ state #x6ED) :u8) #x77)
    (setf (mem-ref (+ state #x6EE) :u8) #x2C) (setf (mem-ref (+ state #x6EF) :u8) #x56)
    (setf (mem-ref (+ state #x6F0) :u8) #x9F) (setf (mem-ref (+ state #x6F1) :u8) #x5F)
    (setf (mem-ref (+ state #x6F2) :u8) #xA9) (setf (mem-ref (+ state #x6F3) :u8) #xBB)
    (setf (mem-ref (+ state #x6F4) :u8) #x13) (setf (mem-ref (+ state #x6F5) :u8) #xD9)
    (setf (mem-ref (+ state #x6F6) :u8) #x06) (setf (mem-ref (+ state #x6F7) :u8) #xB4)
    (setf (mem-ref (+ state #x6F8) :u8) #x6A) (setf (mem-ref (+ state #x6F9) :u8) #xB6)
    (setf (mem-ref (+ state #x6FA) :u8) #x8C) (setf (mem-ref (+ state #x6FB) :u8) #x9D)
    (setf (mem-ref (+ state #x6FC) :u8) #xF9) (setf (mem-ref (+ state #x6FD) :u8) #xDC)
    (setf (mem-ref (+ state #x6FE) :u8) #x2B) (setf (mem-ref (+ state #x6FF) :u8) #x44)
    (setf (mem-ref (+ state #x700) :u8) #x09) (setf (mem-ref (+ state #x701) :u8) #xF8)
    (setf (mem-ref (+ state #x702) :u8) #xA2) (setf (mem-ref (+ state #x703) :u8) #x09)) 0)
")

;;; BROKEN: monolithic kernel-main (~40 sequential forms, no helpers)
(defvar *broken-main* (concatenate 'string *key-setup* "
(defun kernel-main ()
  (setf (mem-ref (+ (ssh-ipc-base) #x14) :u32) 0)
  (pci-assign-bars) (e1000-probe)
  (write-char-serial 91) (write-char-serial 49) (write-char-serial 93) (sha256-init)
  (write-char-serial 91) (write-char-serial 50) (write-char-serial 93) (sha512-init)
  (write-char-serial 91) (write-char-serial 51) (write-char-serial 93) (ed25519-init)
  (write-char-serial 91) (write-char-serial 52) (write-char-serial 93) (ssh-seed-random)
  (write-char-serial 91) (write-char-serial 53) (write-char-serial 93) (dhcp-client)
  (write-char-serial 91) (write-char-serial 54) (write-char-serial 93) (ssh-seed-random) (ssh-init-strings)
  (km-set-host-key) (pre-compute-host-sign)
  (write-char-serial 83) (write-char-serial 83) (write-char-serial 72) (write-char-serial 58) (print-dec 22) (write-char-serial 10)
  (setf (mem-ref (+ (ssh-ipc-base) #x60438) :u32) 22)
  (let ((i 0)) (loop (when (>= i 4) (return 0)) (setf (mem-ref (conn-base i) :u32) 0) (setq i (+ i 1))))
  (km-set-eph-key)
  (enable-gic-timer)
  (net-actor-main))
"))

;;; FIXED: split kernel-main (<25 forms each)
(defvar *fixed-main* (concatenate 'string *key-setup* "
(defun km-init-crypto ()
  (write-char-serial 91) (write-char-serial 49) (write-char-serial 93) (sha256-init)
  (write-char-serial 91) (write-char-serial 50) (write-char-serial 93) (sha512-init)
  (write-char-serial 91) (write-char-serial 51) (write-char-serial 93) (ed25519-init)
  (write-char-serial 91) (write-char-serial 52) (write-char-serial 93) (ssh-seed-random) 0)
(defun km-init-net ()
  (write-char-serial 91) (write-char-serial 53) (write-char-serial 93) (dhcp-client)
  (write-char-serial 91) (write-char-serial 54) (write-char-serial 93) (ssh-seed-random) (ssh-init-strings) 0)
(defun km-init-conns ()
  (setf (mem-ref (+ (ssh-ipc-base) #x60438) :u32) 22)
  (let ((i 0)) (loop (when (>= i 4) (return 0)) (setf (mem-ref (conn-base i) :u32) 0) (setq i (+ i 1)))) 0)
(defun kernel-main ()
  (setf (mem-ref (+ (ssh-ipc-base) #x14) :u32) 0)
  (pci-assign-bars) (e1000-probe)
  (km-init-crypto) (km-init-net)
  (km-set-host-key) (pre-compute-host-sign)
  (write-char-serial 83) (write-char-serial 83) (write-char-serial 72) (write-char-serial 58) (print-dec 22) (write-char-serial 10)
  (km-init-conns) (km-set-eph-key)
  (enable-gic-timer)
  (net-actor-main))
"))

(defun build-and-test (name main-source)
  (format t "~%~A:~%" name)
  (let* ((src (concatenate 'string *net-source* *repl-source* main-source))
         (img (build-image :target :aarch64 :source-text src))
         (bin (format nil "/tmp/km-~A.bin" name)))
    (write-kernel-image img bin)
    (format t "  Built ~D bytes. Booting...~%" (length (kernel-image-image-bytes img)))
    (finish-output)
    ;; Boot QEMU, wait for SSH, run kex dump
    (let ((result
            (with-output-to-string (s)
              (sb-ext:run-program "/bin/bash"
                (list "-c" (format nil "
~A -machine virt -cpu cortex-a57 -m 512 -kernel ~A -nographic -semihosting -device 'e1000,netdev=net0,romfile=,rombar=0' -netdev 'user,id=net0,hostfwd=tcp::2222-:22' > /dev/null 2>&1 &
QPID=$!
for i in $(seq 1 60); do (echo > /dev/tcp/localhost/2222) 2>/dev/null && break; sleep 1; done
python3 ~A/tests/ssh-kex-dump.py localhost 2222 2>&1
kill $QPID 2>/dev/null; wait $QPID 2>/dev/null
" "qemu-system-aarch64" bin (namestring cl-user::*modus-base*)))
                :output s :wait t))))
      ;; Check result
      (if (search "SIGNATURE VALID" result)
          (format t "  PASS — signature valid~%")
          (if (search "SIGNATURE INVALID" result)
              (progn
                (format t "  FAIL — signature invalid~%")
                ;; Print the ephemeral key for diagnosis
                (let ((fpos (search "f (server ephemeral)" result)))
                  (when fpos
                    (format t "  ~A~%" (subseq result fpos (min (+ fpos 100) (length result)))))))
              (format t "  ERROR — unexpected output: ~A~%"
                      (subseq result 0 (min 200 (length result)))))))))

(format t "=== AArch64 kernel-main split test ===~%")
(build-and-test "BROKEN-monolithic" *broken-main*)
(build-and-test "FIXED-split" *fixed-main*)
(format t "~%Done.~%")
