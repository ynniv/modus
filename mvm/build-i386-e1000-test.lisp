;;;; Minimal E1000 SSH test — same as NE2000 build but with E1000
;;;; Tests whether E1000 raw MMIO + SSH works without console/dispatch code

(load (merge-pathnames "../lib/load-mvm.lisp"
                       (directory-namestring (truename *load-truename*))))
(mvm-load "mvm/repl-source.lisp")

(defun read-file-text (path)
  (with-open-file (s path :direction :input)
    (let ((text (make-string (file-length s))))
      (let ((n (read-sequence text s)))
        (subseq text 0 n)))))

(defvar *net-dir*
  (merge-pathnames "net/" *modus-base*))

(defvar *e1000-raw-source*
  (read-file-text (merge-pathnames "net/i386-e1000-raw.lisp" *modus-base*)))

;;; Same source order as NE2000 build, but with e1000 instead of ne2000,
;;; plus e1000-raw at the end for MMIO overrides
(defvar *net-source*
  (format nil "~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%~A~%"
          (read-file-text (merge-pathnames "arch-i386.lisp" *net-dir*))
          (read-file-text (merge-pathnames "e1000.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ip.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto-32.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto-w32.lisp" *net-dir*))
          (read-file-text (merge-pathnames "ssh.lisp" *net-dir*))
          (read-file-text (merge-pathnames "http.lisp" *net-dir*))
          (read-file-text (merge-pathnames "aarch64-overrides.lisp" *net-dir*))
          (read-file-text (merge-pathnames "32bit-overrides.lisp" *net-dir*))
          (read-file-text (merge-pathnames "crypto-32-fast.lisp" *net-dir*))))

;;; String literal expansion for e1000-raw source
(defun gen-chars-cons (text)
  (if (zerop (length text)) "nil"
      (with-output-to-string (s)
        (loop for c across text do (format s "(cons ~D " (char-code c)))
        (write-string "nil" s)
        (dotimes (i (length text)) (write-char #\) s)))))

(defun expand-print-str (text)
  (format nil "(write-string-codes ~A)" (gen-chars-cons text)))
(defun expand-print-ln (text)
  (format nil "(progn (write-string-codes ~A) (write-char-output 10) 0)"
          (gen-chars-cons text)))
(defun expand-print-reg-raw (name-text)
  (format nil "(progn (write-string-codes ~A) (write-char-output 58) (write-char-output 32) (mmio-print-result) (write-char-output 10) 0)"
          (gen-chars-cons name-text)))

(defun expand-one-pattern (source pattern expander)
  (let ((result source)
        (pat (concatenate 'string "(" pattern " \"")))
    (loop
      (let ((pos (search pat result)))
        (unless pos (return result))
        (let* ((str-start (+ pos (length pat)))
               (str-end (position #\" result :start str-start)))
          (unless str-end (return result))
          (let* ((close-paren (position #\) result :start (1+ str-end)))
                 (text (subseq result str-start str-end))
                 (expansion (funcall expander text)))
            (setf result (concatenate 'string
                                      (subseq result 0 pos)
                                      expansion
                                      (subseq result (1+ close-paren))))))))))

(defun expand-string-calls (source-text)
  (let ((result source-text))
    (setf result (expand-one-pattern result "print-reg-raw" #'expand-print-reg-raw))
    (setf result (expand-one-pattern result "print-ln" #'expand-print-ln))
    (setf result (expand-one-pattern result "print-str" #'expand-print-str))
    result))

(setf *e1000-raw-source* (expand-string-calls *e1000-raw-source*))

(in-package :modus.mvm)

(modus.mvm.i386:install-i386-translator)

;;; Exact same kernel-main as NE2000 build, just uses e1000-probe
(let* ((ssh-main (format nil "~{~A~%~}"
                        (list
                         "(defun kernel-main ()"
                         "  (e1000-probe)"
                         "  (sha256-init)"
                         "  (sha512-init)"
                         "  (ed25519-init)"
                         "  (ssh-seed-random)"
                         "  (dhcp-client)"
                         "  (ssh-seed-random)"
                         "  (ssh-init-strings)"
                         "  (let ((state (e1000-state-base)))"
                         "    (dotimes (i 32)"
                         "      (setf (mem-ref (+ state (+ #x710 i)) :u8) 0))"
                         "    (setf (mem-ref (+ state #x730) :u8) #x3B)"
                         "    (setf (mem-ref (+ state #x731) :u8) #x6A)"
                         "    (setf (mem-ref (+ state #x732) :u8) #x27)"
                         "    (setf (mem-ref (+ state #x733) :u8) #xBC)"
                         "    (setf (mem-ref (+ state #x734) :u8) #xCE)"
                         "    (setf (mem-ref (+ state #x735) :u8) #xB6)"
                         "    (setf (mem-ref (+ state #x736) :u8) #xA4)"
                         "    (setf (mem-ref (+ state #x737) :u8) #x2D)"
                         "    (setf (mem-ref (+ state #x738) :u8) #x62)"
                         "    (setf (mem-ref (+ state #x739) :u8) #xA3)"
                         "    (setf (mem-ref (+ state #x73A) :u8) #xA8)"
                         "    (setf (mem-ref (+ state #x73B) :u8) #xD0)"
                         "    (setf (mem-ref (+ state #x73C) :u8) #x2A)"
                         "    (setf (mem-ref (+ state #x73D) :u8) #x6F)"
                         "    (setf (mem-ref (+ state #x73E) :u8) #x0D)"
                         "    (setf (mem-ref (+ state #x73F) :u8) #x73)"
                         "    (setf (mem-ref (+ state #x740) :u8) #x65)"
                         "    (setf (mem-ref (+ state #x741) :u8) #x32)"
                         "    (setf (mem-ref (+ state #x742) :u8) #x15)"
                         "    (setf (mem-ref (+ state #x743) :u8) #x77)"
                         "    (setf (mem-ref (+ state #x744) :u8) #x1D)"
                         "    (setf (mem-ref (+ state #x745) :u8) #xE2)"
                         "    (setf (mem-ref (+ state #x746) :u8) #x43)"
                         "    (setf (mem-ref (+ state #x747) :u8) #xA6)"
                         "    (setf (mem-ref (+ state #x748) :u8) #x3A)"
                         "    (setf (mem-ref (+ state #x749) :u8) #xC0)"
                         "    (setf (mem-ref (+ state #x74A) :u8) #x48)"
                         "    (setf (mem-ref (+ state #x74B) :u8) #xA1)"
                         "    (setf (mem-ref (+ state #x74C) :u8) #x8B)"
                         "    (setf (mem-ref (+ state #x74D) :u8) #x59)"
                         "    (setf (mem-ref (+ state #x74E) :u8) #xDA)"
                         "    (setf (mem-ref (+ state #x74F) :u8) #x29)"
                         "    (setf (mem-ref (+ state #x624) :u32) 1))"
                         "  (let ((state (e1000-state-base)))"
                         "    (setf (mem-ref (+ state #x680) :u8) #x50)"
                         "    (setf (mem-ref (+ state #x681) :u8) #x46)"
                         "    (setf (mem-ref (+ state #x682) :u8) #xAD)"
                         "    (setf (mem-ref (+ state #x683) :u8) #xC1)"
                         "    (setf (mem-ref (+ state #x684) :u8) #xDB)"
                         "    (setf (mem-ref (+ state #x685) :u8) #xA8)"
                         "    (setf (mem-ref (+ state #x686) :u8) #x38)"
                         "    (setf (mem-ref (+ state #x687) :u8) #x86)"
                         "    (setf (mem-ref (+ state #x688) :u8) #x7B)"
                         "    (setf (mem-ref (+ state #x689) :u8) #x2B)"
                         "    (setf (mem-ref (+ state #x68A) :u8) #xBB)"
                         "    (setf (mem-ref (+ state #x68B) :u8) #xFD)"
                         "    (setf (mem-ref (+ state #x68C) :u8) #xD0)"
                         "    (setf (mem-ref (+ state #x68D) :u8) #xC3)"
                         "    (setf (mem-ref (+ state #x68E) :u8) #x42)"
                         "    (setf (mem-ref (+ state #x68F) :u8) #x3E)"
                         "    (setf (mem-ref (+ state #x690) :u8) #x58)"
                         "    (setf (mem-ref (+ state #x691) :u8) #xB5)"
                         "    (setf (mem-ref (+ state #x692) :u8) #x79)"
                         "    (setf (mem-ref (+ state #x693) :u8) #x70)"
                         "    (setf (mem-ref (+ state #x694) :u8) #xB5)"
                         "    (setf (mem-ref (+ state #x695) :u8) #x26)"
                         "    (setf (mem-ref (+ state #x696) :u8) #x7A)"
                         "    (setf (mem-ref (+ state #x697) :u8) #x90)"
                         "    (setf (mem-ref (+ state #x698) :u8) #xF5)"
                         "    (setf (mem-ref (+ state #x699) :u8) #x79)"
                         "    (setf (mem-ref (+ state #x69A) :u8) #x60)"
                         "    (setf (mem-ref (+ state #x69B) :u8) #x92)"
                         "    (setf (mem-ref (+ state #x69C) :u8) #x4A)"
                         "    (setf (mem-ref (+ state #x69D) :u8) #x87)"
                         "    (setf (mem-ref (+ state #x69E) :u8) #xF1)"
                         "    (setf (mem-ref (+ state #x69F) :u8) #x56)"
                         "    (setf (mem-ref (+ state #x6A0) :u8) #x0A)"
                         "    (setf (mem-ref (+ state #x6A1) :u8) #x6A)"
                         "    (setf (mem-ref (+ state #x6A2) :u8) #x85)"
                         "    (setf (mem-ref (+ state #x6A3) :u8) #xEA)"
                         "    (setf (mem-ref (+ state #x6A4) :u8) #xA6)"
                         "    (setf (mem-ref (+ state #x6A5) :u8) #x42)"
                         "    (setf (mem-ref (+ state #x6A6) :u8) #xDA)"
                         "    (setf (mem-ref (+ state #x6A7) :u8) #xC8)"
                         "    (setf (mem-ref (+ state #x6A8) :u8) #x35)"
                         "    (setf (mem-ref (+ state #x6A9) :u8) #x42)"
                         "    (setf (mem-ref (+ state #x6AA) :u8) #x4B)"
                         "    (setf (mem-ref (+ state #x6AB) :u8) #x5D)"
                         "    (setf (mem-ref (+ state #x6AC) :u8) #x7C)"
                         "    (setf (mem-ref (+ state #x6AD) :u8) #x8D)"
                         "    (setf (mem-ref (+ state #x6AE) :u8) #x63)"
                         "    (setf (mem-ref (+ state #x6AF) :u8) #x7C)"
                         "    (setf (mem-ref (+ state #x6B0) :u8) #x00)"
                         "    (setf (mem-ref (+ state #x6B1) :u8) #x40)"
                         "    (setf (mem-ref (+ state #x6B2) :u8) #x8C)"
                         "    (setf (mem-ref (+ state #x6B3) :u8) #x7A)"
                         "    (setf (mem-ref (+ state #x6B4) :u8) #x73)"
                         "    (setf (mem-ref (+ state #x6B5) :u8) #xDA)"
                         "    (setf (mem-ref (+ state #x6B6) :u8) #x67)"
                         "    (setf (mem-ref (+ state #x6B7) :u8) #x2B)"
                         "    (setf (mem-ref (+ state #x6B8) :u8) #x7F)"
                         "    (setf (mem-ref (+ state #x6B9) :u8) #x49)"
                         "    (setf (mem-ref (+ state #x6BA) :u8) #x85)"
                         "    (setf (mem-ref (+ state #x6BB) :u8) #x21)"
                         "    (setf (mem-ref (+ state #x6BC) :u8) #x42)"
                         "    (setf (mem-ref (+ state #x6BD) :u8) #x0B)"
                         "    (setf (mem-ref (+ state #x6BE) :u8) #x6D)"
                         "    (setf (mem-ref (+ state #x6BF) :u8) #xD3)"
                         "    (setf (mem-ref (+ state #x6C0) :u32) 1))"
                         "  (setf (mem-ref (+ (ssh-ipc-base) #x60438) :u32) 22)"
                         "  (let ((i 0))"
                         "    (loop"
                         "      (when (>= i 4) (return 0))"
                         "      (setf (mem-ref (conn-base i) :u32) 0)"
                         "      (setq i (+ i 1))))"
                         "  (let ((state (e1000-state-base)))"
                         "    (setf (mem-ref (+ state #x6C4) :u8) #x00)"
                         "    (dotimes (i 30)"
                         "      (setf (mem-ref (+ state (+ #x6C5 i)) :u8) #x01))"
                         "    (setf (mem-ref (+ state #x6E3) :u8) #x41)"
                         "    (setf (mem-ref (+ state #x6E4) :u8) #xA4)"
                         "    (setf (mem-ref (+ state #x6E5) :u8) #xE0)"
                         "    (setf (mem-ref (+ state #x6E6) :u8) #x92)"
                         "    (setf (mem-ref (+ state #x6E7) :u8) #x92)"
                         "    (setf (mem-ref (+ state #x6E8) :u8) #xB6)"
                         "    (setf (mem-ref (+ state #x6E9) :u8) #x51)"
                         "    (setf (mem-ref (+ state #x6EA) :u8) #xC2)"
                         "    (setf (mem-ref (+ state #x6EB) :u8) #x78)"
                         "    (setf (mem-ref (+ state #x6EC) :u8) #xB9)"
                         "    (setf (mem-ref (+ state #x6ED) :u8) #x77)"
                         "    (setf (mem-ref (+ state #x6EE) :u8) #x2C)"
                         "    (setf (mem-ref (+ state #x6EF) :u8) #x56)"
                         "    (setf (mem-ref (+ state #x6F0) :u8) #x9F)"
                         "    (setf (mem-ref (+ state #x6F1) :u8) #x5F)"
                         "    (setf (mem-ref (+ state #x6F2) :u8) #xA9)"
                         "    (setf (mem-ref (+ state #x6F3) :u8) #xBB)"
                         "    (setf (mem-ref (+ state #x6F4) :u8) #x13)"
                         "    (setf (mem-ref (+ state #x6F5) :u8) #xD9)"
                         "    (setf (mem-ref (+ state #x6F6) :u8) #x06)"
                         "    (setf (mem-ref (+ state #x6F7) :u8) #xB4)"
                         "    (setf (mem-ref (+ state #x6F8) :u8) #x6A)"
                         "    (setf (mem-ref (+ state #x6F9) :u8) #xB6)"
                         "    (setf (mem-ref (+ state #x6FA) :u8) #x8C)"
                         "    (setf (mem-ref (+ state #x6FB) :u8) #x9D)"
                         "    (setf (mem-ref (+ state #x6FC) :u8) #xF9)"
                         "    (setf (mem-ref (+ state #x6FD) :u8) #xDC)"
                         "    (setf (mem-ref (+ state #x6FE) :u8) #x2B)"
                         "    (setf (mem-ref (+ state #x6FF) :u8) #x44)"
                         "    (setf (mem-ref (+ state #x700) :u8) #x09)"
                         "    (setf (mem-ref (+ state #x701) :u8) #xF8)"
                         "    (setf (mem-ref (+ state #x702) :u8) #xA2)"
                         "    (setf (mem-ref (+ state #x703) :u8) #x09))"
                         "  (enable-pit-timer)"
                         "  (net-actor-main))"
                         "(defun net-actor-main ()"
                         "  (loop"
                         "    (io-delay)"
                         "    (let ((pkt-len (e1000-receive)))"
                         "      (when (not (zerop pkt-len))"
                         "        (let ((buf (e1000-rx-buf)))"
                         "          (let ((et-hi (mem-ref (+ buf 12) :u8)))"
                         "            (when (eq et-hi #x08)"
                         "              (let ((et-lo (mem-ref (+ buf 13) :u8)))"
                         "                (if (eq et-lo #x06)"
                         "                    (let ((arp-op (buf-read-u16-mem buf 20)))"
                         "                      (when (eq arp-op 1) (arp-reply buf)))"
                         "                    (when (eq et-lo 0)"
                         "                      (let ((st (e1000-state-base)))"
                         "                        (dotimes (m 6)"
                         "                          (setf (mem-ref (+ st (+ #x28 m)) :u8)"
                         "                                (mem-ref (+ buf (+ 6 m)) :u8))))"
                         "                      (let ((proto (mem-ref (+ buf 23) :u8)))"
                         "                        (if (eq proto 17)"
                         "                            (udp-receive buf pkt-len)"
                         "                            (when (eq proto 6)"
                         "                              (net-handle-tcp buf pkt-len))))))))))))))")))
       (ssh-overrides "
(defun ssh-handle-connection (ssh)
  (let ((cb (- ssh #x20)))
    (ssh-send-version ssh)
    (when (zerop (ssh-receive-version ssh))
      (return ()))
    (let ((kexinit (ssh-build-kexinit ssh)))
      (ssh-send-payload ssh kexinit (array-length kexinit)))
    (let ((cli-kex (ssh-receive-packet ssh 500)))
      (when (zerop cli-kex) (return ()))
      (let ((cli-kex-payload (car cli-kex)))
        (when (not (eq (aref cli-kex-payload 0) 20)) (return ()))
        (ssh-mem-store (+ cb #x1F00) cli-kex-payload (cdr cli-kex))
        (setf (mem-ref (+ ssh #x20) :u32) (cdr cli-kex))
        (let ((kex-init (ssh-receive-packet ssh 500)))
          (when (zerop kex-init) (return ()))
          (let ((kex-payload (car kex-init)))
            (when (not (eq (aref kex-payload 0) 30)) (return ()))
            (ssh-handle-kex ssh kex-payload (cdr kex-init))
            (ssh-send-newkeys ssh)
            (let ((nk (ssh-receive-packet ssh 500)))
              (when (zerop nk) (return ()))
              (when (not (eq (aref (car nk) 0) 21)) (return ()))
              (ssh-derive-keys ssh)
              (ssh-message-loop ssh))))))))
")
       (combined-source (concatenate 'string
                                      cl-user::*net-source*
                                      *repl-source*
                                      cl-user::*e1000-raw-source*
                                      ssh-main
                                      ssh-overrides)))
  (format t "Building i386 E1000 SSH test image...~%")
  (format t "Combined source: ~D chars~%" (length combined-source))
  (let ((image (build-image :target :i386 :source-text combined-source)))
    (format t "Entry point offset: ~A~%" (kernel-image-entry-point image))
    (format t "Native code size: ~D~%" (length (kernel-image-native-code image)))
    (write-kernel-image image "/tmp/modus-i386-e1000-test.bin")
    (format t "Done.~%")))
