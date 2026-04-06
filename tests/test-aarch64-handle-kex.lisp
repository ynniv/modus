;;;; Test ssh-handle-kex end-to-end: mock all inputs, verify signature
;;;; This simulates what happens after tcp/ssh-receive gives us the data

(load "lib/load-mvm.lisp")
(mvm-load "mvm/repl-source.lisp")
(in-package :modus.mvm)
(install-aarch64-translator)

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

(format t "Building handle-kex test...~%") (finish-output)

;; Compute expected signature with Python
(let ((expected-sig-prefix
        (with-output-to-string (s)
          (sb-ext:run-program "/usr/bin/python3"
            (list "-c" "
import hashlib, struct, nacl.signing

def ssh_str(data):
    return struct.pack('>I', len(data)) + data

def ssh_mpint(data):
    # Strip leading zeros, add leading zero if high bit set
    d = data.lstrip(b'\\x00') or b'\\x00'
    if d[0] & 0x80:
        d = b'\\x00' + d
    return struct.pack('>I', len(d)) + d

# Inputs (same as test)
vc = ssh_str(b'SSH-2.0-Test')
vs = ssh_str(b'SSH-2.0-Modus_1.0')
ic = ssh_str(b'\\xBB' * 20)
is_ = ssh_str(b'\\xAA' * 20)
algo = ssh_str(b'ssh-ed25519')
pk = ssh_str(b'\\xCC' * 32)
ks = ssh_str(algo + pk)
qc = ssh_str(b'\\xDD' * 32)
qs = ssh_str(b'\\xEE' * 32)
k = ssh_mpint(b'\\xFF' * 32)
hash_input = vc + vs + ic + is_ + ks + qc + qs + k
H = hashlib.sha256(hash_input).digest()

# Ed25519 sign with private key = zeros
privkey = b'\\x00' * 32
signing_key = nacl.signing.SigningKey(privkey)
sig = signing_key.sign(H).signature
print(sig[:4].hex().upper(), end='')
")
            :output s :wait t))))
  (format t "Expected sig prefix: ~A~%" expected-sig-prefix)

  (let* ((src (concatenate 'string *net-source* *repl-source*
    (format nil
    "(defun phex-nib (n) (if (< n 10) (write-char-serial (+ n 48)) (write-char-serial (+ n 55))))
     (defun phex (b) (phex-nib (logand (ash b -4) 15)) (phex-nib (logand b 15)))
     ;; No-op usb-keepalive (E1000 not initialized in test)
     (defun usb-keepalive () 0)
     ;; Override ssh-kex-hash-and-sign to print exchange hash
     (defun ssh-kex-hash-and-sign (ssh cli-eph srv-eph shared)
       (prof-mark-2 72 62)
       (let ((h (ssh-compute-exchange-hash ssh cli-eph srv-eph shared)))
         (prof-mark-2 72 60)
         ;; Print hash for comparison (expected FD278F52)
         (write-char-serial 72)
         (phex (aref h 0)) (phex (aref h 1)) (phex (aref h 2)) (phex (aref h 3))
         (write-char-serial 10)
         ;; Print cli-eph[0], srv-eph[0], shared[0] to verify args
         (write-char-serial 65)
         (phex (aref cli-eph 0))
         (phex (aref srv-eph 0))
         (phex (aref shared 0))
         (write-char-serial 10)
         (ssh-mem-store (+ ssh #x050) h 32)
         (ssh-kex-finish-sign ssh h srv-eph)))
     ;; Capture what ssh-send-kex-reply would send
     (defun ssh-send-payload (ssh payload payload-len)
       ;; The sig is the LAST 64+4+11+4+4 bytes of the payload
       ;; Actually sig-blob is at the end. Let's just print key bytes.
       ;; payload[0] = msg type 0x1F
       ;; Find sig data: it's inside a nested SSH string at the end
       ;; Easier: print the last 68 bytes (4-byte sig-blob-len + string(algo) + string(sig))
       ;; Actually just print the WHOLE payload length and first 4 sig bytes
       ;; The sig-blob = ssh-make-str(concat(ssh-make-str(algo), ssh-make-str(sig)))
       ;; sig starts 4 (outer len) + 4+11 (algo str) + 4 (sig str len) = 23 bytes from end of payload
       ;; But sig is 64 bytes, and sig-blob = 4+15+4+64+4 = 91 bytes
       ;; Last 64 bytes of the nested structure... complex. Just print raw bytes.
       (let ((soff (- payload-len 64)))
         (write-char-serial 83)
         (phex (aref payload soff))
         (phex (aref payload (+ soff 1)))
         (phex (aref payload (+ soff 2)))
         (phex (aref payload (+ soff 3)))
         (write-char-serial 10))
       0)
     (defun kernel-main ()
       (sha256-init) (sha512-init) (ed25519-init)
       ;; Host key setup
       (let ((state (e1000-state-base)))
         (setf (mem-ref (+ state #x710) :u64) 0)
         (setf (mem-ref (+ state #x718) :u64) 0)
         (setf (mem-ref (+ state #x720) :u64) 0)
         (setf (mem-ref (+ state #x728) :u64) 0)
         (setf (mem-ref (+ state #x730) :u32) #xBC276A3B)
         (setf (mem-ref (+ state #x734) :u32) #x2DA4B6CE)
         (setf (mem-ref (+ state #x738) :u32) #xD0A8A362)
         (setf (mem-ref (+ state #x73C) :u32) #x730D6F2A)
         (setf (mem-ref (+ state #x740) :u32) #x77153265)
         (setf (mem-ref (+ state #x744) :u32) #xA643E21D)
         (setf (mem-ref (+ state #x748) :u32) #xA148C03A)
         (setf (mem-ref (+ state #x74C) :u32) #x29DA598B)
         (setf (mem-ref (+ state #x624) :u32) 1))
       (pre-compute-host-sign)
       ;; Ephemeral key
       (let ((state (e1000-state-base)))
         (setf (mem-ref (+ state #x6C4) :u8) #x00)
         (dotimes (i 30) (setf (mem-ref (+ state (+ #x6C5 i)) :u8) #x01))
         (setf (mem-ref (+ state #x6E3) :u8) #x41)
         (dotimes (i 32) (setf (mem-ref (+ state (+ #x6E4 i)) :u8) #xEE)))
       ;; SSH conn state
       (let ((ssh (+ (ssh-conn-base) #x20)))
         ;; Copy host keys to per-conn
         (dotimes (i 32) (setf (mem-ref (+ ssh (+ #x110 i)) :u8) 0))
         (dotimes (i 32) (setf (mem-ref (+ ssh (+ #x130 i)) :u8) #xCC))
         ;; Version, kexinits
         (let ((ver-base (+ ssh #x650)))
           (setf (mem-ref ver-base :u8) 83) (setf (mem-ref (+ ver-base 1) :u8) 83)
           (setf (mem-ref (+ ver-base 2) :u8) 72) (setf (mem-ref (+ ver-base 3) :u8) 45)
           (setf (mem-ref (+ ver-base 4) :u8) 50) (setf (mem-ref (+ ver-base 5) :u8) 46)
           (setf (mem-ref (+ ver-base 6) :u8) 48) (setf (mem-ref (+ ver-base 7) :u8) 45)
           (setf (mem-ref (+ ver-base 8) :u8) 84) (setf (mem-ref (+ ver-base 9) :u8) 101)
           (setf (mem-ref (+ ver-base 10) :u8) 115) (setf (mem-ref (+ ver-base 11) :u8) 116))
         (setf (mem-ref (+ ssh #x6D0) :u32) 12)
         (let ((cb (- ssh #x20)))
           (dotimes (i 20) (setf (mem-ref (+ cb (+ #x1700 i)) :u8) #xAA)))
         (setf (mem-ref (+ ssh #x1C) :u32) 20)
         (let ((cb (- ssh #x20)))
           (dotimes (i 20) (setf (mem-ref (+ cb (+ #x1F00 i)) :u8) #xBB)))
         (setf (mem-ref (+ ssh #x20) :u32) 20)
         (setf (mem-ref ssh :u32) 0)
         ;; Build KEX_ECDH_INIT payload: type=30, len=32, then 32 bytes of 0xDD
         (let ((kex-payload (make-array 37)))
           (aset kex-payload 0 30)
           (aset kex-payload 1 0) (aset kex-payload 2 0)
           (aset kex-payload 3 0) (aset kex-payload 4 32)
           (dotimes (i 32) (aset kex-payload (+ 5 i) #xDD))
           ;; Call ssh-handle-kex (from ssh-profile.lisp)
           (write-char-serial 75)
           (ssh-handle-kex ssh kex-payload 37)
           (write-char-serial 68) (write-char-serial 10)
           0)))"
    )))
         (img (build-image :target :aarch64 :source-text src))
         (bin "/tmp/handle-kex-test.bin")
         (out "/tmp/handle-kex-test.out"))
    (write-kernel-image img bin)
    (format t "Built. Running (ed25519 takes ~A60s)...~%" "~") (finish-output)
    (sb-ext:run-program "/bin/bash"
      (list "-c" (format nil "timeout 180 qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel ~A -nographic -semihosting > ~A 2>/dev/null" bin out))
      :search t :wait t)
    (let ((output (with-open-file (f out :if-does-not-exist nil)
                    (when f (let ((s (make-string (file-length f)))) (read-sequence s f) s)))))
      (format t "Output: ~A~%" output)
      (if (and output (search expected-sig-prefix output))
          (format t "PASS — signature prefix ~A matches~%" expected-sig-prefix)
          (format t "FAIL — expected sig prefix ~A~%" expected-sig-prefix)))))
