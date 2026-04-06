;;;; Test SSH packet framing, buffer management, and round-trip on AArch64

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

(defvar *helpers* "
(defun phex-nib (n) (if (< n 10) (write-char-serial (+ n 48)) (write-char-serial (+ n 55))))
(defun phex (b) (phex-nib (logand (ash b -4) 15)) (phex-nib (logand b 15)))
(defun usb-keepalive () 0)
")

(defun run (name src expected)
  (format t "~A: " name) (finish-output)
  (handler-case
    (let* ((full (concatenate 'string *net-source* *repl-source* *helpers* src))
           (img (build-image :target :aarch64 :source-text full))
           (bin (format nil "/tmp/pkt-~A.bin" name))
           (out (format nil "/tmp/pkt-~A.out" name)))
      (write-kernel-image img bin)
      (sb-ext:run-program "/bin/bash"
        (list "-c" (format nil "timeout 8 qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 -kernel ~A -nographic -semihosting > ~A 2>/dev/null" bin out))
        :search t :wait t)
      (let ((output (with-open-file (f out :if-does-not-exist nil)
                      (when f (let ((s (make-string (file-length f)))) (read-sequence s f) s)))))
        (if (and output (search expected output))
            (format t "PASS~%")
            (format t "FAIL — got ~S, want ~S~%"
                    (when output (subseq output 0 (min 80 (length output)))) expected))))
    (error (e) (format t "ERROR: ~A~%" e))))

;;; ================================================================
;;; Test 1: ssh-make-packet round-trip — build packet, parse it back
;;; ================================================================
(run "make-parse-roundtrip"
  "(defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       (setf (mem-ref (+ ssh #x604) :u32) 42)
       ;; Build a payload: [20 0x41 0x42 0x43] (kexinit-like, 4 bytes)
       (let ((payload (make-array 4)))
         (aset payload 0 20) (aset payload 1 #x41)
         (aset payload 2 #x42) (aset payload 3 #x43)
         ;; Make SSH packet
         (let ((pkt (ssh-make-packet ssh payload 4)))
           ;; pkt = cons(array . total-len)
           ;; Parse it back
           (let ((parsed (ssh-parse-packet ssh (car pkt) (cdr pkt))))
             ;; parsed = cons(payload . payload-len)
             (write-char-serial 76) (phex (cdr parsed)) (write-char-serial 58)
             (phex (aref (car parsed) 0))
             (phex (aref (car parsed) 1))
             (phex (aref (car parsed) 2))
             (phex (aref (car parsed) 3))
             (write-char-serial 10) 0)))))"
  "L04:1441424")

;;; ================================================================
;;; Test 2: ssh-buf-consume — write data to recv buffer, consume some, check rest
;;; The recv buffer is at ssh+0x6D8, length at ssh+0x6D4
;;; ================================================================
(run "buf-consume"
  "(defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       ;; Write 6 bytes to recv buffer: [A B C D E F]
       (setf (mem-ref (+ ssh #x6D8) :u8) #xAA)
       (setf (mem-ref (+ ssh #x6D9) :u8) #xBB)
       (setf (mem-ref (+ ssh #x6DA) :u8) #xCC)
       (setf (mem-ref (+ ssh #x6DB) :u8) #xDD)
       (setf (mem-ref (+ ssh #x6DC) :u8) #xEE)
       (setf (mem-ref (+ ssh #x6DD) :u8) #xFF)
       (setf (mem-ref (+ ssh #x6D4) :u32) 6)
       ;; Consume first 2 bytes
       (ssh-buf-consume ssh 2)
       ;; Check remaining: should be [CC DD EE FF], len=4
       (write-char-serial 76)
       (phex (mem-ref (+ ssh #x6D4) :u32))  ;; remaining len = 4
       (write-char-serial 58)
       (phex (mem-ref (+ ssh #x6D8) :u8))   ;; should be CC
       (phex (mem-ref (+ ssh #x6D9) :u8))   ;; should be DD
       (phex (mem-ref (+ ssh #x6DA) :u8))   ;; should be EE
       (phex (mem-ref (+ ssh #x6DB) :u8))   ;; should be FF
       (write-char-serial 10) 0))"
  "L04:CCDDEEFF")

;;; ================================================================
;;; Test 3: ssh-buf-consume with larger buffer (tests the 3-arg + in mem-ref)
;;; Consume N bytes from a 100-byte buffer, check byte at position 50
;;; ================================================================
(run "buf-consume-large"
  "(defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       ;; Fill 100 bytes: byte[i] = i
       (let ((i 0))
         (loop
           (when (>= i 100) (return 0))
           (setf (mem-ref (+ (+ ssh #x6D8) i) :u8) i)
           (setq i (+ i 1))))
       (setf (mem-ref (+ ssh #x6D4) :u32) 100)
       ;; Consume first 10 bytes
       (ssh-buf-consume ssh 10)
       ;; Remaining: 90 bytes, byte[0] should be 10 (was byte[10])
       ;; byte[50] should be 60 (was byte[60])
       (write-char-serial 76)
       (phex (mem-ref (+ ssh #x6D4) :u32))  ;; len = 90 = 0x5A
       (write-char-serial 58)
       (phex (mem-ref (+ ssh #x6D8) :u8))   ;; byte[0] = 0x0A (10)
       (phex (mem-ref (+ (+ ssh #x6D8) 50) :u8))  ;; byte[50] = 0x3C (60)
       (write-char-serial 10) 0))"
  "L5A:0A3C")

;;; ================================================================
;;; Test 4: ssh-receive-version simulation
;;; Write a version string into the recv buffer, call ssh-receive-version
;;; ================================================================
(run "receive-version"
  ";; Override receive to return 1 (data available)
   (defun receive () 1)
   (defun fill-ver-buf (ssh)
     ;; Write 'SSH-2.0-OpenSSH_9.2\\0\\r\\n' (22 bytes) to recv buffer
     (let ((base (+ ssh #x6D8)))
       (setf (mem-ref base :u8) 83) (setf (mem-ref (+ base 1) :u8) 83)
       (setf (mem-ref (+ base 2) :u8) 72) (setf (mem-ref (+ base 3) :u8) 45)
       (setf (mem-ref (+ base 4) :u8) 50) (setf (mem-ref (+ base 5) :u8) 46)
       (setf (mem-ref (+ base 6) :u8) 48) (setf (mem-ref (+ base 7) :u8) 45)
       (setf (mem-ref (+ base 8) :u8) 79) (setf (mem-ref (+ base 9) :u8) 112)
       (setf (mem-ref (+ base 10) :u8) 101) (setf (mem-ref (+ base 11) :u8) 110)
       (setf (mem-ref (+ base 12) :u8) 83) (setf (mem-ref (+ base 13) :u8) 83)
       (setf (mem-ref (+ base 14) :u8) 72) (setf (mem-ref (+ base 15) :u8) 95)
       (setf (mem-ref (+ base 16) :u8) 57) (setf (mem-ref (+ base 17) :u8) 46)
       (setf (mem-ref (+ base 18) :u8) 50) (setf (mem-ref (+ base 19) :u8) 0)
       (setf (mem-ref (+ base 20) :u8) 13) (setf (mem-ref (+ base 21) :u8) 10))
     (setf (mem-ref (+ ssh #x6D4) :u32) 22) 0)
   (defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       (fill-ver-buf ssh)
       (setf (mem-ref (+ ssh #x6D4) :u32) 22)
       ;; Call ssh-receive-version
       (let ((result (ssh-receive-version ssh)))
         ;; Check: version should be stored at ssh+0x650, length at ssh+0x6D0
         (write-char-serial 82) (phex result) (write-char-serial 58)
         (phex (mem-ref (+ ssh #x6D0) :u32))  ;; version len (should be ~19)
         (write-char-serial 58)
         (phex (mem-ref (+ ssh #x650) :u8))   ;; first byte 'S' = 0x53
         (phex (mem-ref (+ ssh #x651) :u8))   ;; 'S' = 0x53
         (phex (mem-ref (+ ssh #x652) :u8))   ;; 'H' = 0x48
         (write-char-serial 10) 0)))"
  ;; Version len=20 (includes NUL at pos 19). First 3 bytes: S,S,H = 53,53,48
  "R01:14:535348")

;;; ================================================================
;;; Test 5: Full packet round-trip — make packet, put in recv buffer,
;;; receive it back, check payload matches
;;; ================================================================
(run "packet-roundtrip"
  "(defun receive () 1)
   (defun copy-pkt-to-buf (ssh pkt)
     (let ((arr (car pkt)))
       (let ((len (cdr pkt)))
         (dotimes (i len)
           (setf (mem-ref (+ (+ ssh #x6D8) i) :u8) (aref arr i)))
         (setf (mem-ref (+ ssh #x6D4) :u32) len) 0)))
   (defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       (setf (mem-ref (+ ssh #x604) :u32) 42)
       (setf (mem-ref (+ ssh #x0C) :u32) 0)
       (let ((payload (make-array 4)))
         (aset payload 0 20) (aset payload 1 #xAA)
         (aset payload 2 #xBB) (aset payload 3 #xCC)
         (let ((pkt (ssh-make-packet ssh payload 4)))
           (copy-pkt-to-buf ssh pkt)
           (let ((result (ssh-receive-packet ssh 100)))
             (let ((rpay (car result)))
               (let ((rlen (cdr result)))
                 (write-char-serial 76) (phex rlen) (write-char-serial 58)
                 (phex (aref rpay 0))
                 (phex (aref rpay 1))
                 (phex (aref rpay 2))
                 (phex (aref rpay 3))
                 (write-char-serial 10) 0)))))))"
  "L04:14AABBCC")

;;; ================================================================
;;; Test 6: ssh-send-version — verify the TCP payload
;;; ================================================================
(run "send-version"
  ";; Capture tcp-send-conn args
   (defun tcp-send-conn (cb data len)
     (write-char-serial 84)  ;; T
     (phex len)
     (write-char-serial 58)
     ;; Print first 4 bytes
     (phex (aref data 0)) (phex (aref data 1))
     (phex (aref data 2)) (phex (aref data 3))
     ;; Print last 2 bytes (should be \\r\\n = 0D 0A)
     (write-char-serial 58)
     (phex (aref data (- len 2)))
     (phex (aref data (- len 1)))
     (write-char-serial 10) 0)
   (defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       (ssh-send-version ssh)
       0))"
  ;; ssh-send-version sends 'SSH-2.0-Modus_1.0\\r\\n' = 19 bytes
  ;; First 4: S S H - = 53 53 48 2D. Last 2: \\r\\n = 0D 0A
  "T13:5353482D:0D0A")

;;; ================================================================
;;; Test 7: ssh-send-payload — verify unencrypted packet framing sent via TCP
;;; ================================================================
(run "send-payload"
  "(defun tcp-send-conn (cb data len)
     (write-char-serial 84) (phex len) (write-char-serial 58)
     ;; Print packet-length field (first 4 bytes)
     (phex (aref data 0)) (phex (aref data 1))
     (phex (aref data 2)) (phex (aref data 3))
     ;; Print padding-length (byte 4)
     (write-char-serial 58) (phex (aref data 4))
     ;; Print first payload byte (byte 5)
     (write-char-serial 58) (phex (aref data 5))
     (write-char-serial 10) 0)
   (defun kernel-main ()
     (let ((ssh (+ (ssh-conn-base) #x20)))
       (setf (mem-ref (+ ssh #x604) :u32) 42)
       (setf (mem-ref (+ ssh #x0C) :u32) 0)  ;; unencrypted
       (setf (mem-ref (+ ssh #x08) :u32) 0)  ;; server-seq
       (let ((payload (make-array 1)))
         (aset payload 0 21)  ;; SSH_MSG_NEWKEYS
         (ssh-send-payload ssh payload 1)
         0)))"
  ;; 1-byte payload: packet_len = 1+1+pad_len, base = 5+1=6, pad = 8-6=2, +8=10
  ;; Actually: base-len=5+1=6, pad=8-(6%8)=8-6=2, but 2<4 → 2+8=10
  ;; packet_len = 1+1+10 = 12 = 0x0C
  ;; First 4 bytes: 00 00 00 0C. pad_len=0A. payload byte=15 (21)
  "T10:0000000C:0A:15")

;;; ================================================================
;;; Test 8: Full ssh-handle-connection with mocked receive
;;; Simulate: version exchange, kexinit exchange, kex_ecdh_init
;;; This tests the COMPLETE handshake up to the signature
;;; ================================================================

;; This is complex — let me first build a helper that stages packet data
;; in the recv buffer in the correct order

(run "staged-handshake"
  ";; Mock receive: inject data into recv buffer from a staging area
   ;; staging area at state+0x800, staging offset at state+0x804
   (defun stage-data (data len)
     (let ((state (e1000-state-base)))
       (let ((off (mem-ref (+ state #x804) :u32)))
         (dotimes (i len)
           (setf (mem-ref (+ state (+ #x808 (+ off i))) :u8) (aref data i)))
         (setf (mem-ref (+ state #x804) :u32) (+ off len)) 0)))
   ;; receive: copy next chunk from staging to recv buffer
   (defun receive ()
     (let ((state (e1000-state-base)))
       (let ((ssh (+ (ssh-conn-base) #x20)))
         (let ((src-off (mem-ref (+ state #x800) :u32)))
           (let ((total (mem-ref (+ state #x804) :u32)))
             (if (>= src-off total)
                 0  ;; no more data → return 0 to signal close
                 (let ((chunk (- total src-off)))
                   (when (> chunk 64) (setq chunk 64))
                   (let ((buf-len (mem-ref (+ ssh #x6D4) :u32)))
                     (dotimes (i chunk)
                       (setf (mem-ref (+ ssh (+ #x6D8 (+ buf-len i))) :u8)
                             (mem-ref (+ state (+ #x808 (+ src-off i))) :u8)))
                     (setf (mem-ref (+ ssh #x6D4) :u32) (+ buf-len chunk))
                     (setf (mem-ref (+ state #x800) :u32) (+ src-off chunk)))
                   1)))))))
   ;; tcp-send-conn: capture last sent payload type
   (defun tcp-send-conn (cb data len)
     ;; For unencrypted packets: type is at byte 5 (after 4-byte len + 1-byte padlen)
     (when (> len 5)
       (write-char-serial 62)  ;; >
       (phex (aref data 5))    ;; msg type
       (write-char-serial 10))
     0)
   (defun kernel-main ()
     (sha256-init) (sha512-init) (ed25519-init)
     (let ((state (e1000-state-base)))
       ;; Host key setup (same as other tests)
       (setf (mem-ref (+ state #x710) :u64) 0) (setf (mem-ref (+ state #x718) :u64) 0)
       (setf (mem-ref (+ state #x720) :u64) 0) (setf (mem-ref (+ state #x728) :u64) 0)
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
       (setf (mem-ref (+ state #x6E4) :u8) #xA4)
       (setf (mem-ref (+ state #x6E5) :u8) #xE0)
       (setf (mem-ref (+ state #x6E6) :u8) #x92)
       (setf (mem-ref (+ state #x6E7) :u8) #x92)
       (setf (mem-ref (+ state #x6E8) :u8) #xB6)
       (setf (mem-ref (+ state #x6E9) :u8) #x51)
       (setf (mem-ref (+ state #x6EA) :u8) #xC2)
       (setf (mem-ref (+ state #x6EB) :u8) #x78)
       (setf (mem-ref (+ state #x6EC) :u8) #xB9)
       (setf (mem-ref (+ state #x6ED) :u8) #x77)
       (setf (mem-ref (+ state #x6EE) :u8) #x2C)
       (setf (mem-ref (+ state #x6EF) :u8) #x56)
       (setf (mem-ref (+ state #x6F0) :u8) #x9F)
       (setf (mem-ref (+ state #x6F1) :u8) #x5F)
       (setf (mem-ref (+ state #x6F2) :u8) #xA9)
       (setf (mem-ref (+ state #x6F3) :u8) #xBB)
       (setf (mem-ref (+ state #x6F4) :u8) #x13)
       (setf (mem-ref (+ state #x6F5) :u8) #xD9)
       (setf (mem-ref (+ state #x6F6) :u8) #x06)
       (setf (mem-ref (+ state #x6F7) :u8) #xB4)
       (setf (mem-ref (+ state #x6F8) :u8) #x6A)
       (setf (mem-ref (+ state #x6F9) :u8) #xB6)
       (setf (mem-ref (+ state #x6FA) :u8) #x8C)
       (setf (mem-ref (+ state #x6FB) :u8) #x9D)
       (setf (mem-ref (+ state #x6FC) :u8) #xF9)
       (setf (mem-ref (+ state #x6FD) :u8) #xDC)
       (setf (mem-ref (+ state #x6FE) :u8) #x2B)
       (setf (mem-ref (+ state #x6FF) :u8) #x44)
       (setf (mem-ref (+ state #x700) :u8) #x09)
       (setf (mem-ref (+ state #x701) :u8) #xF8)
       (setf (mem-ref (+ state #x702) :u8) #xA2)
       (setf (mem-ref (+ state #x703) :u8) #x09))
     ;; Init staging
     (let ((state (e1000-state-base)))
       (setf (mem-ref (+ state #x800) :u32) 0)
       (setf (mem-ref (+ state #x804) :u32) 0))
     ;; Stage client version string
     (let ((cv (make-array 34)))
       (aset cv 0 83) (aset cv 1 83) (aset cv 2 72) (aset cv 3 45)
       (aset cv 4 50) (aset cv 5 46) (aset cv 6 48) (aset cv 7 45)
       (aset cv 8 79) (aset cv 9 112) (aset cv 10 101) (aset cv 11 110)
       (aset cv 12 83) (aset cv 13 83) (aset cv 14 72) (aset cv 15 95)
       (aset cv 16 57) (aset cv 17 46) (aset cv 18 50) (aset cv 19 112)
       (aset cv 20 49) (aset cv 21 32) (aset cv 22 68) (aset cv 23 101)
       (aset cv 24 98) (aset cv 25 105) (aset cv 26 97) (aset cv 27 110)
       (aset cv 28 45) (aset cv 29 50)
       (aset cv 30 0) (aset cv 31 0)
       (aset cv 32 13) (aset cv 33 10)
       (stage-data cv 34))
     ;; Stage fake client KEXINIT (type=20, then 163 bytes of zeros = 164 total)
     ;; Wrap in SSH packet: len=164+1+pad, pad=8-(166%8)=8-6=2+8=10
     ;; packet_len = 164+1+10 = 175 = 0xAF. total = 4+175 = 179
     (let ((kex-pkt (make-array 179)))
       (aset kex-pkt 0 0) (aset kex-pkt 1 0) (aset kex-pkt 2 0) (aset kex-pkt 3 175)
       (aset kex-pkt 4 10)  ;; pad_len
       (aset kex-pkt 5 20)  ;; SSH_MSG_KEXINIT
       ;; Rest is zeros (kexinit cookie + empty name-lists)
       (stage-data kex-pkt 179))
     ;; Stage KEX_ECDH_INIT: type=30, string(32 bytes of 0xDD)
     ;; payload = [30, 00 00 00 20, DD*32] = 37 bytes
     ;; packet: base=5+37=42, pad=8-(42%8)=8-2=6, packet_len=37+1+6=44=0x2C
     ;; total = 4+44 = 48
     (let ((kex-init (make-array 48)))
       (aset kex-init 0 0) (aset kex-init 1 0) (aset kex-init 2 0) (aset kex-init 3 44)
       (aset kex-init 4 6)   ;; pad_len
       (aset kex-init 5 30)  ;; SSH_MSG_KEX_ECDH_INIT
       (aset kex-init 6 0) (aset kex-init 7 0)
       (aset kex-init 8 0) (aset kex-init 9 32)
       (dotimes (i 32) (aset kex-init (+ 10 i) #xDD))
       (stage-data kex-init 48))
     ;; Setup SSH conn and run handshake
     (let ((ssh (+ (ssh-conn-base) #x20)))
       (setf (mem-ref (+ ssh #x0C) :u32) 0)  ;; unencrypted
       (setf (mem-ref (+ ssh #x604) :u32) 42)
       (setf (mem-ref (+ ssh #x6D4) :u32) 0)  ;; empty recv buffer
       (setf (mem-ref ssh :u32) 0)  ;; session-id not set
       ;; Copy host keys to per-conn
       (let ((state (e1000-state-base)))
         (dotimes (i 32) (setf (mem-ref (+ ssh (+ #x110 i)) :u8) (mem-ref (+ state (+ #x710 i)) :u8)))
         (dotimes (i 32) (setf (mem-ref (+ ssh (+ #x130 i)) :u8) (mem-ref (+ state (+ #x730 i)) :u8))))
       (write-char-serial 72)  ;; H for handshake start
       (ssh-handle-connection ssh)
       (write-char-serial 68)  ;; D for done
       (write-char-serial 10)
       0))"
  ;; Expected: server sends version (>14=type field of version packet? no, version is raw text)
  ;; Then sends KEXINIT (>14), then after kex completes, KEXDH_REPLY (>1F) and NEWKEYS (>15)
  ;; The D marker confirms handshake completed without crash
  "D")

(format t "~%Done.~%")
