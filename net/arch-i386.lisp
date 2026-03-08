;;;; arch-i386.lisp - i386 adapter for shared networking code
;;;;
;;;; Uses NE2000 ISA NIC (port I/O, no PCI/MMIO needed).
;;;; All values stay within 31-bit fixnum range.

;; I/O delay: read serial port to yield to QEMU event loop
(defun io-delay ()
  (dotimes (d 5000) (io-in-byte #x3F8)))

;; Seed entropy from I/O timing (x86 PIT counter at 0x40)
(defun arch-seed-random ()
  (let ((s 0))
    (dotimes (i 4)
      (io-in-byte #x3F8)
      (setq s (logxor (ash s 8) (logand (io-in-byte #x40) 255))))
    (when (zerop s) (setq s 42))
    s))

;; State base addresses for i386
;; Must be below 8MB (cons base) and above kernel+stack (4MB)
(defun e1000-state-base () #x200000)     ; 2MB - shared state (crypto K, MAC, IP, etc.)
(defun ssh-conn-base () #x280000)        ; SSH connection state
(defun ssh-ipc-base () #x300000)         ; SSH IPC shared state

;; Hex printing utilities
(defun print-hex-digit (n)
  (if (< n 10)
      (write-byte (+ n 48))
      (write-byte (+ n 55))))

(defun print-hex-byte (b)
  (let ((hi (logand (ash b -4) 15))
        (lo (logand b 15)))
    (print-hex-digit hi)
    (print-hex-digit lo)))

(defun print-hex32 (n)
  (print-hex-byte (logand (ash n -24) 255))
  (print-hex-byte (logand (ash n -16) 255))
  (print-hex-byte (logand (ash n -8) 255))
  (print-hex-byte (logand n 255)))

;; write-byte: capture-aware for SSH output routing
(defun write-byte (b)
  (let ((flags (mem-ref (+ #x300000 #x14) :u32)))
    (when (zerop (logand flags 2))
      (write-char-serial b))
    (when (not (zerop (logand flags 1)))
      (let ((pos (mem-ref (+ #x300000 #x18) :u32)))
        (when (< pos 4096)
          (setf (mem-ref (+ #x300100 pos) :u8) b)
          (setf (mem-ref (+ #x300000 #x18) :u32) (+ pos 1)))))))

;; Print decimal number (recursive, for small values)
(defun print-dec (n)
  (when (>= n 10)
    (print-dec (truncate n 10)))
  (write-byte (+ (mod n 10) 48)))

;; buf-read-u32-mem, buf-read-u32, ssh-get-u32, htonl overrides
;; are in i386-overrides.lisp (loaded LAST, after ip.lisp/ssh.lisp)

;; Line editor state at ssh-ipc-base + offsets
;; 0x12800 = line-len, 0x12808 = cursor-pos, 0x12810 = escape-state
;; 0x12A08 = return-code (1=Enter, 2=Ctrl-D)
;; On i386 :u64 = 32-bit load/store with no tag shift (same as on 64-bit)
(defun edit-line-len () (mem-ref (+ #x300000 #x12800) :u64))
(defun edit-set-line-len (v) (setf (mem-ref (+ #x300000 #x12800) :u64) v))
(defun edit-cursor-pos () (mem-ref (+ #x300000 #x12808) :u64))
(defun edit-set-cursor-pos (v) (setf (mem-ref (+ #x300000 #x12808) :u64) v))

;; Eval stubs -- MVM doesn't have native compiler at runtime
(defun native-eval (form) 0)
(defun eval-line-expr (line) 0)
(defun rt-compile-defun (name args body) 0)

;; Prompt
(defun emit-prompt ()
  (if (zerop (mem-ref (+ #x300000 #x12A00) :u64))
      (progn (write-byte 62) (write-byte 32))
      (progn
        (write-byte 109) (write-byte 111)
        (write-byte 100) (write-byte 117)
        (write-byte 115) (write-byte 54)
        (write-byte 52) (write-byte 62) (write-byte 32))))
