;;;; arch-x86.lisp - x86-64 PCI + I/O adapter for shared networking code
;;;;
;;;; Defines arch-specific functions called by the shared e1000/ip/crypto/ssh code.

;; PCI Configuration Space Access via I/O ports 0xCF8/0xCFC

(defun pci-config-read (bus dev fn reg)
  (io-out-dword #xCF8
    (logior #x80000000
            (logior (ash bus 16)
                    (logior (ash dev 11)
                            (logior (ash fn 8)
                                    (logand reg #xFC))))))
  (io-in-dword #xCFC))

(defun pci-config-write (bus dev fn reg val)
  (io-out-dword #xCF8
    (logior #x80000000
            (logior (ash bus 16)
                    (logior (ash dev 11)
                            (logior (ash fn 8)
                                    (logand reg #xFC))))))
  (io-out-dword #xCFC val))

;; I/O delay: read serial port to yield to QEMU event loop
(defun io-delay ()
  (dotimes (d 5000) (io-in-byte #x3F8)))

;; Seed entropy from I/O timing (x86 has PIT counter at 0x40)
(defun arch-seed-random ()
  (let ((s 0))
    (dotimes (i 4)
      (io-in-byte #x3F8)
      (setq s (logxor (ash s 8) (logand (io-in-byte #x40) #xFF))))
    (when (zerop s) (setq s 42))
    s))

;; DMA and state base addresses for x86-64
(defun e1000-state-base () #x05060000)
(defun e1000-rx-desc-base () #x05000000)
(defun e1000-rx-buf-base () #x05001000)
(defun e1000-tx-desc-base () #x05041000)
(defun e1000-tx-buf-base () #x05041400)
(defun ssh-conn-base () #x05080000)

;; Base address for SSH IPC shared state (REPL, evaluator, connection management)
(defun ssh-ipc-base () #x300000)
