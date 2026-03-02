;;;; uart-bootloader.lisp - UART serial bootloader for Pi Zero 2 W
;;;;
;;;; Receives kernel images over mini UART from Pi 5 host.
;;;; Loaded AFTER arch-raspi3b.lisp and bcm2835-periph.lisp
;;;; (uses timer-read-lo, delay-us, led-blink from bcm2835-periph).
;;;;
;;;; Protocol:
;;;;   1. Bootloader waits ~2s for magic byte 0x55
;;;;   2. If received: sends ACK 0xAA
;;;;   3. Host sends 4-byte little-endian kernel size
;;;;   4. Host sends kernel data bytes
;;;;   5. Host sends 1-byte checksum (sum of all data bytes mod 256)
;;;;   6. Bootloader verifies checksum, prints "OK\n" or "ER\n"
;;;;   7. On success: jumps to loaded kernel at 0x300000

;;; ============================================================
;;; Mini UART Read (can't use TRAP #x0301 — hardcoded PL011)
;;; ============================================================
;;; AUX_MU_IO   = 0x3F215040  data register
;;; AUX_MU_LSR  = 0x3F215054  bit 0 = data ready

(defun uart-read-byte ()
  ;; Blocking read with safety timeout (~5 seconds at ~1GHz)
  (let ((i 0))
    (loop
      (when (> i 50000000) (return -1))
      (when (not (zerop (logand (mem-ref #x3F215054 :u32) 1)))
        (return (logand (mem-ref #x3F215040 :u32) #xFF)))
      (setq i (+ i 1)))))

(defun uart-read-byte-timeout (timeout-us)
  ;; Read with microsecond timeout using system timer
  (let ((deadline (+ (timer-read-lo) timeout-us)))
    (loop
      (when (>= (timer-read-lo) deadline) (return -1))
      (when (not (zerop (logand (mem-ref #x3F215054 :u32) 1)))
        (return (logand (mem-ref #x3F215040 :u32) #xFF))))))

(defun uart-read-u32 ()
  ;; Read 4-byte little-endian value
  ;; NOTE: must use 2-arg logior (MVM limitation)
  (let ((b0 (uart-read-byte)))
    (let ((b1 (uart-read-byte)))
      (let ((b2 (uart-read-byte)))
        (let ((b3 (uart-read-byte)))
          (let ((lo (logior b0 (ash b1 8))))
            (let ((hi (logior (ash b2 16) (ash b3 24))))
              (logior lo hi))))))))

;;; ============================================================
;;; Kernel Receive + Jump
;;; ============================================================

(defun bootloader-load-addr () #x300000)

(defun bootloader-receive ()
  ;; Send ACK
  (write-byte #xAA)
  ;; Read 4-byte kernel size
  (let ((size (uart-read-u32)))
    ;; Print size
    (write-byte 83) (write-byte 90) (write-byte 58)  ;; "SZ:"
    (print-hex32 size)
    (write-byte 10)
    ;; Read kernel data byte by byte
    (let ((load-addr (bootloader-load-addr)))
      (let ((i 0))
        (let ((checksum 0))
          (loop
            (when (>= i size) (return nil))
            (let ((b (uart-read-byte)))
              (when (= b -1)
                ;; Timeout during receive
                (write-byte 84) (write-byte 79) (write-byte 10)  ;; "TO\n"
                (return nil))
              (setf (mem-ref (+ load-addr i) :u8) b)
              (setq checksum (logand (+ checksum b) #xFF)))
            (setq i (+ i 1)))
          ;; Read expected checksum
          (let ((expected (uart-read-byte)))
            (if (= checksum expected)
                (progn
                  (write-byte 79) (write-byte 75) (write-byte 10)  ;; "OK\n"
                  ;; Small delay for UART TX to drain
                  (delay-us 50000)
                  ;; Jump to loaded kernel
                  (jump-to-address load-addr))
                (progn
                  (write-byte 69) (write-byte 82) (write-byte 10)  ;; "ER\n"
                  nil))))))))

(defun uart-drain ()
  ;; Drain any garbage from UART RX FIFO (reset transients on GPIO)
  (let ((n 0))
    (loop
      (when (>= n 64) (return nil))
      (when (zerop (logand (mem-ref #x3F215054 :u32) 1))
        (return nil))
      (mem-ref #x3F215040 :u32)  ;; read and discard
      (setq n (+ n 1)))))

(defun bootloader-wait ()
  ;; Drain FIFO, then wait ~5 seconds for magic byte 0x55
  (uart-drain)
  (let ((b (uart-read-byte-timeout 5000000)))
    (if (= b #x55)
        (bootloader-receive)
        nil)))
