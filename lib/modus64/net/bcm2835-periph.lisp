;;;; bcm2835-periph.lisp - BCM2835 peripheral drivers (QEMU-testable)
;;;;
;;;; Hardware RNG, System Timer, Activity LED, GPU Framebuffer.
;;;; Loaded AFTER arch-raspi3b.lisp to override io-delay and arch-seed-random.
;;;; Loaded AFTER dwc2-device.lisp for mbox-buf, dwc2-read, dwc2-write.

;;; ============================================================
;;; Hardware RNG (0x3F104000)
;;; ============================================================
;;; RNG_CTRL   = 0x3F104000  bit 0 = enable
;;; RNG_STATUS = 0x3F104004  bits[31:24] = words available
;;; RNG_DATA   = 0x3F104008  random 32-bit word

(defun rng-init ()
  ;; BCM2710A1 RNG at 0x3F104000 may need clock enable via mailbox.
  ;; Skip hardware RNG for now — accessing registers crashes on real hardware.
  nil)

(defun arch-seed-random ()
  ;; Use system timer for entropy (always available, no clock gating)
  (timer-read-lo))

;;; ============================================================
;;; System Timer (0x3F003000) — 1MHz free-running counter
;;; ============================================================
;;; CLO = 0x3F003004  low 32 bits
;;; CHI = 0x3F003008  high 32 bits

(defun timer-read-lo () (mem-ref #x3F003004 :u32))

(defun io-delay ()
  ;; ~1ms delay using 1MHz system timer
  (let ((target (+ (timer-read-lo) 1000)))
    (let ((i 0))
      (loop
        (when (> i 100000) (return nil))
        (when (>= (timer-read-lo) target) (return nil))
        (setq i (+ i 1))))))

(defun delay-us (us)
  (let ((target (+ (timer-read-lo) us)))
    (let ((i 0))
      (loop
        (when (> i 10000000) (return nil))
        (when (>= (timer-read-lo) target) (return nil))
        (setq i (+ i 1))))))

;;; ============================================================
;;; Activity LED — GPIO 29 (active low on BCM2837)
;;; ============================================================
;;; GPFSEL2  = 0x3F200008  GPIO 20-29 function select
;;; GPSET0   = 0x3F20001C  set output high
;;; GPCLR0   = 0x3F200028  set output low
;;; GPIO 29: bits [29:27] in GPFSEL2, bit 29 in SET0/CLR0

(defun led-init ()
  ;; Set GPIO29 as output: GPFSEL2 bits[29:27] = 001
  (let ((val (mem-ref #x3F200008 :u32)))
    ;; Clear bits 29:27 (3 bits for GPIO29 function)
    (let ((cleared (logand val #x07FFFFFF)))
      (setf (mem-ref #x3F200008 :u32) (logior cleared #x08000000)))))

(defun led-on ()
  ;; Active low: clear GPIO29 to turn LED on
  (setf (mem-ref #x3F200028 :u32) (ash 1 29)))

(defun led-off ()
  ;; Active low: set GPIO29 to turn LED off
  (setf (mem-ref #x3F20001C :u32) (ash 1 29)))

(defun led-blink (count ms)
  (let ((us (* ms 1000)))
    (let ((i 0))
      (loop
        (when (>= i count) (return nil))
        (led-on) (delay-us us)
        (led-off) (delay-us us)
        (setq i (+ i 1))))))

;;; ============================================================
;;; GPU Framebuffer via Mailbox Property Tags
;;; ============================================================
;;; Reuses mbox-buf (0x01050100), dwc2-read, dwc2-write from dwc2-device.lisp
;;; Mailbox channel 8 = property tags (ARM → VC)
;;;
;;; Framebuffer state at 0x01050200:
;;; +0x00: fb-addr (ARM physical)
;;; +0x04: fb-size (bytes)
;;; +0x08: pitch (bytes per row)
;;; +0x0C: width
;;; +0x10: height

(defun fb-state () #x01050200)

(defun fb-init (width height)
  ;; Build mailbox property buffer for framebuffer allocation
  (let ((buf (mbox-buf)))
    ;; Zero the buffer first (120 bytes)
    (let ((j 0))
      (loop
        (when (>= j 120) (return nil))
        (setf (mem-ref (+ buf j) :u32) 0)
        (setq j (+ j 4))))
    ;; Buffer header
    (setf (mem-ref (+ buf 0) :u32) 120)
    (setf (mem-ref (+ buf 4) :u32) 0)
    ;; Tag: Set physical display (0x00048003)
    (setf (mem-ref (+ buf 8) :u32) #x00048003)
    (setf (mem-ref (+ buf 12) :u32) 8)
    (setf (mem-ref (+ buf 16) :u32) 0)
    (setf (mem-ref (+ buf 20) :u32) width)
    (setf (mem-ref (+ buf 24) :u32) height)
    ;; Tag: Set virtual display (0x00048004)
    (setf (mem-ref (+ buf 28) :u32) #x00048004)
    (setf (mem-ref (+ buf 32) :u32) 8)
    (setf (mem-ref (+ buf 36) :u32) 0)
    (setf (mem-ref (+ buf 40) :u32) width)
    (setf (mem-ref (+ buf 44) :u32) height)
    ;; Tag: Set depth (0x00048005) — 32 bpp
    (setf (mem-ref (+ buf 48) :u32) #x00048005)
    (setf (mem-ref (+ buf 52) :u32) 4)
    (setf (mem-ref (+ buf 56) :u32) 0)
    (setf (mem-ref (+ buf 60) :u32) 32)
    ;; Tag: Set pixel order (0x00048006) — BGR (0)
    ;; make-color builds 0xFFRRGGBB; little-endian stores [BB,GG,RR,FF].
    ;; BGR mode (0) = blue in LSB, matching our byte layout.
    (setf (mem-ref (+ buf 64) :u32) #x00048006)
    (setf (mem-ref (+ buf 68) :u32) 4)
    (setf (mem-ref (+ buf 72) :u32) 0)
    (setf (mem-ref (+ buf 76) :u32) 0)
    ;; Tag: Allocate buffer (0x00040001)
    (setf (mem-ref (+ buf 80) :u32) #x00040001)
    (setf (mem-ref (+ buf 84) :u32) 8)
    (setf (mem-ref (+ buf 88) :u32) 0)
    (setf (mem-ref (+ buf 92) :u32) 16)
    (setf (mem-ref (+ buf 96) :u32) 0)
    ;; Tag: Get pitch (0x00040008)
    (setf (mem-ref (+ buf 100) :u32) #x00040008)
    (setf (mem-ref (+ buf 104) :u32) 4)
    (setf (mem-ref (+ buf 108) :u32) 0)
    ;; End tag is already 0 from zeroing
    ;; Send via mailbox channel 8
    ;; Wait for write-ready (bit 31 = full)
    (let ((i 0))
      (loop
        (when (> i 100000) (return 0))
        (when (zerop (logand (dwc2-read (mbox-write-status)) (ash 1 31)))
          (return nil))
        (setq i (+ i 1))))
    ;; Physical address of buf | channel 8
    ;; mbox-buf = 0x01050100, bus address = 0xC1050100
    (dwc2-write (mbox-write) (logior #xC1050100 8))
    ;; Wait for response (bit 30 = empty)
    (let ((i 0))
      (loop
        (when (> i 100000) (return 0))
        (when (zerop (logand (dwc2-read (mbox-status)) (ash 1 30)))
          (let ((resp (dwc2-read (mbox-read))))
            (return resp)))
        (setq i (+ i 1))))
    ;; Extract results from response buffer
    (let ((fb-addr (mem-ref (+ buf 92) :u32)))
      (let ((fb-size (mem-ref (+ buf 96) :u32)))
        (let ((pitch (mem-ref (+ buf 112) :u32)))
          ;; Convert GPU bus address to ARM physical (mask off 0xC0000000)
          (let ((arm-addr (logand fb-addr #x3FFFFFFF)))
            (setf (mem-ref (fb-state) :u32) arm-addr)
            (setf (mem-ref (+ (fb-state) 4) :u32) fb-size)
            (setf (mem-ref (+ (fb-state) 8) :u32) pitch)
            (setf (mem-ref (+ (fb-state) #xC) :u32) width)
            (setf (mem-ref (+ (fb-state) #x10) :u32) height)
            arm-addr))))))

(defun make-color (r g b)
  ;; Build 32-bit ARGB from components (2-arg logior only)
  (let ((c1 (logior (ash r 16) (ash g 8))))
    (let ((c2 (logior c1 b)))
      (logior (ash #xFF 24) c2))))

(defun fb-pixel (x y r g b)
  ;; Write 32-bit ARGB pixel at (x, y)
  (let ((fb (mem-ref (fb-state) :u32)))
    (let ((pitch (mem-ref (+ (fb-state) 8) :u32)))
      (let ((off (+ (* y pitch) (* x 4))))
        (let ((color (make-color r g b)))
          (setf (mem-ref (+ fb off) :u32) color))))))

(defun fb-clear (r g b)
  ;; Clear entire framebuffer to solid color
  (let ((fb (mem-ref (fb-state) :u32)))
    (let ((size (mem-ref (+ (fb-state) 4) :u32)))
      (let ((color (make-color r g b)))
        (let ((i 0))
          (loop
            (when (>= i size) (return nil))
            (setf (mem-ref (+ fb i) :u32) color)
            (setq i (+ i 4))))))))

(defun fb-fill-rect (x0 y0 w h r g b)
  ;; Fill rectangle at (x0,y0) with dimensions w x h
  (let ((fb (mem-ref (fb-state) :u32)))
    (let ((pitch (mem-ref (+ (fb-state) 8) :u32)))
      (let ((color (make-color r g b)))
        (let ((dy 0))
          (loop
            (when (>= dy h) (return nil))
            (let ((yoff (* (+ y0 dy) pitch)))
              (let ((row-off (+ yoff (* x0 4))))
                (let ((dx 0))
                  (loop
                    (when (>= dx w) (return nil))
                    (let ((addr (+ fb (+ row-off (* dx 4)))))
                      (setf (mem-ref addr :u32) color))
                    (setq dx (+ dx 1))))))
            (setq dy (+ dy 1))))))))
