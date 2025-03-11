;;;;------------------------------------------------------------------
;;;;
;;;;    Copyright (C) 2025
;;;;    For distribution policy, see the accompanying file COPYING.
;;;;
;;;; Filename:      e1000.lisp
;;;; Description:   Intel e1000 (82540EM) PCI ethernet NIC driver
;;;; Author:        Claude
;;;; Created at:    2025
;;;;
;;;;------------------------------------------------------------------

(require :x86-pc/package)
(require :x86-pc/pci)
(require :lib/net/ethernet)
(require :lib/net/ip4)

(defpackage muerte.x86-pc.e1000
  (:use muerte.cl muerte muerte.lib muerte.x86-pc muerte.ethernet)
  (:export ;; Core API
           #:e1000-probe
           #:e1000-device
           #:*e1000-devices*
           #:*e1000-verbose*
           ;; Network operations
           #:e1000-ping
           #:e1000-icmp-test
           #:e1000-ip-init
           #:e1000-ip-loop
           ;; Stack integration
           #:e1000-stack-test
           #:e1000-udp-send
           #:e1000-udp-receive
           #:e1000-udp-echo-server
           ;; Interrupts
           #:e1000-irq
           #:e1000-enable-interrupts
           #:e1000-disable-interrupts
           #:e1000-interrupt-status
           #:interrupt-count
           #:e1000-wait-for-packet
           #:e1000-receive-wait
           ;; Link status
           #:e1000-link-up-p
           ;; Debug (optional)
           #:e1000-debug
           ;; Packet pool API
           #:init-packet-pool
           #:get-packet
           #:free-packet
           #:with-packet
           ;; End-to-end tests
           #:e1000-dhcp-test
           #:e1000-udp-test
           ;; DNS
           #:dns-resolve
           #:dns-test
           ;; NTP
           #:ntp-get-time
           #:ntp-test
           ;; TCP
           #:tcp-connect
           #:tcp-send
           #:tcp-receive
           #:tcp-close
           #:tcp-time-test
           ;; TCP server
           #:tcp-listen
           #:tcp-accept
           #:tcp-listener-close
           #:tcp-echo-server
           ;; HTTP
           #:http-get
           #:http-test
           ;; Speed test
           #:tcp-speed-test))

(provide :x86-pc/e1000)

(in-package muerte.x86-pc.e1000)

;;; ============================================================
;;; Constants - Intel e1000 (82540EM) registers and bits
;;; ============================================================

;; PCI IDs
(defconstant +e1000-vendor-id+ #x8086)    ; Intel
(defconstant +e1000-device-id+ #x100e)    ; 82540EM (QEMU default)

;; Register offsets (directly from Intel SDM / OSDev wiki)
(defconstant +e1000-ctrl+    #x00000)  ; Device Control
(defconstant +e1000-status+  #x00008)  ; Device Status
(defconstant +e1000-eecd+    #x00010)  ; EEPROM Control/Data
(defconstant +e1000-eerd+    #x00014)  ; EEPROM Read
(defconstant +e1000-icr+     #x000C0)  ; Interrupt Cause Read
(defconstant +e1000-ims+     #x000D0)  ; Interrupt Mask Set
(defconstant +e1000-imc+     #x000D8)  ; Interrupt Mask Clear
(defconstant +e1000-rctl+    #x00100)  ; Receive Control
(defconstant +e1000-tctl+    #x00400)  ; Transmit Control
(defconstant +e1000-rdbal+   #x02800)  ; RX Descriptor Base Low
(defconstant +e1000-rdbah+   #x02804)  ; RX Descriptor Base High
(defconstant +e1000-rdlen+   #x02808)  ; RX Descriptor Length
(defconstant +e1000-rdh+     #x02810)  ; RX Descriptor Head
(defconstant +e1000-rdt+     #x02818)  ; RX Descriptor Tail
(defconstant +e1000-tdbal+   #x03800)  ; TX Descriptor Base Low
(defconstant +e1000-tdbah+   #x03804)  ; TX Descriptor Base High
(defconstant +e1000-tdlen+   #x03808)  ; TX Descriptor Length
(defconstant +e1000-tdh+     #x03810)  ; TX Descriptor Head
(defconstant +e1000-tdt+     #x03818)  ; TX Descriptor Tail
(defconstant +e1000-tidv+    #x03820)  ; TX Interrupt Delay Value
(defconstant +e1000-txdctl+  #x03828)  ; TX Descriptor Control
(defconstant +e1000-tadv+    #x0382c)  ; TX Absolute Interrupt Delay
(defconstant +e1000-itr+     #x000c4)  ; Interrupt Throttle Rate
(defconstant +e1000-ral0+    #x05400)  ; Receive Address Low
(defconstant +e1000-rah0+    #x05404)  ; Receive Address High
(defconstant +e1000-mta+     #x05200)  ; Multicast Table Array (128 entries)

;; Control Register bits
(defconstant +ctrl-fd+       (ash 1 0))   ; Full Duplex
(defconstant +ctrl-lrst+     (ash 1 3))   ; Link Reset
(defconstant +ctrl-asde+     (ash 1 5))   ; Auto-Speed Detection Enable
(defconstant +ctrl-slu+      (ash 1 6))   ; Set Link Up
(defconstant +ctrl-rst+      (ash 1 26))  ; Device Reset
(defconstant +ctrl-phy-rst+  (ash 1 31))  ; PHY Reset

;; EEPROM Read bits
(defconstant +eerd-start+    (ash 1 0))   ; Start Read
(defconstant +eerd-done+     (ash 1 4))   ; Read Done

;; RX statistics registers
(defconstant +e1000-crcerrs+ #x04000)  ; CRC Error Count
(defconstant +e1000-rxerrc+  #x0400C)  ; RX Error Count
(defconstant +e1000-mpc+     #x04010)  ; Missed Packets Count
(defconstant +e1000-gprc+    #x04074)  ; Good Packets Received Count

;; Receive Control bits
(defconstant +rctl-en+       (ash 1 1))   ; Receiver Enable
(defconstant +rctl-sbp+      (ash 1 2))   ; Store Bad Packets
(defconstant +rctl-upe+      (ash 1 3))   ; Unicast Promiscuous
(defconstant +rctl-mpe+      (ash 1 4))   ; Multicast Promiscuous
(defconstant +rctl-bam+      (ash 1 15))  ; Broadcast Accept Mode
(defconstant +rctl-bsize-2048+ 0)         ; Buffer size 2048 (bits 16-17 = 00)
(defconstant +rctl-bsize-1024+ (ash 1 16)) ; Buffer size 1024
(defconstant +rctl-bsize-512+  (ash 2 16)) ; Buffer size 512
(defconstant +rctl-bsize-256+  (ash 3 16)) ; Buffer size 256
(defconstant +rctl-secrc+    (ash 1 26))  ; Strip Ethernet CRC

;; Transmit Control bits
(defconstant +tctl-en+       (ash 1 1))   ; Transmitter Enable
(defconstant +tctl-psp+      (ash 1 3))   ; Pad Short Packets
(defconstant +tctl-ct+       (ash #x0f 4))  ; Collision Threshold (default)
(defconstant +tctl-cold+     (ash #x40 12)) ; Collision Distance (full duplex)

;; TX Descriptor command bits
(defconstant +txd-cmd-eop+   (ash 1 0))   ; End of Packet
(defconstant +txd-cmd-ifcs+  (ash 1 1))   ; Insert FCS/CRC
(defconstant +txd-cmd-rs+    (ash 1 3))   ; Report Status

;; TX Descriptor status bits
(defconstant +txd-stat-dd+   (ash 1 0))   ; Descriptor Done

;; RX Descriptor status bits
(defconstant +rxd-stat-dd+   (ash 1 0))   ; Descriptor Done
(defconstant +rxd-stat-eop+  (ash 1 1))   ; End of Packet

;; Interrupt bits
(defconstant +int-txdw+      (ash 1 0))   ; TX Descriptor Written Back
(defconstant +int-lsc+       (ash 1 2))   ; Link Status Change
(defconstant +int-rxdmt0+    (ash 1 4))   ; RX Descriptor Min Threshold
(defconstant +int-rxo+       (ash 1 6))   ; Receiver Overrun
(defconstant +int-rxt0+      (ash 1 7))   ; Receiver Timer Interrupt

;; Ring sizes (must be multiple of 8, and 128 bytes aligned for descriptors)
(defconstant +rx-ring-size+ 128)
(defconstant +tx-ring-size+ 64)
(defconstant +rx-buffer-size+ 2048)

;;; ============================================================
;;; Configuration
;;; ============================================================

(defvar *e1000-verbose* nil
  "When true, print verbose debug output during initialization and operations")

;;; ============================================================
;;; Packet Pool - GC-free packet management
;;; ============================================================
;;; Following the pattern from IPv6 implementation to avoid
;;; triggering garbage collection during packet processing.

(defconstant +packet-pool-size+ 8)

(defvar *packet-pool* nil
  "Pool of pre-allocated packet buffers to avoid GC during networking")

(defvar *packet-pool-initialized* nil
  "Flag indicating if packet pool has been initialized")

(defun init-packet-pool ()
  "Initialize the packet pool with pre-allocated buffers.
   Call this once at startup, before any networking operations."
  (unless *packet-pool-initialized*
    (setf *packet-pool* (make-array +packet-pool-size+ :fill-pointer 0))
    ;; Pre-allocate all packet buffers
    (dotimes (i +packet-pool-size+)
      (vector-push (make-array +max-ethernet-frame-size+
                               :element-type '(unsigned-byte 8)
                               :fill-pointer 0)
                   *packet-pool*))
    (setf *packet-pool-initialized* t))
  *packet-pool*)

(defun get-packet ()
  "Get a packet buffer from the pool. Returns a pre-allocated buffer
   if available, otherwise allocates a new one (which may trigger GC)."
  (unless *packet-pool-initialized*
    (init-packet-pool))
  (if (plusp (fill-pointer *packet-pool*))
      (let ((packet (vector-pop *packet-pool*)))
        (setf (fill-pointer packet) 0)
        packet)
      ;; Pool exhausted - must allocate (will trigger GC)
      (progn
        (format t "~&WARNING: Packet pool exhausted, allocating...~%")
        (make-array +max-ethernet-frame-size+
                    :element-type '(unsigned-byte 8)
                    :fill-pointer 0))))

(defun free-packet (packet)
  "Return a packet buffer to the pool for reuse."
  (when (and *packet-pool*
             (< (fill-pointer *packet-pool*) +packet-pool-size+))
    (setf (fill-pointer packet) 0)
    (vector-push packet *packet-pool*))
  nil)

(defmacro with-packet ((var) &body body)
  "Execute BODY with VAR bound to a packet from the pool.
   Automatically returns packet to pool when done."
  `(let ((,var (get-packet)))
     (unwind-protect
         (progn ,@body)
       (free-packet ,var))))

;;; ============================================================
;;; GC-free delay - avoids loop variable allocation
;;; ============================================================

(defun asm-delay (&optional (iterations #x10000))
  "Delay using pure assembly loop - no GC pressure.
   Each iteration is roughly a few CPU cycles."
  (with-inline-assembly (:returns :nothing)
    (:compile-form (:result-mode :ecx) iterations)
    (:sarl 2 :ecx)                      ; Convert fixnum to raw integer
    asm-delay-loop
    (:decl :ecx)
    (:jnz 'asm-delay-loop)))

(defun asm-delay-short ()
  "Short delay (~65k iterations) using pure assembly."
  (with-inline-assembly (:returns :nothing)
    (:movl #x10000 :ecx)
    short-delay-loop
    (:decl :ecx)
    (:jnz 'short-delay-loop)))

(defun asm-delay-long ()
  "Long delay (~1M iterations) using pure assembly."
  (with-inline-assembly (:returns :nothing)
    (:movl #x100000 :ecx)
    long-delay-loop
    (:decl :ecx)
    (:jnz 'long-delay-loop)))

;;; ============================================================
;;; Device class
;;; ============================================================

(defvar *e1000-devices* nil
  "List of detected e1000 devices")

(defclass e1000-device (ethernet-device)
  ((mmio-base
    :initarg :mmio-base
    :reader mmio-base
    :documentation "Memory-mapped I/O base address")
   (pci-bus :initarg :pci-bus :reader pci-bus)
   (pci-device :initarg :pci-device :reader pci-device)
   (pci-function :initarg :pci-function :reader pci-function)
   ;; Interrupt
   (irq :initarg :irq :accessor e1000-irq :initform nil)
   (interrupt-count :initform 0 :accessor interrupt-count)
   (rx-pending :initform nil :accessor rx-pending
               :documentation "Flag set by interrupt handler when RX ready")
   ;; RX ring
   (rx-ring-phys :accessor rx-ring-phys)
   (rx-ring :accessor rx-ring)
   (rx-buffers :accessor rx-buffers)
   (rx-cur :initform 0 :accessor rx-cur)
   ;; TX ring
   (tx-ring-phys :accessor tx-ring-phys)
   (tx-ring :accessor tx-ring)
   (tx-buffers :accessor tx-buffers)
   (tx-cur :initform 0 :accessor tx-cur)))

;;; ============================================================
;;; Register access (MMIO)
;;; ============================================================

(defun e1000-read-reg (device reg)
  "Read a 32-bit register via MMIO"
  (memref-int (+ (mmio-base device) reg) :physicalp t))

(defun e1000-write-reg (device reg value)
  "Write a 32-bit register via MMIO"
  (setf (memref-int (+ (mmio-base device) reg) :physicalp t) value))

(defsetf e1000-read-reg e1000-write-reg)

;;; ============================================================
;;; Interrupt Handling
;;; ============================================================

(defvar *e1000-interrupt-device* nil
  "The e1000 device for the interrupt handler (single device support)")

(defun e1000-interrupt-handler (vector int-frame)
  "Handle e1000 interrupts. Called from the interrupt dispatcher."
  (declare (ignore vector int-frame))
  (let ((device *e1000-interrupt-device*))
    (when device
      ;; Read and clear interrupt cause
      (let ((icr (e1000-read-reg device +e1000-icr+)))
        (incf (interrupt-count device))
        ;; RX interrupt - packet(s) received
        (when (logtest icr +int-rxt0+)
          (setf (rx-pending device) t))
        ;; Link status change
        (when (logtest icr +int-lsc+)
          (when *e1000-verbose*
            (format t "~&e1000: link ~A~%"
                    (if (e1000-link-up-p device) "up" "down"))))
        ;; Send EOI to PIC
        (muerte.x86-pc:pic8259-end-of-interrupt (e1000-irq device))))))

(defvar *e1000-interrupts-enabled* nil "T if e1000 interrupts are already enabled")

(defun e1000-enable-interrupts (device)
  "Enable e1000 hardware interrupts. Skips setup if already enabled."
  (when *e1000-interrupts-enabled*
    (return-from e1000-enable-interrupts t))
  (let ((irq (e1000-irq device)))
    (unless irq
      (error "Device has no IRQ assigned"))
    ;; Store device for interrupt handler
    (setf *e1000-interrupt-device* device)
    ;; Register handler (IRQ N -> vector 32+N)
    (setf (exception-handler (+ 32 irq)) #'e1000-interrupt-handler)
    ;; Clear any pending interrupts
    (e1000-read-reg device +e1000-icr+)
    ;; Enable RX and link status interrupts
    (e1000-write-reg device +e1000-ims+
                     (logior +int-rxt0+ +int-lsc+))
    ;; Unmask IRQ in PIC
    ;; For IRQs 8-15, also unmask IRQ 2 (cascade from slave to master)
    (let ((mask (muerte.x86-pc:pic8259-irq-mask)))
      (setf (muerte.x86-pc:pic8259-irq-mask)
            (logand mask
                    (lognot (ash 1 irq))
                    (if (>= irq 8) #xFFFB #xFFFF))))
    ;; Enable CPU interrupts
    (with-inline-assembly (:returns :nothing) (:sti))
    (setf *e1000-interrupts-enabled* t)
    (when *e1000-verbose*
      (format t "~&e1000: interrupts enabled on IRQ ~D (vector ~D)~%"
              irq (+ 32 irq)))
    t))

(defun e1000-interrupt-status (device)
  "Check e1000 interrupt status for debugging."
  (let ((icr (e1000-read-reg device +e1000-icr+))
        (ims (e1000-read-reg device +e1000-ims+))
        (irq (e1000-irq device))
        (mask (muerte.x86-pc:pic8259-irq-mask)))
    (format t "~&e1000 interrupt status:~%")
    (format t "  ICR: #x~8,'0X (pending interrupts)~%" icr)
    (format t "  IMS: #x~8,'0X (enabled interrupts)~%" ims)
    (format t "  IRQ: ~A  PIC mask bit: ~A~%"
            irq
            (if irq (if (logbitp irq mask) "masked" "unmasked") "N/A"))
    (format t "  Interrupt count: ~D~%" (interrupt-count device))
    (values icr ims)))

(defun e1000-disable-interrupts (device)
  "Disable e1000 hardware interrupts."
  (let ((irq (e1000-irq device)))
    (when irq
      ;; Disable all interrupts in hardware
      (e1000-write-reg device +e1000-imc+ #xffffffff)
      ;; Mask IRQ in PIC
      (let ((mask (muerte.x86-pc:pic8259-irq-mask)))
        (setf (muerte.x86-pc:pic8259-irq-mask)
              (logior mask (ash 1 irq))))
      (setf *e1000-interrupts-enabled* nil)
      (when *e1000-verbose*
        (format t "~&e1000: interrupts disabled~%"))))
  nil)

(defvar *wait-immediate-count* 0 "Packets found immediately")
(defvar *wait-interrupt-count* 0 "Packets found via interrupt")
(defvar *wait-hw-count* 0 "Packets found via hardware check")
(defvar *wait-timeout-count* 0 "Timeouts")
(defvar *wait-total-loops* 0 "Total HLT iterations")

(defun e1000-wait-stats ()
  "Print wait statistics."
  (format t "~&Wait stats: immed=~D int=~D hw=~D timeout=~D loops=~D~%"
          *wait-immediate-count* *wait-interrupt-count*
          *wait-hw-count* *wait-timeout-count* *wait-total-loops*))

(defun e1000-wait-stats-reset ()
  "Reset wait statistics."
  (setf *wait-immediate-count* 0
        *wait-interrupt-count* 0
        *wait-hw-count* 0
        *wait-timeout-count* 0
        *wait-total-loops* 0))

(defun e1000-wait-for-packet (device &optional (timeout-ms 1000))
  "Wait for a packet using PIT-based polling. Returns T if packet available, NIL on timeout.
   TIMEOUT-MS is the timeout in milliseconds (default 1000ms = 1 second).
   Uses the PIT counter for precise timing - much faster than HLT-based waiting."
  ;; Check immediately - packet might already be here
  (when (packet-available-p device)
    (incf *wait-immediate-count*)
    (return-from e1000-wait-for-packet t))
  ;; PIT-based polling loop
  ;; PIT frequency is ~1.19MHz, so 1ms = ~1193 ticks
  ;; Counter counts DOWN and wraps at 65536 (~55ms)
  (let ((start-count (muerte.x86-pc:pit8253-timer-count 0))
        (ticks-per-ms 1193)
        (elapsed-ms 0)
        (polls 0))
    (tagbody
     wait-loop
       ;; Check for timeout
       (when (>= elapsed-ms timeout-ms)
         (incf *wait-timeout-count*)
         (incf *wait-total-loops* polls)
         (return-from e1000-wait-for-packet nil))
       ;; Check for packet via interrupt flag
       (when (rx-pending device)
         (setf (rx-pending device) nil)
         (incf *wait-interrupt-count*)
         (incf *wait-total-loops* polls)
         (return-from e1000-wait-for-packet t))
       ;; Check hardware directly
       (when (packet-available-p device)
         (incf *wait-hw-count*)
         (incf *wait-total-loops* polls)
         (return-from e1000-wait-for-packet t))
       ;; Update elapsed time from PIT counter
       ;; Counter counts down, so elapsed = start - current (mod 65536)
       (let* ((current (muerte.x86-pc:pit8253-timer-count 0))
              (elapsed-ticks (logand (- start-count current) #xffff)))
         ;; If wrapped more than once (~55ms), just count as one wrap
         (when (> elapsed-ticks 60000)
           (setf elapsed-ticks 60000))
         (setf elapsed-ms (truncate elapsed-ticks ticks-per-ms)))
       (incf polls)
       ;; Brief pause to avoid hammering the PIT
       (dotimes (i 10) (declare (ignore i)))
       (go wait-loop))))

(defun e1000-receive-wait (device &optional packet (start 0) (timeout-ms 1000))
  "Receive a packet, waiting for interrupt if none available.
   TIMEOUT-MS is timeout in milliseconds (default 1000ms).
   Returns the packet on success, NIL on timeout."
  (when (e1000-wait-for-packet device timeout-ms)
    (receive device packet start)))

;;; ============================================================
;;; EEPROM access
;;; ============================================================

(defun e1000-read-eeprom (device addr)
  "Read a word from EEPROM at ADDR"
  ;; Write address with start bit
  (e1000-write-reg device +e1000-eerd+
                   (logior +eerd-start+ (ash addr 8)))
  ;; Poll for completion
  (loop for i from 0 below 1000
        for val = (e1000-read-reg device +e1000-eerd+)
        when (logbitp 4 val)  ; DONE bit
        return (ash val -16)  ; Data in upper 16 bits
        finally (error "EEPROM read timeout")))

(defun e1000-read-mac-from-eeprom (device)
  "Read MAC address from EEPROM"
  (let ((mac (make-array 6 :element-type '(unsigned-byte 8))))
    (let ((word0 (e1000-read-eeprom device 0))
          (word1 (e1000-read-eeprom device 1))
          (word2 (e1000-read-eeprom device 2)))
      (setf (aref mac 0) (ldb (byte 8 0) word0)
            (aref mac 1) (ldb (byte 8 8) word0)
            (aref mac 2) (ldb (byte 8 0) word1)
            (aref mac 3) (ldb (byte 8 8) word1)
            (aref mac 4) (ldb (byte 8 0) word2)
            (aref mac 5) (ldb (byte 8 8) word2)))
    mac))

;;; ============================================================
;;; Descriptor ring setup
;;; ============================================================

;;; ============================================================
;;; Static DMA Buffers - Fixed physical memory outside GC
;;; ============================================================
;;;
;;; The GC is a copying collector that moves objects to new locations.
;;; This breaks DMA because hardware descriptors contain physical addresses
;;; that become stale after GC. The solution is to allocate DMA buffers
;;; at a FIXED physical address that GC doesn't manage.
;;;
;;; Memory layout at +dma-base-address+:
;;; Offset 0x00000: RX descriptor ring (128 * 16 = 2048 bytes)
;;; Offset 0x01000: RX buffers (128 * 2048 = 262144 bytes)
;;; Offset 0x41000: TX descriptor ring (64 * 16 = 1024 bytes)
;;; Offset 0x41400: TX buffers (64 * 1536 = 98304 bytes)
;;; Total: ~360KB

;; Base physical address for all DMA buffers
;; Using 64MB to stay above the Lisp heap (which can grow to 30+ MB during
;; crypto operations). Must be below 4GB for 32-bit DMA and within QEMU's
;; memory allocation (512MB with -m 512).
(defconstant +dma-base-address+ #x04000000)  ; 64 MB

;; Offsets within DMA region
(defconstant +dma-rx-ring-offset+ #x00000)
(defconstant +dma-rx-bufs-offset+ #x01000)
(defconstant +dma-tx-ring-offset+ #x41000)
(defconstant +dma-tx-bufs-offset+ #x41400)

;; Track initialization
(defvar *dma-initialized* nil
  "True if static DMA buffers have been initialized")

(defun dma-address (offset)
  "Calculate the physical address for a DMA buffer offset."
  (+ +dma-base-address+ offset))

(defun dma-read-byte (offset)
  "Read a byte from DMA memory at OFFSET."
  (memref-int (dma-address offset) :type :unsigned-byte8 :physicalp t))

(defun dma-write-byte (offset value)
  "Write a byte VALUE to DMA memory at OFFSET."
  (setf (memref-int (dma-address offset) :type :unsigned-byte8 :physicalp t) value))

(defun dma-read-u32 (offset)
  "Read a 32-bit word from DMA memory at OFFSET."
  (memref-int (dma-address offset) :type :unsigned-byte32 :physicalp t))

(defun dma-write-u32 (offset value)
  "Write a 32-bit VALUE to DMA memory at OFFSET."
  (setf (memref-int (dma-address offset) :type :unsigned-byte32 :physicalp t) value))

(defun dma-write-u16 (offset value)
  "Write a 16-bit VALUE to DMA memory at OFFSET."
  (setf (memref-int (dma-address offset) :type :unsigned-byte16 :physicalp t) value))

(defun dma-read-u16 (offset)
  "Read a 16-bit word from DMA memory at OFFSET."
  (memref-int (dma-address offset) :type :unsigned-byte16 :physicalp t))

(defun init-dma-memory ()
  "Initialize the static DMA memory region.
   Zeroes out all DMA buffers. Call once before using networking."
  (unless *dma-initialized*
    (format t "~&Initializing static DMA memory at #x~8,'0X...~%" +dma-base-address+)
    ;; Zero the RX ring (2KB)
    (dotimes (i 512)
      (dma-write-u32 (+ +dma-rx-ring-offset+ (* i 4)) 0))
    ;; Zero first part of RX buffers (just headers, not all 256KB)
    (dotimes (i 256)
      (dma-write-u32 (+ +dma-rx-bufs-offset+ (* i 4)) 0))
    ;; Zero the TX ring (1KB)
    (dotimes (i 256)
      (dma-write-u32 (+ +dma-tx-ring-offset+ (* i 4)) 0))
    ;; Zero first part of TX buffers
    (dotimes (i 256)
      (dma-write-u32 (+ +dma-tx-bufs-offset+ (* i 4)) 0))
    (setf *dma-initialized* t)
    (format t "~&DMA memory initialized.~%"))
  t)

(defun dma-copy-to (offset data &optional (start 0) (end (length data)))
  "Copy DATA (array of bytes) to DMA memory at OFFSET."
  (loop for i from start below end
        for j from 0
        do (dma-write-byte (+ offset j) (aref data i))))

(defun dma-copy-from (offset length)
  "Copy LENGTH bytes from DMA memory at OFFSET to a new array."
  (let ((result (make-array length :element-type '(unsigned-byte 8))))
    (dotimes (i length)
      (setf (aref result i) (dma-read-byte (+ offset i))))
    result))

;;; ============================================================
;;; Legacy array-based support (for compatibility)
;;; ============================================================

(defun array-data-address (array)
  "Get the PHYSICAL address of array data.
   Uses the standard Movitz pattern: (object-location + location-physical-offset + header-offset) * 4"
  ;; object-location returns address/4, location-physical-offset is offset/4
  ;; For a simple-array, data starts 2 words (8 bytes) after object start
  ;; So physical data address = ((object-location + phys-offset) * 4) + 8
  ;;                          = (object-location + phys-offset + 2) * 4
  (* 4 (+ (object-location array)
          (location-physical-offset)
          2)))

(defun test-memory-access ()
  "Test if array-data-address returns correct physical addresses."
  (let* ((arr (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (obj-loc (object-location arr))
         (phys-off (location-physical-offset))
         (addr (array-data-address arr)))
    (format t "~&Object location: #x~8,'0X~%" obj-loc)
    (format t "~&Physical offset: #x~8,'0X~%" phys-off)
    (format t "~&Array data addr: #x~8,'0X~%" addr)
    (format t "~&Calculated phys: #x~8,'0X~%" (* 4 (+ obj-loc phys-off 2)))  ; +2 for header
    ;; Write via normal array access
    (setf (aref arr 0) #xDE
          (aref arr 1) #xAD
          (aref arr 2) #xBE
          (aref arr 3) #xEF)
    ;; Read back via physical access using our calculated address
    (let ((b0 (memref-int addr :offset 0 :type :unsigned-byte8 :physicalp t))
          (b1 (memref-int addr :offset 1 :type :unsigned-byte8 :physicalp t))
          (b2 (memref-int addr :offset 2 :type :unsigned-byte8 :physicalp t))
          (b3 (memref-int addr :offset 3 :type :unsigned-byte8 :physicalp t)))
      (format t "~&Wrote (via aref): DE AD BE EF~%")
      (format t "~&Read (at #x~8,'0X): ~2,'0X ~2,'0X ~2,'0X ~2,'0X~%"
              addr b0 b1 b2 b3)
      ;; Also try using calculated address
      (let* ((calc-addr (* 4 (+ obj-loc phys-off 2)))
             (c0 (memref-int calc-addr :offset 0 :type :unsigned-byte8 :physicalp t))
             (c1 (memref-int calc-addr :offset 1 :type :unsigned-byte8 :physicalp t))
             (c2 (memref-int calc-addr :offset 2 :type :unsigned-byte8 :physicalp t))
             (c3 (memref-int calc-addr :offset 3 :type :unsigned-byte8 :physicalp t)))
        (format t "~&Read (at #x~8,'0X): ~2,'0X ~2,'0X ~2,'0X ~2,'0X~%"
                calc-addr c0 c1 c2 c3)
        (if (and (= c0 #xDE) (= c1 #xAD) (= c2 #xBE) (= c3 #xEF))
            (format t "~&MATCH with calculated addr!~%")
            (format t "~&Still MISMATCH.~%"))))))

(defun align-to-16 (addr)
  "Round up address to next 16-byte boundary"
  (let ((remainder (logand addr 15)))
    (if (zerop remainder)
        addr
        (+ addr (- 16 remainder)))))

(defun allocate-ring-memory (count desc-size)
  "Allocate memory for a descriptor ring. Returns (values array phys-addr).
   The descriptor ring needs 16-byte alignment."
  ;; Create a simple array with extra space for alignment padding
  ;; Allocate 16 extra bytes to ensure we can find an aligned address
  (let* ((total-size (+ (* count desc-size) 16))
         (array (make-array total-size :element-type '(unsigned-byte 8)
                            :initial-element 0)))
    ;; Get physical address of array data and align to 16 bytes
    (let* ((raw-addr (array-data-address array))
           (aligned-addr (align-to-16 raw-addr)))
      (values array aligned-addr))))

(defun setup-rx-ring (device)
  "Initialize the receive descriptor ring using static DMA memory.
   Uses fixed physical addresses that won't be moved by GC."
  ;; Initialize static DMA memory if not done yet
  (init-dma-memory)
  (let* ((ring-size 2048)  ; 128 * 16 bytes
         (ring-phys (dma-address +dma-rx-ring-offset+))
         (buf-phys-base (dma-address +dma-rx-bufs-offset+)))
    ;; Store physical address of ring (no array needed - using fixed memory)
    (setf (rx-ring device) nil  ; No GC-managed array
          (rx-ring-phys device) ring-phys)
    ;; Set up descriptors pointing into the static buffer area
    ;; Use explicit loop with incremented offsets to avoid complex arithmetic
    (let ((desc-offset +dma-rx-ring-offset+)
          (buf-phys buf-phys-base))
      (dotimes (i +rx-ring-size+)
        (declare (ignore i))
        ;; Set up descriptor in static DMA memory
        (dma-write-u32 desc-offset buf-phys)              ; buf addr lo
        (dma-write-u32 (+ desc-offset 4) 0)               ; buf addr hi
        (dma-write-u32 (+ desc-offset 8) 0)               ; length, checksum
        (dma-write-u32 (+ desc-offset 12) 0)              ; status, errors, special
        ;; Advance to next descriptor and buffer
        (incf desc-offset 16)
        (incf buf-phys +rx-buffer-size+)))
    ;; No need for rx-buffers array - we calculate offsets on the fly
    (setf (rx-buffers device) nil)
    ;; Tell hardware about the ring
    (e1000-write-reg device +e1000-rdbal+ ring-phys)
    (e1000-write-reg device +e1000-rdbah+ 0)
    (e1000-write-reg device +e1000-rdlen+ ring-size)
    (e1000-write-reg device +e1000-rdh+ 0)
    (e1000-write-reg device +e1000-rdt+ 0)  ; Initialize to 0 (empty ring)
    (setf (rx-cur device) 0)
    (when *e1000-verbose*
      (format t "~&  RX ring: #x~8,'0X (~D descriptors) [static DMA]~%"
              ring-phys +rx-ring-size+))))

(defun setup-tx-ring (device)
  "Initialize the transmit descriptor ring using static DMA memory.
   Uses fixed physical addresses that won't be moved by GC."
  ;; Initialize static DMA memory if not done yet
  (init-dma-memory)
  (let* ((ring-size 1024)  ; 64 * 16 bytes
         (ring-phys (dma-address +dma-tx-ring-offset+)))
    (setf (tx-ring device) nil  ; No GC-managed array
          (tx-ring-phys device) ring-phys)
    ;; Clear the TX ring (descriptors will be set up when transmitting)
    ;; Use explicit loop with incremented offset
    (let ((desc-offset +dma-tx-ring-offset+))
      (dotimes (i +tx-ring-size+)
        (declare (ignore i))
        (dma-write-u32 desc-offset 0)
        (dma-write-u32 (+ desc-offset 4) 0)
        (dma-write-u32 (+ desc-offset 8) 0)
        (dma-write-u32 (+ desc-offset 12) 0)
        (incf desc-offset 16)))
    ;; No need for tx-buffers array
    (setf (tx-buffers device) nil)
    ;; Tell hardware about the ring
    (e1000-write-reg device +e1000-tdbal+ ring-phys)
    (e1000-write-reg device +e1000-tdbah+ 0)
    (e1000-write-reg device +e1000-tdlen+ ring-size)
    (e1000-write-reg device +e1000-tdh+ 0)
    (e1000-write-reg device +e1000-tdt+ 0)
    (setf (tx-cur device) 0)
    (when *e1000-verbose*
      (format t "~&  TX ring: #x~8,'0X (~D descriptors) [static DMA]~%"
              ring-phys +tx-ring-size+))))

;;; ============================================================
;;; Device initialization
;;; ============================================================

(defun e1000-reset (device)
  "Reset the e1000 device"
  ;; Write CTRL with RST bit set - use known good value
  ;; CTRL.RST = bit 26 = #x4000000
  (e1000-write-reg device +e1000-ctrl+ #x4000000)
  ;; Wait for reset to complete (bit clears itself)
  (loop repeat 1000
        until (zerop (logand (e1000-read-reg device +e1000-ctrl+) #x4000000))
        do (io-delay 10))
  ;; Disable all interrupts - write -1 which is all bits set
  (e1000-write-reg device +e1000-imc+ -1)
  ;; Clear pending interrupts
  (e1000-read-reg device +e1000-icr+))

(defun e1000-init-link (device)
  "Initialize the link"
  ;; Write CTRL with ASDE (bit 5) and SLU (bit 6) set
  ;; This is a simple init - no need to preserve other bits after reset
  (e1000-write-reg device +e1000-ctrl+
                   (logior +ctrl-asde+ +ctrl-slu+)))

(defun e1000-write-reg32-with-high-bit (addr low-30-bits)
  "Write 32 bits to ADDR with bit 31 set.
   LOW-30-BITS is a fixnum containing the lower 30 bits of the value.
   Bit 31 will be set in addition to the provided bits.
   Uses inline assembly to bypass fixnum limitations."
  (with-inline-assembly (:returns :nothing)
    (:compile-two-forms (:eax :ebx) addr low-30-bits)
    ;; EAX has the address as a fixnum (shifted left by 2)
    ;; EBX has low-30-bits as a fixnum (shifted left by 2)
    ;; Convert fixnums to raw values
    (:sarl 2 :eax)                      ; EAX = physical address
    (:sarl 2 :ebx)                      ; EBX = low 30 bits
    (:orl #x80000000 :ebx)              ; Set bit 31
    ((:gs-override) :movl :ebx (:eax)))) ; Write to physical memory

(defun e1000-setup-mac (device)
  "Read and configure MAC address"
  (let ((mac (e1000-read-mac-from-eeprom device)))
    (setf (mac-address device) mac)
    ;; Write MAC to RAL0 (lower 4 bytes)
    (e1000-write-reg device +e1000-ral0+
                     (logior (aref mac 0)
                             (ash (aref mac 1) 8)
                             (ash (aref mac 2) 16)
                             (ash (aref mac 3) 24)))
    ;; Write MAC to RAH0 (upper 2 bytes) plus AV bit (bit 31)
    ;; RAH0 format: bits 0-15 = MAC[4:5], bit 31 = AV
    ;; Use inline assembly to write full 32 bits with bit 31 set
    (let* ((mmio (mmio-base device))
           (rah0-addr (+ mmio +e1000-rah0+))
           (low-bits (logior (aref mac 4) (ash (aref mac 5) 8))))
      (e1000-write-reg32-with-high-bit rah0-addr low-bits))
    mac))

(defun e1000-clear-multicast (device)
  "Clear the multicast table array"
  (dotimes (i 128)
    (e1000-write-reg device (+ +e1000-mta+ (* i 4)) 0)))

(defun e1000-enable-rx (device)
  "Enable the receiver"
  (let ((rctl (logior +rctl-en+         ; Enable
                      +rctl-upe+        ; Unicast promiscuous (bypass MAC filter)
                      +rctl-mpe+        ; Multicast promiscuous
                      +rctl-bam+        ; Accept broadcast
                      +rctl-bsize-2048+ ; 2KB buffers
                      +rctl-secrc+)))   ; Strip CRC
    (e1000-write-reg device +e1000-rctl+ rctl)
    ;; Re-write RDT after enabling RX to ensure hardware sees it
    (e1000-write-reg device +e1000-rdt+ (1- +rx-ring-size+))))

(defun e1000-enable-tx (device)
  "Enable the transmitter with no delays"
  ;; Clear all TX delay registers for immediate transmission
  (e1000-write-reg device +e1000-tidv+ 0)   ; No TX interrupt delay
  (e1000-write-reg device +e1000-tadv+ 0)   ; No TX absolute delay
  (e1000-write-reg device +e1000-itr+ 0)    ; No interrupt throttling
  ;; TXDCTL: enable TX queue, no prefetch/writeback thresholds
  (e1000-write-reg device +e1000-txdctl+ (ash 1 25))  ; TXDCTL.QUEUE_ENABLE
  ;; Enable transmitter
  (let ((tctl (logior +tctl-en+    ; Enable
                      +tctl-psp+   ; Pad short packets
                      +tctl-ct+    ; Collision threshold
                      +tctl-cold+))) ; Collision distance
    (e1000-write-reg device +e1000-tctl+ tctl)))

(defmethod reset-device ((device e1000-device))
  "Full device reset and initialization"
  (e1000-reset device)
  (e1000-setup-mac device)
  (e1000-clear-multicast device)
  (setup-rx-ring device)
  (setup-tx-ring device)
  (e1000-init-link device)
  (e1000-enable-rx device)
  (e1000-enable-tx device)
  device)

;;; ============================================================
;;; Packet I/O
;;; ============================================================

(defmethod packet-available-p ((device e1000-device))
  "Check if a packet is available in the RX ring"
  (let* ((cur (rx-cur device))
         (desc-addr (+ (rx-ring-phys device) (* cur 16)))
         ;; Status is at offset 12 in descriptor
         (status (memref-int desc-addr :offset 12
                             :type :unsigned-byte8 :physicalp t)))
    (logbitp 0 status)))  ; DD bit

(defmethod receive ((device e1000-device) &optional packet (start 0))
  "Receive a packet from the device. GC-free version using static DMA memory."
  (when (packet-available-p device)
    (let* ((cur (rx-cur device))
           (desc-addr (+ (rx-ring-phys device) (* cur 16)))
           ;; Get length from descriptor (offset 8, 16-bit)
           (pkt-length (memref-int desc-addr :offset 8
                                   :type :unsigned-byte16 :physicalp t))
           ;; Calculate buffer physical address from static DMA region
           (buf-phys (dma-address (+ +dma-rx-bufs-offset+ (* cur +rx-buffer-size+))))
           (packet (or packet (make-array +max-ethernet-frame-size+
                                          :element-type '(unsigned-byte 8)
                                          :fill-pointer t)))
           (max-copy (min pkt-length (- (array-dimension packet 0) start))))
      ;; Copy data from static DMA memory to packet array
      ;; Using tagbody to avoid loop allocation
      (let ((i 0)
            (addr buf-phys))
        (tagbody
         copy-loop
           (when (>= i max-copy)
             (go copy-done))
           (setf (aref packet (the fixnum (+ start i)))
                 (memref-int addr :type :unsigned-byte8 :physicalp t))
           (setf i (the fixnum (1+ i)))
           (setf addr (the fixnum (1+ addr)))
           (go copy-loop)
         copy-done))
      (setf (fill-pointer packet) (+ start pkt-length))
      ;; Clear status in descriptor
      (setf (memref-int desc-addr :offset 12 :type :unsigned-byte8 :physicalp t) 0)
      ;; Advance tail pointer (give buffer back to hardware)
      (let ((new-cur (mod (1+ cur) +rx-ring-size+)))
        (setf (rx-cur device) new-cur)
        (e1000-write-reg device +e1000-rdt+ cur))
      packet)))

(defmethod transmit ((device e1000-device) packet
                     &key (start 0) (end (length packet)))
  "Transmit a packet. GC-free version using static DMA memory.
   TX Descriptor format (legacy):
   Offset 0-7:  Buffer Address (64-bit)
   Offset 8-9:  Length (16-bit)
   Offset 10:   CSO (Checksum Offset, 8-bit)
   Offset 11:   CMD (Command, 8-bit) - EOP, IFCS, RS bits
   Offset 12:   STA (Status, 8-bit) - DD bit
   Offset 13:   Reserved
   Offset 14-15: Special"
  (let* ((cur (tx-cur device))
         (desc-addr (+ (tx-ring-phys device) (* cur 16)))
         ;; Calculate buffer physical address from static DMA region
         (buf-phys (dma-address (+ +dma-tx-bufs-offset+ (* cur +max-ethernet-frame-size+))))
         (length (- end start))
         (cmd (logior +txd-cmd-eop+ +txd-cmd-ifcs+ +txd-cmd-rs+)))
    ;; Check if ring is full (TDT about to catch up to TDH)
    ;; Only wait if we're about to overwrite a descriptor the hardware hasn't processed
    (let* ((tdh (e1000-read-reg device +e1000-tdh+))
           (next-cur (mod (1+ cur) +tx-ring-size+)))
      (when (= next-cur tdh)
        ;; Ring is full - wait briefly for hardware to catch up
        (let ((wait-count 0))
          (tagbody
           wait-loop
             (when (>= wait-count 1000)
               (go wait-done))
             (when (/= (e1000-read-reg device +e1000-tdh+) tdh)
               (go wait-done))
             (setf wait-count (the fixnum (1+ wait-count)))
             (go wait-loop)
           wait-done))))
    ;; Copy packet directly to static DMA memory
    ;; Using tagbody to avoid loop allocation
    (let ((i 0)
          (addr buf-phys))
      (tagbody
       copy-loop
         (when (>= i length)
           (go copy-done))
         (setf (memref-int addr :type :unsigned-byte8 :physicalp t)
               (aref packet (the fixnum (+ start i))))
         (setf i (the fixnum (1+ i)))
         (setf addr (the fixnum (1+ addr)))
         (go copy-loop)
       copy-done))
    ;; Set up descriptor
    ;; Buffer address low (offset 0)
    (setf (memref-int desc-addr :physicalp t) buf-phys)
    ;; Buffer address high (offset 4)
    (setf (memref-int desc-addr :offset 4 :physicalp t) 0)
    ;; Length (offset 8, 16-bit) + CSO (offset 10) + CMD (offset 11)
    (setf (memref-int desc-addr :offset 8 :type :unsigned-byte8 :physicalp t)
          (logand length #xff))
    (setf (memref-int desc-addr :offset 9 :type :unsigned-byte8 :physicalp t)
          (ash length -8))
    (setf (memref-int desc-addr :offset 10 :type :unsigned-byte8 :physicalp t) 0)
    (setf (memref-int desc-addr :offset 11 :type :unsigned-byte8 :physicalp t) cmd)
    (setf (memref-int desc-addr :offset 12 :type :unsigned-byte8 :physicalp t) 0)
    ;; Advance tail pointer to trigger transmission
    ;; Note: In QEMU user-mode networking, TX may be delayed by ~3 seconds
    ;; due to SLiRP's internal timing. This is a QEMU limitation, not a
    ;; driver issue - on real hardware, TX is immediate.
    (let ((new-cur (mod (1+ cur) +tx-ring-size+)))
      (setf (tx-cur device) new-cur)
      (e1000-write-reg device +e1000-tdt+ new-cur)))
  nil)

;;; ============================================================
;;; PCI Detection and Probe
;;; ============================================================

(defun e1000-probe-pci ()
  "Probe for e1000 devices on the PCI bus"
  (multiple-value-bind (bus device function status)
      (muerte.x86-pc::find-pci-device +e1000-vendor-id+ +e1000-device-id+)
    (when (eq status :successful)
      (values bus device function))))

(defun e1000-probe ()
  "Probe for and initialize e1000 network card.
   Returns the device on success, NIL if no card found."
  (multiple-value-bind (bus device function)
      (e1000-probe-pci)
    (unless bus
      (when *e1000-verbose*
        (format t "~&No e1000 found~%"))
      (return-from e1000-probe nil))
    (when *e1000-verbose*
      (format t "~&Found e1000 at PCI ~D:~D.~D~%" bus device function))
    ;; Enable bus mastering and memory space access
    (let ((cmd (muerte.x86-pc::pci-bios-config-space-word bus device function 4)))
      (when *e1000-verbose*
        (format t "~&  PCI CMD: #x~4,'0X" cmd))
      (setf (muerte.x86-pc::pci-bios-config-space-word bus device function 4)
            (logior cmd #x06))  ; Memory Space + Bus Master
      (when *e1000-verbose*
        (let ((new-cmd (muerte.x86-pc::pci-bios-config-space-word bus device function 4)))
          (format t " -> #x~4,'0X~%" new-cmd))))
    ;; Get BAR0 (MMIO base address) and IRQ
    (let* ((bar0 (muerte.x86-pc::pci-bios-config-space-dword bus device function #x10))
           (mmio-base (logand bar0 #xFFFFFFF0))  ; Mask off type bits
           (irq (ldb (byte 8 0)
                     (muerte.x86-pc::pci-bios-config-space-byte bus device function #x3c))))
      (when *e1000-verbose*
        (format t "~&  MMIO: #x~8,'0X  IRQ: ~D~%" mmio-base irq))
      ;; Create and initialize device
      (let ((e1000 (make-instance 'e1000-device
                     :mmio-base mmio-base
                     :pci-bus bus
                     :pci-device device
                     :pci-function function
                     :irq (if (< irq 16) irq nil))))  ; Valid IRQ range
        ;; Initialize the device
        (reset-device e1000)
        ;; Always print MAC - this is the essential info
        (format t "~&e1000: ~/ethernet:pprint-mac/~%" (mac-address e1000))
        (when *e1000-verbose*
          (format t "~&  Link: ~A  IRQ: ~A~%"
                  (if (e1000-link-up-p e1000) "UP" "DOWN")
                  (or (e1000-irq e1000) "none")))
        (push e1000 *e1000-devices*)
        e1000))))

;;; ============================================================
;;; IP Stack Integration
;;; ============================================================

(defun e1000-ip-init (&optional (ip #(10 0 2 15)) (router #(10 0 2 2)))
  "Initialize the e1000 as the IP stack's network interface.
   Default IPs are for QEMU user-mode networking."
  (let ((device (or (car *e1000-devices*) (e1000-probe))))
    (unless device
      (error "No e1000 device available"))
    ;; Set up the IP stack globals
    (setf muerte.ip4::*ip4-nic* device)
    (when ip
      (setf muerte.ip4::*ip4-ip* (muerte.ip4:ip4-address ip)))
    (when router
      (setf muerte.ip4::*ip4-router* (muerte.ip4:ip4-address router)))
    (format t "~&E1000 IP stack initialized:~%")
    (format t "  MAC: ~/ethernet:pprint-mac/~%" (mac-address device))
    (format t "  IP:  ~/ip4:pprint-ip4/~%" muerte.ip4::*ip4-ip*)
    (format t "  GW:  ~/ip4:pprint-ip4/~%" muerte.ip4::*ip4-router*)
    device))

(defun e1000-arp-respond (packet device)
  "Check if PACKET is an ARP request for our IP and respond if so.
   Returns T if we responded, NIL otherwise."
  (let ((pkt-len (if (arrayp packet) (length packet) 0)))
    ;; Need at least 42 bytes for ARP: 14 eth + 28 arp
    (when (< pkt-len 42)
      (return-from e1000-arp-respond nil))
    ;; Check EtherType = ARP (0x0806)
    (unless (and (= (aref packet 12) #x08)
                 (= (aref packet 13) #x06))
      (return-from e1000-arp-respond nil))
    ;; Check ARP operation = request (1)
    (unless (and (= (aref packet 20) #x00)
                 (= (aref packet 21) #x01))
      (return-from e1000-arp-respond nil))
    ;; Check target IP matches our IP (bytes 38-41)
    (let ((our-ip muerte.ip4::*ip4-ip*))
      (unless (and our-ip
                   (= (aref packet 38) (aref our-ip 0))
                   (= (aref packet 39) (aref our-ip 1))
                   (= (aref packet 40) (aref our-ip 2))
                   (= (aref packet 41) (aref our-ip 3)))
        (return-from e1000-arp-respond nil))
      ;; Build ARP reply
      (let ((reply (make-array 60 :element-type '(unsigned-byte 8)
                                  :initial-element 0))
            (our-mac (mac-address device)))
        ;; Ethernet header - dest = sender's MAC (from ARP packet bytes 22-27)
        (setf (aref reply 0) (aref packet 22)
              (aref reply 1) (aref packet 23)
              (aref reply 2) (aref packet 24)
              (aref reply 3) (aref packet 25)
              (aref reply 4) (aref packet 26)
              (aref reply 5) (aref packet 27))
        ;; Ethernet header - source = our MAC
        (setf (aref reply 6) (aref our-mac 0)
              (aref reply 7) (aref our-mac 1)
              (aref reply 8) (aref our-mac 2)
              (aref reply 9) (aref our-mac 3)
              (aref reply 10) (aref our-mac 4)
              (aref reply 11) (aref our-mac 5))
        ;; EtherType = ARP
        (setf (aref reply 12) #x08 (aref reply 13) #x06)
        ;; ARP hardware type = Ethernet (1)
        (setf (aref reply 14) #x00 (aref reply 15) #x01)
        ;; ARP protocol type = IPv4 (0x0800)
        (setf (aref reply 16) #x08 (aref reply 17) #x00)
        ;; Hardware size = 6, Protocol size = 4
        (setf (aref reply 18) 6 (aref reply 19) 4)
        ;; ARP operation = reply (2)
        (setf (aref reply 20) #x00 (aref reply 21) #x02)
        ;; Sender MAC = our MAC
        (setf (aref reply 22) (aref our-mac 0)
              (aref reply 23) (aref our-mac 1)
              (aref reply 24) (aref our-mac 2)
              (aref reply 25) (aref our-mac 3)
              (aref reply 26) (aref our-mac 4)
              (aref reply 27) (aref our-mac 5))
        ;; Sender IP = our IP
        (setf (aref reply 28) (aref our-ip 0)
              (aref reply 29) (aref our-ip 1)
              (aref reply 30) (aref our-ip 2)
              (aref reply 31) (aref our-ip 3))
        ;; Target MAC = original sender's MAC (bytes 22-27)
        (setf (aref reply 32) (aref packet 22)
              (aref reply 33) (aref packet 23)
              (aref reply 34) (aref packet 24)
              (aref reply 35) (aref packet 25)
              (aref reply 36) (aref packet 26)
              (aref reply 37) (aref packet 27))
        ;; Target IP = original sender's IP (bytes 28-31)
        (setf (aref reply 38) (aref packet 28)
              (aref reply 39) (aref packet 29)
              (aref reply 40) (aref packet 30)
              (aref reply 41) (aref packet 31))
        ;; Send the reply
        (transmit device reply :end 60)
        (when *e1000-verbose*
          (format t "~&ARP: replied to ~D.~D.~D.~D~%"
                  (aref packet 28) (aref packet 29)
                  (aref packet 30) (aref packet 31)))
        t))))

(defun e1000-ip-loop ()
  "Run the IP stack receive loop. Press any key to exit."
  (let* ((device (or muerte.ip4::*ip4-nic* (e1000-ip-init)))
         (stack (make-instance 'muerte.ip4::ip4-stack
                  :interface device
                  :address muerte.ip4::*ip4-ip*)))
    (format t "~&IP stack running. Press any key to stop.~%")
    (loop
      (when (muerte.x86-pc.keyboard:poll-char)
        (return))
      (when (packet-available-p device)
        (let ((packet (receive device)))
          (when packet
            (case (ether-type packet)
              (#.+ether-type-arp+
               (muerte.ip4::arp-input stack packet 14))
              (#.+ether-type-ip4+
               (muerte.ip4::ip-input stack packet 14)))))))))

;;; ============================================================
;;; Stack Integration Test
;;; ============================================================

(defun e1000-stack-test (&optional (target-ip #(10 0 2 2)))
  "Test integration with the Movitz IP stack.
   Uses the existing stack's polling-arp to resolve gateway MAC."
  ;; Initialize if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (format t "~&Stack test: NIC=~A IP=~/ip4:pprint-ip4/~%"
          (type-of muerte.ip4::*ip4-nic*)
          muerte.ip4::*ip4-ip*)
  ;; Test ARP using stack's polling-arp
  (format t "~&Resolving ~/ip4:pprint-ip4/ via stack's polling-arp...~%"
          (muerte.ip4:ip4-address target-ip))
  (let ((mac (muerte.ip4::polling-arp target-ip
                                       (let ((count 0))
                                         (lambda ()
                                           (incf count)
                                           (> count 100000))))))
    (if mac
        (format t "~&  Gateway MAC: ~/ethernet:pprint-mac/~%" mac)
        (format t "~&  ARP timeout~%"))
    mac))

(defun e1000-udp-send (dest-ip dest-port data &key (source-port 12345))
  "Send a UDP packet using the Movitz IP stack.
   DATA should be a vector of bytes."
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (let* ((device muerte.ip4::*ip4-nic*)
         (dest (muerte.ip4:ip4-address dest-ip))
         (data-len (length data))
         ;; Packet: 14 eth + 20 ip + 8 udp + data
         (packet-len (+ 14 20 8 data-len))
         (packet (make-array (max 60 packet-len)
                             :element-type '(unsigned-byte 8)
                             :fill-pointer packet-len)))
    ;; Get destination MAC (using gateway for routing if needed)
    (let ((dest-mac (or (e1000-resolve-next-hop-mac dest-ip muerte.ip4::*ip4-ip* device)
                        (progn (format t "~&ARP failed~%") (return-from e1000-udp-send nil)))))
      ;; Copy data into packet
      (replace packet data :start1 (+ 14 20 8))
      ;; Format UDP header (also formats IP header)
      (muerte.ip4:format-udp-header packet
                                     :destination dest
                                     :destination-port dest-port
                                     :source-port source-port
                                     :payload data-len)
      ;; Format ethernet header
      (muerte.ethernet:format-ethernet-packet packet
                                               (mac-address device)
                                               dest-mac
                                               muerte.ethernet:+ether-type-ip4+)
      ;; Transmit
      (transmit device packet)
      (format t "~&UDP sent: ~D bytes to ~/ip4:pprint-ip4/:~D~%"
              data-len dest dest-port)
      t)))

(defun e1000-udp-receive (port &key (timeout 20) (device (car *e1000-devices*)))
  "Wait for a UDP packet on PORT. Returns (values data source-ip source-port length)
   or NIL on timeout. Uses interrupt-driven receive.
   TIMEOUT is number of wait cycles (each ~100ms with HLT)."
  (unless device
    (format t "~&No device~%")
    (return-from e1000-udp-receive nil))
  ;; Enable interrupts if not already
  (e1000-enable-interrupts device)
  (when *e1000-verbose*
    (format t "~&UDP: waiting on port ~D, timeout=~D cycles~%" port timeout))
  (let ((packet (make-array +max-ethernet-frame-size+
                            :element-type '(unsigned-byte 8)
                            :fill-pointer t))
        (tries 0)
        (pkts-seen 0))
    (tagbody
     wait-loop
       (when (>= tries timeout)
         (when *e1000-verbose*
           (format t "~&UDP: timeout after ~D tries, ~D packets seen~%" tries pkts-seen))
         (return-from e1000-udp-receive nil))
       ;; Wait for packet using interrupt-driven approach (500ms timeout)
       (unless (e1000-wait-for-packet device 500)
         (setf tries (the fixnum (1+ tries)))
         (go wait-loop))
       ;; Got a packet - check if it's UDP for our port
       (receive device packet 0)
       (incf pkts-seen)
       (let ((pkt-len (fill-pointer packet)))
         (when *e1000-verbose*
           (format t "~&UDP: pkt ~D, len=~D, eth=~2,'0X~2,'0X~%"
                   pkts-seen pkt-len (aref packet 12) (aref packet 13)))
         ;; Handle ARP requests (respond and continue waiting)
         (when (and (>= pkt-len 42)
                    (= (aref packet 12) #x08)
                    (= (aref packet 13) #x06))
           (e1000-arp-respond packet device)
           (go wait-loop))
         ;; Need at least: 14 eth + 20 ip + 8 udp = 42 bytes
         (unless (>= pkt-len 42)
           (go wait-loop))
         ;; Check EtherType = IP (0x0800)
         (unless (and (= (aref packet 12) #x08)
                      (= (aref packet 13) #x00))
           (go wait-loop))
         ;; Check IP protocol = UDP (17)
         (unless (= (aref packet 23) 17)
           (when *e1000-verbose*
             (format t "~&UDP: not UDP, proto=~D~%" (aref packet 23)))
           (go wait-loop))
         ;; Check destination port
         (let ((dst-port (logior (ash (aref packet 36) 8)
                                 (aref packet 37))))
           (when *e1000-verbose*
             (format t "~&UDP: dst-port=~D (want ~D)~%" dst-port port))
           (unless (= dst-port port)
             (go wait-loop))
           ;; Got a UDP packet for our port!
           ;; Extract source IP (bytes 26-29)
           (let* ((src-ip (make-array 4 :element-type '(unsigned-byte 8)))
                  (src-port (logior (ash (aref packet 34) 8)
                                    (aref packet 35)))
                  ;; UDP length includes header (8 bytes)
                  (udp-len (logior (ash (aref packet 38) 8)
                                   (aref packet 39)))
                  (data-len (- udp-len 8))
                  ;; Data starts at offset 42 (14 + 20 + 8)
                  (data (make-array data-len :element-type '(unsigned-byte 8))))
             ;; Copy source IP
             (setf (aref src-ip 0) (aref packet 26)
                   (aref src-ip 1) (aref packet 27)
                   (aref src-ip 2) (aref packet 28)
                   (aref src-ip 3) (aref packet 29))
             ;; Copy data
             (replace data packet :start2 42 :end2 (+ 42 data-len))
             (return-from e1000-udp-receive
               (values data src-ip src-port data-len))))))))

(defun e1000-udp-echo-server (&key (port 7) (count 10) (device (car *e1000-devices*)))
  "Simple UDP echo server. Listens on PORT and echoes back received data.
   Runs for COUNT packets then exits. Port 7 is the standard echo port."
  (unless device
    (e1000-probe)
    (setf device (car *e1000-devices*)))
  (unless device
    (format t "~&No device~%")
    (return-from e1000-udp-echo-server nil))
  ;; Initialize IP stack
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (format t "~&UDP echo server listening on port ~D...~%" port)
  (format t "~&Our IP: ~/ip4:pprint-ip4/~%" muerte.ip4::*ip4-ip*)
  (let ((received 0))
    (tagbody
     server-loop
       (when (>= received count)
         (go server-done))
       (multiple-value-bind (data src-ip src-port data-len)
           (e1000-udp-receive port :timeout 50000 :device device)
         (unless data
           (format t "~&Timeout waiting for packet~%")
           (go server-loop))
         (incf received)
         (format t "~&[~D] Received ~D bytes from ~/ip4:pprint-ip4/:~D~%"
                 received data-len (muerte.ip4:ip4-address src-ip) src-port)
         ;; Echo back
         (e1000-udp-send src-ip src-port data :source-port port)
         (go server-loop))
     server-done)
    (format t "~&Echo server done, handled ~D packets~%" received)
    received))

;;; ============================================================
;;; ICMP Ping
;;; ============================================================

;; Gateway MAC cache for QEMU user-mode networking
(defvar *e1000-gateway-mac* nil
  "Cached MAC address of the gateway (10.0.2.2).")

(defvar *e1000-gateway-ip* #(10 0 2 2)
  "QEMU user-mode networking gateway IP.")

(defun e1000-is-gateway-p (ip)
  "Check if IP is the gateway address."
  (let ((addr (muerte.ip4:ip4-address ip)))
    (and (= (aref addr 0) 10)
         (= (aref addr 1) 0)
         (= (aref addr 2) 2)
         (= (aref addr 3) 2))))

(defun e1000-resolve-next-hop-mac (target-ip my-ip device)
  "Resolve the MAC address for the next hop to reach TARGET-IP.
   In QEMU user-mode networking, only the gateway (10.0.2.2) responds to ARP.
   All other traffic must be sent to the gateway's MAC address."
  ;; In QEMU user-mode networking, ALL traffic goes through the gateway
  ;; Use cached gateway MAC or resolve it once
  (unless (e1000-is-gateway-p target-ip)
    (when *e1000-verbose*
      (format t "~&Routing via gateway for ~/ip4:pprint-ip4/~%"
              (muerte.ip4:ip4-address target-ip))))
  (or *e1000-gateway-mac*
      (setf *e1000-gateway-mac*
            (e1000-arp-resolve *e1000-gateway-ip* my-ip device))))

(defun e1000-arp-resolve (target-ip my-ip device)
  "Resolve TARGET-IP to MAC address using ARP. Returns MAC or nil on timeout.
   Uses interrupt-driven receive with e1000-wait-for-packet like the working ICMP test."
  (when *e1000-verbose*
    (format t "~&ARP: resolving ~/ip4:pprint-ip4/~%" (muerte.ip4:ip4-address target-ip)))
  ;; Enable interrupts for HLT-based waiting
  (e1000-enable-interrupts device)
  (let* ((target (muerte.ip4:ip4-address target-ip))
         (source (muerte.ip4:ip4-address my-ip))
         (mac (mac-address device)))
    ;; Use packet pool for GC-free operation
    (with-packet (arp-pkt)
      ;; Build ARP request
      ;; Ethernet: broadcast dest
      (setf (aref arp-pkt 0) #xff (aref arp-pkt 1) #xff (aref arp-pkt 2) #xff
            (aref arp-pkt 3) #xff (aref arp-pkt 4) #xff (aref arp-pkt 5) #xff)
      ;; Source MAC
      (setf (aref arp-pkt 6) (aref mac 0) (aref arp-pkt 7) (aref mac 1)
            (aref arp-pkt 8) (aref mac 2) (aref arp-pkt 9) (aref mac 3)
            (aref arp-pkt 10) (aref mac 4) (aref arp-pkt 11) (aref mac 5))
      ;; EtherType: ARP
      (setf (aref arp-pkt 12) #x08 (aref arp-pkt 13) #x06)
      ;; ARP header
      (setf (aref arp-pkt 14) 0 (aref arp-pkt 15) 1)    ; Hardware: Ethernet
      (setf (aref arp-pkt 16) #x08 (aref arp-pkt 17) 0)  ; Protocol: IPv4
      (setf (aref arp-pkt 18) 6 (aref arp-pkt 19) 4)     ; Sizes
      (setf (aref arp-pkt 20) 0 (aref arp-pkt 21) 1)     ; Op: Request
      ;; Sender MAC
      (setf (aref arp-pkt 22) (aref mac 0) (aref arp-pkt 23) (aref mac 1)
            (aref arp-pkt 24) (aref mac 2) (aref arp-pkt 25) (aref mac 3)
            (aref arp-pkt 26) (aref mac 4) (aref arp-pkt 27) (aref mac 5))
      ;; Sender IP
      (setf (aref arp-pkt 28) (aref source 0) (aref arp-pkt 29) (aref source 1)
            (aref arp-pkt 30) (aref source 2) (aref arp-pkt 31) (aref source 3))
      ;; Target MAC (zeros)
      (setf (aref arp-pkt 32) 0 (aref arp-pkt 33) 0 (aref arp-pkt 34) 0
            (aref arp-pkt 35) 0 (aref arp-pkt 36) 0 (aref arp-pkt 37) 0)
      ;; Target IP
      (setf (aref arp-pkt 38) (aref target 0) (aref arp-pkt 39) (aref target 1)
            (aref arp-pkt 40) (aref target 2) (aref arp-pkt 41) (aref target 3))
      (setf (fill-pointer arp-pkt) 60)
      (transmit device arp-pkt :end 60))
    ;; Wait for reply using interrupt-driven receive (like working ICMP test)
    (let ((result-mac (make-array 6 :element-type '(unsigned-byte 8)))
          (got-reply nil))
      (with-packet (reply-pkt)
        (let ((tries 0))
          (tagbody
           arp-loop
             (when (>= tries 10)
               (go arp-done))
             ;; Use e1000-wait-for-packet (500ms timeout)
             (when (e1000-wait-for-packet device 500)
               (receive device reply-pkt 0)
               ;; Check if it's an ARP packet
               (when (and (= (aref reply-pkt 12) #x08)
                          (= (aref reply-pkt 13) #x06))  ; ARP
                 ;; Handle incoming ARP request (respond to it)
                 (when (= (aref reply-pkt 21) 1)  ; Request
                   (e1000-arp-respond reply-pkt device))
                 ;; Check for ARP reply from our target
                 (when (= (aref reply-pkt 21) 2)  ; Reply
                   ;; Check if it's from our target
                   (when (and (= (aref reply-pkt 28) (aref target 0))
                              (= (aref reply-pkt 29) (aref target 1))
                              (= (aref reply-pkt 30) (aref target 2))
                              (= (aref reply-pkt 31) (aref target 3)))
                     ;; Copy MAC
                     (setf (aref result-mac 0) (aref reply-pkt 22)
                           (aref result-mac 1) (aref reply-pkt 23)
                           (aref result-mac 2) (aref reply-pkt 24)
                           (aref result-mac 3) (aref reply-pkt 25)
                           (aref result-mac 4) (aref reply-pkt 26)
                           (aref result-mac 5) (aref reply-pkt 27))
                     (setf got-reply t)
                     (go arp-done)))))
             (setf tries (the fixnum (1+ tries)))
             (go arp-loop)
           arp-done)))
      (if got-reply result-mac nil))))

(defun e1000-ping (target-ip &key (count 4) (my-ip #(10 0 2 15))
                                  (device (or (car *e1000-devices*) (e1000-probe))))
  "Send ICMP echo requests to TARGET-IP and wait for replies.
   Returns number of successful pings."
  (unless device
    (error "No e1000 device available"))
  (let* ((target (muerte.ip4:ip4-address target-ip))
         (source (muerte.ip4:ip4-address my-ip))
         (mac (mac-address device))
         (successes 0)
         (target-mac nil))
    ;; First, resolve MAC for the target (using gateway for routing if needed)
    (format t "~&Resolving ~/ip4:pprint-ip4/...~%" target)
    (setf target-mac (e1000-resolve-next-hop-mac target-ip my-ip device))
    (unless target-mac
      (format t "~&  MAC resolution failed~%")
      (return-from e1000-ping 0))
    (format t "~&  ~/ip4:pprint-ip4/ is at ~/ethernet:pprint-mac/~%" target target-mac)
    (format t "~&Pinging ~/ip4:pprint-ip4/...~%" target)

    (dotimes (seq count)
      ;; Build ICMP echo request packet
      ;; Ethernet (14) + IP (20) + ICMP (8+data)
      (let* ((data-len 32)
             (icmp-len (+ 8 data-len))
             (ip-len (+ 20 icmp-len))
             (total-len (+ 14 ip-len))
             (packet (make-array total-len :element-type '(unsigned-byte 8)
                                           :initial-element 0)))
        ;; Ethernet header - use resolved target MAC
        (dotimes (i 6) (setf (aref packet i) (aref target-mac i)))
        (dotimes (i 6) (setf (aref packet (+ 6 i)) (aref mac i)))
        (setf (aref packet 12) #x08 (aref packet 13) #x00)  ; IPv4

        ;; IP header (offset 14)
        (setf (aref packet 14) #x45)      ; Version 4, IHL 5
        (setf (aref packet 15) #x00)      ; TOS
        (setf (aref packet 16) (ash ip-len -8))  ; Total length high
        (setf (aref packet 17) (logand ip-len #xff))
        (setf (aref packet 18) 0 (aref packet 19) seq)  ; ID
        (setf (aref packet 20) #x40 (aref packet 21) 0)  ; Don't fragment
        (setf (aref packet 22) 64)        ; TTL
        (setf (aref packet 23) 1)         ; Protocol: ICMP
        (setf (aref packet 24) 0 (aref packet 25) 0)  ; Checksum (fill later)
        ;; Source IP
        (dotimes (i 4) (setf (aref packet (+ 26 i)) (aref source i)))
        ;; Destination IP
        (dotimes (i 4) (setf (aref packet (+ 30 i)) (aref target i)))
        ;; IP header checksum
        (let ((sum 0))
          (loop for i from 14 below 34 by 2
                do (incf sum (logior (ash (aref packet i) 8)
                                     (aref packet (1+ i)))))
          (setf sum (+ (logand sum #xffff) (ash sum -16)))
          (setf sum (logxor sum #xffff))
          (setf (aref packet 24) (ash sum -8)
                (aref packet 25) (logand sum #xff)))

        ;; ICMP header (offset 34)
        (setf (aref packet 34) 8)         ; Type: Echo request
        (setf (aref packet 35) 0)         ; Code
        (setf (aref packet 36) 0 (aref packet 37) 0)  ; Checksum (fill later)
        (setf (aref packet 38) 0 (aref packet 39) 1)  ; Identifier
        (setf (aref packet 40) (ash seq -8) (aref packet 41) (logand seq #xff))  ; Sequence
        ;; Fill data with pattern
        (loop for i from 0 below data-len
              do (setf (aref packet (+ 42 i)) (logand i #xff)))
        ;; ICMP checksum
        (let ((sum 0))
          (loop for i from 34 below total-len by 2
                do (incf sum (logior (ash (aref packet i) 8)
                                     (if (< (1+ i) total-len)
                                         (aref packet (1+ i))
                                         0))))
          (setf sum (+ (logand sum #xffff) (ash sum -16)))
          (setf sum (logxor sum #xffff))
          (setf (aref packet 36) (ash sum -8)
                (aref packet 37) (logand sum #xff)))

        ;; Transmit
        (transmit device packet :end total-len)

        ;; Wait for reply using interrupt-driven receive
        (let ((got-reply nil)
              (tries 0))
          (tagbody
           ping-wait
             (when (>= tries 10)
               (format t "~&  Request timed out seq=~D~%" seq)
               (go ping-done))
             (when (e1000-wait-for-packet device 500)
               (let ((reply (receive device)))
                 (when (and reply
                            (= (aref reply 12) #x08)   ; IPv4
                            (= (aref reply 13) #x00)
                            (= (aref reply 23) 1)      ; ICMP
                            (= (aref reply 34) 0))     ; Echo reply
                   (format t "~&  Reply from ~/ip4:pprint-ip4/ seq=~D~%"
                           (subseq reply 26 30) seq)
                   (incf successes)
                   (setf got-reply t)
                   (go ping-done))))
             (setf tries (the fixnum (1+ tries)))
             (go ping-wait)
           ping-done))))

    (format t "~&Ping complete: ~D/~D successful~%" successes count)
    successes))

;;; ============================================================
;;; Network testing
;;; ============================================================

(defun e1000-link-up-p (device)
  "Check if the link is up (status register bit 1)"
  (logbitp 1 (e1000-read-reg device +e1000-status+)))

(defun e1000-debug (device)
  "Print debug info about device state"
  (format t "~&E1000 Status:~%")
  (format t "  Link: ~A~%" (if (e1000-link-up-p device) "UP" "DOWN"))
  (format t "  TX: head=~D tail=~D  RX: head=~D tail=~D~%"
          (e1000-read-reg device +e1000-tdh+)
          (e1000-read-reg device +e1000-tdt+)
          (e1000-read-reg device +e1000-rdh+)
          (e1000-read-reg device +e1000-rdt+)))

(defun e1000-rx-debug (device)
  "Print detailed RX ring state for debugging"
  (let ((ring-phys (rx-ring-phys device))
        (cur (rx-cur device))
        (mmio (mmio-base device)))
    (format t "~&RX Ring: phys=#x~8,'0X cur=~D~%" ring-phys cur)
    (format t "~&RCTL=#x~8,'0X RDBAL=#x~8,'0X RDLEN=~D~%"
            (e1000-read-reg device +e1000-rctl+)
            (e1000-read-reg device +e1000-rdbal+)
            (e1000-read-reg device +e1000-rdlen+))
    ;; Check RAH0 AV bit
    (let ((rah0-hi (memref-int (+ mmio +e1000-rah0+) :offset 2
                               :type :unsigned-byte16 :physicalp t)))
      (format t "~&RAH0 hi=#x~4,'0X (AV=~D)~%" rah0-hi (if (logbitp 15 rah0-hi) 1 0)))
    ;; Show ICR (interrupt cause) and error counts
    (format t "~&ICR=#x~8,'0X STATUS=#x~8,'0X~%"
            (e1000-read-reg device +e1000-icr+)
            (e1000-read-reg device +e1000-status+))
    ;; Check if receiver is actually enabled (RCTL.EN = bit 1)
    (let ((rctl (e1000-read-reg device +e1000-rctl+)))
      (format t "~&RCTL.EN=~D RCTL.UPE=~D RCTL.MPE=~D~%"
              (if (logbitp 1 rctl) 1 0)
              (if (logbitp 3 rctl) 1 0)
              (if (logbitp 4 rctl) 1 0)))
    ;; Show RX statistics
    (format t "~&GPRC=~D MPC=~D CRCERRS=~D RXERRC=~D~%"
            (e1000-read-reg device +e1000-gprc+)
            (e1000-read-reg device +e1000-mpc+)
            (e1000-read-reg device +e1000-crcerrs+)
            (e1000-read-reg device +e1000-rxerrc+))
    ;; Show first few descriptors
    (dotimes (i 4)
      (let* ((desc-addr (+ ring-phys (* i 16)))
             (buf-lo (memref-int desc-addr :physicalp t))
             (buf-hi (memref-int desc-addr :offset 4 :physicalp t))
             (len (memref-int desc-addr :offset 8 :type :unsigned-byte16 :physicalp t))
             (status (memref-int desc-addr :offset 12 :type :unsigned-byte8 :physicalp t)))
        (format t "  [~D] buf=#x~8,'0X len=~D status=#x~2,'0X DD=~D~%"
                i buf-lo len status (logand status 1))))))

;;; ============================================================
;;; GC-free ICMP test using packet pool and interrupts
;;; ============================================================

(defun e1000-icmp-test (&optional (target-ip #(10 0 2 2))
                                            (my-ip #(10 0 2 15))
                                            (device (or (car *e1000-devices*) (e1000-probe))))
  "ICMP echo test using interrupt-driven receive.
   Uses HLT to sleep between packets instead of busy-polling."
  (unless device
    (format t "~&No device~%")
    (return-from e1000-icmp-test nil))

  ;; Enable interrupts
  (e1000-enable-interrupts device)
  (let ((int-count-before (interrupt-count device)))

    ;; Initialize the packet pool
    (init-packet-pool)

    (let ((mac (mac-address device))
          (target-mac nil)
          (success nil))

      ;; Phase 1: ARP resolution using interrupt-driven receive
      (with-packet (arp-pkt)
        ;; Build ARP request (same as e1000-icmp-test)
        (setf (aref arp-pkt 0) #xff (aref arp-pkt 1) #xff (aref arp-pkt 2) #xff
              (aref arp-pkt 3) #xff (aref arp-pkt 4) #xff (aref arp-pkt 5) #xff)
        (setf (aref arp-pkt 6) (aref mac 0) (aref arp-pkt 7) (aref mac 1)
              (aref arp-pkt 8) (aref mac 2) (aref arp-pkt 9) (aref mac 3)
              (aref arp-pkt 10) (aref mac 4) (aref arp-pkt 11) (aref mac 5))
        (setf (aref arp-pkt 12) #x08 (aref arp-pkt 13) #x06)
        (setf (aref arp-pkt 14) 0 (aref arp-pkt 15) 1)
        (setf (aref arp-pkt 16) #x08 (aref arp-pkt 17) 0)
        (setf (aref arp-pkt 18) 6 (aref arp-pkt 19) 4)
        (setf (aref arp-pkt 20) 0 (aref arp-pkt 21) 1)
        (setf (aref arp-pkt 22) (aref mac 0) (aref arp-pkt 23) (aref mac 1)
              (aref arp-pkt 24) (aref mac 2) (aref arp-pkt 25) (aref mac 3)
              (aref arp-pkt 26) (aref mac 4) (aref arp-pkt 27) (aref mac 5))
        (setf (aref arp-pkt 28) (aref my-ip 0) (aref arp-pkt 29) (aref my-ip 1)
              (aref arp-pkt 30) (aref my-ip 2) (aref arp-pkt 31) (aref my-ip 3))
        (setf (aref arp-pkt 32) 0 (aref arp-pkt 33) 0 (aref arp-pkt 34) 0
              (aref arp-pkt 35) 0 (aref arp-pkt 36) 0 (aref arp-pkt 37) 0)
        (setf (aref arp-pkt 38) (aref target-ip 0) (aref arp-pkt 39) (aref target-ip 1)
              (aref arp-pkt 40) (aref target-ip 2) (aref arp-pkt 41) (aref target-ip 3))
        (setf (fill-pointer arp-pkt) 60)
        (transmit device arp-pkt :end 60))

      ;; Wait for ARP reply using interrupts
      (setf target-mac (make-array 6 :element-type '(unsigned-byte 8)))
      (with-packet (reply-pkt)
        (let ((got-arp nil)
              (tries 0))
          ;; Try up to 10 interrupt cycles
          (tagbody
           arp-loop
             (when (>= tries 10)
               (go arp-done))
             ;; Wait for interrupt (HLT-based)
             (when (e1000-wait-for-packet device 500)
               (receive device reply-pkt 0)
               (when (and (= (aref reply-pkt 12) #x08)
                          (= (aref reply-pkt 13) #x06)
                          (= (aref reply-pkt 21) 2))
                 (setf (aref target-mac 0) (aref reply-pkt 22)
                       (aref target-mac 1) (aref reply-pkt 23)
                       (aref target-mac 2) (aref reply-pkt 24)
                       (aref target-mac 3) (aref reply-pkt 25)
                       (aref target-mac 4) (aref reply-pkt 26)
                       (aref target-mac 5) (aref reply-pkt 27))
                 (format t "~&MAC: ~2,'0X:~2,'0X:~2,'0X:~2,'0X:~2,'0X:~2,'0X~%"
                         (aref target-mac 0) (aref target-mac 1) (aref target-mac 2)
                         (aref target-mac 3) (aref target-mac 4) (aref target-mac 5))
                 (setf got-arp t)
                 (go arp-done)))
             (setf tries (the fixnum (1+ tries)))
             (go arp-loop)
           arp-done)
          (unless got-arp
            (format t "~&ARP timeout~%")
            (return-from e1000-icmp-test nil))))

      ;; Phase 2: Send ICMP
      (let ((icmp-pkt (get-packet)))
        (setf (aref icmp-pkt 0) (aref target-mac 0)
              (aref icmp-pkt 1) (aref target-mac 1)
              (aref icmp-pkt 2) (aref target-mac 2)
              (aref icmp-pkt 3) (aref target-mac 3)
              (aref icmp-pkt 4) (aref target-mac 4)
              (aref icmp-pkt 5) (aref target-mac 5))
        (setf (aref icmp-pkt 6) (aref mac 0)
              (aref icmp-pkt 7) (aref mac 1)
              (aref icmp-pkt 8) (aref mac 2)
              (aref icmp-pkt 9) (aref mac 3)
              (aref icmp-pkt 10) (aref mac 4)
              (aref icmp-pkt 11) (aref mac 5))
        (setf (aref icmp-pkt 12) #x08 (aref icmp-pkt 13) #x00)
        ;; IP header with correct checksum
        (setf (aref icmp-pkt 14) #x45 (aref icmp-pkt 15) #x00
              (aref icmp-pkt 16) #x00 (aref icmp-pkt 17) #x3c
              (aref icmp-pkt 18) #x00 (aref icmp-pkt 19) #x01
              (aref icmp-pkt 20) #x40 (aref icmp-pkt 21) #x00
              (aref icmp-pkt 22) #x40 (aref icmp-pkt 23) #x01
              (aref icmp-pkt 24) #x22 (aref icmp-pkt 25) #xb0
              (aref icmp-pkt 26) #x0a (aref icmp-pkt 27) #x00
              (aref icmp-pkt 28) #x02 (aref icmp-pkt 29) #x0f
              (aref icmp-pkt 30) #x0a (aref icmp-pkt 31) #x00
              (aref icmp-pkt 32) #x02 (aref icmp-pkt 33) #x02)
        ;; ICMP header with correct checksum
        (setf (aref icmp-pkt 34) #x08 (aref icmp-pkt 35) #x00
              (aref icmp-pkt 36) #x06 (aref icmp-pkt 37) #xfd
              (aref icmp-pkt 38) #x00 (aref icmp-pkt 39) #x01
              (aref icmp-pkt 40) #x00 (aref icmp-pkt 41) #x01)
        ;; Data
        (setf (aref icmp-pkt 42) 0 (aref icmp-pkt 43) 1
              (aref icmp-pkt 44) 2 (aref icmp-pkt 45) 3
              (aref icmp-pkt 46) 4 (aref icmp-pkt 47) 5
              (aref icmp-pkt 48) 6 (aref icmp-pkt 49) 7
              (aref icmp-pkt 50) 8 (aref icmp-pkt 51) 9
              (aref icmp-pkt 52) 10 (aref icmp-pkt 53) 11
              (aref icmp-pkt 54) 12 (aref icmp-pkt 55) 13
              (aref icmp-pkt 56) 14 (aref icmp-pkt 57) 15
              (aref icmp-pkt 58) 16 (aref icmp-pkt 59) 17
              (aref icmp-pkt 60) 18 (aref icmp-pkt 61) 19
              (aref icmp-pkt 62) 20 (aref icmp-pkt 63) 21
              (aref icmp-pkt 64) 22 (aref icmp-pkt 65) 23
              (aref icmp-pkt 66) 24 (aref icmp-pkt 67) 25
              (aref icmp-pkt 68) 26 (aref icmp-pkt 69) 27
              (aref icmp-pkt 70) 28 (aref icmp-pkt 71) 29
              (aref icmp-pkt 72) 30 (aref icmp-pkt 73) 31)
        (transmit device icmp-pkt :end 74)
        (free-packet icmp-pkt))

      ;; Phase 3: Wait for ICMP reply using interrupts
      (with-packet (reply-pkt)
        (let ((tries 0))
          (tagbody
           icmp-loop
             (when (>= tries 10)
               (go icmp-done))
             (when (e1000-wait-for-packet device 500)
               (receive device reply-pkt 0)
               (when (and (= (aref reply-pkt 12) #x08)
                          (= (aref reply-pkt 13) #x00)
                          (= (aref reply-pkt 23) 1)
                          (= (aref reply-pkt 34) 0))
                 (format t "~&ICMP reply OK!~%")
                 (setf success t)
                 (go icmp-done)))
             (setf tries (the fixnum (1+ tries)))
             (go icmp-loop)
           icmp-done)))

      (unless success
        (format t "~&ICMP timeout~%"))

      ;; Show interrupt stats
      (let ((int-count-after (interrupt-count device)))
        (format t "~&Interrupts: ~D (was ~D)~%"
                int-count-after int-count-before))

      success)))

;;; ============================================================
;;; DHCP Test
;;; ============================================================

(defun compute-ip-checksum (pkt start len)
  "Compute IP header checksum for LEN bytes starting at START."
  (let ((sum 0)
        (end (+ start len)))
    (loop for i from start below end by 2
          do (incf sum (logior (ash (aref pkt i) 8)
                               (if (< (1+ i) end)
                                   (aref pkt (1+ i))
                                   0))))
    ;; Fold carry bits
    (setf sum (+ (logand sum #xffff) (ash sum -16)))
    (setf sum (+ (logand sum #xffff) (ash sum -16)))
    ;; One's complement
    (logxor sum #xffff)))

(defun make-dhcp-discover-packet (nic xid)
  "Build a DHCP DISCOVER packet with proper message-type option."
  (let* ((mac (mac-address nic))
         ;; 14 eth + 20 ip + 8 udp + 236 dhcp base + 64 options max = ~342
         (pkt (make-array 400 :element-type '(unsigned-byte 8)
                          :fill-pointer 0 :initial-element 0)))
    ;; Ethernet header (14 bytes)
    ;; Destination: broadcast
    (dotimes (i 6) (vector-push #xff pkt))
    ;; Source: our MAC
    (dotimes (i 6) (vector-push (aref mac i) pkt))
    ;; Type: IP (0x0800)
    (vector-push #x08 pkt) (vector-push #x00 pkt)
    ;; IP header (20 bytes) - starts at offset 14
    (vector-push #x45 pkt)  ; version=4, ihl=5
    (vector-push 0 pkt)     ; TOS
    (vector-push 0 pkt) (vector-push 0 pkt)  ; total length (fill later)
    (vector-push 0 pkt) (vector-push 0 pkt)  ; identification
    (vector-push #x40 pkt) (vector-push 0 pkt)  ; flags=DF, frag offset=0
    (vector-push 64 pkt)    ; TTL
    (vector-push 17 pkt)    ; protocol = UDP
    (vector-push 0 pkt) (vector-push 0 pkt)  ; checksum (fill later)
    ;; source IP: 0.0.0.0
    (dotimes (i 4) (vector-push 0 pkt))
    ;; dest IP: 255.255.255.255 (broadcast)
    (dotimes (i 4) (vector-push #xff pkt))
    ;; UDP header (8 bytes) - starts at offset 34
    (vector-push 0 pkt) (vector-push 68 pkt)  ; src port = 68 (DHCP client)
    (vector-push 0 pkt) (vector-push 67 pkt)  ; dst port = 67 (DHCP server)
    (vector-push 0 pkt) (vector-push 0 pkt)   ; length (fill later)
    (vector-push 0 pkt) (vector-push 0 pkt)   ; checksum (optional for UDP)
    ;; DHCP (BOOTP) - starts at offset 42
    (vector-push 1 pkt)    ; op = BOOTREQUEST
    (vector-push 1 pkt)    ; htype = Ethernet
    (vector-push 6 pkt)    ; hlen = 6
    (vector-push 0 pkt)    ; hops = 0
    ;; XID (4 bytes)
    (vector-push (ldb (byte 8 24) xid) pkt)
    (vector-push (ldb (byte 8 16) xid) pkt)
    (vector-push (ldb (byte 8 8) xid) pkt)
    (vector-push (ldb (byte 8 0) xid) pkt)
    ;; secs (2 bytes)
    (vector-push 0 pkt) (vector-push 0 pkt)
    ;; flags (2 bytes) - broadcast flag
    (vector-push #x80 pkt) (vector-push 0 pkt)
    ;; ciaddr (4 bytes) - 0
    (dotimes (i 4) (vector-push 0 pkt))
    ;; yiaddr (4 bytes) - 0
    (dotimes (i 4) (vector-push 0 pkt))
    ;; siaddr (4 bytes) - 0
    (dotimes (i 4) (vector-push 0 pkt))
    ;; giaddr (4 bytes) - 0
    (dotimes (i 4) (vector-push 0 pkt))
    ;; chaddr (16 bytes) - client MAC + padding
    (dotimes (i 6) (vector-push (aref mac i) pkt))
    (dotimes (i 10) (vector-push 0 pkt))
    ;; sname (64 bytes) - all zeros
    (dotimes (i 64) (vector-push 0 pkt))
    ;; file (128 bytes) - all zeros
    (dotimes (i 128) (vector-push 0 pkt))
    ;; DHCP magic cookie (4 bytes)
    (vector-push #x63 pkt)
    (vector-push #x82 pkt)
    (vector-push #x53 pkt)
    (vector-push #x63 pkt)
    ;; DHCP options
    ;; Option 53: DHCP Message Type = 1 (DISCOVER)
    (vector-push 53 pkt)   ; option code
    (vector-push 1 pkt)    ; length
    (vector-push 1 pkt)    ; value: 1 = DHCPDISCOVER
    ;; Option 61: Client Identifier (MAC address)
    (vector-push 61 pkt)   ; option code
    (vector-push 7 pkt)    ; length: 1 + 6
    (vector-push 1 pkt)    ; hardware type: Ethernet
    (dotimes (i 6) (vector-push (aref mac i) pkt))
    ;; Option 55: Parameter Request List
    (vector-push 55 pkt)   ; option code
    (vector-push 4 pkt)    ; length
    (vector-push 1 pkt)    ; Subnet Mask
    (vector-push 3 pkt)    ; Router
    (vector-push 6 pkt)    ; DNS
    (vector-push 15 pkt)   ; Domain Name
    ;; Option 255: End
    (vector-push 255 pkt)
    ;; Pad to minimum size (300 bytes for BOOTP)
    (loop while (< (fill-pointer pkt) 300) do (vector-push 0 pkt))
    ;; Now fix up the lengths and checksums
    (let* ((total-len (fill-pointer pkt))
           (ip-len (- total-len 14))
           (udp-len (- total-len 34)))
      ;; IP total length at offset 16-17
      (setf (aref pkt 16) (ldb (byte 8 8) ip-len))
      (setf (aref pkt 17) (ldb (byte 8 0) ip-len))
      ;; UDP length at offset 38-39
      (setf (aref pkt 38) (ldb (byte 8 8) udp-len))
      (setf (aref pkt 39) (ldb (byte 8 0) udp-len))
      ;; IP header checksum at offset 24-25
      (let ((csum (compute-ip-checksum pkt 14 20)))
        (setf (aref pkt 24) (ldb (byte 8 8) csum))
        (setf (aref pkt 25) (ldb (byte 8 0) csum))))
    pkt))

(defun e1000-dhcp-test ()
  "Test DHCP using the e1000 driver.
   First ensures the NIC is set up as *ip4-nic*, then calls dhcp-init."
  ;; Initialize NIC for IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (format t "~&DHCP test with e1000...~%")
  (format t "~&NIC: ~A~%" (type-of muerte.ip4::*ip4-nic*))
  ;; Check if sleep is functional
  (handler-case
      (progn
        (format t "~&Testing sleep...~%")
        (sleep 0)  ; Quick test
        (format t "~&sleep OK~%"))
    (error (c)
      (format t "~&Warning: sleep not functional: ~A~%" c)
      (format t "~&DHCP requires working sleep function.~%")
      (format t "~&If internal-time is not initialized, DHCP will fail.~%")
      (return-from e1000-dhcp-test nil)))
  ;; Clear any pending packets
  (let ((cleared 0))
    (loop while (packet-available-p (car *e1000-devices*))
          do (receive (car *e1000-devices*))
             (incf cleared))
    (when (> cleared 0)
      (format t "~&Cleared ~D pending packets~%" cleared)))
  ;; Try DHCP with verbose output
  (format t "~&Starting DHCP request...~%")
  (let ((result (e1000-dhcp-request-verbose)))
    (if result
        (progn
          (format t "~&DHCP complete!~%")
          (format t "~&IP: ~/ip4:pprint-ip4/~%" muerte.ip4::*ip4-ip*)
          (format t "~&Router: ~/ip4:pprint-ip4/~%" muerte.ip4::*ip4-router*)
          t)
        (progn
          (format t "~&DHCP failed~%")
          nil))))

(defun e1000-dhcp-request-verbose ()
  "Verbose DHCP request for debugging."
  (let* ((nic muerte.ip4::*ip4-nic*)
         (packet (make-array +max-ethernet-frame-size+
                             :element-type '(unsigned-byte 8)
                             :fill-pointer t))
         (xid (mod (get-internal-run-time) 10000))
         (attempt 0)
         (rx-count 0))
    (format t "~&DHCP: MAC=~/ethernet:pprint-mac/ XID=~D~%"
            (mac-address nic) xid)
    (tagbody
     dhcp-loop
       (when (>= attempt 5)
         (return-from e1000-dhcp-request-verbose nil))
       (incf attempt)
       (format t "~&DHCP attempt ~D: transmitting discover...~%" attempt)
       ;; Build DHCP discover manually since format-dhcp-request doesn't support message-type
       (let ((dhcp-pkt (make-dhcp-discover-packet nic xid)))
         (format t "~&  Packet length: ~D~%" (fill-pointer dhcp-pkt))
         (transmit nic dhcp-pkt))
       (format t "~&  Sleeping 500ms...~%")
       (sleep 1/2)
       ;; Check if any packets arrived
       (format t "~&  Packets pending: ~A~%" (packet-available-p (car *e1000-devices*)))
       ;; Check for packets
       (setf rx-count 0)
       (format t "~&  Checking for replies...~%")
     rx-loop
       (unless (receive nic packet)
         (go rx-done))
       (incf rx-count)
       (format t "~&  RX ~D: len=~D~%" rx-count (fill-pointer packet))
       ;; Check ether type
       (unless (and (>= (fill-pointer packet) 14)
                    (= (aref packet 12) #x08)
                    (= (aref packet 13) #x00))
         (go rx-loop))
       ;; Check IP protocol = UDP
       (unless (and (>= (fill-pointer packet) 24)
                    (= (aref packet 23) 17))
         (go rx-loop))
       (format t "~&    UDP packet~%")
       ;; Check dst port = 68 (DHCP client)
       (unless (and (>= (fill-pointer packet) 38)
                    (= (aref packet 36) 0)
                    (= (aref packet 37) 68))
         (go rx-loop))
       (format t "~&    DHCP response~%")
       ;; Check XID (offset 46 in packet = 14 eth + 20 ip + 8 udp + 4 = 46)
       (let ((rx-xid (logior (ash (aref packet 46) 24)
                             (ash (aref packet 47) 16)
                             (ash (aref packet 48) 8)
                             (aref packet 49))))
         (format t "~&    XID=~D (expected ~D)~%" rx-xid xid)
         (unless (= rx-xid xid)
           (go rx-loop))
         ;; Got DHCP reply - parse it
         ;; yiaddr is at offset 58 = 14 + 20 + 8 + 16
         (let ((yiaddr (muerte.ip4:ip4-address (subseq packet 58 62))))
           (format t "~&    DHCP offer: IP=~/ip4:pprint-ip4/~%" yiaddr)
           (setf muerte.ip4::*ip4-ip* yiaddr)
           ;; Parse options to find router (option 3)
           ;; Options start at offset 282 = 14 + 20 + 8 + 240 (after DHCP magic cookie)
           (let ((opt-start 282)
                 (opt-end (fill-pointer packet)))
             (tagbody
              opt-loop
                (when (>= opt-start opt-end)
                  (go opt-done))
                (let ((opt-code (aref packet opt-start)))
                  (when (= opt-code 255) ; End option
                    (go opt-done))
                  (when (= opt-code 0)   ; Pad option
                    (incf opt-start)
                    (go opt-loop))
                  (let ((opt-len (aref packet (1+ opt-start))))
                    (when (= opt-code 3) ; Router option
                      (when (>= opt-len 4)
                        (let ((router (muerte.ip4:ip4-address
                                       (subseq packet (+ opt-start 2) (+ opt-start 6)))))
                          (format t "~&    Router: ~/ip4:pprint-ip4/~%" router)
                          (setf muerte.ip4::*ip4-router* router))))
                    (setf opt-start (+ opt-start 2 opt-len))
                    (go opt-loop)))
              opt-done))
           (return-from e1000-dhcp-request-verbose packet)))
     rx-done
       (format t "~&  Received ~D packets total~%" rx-count)
       (go dhcp-loop))))

;;; ============================================================
;;; UDP Test
;;; ============================================================

(defun e1000-udp-test (&key (port 12345) (target-port 7))
  "Test UDP send/receive. Sends a UDP packet and waits for response.
   Uses interrupt-driven receive with HLT."
  (let* ((device (or (car *e1000-devices*) (e1000-probe)))
         (target #(10 0 2 2))  ; Gateway
         (my-ip #(10 0 2 15)))
    (unless device
      (format t "~&No device~%")
      (return-from e1000-udp-test nil))
    ;; Initialize packet pool and interrupts first (exactly like ICMP test)
    (e1000-enable-interrupts device)
    (init-packet-pool)
    ;; Initialize IP stack if needed
    (unless muerte.ip4::*ip4-nic*
      (e1000-ip-init))
    ;; Resolve gateway MAC using ARP
    (format t "~&UDP test: resolving gateway...~%")
    (let ((gw-mac (e1000-arp-resolve target my-ip device)))
      (unless gw-mac
        (format t "~&ARP failed~%")
        (return-from e1000-udp-test nil))
      (format t "~&Gateway MAC: ~/ethernet:pprint-mac/~%" gw-mac)
      ;; Build UDP packet: 14 eth + 20 ip + 8 udp + data
      (let* ((data #(72 69 76 76 79))  ; "HELLO"
             (data-len 5)
             (pkt-len (+ 14 20 8 data-len))
             (pkt (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
        ;; Ethernet header
        (dotimes (i 6) (setf (aref pkt i) (aref gw-mac i)))
        (dotimes (i 6) (setf (aref pkt (+ 6 i)) (aref (mac-address device) i)))
        (setf (aref pkt 12) #x08 (aref pkt 13) #x00)  ; IPv4
        ;; IP header
        (setf (aref pkt 14) #x45)  ; Version + IHL
        (setf (aref pkt 15) 0)     ; TOS
        (let ((ip-len (+ 20 8 data-len)))
          (setf (aref pkt 16) (ash ip-len -8)
                (aref pkt 17) (logand ip-len #xff)))
        (setf (aref pkt 18) 0 (aref pkt 19) 1)  ; ID
        (setf (aref pkt 20) #x40 (aref pkt 21) 0)  ; Flags + frag
        (setf (aref pkt 22) 64)   ; TTL
        (setf (aref pkt 23) 17)   ; Protocol = UDP
        (setf (aref pkt 24) 0 (aref pkt 25) 0)  ; Checksum (fill later)
        ;; Source IP
        (dotimes (i 4) (setf (aref pkt (+ 26 i)) (aref my-ip i)))
        ;; Dest IP
        (dotimes (i 4) (setf (aref pkt (+ 30 i)) (aref target i)))
        ;; IP checksum
        (let ((csum (compute-ip-checksum pkt 14 20)))
          (setf (aref pkt 24) (ash csum -8)
                (aref pkt 25) (logand csum #xff)))
        ;; UDP header (offset 34)
        (setf (aref pkt 34) (ash port -8)
              (aref pkt 35) (logand port #xff))
        (setf (aref pkt 36) (ash target-port -8)
              (aref pkt 37) (logand target-port #xff))
        (let ((udp-len (+ 8 data-len)))
          (setf (aref pkt 38) (ash udp-len -8)
                (aref pkt 39) (logand udp-len #xff)))
        (setf (aref pkt 40) 0 (aref pkt 41) 0)  ; UDP checksum (optional)
        ;; Data
        (dotimes (i data-len) (setf (aref pkt (+ 42 i)) (aref data i)))
        ;; Send
        (format t "~&Sending UDP to port ~D...~%" target-port)
        (transmit device pkt :end pkt-len)
        ;; Wait for response using interrupts
        (format t "~&Waiting for response...~%")
        (let ((reply (make-array +max-ethernet-frame-size+
                                 :element-type '(unsigned-byte 8)
                                 :fill-pointer t))
              (got-reply nil)
              (tries 0))
          (tagbody
           wait-loop
             (when (>= tries 10)
               (go wait-done))
             (when (e1000-wait-for-packet device 500)
               (receive device reply 0)
               (format t "~&Got packet: len=~D etype=#x~2,'0X~2,'0X~%"
                       (fill-pointer reply) (aref reply 12) (aref reply 13))
               (setf got-reply t)
               (go wait-done))
             (setf tries (the fixnum (1+ tries)))
             (go wait-loop)
           wait-done)
          (if got-reply
              (format t "~&Received response~%")
              (format t "~&Timeout - no response~%"))
          got-reply)))))

;;; ============================================================
;;; DNS Client
;;; ============================================================
;;; Uses UDP port 53 to query DNS servers.
;;; Default server: 10.0.2.3 (QEMU user-mode networking DNS)

(defun dns-encode-name (name)
  "Encode a domain name in DNS wire format.
   Example: 'www.google.com' -> #(3 119 119 119 6 103 111 111 103 108 101 3 99 111 109 0)
   Each label is prefixed with its length, terminated with null byte."
  (let* ((name-len (length name))
         ;; Worst case: each char is a label + length byte + terminator
         (result (make-array (+ name-len 2) :element-type '(unsigned-byte 8)
                                            :fill-pointer 0))
         (label-start 0))
    ;; Process each character looking for dots
    (loop for i from 0 to name-len
          do (when (or (= i name-len)
                       (char= (char name i) #\.))
               ;; Found end of label
               (let ((label-len (- i label-start)))
                 (when (> label-len 0)
                   ;; Push length byte
                   (vector-push label-len result)
                   ;; Push label characters
                   (loop for j from label-start below i
                         do (vector-push (char-code (char name j)) result))))
               (setf label-start (1+ i))))
    ;; Terminate with null byte
    (vector-push 0 result)
    result))

(defun dns-build-query (name &key (type 1) (id nil))
  "Build a complete DNS query message for NAME.
   TYPE 1 = A record (IPv4 address).
   Returns a byte array containing the complete query."
  (let* ((encoded-name (dns-encode-name name))
         (name-len (length encoded-name))
         ;; Header (12 bytes) + name + type (2) + class (2)
         (query-len (+ 12 name-len 4))
         (query (make-array query-len :element-type '(unsigned-byte 8)
                                      :initial-element 0))
         ;; Generate ID if not provided (use time-based value)
         (query-id (or id (logand (get-internal-run-time) #xffff))))
    ;; Header - bytes 0-1: Transaction ID
    (setf (aref query 0) (ash query-id -8)
          (aref query 1) (logand query-id #xff))
    ;; Header - bytes 2-3: Flags (RD=1, standard query)
    ;; 0x0100 = Recursion Desired
    (setf (aref query 2) #x01
          (aref query 3) #x00)
    ;; Header - bytes 4-5: QDCOUNT = 1
    (setf (aref query 4) #x00
          (aref query 5) #x01)
    ;; Header - bytes 6-7: ANCOUNT = 0
    ;; Header - bytes 8-9: NSCOUNT = 0
    ;; Header - bytes 10-11: ARCOUNT = 0
    ;; (already zero from initial-element)

    ;; Question section - encoded name
    (replace query encoded-name :start1 12)
    ;; QTYPE (2 bytes) - A record = 1
    (setf (aref query (+ 12 name-len)) (ash type -8)
          (aref query (+ 13 name-len)) (logand type #xff))
    ;; QCLASS (2 bytes) - IN (Internet) = 1
    (setf (aref query (+ 14 name-len)) #x00
          (aref query (+ 15 name-len)) #x01)
    query))

(defun dns-parse-response (data data-len)
  "Parse a DNS response and extract IPv4 addresses from A records.
   Returns a list of IP address vectors, or NIL on error."
  (when (< data-len 12)
    (when *e1000-verbose*
      (format t "~&DNS: Response too short (~D bytes)~%" data-len))
    (return-from dns-parse-response nil))
  ;; Check header
  ;; Byte 2 bit 7 (QR) should be 1 (response)
  (unless (logbitp 7 (aref data 2))
    (when *e1000-verbose*
      (format t "~&DNS: Not a response (QR=0)~%"))
    (return-from dns-parse-response nil))
  ;; Byte 3 bits 0-3 (RCODE) should be 0 (no error)
  (let ((rcode (logand (aref data 3) #x0f)))
    (unless (zerop rcode)
      (when *e1000-verbose*
        (format t "~&DNS: Error response (RCODE=~D)~%" rcode))
      (return-from dns-parse-response nil)))
  ;; Get answer count
  (let ((ancount (logior (ash (aref data 6) 8) (aref data 7))))
    (when (zerop ancount)
      (when *e1000-verbose*
        (format t "~&DNS: No answers in response~%"))
      (return-from dns-parse-response nil))
    ;; Skip question section to find answers
    ;; Question starts at byte 12
    (let ((offset 12)
          (addresses nil))
      ;; Skip QNAME - find null terminator or pointer
      (loop
        (when (>= offset data-len)
          (return-from dns-parse-response nil))
        (let ((label-len (aref data offset)))
          (cond
            ;; Null terminator - end of name
            ((zerop label-len)
             (incf offset)
             (return))
            ;; Compression pointer (starts with 11xxxxxx = 0xC0+)
            ((>= label-len #xc0)
             (incf offset 2)
             (return))
            ;; Regular label
            (t
             (incf offset (1+ label-len))))))
      ;; Skip QTYPE and QCLASS (4 bytes)
      (incf offset 4)
      ;; Parse answer records
      (dotimes (i ancount)
        (when (>= offset data-len)
          (return))
        ;; Skip NAME (may be pointer or label)
        (let ((name-byte (aref data offset)))
          (cond
            ;; Compression pointer
            ((>= name-byte #xc0)
             (incf offset 2))
            ;; Labels
            (t
             (loop
               (when (>= offset data-len)
                 (return-from dns-parse-response addresses))
               (let ((label-len (aref data offset)))
                 (cond
                   ((zerop label-len)
                    (incf offset)
                    (return))
                   ((>= label-len #xc0)
                    (incf offset 2)
                    (return))
                   (t
                    (incf offset (1+ label-len)))))))))
        ;; Read TYPE, CLASS, TTL, RDLENGTH
        (when (< (- data-len offset) 10)
          (return))
        (let* ((rtype (logior (ash (aref data offset) 8)
                              (aref data (+ offset 1))))
               (rclass (logior (ash (aref data (+ offset 2)) 8)
                               (aref data (+ offset 3))))
               ;; TTL is bytes 4-7 (we skip it)
               (rdlength (logior (ash (aref data (+ offset 8)) 8)
                                 (aref data (+ offset 9)))))
          (incf offset 10)
          ;; Check if this is an A record (type=1, class=1)
          (when (and (= rtype 1) (= rclass 1) (= rdlength 4))
            (when (<= (+ offset 4) data-len)
              (let ((ip (make-array 4 :element-type '(unsigned-byte 8))))
                (setf (aref ip 0) (aref data offset)
                      (aref ip 1) (aref data (+ offset 1))
                      (aref ip 2) (aref data (+ offset 2))
                      (aref ip 3) (aref data (+ offset 3)))
                (push ip addresses))))
          ;; Skip RDATA
          (incf offset rdlength)))
      ;; Return addresses in order received
      (nreverse addresses))))

(defun dns-resolve (name &key (server #(10 0 2 3)) (timeout 20) (source-port nil))
  "Resolve a domain name to an IPv4 address using DNS.
   SERVER defaults to QEMU's built-in DNS (10.0.2.3).
   Returns the first IPv4 address as a byte vector, or NIL on failure."
  ;; Generate a source port if not provided
  (let ((port (or source-port (+ 49152 (mod (get-internal-run-time) 16384)))))
    ;; Build query
    (let ((query (dns-build-query name)))
      (when *e1000-verbose*
        (format t "~&DNS: Resolving ~A via ~/ip4:pprint-ip4/~%"
                name (muerte.ip4:ip4-address server))
        (format t "~&DNS: Query length=~D, source-port=~D~%" (length query) port))
      ;; Send query
      (unless (e1000-udp-send server 53 query :source-port port)
        (when *e1000-verbose*
          (format t "~&DNS: Failed to send query~%"))
        (return-from dns-resolve nil))
      ;; Receive response
      (multiple-value-bind (data src-ip src-port data-len)
          (e1000-udp-receive port :timeout timeout)
        (unless data
          (when *e1000-verbose*
            (format t "~&DNS: Timeout waiting for response~%"))
          (return-from dns-resolve nil))
        (when *e1000-verbose*
          (format t "~&DNS: Got response from ~/ip4:pprint-ip4/:~D, ~D bytes~%"
                  (muerte.ip4:ip4-address src-ip) src-port data-len))
        ;; Parse response
        (let ((addresses (dns-parse-response data data-len)))
          (if addresses
              (car addresses)
              nil))))))

(defun dns-test (&optional (name "google.com"))
  "Test DNS resolution by looking up NAME.
   Prints the resolved IP address or an error message."
  ;; Initialize IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (format t "~&DNS test: resolving ~A...~%" name)
  (let ((ip (dns-resolve name)))
    (if ip
        (progn
          (format t "~&Resolved ~A to ~D.~D.~D.~D~%"
                  name (aref ip 0) (aref ip 1) (aref ip 2) (aref ip 3))
          ip)
        (progn
          (format t "~&Failed to resolve ~A~%" name)
          nil))))

;;; ============================================================
;;; NTP Client
;;; ============================================================
;;; Uses UDP port 123 to query NTP servers.
;;; NTP timestamps are 64-bit: upper 32 bits = seconds since 1900-01-01,
;;; lower 32 bits = fractional seconds.

;; NTP epoch is 1900-01-01, Unix epoch is 1970-01-01
;; Difference: 70 years + 17 leap days = 2208988800 seconds
(defconstant +ntp-unix-epoch-offset+ 2208988800)

(defun ntp-build-request ()
  "Build an NTP client request packet (48 bytes).
   Returns a byte array ready to send."
  (let ((packet (make-array 48 :element-type '(unsigned-byte 8)
                               :initial-element 0)))
    ;; Byte 0: LI=0, VN=4, Mode=3 (client)
    ;; LI (2 bits): 00 = no warning
    ;; VN (3 bits): 100 = version 4
    ;; Mode (3 bits): 011 = client
    ;; Combined: 00100011 = 0x23
    (setf (aref packet 0) #x23)
    ;; Rest of packet is zeros for a simple client request
    ;; The server will fill in the timestamps
    packet))

(defun ntp-parse-response (data data-len)
  "Parse an NTP response and extract the transmit timestamp.
   Returns (values unix-seconds fraction) or NIL on error.
   The transmit timestamp is when the server sent the response."
  (when (< data-len 48)
    (when *e1000-verbose*
      (format t "~&NTP: Response too short (~D bytes)~%" data-len))
    (return-from ntp-parse-response nil))
  ;; Check mode - should be 4 (server) or 5 (broadcast)
  (let ((mode (logand (aref data 0) #x07)))
    (unless (or (= mode 4) (= mode 5))
      (when *e1000-verbose*
        (format t "~&NTP: Unexpected mode ~D~%" mode))
      ;; Continue anyway - some servers may use different modes
      ))
  ;; Check stratum - 0 means kiss-of-death, 1-15 are valid
  (let ((stratum (aref data 1)))
    (when (zerop stratum)
      (when *e1000-verbose*
        (format t "~&NTP: Kiss-of-death packet (stratum=0)~%"))
      (return-from ntp-parse-response nil)))
  ;; Extract transmit timestamp (bytes 40-47)
  ;; Bytes 40-43: seconds since 1900-01-01 (big-endian)
  ;; Bytes 44-47: fraction (big-endian)
  (let ((ntp-seconds (logior (ash (aref data 40) 24)
                             (ash (aref data 41) 16)
                             (ash (aref data 42) 8)
                             (aref data 43)))
        (fraction (logior (ash (aref data 44) 24)
                          (ash (aref data 45) 16)
                          (ash (aref data 46) 8)
                          (aref data 47))))
    ;; Convert to Unix timestamp
    (let ((unix-seconds (- ntp-seconds +ntp-unix-epoch-offset+)))
      (values unix-seconds fraction))))

(defun ntp-get-time (&key (server nil) (server-name "pool.ntp.org") (timeout 20))
  "Get current time from an NTP server.
   SERVER: IP address as byte vector (e.g., #(216 239 35 0) for time.google.com)
   SERVER-NAME: DNS name to resolve if SERVER not provided (default: pool.ntp.org)
   Returns (values unix-seconds fraction) or NIL on failure."
  ;; Resolve server if not provided
  (let ((server-ip (or server
                       (progn
                         (when *e1000-verbose*
                           (format t "~&NTP: Resolving ~A...~%" server-name))
                         (dns-resolve server-name)))))
    (unless server-ip
      (format t "~&NTP: Failed to resolve server~%")
      (return-from ntp-get-time nil))
    (when *e1000-verbose*
      (format t "~&NTP: Querying ~D.~D.~D.~D...~%"
              (aref server-ip 0) (aref server-ip 1)
              (aref server-ip 2) (aref server-ip 3)))
    ;; Generate source port
    (let ((port (+ 49152 (mod (get-internal-run-time) 16384))))
      ;; Build and send request
      (let ((request (ntp-build-request)))
        (unless (e1000-udp-send server-ip 123 request :source-port port)
          (when *e1000-verbose*
            (format t "~&NTP: Failed to send request~%"))
          (return-from ntp-get-time nil))
        ;; Receive response
        (multiple-value-bind (data src-ip src-port data-len)
            (e1000-udp-receive port :timeout timeout)
          (unless data
            (when *e1000-verbose*
              (format t "~&NTP: Timeout waiting for response~%"))
            (return-from ntp-get-time nil))
          (when *e1000-verbose*
            (format t "~&NTP: Got response, ~D bytes~%" data-len))
          ;; Parse response
          (ntp-parse-response data data-len))))))

(defun ntp-unix-to-date (unix-seconds)
  "Convert Unix timestamp to (year month day hour minute second).
   Simple implementation - does not handle all edge cases."
  (let* ((seconds-per-minute 60)
         (seconds-per-hour 3600)
         (seconds-per-day 86400)
         ;; Days since 1970-01-01
         (days (floor unix-seconds seconds-per-day))
         (remaining (mod unix-seconds seconds-per-day))
         (hour (floor remaining seconds-per-hour))
         (remaining (mod remaining seconds-per-hour))
         (minute (floor remaining seconds-per-minute))
         (second (mod remaining seconds-per-minute))
         ;; Calculate year, month, day from days since epoch
         (year 1970)
         (month 1)
         (day 1))
    ;; Count years
    (loop
      (let ((days-in-year (if (and (zerop (mod year 4))
                                   (or (not (zerop (mod year 100)))
                                       (zerop (mod year 400))))
                              366 365)))
        (when (< days days-in-year)
          (return))
        (decf days days-in-year)
        (incf year)))
    ;; Count months
    (let ((leap (and (zerop (mod year 4))
                     (or (not (zerop (mod year 100)))
                         (zerop (mod year 400))))))
      (loop for m from 1 to 12
            for days-in-month in (if leap
                                     '(31 29 31 30 31 30 31 31 30 31 30 31)
                                     '(31 28 31 30 31 30 31 31 30 31 30 31))
            do (if (< days days-in-month)
                   (progn
                     (setf month m)
                     (setf day (1+ days))
                     (return))
                   (decf days days-in-month))))
    (values year month day hour minute second)))

(defun ntp-test (&optional (server-name "pool.ntp.org"))
  "Test NTP by querying a time server and displaying the result.
   Uses DNS to resolve SERVER-NAME (default: pool.ntp.org)."
  ;; Initialize IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (format t "~&NTP test: querying ~A...~%" server-name)
  (multiple-value-bind (unix-seconds fraction)
      (ntp-get-time :server-name server-name)
    (if unix-seconds
        (multiple-value-bind (year month day hour minute second)
            (ntp-unix-to-date unix-seconds)
          (format t "~&NTP time: ~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D UTC~%"
                  year month day hour minute second)
          (format t "~&Unix timestamp: ~D~%" unix-seconds)
          (values unix-seconds fraction))
        (progn
          (format t "~&Failed to get NTP time~%")
          nil))))

;;; ============================================================
;;; TCP Client
;;; ============================================================
;;; Implements a minimal TCP client for connection-oriented communication.
;;; Supports 3-way handshake, data transfer, and connection close.

;; TCP flags
(defconstant +tcp-flag-fin+ #x01)
(defconstant +tcp-flag-syn+ #x02)
(defconstant +tcp-flag-rst+ #x04)
(defconstant +tcp-flag-psh+ #x08)
(defconstant +tcp-flag-ack+ #x10)
(defconstant +tcp-flag-urg+ #x20)

;; TCP Maximum Segment Size
;; Total packet: 14 eth + 20 IP + 20 TCP + data = 54 + data
;; Standard Ethernet MSS is 1460, but we use 1400 for some headroom
(defconstant +tcp-mss+ 1400)

;; TCP connection states
(defconstant +tcp-state-closed+ 0)
(defconstant +tcp-state-syn-sent+ 1)
(defconstant +tcp-state-established+ 2)
(defconstant +tcp-state-fin-wait-1+ 3)
(defconstant +tcp-state-fin-wait-2+ 4)
(defconstant +tcp-state-close-wait+ 5)
(defconstant +tcp-state-time-wait+ 6)
(defconstant +tcp-state-listen+ 7)
(defconstant +tcp-state-syn-received+ 8)

;; TCP connection structure (simple property list for now)
(defvar *tcp-connections* nil
  "List of active TCP connections")

(defun make-tcp-connection (local-port remote-ip remote-port)
  "Create a new TCP connection structure."
  (list :state +tcp-state-closed+
        :local-port local-port
        :remote-ip (copy-seq remote-ip)
        :remote-port remote-port
        :send-seq (get-internal-run-time)  ; Initial sequence number
        :send-ack 0
        :recv-seq 0
        :recv-ack 0
        :recv-buffer nil                  ; Buffered data from tcp-send ACK wait
        :device (car *e1000-devices*)))

(defun tcp-conn-get (conn key)
  "Get a value from a TCP connection."
  (getf conn key))

(defun tcp-conn-set (conn key value)
  "Set a value in a TCP connection. Returns the modified connection."
  (setf (getf conn key) value)
  conn)

(defun tcp-compute-checksum (packet ip-start tcp-start tcp-len)
  "Compute TCP checksum including pseudo-header.
   Pseudo-header: source IP (4) + dest IP (4) + zero (1) + protocol (1) + TCP length (2)"
  (let ((sum 0))
    ;; Add pseudo-header components
    ;; Source IP (bytes 26-29 in packet = ip-start + 12)
    (incf sum (logior (ash (aref packet (+ ip-start 12)) 8)
                      (aref packet (+ ip-start 13))))
    (incf sum (logior (ash (aref packet (+ ip-start 14)) 8)
                      (aref packet (+ ip-start 15))))
    ;; Destination IP (bytes 30-33 in packet = ip-start + 16)
    (incf sum (logior (ash (aref packet (+ ip-start 16)) 8)
                      (aref packet (+ ip-start 17))))
    (incf sum (logior (ash (aref packet (+ ip-start 18)) 8)
                      (aref packet (+ ip-start 19))))
    ;; Protocol (6 = TCP)
    (incf sum 6)
    ;; TCP length
    (incf sum tcp-len)
    ;; Add TCP header and data (16-bit words)
    (loop for i from tcp-start below (+ tcp-start tcp-len) by 2
          do (incf sum (logior (ash (aref packet i) 8)
                               (if (< (1+ i) (+ tcp-start tcp-len))
                                   (aref packet (1+ i))
                                   0))))
    ;; Fold 32-bit sum to 16 bits
    (loop while (> sum #xffff)
          do (setf sum (+ (logand sum #xffff) (ash sum -16))))
    ;; Return one's complement
    (logxor sum #xffff)))

(defun tcp-send-packet (conn flags &optional data)
  "Send a TCP packet with the given flags and optional data."
  (let* ((device (tcp-conn-get conn :device))
         (local-port (tcp-conn-get conn :local-port))
         (remote-ip (tcp-conn-get conn :remote-ip))
         (remote-port (tcp-conn-get conn :remote-port))
         (send-seq (tcp-conn-get conn :send-seq))
         (send-ack (tcp-conn-get conn :send-ack))
         (data-len (if data (length data) 0))
         ;; Packet: 14 eth + 20 ip + 20 tcp + data
         (tcp-len (+ 20 data-len))
         (packet-len (+ 14 20 tcp-len))
         (packet (make-array (max 60 packet-len)
                             :element-type '(unsigned-byte 8)
                             :initial-element 0)))
    ;; Get destination MAC (using gateway for routing if needed)
    (let ((dest-mac (e1000-resolve-next-hop-mac remote-ip muerte.ip4::*ip4-ip* device)))
      (unless dest-mac
        (when *e1000-verbose*
          (format t "~&TCP: ARP failed~%"))
        (return-from tcp-send-packet nil))
      ;; Ethernet header
      (replace packet dest-mac :start1 0 :end1 6)
      (replace packet (mac-address device) :start1 6 :end1 12)
      (setf (aref packet 12) #x08 (aref packet 13) #x00)  ; IPv4
      ;; IP header (offset 14)
      (setf (aref packet 14) #x45)      ; Version 4, IHL 5
      (setf (aref packet 15) #x00)      ; TOS
      (let ((ip-len (+ 20 tcp-len)))
        (setf (aref packet 16) (ash ip-len -8)
              (aref packet 17) (logand ip-len #xff)))
      (setf (aref packet 18) 0 (aref packet 19) 0)  ; ID
      (setf (aref packet 20) #x40 (aref packet 21) 0)  ; Don't fragment
      (setf (aref packet 22) 64)        ; TTL
      (setf (aref packet 23) 6)         ; Protocol: TCP
      (setf (aref packet 24) 0 (aref packet 25) 0)  ; Checksum (fill later)
      ;; Source IP
      (replace packet muerte.ip4::*ip4-ip* :start1 26 :end1 30)
      ;; Destination IP
      (replace packet remote-ip :start1 30 :end1 34)
      ;; IP header checksum
      (let ((sum 0))
        (loop for i from 14 below 34 by 2
              do (incf sum (logior (ash (aref packet i) 8)
                                   (aref packet (1+ i)))))
        (loop while (> sum #xffff)
              do (setf sum (+ (logand sum #xffff) (ash sum -16))))
        (setf sum (logxor sum #xffff))
        (setf (aref packet 24) (ash sum -8)
              (aref packet 25) (logand sum #xff)))
      ;; TCP header (offset 34)
      ;; Source port
      (setf (aref packet 34) (ash local-port -8)
            (aref packet 35) (logand local-port #xff))
      ;; Destination port
      (setf (aref packet 36) (ash remote-port -8)
            (aref packet 37) (logand remote-port #xff))
      ;; Sequence number
      (setf (aref packet 38) (ash (logand send-seq #xff000000) -24)
            (aref packet 39) (ash (logand send-seq #x00ff0000) -16)
            (aref packet 40) (ash (logand send-seq #x0000ff00) -8)
            (aref packet 41) (logand send-seq #xff))
      ;; Acknowledgment number
      (setf (aref packet 42) (ash (logand send-ack #xff000000) -24)
            (aref packet 43) (ash (logand send-ack #x00ff0000) -16)
            (aref packet 44) (ash (logand send-ack #x0000ff00) -8)
            (aref packet 45) (logand send-ack #xff))
      ;; Data offset (5 = 20 bytes, no options) + reserved
      (setf (aref packet 46) #x50)      ; 5 << 4
      ;; Flags
      (setf (aref packet 47) flags)
      ;; Window size - max without scaling (65535)
      (setf (aref packet 48) #xff (aref packet 49) #xff)  ; 65535
      ;; Checksum (fill later)
      (setf (aref packet 50) 0 (aref packet 51) 0)
      ;; Urgent pointer
      (setf (aref packet 52) 0 (aref packet 53) 0)
      ;; Data
      (when data
        (replace packet data :start1 54))
      ;; TCP checksum
      (let ((checksum (tcp-compute-checksum packet 14 34 tcp-len)))
        (setf (aref packet 50) (ash checksum -8)
              (aref packet 51) (logand checksum #xff)))
      ;; Transmit
      (transmit device packet :end (max 60 packet-len))
      (when *e1000-verbose*
        (format t "~&TCP: sent flags=#x~2,'0X seq=~D ack=~D len=~D~%"
                flags send-seq send-ack data-len))
      t)))

(defvar *tcp-recv-total-packets* 0 "Total packets received")
(defvar *tcp-recv-filtered-arp* 0 "ARP packets filtered")
(defvar *tcp-recv-filtered-short* 0 "Short packets filtered")
(defvar *tcp-recv-filtered-non-ip* 0 "Non-IP packets filtered")
(defvar *tcp-recv-filtered-non-tcp* 0 "Non-TCP packets filtered")
(defvar *tcp-recv-filtered-wrong-port* 0 "Wrong port packets filtered")
(defvar *tcp-recv-accepted* 0 "Accepted TCP packets")

(defun tcp-recv-stats ()
  "Print TCP receive statistics."
  (format t "~&TCP recv: total=~D arp=~D short=~D non-ip=~D non-tcp=~D wrong-port=~D accepted=~D~%"
          *tcp-recv-total-packets* *tcp-recv-filtered-arp* *tcp-recv-filtered-short*
          *tcp-recv-filtered-non-ip* *tcp-recv-filtered-non-tcp*
          *tcp-recv-filtered-wrong-port* *tcp-recv-accepted*))

(defun tcp-recv-stats-reset ()
  "Reset TCP receive statistics."
  (setf *tcp-recv-total-packets* 0
        *tcp-recv-filtered-arp* 0
        *tcp-recv-filtered-short* 0
        *tcp-recv-filtered-non-ip* 0
        *tcp-recv-filtered-non-tcp* 0
        *tcp-recv-filtered-wrong-port* 0
        *tcp-recv-accepted* 0))

(defun tcp-receive-packet (conn &key (timeout 20))
  "Wait for and receive a TCP packet for this connection.
   Returns (list flags seq-num ack-num data data-len) or NIL on timeout."
  (let* ((device (tcp-conn-get conn :device))
         (local-port (tcp-conn-get conn :local-port))
         (remote-port (tcp-conn-get conn :remote-port))
         (packet (get-packet))  ; Use pooled buffer instead of allocating
         (tries 0)
         (result nil))
    (unwind-protect
        (block receive-block
          (e1000-enable-interrupts device)
          (tagbody
           wait-loop
             (when (>= tries timeout)
               (when *e1000-verbose*
                 (format t "~&TCP: timeout~%"))
               (return-from receive-block nil))
             (unless (e1000-wait-for-packet device 100)
               (incf tries)
               (go wait-loop))
             (receive device packet 0)
             (incf *tcp-recv-total-packets*)
             (let ((pkt-len (fill-pointer packet)))
               ;; Handle ARP requests (respond and continue waiting)
               (when (and (>= pkt-len 42)
                          (= (aref packet 12) #x08)
                          (= (aref packet 13) #x06))
                 (incf *tcp-recv-filtered-arp*)
                 (e1000-arp-respond packet device)
                 (incf tries)
                 (go wait-loop))
               ;; Check minimum length: 14 eth + 20 ip + 20 tcp = 54
               (unless (>= pkt-len 54)
                 (incf *tcp-recv-filtered-short*)
                 (incf tries)
                 (go wait-loop))
               ;; Check EtherType = IP
               (unless (and (= (aref packet 12) #x08) (= (aref packet 13) #x00))
                 (incf *tcp-recv-filtered-non-ip*)
                 (incf tries)
                 (go wait-loop))
               ;; Check protocol = TCP (6)
               (unless (= (aref packet 23) 6)
                 (incf *tcp-recv-filtered-non-tcp*)
                 (incf tries)
                 (go wait-loop))
               ;; Check ports
               (let ((src-port (logior (ash (aref packet 34) 8) (aref packet 35)))
                     (dst-port (logior (ash (aref packet 36) 8) (aref packet 37))))
                 (unless (and (= src-port remote-port) (= dst-port local-port))
                   (incf *tcp-recv-filtered-wrong-port*)
                   (incf tries)
                   (go wait-loop))
                 ;; Extract TCP fields
                 (let* ((seq-num (logior (ash (aref packet 38) 24)
                                         (ash (aref packet 39) 16)
                                         (ash (aref packet 40) 8)
                                         (aref packet 41)))
                        (ack-num (logior (ash (aref packet 42) 24)
                                         (ash (aref packet 43) 16)
                                         (ash (aref packet 44) 8)
                                         (aref packet 45)))
                        (data-offset (ash (aref packet 46) -4))
                        (flags (aref packet 47))
                        (tcp-header-len (* data-offset 4))
                        (tcp-start 34)
                        (data-start (+ tcp-start tcp-header-len))
                        (ip-len (logior (ash (aref packet 16) 8) (aref packet 17)))
                        (data-len (- ip-len 20 tcp-header-len)))
                   (when *e1000-verbose*
                     (format t "~&TCP: recv flags=#x~2,'0X seq=~D ack=~D len=~D~%"
                             flags seq-num ack-num data-len))
                   ;; Check for RST
                   (when (logtest flags +tcp-flag-rst+)
                     (format t "~&TCP: Received RST from remote!~%")
                     (tcp-conn-set conn :state +tcp-state-closed+)
                     (return-from receive-block nil))
                   ;; Extract data if any
                   (let ((data (when (> data-len 0)
                                 (let ((d (make-array data-len :element-type '(unsigned-byte 8))))
                                   (replace d packet :start2 data-start :end2 (+ data-start data-len))
                                   d))))
                     (incf *tcp-recv-accepted*)
                     (setf result (list flags seq-num ack-num data data-len))
                     (return-from receive-block result)))))))
      ;; Cleanup: always return packet to pool
      (free-packet packet))
    result))

(defun tcp-connect (remote-ip remote-port &key (local-port nil) (timeout 20))
  "Establish a TCP connection to REMOTE-IP:REMOTE-PORT.
   Returns a connection object on success, NIL on failure."
  ;; Initialize IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  ;; Generate local port if not specified
  (let* ((port (or local-port (+ 49152 (mod (get-internal-run-time) 16384))))
         (conn (make-tcp-connection port remote-ip remote-port)))
    (when *e1000-verbose*
      (format t "~&TCP: connecting to ~D.~D.~D.~D:~D from port ~D~%"
              (aref remote-ip 0) (aref remote-ip 1)
              (aref remote-ip 2) (aref remote-ip 3)
              remote-port port))
    ;; Send SYN
    (format t ";syn~%")
    (tcp-conn-set conn :state +tcp-state-syn-sent+)
    (unless (tcp-send-packet conn +tcp-flag-syn+)
      (return-from tcp-connect nil))
    (format t ";syn-sent~%")
    ;; Wait for SYN-ACK
    (let* ((result (tcp-receive-packet conn :timeout 30))
           (flags (first result))
           (seq-num (second result)))
      (unless flags
        (when *e1000-verbose*
          (format t "~&TCP: no SYN-ACK received~%"))
        (return-from tcp-connect nil))
      ;; Check for SYN+ACK
      (unless (= (logand flags (logior +tcp-flag-syn+ +tcp-flag-ack+))
                 (logior +tcp-flag-syn+ +tcp-flag-ack+))
        (when *e1000-verbose*
          (format t "~&TCP: expected SYN-ACK, got flags=#x~2,'0X~%" flags))
        (return-from tcp-connect nil))
      ;; Update connection state
      ;; Server's seq becomes our recv-seq (need to ACK seq+1)
      (tcp-conn-set conn :recv-seq (1+ seq-num))
      (tcp-conn-set conn :send-ack (1+ seq-num))
      ;; Our seq was ACKed, advance it
      (tcp-conn-set conn :send-seq (1+ (tcp-conn-get conn :send-seq)))
      ;; Send ACK to complete handshake
      (unless (tcp-send-packet conn +tcp-flag-ack+)
        (return-from tcp-connect nil))
      (tcp-conn-set conn :state +tcp-state-established+)
      (when *e1000-verbose*
        (format t "~&TCP: connection established~%"))
      conn)))

(defun tcp-send (conn data)
  "Send DATA over an established TCP connection.
   Returns T on success, NIL on failure.
   Segments data into chunks of +tcp-mss+ bytes to avoid QEMU slirp issues.
   Does NOT buffer incoming data - caller must use tcp-receive for that."
  ;; Allow sending in CLOSE_WAIT state too (server closed, but we can still send)
  (let ((state (tcp-conn-get conn :state))
        (data-len (length data)))
    (unless (or (= state +tcp-state-established+)
                (= state +tcp-state-close-wait+))
      (return-from tcp-send nil))
    ;; Segment data if larger than MSS
    (if (<= data-len +tcp-mss+)
        ;; Small data - send in one packet with PSH
        (progn
          (unless (tcp-send-packet conn (logior +tcp-flag-psh+ +tcp-flag-ack+) data)
            (return-from tcp-send nil))
          (tcp-conn-set conn :send-seq (+ (tcp-conn-get conn :send-seq) data-len)))
        ;; Large data - segment into multiple packets
        (let ((offset 0))
          (loop while (< offset data-len) do
            (let* ((remaining (- data-len offset))
                   (chunk-size (min +tcp-mss+ remaining))
                   (is-last (>= (+ offset chunk-size) data-len))
                   (chunk (subseq data offset (+ offset chunk-size)))
                   ;; Use PSH only on last segment to signal end of data
                   (flags (if is-last
                              (logior +tcp-flag-psh+ +tcp-flag-ack+)
                              +tcp-flag-ack+)))
              (when *e1000-verbose*
                (format t "TCP segment: ~d-~d of ~d (~a)~%"
                        offset (+ offset chunk-size) data-len
                        (if is-last "PSH" "ACK")))
              (unless (tcp-send-packet conn flags chunk)
                (return-from tcp-send nil))
              (tcp-conn-set conn :send-seq (+ (tcp-conn-get conn :send-seq) chunk-size))
              (incf offset chunk-size)))))
    ;; Don't wait for ACK - let tcp-receive handle any incoming data
    ;; This avoids a 12+ second delay where we wait for ACK that may come with data
    t))

(defun tcp-receive (conn &key (timeout 20))
  "Receive data from a TCP connection.
   Returns received data as a byte vector, or NIL on timeout/error."
  (let ((state (tcp-conn-get conn :state)))
    ;; Allow receiving in both ESTABLISHED and CLOSE_WAIT states
    (unless (or (= state +tcp-state-established+)
                (= state +tcp-state-close-wait+))
      (return-from tcp-receive nil)))
  ;; First check if there's buffered data from tcp-send ACK wait
  (let ((buffered (tcp-conn-get conn :recv-buffer)))
    (when buffered
      (tcp-conn-set conn :recv-buffer nil)
      (return-from tcp-receive buffered)))
  ;; If in CLOSE_WAIT with no buffered data, connection is done
  (when (= (tcp-conn-get conn :state) +tcp-state-close-wait+)
    (return-from tcp-receive nil))
  ;; No buffered data, wait for new data
  (loop
    (let* ((result (tcp-receive-packet conn :timeout timeout))
           (flags (first result))
           (seq-num (second result))
           (payload (fourth result))
           (payload-len (or (fifth result) 0))
           (expected-seq (tcp-conn-get conn :recv-seq)))
      ;; Timeout
      (unless flags
        (return-from tcp-receive nil))
      ;; Got data - validate sequence and ACK
      (when (and payload (> payload-len 0))
        (let ((seg-end (+ seq-num payload-len)))
          (cond
            ;; Case 1: Exact match - this is the data we expect
            ((= seq-num expected-seq)
             (tcp-conn-set conn :recv-seq seg-end)
             (tcp-conn-set conn :send-ack seg-end)
             ;; ACK immediately for reliable flow control
             (when (logtest flags +tcp-flag-fin+)
               (tcp-conn-set conn :send-ack (1+ (tcp-conn-get conn :send-ack)))
               (tcp-conn-set conn :state +tcp-state-close-wait+))
             (tcp-send-packet conn +tcp-flag-ack+)
             (return-from tcp-receive payload))
            ;; Case 2: Duplicate - already have this data
            ((<= seg-end expected-seq)
             (when *e1000-verbose*
               (format t "TCP recv: Discarding duplicate seq=~d (expected ~d)~%"
                       seq-num expected-seq))
             (tcp-send-packet conn +tcp-flag-ack+))
            ;; Case 3: Partial overlap - trim and return new portion
            ((< seq-num expected-seq)
             (let* ((overlap (- expected-seq seq-num))
                    (new-data (subseq payload overlap)))
               (when *e1000-verbose*
                 (format t "TCP recv: Trimming ~d bytes overlap~%" overlap))
               (tcp-conn-set conn :recv-seq seg-end)
               (tcp-conn-set conn :send-ack seg-end)
               (when (logtest flags +tcp-flag-fin+)
                 (tcp-conn-set conn :send-ack (1+ (tcp-conn-get conn :send-ack)))
                 (tcp-conn-set conn :state +tcp-state-close-wait+))
               (tcp-send-packet conn +tcp-flag-ack+)
               (return-from tcp-receive new-data)))
            ;; Case 4: Gap - missing data (shouldn't normally happen)
            (t
             (when *e1000-verbose*
               (format t "TCP recv: Gap! seq=~d expected=~d~%" seq-num expected-seq))
             ;; Accept anyway but log the issue
             (tcp-conn-set conn :recv-seq seg-end)
             (tcp-conn-set conn :send-ack seg-end)
             (when (logtest flags +tcp-flag-fin+)
               (tcp-conn-set conn :send-ack (1+ (tcp-conn-get conn :send-ack)))
               (tcp-conn-set conn :state +tcp-state-close-wait+))
             (tcp-send-packet conn +tcp-flag-ack+)
             (return-from tcp-receive payload)))))
      ;; FIN without data
      (when (logtest flags +tcp-flag-fin+)
        (tcp-conn-set conn :send-ack (1+ seq-num))
        (tcp-conn-set conn :state +tcp-state-close-wait+)
        (tcp-send-packet conn +tcp-flag-ack+)
        (return-from tcp-receive nil)))))

(defun tcp-close (conn)
  "Close a TCP connection."
  (let ((state (tcp-conn-get conn :state)))
    (cond
      ((= state +tcp-state-established+)
       ;; Send FIN+ACK
       (tcp-send-packet conn (logior +tcp-flag-fin+ +tcp-flag-ack+))
       (tcp-conn-set conn :state +tcp-state-fin-wait-1+)
       ;; Wait for ACK/FIN
       (let* ((result (tcp-receive-packet conn :timeout 10))
              (flags (first result))
              (seq-num (second result)))
         (when flags
           (when (logtest flags +tcp-flag-fin+)
             (tcp-conn-set conn :send-ack (1+ seq-num))
             (tcp-send-packet conn +tcp-flag-ack+))))
       (tcp-conn-set conn :state +tcp-state-closed+))
      ((= state +tcp-state-close-wait+)
       ;; Send FIN
       (tcp-send-packet conn (logior +tcp-flag-fin+ +tcp-flag-ack+))
       (tcp-conn-set conn :state +tcp-state-closed+))
      (t
       (tcp-conn-set conn :state +tcp-state-closed+))))
  (when *e1000-verbose*
    (format t "~&TCP: connection closed~%"))
  t)

;;; ============================================================
;;; TCP Server (Passive Open)
;;; ============================================================

(defvar *tcp-listeners* nil
  "List of active TCP listeners")

(defun make-tcp-listener (port)
  "Create a new TCP listener structure."
  (list :state +tcp-state-listen+
        :local-port port
        :device (car *e1000-devices*)))

(defun tcp-listener-get (listener key)
  "Get a value from a TCP listener."
  (getf listener key))

(defun tcp-listener-set (listener key value)
  "Set a value in a TCP listener."
  (setf (getf listener key) value)
  listener)

(defun tcp-listen (port)
  "Create a TCP listener on PORT.
   Returns a listener object that can be passed to tcp-accept."
  ;; Initialize IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (when *e1000-verbose*
    (format t "~&TCP: listening on port ~D~%" port))
  (let ((listener (make-tcp-listener port)))
    (push listener *tcp-listeners*)
    listener))

(defun tcp-listener-close (listener)
  "Close a TCP listener."
  (tcp-listener-set listener :state +tcp-state-closed+)
  (setf *tcp-listeners* (remove listener *tcp-listeners*))
  (when *e1000-verbose*
    (format t "~&TCP: listener closed~%"))
  t)

(defun tcp-accept (listener &key (timeout 60))
  "Wait for and accept a TCP connection on LISTENER.
   Performs the server side of the 3-way handshake.
   Returns a tcp-conn on success, NIL on timeout."
  (let* ((device (tcp-listener-get listener :device))
         (local-port (tcp-listener-get listener :local-port))
         (packet (get-packet))
         (tries 0)
         (result nil))
    (unwind-protect
        (block accept-block
          (e1000-enable-interrupts device)
          (tagbody
           wait-loop
             (when (>= tries timeout)
               (when *e1000-verbose*
                 (format t "~&TCP accept: timeout~%"))
               (return-from accept-block nil))
             (unless (e1000-wait-for-packet device 1000)
               (incf tries)
               (go wait-loop))
             (receive device packet 0)
             (let ((pkt-len (fill-pointer packet)))
               ;; Handle ARP requests (respond and continue waiting)
               (when (and (>= pkt-len 42)
                          (= (aref packet 12) #x08)
                          (= (aref packet 13) #x06))
                 (e1000-arp-respond packet device)
                 (go wait-loop))
               ;; Check minimum length: 14 eth + 20 ip + 20 tcp = 54
               (unless (>= pkt-len 54)
                 (go wait-loop))
               ;; Check EtherType = IP
               (unless (and (= (aref packet 12) #x08) (= (aref packet 13) #x00))
                 (go wait-loop))
               ;; Check protocol = TCP (6)
               (unless (= (aref packet 23) 6)
                 (go wait-loop))
               ;; Check destination port
               (let ((dst-port (logior (ash (aref packet 36) 8) (aref packet 37))))
                 (unless (= dst-port local-port)
                   (go wait-loop))
                 ;; Extract TCP fields
                 (let* ((src-port (logior (ash (aref packet 34) 8) (aref packet 35)))
                        (seq-num (logior (ash (aref packet 38) 24)
                                         (ash (aref packet 39) 16)
                                         (ash (aref packet 40) 8)
                                         (aref packet 41)))
                        (flags (aref packet 47))
                        ;; Extract source IP
                        (remote-ip (make-array 4 :element-type '(unsigned-byte 8))))
                   (setf (aref remote-ip 0) (aref packet 26)
                         (aref remote-ip 1) (aref packet 27)
                         (aref remote-ip 2) (aref packet 28)
                         (aref remote-ip 3) (aref packet 29))
                   ;; Check for SYN (and not ACK - pure SYN for new connection)
                   (unless (and (logtest flags +tcp-flag-syn+)
                                (not (logtest flags +tcp-flag-ack+)))
                     (go wait-loop))
                   (when *e1000-verbose*
                     (format t "~&TCP accept: SYN from ~D.~D.~D.~D:~D seq=~D~%"
                             (aref remote-ip 0) (aref remote-ip 1)
                             (aref remote-ip 2) (aref remote-ip 3)
                             src-port seq-num))
                   ;; Create connection for the incoming request
                   (let ((conn (make-tcp-connection local-port remote-ip src-port)))
                     ;; Set up connection state
                     (tcp-conn-set conn :state +tcp-state-syn-received+)
                     (tcp-conn-set conn :recv-seq (1+ seq-num))
                     (tcp-conn-set conn :send-ack (1+ seq-num))
                     ;; Send SYN-ACK
                     (unless (tcp-send-packet conn (logior +tcp-flag-syn+ +tcp-flag-ack+))
                       (when *e1000-verbose*
                         (format t "~&TCP accept: failed to send SYN-ACK~%"))
                       (go wait-loop))
                     ;; Wait for ACK to complete handshake
                     (let ((ack-result (tcp-receive-packet conn :timeout 30)))
                       (unless ack-result
                         (when *e1000-verbose*
                           (format t "~&TCP accept: no ACK received~%"))
                         (go wait-loop))
                       (let ((ack-flags (first ack-result)))
                         (unless (logtest ack-flags +tcp-flag-ack+)
                           (when *e1000-verbose*
                             (format t "~&TCP accept: expected ACK, got flags=#x~2,'0X~%"
                                     ack-flags))
                           (go wait-loop))
                         ;; Handshake complete - advance our sequence number
                         (tcp-conn-set conn :send-seq (1+ (tcp-conn-get conn :send-seq)))
                         (tcp-conn-set conn :state +tcp-state-established+)
                         (when *e1000-verbose*
                           (format t "~&TCP accept: connection established~%"))
                         (setf result conn)
                         (return-from accept-block conn)))))))))
      ;; Cleanup: always return packet to pool
      (free-packet packet))
    result))

;;; ============================================================
;;; TCP TIME Protocol (RFC 868)
;;; ============================================================
;;; TIME protocol returns a 32-bit time value (seconds since 1900-01-01)
;;; over TCP port 37. Simple protocol for testing TCP.

(defun tcp-time-get (&key (server nil) (server-name "time.nist.gov") (timeout 30))
  "Get time from a TIME protocol server (TCP port 37).
   Returns Unix timestamp or NIL on failure."
  ;; Resolve server if needed
  (let ((server-ip (or server
                       (progn
                         (when *e1000-verbose*
                           (format t "~&TIME: Resolving ~A...~%" server-name))
                         (dns-resolve server-name)))))
    (unless server-ip
      (format t "~&TIME: Failed to resolve server~%")
      (return-from tcp-time-get nil))
    (when *e1000-verbose*
      (format t "~&TIME: Connecting to ~D.~D.~D.~D:37...~%"
              (aref server-ip 0) (aref server-ip 1)
              (aref server-ip 2) (aref server-ip 3)))
    ;; Connect
    (let ((conn (tcp-connect server-ip 37 :timeout timeout)))
      (unless conn
        (format t "~&TIME: Connection failed~%")
        (return-from tcp-time-get nil))
      ;; Server should immediately send 4 bytes of time data
      (let ((data (tcp-receive conn :timeout timeout)))
        (tcp-close conn)
        (unless (and data (>= (length data) 4))
          (format t "~&TIME: No data received~%")
          (return-from tcp-time-get nil))
        ;; Parse 32-bit time (seconds since 1900-01-01, big-endian)
        (let ((ntp-seconds (logior (ash (aref data 0) 24)
                                   (ash (aref data 1) 16)
                                   (ash (aref data 2) 8)
                                   (aref data 3))))
          ;; Convert to Unix time
          (- ntp-seconds +ntp-unix-epoch-offset+))))))

(defun tcp-time-test (&optional (server-name "time.nist.gov"))
  "Test TCP by fetching time from a TIME protocol server.
   Uses TCP port 37 (RFC 868)."
  ;; Initialize IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  (format t "~&TCP TIME test: connecting to ~A:37...~%" server-name)
  (let ((unix-seconds (tcp-time-get :server-name server-name)))
    (if unix-seconds
        (multiple-value-bind (year month day hour minute second)
            (ntp-unix-to-date unix-seconds)
          (format t "~&TIME server reports: ~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D UTC~%"
                  year month day hour minute second)
          (format t "~&Unix timestamp: ~D~%" unix-seconds)
          unix-seconds)
        (progn
          (format t "~&Failed to get time via TCP~%")
          nil))))

;;; ============================================================
;;; HTTP Client (simple GET request)
;;; ============================================================

(defun http-get (host &key (port 80) (path "/") (timeout 30))
  "Make an HTTP GET request to HOST:PORT/PATH.
   Returns the response as a string, or NIL on failure."
  ;; Initialize IP stack if needed
  (unless muerte.ip4::*ip4-nic*
    (e1000-ip-init))
  ;; Resolve hostname if it's a string
  (let ((server-ip (if (stringp host)
                       (progn
                         (when *e1000-verbose*
                           (format t "~&HTTP: Resolving ~A...~%" host))
                         (dns-resolve host))
                       host)))
    (unless server-ip
      (format t "~&HTTP: DNS resolution failed~%")
      (return-from http-get nil))
    (when *e1000-verbose*
      (format t "~&HTTP: Connecting to ~/ip4:pprint-ip4/:~D...~%"
              (muerte.ip4:ip4-address server-ip) port))
    ;; Connect
    (let ((conn (tcp-connect server-ip port :timeout timeout)))
      (unless conn
        (format t "~&HTTP: Connection failed~%")
        (return-from http-get nil))
      ;; Build and send HTTP request
      ;; Build request as byte array directly (format nil may not work in Movitz)
      (let* ((host-str (if (stringp host) host
                           (format nil "~D.~D.~D.~D"
                                   (aref server-ip 0) (aref server-ip 1)
                                   (aref server-ip 2) (aref server-ip 3))))
             (crlf (vector 13 10))  ; CR LF
             (request-parts (list "GET " path " HTTP/1.0" crlf
                                  "Host: " host-str crlf
                                  "Connection: close" crlf crlf))
             (req-len (let ((len 0))
                        (dolist (part request-parts)
                          (incf len (length part)))
                        len))
             (request-bytes (make-array req-len :element-type '(unsigned-byte 8))))
        ;; Copy parts into byte array
        (let ((pos 0))
          (dolist (part request-parts)
            (dotimes (i (length part))
              (setf (aref request-bytes pos)
                    (if (stringp part)
                        (char-code (aref part i))
                        (aref part i)))
              (incf pos))))
        (when *e1000-verbose*
          (format t "~&HTTP: Sending request (~D bytes)...~%" req-len))
        (unless (tcp-send conn request-bytes)
          (format t "~&HTTP: Send failed~%")
          (tcp-close conn)
          (return-from http-get nil))
        ;; Receive response
        (let ((response-parts nil)
              (total-len 0))
          ;; Read until connection closed or timeout
          (loop
            (let ((data (tcp-receive conn :timeout timeout)))
              (unless data
                (return))
              (push data response-parts)
              (incf total-len (length data))
              (when *e1000-verbose*
                (format t "~&HTTP: Received ~D bytes (total ~D)~%" (length data) total-len))))
          (tcp-close conn)
          ;; Combine response parts
          (when response-parts
            (let ((response (make-array total-len :element-type 'character)))
              (let ((pos 0))
                (dolist (part (reverse response-parts))
                  (dotimes (i (length part))
                    (setf (aref response pos) (code-char (aref part i)))
                    (incf pos))))
              response)))))))

(defun http-test (&optional (url "example.com"))
  "Test HTTP by fetching a web page."
  (format t "~&HTTP test: fetching http://~A/...~%" url)
  (let ((response (http-get url)))
    (if response
        (progn
          (format t "~&--- Response (~D bytes) ---~%" (length response))
          ;; Print first 500 chars or so
          (let ((preview-len (min 500 (length response))))
            (format t "~A" (subseq response 0 preview-len))
            (when (> (length response) preview-len)
              (format t "~&... (~D more bytes)~%" (- (length response) preview-len))))
          (format t "~&--- End ---~%")
          response)
        (progn
          (format t "~&HTTP request failed~%")
          nil))))

;;; ============================================================
;;; TCP Echo Server (for testing tcp-listen/tcp-accept)
;;; ============================================================

(defun tcp-echo-server (&key (port 7777) (max-connections 1))
  "Simple TCP echo server for testing.
   Listens on PORT and echoes back any data received.
   Handles MAX-CONNECTIONS connections before returning."
  (format t "~&TCP Echo Server starting on port ~D~%" port)
  (let ((listener (tcp-listen port)))
    (unwind-protect
        (dotimes (i max-connections)
          (format t "~&Waiting for connection ~D/~D...~%" (1+ i) max-connections)
          (let ((conn (tcp-accept listener :timeout 120)))
            (if conn
                (progn
                  (format t "~&Connection accepted~%")
                  ;; Echo loop
                  (loop
                    (let ((data (tcp-receive conn :timeout 30)))
                      (unless data
                        (format t "~&No more data, closing connection~%")
                        (return))
                      (format t "~&Received ~D bytes, echoing back~%" (length data))
                      (unless (tcp-send conn data)
                        (format t "~&Send failed~%")
                        (return))))
                  (tcp-close conn)
                  (format t "~&Connection closed~%"))
                (format t "~&Accept timeout~%"))))
      (tcp-listener-close listener))
    (format t "~&Echo server done~%")))

;;; ============================================================
;;; TCP Speed Test
;;; ============================================================

(defun tcp-speed-test (&key (host #(10 0 2 2)) (port 8888) (path "/test1m.bin") (silent nil))
  "Download a file via HTTP and count bytes received.
   Default connects to host machine (10.0.2.2) port 8888.
   Set :silent t to skip per-chunk output.
   Returns total-bytes or NIL."
  (format t "~&TCP Speed Test~%")
  (format t ";connect~%")
  (let ((conn (tcp-connect host port :timeout 30)))
    (unless conn
      (format t "Connection failed~%")
      (return-from tcp-speed-test nil))
    (format t ";connected~%")
    ;; Build HTTP request
    (let* ((host-str (format nil "~d.~d.~d.~d"
                             (aref host 0) (aref host 1) (aref host 2) (aref host 3)))
           (req-str (format nil "GET ~a HTTP/1.0~c~cHost: ~a~c~c~c~c"
                            path #\return #\linefeed
                            host-str #\return #\linefeed #\return #\linefeed))
           (req (make-array (length req-str) :element-type '(unsigned-byte 8))))
      (dotimes (i (length req-str))
        (setf (aref req i) (char-code (char req-str i))))
      (format t ";sending~%")
      (tcp-send conn req)
      (format t ";receiving~%")
      ;; Download and count
      (let ((total 0)
            (chunks 0))
        (loop
          (let ((data (tcp-receive conn :timeout 20)))
            (unless data
              (format t "  (no more data after ~d chunks)~%" chunks)
              (return))
            (incf total (length data))
            (incf chunks)
            (unless silent
              (format t "  +~d = ~d bytes~%" (length data) total))))
        (format t ";closing~%")
        (tcp-close conn)
        (format t ";closed~%")
        (format t "Done: ~d bytes in ~d chunks~%" total chunks)
        (e1000-wait-stats)
        (tcp-recv-stats)
        total))))
