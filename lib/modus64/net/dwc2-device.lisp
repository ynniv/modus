;;;; dwc2-device.lisp - DWC2 USB Device Mode + CDC-ECM Ethernet Gadget
;;;;
;;;; Provides USB Ethernet gadget for bare-metal networking on Pi Zero 2 W.
;;;; The host sees a standard CDC-ECM USB Ethernet adapter.
;;;;
;;;; Replaces: dwc2.lisp + usb.lisp + cdc-ether.lisp
;;;; Provides: e1000-send, e1000-receive, e1000-rx-buf, cdc-ether-init
;;;; Depends on: arch adapter (dwc2-base, e1000-state-base, etc.)

;;; ============================================================
;;; Register offsets
;;; ============================================================

;; Core global registers
(defun dwc2-gahbcfg ()   (+ (dwc2-base) #x008))
(defun dwc2-gusbcfg ()   (+ (dwc2-base) #x00C))
(defun dwc2-grstctl ()   (+ (dwc2-base) #x010))
(defun dwc2-gintsts ()   (+ (dwc2-base) #x014))
(defun dwc2-gintmsk ()   (+ (dwc2-base) #x018))
(defun dwc2-grxstsp ()   (+ (dwc2-base) #x020))
(defun dwc2-grxfsiz ()   (+ (dwc2-base) #x024))
(defun dwc2-gnptxfsiz () (+ (dwc2-base) #x028))

;; Device-mode registers
(defun dwc2-dcfg ()      (+ (dwc2-base) #x800))
(defun dwc2-dctl ()      (+ (dwc2-base) #x804))
(defun dwc2-dsts ()      (+ (dwc2-base) #x808))
(defun dwc2-diepmsk ()   (+ (dwc2-base) #x810))
(defun dwc2-doepmsk ()   (+ (dwc2-base) #x814))
(defun dwc2-daintmsk ()  (+ (dwc2-base) #x81C))

;; IN endpoint registers
(defun dwc2-diepctl (n)  (+ (dwc2-base) #x900 (* n #x20)))
(defun dwc2-diepint (n)  (+ (dwc2-base) #x908 (* n #x20)))
(defun dwc2-dieptsiz (n) (+ (dwc2-base) #x910 (* n #x20)))

;; OUT endpoint registers
(defun dwc2-doepctl (n)  (+ (dwc2-base) #xB00 (* n #x20)))
(defun dwc2-doepint (n)  (+ (dwc2-base) #xB08 (* n #x20)))
(defun dwc2-doeptsiz (n) (+ (dwc2-base) #xB10 (* n #x20)))

;; Data FIFO access
(defun dwc2-dfifo (n)    (+ (dwc2-base) #x1000 (* n #x1000)))

;; Power and Clock Gating Control
(defun dwc2-pcgcctl ()   (+ (dwc2-base) #xE00))

;;; ============================================================
;;; Register read/write
;;; ============================================================

(defun dwc2-read (addr)
  (mem-ref addr :u32))

(defun dwc2-write (addr val)
  (setf (mem-ref addr :u32) val))

;;; ============================================================
;;; Gadget state at 0x01050000
;;; ============================================================
;;; +0x00: configured    +0x04: address-pending
;;; +0x08: rx-ready      +0x0C: rx-len
;;; +0x10: rx-offset     +0x14: ep0-setup-pending

(defun gadget-state () #x01050000)

(defun gadget-configured ()     (mem-ref (gadget-state) :u32))
(defun gadget-set-configured (v)(setf (mem-ref (gadget-state) :u32) v))
(defun gadget-addr-pending ()     (mem-ref (+ (gadget-state) 4) :u32))
(defun gadget-set-addr-pending (v)(setf (mem-ref (+ (gadget-state) 4) :u32) v))
(defun gadget-rx-ready ()       (mem-ref (+ (gadget-state) 8) :u32))
(defun gadget-set-rx-ready (v)  (setf (mem-ref (+ (gadget-state) 8) :u32) v))
(defun gadget-rx-len ()         (mem-ref (+ (gadget-state) #xC) :u32))
(defun gadget-set-rx-len (v)    (setf (mem-ref (+ (gadget-state) #xC) :u32) v))
(defun gadget-rx-offset ()      (mem-ref (+ (gadget-state) #x10) :u32))
(defun gadget-set-rx-offset (v) (setf (mem-ref (+ (gadget-state) #x10) :u32) v))

;; Descriptor and EP0 buffers
(defun desc-base () #x01000100)
(defun setup-pkt () #x01000080)

;;; ============================================================
;;; Delay helpers
;;; ============================================================

(defun gadget-delay (n)
  (let ((i 0))
    (loop
      (when (>= i n) (return 0))
      (io-delay)
      (setq i (+ i 1)))))

;;; ============================================================
;;; FIFO read/write helpers
;;; ============================================================

;; Read bcnt bytes from RX FIFO into buffer (byte-by-byte extraction)
(defun fifo-read-to-buf (buf bcnt)
  (let ((words (ash (+ bcnt 3) -2)))
    (let ((i 0))
      (loop
        (when (>= i words) (return 0))
        (let ((w (dwc2-read (dwc2-dfifo 0))))
          (let ((off (* i 4)))
            (setf (mem-ref (+ buf off) :u8) (logand w #xFF))
            (when (< (+ off 1) bcnt)
              (setf (mem-ref (+ buf (+ off 1)) :u8) (logand (ash w -8) #xFF)))
            (when (< (+ off 2) bcnt)
              (setf (mem-ref (+ buf (+ off 2)) :u8) (logand (ash w -16) #xFF)))
            (when (< (+ off 3) bcnt)
              (setf (mem-ref (+ buf (+ off 3)) :u8) (logand (ash w -24) #xFF)))))
        (setq i (+ i 1))))))

;; Discard bcnt bytes from RX FIFO
(defun fifo-discard (bcnt)
  (let ((words (ash (+ bcnt 3) -2)))
    (let ((i 0))
      (loop
        (when (>= i words) (return 0))
        (dwc2-read (dwc2-dfifo 0))
        (setq i (+ i 1))))))

;; Write len bytes from buffer to TX FIFO n
(defun fifo-write-from-buf (n buf len)
  (let ((words (ash (+ len 3) -2)))
    (let ((i 0))
      (loop
        (when (>= i words) (return 0))
        (let ((off (* i 4)))
          (let ((b0 (mem-ref (+ buf off) :u8)))
            (let ((b1 (if (< (+ off 1) len) (mem-ref (+ buf (+ off 1)) :u8) 0)))
              (let ((b2 (if (< (+ off 2) len) (mem-ref (+ buf (+ off 2)) :u8) 0)))
                (let ((b3 (if (< (+ off 3) len) (mem-ref (+ buf (+ off 3)) :u8) 0)))
                  (let ((lo (logior b0 (ash b1 8))))
                    (let ((hi (logior b2 (ash b3 8))))
                      (dwc2-write (dwc2-dfifo n) (logior lo (ash hi 16))))))))))
        (setq i (+ i 1))))))

;; Write len bytes from descriptor memory to EP0 TX FIFO
(defun fifo-write-from-desc (src len)
  (fifo-write-from-buf 0 src len))

;;; ============================================================
;;; Descriptor initialization (CDC-ECM)
;;; ============================================================
;;;
;;; Layout:  desc-base+0x000: Device descriptor (18 bytes)
;;;          desc-base+0x020: Config descriptor (71 bytes)
;;;          desc-base+0x080: String 0 - Language (4 bytes)
;;;          desc-base+0x090: String 1 - "Modus64" (16 bytes)
;;;          desc-base+0x0A0: String 2 - "USB Ether" (20 bytes)
;;;          desc-base+0x0C0: String 3 - "000001" (14 bytes)
;;;          desc-base+0x0E0: String 4 - MAC "020000000001" (26 bytes)

(defun gadget-init-dev-desc ()
  (let ((d (desc-base)))
    (setf (mem-ref d :u8) 18)            ;; bLength
    (setf (mem-ref (+ d 1) :u8) 1)      ;; bDescriptorType = DEVICE
    (setf (mem-ref (+ d 2) :u8) 0)      ;; bcdUSB lo
    (setf (mem-ref (+ d 3) :u8) 2)      ;; bcdUSB hi = 2.00
    (setf (mem-ref (+ d 4) :u8) 2)      ;; bDeviceClass = CDC
    (setf (mem-ref (+ d 5) :u8) 0)      ;; bDeviceSubClass
    (setf (mem-ref (+ d 6) :u8) 0)      ;; bDeviceProtocol
    (setf (mem-ref (+ d 7) :u8) 64)     ;; bMaxPacketSize0
    (setf (mem-ref (+ d 8) :u8) #x6B)   ;; idVendor lo = 0x1D6B
    (setf (mem-ref (+ d 9) :u8) #x1D)   ;; idVendor hi
    (setf (mem-ref (+ d 10) :u8) #x37)  ;; idProduct lo
    (setf (mem-ref (+ d 11) :u8) 1)     ;; idProduct hi = 0x0137
    (setf (mem-ref (+ d 12) :u8) 0)     ;; bcdDevice lo
    (setf (mem-ref (+ d 13) :u8) 1)     ;; bcdDevice hi
    (setf (mem-ref (+ d 14) :u8) 1)     ;; iManufacturer
    (setf (mem-ref (+ d 15) :u8) 2)     ;; iProduct
    (setf (mem-ref (+ d 16) :u8) 3)     ;; iSerialNumber
    (setf (mem-ref (+ d 17) :u8) 1)))   ;; bNumConfigurations

(defun gadget-init-config-desc ()
  (let ((c (+ (desc-base) #x20)))
    ;; Configuration descriptor (9)
    (setf (mem-ref c :u8) 9)
    (setf (mem-ref (+ c 1) :u8) 2)       ;; CONFIGURATION
    (setf (mem-ref (+ c 2) :u8) 71)      ;; wTotalLength lo
    (setf (mem-ref (+ c 3) :u8) 0)       ;; wTotalLength hi
    (setf (mem-ref (+ c 4) :u8) 2)       ;; bNumInterfaces
    (setf (mem-ref (+ c 5) :u8) 1)       ;; bConfigurationValue
    (setf (mem-ref (+ c 6) :u8) 0)       ;; iConfiguration
    (setf (mem-ref (+ c 7) :u8) #xC0)    ;; bmAttributes (self-powered)
    (setf (mem-ref (+ c 8) :u8) 50)      ;; bMaxPower (100mA)
    ;; Interface 0: CDC Communication (9)
    (setf (mem-ref (+ c 9) :u8) 9)
    (setf (mem-ref (+ c 10) :u8) 4)      ;; INTERFACE
    (setf (mem-ref (+ c 11) :u8) 0)      ;; bInterfaceNumber
    (setf (mem-ref (+ c 12) :u8) 0)      ;; bAlternateSetting
    (setf (mem-ref (+ c 13) :u8) 1)      ;; bNumEndpoints
    (setf (mem-ref (+ c 14) :u8) 2)      ;; bInterfaceClass = CDC
    (setf (mem-ref (+ c 15) :u8) 6)      ;; bInterfaceSubClass = ECM
    (setf (mem-ref (+ c 16) :u8) 0)      ;; bInterfaceProtocol
    (setf (mem-ref (+ c 17) :u8) 0)      ;; iInterface
    ;; CDC Header Functional Descriptor (5)
    (setf (mem-ref (+ c 18) :u8) 5)
    (setf (mem-ref (+ c 19) :u8) #x24)   ;; CS_INTERFACE
    (setf (mem-ref (+ c 20) :u8) 0)      ;; Header
    (setf (mem-ref (+ c 21) :u8) #x20)   ;; bcdCDC lo = 1.20
    (setf (mem-ref (+ c 22) :u8) 1)      ;; bcdCDC hi
    ;; CDC Union Functional Descriptor (5)
    (setf (mem-ref (+ c 23) :u8) 5)
    (setf (mem-ref (+ c 24) :u8) #x24)   ;; CS_INTERFACE
    (setf (mem-ref (+ c 25) :u8) 6)      ;; Union
    (setf (mem-ref (+ c 26) :u8) 0)      ;; bControlInterface
    (setf (mem-ref (+ c 27) :u8) 1)      ;; bSubordinateInterface0
    ;; CDC Ethernet Networking Functional Descriptor (13)
    (setf (mem-ref (+ c 28) :u8) 13)
    (setf (mem-ref (+ c 29) :u8) #x24)   ;; CS_INTERFACE
    (setf (mem-ref (+ c 30) :u8) #x0F)   ;; Ethernet Networking
    (setf (mem-ref (+ c 31) :u8) 4)      ;; iMACAddress = string 4
    (setf (mem-ref (+ c 32) :u8) 0)      ;; bmEthernetStatistics
    (setf (mem-ref (+ c 33) :u8) 0)
    (setf (mem-ref (+ c 34) :u8) 0)
    (setf (mem-ref (+ c 35) :u8) 0)
    (setf (mem-ref (+ c 36) :u8) #xEA)   ;; wMaxSegmentSize lo (1514)
    (setf (mem-ref (+ c 37) :u8) 5)      ;; wMaxSegmentSize hi
    (setf (mem-ref (+ c 38) :u8) 0)      ;; wNumberMCFilters
    (setf (mem-ref (+ c 39) :u8) 0)
    (setf (mem-ref (+ c 40) :u8) 0)      ;; bNumberPowerFilters
    ;; Endpoint: Interrupt IN EP3 (7)
    (setf (mem-ref (+ c 41) :u8) 7)
    (setf (mem-ref (+ c 42) :u8) 5)      ;; ENDPOINT
    (setf (mem-ref (+ c 43) :u8) #x83)   ;; EP3 IN
    (setf (mem-ref (+ c 44) :u8) 3)      ;; Interrupt
    (setf (mem-ref (+ c 45) :u8) 16)     ;; wMaxPacketSize lo
    (setf (mem-ref (+ c 46) :u8) 0)
    (setf (mem-ref (+ c 47) :u8) 32)     ;; bInterval
    ;; Interface 1: CDC Data (9)
    (setf (mem-ref (+ c 48) :u8) 9)
    (setf (mem-ref (+ c 49) :u8) 4)      ;; INTERFACE
    (setf (mem-ref (+ c 50) :u8) 1)      ;; bInterfaceNumber
    (setf (mem-ref (+ c 51) :u8) 0)      ;; bAlternateSetting
    (setf (mem-ref (+ c 52) :u8) 2)      ;; bNumEndpoints
    (setf (mem-ref (+ c 53) :u8) #x0A)   ;; bInterfaceClass = CDC Data
    (setf (mem-ref (+ c 54) :u8) 0)
    (setf (mem-ref (+ c 55) :u8) 0)
    (setf (mem-ref (+ c 56) :u8) 0)
    ;; Endpoint: Bulk IN EP1 (7)
    (setf (mem-ref (+ c 57) :u8) 7)
    (setf (mem-ref (+ c 58) :u8) 5)      ;; ENDPOINT
    (setf (mem-ref (+ c 59) :u8) #x81)   ;; EP1 IN
    (setf (mem-ref (+ c 60) :u8) 2)      ;; Bulk
    (setf (mem-ref (+ c 61) :u8) 64)     ;; wMaxPacketSize (FS)
    (setf (mem-ref (+ c 62) :u8) 0)
    (setf (mem-ref (+ c 63) :u8) 0)
    ;; Endpoint: Bulk OUT EP2 (7)
    (setf (mem-ref (+ c 64) :u8) 7)
    (setf (mem-ref (+ c 65) :u8) 5)      ;; ENDPOINT
    (setf (mem-ref (+ c 66) :u8) 2)      ;; EP2 OUT
    (setf (mem-ref (+ c 67) :u8) 2)      ;; Bulk
    (setf (mem-ref (+ c 68) :u8) 64)     ;; wMaxPacketSize (FS)
    (setf (mem-ref (+ c 69) :u8) 0)
    (setf (mem-ref (+ c 70) :u8) 0)))

(defun gadget-init-string-descs ()
  ;; String 0: Language (4 bytes) at +0x80
  (let ((s (+ (desc-base) #x80)))
    (setf (mem-ref s :u8) 4)
    (setf (mem-ref (+ s 1) :u8) 3)
    (setf (mem-ref (+ s 2) :u8) 9)
    (setf (mem-ref (+ s 3) :u8) 4))
  ;; String 1: "Modus64" (16 bytes) at +0x90
  (let ((s (+ (desc-base) #x90)))
    (setf (mem-ref s :u8) 16)
    (setf (mem-ref (+ s 1) :u8) 3)
    (setf (mem-ref (+ s 2) :u8) 77)(setf (mem-ref (+ s 3) :u8) 0)
    (setf (mem-ref (+ s 4) :u8) 111)(setf (mem-ref (+ s 5) :u8) 0)
    (setf (mem-ref (+ s 6) :u8) 100)(setf (mem-ref (+ s 7) :u8) 0)
    (setf (mem-ref (+ s 8) :u8) 117)(setf (mem-ref (+ s 9) :u8) 0)
    (setf (mem-ref (+ s 10) :u8) 115)(setf (mem-ref (+ s 11) :u8) 0)
    (setf (mem-ref (+ s 12) :u8) 54)(setf (mem-ref (+ s 13) :u8) 0)
    (setf (mem-ref (+ s 14) :u8) 52)(setf (mem-ref (+ s 15) :u8) 0))
  ;; String 2: "USB Ether" (20 bytes) at +0xA0
  (let ((s (+ (desc-base) #xA0)))
    (setf (mem-ref s :u8) 20)
    (setf (mem-ref (+ s 1) :u8) 3)
    (setf (mem-ref (+ s 2) :u8) 85)(setf (mem-ref (+ s 3) :u8) 0)
    (setf (mem-ref (+ s 4) :u8) 83)(setf (mem-ref (+ s 5) :u8) 0)
    (setf (mem-ref (+ s 6) :u8) 66)(setf (mem-ref (+ s 7) :u8) 0)
    (setf (mem-ref (+ s 8) :u8) 32)(setf (mem-ref (+ s 9) :u8) 0)
    (setf (mem-ref (+ s 10) :u8) 69)(setf (mem-ref (+ s 11) :u8) 0)
    (setf (mem-ref (+ s 12) :u8) 116)(setf (mem-ref (+ s 13) :u8) 0)
    (setf (mem-ref (+ s 14) :u8) 104)(setf (mem-ref (+ s 15) :u8) 0)
    (setf (mem-ref (+ s 16) :u8) 101)(setf (mem-ref (+ s 17) :u8) 0)
    (setf (mem-ref (+ s 18) :u8) 114)(setf (mem-ref (+ s 19) :u8) 0))
  ;; String 3: "000001" (14 bytes) at +0xC0
  (let ((s (+ (desc-base) #xC0)))
    (setf (mem-ref s :u8) 14)
    (setf (mem-ref (+ s 1) :u8) 3)
    (setf (mem-ref (+ s 2) :u8) 48)(setf (mem-ref (+ s 3) :u8) 0)
    (setf (mem-ref (+ s 4) :u8) 48)(setf (mem-ref (+ s 5) :u8) 0)
    (setf (mem-ref (+ s 6) :u8) 48)(setf (mem-ref (+ s 7) :u8) 0)
    (setf (mem-ref (+ s 8) :u8) 48)(setf (mem-ref (+ s 9) :u8) 0)
    (setf (mem-ref (+ s 10) :u8) 48)(setf (mem-ref (+ s 11) :u8) 0)
    (setf (mem-ref (+ s 12) :u8) 49)(setf (mem-ref (+ s 13) :u8) 0))
  ;; String 4: MAC "020000000001" (26 bytes) at +0xE0
  (let ((s (+ (desc-base) #xE0)))
    (setf (mem-ref s :u8) 26)
    (setf (mem-ref (+ s 1) :u8) 3)
    (setf (mem-ref (+ s 2) :u8) 48)(setf (mem-ref (+ s 3) :u8) 0)
    (setf (mem-ref (+ s 4) :u8) 50)(setf (mem-ref (+ s 5) :u8) 0)
    (setf (mem-ref (+ s 6) :u8) 48)(setf (mem-ref (+ s 7) :u8) 0)
    (setf (mem-ref (+ s 8) :u8) 48)(setf (mem-ref (+ s 9) :u8) 0)
    (setf (mem-ref (+ s 10) :u8) 48)(setf (mem-ref (+ s 11) :u8) 0)
    (setf (mem-ref (+ s 12) :u8) 48)(setf (mem-ref (+ s 13) :u8) 0)
    (setf (mem-ref (+ s 14) :u8) 48)(setf (mem-ref (+ s 15) :u8) 0)
    (setf (mem-ref (+ s 16) :u8) 48)(setf (mem-ref (+ s 17) :u8) 0)
    (setf (mem-ref (+ s 18) :u8) 48)(setf (mem-ref (+ s 19) :u8) 0)
    (setf (mem-ref (+ s 20) :u8) 48)(setf (mem-ref (+ s 21) :u8) 0)
    (setf (mem-ref (+ s 22) :u8) 48)(setf (mem-ref (+ s 23) :u8) 0)
    (setf (mem-ref (+ s 24) :u8) 49)(setf (mem-ref (+ s 25) :u8) 0)))

(defun gadget-init-descriptors ()
  (gadget-init-dev-desc)
  (gadget-init-config-desc)
  (gadget-init-string-descs))

;;; ============================================================
;;; VideoCore mailbox: power on USB controller
;;; ============================================================
;;; BCM2837 mailbox at 0x3F00B880. Required on real hardware
;;; (QEMU has USB always powered). Uses property tag channel 8.
;;; Buffer at 0x01050100 (16-byte aligned, after gadget state).

(defun mbox-base () #x3F00B880)
(defun mbox-read () (mbox-base))
(defun mbox-status () (+ (mbox-base) #x18))
(defun mbox-write () (+ (mbox-base) #x20))
(defun mbox-write-status () (+ (mbox-base) #x38))
(defun mbox-buf () #x01050100)

(defun mbox-send-power (state-val)
  ;; Send SET_POWER_STATE for USB HCD (device 3) with given state
  (let ((buf (mbox-buf)))
    (setf (mem-ref buf :u32) 32)              ;; buffer size
    (setf (mem-ref (+ buf 4) :u32) 0)        ;; request code
    (setf (mem-ref (+ buf 8) :u32) #x00028001) ;; SET_POWER_STATE
    (setf (mem-ref (+ buf 12) :u32) 8)       ;; value buffer size
    (setf (mem-ref (+ buf 16) :u32) 8)       ;; request length
    (setf (mem-ref (+ buf 20) :u32) 3)       ;; device ID = USB HCD
    (setf (mem-ref (+ buf 24) :u32) state-val) ;; state
    (setf (mem-ref (+ buf 28) :u32) 0)       ;; end tag
    ;; Wait until mailbox is not full
    (let ((w 0))
      (loop
        (when (>= w 100000) (return 0))
        (when (zerop (logand (dwc2-read (mbox-write-status)) (ash 1 31)))
          (return 0))
        (setq w (+ w 1))))
    ;; Write buffer address (uncached: |0xC0000000) | channel 8
    (dwc2-write (mbox-write) (logior #xC1050100 8))
    ;; Read response: wait for non-empty, match channel 8
    (let ((r 0))
      (loop
        (when (>= r 100000) (return 0))
        (when (zerop (logand (dwc2-read (mbox-status)) (ash 1 30)))
          (let ((resp (dwc2-read (mbox-read))))
            (when (eq (logand resp #xF) 8)
              (return resp))))
        (setq r (+ r 1))))
    (mem-ref (+ buf 24) :u32)))

(defun mbox-set-uart-clock ()
  ;; Set PL011 UART clock to 48MHz via VideoCore mailbox
  ;; Required on real hardware — firmware only enables mini UART clock
  (let ((buf (mbox-buf)))
    (setf (mem-ref buf :u32) 36)              ;; buffer size
    (setf (mem-ref (+ buf 4) :u32) 0)        ;; request code
    (setf (mem-ref (+ buf 8) :u32) #x00038002) ;; SET_CLOCK_RATE
    (setf (mem-ref (+ buf 12) :u32) 12)      ;; value buffer size
    (setf (mem-ref (+ buf 16) :u32) 12)      ;; request length
    (setf (mem-ref (+ buf 20) :u32) 2)       ;; clock ID = UART
    (setf (mem-ref (+ buf 24) :u32) #x02DC6C00) ;; 48000000 Hz = 48MHz
    (setf (mem-ref (+ buf 28) :u32) 0)       ;; skip turbo = 0
    (setf (mem-ref (+ buf 32) :u32) 0)       ;; end tag
    ;; Wait until mailbox is not full
    (let ((w 0))
      (loop
        (when (>= w 100000) (return 0))
        (when (zerop (logand (dwc2-read (mbox-write-status)) (ash 1 31)))
          (return 0))
        (setq w (+ w 1))))
    ;; Write buffer address | channel 8
    (dwc2-write (mbox-write) (logior #xC1050100 8))
    ;; Read response
    (let ((r 0))
      (loop
        (when (>= r 100000) (return 0))
        (when (zerop (logand (dwc2-read (mbox-status)) (ash 1 30)))
          (let ((resp (dwc2-read (mbox-read))))
            (when (eq (logand resp #xF) 8)
              (return resp))))
        (setq r (+ r 1))))))

(defun mbox-power-on-usb ()
  ;; Power ON USB HCD
  (let ((state (mbox-send-power 3)))  ;; ON | WAIT (bit 1=WAIT, bit 0=1=ON)
    (write-byte 80)(write-byte 87)(write-byte 82)  ;; "PWR"
    (write-byte 58) ;; ":"
    (print-hex-byte (logand state #xFF))
    (write-byte 10)
    state))

;;; ============================================================
;;; Core DWC2 device mode initialization
;;; ============================================================

(defun gadget-core-reset ()
  ;; Clear PCGCCTL — ensure PHY clocks are running
  ;; If start.elf or boot ROM left clocks gated, all register writes are dead
  (dwc2-write (dwc2-pcgcctl) 0)
  (gadget-delay 10)
  ;; Wait for AHB idle (bit 31 of GRSTCTL)
  (let ((i 0))
    (loop
      (when (>= i 100000) (return 0))
      (when (not (zerop (logand (dwc2-read (dwc2-grstctl)) (ash 1 31))))
        (return 1))
      (setq i (+ i 1))))
  ;; Core soft reset (bit 0)
  (dwc2-write (dwc2-grstctl) 1)
  (let ((i 0))
    (loop
      (when (>= i 100000) (return 0))
      (when (zerop (logand (dwc2-read (dwc2-grstctl)) 1))
        (return 1))
      (setq i (+ i 1))))
  (gadget-delay 100))

(defun gadget-init-fifos ()
  ;; RX FIFO: 512 words (2KB)
  (dwc2-write (dwc2-grxfsiz) 512)
  ;; EP0 TX FIFO: start=512, size=64 words
  (dwc2-write (dwc2-gnptxfsiz) (logior 512 (ash 64 16)))
  ;; EP1 TX FIFO: start=576, size=384 words (1.5KB for Ethernet frames)
  (dwc2-write (+ (dwc2-base) #x104) (logior 576 (ash 384 16)))
  ;; EP3 TX FIFO: start=960, size=16 words
  (dwc2-write (+ (dwc2-base) #x10C) (logior 960 (ash 16 16)))
  ;; Flush all TX FIFOs
  (dwc2-write (dwc2-grstctl) (logior (ash 1 5) (ash #x10 6)))
  (let ((i 0))
    (loop
      (when (>= i 10000) (return 0))
      (when (zerop (logand (dwc2-read (dwc2-grstctl)) (ash 1 5)))
        (return 0))
      (setq i (+ i 1))))
  ;; Flush RX FIFO
  (dwc2-write (dwc2-grstctl) (ash 1 4))
  (let ((i 0))
    (loop
      (when (>= i 10000) (return 0))
      (when (zerop (logand (dwc2-read (dwc2-grstctl)) (ash 1 4)))
        (return 0))
      (setq i (+ i 1)))))

(defun gadget-ep0-prepare ()
  ;; Program DOEPTSIZ[0]: XFERSIZE=64, PKTCNT=1, SUPCNT=3
  (dwc2-write (dwc2-doeptsiz 0)
              (logior 64 (logior (ash 1 19) (ash 3 29))))
  ;; Enable EP0 OUT: CNAK | EPENA
  (let ((ctl (dwc2-read (dwc2-doepctl 0))))
    (dwc2-write (dwc2-doepctl 0)
                (logior ctl (logior (ash 1 26) (ash 1 31))))))

(defun gadget-init ()
  ;; Clear state
  (gadget-set-configured 0)
  (gadget-set-addr-pending 0)
  (gadget-set-rx-ready 0)
  (gadget-set-rx-len 0)
  (gadget-set-rx-offset 0)
  ;; Power on USB controller via VideoCore mailbox (required on real hardware)
  (mbox-power-on-usb)
  (gadget-delay 200)
  ;; Init descriptors
  (gadget-init-descriptors)
  ;; Core reset
  (gadget-core-reset)
  ;; Force device mode: read-modify-write to preserve boot ROM's PHY configuration
  (let ((cfg (dwc2-read (dwc2-gusbcfg))))
    ;; Clear force-host (bit 29)
    (let ((cleared (logand cfg (logxor (ash 1 29) #xFFFFFFFF))))
      ;; Set force-device (bit 30)
      (dwc2-write (dwc2-gusbcfg) (logior cleared (ash 1 30)))))
  (gadget-delay 200)  ;; DWC2 spec: 25ms for mode switch; 200 iters ≈ 50-100ms
  ;; DCFG: Full Speed (DevSpd=1), address=0
  (dwc2-write (dwc2-dcfg) 1)
  ;; AHB config: no DMA, global interrupt enable
  (dwc2-write (dwc2-gahbcfg) 1)
  ;; Init FIFOs
  (gadget-init-fifos)
  ;; Unmask interrupts: USBRst(12), EnumDone(13), RxFLvl(4), IEPInt(18), OEPInt(19)
  (dwc2-write (dwc2-gintmsk)
              (logior (ash 1 4) (logior (ash 1 12) (logior (ash 1 13)
              (logior (ash 1 18) (ash 1 19))))))
  ;; Unmask endpoint interrupts
  (dwc2-write (dwc2-daintmsk) (logior #xF (ash #xF 16)))
  (dwc2-write (dwc2-diepmsk) (logior 1 (ash 1 3)))
  (dwc2-write (dwc2-doepmsk) (logior 1 (logior (ash 1 3) (ash 1 0))))
  ;; Prepare EP0 for SETUP
  (gadget-ep0-prepare)
  ;; Soft disconnect
  (let ((dctl (dwc2-read (dwc2-dctl))))
    (dwc2-write (dwc2-dctl) (logior dctl 2)))
  (gadget-delay 50)
  ;; Soft connect (clear SftDiscon bit 1)
  (let ((dctl (dwc2-read (dwc2-dctl))))
    (dwc2-write (dwc2-dctl) (logand dctl (logxor 2 #xFFFFFFFF))))
  (write-byte 71)(write-byte 65)(write-byte 68)(write-byte 10)  ;; "GAD\n"
  1)

;;; ============================================================
;;; EP0 SETUP handling
;;; ============================================================

(defun gadget-ep0-send-data (src len wlength)
  ;; Send min(len, wlength) bytes on EP0 IN
  (let ((send-len (if (< len wlength) len wlength)))
    (let ((pktcnt (if (zerop send-len) 1 (/ (+ send-len 63) 64))))
      ;; Program DIEPTSIZ[0]
      (dwc2-write (dwc2-dieptsiz 0) (logior send-len (ash pktcnt 19)))
      ;; Enable EP0 IN: CNAK | EPENA
      (let ((ctl (dwc2-read (dwc2-diepctl 0))))
        (dwc2-write (dwc2-diepctl 0)
                    (logior ctl (logior (ash 1 26) (ash 1 31)))))
      ;; Write data to EP0 TX FIFO
      (fifo-write-from-desc src send-len)
      ;; Prepare EP0 OUT for STATUS
      (gadget-ep0-prepare))))

(defun gadget-ep0-send-zlp ()
  ;; Send zero-length packet on EP0 IN (STATUS stage)
  (dwc2-write (dwc2-dieptsiz 0) (ash 1 19))
  (let ((ctl (dwc2-read (dwc2-diepctl 0))))
    (dwc2-write (dwc2-diepctl 0)
                (logior ctl (logior (ash 1 26) (ash 1 31)))))
  (gadget-ep0-prepare))

(defun gadget-ep0-stall ()
  ;; STALL EP0 IN
  (let ((ctl (dwc2-read (dwc2-diepctl 0))))
    (dwc2-write (dwc2-diepctl 0) (logior ctl (ash 1 21))))
  (gadget-ep0-prepare))

(defun gadget-get-string (idx wlength)
  (if (eq idx 0)
      (gadget-ep0-send-data (+ (desc-base) #x80) 4 wlength)
      (if (eq idx 1)
          (gadget-ep0-send-data (+ (desc-base) #x90) 16 wlength)
          (if (eq idx 2)
              (gadget-ep0-send-data (+ (desc-base) #xA0) 20 wlength)
              (if (eq idx 3)
                  (gadget-ep0-send-data (+ (desc-base) #xC0) 14 wlength)
                  (if (eq idx 4)
                      (gadget-ep0-send-data (+ (desc-base) #xE0) 26 wlength)
                      (gadget-ep0-stall)))))))

(defun gadget-activate-endpoints ()
  ;; EP1 IN (Bulk): MPS=64, USBActEP, EPType=Bulk, TxFNum=1
  (dwc2-write (dwc2-diepctl 1)
              (logior 64 (logior (ash 1 15) (logior (ash 2 18)
              (logior (ash 1 22) (ash 1 28))))))
  ;; EP2 OUT (Bulk): MPS=64, USBActEP, EPType=Bulk
  (dwc2-write (dwc2-doepctl 2)
              (logior 64 (logior (ash 1 15) (logior (ash 2 18) (ash 1 28)))))
  ;; EP3 IN (Interrupt): MPS=16, USBActEP, EPType=Interrupt, TxFNum=3
  ;; DIEPCTL[3] = 16 | (1<<15) | (3<<18) | (3<<22) | (1<<28)
  (dwc2-write (dwc2-diepctl 3)
              (logior 16 (logior (ash 1 15) (logior (ash 3 18)
              (logior (ash 3 22) (ash 1 28))))))
  ;; Arm EP2 OUT for receiving
  (gadget-arm-ep2))

(defun gadget-arm-ep2 ()
  ;; Program DOEPTSIZ[2]: XFERSIZE=2048, PKTCNT=32
  (dwc2-write (dwc2-doeptsiz 2) (logior 2048 (ash 32 19)))
  ;; Enable EP2 OUT: CNAK | EPENA
  (let ((ctl (dwc2-read (dwc2-doepctl 2))))
    (dwc2-write (dwc2-doepctl 2)
                (logior ctl (logior (ash 1 26) (ash 1 31))))))

(defun gadget-handle-setup ()
  (let ((breq (mem-ref (+ (setup-pkt) 1) :u8))
        (wval-lo (mem-ref (+ (setup-pkt) 2) :u8))
        (wval-hi (mem-ref (+ (setup-pkt) 3) :u8))
        (wlen-lo (mem-ref (+ (setup-pkt) 6) :u8))
        (wlen-hi (mem-ref (+ (setup-pkt) 7) :u8)))
    (let ((wvalue (logior wval-lo (ash wval-hi 8)))
          (wlength (logior wlen-lo (ash wlen-hi 8))))
      ;; Debug: print "S:xx" where xx = bRequest
      (write-byte 83)(write-byte 58)  ;; "S:"
      (print-hex-byte breq)
      (write-byte 10)
      (if (eq breq 6)       ;; GET_DESCRIPTOR
          (let ((desc-type (ash wvalue -8))
                (desc-idx (logand wvalue #xFF)))
            (if (eq desc-type 1)
                (gadget-ep0-send-data (desc-base) 18 wlength)
                (if (eq desc-type 2)
                    (gadget-ep0-send-data (+ (desc-base) #x20) 71 wlength)
                    (if (eq desc-type 3)
                        (gadget-get-string desc-idx wlength)
                        (gadget-ep0-stall)))))
          (if (eq breq 5)   ;; SET_ADDRESS
              (progn
                (gadget-set-addr-pending wvalue)
                (gadget-ep0-send-zlp))
              (if (eq breq 9)   ;; SET_CONFIGURATION
                  (progn
                    (gadget-set-configured wvalue)
                    (when (not (zerop wvalue))
                      (gadget-activate-endpoints))
                    (gadget-ep0-send-zlp))
                  (if (eq breq 11)  ;; SET_INTERFACE
                      (gadget-ep0-send-zlp)
                      ;; CDC or unknown: ACK
                      (gadget-ep0-send-zlp))))))))

;;; ============================================================
;;; USB event handling
;;; ============================================================

(defun gadget-handle-reset ()
  ;; USB bus reset
  (write-byte 82)(write-byte 83)(write-byte 84)(write-byte 10)  ;; "RST\n"
  (gadget-set-configured 0)
  ;; Reset address to 0
  (let ((dcfg (dwc2-read (dwc2-dcfg))))
    (dwc2-write (dwc2-dcfg) (logand dcfg (logxor (ash #x7F 4) #xFFFFFFFF))))
  ;; Re-prepare EP0
  (gadget-ep0-prepare))

(defun gadget-handle-enum-done ()
  ;; Enumeration complete — read negotiated speed from DSTS
  (let ((dsts (dwc2-read (dwc2-dsts))))
    (let ((speed (logand (ash dsts -1) 3)))
      (write-byte 83)(write-byte 80)(write-byte 58)  ;; "SP:"
      (write-byte (+ 48 speed))(write-byte 10)))
  ;; Set EP0 MPS in DIEPCTL[0] (bits 1:0 for EP0: 0=64, 1=32, 2=16, 3=8)
  (let ((ctl (dwc2-read (dwc2-diepctl 0))))
    (dwc2-write (dwc2-diepctl 0) (logand ctl (logxor 3 #xFFFFFFFF)))))

(defun gadget-handle-ep0-in-complete ()
  ;; EP0 IN transfer complete — check if we need to apply pending address
  (let ((addr (gadget-addr-pending)))
    (when (not (zerop addr))
      (let ((dcfg (dwc2-read (dwc2-dcfg))))
        (let ((cleared (logand dcfg (logxor (ash #x7F 4) #xFFFFFFFF))))
          (dwc2-write (dwc2-dcfg) (logior cleared (ash addr 4)))))
      (gadget-set-addr-pending 0))))

(defun gadget-handle-rxflvl ()
  ;; Read and pop RX status
  (let ((rxsts (dwc2-read (dwc2-grxstsp))))
    (let ((ep (logand rxsts #xF))
          (bcnt (logand (ash rxsts -4) #x7FF))
          (pktsts (logand (ash rxsts -17) #xF)))
      ;; SETUP data received (pktsts=6)
      (when (eq pktsts 6)
        (fifo-read-to-buf (setup-pkt) bcnt))
      ;; SETUP complete (pktsts=4) — process the SETUP
      (when (eq pktsts 4)
        (gadget-handle-setup))
      ;; OUT data received (pktsts=2)
      (when (eq pktsts 2)
        (if (eq ep 2)
            ;; Bulk OUT — Ethernet frame data
            (let ((offset (gadget-rx-offset)))
              (fifo-read-to-buf (+ (e1000-rx-buf-base) offset) bcnt)
              (gadget-set-rx-offset (+ offset bcnt)))
            ;; EP0 OUT data (STATUS ZLP) or unexpected — discard
            (fifo-discard bcnt)))
      ;; OUT transfer complete (pktsts=3)
      (when (eq pktsts 3)
        (when (eq ep 2)
          ;; Ethernet frame complete
          (let ((total (gadget-rx-offset)))
            (when (> total 0)
              (gadget-set-rx-len total)
              (gadget-set-rx-ready 1)
              (gadget-set-rx-offset 0))))))))

(defun gadget-poll ()
  ;; Handle USB events by polling GINTSTS
  (let ((sts (dwc2-read (dwc2-gintsts))))
    ;; Bus Reset
    (when (not (zerop (logand sts (ash 1 12))))
      (gadget-handle-reset)
      (dwc2-write (dwc2-gintsts) (ash 1 12)))
    ;; Enum Done
    (when (not (zerop (logand sts (ash 1 13))))
      (gadget-handle-enum-done)
      (dwc2-write (dwc2-gintsts) (ash 1 13)))
    ;; RX FIFO non-empty — drain all pending entries
    (when (not (zerop (logand sts (ash 1 4))))
      (let ((rx-count 0))
        (loop
          (when (>= rx-count 32) (return 0))
          (when (zerop (logand (dwc2-read (dwc2-gintsts)) (ash 1 4)))
            (return 0))
          (gadget-handle-rxflvl)
          (setq rx-count (+ rx-count 1)))))
    ;; IN endpoint interrupt
    (when (not (zerop (logand sts (ash 1 18))))
      ;; Check EP0 IN complete
      (let ((ep0int (dwc2-read (dwc2-diepint 0))))
        (when (not (zerop (logand ep0int 1)))
          (dwc2-write (dwc2-diepint 0) 1)
          (gadget-handle-ep0-in-complete)))
      ;; Clear EP1 IN complete
      (let ((ep1int (dwc2-read (dwc2-diepint 1))))
        (when (not (zerop (logand ep1int 1)))
          (dwc2-write (dwc2-diepint 1) 1))))
    ;; OUT endpoint interrupt
    (when (not (zerop (logand sts (ash 1 19))))
      ;; Clear EP0 OUT interrupts
      (let ((ep0int (dwc2-read (dwc2-doepint 0))))
        (when (not (zerop ep0int))
          (dwc2-write (dwc2-doepint 0) ep0int)))
      ;; EP2 OUT complete — re-arm
      (let ((ep2int (dwc2-read (dwc2-doepint 2))))
        (when (not (zerop (logand ep2int 1)))
          (dwc2-write (dwc2-doepint 2) ep2int)
          (gadget-arm-ep2))))))

;;; ============================================================
;;; NIC API (same interface as e1000.lisp / cdc-ether.lisp)
;;; ============================================================

(defun e1000-receive ()
  ;; Poll USB events, then check if an Ethernet frame is ready
  (gadget-poll)
  (if (not (zerop (gadget-rx-ready)))
      (let ((len (gadget-rx-len)))
        (gadget-set-rx-ready 0)
        len)
      0))

(defun e1000-rx-buf ()
  (e1000-rx-buf-base))

(defun e1000-send (buf len)
  ;; Copy Lisp byte array to TX buffer, then send via EP1 IN
  (let ((tx-buf (e1000-tx-buf-base)))
    (let ((i 0))
      (loop
        (when (>= i len) (return 0))
        (setf (mem-ref (+ tx-buf i) :u8) (aref buf i))
        (setq i (+ i 1))))
    ;; Wait for previous TX to complete
    (let ((w 0))
      (loop
        (when (>= w 50000) (return 0))
        (when (zerop (logand (dwc2-read (dwc2-diepctl 1)) (ash 1 31)))
          (return 0))
        (setq w (+ w 1))))
    ;; Program DIEPTSIZ[1]: XFERSIZE=len, PKTCNT
    (let ((pktcnt (/ (+ len 63) 64)))
      (dwc2-write (dwc2-dieptsiz 1) (logior len (ash pktcnt 19))))
    ;; Enable EP1 IN: CNAK | EPENA
    (let ((ctl (dwc2-read (dwc2-diepctl 1))))
      (dwc2-write (dwc2-diepctl 1)
                  (logior ctl (logior (ash 1 26) (ash 1 31)))))
    ;; Write to EP1 TX FIFO
    (fifo-write-from-buf 1 tx-buf len)
    1))

(defun e1000-probe ()
  (cdc-ether-init))

;; E1000 register stubs
(defun e1000-write-reg (reg val) nil)
(defun e1000-read-reg (reg) 0)

;;; ============================================================
;;; Main initialization
;;; ============================================================

(defun cdc-ether-init ()
  ;; Initialize DWC2 device mode + CDC-ECM gadget
  (gadget-init)
  ;; Set up network state
  (let ((state (e1000-state-base)))
    ;; MAC: 02:00:00:00:00:01 (locally administered)
    (setf (mem-ref (+ state #x08) :u8) 2)
    (setf (mem-ref (+ state #x09) :u8) 0)
    (setf (mem-ref (+ state #x0A) :u8) 0)
    (setf (mem-ref (+ state #x0B) :u8) 0)
    (setf (mem-ref (+ state #x0C) :u8) 0)
    (setf (mem-ref (+ state #x0D) :u8) 1)
    ;; Static IP: 10.0.0.2 (host will be 10.0.0.1)
    (setf (mem-ref (+ state #x18) :u32) #x0200000A)
    (setf (mem-ref (+ state #x1C) :u32) #x0100000A)
    ;; Clear cursors
    (setf (mem-ref (+ state #x10) :u32) 0)
    (setf (mem-ref (+ state #x14) :u32) 0)
    (setf (mem-ref (+ state #x44) :u32) 0))
  ;; Wait for enumeration to complete (host configures us)
  (write-byte 69)(write-byte 78)(write-byte 85)(write-byte 77)  ;; "ENUM"
  (write-byte 10)
  (let ((i 0))
    (loop
      (when (not (zerop (gadget-configured))) (return 1))
      (when (>= i 500000) (return 0))
      (gadget-poll)
      (io-delay)
      (setq i (+ i 1))))
  (write-byte 67)(write-byte 70)(write-byte 71)  ;; "CFG"
  (write-byte 10)
  1)
