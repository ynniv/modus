;;;; i386-ehci.lisp — EHCI USB Host + RTL8153 USB Ethernet for i386 bare metal
;;;;
;;;; Provides USB networking via RTL8153 Gigabit Ethernet adapter on
;;;; Intel 6/7 Series EHCI controllers (e.g., ThinkPad T420).
;;;;
;;;; Requires (loaded before this file):
;;;;   i386-console.lisp — mmio-do-read32, mmio-do-write32, pci-config-read, etc.
;;;;   e1000.lisp        — e1000-send/receive API (overridden here)
;;;;   arch-i386.lisp    — e1000-state-base, io-delay
;;;;
;;;; Memory layout:
;;;;   0x600170: EHCI BAR0 (4 bytes raw)
;;;;   0x600174: EHCI CAPLENGTH
;;;;   0x600178: Hub USB address
;;;;   0x600179: Device USB address
;;;;   0x60017A: Bulk IN EP number
;;;;   0x60017B: Bulk OUT EP number
;;;;   0x60017C: Bulk IN MPS (2 bytes LE)
;;;;   0x60017E: Bulk OUT MPS (2 bytes LE)
;;;;   0x600180: Bulk IN toggle
;;;;   0x600181: Bulk OUT toggle
;;;;   0x600182: Hub port where device was found
;;;;   0x600183: EHCI root port where hub was found
;;;;   0x7C00000: Periodic frame list (4096 bytes, 4K aligned)
;;;;   0x7C01000: Async sentinel QH (64 bytes)
;;;;   0x7C01040: Work QH (64 bytes)
;;;;   0x7C01080: qTD 0 — SETUP (32 bytes)
;;;;   0x7C010A0: qTD 1 — DATA (32 bytes)
;;;;   0x7C010C0: qTD 2 — STATUS (32 bytes)
;;;;   0x7C010E0: qTD 3 — spare (32 bytes)
;;;;   0x7C01100: USB setup packet (8 bytes)
;;;;   0x7C01200: USB control data buffer (512 bytes)
;;;;   0x7C01400: RTL8153 TX header + frame (8 + 1536 bytes)
;;;;   0x7C01A00: RTL8153 RX buffer (2048 bytes)

;;; ============================================================
;;; Constants
;;; ============================================================

;;; DMA memory at 0x480000 (4.5MB) — between stack top (0x400000) and
;;; state area (0x500000). Low address ensures DMA accessibility.
(defun ehci-frame-list () #x480000)
(defun ehci-sentinel-qh () #x481000)
(defun ehci-work-qh () #x481040)
(defun ehci-qtd0 () #x481080)
(defun ehci-qtd1 () #x4810A0)
(defun ehci-qtd2 () #x4810C0)
(defun ehci-qtd3 () #x4810E0)
(defun ehci-setup-buf () #x481100)
(defun ehci-data-buf () #x481200)
(defun ehci-tx-buf () #x481400)
(defun ehci-rx-buf () #x481A00)

;;; ============================================================
;;; EHCI MMIO access (BAR at 0x600170, shares scratch with NIC)
;;; ============================================================

(defun ehci-mmio-setup (reg)
  ;; Set MMIO address = EHCI BAR0 + CAPLENGTH + reg
  (let ((r (+ reg (mem-ref #x600174 :u8))))
    (setf (mem-ref #x600140 :u8) (mem-ref #x600170 :u8))
    (setf (mem-ref #x600141 :u8) (mem-ref #x600171 :u8))
    (setf (mem-ref #x600142 :u8) (mem-ref #x600172 :u8))
    (setf (mem-ref #x600143 :u8) (mem-ref #x600173 :u8))
    (addr-add-byte0 (logand r #xFF))
    (addr-add-byte1 (logand (ash r -8) #xFF))))

(defun ehci-read (reg)
  ;; Read EHCI operational register.
  (let ((r reg))
    (ehci-mmio-setup r)
    (mmio-do-read32)
    (let ((b0 (mem-ref #x600148 :u8)))
      (let ((b1 (mem-ref #x600149 :u8)))
        (let ((lo (logior b0 (ash b1 8))))
          (let ((b2 (mem-ref #x60014A :u8)))
            (let ((b3 (logand (mem-ref #x60014B :u8) #x3F)))
              (let ((hi (logior (ash b2 16) (ash b3 24))))
                (logior lo hi)))))))))

(defun ehci-write (reg val)
  ;; Write EHCI operational register.
  (let ((r reg) (v val))
    (ehci-mmio-setup r)
    (setf (mem-ref #x600148 :u8) (logand v #xFF))
    (setf (mem-ref #x600149 :u8) (logand (ash v -8) #xFF))
    (setf (mem-ref #x60014A :u8) (logand (ash v -16) #xFF))
    (setf (mem-ref #x60014B :u8) (logand (ash v -24) #xFF))
    (mmio-do-write32)))

(defun ehci-read-cap (off)
  ;; Read EHCI capability register (BAR0 + off, NO caplength offset).
  (let ((o off))
    (setf (mem-ref #x600140 :u8) (mem-ref #x600170 :u8))
    (setf (mem-ref #x600141 :u8) (mem-ref #x600171 :u8))
    (setf (mem-ref #x600142 :u8) (mem-ref #x600172 :u8))
    (setf (mem-ref #x600143 :u8) (mem-ref #x600173 :u8))
    (addr-add-byte0 (logand o #xFF))
    (addr-add-byte1 (logand (ash o -8) #xFF))
    (mmio-do-read32)
    (let ((b0 (mem-ref #x600148 :u8)))
      (let ((b1 (mem-ref #x600149 :u8)))
        (logior b0 (ash b1 8))))))

;;; ============================================================
;;; EHCI Port Status/Control
;;; ============================================================

(defun ehci-portsc (port)
  ;; PORTSC register offset for given port (0-based).
  (+ #x44 (* port 4)))

(defun ehci-read-port (port)
  (let ((p port))
    (ehci-read (ehci-portsc p))))

(defun ehci-write-port (port val)
  ;; Write PORTSC, masking write-clear bits (1,3,5) to avoid clearing them.
  (let ((p port) (v val))
    (let ((masked (logand v #x3FFFFFD5)))
      (ehci-write (ehci-portsc p) masked))))

;;; ============================================================
;;; QH/qTD data structure helpers
;;; ============================================================

(defun ehci-zero-mem (addr count)
  ;; Zero count u32 words starting at addr.
  (let ((a addr) (n count))
    (dotimes (i n)
      (setf (mem-ref (+ a (* i 4)) :u32) 0))))

(defun ehci-init-async-qh ()
  ;; Set up single async QH: self-link, H flag, idle (overlay terminates).
  ;; This QH is permanently in the async schedule. We reconfigure it per-transfer.
  (let ((qh (ehci-work-qh)))
    (ehci-zero-mem qh 16)
    ;; Horizontal link → self, type=QH
    (setf (mem-ref qh :u32) (logior qh 2))
    ;; Characteristics: Head of reclamation (bit 15)
    (setf (mem-ref (+ qh 4) :u32) #x8000)
    ;; Capabilities: zero (filled per-transfer)
    (setf (mem-ref (+ qh 8) :u32) 0)
    (setf (mem-ref (+ qh 12) :u32) 0)
    ;; Overlay: terminate (idle)
    (setf (mem-ref (+ qh 16) :u32) 1)
    (setf (mem-ref (+ qh 20) :u32) 1)
    (setf (mem-ref (+ qh 24) :u32) 0)))

(defun ehci-setup-work-qh-hs (addr ep mps)
  ;; Set up work QH for HIGH-SPEED device (async schedule).
  (let ((a addr) (e ep) (m mps))
    (let ((qh (ehci-work-qh)))
      (setf (mem-ref (+ qh 4) :u8) a)
      ;; speed=2(HS), DTC, H
      (setf (mem-ref (+ qh 5) :u8) (logior e #xE0))
      (setf (mem-ref (+ qh 6) :u8) (logand m #xFF))
      (setf (mem-ref (+ qh 7) :u8) (logior (logand (ash m -8) 7) #x50))
      ;; Caps: Mult=1 only
      (setf (mem-ref (+ qh 8) :u32) 0)
      (setf (mem-ref (+ qh 11) :u8) #x40)
      (setf (mem-ref (+ qh 12) :u32) 0)
      qh)))

(defun ehci-setup-work-qh-split (addr ep mps hub-addr hub-port)
  ;; Set up work QH for FULL-SPEED device behind hub (PERIODIC schedule).
  ;; Uses SMask/CMask for split transaction scheduling in periodic frame list.
  (let ((a addr) (e ep) (m mps))
    (let ((ha hub-addr) (hp hub-port))
      (let ((qh (ehci-work-qh)))
        ;; Horizontal link → terminate (periodic, linked via frame list)
        (setf (mem-ref qh :u32) 1)
        ;; Characteristics:
        (setf (mem-ref (+ qh 4) :u8) a)
        ;; Speed=0(FS), DTC(6), no H flag
        (setf (mem-ref (+ qh 5) :u8) (logior e #x40))
        (setf (mem-ref (+ qh 6) :u8) (logand m #xFF))
        ;; C=1(3) for control EP, NAK=0(7:4) for periodic
        (setf (mem-ref (+ qh 7) :u8) (logior (logand (ash m -8) 7) 8))
        ;; SMask=0x01 (start-split in microframe 0)
        (setf (mem-ref (+ qh 8) :u8) 1)
        ;; CMask=0x1C (complete-split in microframes 2,3,4)
        (setf (mem-ref (+ qh 9) :u8) #x1C)
        ;; Hub Address
        (setf (mem-ref (+ qh 10) :u8) ha)
        ;; Hub Port | Mult=1
        (setf (mem-ref (+ qh 11) :u8) (logior hp #x40))
        (setf (mem-ref (+ qh 12) :u32) 0)
        qh))))

(defun ehci-setup-work-qh (addr ep speed mps)
  ;; Dispatch: high-speed (2) uses async, full-speed (0) uses periodic+split.
  (let ((a addr) (e ep) (s speed) (m mps))
    (if (= s 2)
        (ehci-setup-work-qh-hs a e m)
      ;; Full-speed: use split transactions via hub
      (let ((ha (mem-ref #x600190 :u8)))   ; stored hub address
        (let ((hp (mem-ref #x600191 :u8))) ; stored hub port
          (let ((hub-a (if (zerop ha) 1 ha)))
            (let ((hub-p (if (zerop hp) 1 hp)))
              (ehci-setup-work-qh-split a e m hub-a hub-p))))))))

;;; ============================================================
;;; EHCI periodic schedule for split transactions
;;; ============================================================

(defun ehci-link-periodic-qh ()
  ;; Link work QH into ALL frame list entries (poll every 1ms frame).
  ;; Frame list entry: QH address | type=QH(01 in bits 2:1) = addr | 2.
  (let ((fl (ehci-frame-list)))
    (let ((qh-link (logior (ehci-work-qh) 2)))
      (dotimes (i 1024)
        (setf (mem-ref (+ fl (* i 4)) :u32) qh-link))))
  (wbinvd))

(defun ehci-unlink-periodic-qh ()
  ;; Remove work QH from frame list (all entries → terminate).
  (let ((fl (ehci-frame-list)))
    (dotimes (i 1024)
      (setf (mem-ref (+ fl (* i 4)) :u32) 1)))
  (wbinvd))

(defun ehci-poll-qtd (qtd timeout)
  ;; Poll work QH overlay until entire chain completes.
  ;; Wait for overlay.nextLink = Terminate AND Active = 0.
  ;; This ensures all qTDs in the chain have been processed.
  (let ((qh (ehci-work-qh)) (n timeout))
    (let ((i 0))
      (loop
        (when (>= i n) (return -1))
        (let ((status (mem-ref (+ qh 24) :u8)))
          ;; Only read byte 0 of token (status bits) — avoids fixnum overflow
          ;; from toggle bit 31 in higher bytes.
          ;; Done when: Halted (bit 6), OR (Active=0 AND nextLink Terminates)
          (when (not (zerop (logand status #x40)))
            (return status))
          (when (zerop (logand status #x80))
            (let ((next-lo (mem-ref (+ qh 16) :u8)))
              (when (= (logand next-lo 1) 1)
                (return status)))))
        (io-delay)
        (setq i (+ i 1))))))

(defun ehci-exec-transfer (first-qtd)
  ;; Execute a transfer via the PERIODIC schedule (for split transactions).
  ;; Copies qTD into QH overlay, links QH into frame list, polls, unlinks.
  ;; Returns token value on completion, -1 on timeout.
  (let ((qtd first-qtd))
    (let ((qh (ehci-work-qh)))
      ;; Use advance queue: set overlay.nextLink = first qTD, token = 0.
      ;; EHCI sees Active=0, nextLink != Terminate → fetches qTD and advances.
      ;; This avoids the overlay copy corruption that breaks multi-qTD chains.
      (setf (mem-ref (+ qh 12) :u32) 0)     ; curLink = 0
      (setf (mem-ref (+ qh 16) :u32) qtd)   ; overlay.nextLink = first qTD
      (setf (mem-ref (+ qh 20) :u32) 1)     ; overlay.altNext = Terminate
      (setf (mem-ref (+ qh 24) :u32) 0)     ; overlay.token = 0 (Active=0)
      (setf (mem-ref (+ qh 28) :u32) 0)     ; clear buffer pointers
      (setf (mem-ref (+ qh 32) :u32) 0)
      (setf (mem-ref (+ qh 36) :u32) 0)
      (setf (mem-ref (+ qh 40) :u32) 0)
      (setf (mem-ref (+ qh 44) :u32) 0))
    ;; Check QH link: terminate(1) = periodic/split, self-link = async/HS
    (let ((hlink (mem-ref (ehci-work-qh) :u32)))
      (if (= hlink 1)
          ;; Periodic: link into frame list, enable PSE
          (progn
            (ehci-link-periodic-qh)
            (let ((cmd (ehci-read 0)))
              (ehci-write 0 (logior cmd #x10))))
        ;; Async: kick ASE
        (let ((cmd (ehci-read 0)))
          (ehci-write 0 (logand cmd #x3FFFFFDF))
          (dotimes (k 5) (io-delay))
          (ehci-write 0 (logior cmd #x21)))))
    (ehci-poll-qtd qtd 3000)))

;;; ============================================================
;;; USB setup packet builder
;;; ============================================================

(defun ehci-build-setup (rt req val idx len)
  ;; Write 8-byte SETUP packet to ehci-setup-buf.
  (let ((buf (ehci-setup-buf)))
    (let ((r rt) (q req) (v val) (x idx) (l len))
      (setf (mem-ref buf :u8) r)
      (setf (mem-ref (+ buf 1) :u8) q)
      (setf (mem-ref (+ buf 2) :u8) (logand v #xFF))
      (setf (mem-ref (+ buf 3) :u8) (logand (ash v -8) #xFF))
      (setf (mem-ref (+ buf 4) :u8) (logand x #xFF))
      (setf (mem-ref (+ buf 5) :u8) (logand (ash x -8) #xFF))
      (setf (mem-ref (+ buf 6) :u8) (logand l #xFF))
      (setf (mem-ref (+ buf 7) :u8) (logand (ash l -8) #xFF)))))

;;; ============================================================
;;; USB Control Transfer
;;; ============================================================

(defun ehci-setup-qtd (qtd next pid len toggle buf)
  ;; Initialize a qTD: set next pointer, token bytes, and buffer pointer.
  ;; Uses byte writes for token to avoid fixnum overflow (toggle bit 31).
  (let ((q qtd) (n next) (p pid) (l len))
    (let ((t toggle) (b buf))
      ;; Zero entire qTD first (8 u32 words = 32 bytes)
      (ehci-zero-mem q 8)
      (setf (mem-ref q :u32) n)            ; next qTD
      (setf (mem-ref (+ q 4) :u32) 1)     ; alt next → terminate
      ;; Token: individual byte writes (u32 write had byte 3 = 0x40 bug)
      ;; Byte 0 (offset 8): Active = 0x80
      (setf (mem-ref (+ q 8) :u8) #x80)
      ;; Byte 1 (offset 9): PID(1:0) | CERR=3(3:2)
      (let ((b1 (logior p (ash 3 2))))
        (setf (mem-ref (+ q 9) :u8) b1))
      ;; Byte 2 (offset 10): Total bytes low 8 bits
      (setf (mem-ref (+ q 10) :u8) (logand l #xFF))
      ;; Byte 3 (offset 11): Total bytes high 7 | toggle(7)
      ;; FORCE write 0 then overwrite with correct value
      (setf (mem-ref (+ q 11) :u8) 0)
      (let ((hi (logand (ash l -8) #x7F)))
        (let ((tg (ash t 7)))
          (let ((b3 (logior hi tg)))
            (setf (mem-ref (+ q 11) :u8) b3))))
      ;; Buffer pointer 0
      (setf (mem-ref (+ q 12) :u32) b)
      ;; Additional page pointers
      (when (not (zerop b))
        (let ((page (logand (+ b #x1000) #x3FFFF000)))
          (setf (mem-ref (+ q 16) :u32) page)
          (setf (mem-ref (+ q 20) :u32) (+ page #x1000))
          (setf (mem-ref (+ q 24) :u32) (+ page #x2000))
          (setf (mem-ref (+ q 28) :u32) (+ page #x3000)))))))

(defun ehci-control-msg-inner (a m r b l)
  ;; Inner function: build setup, configure QH, execute transfer.
  (let ((spd (mem-ref #x600192 :u8)))
    (ehci-setup-work-qh a 0 spd m))
  (wbinvd)
  (let ((dir-in (logand r #x80)))
    (if (zerop l)
        (ehci-ctrl-no-data dir-in)
      (ehci-ctrl-with-data dir-in b l))))

(defun ehci-control-msg (addr mps rt req val idx buf len)
  ;; Full USB control transfer. Split into two functions to avoid multi-binding let.
  (let ((a addr))
    (let ((m mps))
      (let ((r rt))
        (let ((q req))
          (let ((v val))
            (let ((x idx))
              (let ((b buf))
                (let ((l len))
                  (ehci-build-setup r q v x l)
                  (ehci-control-msg-inner a m r b l))))))))))

(defun ehci-ctrl-no-data (dir-in)
  ;; Control transfer with no data phase: SETUP → STATUS
  (let ((d dir-in))
    (let ((status-pid (if (zerop d) 1 0)))
      (ehci-setup-qtd (ehci-qtd1) 1 status-pid 0 1 0)
      (ehci-setup-qtd (ehci-qtd0) (ehci-qtd1) 2 8 0 (ehci-setup-buf))
      (let ((tok (ehci-exec-transfer (ehci-qtd0))))
        (if (< tok 0) 0
          (if (zerop (logand tok #x40)) 1 0))))))

(defun ehci-ctrl-with-data (dir-in buf len)
  ;; Control transfer with data phase: SETUP → DATA → STATUS
  ;; Single-binding lets only (MVM requirement).
  (let ((d dir-in))
    (let ((b buf))
      (let ((l len))
        (let ((data-pid (if (zerop d) 0 1)))
          (let ((status-pid (if (zerop d) 1 0)))
            (ehci-setup-qtd (ehci-qtd2) 1 status-pid 0 1 0)
            (ehci-setup-qtd (ehci-qtd1) (ehci-qtd2) data-pid l 1 b)
            (ehci-setup-qtd (ehci-qtd0) (ehci-qtd1) 2 8 0 (ehci-setup-buf))
            (let ((tok (ehci-exec-transfer (ehci-qtd0))))
              (if (zerop (logand tok #x40)) 1 0))))))))

;;; ============================================================
;;; USB Bulk Transfer
;;; ============================================================

(defun ehci-bulk-transfer (addr ep mps buf len pid toggle-addr)
  ;; Single bulk transfer (IN or OUT). Updates toggle at toggle-addr.
  ;; Returns bytes transferred (0 on error).
  (let ((a addr) (e ep) (m mps) (b buf))
    (let ((l len) (p pid) (ta toggle-addr))
      (let ((tog (mem-ref ta :u8)))
        ;; Set up work QH
        (ehci-setup-work-qh a e 2 m)
        (wbinvd)  ; flush QH before EHCI reads it
        ;; Single qTD
        (ehci-setup-qtd (ehci-qtd0) 1 p l tog b)
        (let ((tok (ehci-exec-transfer (ehci-qtd0))))
          ;; Toggle flips on success
          (when (zerop (logand tok #x7E))
            (setf (mem-ref ta :u8) (logand (+ tog 1) 1)))
          ;; Return bytes transferred (total - remaining)
          (let ((remaining (logand (ash tok -16) #x7FFF)))
            (- l remaining)))))))

(defun ehci-bulk-in (buf len)
  ;; Bulk IN from the RTL8153 device.
  (let ((b buf) (l len))
    (ehci-bulk-transfer
      (mem-ref #x600179 :u8)
      (mem-ref #x60017A :u8)
      (logior (mem-ref #x60017C :u8) (ash (mem-ref #x60017D :u8) 8))
      b l 1 #x600180)))

(defun ehci-bulk-out (buf len)
  ;; Bulk OUT to the RTL8153 device.
  (let ((b buf) (l len))
    (ehci-bulk-transfer
      (mem-ref #x600179 :u8)
      (mem-ref #x60017B :u8)
      (logior (mem-ref #x60017E :u8) (ash (mem-ref #x60017F :u8) 8))
      b l 0 #x600181)))

;;; ============================================================
;;; EHCI Controller Initialization
;;; ============================================================

(defun ehci-try-pci-dev (dev)
  ;; Check if PCI device is Intel EHCI, save BAR0 raw at 0x600170.
  ;; Returns 1 if found, 0 otherwise.
  (let ((d dev))
    ;; Check vendor = Intel (0x8086)
    (pci-read-raw 0 d 0 0)
    (let ((v0 (mmio-result-byte 0)))
      (let ((v1 (mmio-result-byte 1)))
        (when (not (and (= v0 #x86) (= v1 #x80)))
          (return 0))))
    ;; Read BAR0 (reg 0x10), save raw bytes at 0x600170
    (pci-read-raw 0 d 0 #x10)
    (pci-read-raw 0 d 0 #x10)  ;; (debug stripped)
    (let ((b0 (logand (mmio-result-byte 0) #xF0)))
      (let ((b1 (mmio-result-byte 1)))
        (let ((b2 (mmio-result-byte 2)))
          (let ((b3 (mmio-result-byte 3)))
            (when (zerop (logior b0 (logior b1 (logior b2 b3))))
              (return 0))
            (setf (mem-ref #x600170 :u8) b0)
            (setf (mem-ref #x600171 :u8) b1)
            (setf (mem-ref #x600172 :u8) b2)
            (setf (mem-ref #x600173 :u8) b3)))))
    ;; Enable bus mastering + memory space
    (pci-nic-enable d)
    ;; Store PCI device number
    (setf (mem-ref #x600175 :u8) d)
    (write-char-output (+ 48 d))    ; print device number
    1))

(defun ehci-is-ehci-class (dev)
  ;; Check if PCI device has class 0C/03/20 (USB EHCI).
  ;; Class code at config reg 0x08: byte 1=prog-if, byte 2=subclass, byte 3=class.
  (let ((d dev))
    (pci-read-raw 0 d 0 8)
    (let ((progif (mmio-result-byte 1)))
      (let ((subclass (mmio-result-byte 2)))
        (let ((class (mmio-result-byte 3)))
          (and (= class #xC) (= subclass 3) (= progif #x20)))))))

(defun ehci-find-controller ()
  ;; Scan PCI bus 0 for any EHCI controller (class 0C/03/20).
  ;; Stores BAR0 raw bytes at 0x600170, returns 1 on success.
  ;; Try 0x1D and 0x1A first (Intel 6 Series), then scan all.
  (let ((found (ehci-try-pci-dev #x1D)))
    (when (not (zerop found)) (return found)))
  (let ((found (ehci-try-pci-dev #x1A)))
    (when (not (zerop found)) (return found)))
  ;; Broad scan
  (let ((dev 0))
    (loop
      (when (>= dev 32) (return 0))
      (when (ehci-is-ehci-class dev)
        (let ((r (ehci-try-pci-dev dev)))
          (when (not (zerop r)) (return r))))
      (setq dev (+ dev 1)))))

(defun ehci-bios-handoff (pci-dev)
  ;; Take EHCI ownership from BIOS/coreboot.
  ;; EECP from HCCPARAMS (BAR0+0x08, bits 15:8 = byte 1).
  (let ((d pci-dev))
    ;; Read HCCPARAMS via raw MMIO at BAR0+8
    (setf (mem-ref #x600140 :u8) (mem-ref #x600170 :u8))
    (setf (mem-ref #x600141 :u8) (mem-ref #x600171 :u8))
    (setf (mem-ref #x600142 :u8) (mem-ref #x600172 :u8))
    (setf (mem-ref #x600143 :u8) (mem-ref #x600173 :u8))
    (addr-add-byte0 8)
    (mmio-do-read32)
    ;; EECP = byte 1 (bits 15:8 of HCCPARAMS)
    (let ((ee (mmio-result-byte 1)))
      (when (>= ee #x40)
        ;; Read USBLEGSUP via raw PCI at offset EECP
        (pci-read-raw 0 d 0 ee)
        (let ((bios-own (logand (mmio-result-byte 2) 1)))
          (when (not (zerop bios-own))
            ;; Build modified dword: set OS-owned (byte 3 bit 0)
            (let ((b0 (mmio-result-byte 0)))
              (let ((b1 (mmio-result-byte 1)))
                (let ((b2 (mmio-result-byte 2)))
                  (let ((lo (logior b0 (ash b1 8))))
                    (let ((hi (logior (ash b2 16) (ash 1 24))))
                      ;; Write back via PCI config
                      (let ((addr (pci-addr 0 d 0 ee)))
                        (pci-config-read-raw addr)
                        (io-out-dword #xCFC (logior lo hi))))))))
            ;; Wait for BIOS to release (byte 2 bit 0 clears)
            (dotimes (j 500)
              (pci-read-raw 0 d 0 ee)
              (when (zerop (logand (mmio-result-byte 2) 1))
                (setq j 501))
              (io-delay))))
        ;; Clear BIOS SMI enables at EECP+4
        (pci-config-write 0 d 0 (+ ee 4) 0))
      (write-char-output 66))))   ; 'B' = BIOS handoff done

(defun ehci-init-reset ()
  ;; Reset EHCI controller: halt, HCRESET, wait for completion.
  (let ((cmd (ehci-read 0)))
    (ehci-write 0 (logand cmd #x3FFFFFFE)))
  (dotimes (i 100) (io-delay))
  (ehci-write 0 2)
  (dotimes (i 200)
    (when (zerop (logand (ehci-read 0) 2))
      (setq i 201))
    (io-delay)))

(defun ehci-init-schedules ()
  ;; Set up async QH, frame list, and configure registers.
  (ehci-init-async-qh)
  (let ((fl (ehci-frame-list)))
    (dotimes (i 1024)
      (setf (mem-ref (+ fl (* i 4)) :u32) 1)))
  (wbinvd)
  (ehci-write 8 0)
  (ehci-write #x10 0)
  (ehci-write #x14 (ehci-frame-list))
  (ehci-write #x18 (ehci-work-qh))
  (ehci-write 4 #x3F)
  (ehci-write #x40 1)
  (dotimes (i 100) (io-delay)))

(defun ehci-init-start ()
  ;; Start controller and verify SOF frames flowing.
  (ehci-write 0 (logior (ash 8 16) #x31))
  (dotimes (i 100)
    (when (zerop (logand (ehci-read 4) #x1000))
      (setq i 101))
    (io-delay))
  (let ((fr1 (ehci-read #xC)))
    (dotimes (i 20) (io-delay))
    (let ((fr2 (ehci-read #xC)))
      (if (= fr1 fr2)
          (write-char-output 115)
        (write-char-output 70))))
  (dotimes (i 100)
    (when (zerop (logand (ehci-read 4) #x1000))
      (setq i 101))
    (io-delay))
  (ehci-write #x40 1)
  (dotimes (i 50) (io-delay))
  (write-char-output 69)
  1)

(defun ehci-init-controller ()
  ;; Full EHCI init: caplength, BIOS handoff, reset, configure, start.
  (let ((cap (ehci-read-cap 0)))
    (setf (mem-ref #x600174 :u8) (logand cap #xFF)))
  (ehci-bios-handoff (mem-ref #x600175 :u8))
  (ehci-init-reset)
  (ehci-init-schedules)
  (ehci-init-start))

;;; ============================================================
;;; EHCI Port Reset + Hub Enumeration
;;; ============================================================

(defun ehci-port-reset (port)
  ;; Reset a root port. Returns 1 if device connected after reset.
  (let ((p port))
    (let ((sc (ehci-read-port p)))
      ;; Set reset bit, clear enable
      (ehci-write-port p (logior (logand sc #xFFFFFFFB) #x100))
      ;; Hold reset for ~50ms
      (dotimes (i 50) (io-delay))
      ;; Clear reset
      (let ((sc2 (ehci-read-port p)))
        (ehci-write-port p (logand sc2 #xFFFFFEFF)))
      ;; Wait for reset to complete
      (dotimes (i 200)
        (when (zerop (logand (ehci-read-port p) #x100))
          (setq i 201))
        (io-delay))
      ;; Check if device is connected and enabled
      (let ((final (ehci-read-port p)))
        (if (not (zerop (logand final 5)))    ; CCS + PE
            1
          0)))))

(defun ehci-find-device-port ()
  ;; Find a root port with a connected device. Returns port number or -1.
  (let ((nports (logand (ehci-read-cap 4) #xF)))
    (let ((found -1))
      (dotimes (i nports)
        (let ((sc (ehci-read-port i)))
          (when (not (zerop (logand sc 1)))   ; CCS = connected
            (when (= found -1)
              (setq found i)))))
      found)))

(defun ehci-hub-get-port-status (hub-addr port)
  ;; GET_PORT_STATUS on hub. Returns status word.
  (let ((ha hub-addr) (p port))
    (ehci-control-msg ha 64 #xA3 0 0 p (ehci-data-buf) 4)
    (logior (mem-ref (ehci-data-buf) :u8)
            (ash (mem-ref (+ (ehci-data-buf) 1) :u8) 8))))

(defun ehci-hub-set-feature (hub-addr feature port)
  ;; SET_PORT_FEATURE on hub.
  (let ((ha hub-addr) (f feature) (p port))
    (ehci-control-msg ha 64 #x23 3 f p 0 0)))

(defun ehci-hub-clear-feature (hub-addr feature port)
  ;; CLEAR_PORT_FEATURE on hub.
  (let ((ha hub-addr) (f feature) (p port))
    (ehci-control-msg ha 64 #x23 1 f p 0 0)))

(defun ehci-hub-port-reset (hub-addr port)
  ;; Reset a hub port and wait for completion.
  (let ((ha hub-addr) (p port))
    ;; SET_FEATURE PORT_RESET
    (ehci-hub-set-feature ha 4 p)
    ;; Wait ~100ms
    (dotimes (i 100) (io-delay))
    ;; Poll for reset complete (bit 4 of change = C_PORT_RESET)
    (let ((ok 0))
      (dotimes (i 500)
        (let ((st (ehci-hub-get-port-status ha p)))
          ;; Check change bits (high word): C_PORT_RESET = bit 4+16 = bit 20
          ;; Actually GET_PORT_STATUS returns 4 bytes: status(16) + change(16)
          ;; We only read the low 16 bits above. Need full 4 bytes.
          ;; For simplicity, just poll until enabled (bit 1) is set
          (when (not (zerop (logand st 2)))
            (setq ok 1)
            (setq i 501)))
        (io-delay))
      ;; Clear C_PORT_RESET
      (ehci-hub-clear-feature ha 20 p)
      ok)))

(defun ehci-hub-find-device (hub-addr nports)
  ;; Find a connected port on the hub. Returns port (1-based) or 0.
  (let ((ha hub-addr) (n nports))
    (let ((found 0))
      (let ((i 1))
        (loop
          (when (> i n) (return found))
          (let ((st (ehci-hub-get-port-status ha i)))
            (when (not (zerop (logand st 1)))   ; connected
              (when (zerop found)
                (setq found i))))
          (setq i (+ i 1)))))))

;;; ============================================================
;;; USB Standard Requests
;;; ============================================================

(defun ehci-set-address (new-addr)
  ;; SET_ADDRESS (to device at addr 0).
  (let ((a new-addr))
    (ehci-control-msg 0 64 0 5 a 0 0 0)))

(defun ehci-get-descriptor (addr desc-type idx buf len)
  ;; GET_DESCRIPTOR.
  (let ((a addr) (dt desc-type) (x idx) (b buf) (l len))
    (ehci-control-msg a 64 #x80 6 (logior (ash dt 8) x) 0 b l)))

(defun ehci-set-configuration (addr config)
  ;; SET_CONFIGURATION.
  (let ((a addr) (c config))
    (ehci-control-msg a 64 0 9 c 0 0 0)))

;;; ============================================================
;;; USB Enumeration
;;; ============================================================

(defun ehci-read-desc-u16 (buf off)
  ;; Read little-endian u16 from buffer.
  (let ((b buf) (o off))
    (logior (mem-ref (+ b o) :u8) (ash (mem-ref (+ b (+ o 1)) :u8) 8))))

(defun ehci-find-bulk-eps (buf total-len)
  ;; Walk config descriptor to find bulk IN and OUT endpoints.
  ;; Stores EP numbers at 0x60017A/B, MPS at 0x60017C/E.
  (let ((b buf) (tl total-len))
    (let ((pos 0))
      (loop
        (when (>= pos tl) (return 0))
        (let ((dlen (mem-ref (+ b pos) :u8)))
          (when (zerop dlen) (return 0))
          (let ((dtype (mem-ref (+ b (+ pos 1)) :u8)))
            ;; Endpoint descriptor: type = 5, len >= 7
            (when (= dtype 5)
              (let ((ep-addr (mem-ref (+ b (+ pos 2)) :u8)))
                (let ((bmattr (mem-ref (+ b (+ pos 3)) :u8)))
                  (let ((mps (ehci-read-desc-u16 b (+ pos 4))))
                    ;; Bulk endpoint: bmAttributes bits 1:0 = 2
                    (when (= (logand bmattr 3) 2)
                      (if (zerop (logand ep-addr #x80))
                          ;; OUT endpoint
                          (progn
                            (setf (mem-ref #x60017B :u8) (logand ep-addr #xF))
                            (setf (mem-ref #x60017E :u8) (logand mps #xFF))
                            (setf (mem-ref #x60017F :u8) (logand (ash mps -8) #xFF)))
                        ;; IN endpoint
                        (progn
                          (setf (mem-ref #x60017A :u8) (logand ep-addr #xF))
                          (setf (mem-ref #x60017C :u8) (logand mps #xFF))
                          (setf (mem-ref #x60017D :u8) (logand (ash mps -8) #xFF))))))))))
          (setq pos (+ pos dlen)))))))

(defun ehci-enumerate-device (addr)
  ;; Enumerate device at USB addr. Assumes device already addressed.
  ;; Returns 1 if RTL8153 found.
  (let ((a addr))
    ;; GET_DEVICE_DESCRIPTOR (18 bytes)
    (ehci-get-descriptor a 1 0 (ehci-data-buf) 18)
    (let ((vid (ehci-read-desc-u16 (ehci-data-buf) 8)))
      (let ((pid (ehci-read-desc-u16 (ehci-data-buf) 10)))
        (write-char-output 86)    ; 'V'
        ;; Check for RTL8153: VID=0x0BDA, PID=0x8153
        (if (and (= vid #xBDA) (= pid #x8153))
            (progn
              (write-char-output 33)    ; '!'
              ;; GET_CONFIG_DESCRIPTOR
              (ehci-get-descriptor a 2 0 (ehci-data-buf) 9)
              (let ((total-len (ehci-read-desc-u16 (ehci-data-buf) 2)))
                (let ((tl (if (> total-len 512) 512 total-len)))
                  (ehci-get-descriptor a 2 0 (ehci-data-buf) tl)
                  (ehci-find-bulk-eps (ehci-data-buf) tl)))
              ;; SET_CONFIGURATION (config value = 1)
              (ehci-set-configuration a 1)
              ;; Store device address
              (setf (mem-ref #x600179 :u8) a)
              ;; Clear toggles
              (setf (mem-ref #x600180 :u8) 0)
              (setf (mem-ref #x600181 :u8) 0)
              1)
          (progn
            (write-char-output 45)    ; '-' = not RTL8153
            0))))))

;;; ============================================================
;;; RTL8153 Register Access
;;; ============================================================

(defun rtl-read-reg (reg mcu-type len)
  ;; Read RTL8153 register via vendor control transfer.
  ;; Result in ehci-data-buf.
  (let ((r reg) (m mcu-type) (l len))
    (let ((a (mem-ref #x600179 :u8)))
      (let ((mps (logior (mem-ref #x60017C :u8) (ash (mem-ref #x60017D :u8) 8))))
        (ehci-control-msg a mps #xC0 5 r m (ehci-data-buf) l)))))

(defun rtl-write-reg (reg mcu-type val len)
  ;; Write RTL8153 register via vendor control transfer.
  (let ((r reg) (m mcu-type) (v val) (l len))
    ;; Store value in data buf (little-endian)
    (setf (mem-ref (ehci-data-buf) :u8) (logand v #xFF))
    (when (> l 1)
      (setf (mem-ref (+ (ehci-data-buf) 1) :u8) (logand (ash v -8) #xFF)))
    (when (> l 2)
      (setf (mem-ref (+ (ehci-data-buf) 2) :u8) (logand (ash v -16) #xFF)))
    (when (> l 3)
      (setf (mem-ref (+ (ehci-data-buf) 3) :u8) (logand (ash v -24) #xFF)))
    (let ((a (mem-ref #x600179 :u8)))
      (let ((mps (logior (mem-ref #x60017C :u8) (ash (mem-ref #x60017D :u8) 8))))
        (ehci-control-msg a mps #x40 5 r m (ehci-data-buf) l)))))

(defun rtl-read-u8 (reg mcu)
  ;; Read 1-byte register, return value.
  (let ((r reg) (m mcu))
    (rtl-read-reg r m 4)
    (mem-ref (ehci-data-buf) :u8)))

(defun rtl-read-u16 (reg mcu)
  ;; Read 2-byte register, return value.
  (let ((r reg) (m mcu))
    (rtl-read-reg r m 4)
    (logior (mem-ref (ehci-data-buf) :u8)
            (ash (mem-ref (+ (ehci-data-buf) 1) :u8) 8))))

;;; ============================================================
;;; RTL8153 Initialization
;;; ============================================================

(defun rtl-read-mac ()
  ;; Read MAC address from PLA_IDR (0xC000), store at state+0x08.
  (rtl-read-reg #xC000 #x100 8)
  (let ((state (e1000-state-base)))
    (dotimes (i 6)
      (setf (mem-ref (+ state (+ 8 i)) :u8)
            (mem-ref (+ (ehci-data-buf) i) :u8))))
  (write-char-output 77))   ; 'M' = MAC read

(defun rtl-init-chip ()
  ;; Minimal RTL8153 initialization (based on U-Boot r8152.c).
  ;; MCU_TYPE_PLA = 0x100, MCU_TYPE_USB = 0
  ;; 1. Disable RX
  (rtl-write-reg #xC010 #x100 0 4)      ; PLA_RCR = 0
  ;; 2. Set RX max size (9728 bytes = 0x2600)
  (rtl-write-reg #xC016 #x100 #x2600 4) ; PLA_RMS
  ;; 3. Disable TX/RX aggregation
  (rtl-write-reg #xD40A 0 0 4)          ; USB_TX_AGG = 0
  ;; 4. Set RX buffer threshold
  (rtl-write-reg #xD40C 0 #x600 4)      ; USB_RX_BUF_TH (1536)
  ;; 5. Enable RX/TX in PLA_CR
  (let ((cr (rtl-read-u8 #xE813 #x100)))
    (rtl-write-reg #xE813 #x100 (logior cr #xC) 1))   ; CR_RE | CR_TE
  ;; 6. Ungate RX: clear RXDY_GATED_EN in PLA_OOB_CTRL
  (let ((oob (rtl-read-u16 #xE84F #x100)))
    (let ((new-oob (if (zerop (logand oob #x8)) oob (- oob #x8))))
      (rtl-write-reg #xE84F #x100 new-oob 2)))
  ;; 7. Set multicast filter to accept all
  (rtl-write-reg #xCD00 #x100 #xFFFFFFFF 4)
  (rtl-write-reg #xCD04 #x100 #xFFFFFFFF 4)
  ;; 8. Enable RX: accept all unicast/multicast/broadcast
  ;; RCR: AAP(0) | AM(1) | AB(3) | APM(1)
  (rtl-write-reg #xC010 #x100 #xF 4)    ; PLA_RCR = all accept
  (write-char-output 82))   ; 'R' = RTL init

;;; ============================================================
;;; RTL8153 Send/Receive (named ehci-net-* to avoid shadowing E1000 NIC)
;;; ============================================================

(defun ehci-net-send (buf len)
  ;; Send Ethernet frame via RTL8153.
  ;; Prepend 8-byte TX descriptor: opts1 = TX_FS|TX_LS|len, opts2 = 0.
  (let ((b buf) (l len))
    (let ((tx (ehci-tx-buf)))
      ;; TX descriptor opts1: bits 31:30 = FS|LS, bits 15:0 = length
      (let ((opts1 (logior #x30000000 (logior (ash #xC 28) l))))
        ;; Actually TX_FS=bit31, TX_LS=bit30 → 0xC0000000
        ;; But 0xC0000000 > fixnum max. Use two writes.
        (setf (mem-ref tx :u8) (logand l #xFF))
        (setf (mem-ref (+ tx 1) :u8) (logand (ash l -8) #xFF))
        (setf (mem-ref (+ tx 2) :u8) 0)
        (setf (mem-ref (+ tx 3) :u8) #xC0))   ; TX_FS | TX_LS in high byte
      ;; opts2 = 0
      (setf (mem-ref (+ tx 4) :u32) 0)
      ;; Copy frame data after 8-byte header
      (dotimes (i l)
        (setf (mem-ref (+ tx (+ 8 i)) :u8) (aref b i)))
      ;; Bulk OUT
      (let ((sent (ehci-bulk-out tx (+ l 8))))
        (if (> sent 0) 1 0)))))

(defun ehci-net-receive ()
  ;; Receive Ethernet frame via RTL8153.
  ;; Returns frame length or 0 if no data.
  (let ((rx (ehci-rx-buf)))
    (let ((got (ehci-bulk-in rx 2048)))
      (if (<= got 24) 0
        ;; Parse RX descriptor: opts1 at offset 0, length in bits 14:0
        (let ((opts1-lo (mem-ref rx :u8)))
          (let ((opts1-hi (mem-ref (+ rx 1) :u8)))
            (let ((pkt-len (logand (logior opts1-lo (ash opts1-hi 8)) #x7FFF)))
              ;; Subtract CRC (4 bytes), frame starts at offset 24
              (let ((frame-len (- pkt-len 4)))
                ;; Store frame length
                (setf (mem-ref (+ (e1000-state-base) #x44) :u32) frame-len)
                frame-len))))))))

(defun ehci-net-rx-buf ()
  ;; Return pointer to received frame data (after 24-byte RX descriptor).
  (+ (ehci-rx-buf) 24))

;;; ============================================================
;;; Probe: find EHCI → hub → RTL8153 → init networking
;;; ============================================================

(defun ehci-scan-split (hub-addr hub-port)
  ;; Scan addresses 1-8 using SPLIT transactions (periodic schedule).
  ;; For finding full-speed devices behind the Rate Matching Hub.
  (let ((ha hub-addr) (hp hub-port))
    (setf (mem-ref #x600190 :u8) ha)
    (setf (mem-ref #x600191 :u8) hp)
    (setf (mem-ref #x600192 :u8) 0)   ; speed = FS (split)
    (let ((addr 1))
      (loop
        (when (> addr 8) (return -1))
        (write-char-output (+ 48 addr))
        (let ((r (ehci-get-descriptor addr 1 0 (ehci-data-buf) 8)))
          (when (not (zerop r))
            (write-char-output 33)
            (return addr)))
        (setq addr (+ addr 1))))))

(defun ehci-enum-hub ()
  ;; After HCRESET + CONFIGFLAG, port 1 = Rate Matching Hub at address 0.
  ;; Enumerate it as a standard USB hub.
  (let ((port (ehci-find-device-port)))
    (when (< port 0)
      (write-char-output 110)
      (return 0))
    (write-char-output 112)
    ;; Port reset — device (RMH) comes back at address 0
    (let ((reset-ok (ehci-port-reset port)))
      (if (zerop reset-ok)
          (write-char-output 114)    ; 'r' = reset failed
        (write-char-output 82)))     ; 'R' = reset OK
    ;; Wait 100ms for device to initialize after reset
    (dotimes (i 100) (io-delay))
    ;; GET_DESCRIPTOR at addr 0 (should be the RMH hub)
    (setf (mem-ref #x600192 :u8) 2)  ; speed = HS for hub
    ;; Try GET_DESCRIPTOR — inline with debug
    (setf (mem-ref #x600192 :u8) 2)
    (ehci-build-setup #x80 6 #x100 0 8)
    (ehci-setup-work-qh 0 0 2 64)
    ;; GET_DESCRIPTOR via advance queue (3-qTD chain: SETUP+DATA+STATUS)
    (setf (mem-ref #x600192 :u8) 2)
    (let ((r (ehci-get-descriptor 0 1 0 (ehci-data-buf) 8)))
      (write-char-output 61)
      (vga-hex-byte (mem-ref (+ (ehci-work-qh) 24) :u8))
      (when (zerop r)
        (write-char-output 120)
        (return 0))
      (write-char-output 33))
    ;; SET_ADDRESS to 1
    (ehci-set-address 1)
    (dotimes (i 20) (io-delay))
    ;; Full descriptor + check class
    (ehci-get-descriptor 1 1 0 (ehci-data-buf) 18)
    ;; Print class byte and VID:PID
    (let ((cls (mem-ref (+ (ehci-data-buf) 4) :u8)))
      (write-char-output 99)    ; 'c'
      (vga-hex-byte cls)
      ;; Print VID (bytes 8-9) and PID (bytes 10-11)
      (write-char-output 118)   ; 'v'
      (vga-hex-byte (mem-ref (+ (ehci-data-buf) 9) :u8))
      (vga-hex-byte (mem-ref (+ (ehci-data-buf) 8) :u8))
      (write-char-output 58)    ; ':'
      (vga-hex-byte (mem-ref (+ (ehci-data-buf) 11) :u8))
      (vga-hex-byte (mem-ref (+ (ehci-data-buf) 10) :u8))
      (if (= cls 9)
          (progn
            (write-char-output 72)
            (ehci-set-configuration 1 1)
            (setf (mem-ref #x600190 :u8) 1)
            1)
        (progn
          (write-char-output 63)
          0)))))

(defun ehci-enum-hub-device ()
  ;; Find and enumerate RTL8153 on hub port. Returns 1 on success.
  (let ((hub-addr 1))
    ;; Get hub descriptor to find port count
    (ehci-control-msg hub-addr 64 #xA0 6 #x2900 0 (ehci-data-buf) 8)
    (let ((nports (mem-ref (+ (ehci-data-buf) 2) :u8)))
      (write-char-output (+ 48 nports))    ; print port count
      ;; Power all ports
      (let ((i 1))
        (loop
          (when (> i nports) (return 0))
          (ehci-hub-set-feature hub-addr 8 i)
          (setq i (+ i 1))))
      (dotimes (k 100) (io-delay))
      ;; Find connected port
      (let ((dev-port (ehci-hub-find-device hub-addr nports)))
        (when (zerop dev-port)
          (write-char-output 120)    ; 'x' = no device on hub
          (return 0))
        (write-char-output (+ 48 dev-port))   ; print port number
        (setf (mem-ref #x600182 :u8) dev-port)
        ;; Reset the port
        (ehci-hub-port-reset hub-addr dev-port)
        (dotimes (k 50) (io-delay))
        ;; Enumerate device at address 0 → set address to 2
        (ehci-set-address 2)
        (dotimes (k 20) (io-delay))
        ;; Check if it's RTL8153
        (ehci-enumerate-device 2)))))

(defun ehci-probe ()
  ;; Full probe: EHCI → hub → RTL8153 → MAC → init.
  ;; Overrides e1000-probe for USB networking.
  (write-char-output 85)    ; 'U' = USB probe start
  ;; Find and init EHCI
  (when (zerop (ehci-find-controller))
    (write-char-output 78)    ; 'N' = no EHCI
    (return 0))

  (ehci-init-controller)
  ;; Enumerate hub
  (when (zerop (ehci-enum-hub))
    (return 0))
  ;; Find RTL8153 on hub
  (when (zerop (ehci-enum-hub-device))
    (return 0))
  ;; Read MAC + init chip
  (rtl-read-mac)
  (rtl-init-chip)
  (write-char-output 10)
  (write-char-output 79)    ; 'O'
  (write-char-output 75)    ; 'K'
  (write-char-output 10)
  1)

;;; ============================================================
;;; Interactive diagnostics (callable from SSH REPL)
;;; ============================================================

(defun ehci-diag-find ()
  ;; Find EHCI controller on PCI, store BAR0. Returns 1 or 0.
  (ehci-find-controller))

(defun ehci-diag-init ()
  ;; Initialize EHCI controller (HCRESET + full setup).
  (ehci-init-controller))

(defun ehci-diag-status ()
  ;; Return USBSTS register value.
  (ehci-read 4))

(defun ehci-diag-cmd ()
  ;; Return USBCMD register value.
  (ehci-read 0))

(defun ehci-diag-frindex ()
  ;; Return FRINDEX (frame counter). Non-zero = SOF frames flowing.
  (ehci-read #xC))

(defun ehci-diag-port (port)
  ;; Return PORTSC for given port (0-based).
  (let ((p port))
    (ehci-read-port p)))

(defun ehci-diag-nports ()
  ;; Return number of root ports from HCSPARAMS.
  (logand (ehci-read-cap 4) #xF))

(defun ehci-diag-port-reset (port)
  ;; Reset a root port, return 1 if device enabled after reset.
  (let ((p port))
    (ehci-port-reset p)))

(defun ehci-diag-get-desc ()
  ;; Try GET_DESCRIPTOR at addr 0 (8 bytes). Return first byte or 0.
  (setf (mem-ref #x600192 :u8) 2)
  (let ((r (ehci-get-descriptor 0 1 0 (ehci-data-buf) 8)))
    (if (zerop r) 0
      (mem-ref (ehci-data-buf) :u8))))

(defun ehci-diag-scan-addr (addr)
  ;; Try GET_DESCRIPTOR at given addr. Return descriptor length or 0.
  (let ((a addr))
    (setf (mem-ref #x600192 :u8) 2)
    (let ((r (ehci-get-descriptor a 1 0 (ehci-data-buf) 18)))
      (if (zerop r) 0
        (mem-ref (ehci-data-buf) :u8)))))

(defun ehci-diag-scan ()
  ;; Scan USB addresses 0-8 for any responding device. Returns first found or -1.
  (setf (mem-ref #x600192 :u8) 2)
  (let ((addr 0))
    (loop
      (when (> addr 8) (return -1))
      (let ((r (ehci-get-descriptor addr 1 0 (ehci-data-buf) 8)))
        (when (not (zerop r))
          (return addr)))
      (setq addr (+ addr 1)))))

(defun ehci-diag-desc-bytes ()
  ;; Return first 4 bytes of last descriptor read as packed u32.
  ;; Call after ehci-diag-get-desc or ehci-diag-scan-addr.
  (let ((b0 (mem-ref (ehci-data-buf) :u8)))
    (let ((b1 (mem-ref (+ (ehci-data-buf) 1) :u8)))
      (let ((b2 (mem-ref (+ (ehci-data-buf) 2) :u8)))
        (let ((b3 (mem-ref (+ (ehci-data-buf) 3) :u8)))
          (let ((lo (logior b0 (ash b1 8))))
            (let ((hi (logior (ash b2 16) (ash b3 24))))
              (logior lo hi))))))))

(defun ehci-diag-qh-token ()
  ;; Return overlay token status byte from work QH.
  (mem-ref (+ (ehci-work-qh) 24) :u8))

(defun ehci-diag-bar0 ()
  ;; Return stored BAR0 as packed u32 (low 30 bits).
  (let ((b0 (mem-ref #x600170 :u8)))
    (let ((b1 (mem-ref #x600171 :u8)))
      (let ((b2 (mem-ref #x600172 :u8)))
        (let ((b3 (logand (mem-ref #x600173 :u8) #x3F)))
          (let ((lo (logior b0 (ash b1 8))))
            (let ((hi (logior (ash b2 16) (ash b3 24))))
              (logior lo hi))))))))

(defun ehci-diag-configflag ()
  ;; Return CONFIGFLAG register (should be 1).
  (ehci-read #x40))

(defun ehci-diag-pci-irq ()
  ;; Read PCI interrupt line for EHCI controller.
  (let ((dev (mem-ref #x600175 :u8)))
    (pci-read-raw 0 dev 0 #x3C)
    (mmio-result-byte 0)))
