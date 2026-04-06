;;; i386-console.lisp — VGA text mode output + PS/2 keyboard for i386 direct boot
;;;
;;; Loaded AFTER repl-source.lisp so that write-char-output and read-char-input
;;; overrides take effect via last-defun-wins.
;;;
;;; VGA text mode (80x25) writes to 0xB8000. Works on any x86 with VGA.
;;; PS/2 keyboard via ports 0x60/0x64.
;;; No framebuffer — this is text mode only.
;;;
;;; Memory layout:
;;;   0x600130: vga_cursor_x (u32, raw text column)
;;;   0x600134: vga_cursor_y (u32, raw text row)
;;;   0x601800: scancode normal  (128 bytes)
;;;   0x601880: scancode shifted (128 bytes)
;;;   0x601900: shift_state (u32, 0 or 1)

;;; ============================================================
;;; VGA text mode output (80x25, buffer at 0xB8000)
;;; ============================================================
;;; Each cell: 2 bytes = char + attribute.
;;; Attribute 0x0F = bright white on black.

(defun vga-cursor-x ()  (mem-ref #x600130 :u32))
(defun vga-cursor-y ()  (mem-ref #x600134 :u32))
(defun vga-set-cursor-x (v) (setf (mem-ref #x600130 :u32) v))
(defun vga-set-cursor-y (v) (setf (mem-ref #x600134 :u32) v))

(defun vga-cell-addr (col row)
  (let ((c col) (r row))
    (+ #xB8000 (* (+ (* r 80) c) 2))))

(defun vga-put-char (addr ch)
  (let ((a addr) (c ch))
    (setf (mem-ref a :u8) c)
    (setf (mem-ref (+ a 1) :u8) #x0F)))

(defun vga-scroll-copy ()
  ;; Copy rows 1-24 to rows 0-23 using :u32 (4 bytes = 2 cells at a time)
  ;; 24 rows * 160 bytes/row = 3840 bytes = 960 u32s
  (let ((i 0))
    (loop
      (when (>= i 960) (return 0))
      (let ((off (* i 4)))
        (let ((src (+ #xB80A0 off)))
          (let ((dst (+ #xB8000 off)))
            (let ((val (mem-ref src :u32)))
              (setf (mem-ref dst :u32) val)))))
      (setq i (+ i 1)))))

(defun vga-scroll-clear ()
  ;; Clear last row (row 24): 40 u32s of 0x0F200F20 (2 cells each)
  (let ((i 0))
    (loop
      (when (>= i 40) (return 0))
      (let ((addr (+ #xB8F00 (* i 4))))
        (setf (mem-ref addr :u32) #x0F200F20))
      (setq i (+ i 1)))))

(defun vga-scroll ()
  (vga-scroll-copy)
  (vga-scroll-clear))

(defun vga-newline ()
  (vga-set-cursor-x 0)
  (let ((ny (+ (vga-cursor-y) 1)))
    (if (>= ny 25)
        (progn (vga-scroll)
               (vga-set-cursor-y 24))
      (vga-set-cursor-y ny))))

(defun vga-update-hw-cursor ()
  ;; Update VGA hardware cursor to match software position
  ;; CRTC index 0x0E = cursor high, 0x0F = cursor low
  (let ((pos (+ (* (vga-cursor-y) 80) (vga-cursor-x))))
    (let ((p pos))
      (io-out-byte #x3D4 #x0F)
      (io-out-byte #x3D5 (logand p #xFF))
      (io-out-byte #x3D4 #x0E)
      (io-out-byte #x3D5 (logand (ash p -8) #xFF)))))

(defun vga-advance-cursor ()
  (let ((nx (+ (vga-cursor-x) 1)))
    (if (>= nx 80)
        (vga-newline)
      (vga-set-cursor-x nx))))

(defun vga-write-char (ch)
  (let ((c ch))
    (cond
      ((= c 10) (vga-newline))
      ((= c 13) (vga-set-cursor-x 0))
      ((= c 8)
       (let ((x (vga-cursor-x)))
         (when (> x 0)
           (let ((nx (- x 1)))
             (vga-set-cursor-x nx)
             (let ((y (vga-cursor-y)))
               (let ((addr (vga-cell-addr nx y)))
                 (vga-put-char addr 32)))))))
      (t
       (when (>= c 32)
         (let ((cx (vga-cursor-x)))
           (let ((cy (vga-cursor-y)))
             (let ((addr (vga-cell-addr cx cy)))
               (vga-put-char addr c))))
         (vga-advance-cursor))))))

;;; ============================================================
;;; write-char-output override: serial + VGA text
;;; ============================================================

(defun write-char-output (c)
  (let ((ch c))
    (write-char-serial ch)
    (vga-write-char ch)
    (vga-update-hw-cursor)))

;;; ============================================================
;;; PS/2 keyboard input
;;; ============================================================

(defun ps2-data-ready ()
  (> (logand (io-in-byte #x64) 1) 0))

(defun ps2-read-scancode ()
  (io-in-byte #x60))

(defun ps2-shift-state () (mem-ref #x601900 :u32))
(defun ps2-set-shift (v) (setf (mem-ref #x601900 :u32) v))

(defun ps2-scancode-to-char (code)
  (let ((c code))
    (if (> (ps2-shift-state) 0)
        (mem-ref (+ #x601880 c) :u8)
      (mem-ref (+ #x601800 c) :u8))))

(defun ps2-poll-key ()
  ;; Returns ASCII char or 0 if no key available.
  ;; Handles shift state internally.
  (if (ps2-data-ready)
      (let ((scan (ps2-read-scancode)))
        (cond
          ;; Left shift press
          ((= scan #x2A) (ps2-set-shift 1) 0)
          ;; Right shift press
          ((= scan #x36) (ps2-set-shift 1) 0)
          ;; Left shift release
          ((= scan #xAA) (ps2-set-shift 0) 0)
          ;; Right shift release
          ((= scan #xB6) (ps2-set-shift 0) 0)
          ;; Key release (bit 7 set) — ignore
          ((> scan 127) 0)
          ;; Key press — look up in scancode table
          (t (ps2-scancode-to-char scan))))
    0))

;;; ============================================================
;;; Serial port non-blocking check
;;; ============================================================

(defun serial-data-ready ()
  ;; LSR=0xFF means no UART hardware (floating bus) — ignore
  (let ((lsr (io-in-byte #x3FD)))
    (if (= lsr #xFF) nil
      (> (logand lsr 1) 0))))

(defun serial-read-byte ()
  (io-in-byte #x3F8))

;;; ============================================================
;;; read-char-input override: PS/2 keyboard + serial
;;; ============================================================

(defun kbd-buf-next-scancode ()
  ;; Read next raw scancode from ISR ring buffer, or 0 if empty.
  ;; Ring buffer: 64 bytes at 0x600040, write idx at 0x600030, read idx at 0x600034.
  (let ((rd (mem-ref #x600034 :u32)))
    (let ((wr (mem-ref #x600030 :u32)))
      (if (= rd wr) 0
        (let ((sc (mem-ref (+ #x600040 rd) :u8)))
          (setf (mem-ref #x600034 :u32) (logand (+ rd 1) 63))
          sc)))))

(defun kbd-process-scancode (scan)
  ;; Convert raw scancode to ASCII. Returns 0 for non-character events.
  ;; Handles shift state tracking.
  (let ((s scan))
    (if (= s #x2A) (progn (ps2-set-shift 1) 0)
    (if (= s #x36) (progn (ps2-set-shift 1) 0)
    (if (= s #xAA) (progn (ps2-set-shift 0) 0)
    (if (= s #xB6) (progn (ps2-set-shift 0) 0)
    (if (> s 127) 0
      (ps2-scancode-to-char s))))))))

(defun nic-check-interrupt ()
  ;; Check for received packets (PIT-driven polling or NIC interrupt).
  ;; Process any pending packets. Returns 0.
  (let ((pkt-len (e1000-receive)))
    (when (not (zerop pkt-len))
      (nic-handle-one-packet pkt-len)))
  ;; Also clear NIC interrupt flag if set
  (when (not (zerop (mem-ref #x600020 :u32)))
    (setf (mem-ref #x600020 :u32) 0)
    (e1000-read-reg #xC0)
    (nic-irq-unmask))
  0)

(defun nic-handle-one-packet (pkt-len)
  ;; Dispatch one received packet by ethertype. VGA marker: '.' per packet.
  (write-char-output 46)
  (let ((pl pkt-len))
    (let ((buf (e1000-rx-buf)))
      (let ((et-hi (mem-ref (+ buf 12) :u8)))
        (when (eq et-hi 8)
          (let ((et-lo (mem-ref (+ buf 13) :u8)))
            (if (eq et-lo 6)
                (let ((op (buf-read-u16-mem buf 20)))
                  (when (eq op 1) (arp-reply buf)))
              (when (eq et-lo 0)
                (let ((st (e1000-state-base)))
                  (dotimes (m 6)
                    (setf (mem-ref (+ st (+ 40 m)) :u8)
                          (mem-ref (+ buf (+ 6 m)) :u8))))
                (let ((proto (mem-ref (+ buf 23) :u8)))
                  (if (eq proto 17)
                      (udp-receive buf pl)
                    (when (eq proto 6)
                      (net-handle-tcp buf pl))))))))))))

(defun nic-handle-packets ()
  ;; Drain all pending received packets.
  (let ((pkt-len (e1000-receive)))
    (when (not (zerop pkt-len))
      (nic-handle-one-packet pkt-len)
      (nic-handle-packets))))

(defun read-char-input ()
  ;; Interrupt-driven: wakes on keyboard IRQ, NIC IRQ, or PIT timer.
  ;; Processes NIC packets between keystrokes.
  (loop
    ;; Check keyboard ring buffer
    (let ((sc (kbd-buf-next-scancode)))
      (when (> sc 0)
        (let ((ch (kbd-process-scancode sc)))
          (when (> ch 0) (return ch)))))
    ;; Check serial
    (when (serial-data-ready)
      (return (serial-read-byte)))
    ;; Process NIC interrupt if pending
    (nic-check-interrupt)
    ;; Sleep until next interrupt
    (sti-hlt)
    (cli)))

;;; ============================================================
;;; PCI config space (ports 0xCF8/0xCFC)
;;; ============================================================
;;; On i386, fixnums are 31-bit. The PCI enable bit (bit 31) can't be
;;; represented in a fixnum (io-out-dword does SHR 1, clearing bit 31).
;;; Workaround: write address WITHOUT enable bit, then set enable via
;;; io-out-byte to port 0xCFB (byte 3 of the config address register).

(defun pci-addr (bus dev fn reg)
  ;; PCI config address WITHOUT enable bit (fits in 31-bit fixnum)
  (let ((b bus) (d dev))
    (let ((f fn) (r reg))
      (let ((a (ash b 16)))
        (let ((c (logior a (ash d 11))))
          (let ((e (logior c (ash f 8))))
            (logior e (logand r #xFC))))))))

(defun pci-set-addr (bus dev fn reg)
  ;; Write PCI config address with enable bit to port 0xCF8
  ;; Uses native TRAP since io-out-dword loses bit 31 (enable bit)
  (let ((addr (pci-addr bus dev fn reg)))
    (pci-config-read-raw addr)))

(defun pci-read (bus dev fn reg)
  ;; Read 32-bit PCI config register (result may lose bit 31 due to tagging)
  ;; Use pci-read-raw for full 32-bit results
  (let ((b bus) (d dev))
    (let ((f fn) (r reg))
      (let ((addr (pci-addr b d f r)))
        (pci-config-read-raw addr)
        (io-in-dword #xCFC)))))

(defun pci-write (bus dev fn reg val)
  ;; Write 32-bit PCI config register
  (let ((b bus) (d dev))
    (let ((f fn) (r reg))
      (let ((v val))
        (pci-set-addr b d f r)
        (io-out-dword #xCFC v)))))

(defun pci-read-raw (bus dev fn reg)
  ;; Read PCI config register with full 32-bit result (handles bit 31).
  ;; Uses native TRAP to OR enable bit and do full config cycle.
  ;; Result stored at 0x600148, returns byte 0. Use mmio-result-byte/mmio-print-result.
  (let ((b bus) (d dev))
    (let ((f fn) (r reg))
      (let ((addr (pci-addr b d f r)))
        (pci-config-read-raw addr)))))

;;; ============================================================
;;; Memory peek/poke (physical, no paging on i386 flat mode)
;;; ============================================================

(defun peek8 (addr)
  (mem-ref addr :u8))

(defun peek16 (addr)
  (mem-ref addr :u16))

(defun peek32 (addr)
  (mem-ref addr :u32))

(defun poke8 (addr val)
  (let ((a addr) (v val))
    (setf (mem-ref a :u8) v)))

(defun poke16 (addr val)
  (let ((a addr) (v val))
    (setf (mem-ref a :u16) v)))

(defun poke32 (addr val)
  (let ((a addr) (v val))
    (setf (mem-ref a :u32) v)))

;;; Note: io-in-byte/io-out-byte etc. are compiler primitives requiring
;;; constant ports, so they can't be wrapped as defuns for the REPL.
;;; Use pci-read/pci-write for PCI config and peek*/poke* for MMIO.

;;; ============================================================
;;; Raw MMIO for addresses above 2GB (TRAP-based, bypasses tagging)
;;; ============================================================
;;; On i386, fixnums are 31-bit. Addresses like 0xE0000000 (GPU BAR)
;;; can't be represented. These functions store raw 32-bit addresses
;;; byte-by-byte at 0x600140, then use TRAP opcodes to read/write
;;; using native MOV instructions that bypass fixnum tagging.
;;;
;;; Memory layout:
;;;   0x600140: raw address (4 bytes, little-endian)
;;;   0x600148: raw value   (4 bytes, little-endian)

(defun mmio-set-addr (b0 b1 b2 b3)
  ;; Store raw 32-bit address at 0x600140 as bytes (little-endian)
  ;; b0=low byte, b3=high byte. E.g. 0xE0200000 → (0 0 #x20 #xE0)
  (let ((a b0) (b b1))
    (let ((c b2) (d b3))
      (setf (mem-ref #x600140 :u8) a)
      (setf (mem-ref #x600141 :u8) b)
      (setf (mem-ref #x600142 :u8) c)
      (setf (mem-ref #x600143 :u8) d))))

(defun mmio-set-val (b0 b1 b2 b3)
  ;; Store raw 32-bit value at 0x600148 as bytes (little-endian)
  (let ((a b0) (b b1))
    (let ((c b2) (d b3))
      (setf (mem-ref #x600148 :u8) a)
      (setf (mem-ref #x600149 :u8) b)
      (setf (mem-ref #x60014A :u8) c)
      (setf (mem-ref #x60014B :u8) d))))

(defun mmio-result-byte (idx)
  ;; Read result byte from 0x600148 + idx
  (let ((i idx))
    (mem-ref (+ #x600148 i) :u8)))

(defun mmio-read32 (b0 b1 b2 b3)
  ;; Read 32-bit MMIO at raw address b3:b2:b1:b0. Returns byte 0 of result.
  ;; Full result accessible via (mmio-result-byte 0..3).
  (let ((a b0) (b b1))
    (let ((c b2) (d b3))
      (mmio-set-addr a b c d)
      (mmio-do-read32)
      (mmio-result-byte 0))))

(defun mmio-write32-go ()
  ;; Execute write: address at 0x600140, value at 0x600148. Set both first.
  (mmio-do-write32))

(defun mmio-print-result ()
  ;; Print the 32-bit result at 0x600148 as hex
  (let ((b3 (mmio-result-byte 3)))
    (let ((b2 (mmio-result-byte 2)))
      (let ((b1 (mmio-result-byte 1)))
        (let ((b0 (mmio-result-byte 0)))
          (print-nibble (logand (ash b3 -4) #xF))
          (print-nibble (logand b3 #xF))
          (print-nibble (logand (ash b2 -4) #xF))
          (print-nibble (logand b2 #xF))
          (print-nibble (logand (ash b1 -4) #xF))
          (print-nibble (logand b1 #xF))
          (print-nibble (logand (ash b0 -4) #xF))
          (print-nibble (logand b0 #xF)))))))

;;; --- Byte-wise address addition helpers (carry via 0x60015C) ---

(defun addr-add-byte0 (off)
  ;; Add off to byte 0 of address at 0x600140, carry at 0x60015C
  (let ((b (mem-ref #x600140 :u8)))
    (let ((o off))
      (let ((s (+ b o)))
        (setf (mem-ref #x600140 :u8) (logand s #xFF))
        (if (> s 255)
            (setf (mem-ref #x60015C :u8) 1)
          (setf (mem-ref #x60015C :u8) 0))))))

(defun addr-add-byte1 (off)
  (let ((b (mem-ref #x600141 :u8)))
    (let ((o off))
      (let ((c (mem-ref #x60015C :u8)))
        (let ((s (+ b (+ o c))))
          (setf (mem-ref #x600141 :u8) (logand s #xFF))
          (if (> s 255)
              (setf (mem-ref #x60015C :u8) 1)
            (setf (mem-ref #x60015C :u8) 0)))))))

(defun addr-add-byte2 (off)
  (let ((b (mem-ref #x600142 :u8)))
    (let ((o off))
      (let ((c (mem-ref #x60015C :u8)))
        (let ((s (+ b (+ o c))))
          (setf (mem-ref #x600142 :u8) (logand s #xFF)))))))

;;; --- GPU BAR0 base address (saved at 0x600150, 4 bytes) ---

(defun gpu-bar0-save ()
  ;; Read BAR0 via raw PCI, save at 0x600150 (masked, 4KB aligned)
  (pci-read-raw 0 2 0 #x10)
  (let ((b0 (logand (mmio-result-byte 0) #xF0)))
    (let ((b1 (mmio-result-byte 1)))
      (let ((b2 (mmio-result-byte 2)))
        (let ((b3 (mmio-result-byte 3)))
          (setf (mem-ref #x600150 :u8) b0)
          (setf (mem-ref #x600151 :u8) b1)
          (setf (mem-ref #x600152 :u8) b2)
          (setf (mem-ref #x600153 :u8) b3))))))

(defun gpu-mmio-setup (o0 o1 o2)
  ;; Set MMIO address to BAR0 + offset o2:o1:o0, ready for mmio-do-read32
  (let ((a o0) (b o1))
    (let ((c o2))
      ;; Copy BAR0 base to addr slot
      (setf (mem-ref #x600140 :u8) (mem-ref #x600150 :u8))
      (setf (mem-ref #x600141 :u8) (mem-ref #x600151 :u8))
      (setf (mem-ref #x600142 :u8) (mem-ref #x600152 :u8))
      (setf (mem-ref #x600143 :u8) (mem-ref #x600153 :u8))
      ;; Add offset with carry
      (addr-add-byte0 a)
      (addr-add-byte1 b)
      (addr-add-byte2 c))))

(defun gpu-mmio-read (o0 o1 o2)
  ;; Read GPU MMIO register at BAR0+offset, result at 0x600148
  (let ((a o0) (b o1))
    (let ((c o2))
      (gpu-mmio-setup a b c)
      (mmio-do-read32)
      (mmio-result-byte 0))))

;;; --- Raw PCI result check ---

(defun pci-result-is-ff ()
  ;; Check if raw result at 0x600148 is 0xFFFFFFFF (empty PCI slot)
  (let ((b0 (mmio-result-byte 0)))
    (if (= b0 #xFF)
        (let ((b1 (mmio-result-byte 1)))
          (if (= b1 #xFF)
              (let ((b2 (mmio-result-byte 2)))
                (if (= b2 #xFF)
                    (let ((b3 (mmio-result-byte 3)))
                      (= b3 #xFF))
                  nil))
            nil))
      nil)))

;;; ============================================================
;;; Hex output helpers
;;; ============================================================

(defun print-nibble (n)
  (let ((v n))
    (if (< v 10)
        (write-char-output (+ v 48))
      (write-char-output (+ v 55)))))

(defun print-hex8 (val)
  (let ((v val))
    (print-nibble (logand (ash v -4) #xF))
    (print-nibble (logand v #xF))))

(defun print-hex32 (val)
  (let ((v val))
    (print-hex8 (logand (ash v -24) #xFF))
    (print-hex8 (logand (ash v -16) #xFF))
    (print-hex8 (logand (ash v -8) #xFF))
    (print-hex8 (logand v #xFF))))

(defun print-str (s)
  (let ((str s))
    (let ((i 0))
      (let ((len (array-length str)))
        (loop
          (when (>= i len) (return 0))
          (write-char-output (aref str i))
          (setq i (+ i 1)))))))

(defun print-ln (s)
  (let ((str s))
    (print-str str)
    (write-char-output 10)))

(defun print-reg (name val)
  ;; Print "name: HEXVALUE\n"
  (let ((n name) (v val))
    (print-str n)
    (write-char-output 58)
    (write-char-output 32)
    (print-hex32 v)
    (write-char-output 10)))

(defun print-reg-raw (name)
  ;; Print "name: HEXVALUE\n" from raw result at 0x600148
  (let ((n name))
    (print-str n)
    (write-char-output 58)
    (write-char-output 32)
    (mmio-print-result)
    (write-char-output 10)))

;;; ============================================================
;;; PCI device scanner (uses raw reads for full 32-bit values)
;;; ============================================================

(defun pci-scan-print-dev (dev)
  ;; Print one PCI device line: "  DD: VENDORDEVICE CLASSREV\n"
  (let ((d dev))
    (print-str "  ")
    (print-hex8 d)
    (write-char-output 58)
    (write-char-output 32)
    (mmio-print-result)
    (pci-read-raw 0 d 0 8)
    (write-char-output 32)
    (mmio-print-result)
    (write-char-output 10)))

(defun pci-scan-bus ()
  ;; Scan PCI bus 0, print all devices found
  (let ((dev 0))
    (loop
      (when (>= dev 32) (return 0))
      (let ((d dev))
        (pci-read-raw 0 d 0 0)
        (when (not (pci-result-is-ff))
          (pci-scan-print-dev d)))
      (setq dev (+ dev 1)))))

;;; ============================================================
;;; Intel GPU diagnostic (Sandy Bridge / T420)
;;; ============================================================

(defun gpu-diag-mch ()
  ;; MCH registers (bus 0 dev 0)
  (print-ln "=== MCH (bus 0 dev 0) ===")
  (pci-read-raw 0 0 0 0)
  (print-reg-raw "VID:DID")
  (pci-read-raw 0 0 0 #xB0)
  (print-reg-raw "BDSM   ")
  (pci-read-raw 0 0 0 #xB8)
  (print-reg-raw "TSEGMB ")
  (pci-read-raw 0 0 0 #xBC)
  (print-reg-raw "TOLUD  "))

(defun gpu-diag-gpu ()
  ;; GPU registers (bus 0 dev 2)
  (print-ln "=== GPU (bus 0 dev 2) ===")
  (pci-read-raw 0 2 0 0)
  (print-reg-raw "VID:DID")
  (pci-read-raw 0 2 0 #x10)
  (print-reg-raw "BAR0   ")
  (pci-read-raw 0 2 0 #x18)
  (print-reg-raw "BAR2   ")
  (pci-read-raw 0 2 0 4)
  (print-reg-raw "CMD/STS"))

(defun gpu-diag ()
  (gpu-diag-mch)
  (gpu-diag-gpu)
  0)

;;; ============================================================
;;; GPU MMIO register reads (uses raw MMIO for >2GB addresses)
;;; ============================================================
;;; Call (gpu-bar0-save) first, then (gpu-mmio).
;;; Register offsets are passed as 3 little-endian bytes.

(defun gpu-mmio-print-reg (o0 o1 o2)
  ;; Read GPU MMIO register at BAR0+offset, print raw result + newline
  ;; Caller prints the label first
  (let ((a o0) (b o1))
    (let ((c o2))
      (gpu-mmio-read a b c)
      (write-char-output 58)
      (write-char-output 32)
      (mmio-print-result)
      (write-char-output 10))))

(defun gpu-mmio-part1 ()
  ;; First batch of MMIO reads (split to stay under sequential form limit)
  (print-str "MMIO base: ")
  (pci-read-raw 0 2 0 #x10)
  (mmio-print-result)
  (write-char-output 10)
  (gpu-bar0-save)
  (print-str "PIPECONF ")
  (gpu-mmio-print-reg #x08 #x00 #x07)
  (print-str "DSPCNTR  ")
  (gpu-mmio-print-reg #x80 #x01 #x07))

(defun gpu-mmio-part2 ()
  (print-str "DSPASTRD ")
  (gpu-mmio-print-reg #x88 #x01 #x07)
  (print-str "DSPAOFF  ")
  (gpu-mmio-print-reg #x84 #x01 #x07)
  (print-str "DSPASURF ")
  (gpu-mmio-print-reg #x9C #x01 #x07)
  (print-str "DSPASURFL")
  (gpu-mmio-print-reg #xAC #x01 #x07))

(defun gpu-mmio-part3 ()
  (print-str "HTOTAL-A ")
  (gpu-mmio-print-reg #x00 #x00 #x06)
  (print-str "VTOTAL-A ")
  (gpu-mmio-print-reg #x0C #x00 #x06))

(defun gpu-mmio ()
  (gpu-mmio-part1)
  (gpu-mmio-part2)
  (gpu-mmio-part3)
  0)

;;; Platform call dispatch is auto-generated at build time.
;;; See build-i386-diag.lisp: gen-dispatch-source.
