;;;; cdc-ether.lisp - USB CDC Ethernet driver
;;;;
;;;; Replaces e1000.lisp for USB-based networking (Raspberry Pi, QEMU usb-net).
;;;; Provides the same NIC interface expected by ip.lisp:
;;;;   e1000-send, e1000-receive, e1000-rx-buf, e1000-probe
;;;;
;;;; CDC Ethernet uses raw Ethernet frames over USB bulk endpoints:
;;;;   Bulk OUT = send Ethernet frame
;;;;   Bulk IN  = receive Ethernet frame
;;;; No extra framing headers (unlike RNDIS or LAN9514).
;;;;
;;;; Depends on: dwc2.lisp, usb.lisp, arch adapter (e1000-state-base, etc.)

;; ============================================================
;; Buffer layout
;; Reuses the same memory regions as E1000 (defined in arch adapter):
;;   e1000-rx-buf-base: receive buffer (single buffer, 2048 bytes)
;;   e1000-tx-buf-base: transmit buffer (single buffer, 1536 bytes)
;;   e1000-state-base:  network state (same layout as ip.lisp expects)
;; ============================================================

;; RX state: position and length of last received packet
;; stored in state-base+0x10 (rx-cur) and state-base+0x44 (rx-pkt-len)
(defun cdc-rx-buf-addr ()
  ;; Single RX buffer for USB bulk IN
  (e1000-rx-buf-base))

(defun cdc-tx-buf-addr ()
  ;; Single TX buffer for USB bulk OUT
  (e1000-tx-buf-base))

;; ============================================================
;; CDC Ethernet initialization
;; Uses loop + return for early exit (MVM doesn't support return-from)
;; ============================================================

(defun cdc-ether-init ()
  ;; Initialize DWC2 + USB + CDC Ethernet.
  ;; Returns 1 on success, 0 on failure.
  (loop
    ;; 1. Initialize DWC2 host controller
    (let ((r1 (dwc2-init)))
      (when (zerop r1)
        (write-byte 67) (write-byte 68) (write-byte 67)  ; "CDC"
        (write-byte 58) (write-byte 69) (write-byte 49)  ; ":E1"
        (write-byte 10)
        (return 0))

      ;; 2. Enumerate USB device
      (let ((r2 (usb-enumerate)))
        (when (zerop r2)
          (write-byte 67) (write-byte 68) (write-byte 67)  ; "CDC"
          (write-byte 58) (write-byte 69) (write-byte 50)  ; ":E2"
          (write-byte 10)
          (return 0))

        ;; 3. Initialize network state
        (let ((state (e1000-state-base)))
          ;; Store a default MAC address (52:54:00:12:34:56)
          ;; QEMU assigns this to usb-net by default
          (setf (mem-ref (+ state #x08) :u8) #x52)
          (setf (mem-ref (+ state #x09) :u8) #x54)
          (setf (mem-ref (+ state #x0A) :u8) #x00)
          (setf (mem-ref (+ state #x0B) :u8) #x12)
          (setf (mem-ref (+ state #x0C) :u8) #x34)
          (setf (mem-ref (+ state #x0D) :u8) #x56)

          ;; Initialize cursors
          (setf (mem-ref (+ state #x10) :u32) 0)  ; RX cursor
          (setf (mem-ref (+ state #x14) :u32) 0)  ; TX cursor
          (setf (mem-ref (+ state #x44) :u32) 0)  ; RX packet length

          ;; Default IP (will be overwritten by DHCP)
          (setf (mem-ref (+ state #x18) :u32) #x0F02000A)  ; 10.0.2.15
          (setf (mem-ref (+ state #x1C) :u32) #x0202000A)  ; 10.0.2.2

          ;; Print MAC
          (write-byte 77) (write-byte 65) (write-byte 67) (write-byte 58)  ; "MAC:"
          (print-hex-byte #x52) (write-byte 58)
          (print-hex-byte #x54) (write-byte 58)
          (print-hex-byte #x00) (write-byte 58)
          (print-hex-byte #x12) (write-byte 58)
          (print-hex-byte #x34) (write-byte 58)
          (print-hex-byte #x56) (write-byte 10)

          ;; Print status
          (write-byte 67) (write-byte 68) (write-byte 67)  ; "CDC"
          (write-byte 58) (write-byte 79) (write-byte 75)  ; ":OK"
          (write-byte 10)

          ;; Start the first bulk IN transfer (persistent channel).
          ;; DWC2's work_bh will auto-retry NAK'd transfers.
          ;; Subsequent calls to usb-bulk-receive just poll for completion.
          (dwc2-start-bulk-in 1 (usb-dev-addr) (usb-bulk-in-ep)
                              (cdc-rx-buf-addr) 2048 (usb-bulk-in-mps))
          (return 1))))))

;; ============================================================
;; NIC interface (same signatures as e1000.lisp)
;; ============================================================

;; Send raw Ethernet frame from byte array.
;; buf: Lisp byte array, len: frame length in bytes.
;; Returns 1 on success, 0 on failure.
(defun e1000-send (buf len)
  (let ((tx-buf (cdc-tx-buf-addr)))
    ;; Copy from Lisp array to DMA buffer
    (let ((i 0))
      (loop
        (when (>= i len) (return nil))
        (setf (mem-ref (+ tx-buf i) :u8) (aref buf i))
        (setq i (+ i 1))))
    ;; USB bulk OUT
    (let ((result (usb-bulk-send tx-buf len)))
      (if (eq result 1) 1 0))))

;; Check for received packet. Returns length or 0 if none.
(defun e1000-receive ()
  ;; Read HCTSIZ BEFORE polling — the poll may start a new transfer,
  ;; overwriting the register. We need the remaining bytes from the
  ;; completed transfer to compute the actual received length.
  (let ((hctsiz-before (dwc2-read (dwc2-hctsiz 1))))
    (let ((result (usb-bulk-receive (cdc-rx-buf-addr) 2048)))
      (if (eq result 1)
          ;; Data received. Use saved HCTSIZ to compute actual length.
          (let ((remaining (logand hctsiz-before #x7FFFF)))
            (let ((actual (- 2048 remaining)))
              (setf (mem-ref (+ (e1000-state-base) #x44) :u32) actual)
              actual))
          ;; No data or error
          0))))

;; Get pointer to current RX buffer data (physical address).
;; Called after e1000-receive returns non-zero.
(defun e1000-rx-buf ()
  (cdc-rx-buf-addr))

;; Find NIC and initialize. Main entry point (same name as e1000.lisp).
;; On RPi, this initializes USB + CDC Ethernet instead of PCI + E1000.
(defun e1000-probe ()
  (cdc-ether-init))

;; ============================================================
;; E1000 register stubs (called by ip.lisp init functions)
;; These are no-ops since we don't have E1000 hardware.
;; ============================================================

(defun e1000-write-reg (reg val) nil)
(defun e1000-read-reg (reg) 0)
