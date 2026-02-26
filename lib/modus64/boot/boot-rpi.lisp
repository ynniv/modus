;;;; boot-rpi.lisp - Raspberry Pi (AArch64) Boot Sequence for Modus64
;;;;
;;;; Raspberry Pi boot protocol (kernel8.img loaded by GPU firmware):
;;;;   1. GPU loads kernel8.img to 0x80000 (or 0x200000 with config.txt)
;;;;   2. CPU starts in EL2 (or EL1 depending on firmware)
;;;;   3. x0 = DTB pointer
;;;;   4. Only core 0 runs; cores 1-3 spin on mailbox
;;;;
;;;; QEMU raspi3b emulates BCM2837 (Cortex-A53, 4 cores):
;;;;   - PL011 UART at 0x3F201000
;;;;   - 1GB RAM at 0x00000000
;;;;   - Kernel loaded at 0x80000 (default for -kernel flag)
;;;;
;;;; Real RPi 5 (BCM2712) differences (for future):
;;;;   - UART at 0x1F00030000
;;;;   - 4/8GB RAM
;;;;   - kernel8.img loaded at 0x80000

(in-package :modus64.mvm)

;;; ============================================================
;;; Raspberry Pi Boot Constants
;;; ============================================================

;; RPi 3B memory map (BCM2837 / QEMU raspi3b)
(defconstant +rpi-uart-base+      #x3F201000)   ; PL011 UART
(defconstant +rpi-kernel-base+    #x00080000)   ; Kernel load address
(defconstant +rpi-stack-top+      #x00200000)   ; Stack top (2MB)
(defconstant +rpi-cons-base+      #x04000000)   ; Cons space (64MB)
(defconstant +rpi-general-base+   #x05000000)   ; General heap (80MB)

;;; ============================================================
;;; RPi Boot Code Generation
;;; ============================================================

(defun emit-rpi-entry (buf)
  "Emit Raspberry Pi AArch64 kernel entry point.
   The GPU firmware loads kernel8.img at 0x80000 and jumps there.
   We need to:
   1. Set up SP
   2. Initialize PL011 UART at 0x3F201000
   3. Set up allocation registers
   4. Fall through to native code"
  (let ((sp 31)   ; SP encoding in ADD/SUB context
        (x0 0) (x1 1) (x16 16) (x17 17)
        (x24 24) (x25 25) (x26 26))
    (declare (ignorable x1))
    ;; 1. Set up stack pointer
    ;; x16 = 0x00200000 (stack top, 2MB)
    (emit-aarch64-movz buf x16 #x0020 16)   ; x16 = 0x00200000
    (emit-aarch64-mov-sp buf sp x16)         ; SP = x16

    ;; 2. Initialize PL011 UART at 0x3F201000
    ;; Load UART base into x17
    ;; 0x3F201000 = 0x3F20 << 16 | 0x1000
    (emit-aarch64-movz buf x17 #x1000 0)    ; x17 = 0x1000
    (emit-aarch64-movk buf x17 #x3F20 16)   ; x17 = 0x3F201000

    ;; Disable UART first: UARTCR = 0
    ;; STR wzr, [x17, #0x30]  — store zero to control register
    ;; Use x0=0 temporarily
    (emit-aarch64-movz buf x0 0 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30)     ; size=10 (32-bit)
                                  (ash #b111001 24)  ; STR
                                  (ash 0 22)         ; opc=00
                                  (ash 12 10)        ; imm12=12 (offset 48/4)
                                  (ash x17 5)        ; Rn
                                  x0))               ; Rt

    ;; Set baud rate (115200 with 48MHz reference clock on RPi3)
    ;; IBRD = 48000000 / (16 * 115200) = 26
    ;; FBRD = round(0.0417 * 64) = 3
    ;; Set UARTIBRD = 26  [x17 + #0x24]  imm12 = 0x24/4 = 9
    (emit-aarch64-movz buf x0 26 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 9 10) (ash x17 5) x0))

    ;; Set UARTFBRD = 3  [x17 + #0x28]  imm12 = 0x28/4 = 10
    (emit-aarch64-movz buf x0 3 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 10 10) (ash x17 5) x0))

    ;; Set UARTLCR_H = 0x70 (8-bit, FIFO enable)
    ;; [x17 + #0x2C]  imm12 = 0x2C/4 = 11
    (emit-aarch64-movz buf x0 #x70 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 11 10) (ash x17 5) x0))

    ;; Enable UART: UARTCR = 0x0301 (UARTEN | TXE | RXE)
    ;; [x17 + #0x30]  imm12 = 0x30/4 = 12
    (emit-aarch64-movz buf x0 #x0301 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 12 10) (ash x17 5) x0))

    ;; 3. Initialize allocation registers
    ;; x24 = cons alloc pointer = 0x04000000
    (emit-aarch64-movz buf x24 #x0400 16)
    ;; x25 = alloc limit = 0x05000000
    (emit-aarch64-movz buf x25 #x0500 16)
    ;; x26 = NIL = 0
    (emit-aarch64-movz buf x26 0 0)

    ;; 4. Fall through to native code (kernel-main prologue follows)
    ))

;;; ============================================================
;;; RPi Boot Integration
;;; ============================================================

(defun rpi-boot-descriptor ()
  "Return the Raspberry Pi boot descriptor for image building.
   No :elf-machine → raw binary output (kernel8.img format).
   :serial-base is picked up by build-image to bind *aarch64-serial-base*
   during translation so the translator emits the RPi UART address."
  (list :arch :aarch64
        :entry-fn #'emit-rpi-entry
        :load-addr +rpi-kernel-base+
        :stack-top +rpi-stack-top+
        :cons-base +rpi-cons-base+
        :general-base +rpi-general-base+
        :serial-base +rpi-uart-base+))
