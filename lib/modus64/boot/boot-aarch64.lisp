;;;; boot-aarch64.lisp - AArch64 Boot Sequence for Modus64
;;;;
;;;; AArch64 boot protocol (for -machine virt with UEFI or direct kernel):
;;;;   1. Firmware hands off in EL1 (or EL2 with virtualization)
;;;;   2. x0 = DTB pointer (or ACPI pointer)
;;;;   3. Set up page tables (4KB granule, 4-level or 3-level)
;;;;   4. Enable MMU (SCTLR_EL1.M = 1)
;;;;   5. Set up exception vectors (VBAR_EL1)
;;;;   6. Initialize PL011 UART (0x09000000 on QEMU virt)
;;;;   7. Set up GC metadata, NFN table, symbol table
;;;;   8. Initialize allocation registers (x24=alloc, x25=limit, x26=NIL)
;;;;   9. Call kernel-main
;;;;
;;;; SMP via PSCI (Power State Coordination Interface):
;;;;   - PSCI CPU_ON to wake secondary cores

(in-package :modus64.mvm)

;;; ============================================================
;;; AArch64 Boot Constants
;;; ============================================================

;; QEMU virt machine memory map
(defconstant +aarch64-uart-base+     #x09000000)   ; PL011 UART
(defconstant +aarch64-gic-dist+      #x08000000)   ; GIC Distributor
(defconstant +aarch64-gic-cpu+       #x08010000)   ; GIC CPU Interface
(defconstant +aarch64-gic-redist+    #x080A0000)   ; GICv3 Redistributor
(defconstant +aarch64-dram-base+     #x40000000)   ; DRAM start
(defconstant +aarch64-kernel-base+   #x40200000)   ; Kernel load address

;; Memory regions
(defconstant +aarch64-stack-top+     #x40400000)   ; Stack top
(defconstant +aarch64-page-tables+   #x40500000)   ; Page tables
(defconstant +aarch64-wired-base+    #x42000000)   ; Wired memory
(defconstant +aarch64-cons-base+     #x44000000)   ; Cons space
(defconstant +aarch64-general-base+  #x45000000)   ; General heap

;; Page table constants (4KB granule, Stage 1)
(defconstant +aarch64-page-size+     4096)
(defconstant +aarch64-pte-valid+     #x01)
(defconstant +aarch64-pte-table+     #x02)          ; Table descriptor (next level)
(defconstant +aarch64-pte-af+        (ash 1 10))    ; Access flag
(defconstant +aarch64-pte-sh-inner+  (ash 3 8))     ; Inner shareable
(defconstant +aarch64-pte-mair-wb+   (ash 0 2))     ; MAIR index 0 (write-back)

;; PSCI function IDs (SMC/HVC calling convention)
(defconstant +psci-cpu-on-64+        #xC4000003)
(defconstant +psci-cpu-off+          #x84000002)
(defconstant +psci-system-reset+     #x84000009)

;; Timer
(defconstant +aarch64-timer-irq+     27)            ; Virtual timer PPI

;;; ============================================================
;;; AArch64 Boot Code Generation
;;; ============================================================

(defun emit-aarch64-u32 (buf word)
  "Emit a 32-bit little-endian instruction into BUF."
  (mvm-emit-byte buf (ldb (byte 8  0) word))
  (mvm-emit-byte buf (ldb (byte 8  8) word))
  (mvm-emit-byte buf (ldb (byte 8 16) word))
  (mvm-emit-byte buf (ldb (byte 8 24) word)))

(defun emit-aarch64-movz (buf rd imm16 &optional (shift 0))
  "MOVZ Xd, #imm16{, LSL #shift}  shift=0,16,32,48"
  (let ((hw (/ shift 16)))
    (emit-aarch64-u32 buf (logior (ash 1 31)     ; sf=1
                                  (ash #b10 29)   ; opc=10 (MOVZ)
                                  (ash #b100101 23)
                                  (ash hw 21)
                                  (ash imm16 5)
                                  rd))))

(defun emit-aarch64-movk (buf rd imm16 &optional (shift 0))
  "MOVK Xd, #imm16{, LSL #shift}"
  (let ((hw (/ shift 16)))
    (emit-aarch64-u32 buf (logior (ash 1 31)     ; sf=1
                                  (ash #b11 29)   ; opc=11 (MOVK)
                                  (ash #b100101 23)
                                  (ash hw 21)
                                  (ash imm16 5)
                                  rd))))

(defun emit-aarch64-mov-sp (buf rd rn)
  "MOV Xd, Xn (using ADD Xd, Xn, #0 to handle SP correctly)"
  (emit-aarch64-u32 buf (logior (ash 1 31)       ; sf=1
                                (ash #b00 29)     ; op=0 (ADD), S=0
                                (ash #b100010 23) ; ADD imm
                                (ash 0 22)        ; shift=0
                                (ash 0 10)        ; imm12=0
                                (ash rn 5)
                                rd)))

(defun emit-aarch64-strb (buf rt rn)
  "STRB Wt, [Xn]  (unsigned offset 0)"
  (emit-aarch64-u32 buf (logior (ash #b00 30)     ; size=00 (byte)
                                (ash #b111001 24)  ; opc=00, STR
                                (ash 0 22)         ; opc=00
                                (ash 0 10)         ; imm12=0
                                (ash rn 5)
                                rt)))

(defun emit-aarch64-entry (buf)
  "Emit AArch64 EL1 kernel entry point.
   QEMU virt starts execution at the load address (0x40000000 or 0x40200000)
   with registers mostly zeroed. We need to:
   1. Set up SP
   2. Initialize PL011 UART at 0x09000000
   3. Set up allocation registers
   4. Fall through to native code"
  (let ((sp 31)   ; SP encoding in ADD/SUB context
        (x0 0) (x1 1) (x16 16) (x17 17)
        (x24 24) (x25 25) (x26 26))
    ;; 1. Set up stack pointer
    ;; MOV x16, #0x4040  (x16 = 0x40400000 = stack top)
    ;; MOVK x16, #0x0000, LSL #0
    ;; MOV SP, x16
    (emit-aarch64-movz buf x16 #x4040 16)   ; x16 = 0x40400000
    (emit-aarch64-mov-sp buf sp x16)         ; SP = x16

    ;; 2. Initialize PL011 UART at 0x09000000
    ;; Load UART base into x17
    (emit-aarch64-movz buf x17 #x0900 16)   ; x17 = 0x09000000

    ;; Disable UART: str wzr, [x17, #0x30] (UARTCR = 0)
    ;; Use a simpler approach: store bytes for key registers
    ;; UARTCR offset 0x30 = 48
    ;; For QEMU PL011, UART is already usable — just need to enable TX
    ;; Write UARTCR = 0x0301 (UARTEN | TXE | RXE)
    ;; Load 0x0301 into x0, store to [x17 + 0x30]
    (emit-aarch64-movz buf x0 #x0301 0)
    ;; STR w0, [x17, #0x30]  — unsigned offset, 32-bit store
    ;; Encoding: size=10 | 111001 | 00 | imm12 | Rn | Rt
    ;; imm12 = 0x30 / 4 = 12 (scaled by 4 for 32-bit)
    (emit-aarch64-u32 buf (logior (ash #b10 30)     ; size=10 (32-bit)
                                  (ash #b111001 24)  ; STR
                                  (ash 0 22)         ; opc=00
                                  (ash 12 10)        ; imm12=12 (offset 48/4)
                                  (ash x17 5)        ; Rn
                                  x0))               ; Rt

    ;; Set UARTLCR_H = 0x70 (8-bit, FIFO enable)
    (emit-aarch64-movz buf x0 #x70 0)
    ;; STR w0, [x17, #0x2C]  imm12 = 0x2C / 4 = 11
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 11 10) (ash x17 5) x0))

    ;; Set UARTIBRD = 13  [x17 + #0x24]  imm12 = 0x24/4 = 9
    (emit-aarch64-movz buf x0 13 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 9 10) (ash x17 5) x0))

    ;; Set UARTFBRD = 1  [x17 + #0x28]  imm12 = 0x28/4 = 10
    (emit-aarch64-movz buf x0 1 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 10 10) (ash x17 5) x0))

    ;; Re-enable UART: UARTCR = 0x0301
    (emit-aarch64-movz buf x0 #x0301 0)
    (emit-aarch64-u32 buf (logior (ash #b10 30) (ash #b111001 24) (ash 0 22)
                                  (ash 12 10) (ash x17 5) x0))

    ;; 3. Initialize allocation registers
    ;; x24 = cons alloc pointer = 0x44000000
    (emit-aarch64-movz buf x24 #x4400 16)
    ;; x25 = alloc limit = 0x45000000
    (emit-aarch64-movz buf x25 #x4500 16)
    ;; x26 = NIL = 0 (already zero from QEMU reset, but be explicit)
    (emit-aarch64-movz buf x26 0 0)

    ;; 4. Set TPIDR_EL1 = BSP per-CPU data base (0x41200000)
    (emit-aarch64-movz buf x16 #x4120 16)     ; x16 = 0x41200000
    (emit-aarch64-u32 buf #xD518D090)          ; MSR TPIDR_EL1, x16

    ;; 5. Set VBAR_EL1 = exception vector table (at image offset 0x800)
    ;; Image loads at 0x40000000 on QEMU virt, so vectors at 0x40000800
    (emit-aarch64-movz buf x16 #x4000 16)     ; x16 = 0x40000000
    (emit-aarch64-movk buf x16 #x0800 0)      ; x16 = 0x40000800
    (emit-aarch64-u32 buf #xD518C010)          ; MSR VBAR_EL1, x16
    (emit-aarch64-u32 buf #xD5033FDF)          ; ISB (sync system reg writes)

    ;; 6. Branch over exception vectors to native code
    ;; Vectors occupy 0x800-0x1000 (2KB). Native code starts at offset 0x1000.
    (let* ((current-insn (/ (mvm-buffer-position buf) 4))
           (native-start 1024)                  ; instruction 1024 = offset 0x1000
           (skip (- native-start current-insn)))
      ;; B forward to native code
      (emit-aarch64-u32 buf (logior (ash #b000101 26) (logand skip #x3FFFFFF)))
      ;; Pad with NOPs to offset 0x800 (instruction 512)
      (let ((pad (- 512 (/ (mvm-buffer-position buf) 4))))
        (dotimes (i pad)
          (emit-aarch64-u32 buf #xD503201F))))

    ;; 7. Exception vector table (2KB at offset 0x800)
    (emit-aarch64-exception-vectors buf)
    ;; Native code follows immediately (kernel-main at offset 0x1000)
    ))

(defun emit-aarch64-exception-vectors (buf)
  "Emit AArch64 exception vector table.
   Must be aligned to 2KB (0x800).
   4 exception levels × 4 types = 16 entries, 32 instructions each.
   Entry 5 (offset 0x280, Current EL with SP_ELx IRQ) has a real
   GICv2 IRQ handler. All others are infinite loops for debugging."
  ;; Exception vectors layout (16 entries × 32 instructions = 512 words):
  ;;   Entry 0 (0x000): Current EL, SP_EL0, Sync  → B .
  ;;   Entry 1 (0x080): Current EL, SP_EL0, IRQ   → B .
  ;;   Entry 2 (0x100): Current EL, SP_EL0, FIQ   → B .
  ;;   Entry 3 (0x180): Current EL, SP_EL0, SError → B .
  ;;   Entry 4 (0x200): Current EL, SP_ELx, Sync  → B .
  ;;   Entry 5 (0x280): Current EL, SP_ELx, IRQ   → GIC IRQ handler
  ;;   Entry 6 (0x300): Current EL, SP_ELx, FIQ   → B .
  ;;   Entry 7-15: Lower EL vectors               → B .
  (dotimes (entry 16)
    (if (= entry 5)
        ;; Entry 5: IRQ handler for Current EL with SP_ELx
        ;; This is the active IRQ vector when running in EL1 with SP_EL1.
        ;; Minimal handler: save regs, acknowledge GIC, restore, ERET.
        (progn
          ;; STP x0, x1, [SP, #-16]!    (save scratch regs)
          (mvm-emit-u32 buf #xA9BF07E0)
          ;; MOVZ x0, #0x0801, LSL #16  (x0 = 0x08010000 = GICC base)
          (mvm-emit-u32 buf #xD2A10020)
          ;; LDR w1, [x0, #0x0C]        (w1 = GICC_IAR — acknowledge IRQ)
          (mvm-emit-u32 buf #xB9400C01)
          ;; STR w1, [x0, #0x10]        (GICC_EOIR = w1 — end of interrupt)
          (mvm-emit-u32 buf #xB9001001)
          ;; LDP x0, x1, [SP], #16      (restore scratch regs)
          (mvm-emit-u32 buf #xA8C107E0)
          ;; ERET                        (return from exception)
          (mvm-emit-u32 buf #xD69F03E0)
          ;; Fill remaining 26 instructions with NOP
          (dotimes (i 26)
            (mvm-emit-u32 buf #xD503201F)))
        ;; All other entries: B . (infinite loop for debugging)
        (progn
          (mvm-emit-u32 buf #x14000000)    ; B . (branch to self)
          (dotimes (i 31)
            (mvm-emit-u32 buf #xD503201F))))))

;;; ============================================================
;;; AArch64 PL011 UART
;;; ============================================================

(defun aarch64-init-uart ()
  "Return PL011 UART initialization sequence.
   PL011 on QEMU virt at 0x09000000."
  (let ((base +aarch64-uart-base+))
    (list
     ;; Disable UART
     (cons (+ base #x30) #x0000)     ; UARTCR = 0
     ;; Set baud rate (115200 with 24MHz clock)
     ;; IBRD = 24000000 / (16 * 115200) = 13
     ;; FBRD = round(0.0208 * 64) = 1
     (cons (+ base #x24) 13)          ; UARTIBRD
     (cons (+ base #x28) 1)           ; UARTFBRD
     ;; 8N1, enable FIFO
     (cons (+ base #x2C) #x70)        ; UARTLCR_H: 8-bit, FIFO enable
     ;; Enable UART, TX, RX
     (cons (+ base #x30) #x0301))))   ; UARTCR: UARTEN | TXE | RXE

;;; ============================================================
;;; AArch64 GIC (Generic Interrupt Controller)
;;; ============================================================

(defun aarch64-init-gic ()
  "GIC initialization sequence (GICv2 for QEMU virt default)."
  (list
   ;; Enable distributor
   (cons (+ +aarch64-gic-dist+ #x000) 1)    ; GICD_CTLR = enable
   ;; Enable CPU interface
   (cons (+ +aarch64-gic-cpu+ #x000) 1)     ; GICC_CTLR = enable
   ;; Set priority mask (allow all)
   (cons (+ +aarch64-gic-cpu+ #x004) #xFF)  ; GICC_PMR = 0xFF
   ;; Enable timer interrupt (PPI 27)
   ;; GICD_ISENABLER1 (PPI enables)
   (cons (+ +aarch64-gic-dist+ #x104) (ash 1 (- +aarch64-timer-irq+ 16)))))

;;; ============================================================
;;; AArch64 SMP via PSCI
;;; ============================================================

(defun aarch64-start-cpu (cpu-id entry-addr context-id)
  "Generate PSCI CPU_ON call to start a secondary CPU.
   Uses SMC or HVC depending on conduit method (from DTB)."
  (list :psci-call
        :function-id +psci-cpu-on-64+
        :target-cpu cpu-id
        :entry-point entry-addr
        :context-id context-id))

(defun aarch64-percpu-layout ()
  "Per-CPU structure for AArch64.
   Accessed via TPIDR_EL1 (thread ID register)."
  '((:self-ptr       0   8)
    (:reduction       8   8)
    (:cpu-id         16   8)
    (:current-actor  24   8)
    (:obj-alloc      40   8)
    (:obj-limit      48   8)
    (:scratch-stack  56   8)))

;;; ============================================================
;;; AArch64 Page Table Setup
;;; ============================================================

(defun aarch64-setup-page-tables ()
  "AArch64 page table setup description.
   4KB granule, 4-level (48-bit VA):
   Level 0: 512GB per entry (L0 table)
   Level 1: 1GB per entry
   Level 2: 2MB per entry (block descriptors)
   Level 3: 4KB per entry (page descriptors)

   For QEMU virt: map first 4GB using 1GB block descriptors."
  '(:granule 4096
    :va-bits 48
    :levels 4
    :block-size-l1 #x40000000   ; 1GB
    :block-size-l2 #x200000     ; 2MB
    :identity-map-range (#x00000000 . #x100000000)))

;;; ============================================================
;;; AArch64 Boot Integration
;;; ============================================================

(defun aarch64-boot-descriptor ()
  "Return the AArch64 boot descriptor for image building"
  (list :arch :aarch64
        :entry-fn #'emit-aarch64-entry
        :exception-vectors-fn #'emit-aarch64-exception-vectors
        :uart-init-fn #'aarch64-init-uart
        :gic-init-fn #'aarch64-init-gic
        :smp-start-fn #'aarch64-start-cpu
        :percpu-layout-fn #'aarch64-percpu-layout
        :page-table-fn #'aarch64-setup-page-tables
        :load-addr +aarch64-kernel-base+
        :stack-top +aarch64-stack-top+
        :cons-base +aarch64-cons-base+
        :general-base +aarch64-general-base+))
