;;;; boot-riscv.lisp - RISC-V Boot Sequence for Modus64
;;;;
;;;; RISC-V boot protocol (for -machine virt with OpenSBI):
;;;;   1. Firmware (OpenSBI) hands off in M-mode or S-mode
;;;;   2. Hart ID in a0, DTB pointer in a1
;;;;   3. Set up page tables (Sv39 or Sv48)
;;;;   4. Enable MMU
;;;;   5. Set up trap handler (stvec)
;;;;   6. Initialize UART (NS16550 at 0x10000000 on QEMU virt)
;;;;   7. Set up GC metadata, NFN table, symbol table
;;;;   8. Initialize allocation registers (s8=alloc, s9=limit, s10=NIL)
;;;;   9. Call kernel-main
;;;;
;;;; SMP via SBI HSM extension:
;;;;   - sbi_hart_start(hartid, start_addr, opaque) to wake secondary harts

(in-package :modus64.mvm)

;;; ============================================================
;;; RISC-V Boot Constants
;;; ============================================================

;; QEMU virt machine memory map
(defconstant +riscv-uart-base+      #x10000000)   ; NS16550 UART
(defconstant +riscv-plic-base+      #x0C000000)   ; Platform-Level Interrupt Controller
(defconstant +riscv-clint-base+     #x02000000)   ; Core-Local Interruptor
(defconstant +riscv-dram-base+      #x80000000)   ; DRAM start
(defconstant +riscv-kernel-base+    #x80200000)   ; Kernel load address (after OpenSBI)

;; Memory regions (within DRAM)
(defconstant +riscv-stack-top+      #x80400000)   ; 4MB into DRAM
(defconstant +riscv-page-tables+    #x80500000)   ; Page tables
(defconstant +riscv-wired-base+     #x82000000)   ; Wired memory
(defconstant +riscv-cons-base+      #x84000000)   ; Cons space
(defconstant +riscv-general-base+   #x85000000)   ; General heap

;; Sv39 page table constants
(defconstant +riscv-page-size+      4096)
(defconstant +riscv-pte-v+          #x01)          ; Valid
(defconstant +riscv-pte-r+          #x02)          ; Read
(defconstant +riscv-pte-w+          #x04)          ; Write
(defconstant +riscv-pte-x+          #x08)          ; Execute
(defconstant +riscv-pte-u+          #x10)          ; User
(defconstant +riscv-pte-g+          #x20)          ; Global
(defconstant +riscv-pte-a+          #x40)          ; Accessed
(defconstant +riscv-pte-d+          #x80)          ; Dirty

;; SBI extension IDs
(defconstant +sbi-ext-hsm+         #x48534D)      ; Hart State Management
(defconstant +sbi-hsm-hart-start+  0)
(defconstant +sbi-hsm-hart-stop+   1)
(defconstant +sbi-hsm-hart-status+ 2)

;;; ============================================================
;;; RISC-V Boot Code Generation
;;; ============================================================

(defun emit-riscv-u32 (buf word)
  "Emit a 32-bit little-endian RISC-V instruction."
  (mvm-emit-byte buf (ldb (byte 8  0) word))
  (mvm-emit-byte buf (ldb (byte 8  8) word))
  (mvm-emit-byte buf (ldb (byte 8 16) word))
  (mvm-emit-byte buf (ldb (byte 8 24) word)))

(defun riscv-lui (rd imm20)
  "Encode LUI rd, imm20"
  (logior (ash (logand imm20 #xFFFFF) 12)
          (ash rd 7)
          #x37))

(defun riscv-addi (rd rs1 imm12)
  "Encode ADDI rd, rs1, imm12"
  (logior (ash (logand imm12 #xFFF) 20)
          (ash rs1 15)
          (ash #b000 12)
          (ash rd 7)
          #x13))

(defun riscv-sb (rs2 rs1 imm12)
  "Encode SB rs2, imm12(rs1)"
  (let ((imm-11-5 (logand (ash imm12 -5) #x7F))
        (imm-4-0  (logand imm12 #x1F)))
    (logior (ash imm-11-5 25)
            (ash rs2 20)
            (ash rs1 15)
            (ash #b000 12)
            (ash imm-4-0 7)
            #x23)))

(defun riscv-slli (rd rs1 shamt)
  "Encode SLLI rd, rs1, shamt (6-bit for RV64)"
  (logior (ash (logand shamt #x3F) 20)
          (ash rs1 15)
          (ash #b001 12)
          (ash rd 7)
          #x13))

(defun riscv-srli (rd rs1 shamt)
  "Encode SRLI rd, rs1, shamt (6-bit for RV64)"
  (logior (ash (logand shamt #x3F) 20)
          (ash rs1 15)
          (ash #b101 12)
          (ash rd 7)
          #x13))

(defun emit-riscv-entry (buf)
  "Emit RISC-V kernel entry point.
   QEMU virt with -bios none starts at 0x80000000.
   We need to:
   1. Set up SP
   2. Initialize NS16550 UART at 0x10000000
   3. Set up allocation registers (s8=alloc, s9=limit, s10=nil)
   4. Fall through to native code"
  ;; Register numbers: sp=2, t0=5, t1=6, s8=24, s9=25, s10=26
  (let ((sp 2) (t0 5) (t1 6) (s8 24) (s9 25) (s10 26))
    ;; 1. Set up stack pointer: SP = 0x80400000
    ;; LUI sign-extends on RV64: lui sp, 0x80400 gives 0xFFFFFFFF80400000
    ;; Fix: SLLI+SRLI to clear upper 32 bits
    (emit-riscv-u32 buf (riscv-lui sp #x80400))
    (emit-riscv-u32 buf (riscv-slli sp sp 32))
    (emit-riscv-u32 buf (riscv-srli sp sp 32))

    ;; 2. Initialize NS16550 UART at 0x10000000
    ;; LUI t1, 0x10000  (t1 = 0x10000000)
    (emit-riscv-u32 buf (riscv-lui t1 #x10000))

    ;; Disable interrupts: SB x0, 1(t1)  [IER = 0]
    (emit-riscv-u32 buf (riscv-sb 0 t1 1))
    ;; Enable DLAB: LI t0, 0x80; SB t0, 3(t1)  [LCR = 0x80]
    (emit-riscv-u32 buf (riscv-addi t0 0 #x80))
    (emit-riscv-u32 buf (riscv-sb t0 t1 3))
    ;; Baud divisor low = 1: LI t0, 1; SB t0, 0(t1)  [DLL = 1]
    (emit-riscv-u32 buf (riscv-addi t0 0 1))
    (emit-riscv-u32 buf (riscv-sb t0 t1 0))
    ;; Baud divisor high = 0: SB x0, 1(t1)  [DLM = 0]
    (emit-riscv-u32 buf (riscv-sb 0 t1 1))
    ;; 8N1: LI t0, 3; SB t0, 3(t1)  [LCR = 0x03]
    (emit-riscv-u32 buf (riscv-addi t0 0 3))
    (emit-riscv-u32 buf (riscv-sb t0 t1 3))
    ;; Enable FIFO: LI t0, 1; SB t0, 2(t1)  [FCR = 0x01]
    (emit-riscv-u32 buf (riscv-addi t0 0 1))
    (emit-riscv-u32 buf (riscv-sb t0 t1 2))

    ;; 3. Set up allocation registers
    ;; s8 (cons alloc) = 0x84000000 (LUI sign-extends, fix with SLLI+SRLI)
    (emit-riscv-u32 buf (riscv-lui s8 #x84000))
    (emit-riscv-u32 buf (riscv-slli s8 s8 32))
    (emit-riscv-u32 buf (riscv-srli s8 s8 32))
    ;; s9 (alloc limit) = 0x85000000
    (emit-riscv-u32 buf (riscv-lui s9 #x85000))
    (emit-riscv-u32 buf (riscv-slli s9 s9 32))
    (emit-riscv-u32 buf (riscv-srli s9 s9 32))
    ;; s10 (nil) = 0
    (emit-riscv-u32 buf (riscv-addi s10 0 0))

    ;; 4. Fall through to native code
    ))

(defun emit-riscv-trap-handler (buf)
  "Emit RISC-V trap handler (stvec target).
   Handles:
   - Timer interrupts (for preemption)
   - External interrupts (PLIC)
   - Exceptions (page faults, illegal instruction)"
  (dotimes (i 256)
    (mvm-emit-byte buf #x13)))  ; Placeholder

;;; ============================================================
;;; RISC-V UART (NS16550)
;;; ============================================================

(defun riscv-init-uart ()
  "Return UART initialization sequence for NS16550 at QEMU virt address.
   The NS16550 on QEMU virt is memory-mapped at 0x10000000."
  (list
   ;; Disable interrupts
   (cons (+ +riscv-uart-base+ 1) #x00)
   ;; Enable DLAB
   (cons (+ +riscv-uart-base+ 3) #x80)
   ;; Baud rate divisor = 1 (115200 baud)
   (cons (+ +riscv-uart-base+ 0) #x01)
   (cons (+ +riscv-uart-base+ 1) #x00)
   ;; 8N1
   (cons (+ +riscv-uart-base+ 3) #x03)
   ;; Enable FIFO
   (cons (+ +riscv-uart-base+ 2) #x01)))

;;; ============================================================
;;; RISC-V SMP via SBI HSM
;;; ============================================================

(defun riscv-start-hart (hartid entry-addr opaque)
  "Generate SBI call to start a secondary hart.
   SBI calling convention: a7 = extension ID, a6 = function ID,
   a0-a5 = arguments. Returns in a0 (error code) and a1 (value)."
  (list :sbi-call
        :ext-id +sbi-ext-hsm+
        :fn-id +sbi-hsm-hart-start+
        :args (list hartid entry-addr opaque)))

(defun riscv-percpu-layout ()
  "Per-CPU structure for RISC-V. Accessed via tp (thread pointer) register."
  '((:self-ptr       0   8)
    (:reduction       8   8)
    (:hart-id        16   8)
    (:current-actor  24   8)
    (:obj-alloc      40   8)
    (:obj-limit      48   8)
    (:scratch-stack  56   8)))

;;; ============================================================
;;; RISC-V Page Table Setup
;;; ============================================================

(defun riscv-setup-sv39 ()
  "Sv39 page table setup description.
   3-level page table: root → level-1 → level-0 → 4KB pages
   Virtual address: [VPN[2]:9][VPN[1]:9][VPN[0]:9][offset:12]
   PTE: [reserved:10][PPN[2]:26][PPN[1]:9][PPN[0]:9][RSW:2][DAGUXWRV:8]
   For QEMU virt: identity map first 1GB using 1GB mega-pages."
  '(:mode :sv39
    :levels 3
    :page-size 4096
    :mega-page-size #x40000000    ; 1GB
    :identity-map-range (#x00000000 . #x100000000)))

;;; ============================================================
;;; RISC-V Boot Integration
;;; ============================================================

(defun riscv-boot-descriptor ()
  "Return the RISC-V boot descriptor for image building"
  (list :arch :riscv64
        :entry-fn #'emit-riscv-entry
        :trap-handler-fn #'emit-riscv-trap-handler
        :uart-init-fn #'riscv-init-uart
        :smp-start-fn #'riscv-start-hart
        :percpu-layout-fn #'riscv-percpu-layout
        :page-table-fn #'riscv-setup-sv39
        :load-addr +riscv-kernel-base+
        :stack-top +riscv-stack-top+
        :cons-base +riscv-cons-base+
        :general-base +riscv-general-base+))
