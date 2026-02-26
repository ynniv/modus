;;;; boot-68k.lisp - Motorola 68k Boot Sequence for Modus64
;;;;
;;;; 68k boot protocol (for qemu-system-m68k -machine virt -kernel):
;;;;   1. QEMU loads kernel image at load address
;;;;   2. Exception vectors at address 0: SSP and PC
;;;;   3. CPU reads initial SSP from vector 0, initial PC from vector 1
;;;;   4. Set up stack pointer (A7/SP)
;;;;   5. Initialize allocation registers (A2=alloc, A3=limit, A4=NIL)
;;;;   6. Initialize Goldfish/ColdFire-compatible UART at MMIO base
;;;;   7. Set up GC metadata, NFN table, symbol table
;;;;   8. Call kernel-main
;;;;
;;;; No MMU setup needed (flat 32-bit address space).
;;;; No SMP -- single core only.
;;;; All instructions are BIG-ENDIAN, word-aligned (16-bit minimum).
;;;;
;;;; Register conventions (from translate-68k.lisp):
;;;;   A2 = VA (alloc pointer)
;;;;   A3 = VL (alloc limit)
;;;;   A4 = VN (NIL constant)
;;;;   A6 = VFP (frame pointer)
;;;;   A7 = VSP (stack pointer / SP)
;;;;   A0, A1 = scratch (caller-saved)
;;;;   D0-D7 = data registers (mapped to V0-V7)

(in-package :modus64.mvm)

;;; ============================================================
;;; 68k Boot Constants
;;; ============================================================

;; QEMU virt machine memory map
(defconstant +m68k-kernel-base+    #x10000)       ; 64KB - kernel load address
(defconstant +m68k-stack-top+      #x800000)      ; 8MB - stack top (grows down)
(defconstant +m68k-uart-base+      #xFF008000)    ; Goldfish TTY PUT_CHAR register

;; Memory regions (heap)
(defconstant +m68k-cons-base+      #x900000)      ; 9MB - cons space
(defconstant +m68k-general-base+   #xA00000)      ; 10MB - general heap

;; Exception vector table
(defconstant +m68k-vectors-base+   #x000000)      ; Vectors at address 0
(defconstant +m68k-num-vectors+    256)            ; 256 exception vectors

;;; ============================================================
;;; 68k Big-Endian Emit Helpers
;;; ============================================================
;;;
;;; The standard mvm-emit-u16/u32 are little-endian.
;;; 68k is big-endian, so we need MSB-first emit functions.

(defun emit-m68k-word (buf w)
  "Emit a 16-bit word in big-endian order (MSB first)."
  (mvm-emit-byte buf (ldb (byte 8 8) w))
  (mvm-emit-byte buf (ldb (byte 8 0) w)))

(defun emit-m68k-long (buf l)
  "Emit a 32-bit long in big-endian order (MSB first)."
  (mvm-emit-byte buf (ldb (byte 8 24) l))
  (mvm-emit-byte buf (ldb (byte 8 16) l))
  (mvm-emit-byte buf (ldb (byte 8 8) l))
  (mvm-emit-byte buf (ldb (byte 8 0) l)))

;;; ============================================================
;;; 68k Instruction Encoding
;;; ============================================================
;;;
;;; move.l #imm32, An  -> word: 2x7C (where x = An encoding), then 32-bit imm
;;;   A7 (SP): #x2E7C + imm32    A6 (FP): #x2C7C + imm32
;;;   A5:      #x2A7C + imm32    A4:      #x287C + imm32
;;;   A3:      #x267C + imm32    A2:      #x247C + imm32
;;; nop         -> #x4E71
;;; rts         -> #x4E75
;;; jmp abs.l   -> #x4EF9 + addr32
;;; move.b #imm8, (addr).l -> #x13FC + imm8(pad to word) + addr32

(defun emit-m68k-move-imm32-to-an (buf an-num imm32)
  "Emit: move.l #imm32, An  (68k big-endian)
   Opcode word: #x2(n*2)7C where n is the address register number.
   Encoding: 0010 Annn 01 111 100 = MOVE.L #imm, An"
  (let ((opword (logior #x207C (ash an-num 9))))
    (emit-m68k-word buf opword)
    (emit-m68k-long buf imm32)))

(defun emit-m68k-nop (buf)
  "Emit: nop (#x4E71)"
  (emit-m68k-word buf #x4E71))

(defun emit-m68k-rts (buf)
  "Emit: rts (#x4E75)"
  (emit-m68k-word buf #x4E75))

(defun emit-m68k-jmp-abs (buf addr)
  "Emit: jmp addr.l (#x4EF9 followed by 32-bit address)"
  (emit-m68k-word buf #x4EF9)
  (emit-m68k-long buf addr))

(defun emit-m68k-move-byte-to-abs (buf imm8 addr)
  "Emit: move.b #imm8, (addr).l
   Opcode: 0001 0011 1111 1100 = #x13FC
   Followed by: immediate byte (word-extended), then 32-bit address."
  (emit-m68k-word buf #x13FC)
  (emit-m68k-word buf (logand imm8 #xFF))
  (emit-m68k-long buf addr))

;;; ============================================================
;;; 68k Exception Vector Table
;;; ============================================================

(defun m68k-exception-vectors (buf)
  "Emit 68k exception vector table at address 0.
   Vector 0: Initial SSP (supervisor stack pointer)
   Vector 1: Initial PC (entry point = kernel base)
   Vectors 2-255: point to a default exception handler.
   Each vector is a 32-bit big-endian address."
  (let ((default-handler (+ +m68k-kernel-base+ 8))) ; skip past entry preamble
    ;; Vector 0: Initial SSP
    (emit-m68k-long buf +m68k-stack-top+)
    ;; Vector 1: Initial PC (kernel entry)
    (emit-m68k-long buf +m68k-kernel-base+)
    ;; Vectors 2-255: default handler
    (dotimes (i (- +m68k-num-vectors+ 2))
      (emit-m68k-long buf default-handler))))

;;; ============================================================
;;; 68k UART Initialization
;;; ============================================================

(defun m68k-init-serial (buf)
  "Initialize the QEMU virt machine UART for serial output.
   The Goldfish/ColdFire-compatible UART at +m68k-uart-base+ uses
   simple MMIO register writes. For the QEMU m68k virt platform:
     base+0x00 = data/transmit register
     base+0x04 = status/control register
   We emit move.b instructions to configure the UART for basic TX."
  ;; Enable transmitter: write configuration byte to control register
  ;; For Goldfish UART, writing to the data register is sufficient
  ;; for output; minimal init required on QEMU virt.
  ;; Write a control byte to status register to enable TX
  (emit-m68k-move-byte-to-abs buf #x01 (+ +m68k-uart-base+ #x04))
  ;; NOP barrier (allow UART hardware to settle)
  (emit-m68k-nop buf)
  (emit-m68k-nop buf))

;;; ============================================================
;;; 68k Kernel Entry Point
;;; ============================================================

(defun emit-m68k-entry (buf)
  "Emit the 68k kernel entry point.
   This is the first code executed after the CPU reads the initial
   PC from exception vector 1.

   Steps:
     1. Set stack pointer A7/SP = +m68k-stack-top+
     2. Set frame pointer A6/FP = 0 (no previous frame)
     3. Set allocation pointer A2 = +m68k-cons-base+
     4. Set allocation limit A3 = +m68k-general-base+
     5. Set NIL register A4 = tag for NIL (will be patched by kernel)
     6. Initialize serial (UART)
     7. Fall through to translated native code

   All instructions emitted in big-endian byte order."
  ;; 1. Set up stack pointer: move.l #stack_top, A7
  (emit-m68k-move-imm32-to-an buf 7 +m68k-stack-top+)

  ;; 2. Set up frame pointer: move.l #0, A6 (no previous frame)
  (emit-m68k-move-imm32-to-an buf 6 #x00000000)

  ;; 3. Set allocation pointer: move.l #cons_base, A2
  (emit-m68k-move-imm32-to-an buf 2 +m68k-cons-base+)

  ;; 4. Set allocation limit: move.l #general_base, A3
  (emit-m68k-move-imm32-to-an buf 3 +m68k-general-base+)

  ;; 5. Set NIL register: move.l #0, A4 (placeholder, patched by kernel init)
  (emit-m68k-move-imm32-to-an buf 4 #x00000000)

  ;; 6. Initialize serial output
  (m68k-init-serial buf)

  ;; 7. NOP sled -- native kernel code follows immediately after
  (dotimes (i 4)
    (emit-m68k-nop buf)))

;;; ============================================================
;;; 68k Per-CPU Layout
;;; ============================================================

(defun m68k-percpu-layout ()
  "Return the per-CPU structure layout for 68k.
   Single-core only -- one structure at a fixed address.
   Accessed via absolute addressing (no per-CPU register on 68k).
   Fields use 32-bit (4 byte) slots since 68k is a 32-bit architecture."
  '((:self-ptr       0  4)    ; Pointer to this per-CPU struct
    (:reduction       4  4)    ; Reduction counter (tagged fixnum)
    (:cpu-id          8  4)    ; CPU number (always 0, tagged fixnum)
    (:current-actor  12  4)    ; Current actor pointer
    (:obj-alloc      16  4)    ; Per-actor object alloc pointer
    (:obj-limit      20  4)    ; Per-actor object alloc limit
    (:scratch        24  4)))  ; Scratch word

;;; ============================================================
;;; 68k Boot Integration
;;; ============================================================

(defun m68k-boot-descriptor ()
  "Return the Motorola 68k boot descriptor for image building.
   The 68k is the simplest target: no MMU, no SMP, no secondary
   startup protocol. Just set up the stack, registers, and UART."
  (list :arch :68k
        :entry-fn #'emit-m68k-entry
        :exception-vectors-fn #'m68k-exception-vectors
        :uart-init-fn #'m68k-init-serial
        :percpu-layout-fn #'m68k-percpu-layout
        :elf-machine 4        ; EM_68K
        :elf-class 32
        :load-addr 0          ; Load entire image at address 0
        :stack-top +m68k-stack-top+
        :cons-base +m68k-cons-base+
        :general-base +m68k-general-base+))
