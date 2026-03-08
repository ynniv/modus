;;;; boot-arm32.lisp - ARM32 Boot Sequence for Modus64
;;;;
;;;; ARM32 boot protocol (for qemu-system-arm -machine versatilepb):
;;;;   1. QEMU loads kernel at 0x00010000 and jumps to it
;;;;   2. CPU is in ARM mode (A32), SVC mode
;;;;   3. Set up stack (r13)
;;;;   4. Initialize allocation registers (r9=alloc, r10=limit, r8=NIL)
;;;;   5. Frame pointer r11 = 0 (base frame)
;;;;   6. Fall through to translated native code
;;;;
;;;; UART: versatilepb maps a PL011 UART at 0x101F1000.
;;;; Data register at offset 0 — write a byte to transmit.

(in-package :modus64.mvm)

;;; ============================================================
;;; ARM32 Boot Constants
;;; ============================================================

;; QEMU versatilepb memory map
(defconstant +arm32-uart-base+     #x101F1000)  ; PL011 UART
(defconstant +arm32-kernel-base+   #x00010000)  ; -kernel load address
(defconstant +arm32-stack-top+     #x04000000)  ; 64MB - stack top
(defconstant +arm32-cons-base+     #x01000000)  ; 16MB - cons space
(defconstant +arm32-general-base+  #x02000000)  ; 32MB - general heap

;;; ============================================================
;;; ARM32 Boot Code Generation
;;; ============================================================

(defun arm32-boot-insn (value)
  "Encode a 32-bit ARM instruction value for boot emission."
  value)

;; ARM immediate encoding helpers for boot
(defun arm32-boot-mov-imm (rd rotate imm8)
  "MOV Rd, #imm  (cond=AL, opcode=MOV=1101, S=0, Rn=0)"
  (logior (ash #xE 28) (ash 1 25) (ash #b1101 21)
          (ash (logand rd #xF) 12)
          (ash (logand rotate #xF) 8)
          (logand imm8 #xFF)))

(defun arm32-boot-orr-imm (rd rn rotate imm8)
  "ORR Rd, Rn, #imm"
  (logior (ash #xE 28) (ash 1 25) (ash #b1100 21)
          (ash (logand rn #xF) 16)
          (ash (logand rd #xF) 12)
          (ash (logand rotate #xF) 8)
          (logand imm8 #xFF)))

(defun arm32-boot-mov-reg (rd rm)
  "MOV Rd, Rm"
  (logior (ash #xE 28) (ash #b1101 21)
          (ash (logand rd #xF) 12)
          (logand rm #xF)))

(defun emit-arm32-insn (buf insn)
  "Emit a 32-bit ARM instruction in little-endian byte order."
  (mvm-emit-byte buf (logand insn #xFF))
  (mvm-emit-byte buf (logand (ash insn -8) #xFF))
  (mvm-emit-byte buf (logand (ash insn -16) #xFF))
  (mvm-emit-byte buf (logand (ash insn -24) #xFF)))

(defun emit-arm32-load-imm (buf rd value)
  "Emit instructions to load a 32-bit immediate into Rd."
  (let ((b0 (logand value #xFF))
        (b1 (logand (ash value -8) #xFF))
        (b2 (logand (ash value -16) #xFF))
        (b3 (logand (ash value -24) #xFF)))
    ;; MOV Rd, #b0
    (emit-arm32-insn buf (arm32-boot-mov-imm rd 0 b0))
    ;; ORR Rd, Rd, #b1, rotate=12  (byte at bits 8-15)
    (when (plusp b1)
      (emit-arm32-insn buf (arm32-boot-orr-imm rd rd 12 b1)))
    ;; ORR Rd, Rd, #b2, rotate=8  (byte at bits 16-23)
    (when (plusp b2)
      (emit-arm32-insn buf (arm32-boot-orr-imm rd rd 8 b2)))
    ;; ORR Rd, Rd, #b3, rotate=4  (byte at bits 24-31)
    (when (plusp b3)
      (emit-arm32-insn buf (arm32-boot-orr-imm rd rd 4 b3)))))

(defun emit-arm32-entry (buf)
  "Emit ARM32 versatilepb kernel entry point.
   Sets up stack, allocation registers, frame pointer,
   and falls through to translated native code."
  ;; --- Set up stack pointer (r13 = +arm32-stack-top+) ---
  (emit-arm32-load-imm buf 13 +arm32-stack-top+)

  ;; --- Initialize allocation registers ---
  ;; r9 (VA) = alloc pointer = +arm32-cons-base+
  (emit-arm32-load-imm buf 9 +arm32-cons-base+)
  ;; r10 (VL) = alloc limit = +arm32-general-base+
  (emit-arm32-load-imm buf 10 +arm32-general-base+)
  ;; r8 (VN) = NIL (tagged: 0)
  (emit-arm32-insn buf (arm32-boot-mov-imm 8 0 0))

  ;; --- Frame pointer (r11) = 0 (base frame) ---
  (emit-arm32-insn buf (arm32-boot-mov-imm 11 0 0))

  ;; --- NOP (fall through to native translated code) ---
  (emit-arm32-insn buf (arm32-boot-mov-reg 0 0)))

;;; ============================================================
;;; ARM32 Boot Integration
;;; ============================================================

(defun arm32-boot-descriptor ()
  "Return the ARM32 boot descriptor for image building."
  (list :arch :arm32
        :entry-fn #'emit-arm32-entry
        :load-addr +arm32-kernel-base+
        :stack-top +arm32-stack-top+
        :cons-base +arm32-cons-base+
        :general-base +arm32-general-base+
        :endianness :little))

;;; ============================================================
;;; ARMv7 Boot Constants (QEMU -machine virt -cpu cortex-a15)
;;; ============================================================

;; QEMU virt machine memory map
(defconstant +armv7-uart-base+     #x09000000)  ; PL011 UART
(defconstant +armv7-kernel-base+   #x40000000)  ; -kernel load address
(defconstant +armv7-stack-top+     #x44000000)  ; 64MB above kernel
(defconstant +armv7-cons-base+     #x41000000)  ; 16MB above kernel
(defconstant +armv7-general-base+  #x42000000)  ; 32MB above kernel

(defun emit-armv7-entry (buf)
  "Emit ARMv7 virt machine kernel entry point.
   Same register setup as ARMv5 but for -machine virt memory layout."
  ;; Stack pointer (r13)
  (emit-arm32-load-imm buf 13 +armv7-stack-top+)
  ;; r9 (VA) = alloc pointer
  (emit-arm32-load-imm buf 9 +armv7-cons-base+)
  ;; r10 (VL) = alloc limit
  (emit-arm32-load-imm buf 10 +armv7-general-base+)
  ;; r8 (VN) = NIL (0)
  (emit-arm32-insn buf (arm32-boot-mov-imm 8 0 0))
  ;; r11 (FP) = 0 (base frame)
  (emit-arm32-insn buf (arm32-boot-mov-imm 11 0 0))
  ;; NOP (fall through to native code)
  (emit-arm32-insn buf (arm32-boot-mov-reg 0 0)))

(defun armv7-boot-descriptor ()
  "Return the ARMv7 boot descriptor for image building."
  (list :arch :armv7
        :entry-fn #'emit-armv7-entry
        :load-addr +armv7-kernel-base+
        :stack-top +armv7-stack-top+
        :cons-base +armv7-cons-base+
        :general-base +armv7-general-base+
        :endianness :little))
