;;;; translate-i386.lisp - MVM Bytecode to i386 (32-bit x86) Native Code Translator
;;;;
;;;; Translates MVM (Modus Virtual Machine) bytecode into i386 machine code.
;;;; This is the HARDEST target because i386 has only 8 GPRs and most virtual
;;;; registers must be spilled to the stack frame.
;;;;
;;;; Register mapping (from target.lisp):
;;;;   V0  -> ESI   (arg0)
;;;;   V1  -> EDI   (arg1)
;;;;   V2  -> stack  (arg2, always spills -- only 2 register args!)
;;;;   V3  -> stack  (arg3, always spills)
;;;;   V4  -> EBX   (callee-saved general purpose)
;;;;   V5-V15 -> stack spill
;;;;   VR  -> EAX   (return value)
;;;;   VA  -> stack slot (no dedicated alloc register!)
;;;;   VL  -> stack slot (alloc limit)
;;;;   VN  -> stack slot (NIL constant address)
;;;;   VSP -> ESP   (stack pointer)
;;;;   VFP -> EBP   (frame pointer)
;;;;
;;;; Scratch registers: ECX, EDX (caller-saved, not mapped to any vreg)
;;;;   - ECX is primary scratch for spill mediation
;;;;   - EDX is secondary scratch, also used by CDQ/IDIV
;;;;   - EAX is VR but also used as scratch for arithmetic requiring it
;;;;
;;;; Key challenges:
;;;;   1. Only 3 virtual GPRs have physical mappings (V0, V1, V4) + VR(EAX)
;;;;   2. All arithmetic for spilled regs requires load/op/store sequences
;;;;   3. 32-bit word size: tagged fixnums use 31 bits (value << 1, LSB=0)
;;;;   4. No REX prefix (unlike x86-64); 32-bit operand size is default
;;;;   5. VA, VL, VN are stack slots -- alloc/GC checks need explicit loads
;;;;   6. Cons cell = 8 bytes (car at [ptr], cdr at [ptr+4])
;;;;   7. Cons tag = 0x01 (low 4 bits), Object tag = 0x09
;;;;
;;;; i386 encoding:
;;;;   [prefix] [opcode] [ModR/M] [SIB] [displacement] [immediate]
;;;;   ModR/M: [mod:2 | reg:3 | r/m:3]
;;;;   SIB:    [scale:2 | index:3 | base:3]
;;;;   No REX prefix; PUSH/POP move 4 bytes (not 8)
;;;;
;;;; Two-pass translation (like x64):
;;;;   Pass 1: Scan for branch targets, create labels
;;;;   Pass 2: Emit native code, using labels for forward references

(in-package :cl-user)

(defpackage :modus64.mvm.i386
  (:use :cl :modus64.mvm)
  (:export
   #:translate-mvm-to-i386
   #:translate-i386-function
   #:install-i386-translator
   #:i386-buffer
   #:i386-buffer-bytes
   #:i386-buffer-to-bytes
   #:i386-disassemble-native))

(in-package :modus64.mvm.i386)

;;; ============================================================
;;; i386 Physical Register Encoding
;;; ============================================================
;;;
;;; The 8 GPRs of i386 and their 3-bit ModR/M encoding:
;;;   EAX=0  ECX=1  EDX=2  EBX=3  ESP=4  EBP=5  ESI=6  EDI=7

(defconstant +i386-eax+ 0)
(defconstant +i386-ecx+ 1)
(defconstant +i386-edx+ 2)
(defconstant +i386-ebx+ 3)
(defconstant +i386-esp+ 4)
(defconstant +i386-ebp+ 5)
(defconstant +i386-esi+ 6)
(defconstant +i386-edi+ 7)

;;; Scratch registers (not mapped to any virtual register)
(defconstant +scratch0+ +i386-ecx+  "ECX - primary scratch register")
(defconstant +scratch1+ +i386-edx+  "EDX - secondary scratch register")

;;; ============================================================
;;; Virtual -> Physical Register Mapping
;;; ============================================================
;;;
;;; NIL means the virtual register spills to the stack frame.

(defparameter *i386-vreg-map*
  (vector +i386-esi+     ; V0  -> ESI
          +i386-edi+     ; V1  -> EDI
          nil nil         ; V2, V3 (spill -- only 2 arg regs on i386)
          +i386-ebx+     ; V4  -> EBX
          nil nil nil     ; V5-V7 (spill)
          nil nil nil nil ; V8-V11 (spill)
          nil nil nil nil ; V12-V15 (spill)
          +i386-eax+     ; VR  -> EAX
          nil             ; VA  -> spill (alloc pointer)
          nil             ; VL  -> spill (alloc limit)
          nil             ; VN  -> spill (NIL constant)
          +i386-esp+     ; VSP -> ESP
          +i386-ebp+     ; VFP -> EBP
          nil))           ; VPC -> not mapped

;;; ============================================================
;;; Tagged Value Constants
;;; ============================================================

(defconstant +tag-cons+    #x01 "Cons tag: low 4 bits = 0001")
(defconstant +tag-object+  #x09 "Object tag: low 4 bits = 1001")
(defconstant +tag-mask+    #x0F "Mask for extracting tag from pointer")
(defconstant +i386-mvm-t+  #xDEAD1009 "Placeholder T value (object-tagged marker)")

;;; ============================================================
;;; Stack Frame Layout
;;; ============================================================
;;;
;;; All offsets are negative from EBP. The frame is structured as:
;;;
;;;   [EBP + 8]  = return address (pushed by CALL)
;;;   [EBP + 4]  = old EBP (pushed by PUSH EBP in prologue)
;;;   [EBP + 0]  = current frame pointer
;;;   [EBP -  4] = saved EBX (callee-saved)
;;;   [EBP -  8] = saved ESI (callee-saved)
;;;   [EBP - 12] = saved EDI (callee-saved)
;;;   [EBP - 16] = VA (alloc pointer)
;;;   [EBP - 20] = VL (alloc limit)
;;;   [EBP - 24] = VN (NIL constant)
;;;   [EBP - 28] = V2 spill slot
;;;   [EBP - 32] = V3 spill slot
;;;   [EBP - 36] = V5 spill slot    (V4 = EBX, not spilled)
;;;   [EBP - 40] = V6 spill slot
;;;   [EBP - 44] = V7 spill slot
;;;   [EBP - 48] = V8 spill slot
;;;   [EBP - 52] = V9 spill slot
;;;   [EBP - 56] = V10 spill slot
;;;   [EBP - 60] = V11 spill slot
;;;   [EBP - 64] = V12 spill slot
;;;   [EBP - 68] = V13 spill slot
;;;   [EBP - 72] = V14 spill slot
;;;   [EBP - 76] = V15 spill slot
;;;   Total frame reservation: 76 bytes, rounded to 80 for alignment

(defconstant +save-ebx-off+  -4)
(defconstant +save-esi-off+  -8)
(defconstant +save-edi-off+ -12)
(defconstant +va-off+       -16)   ; Alloc pointer frame slot
(defconstant +vl-off+       -20)   ; Alloc limit frame slot
(defconstant +vn-off+       -24)   ; NIL constant frame slot
(defconstant +spill-base+   -28)   ; First general spill slot

(defun i386-spill-offset (vreg)
  "Calculate EBP-relative offset for a spilled virtual register.
   Returns a negative integer for valid spill vregs."
  (cond
    ;; Special registers with dedicated frame slots
    ((= vreg +vreg-va+)  +va-off+)
    ((= vreg +vreg-vl+)  +vl-off+)
    ((= vreg +vreg-vn+)  +vn-off+)
    ;; V2, V3 (always spill)
    ((= vreg 2)  -28)
    ((= vreg 3)  -32)
    ;; V5-V15 (V4 = EBX, not spilled)
    ((and (>= vreg 5) (<= vreg 15))
     (- -36 (* (- vreg 5) 4)))
    (t (error "i386: unexpected spill for vreg ~D" vreg))))

(defconstant +frame-slot-base+ -80
  "EBP-relative offset for frame slot 0 (local variables via obj-ref VFP).
   Frame slots grow downward: slot N is at EBP + frame-slot-base - N*4.
   This is below all spill slots (which end at EBP-76) to avoid overlap.")

(defconstant +frame-size+ 112
  "Total frame reservation in bytes. Includes saved regs, special slots,
   spill slots, and 8 frame slots for local variables (obj-ref VFP N).
   76 bytes spills + 32 bytes frame slots = 108, rounded to 112.")

;;; ============================================================
;;; Virtual Register Helpers
;;; ============================================================

(defun i386-vreg-phys (vreg)
  "Return the physical register code for VREG, or NIL if it spills."
  (and (< vreg (length *i386-vreg-map*))
       (aref *i386-vreg-map* vreg)))

(defun i386-vreg-spills-p (vreg)
  "Does VREG spill to the stack on i386?"
  (null (i386-vreg-phys vreg)))

;;; ============================================================
;;; i386 Code Buffer
;;; ============================================================

(defstruct i386-buffer
  (bytes (make-array 4096 :element-type '(unsigned-byte 8)
                          :adjustable t :fill-pointer 0))
  (labels (make-hash-table :test 'eql))
  (fixups nil)     ; list of (byte-position label-id fixup-type)
  (position 0))

(defun i386-emit-byte (buf byte)
  "Emit a single byte."
  (vector-push-extend (logand byte #xFF) (i386-buffer-bytes buf))
  (incf (i386-buffer-position buf)))

(defun i386-emit-u16 (buf val)
  "Emit a 16-bit little-endian value."
  (i386-emit-byte buf (logand val #xFF))
  (i386-emit-byte buf (logand (ash val -8) #xFF)))

(defun i386-emit-u32 (buf val)
  "Emit a 32-bit little-endian value."
  (i386-emit-byte buf (logand val #xFF))
  (i386-emit-byte buf (logand (ash val -8) #xFF))
  (i386-emit-byte buf (logand (ash val -16) #xFF))
  (i386-emit-byte buf (logand (ash val -24) #xFF)))

(defun i386-emit-s32 (buf val)
  "Emit a signed 32-bit little-endian value."
  (i386-emit-u32 buf (if (minusp val) (logand val #xFFFFFFFF) val)))

(defun i386-emit-s8 (buf val)
  "Emit a signed 8-bit value."
  (i386-emit-byte buf (if (minusp val) (logand val #xFF) val)))

(defun i386-current-pos (buf)
  "Current byte position in the code buffer."
  (i386-buffer-position buf))

(defun i386-emit-label (buf label-id)
  "Record current position as a branch target."
  (setf (gethash label-id (i386-buffer-labels buf))
        (i386-buffer-position buf)))

(defun i386-make-label ()
  "Create a new unique label."
  (mvm-make-label))

(defun i386-emit-fixup-rel32 (buf label-id)
  "Emit a 32-bit placeholder and record a rel32 fixup."
  (push (list (i386-buffer-position buf) label-id :rel32)
        (i386-buffer-fixups buf))
  (i386-emit-u32 buf 0))

(defun i386-fixup-labels (buf)
  "Resolve all branch label references."
  (let ((bytes (i386-buffer-bytes buf)))
    (dolist (fixup (i386-buffer-fixups buf))
      (destructuring-bind (pos label-id fixup-type) fixup
        (let ((target (gethash label-id (i386-buffer-labels buf))))
          (unless target
            (error "i386: undefined label ~A" label-id))
          (ecase fixup-type
            (:rel32
             ;; rel32 is relative to end of the 4-byte displacement field
             (let* ((rel (- target (+ pos 4)))
                    (urel (if (minusp rel) (logand rel #xFFFFFFFF) rel)))
               (setf (aref bytes (+ pos 0)) (logand urel #xFF)
                     (aref bytes (+ pos 1)) (logand (ash urel -8) #xFF)
                     (aref bytes (+ pos 2)) (logand (ash urel -16) #xFF)
                     (aref bytes (+ pos 3)) (logand (ash urel -24) #xFF))))))))))

(defun i386-buffer-to-bytes (buf)
  "Return the code buffer as a simple byte vector."
  (let* ((fp (fill-pointer (i386-buffer-bytes buf)))
         (result (make-array fp :element-type '(unsigned-byte 8))))
    (dotimes (i fp result)
      (setf (aref result i) (aref (i386-buffer-bytes buf) i)))))

;;; ============================================================
;;; i386 ModR/M and SIB Encoding
;;; ============================================================

(defun i386-modrm (mod reg rm)
  "Build a ModR/M byte: [mod:2 | reg:3 | r/m:3]"
  (logior (ash (logand mod 3) 6)
          (ash (logand reg 7) 3)
          (logand rm 7)))

(defun i386-sib (scale index base)
  "Build a SIB byte: [scale:2 | index:3 | base:3]"
  (logior (ash (logand scale 3) 6)
          (ash (logand index 7) 3)
          (logand base 7)))

(defun i386-emit-modrm-mem (buf reg-field base-reg offset)
  "Emit ModR/M (and SIB if needed) for [base-reg + offset] addressing.
   REG-FIELD is the /r field (register or opcode extension).
   Handles ESP (needs SIB) and EBP (needs explicit disp) edge cases."
  (let ((needs-sib (= base-reg +i386-esp+)))
    (cond
      ;; No displacement (but EBP always needs at least disp8)
      ((and (zerop offset) (/= base-reg +i386-ebp+))
       (if needs-sib
           (progn
             (i386-emit-byte buf (i386-modrm #b00 reg-field 4))
             (i386-emit-byte buf (i386-sib 0 4 +i386-esp+)))
           (i386-emit-byte buf (i386-modrm #b00 reg-field base-reg))))
      ;; 8-bit displacement fits
      ((<= -128 offset 127)
       (if needs-sib
           (progn
             (i386-emit-byte buf (i386-modrm #b01 reg-field 4))
             (i386-emit-byte buf (i386-sib 0 4 +i386-esp+)))
           (i386-emit-byte buf (i386-modrm #b01 reg-field base-reg)))
       (i386-emit-s8 buf offset))
      ;; Full 32-bit displacement
      (t
       (if needs-sib
           (progn
             (i386-emit-byte buf (i386-modrm #b10 reg-field 4))
             (i386-emit-byte buf (i386-sib 0 4 +i386-esp+)))
           (i386-emit-byte buf (i386-modrm #b10 reg-field base-reg)))
       (i386-emit-s32 buf offset)))))

;;; ============================================================
;;; i386 Instruction Emitters
;;; ============================================================

;;; --- MOV ---

(defun i386-emit-mov-reg-reg (buf dst src)
  "MOV dst, src (register-to-register, 32-bit)"
  (i386-emit-byte buf #x89)   ; MOV r/m32, r32
  (i386-emit-byte buf (i386-modrm #b11 src dst)))

(defun i386-emit-mov-reg-imm (buf reg imm)
  "MOV reg, imm32"
  (i386-emit-byte buf (+ #xB8 reg))
  (i386-emit-u32 buf (logand imm #xFFFFFFFF)))

(defun i386-emit-mov-reg-mem (buf reg base offset)
  "MOV reg, [base + offset]"
  (i386-emit-byte buf #x8B)
  (i386-emit-modrm-mem buf reg base offset))

(defun i386-emit-mov-mem-reg (buf base offset reg)
  "MOV [base + offset], reg"
  (i386-emit-byte buf #x89)
  (i386-emit-modrm-mem buf reg base offset))

(defun i386-emit-mov-mem-imm (buf base offset imm)
  "MOV DWORD [base + offset], imm32"
  (i386-emit-byte buf #xC7)
  (i386-emit-modrm-mem buf 0 base offset)
  (i386-emit-u32 buf (logand imm #xFFFFFFFF)))

;;; --- Load/Store for 8/16-bit widths ---

(defun i386-emit-movzx-byte (buf reg base offset)
  "MOVZX reg, BYTE [base+offset]"
  (i386-emit-byte buf #x0F)
  (i386-emit-byte buf #xB6)
  (i386-emit-modrm-mem buf reg base offset))

(defun i386-emit-movzx-word (buf reg base offset)
  "MOVZX reg, WORD [base+offset]"
  (i386-emit-byte buf #x0F)
  (i386-emit-byte buf #xB7)
  (i386-emit-modrm-mem buf reg base offset))

(defun i386-emit-mov-mem8-reg (buf base offset reg)
  "MOV BYTE [base+offset], reg (low 8 bits)"
  (i386-emit-byte buf #x88)
  (i386-emit-modrm-mem buf reg base offset))

(defun i386-emit-mov-mem16-reg (buf base offset reg)
  "MOV WORD [base+offset], reg (low 16 bits)"
  (i386-emit-byte buf #x66)   ; operand-size override prefix
  (i386-emit-byte buf #x89)
  (i386-emit-modrm-mem buf reg base offset))

;;; --- PUSH / POP ---

(defun i386-emit-push-reg (buf reg)
  "PUSH reg (32-bit)"
  (i386-emit-byte buf (+ #x50 reg)))

(defun i386-emit-pop-reg (buf reg)
  "POP reg (32-bit)"
  (i386-emit-byte buf (+ #x58 reg)))

(defun i386-emit-push-imm32 (buf imm)
  "PUSH imm32"
  (i386-emit-byte buf #x68)
  (i386-emit-u32 buf (logand imm #xFFFFFFFF)))

(defun i386-emit-push-mem (buf base offset)
  "PUSH DWORD [base+offset]"
  (i386-emit-byte buf #xFF)
  (i386-emit-modrm-mem buf 6 base offset))

;;; --- ALU Operations ---

(defmacro def-i386-alu (name opcode-rr opcode-ri-8 opcode-ri-32 modrm-ext
                         &optional (opcode-rm nil) (opcode-mr nil))
  "Define i386 ALU instruction forms: reg-reg, reg-imm, reg-mem, mem-reg."
  (let ((pkg (find-package :modus64.mvm.i386)))
    `(progn
       (defun ,(intern (format nil "I386-EMIT-~A-REG-REG" name) pkg) (buf dst src)
         ,(format nil "~A dst, src (register-register)" name)
         (i386-emit-byte buf ,opcode-rr)
         (i386-emit-byte buf (i386-modrm #b11 src dst)))

       (defun ,(intern (format nil "I386-EMIT-~A-REG-IMM" name) pkg) (buf reg imm)
         ,(format nil "~A reg, imm" name)
         (cond
           ;; Sign-extended 8-bit immediate (most common)
           ((<= -128 imm 127)
            (i386-emit-byte buf ,opcode-ri-8)
            (i386-emit-byte buf (i386-modrm #b11 ,modrm-ext reg))
            (i386-emit-s8 buf imm))
           ;; Short form for EAX
           ((= reg +i386-eax+)
            (i386-emit-byte buf ,opcode-ri-32)
            (i386-emit-s32 buf imm))
           ;; General form
           (t
            (i386-emit-byte buf #x81)
            (i386-emit-byte buf (i386-modrm #b11 ,modrm-ext reg))
            (i386-emit-s32 buf imm))))

       ,@(when opcode-rm
           `((defun ,(intern (format nil "I386-EMIT-~A-REG-MEM" name) pkg) (buf reg base offset)
               ,(format nil "~A reg, [base+offset]" name)
               (i386-emit-byte buf ,opcode-rm)
               (i386-emit-modrm-mem buf reg base offset))))

       ,@(when opcode-mr
           `((defun ,(intern (format nil "I386-EMIT-~A-MEM-REG" name) pkg) (buf base offset reg)
               ,(format nil "~A [base+offset], reg" name)
               (i386-emit-byte buf ,opcode-mr)
               (i386-emit-modrm-mem buf reg base offset)))))))

;; Define all standard ALU operations: name, rr, ri8, ri32-eax, /ext, rm, mr
(def-i386-alu "ADD" #x01 #x83 #x05 0 #x03 #x01)
(def-i386-alu "SUB" #x29 #x83 #x2D 5 #x2B #x29)
(def-i386-alu "CMP" #x39 #x83 #x3D 7 #x3B #x39)
(def-i386-alu "AND" #x21 #x83 #x25 4 #x23 #x21)
(def-i386-alu "OR"  #x09 #x83 #x0D 1 #x0B #x09)
(def-i386-alu "XOR" #x31 #x83 #x35 6 #x33 #x31)

;;; --- TEST ---

(defun i386-emit-test-reg-reg (buf r1 r2)
  "TEST r1, r2 (AND, set flags, discard result)"
  (i386-emit-byte buf #x85)
  (i386-emit-byte buf (i386-modrm #b11 r2 r1)))

(defun i386-emit-test-reg-imm (buf reg imm)
  "TEST reg, imm32"
  (if (= reg +i386-eax+)
      (progn
        (i386-emit-byte buf #xA9)
        (i386-emit-u32 buf (logand imm #xFFFFFFFF)))
      (progn
        (i386-emit-byte buf #xF7)
        (i386-emit-byte buf (i386-modrm #b11 0 reg))
        (i386-emit-u32 buf (logand imm #xFFFFFFFF)))))

;;; --- Shifts ---

(defun i386-emit-shl-reg-imm (buf reg count)
  "SHL reg, imm8"
  (if (= count 1)
      (progn (i386-emit-byte buf #xD1)
             (i386-emit-byte buf (i386-modrm #b11 4 reg)))
      (progn (i386-emit-byte buf #xC1)
             (i386-emit-byte buf (i386-modrm #b11 4 reg))
             (i386-emit-byte buf count))))

(defun i386-emit-shr-reg-imm (buf reg count)
  "SHR reg, imm8 (logical shift right)"
  (if (= count 1)
      (progn (i386-emit-byte buf #xD1)
             (i386-emit-byte buf (i386-modrm #b11 5 reg)))
      (progn (i386-emit-byte buf #xC1)
             (i386-emit-byte buf (i386-modrm #b11 5 reg))
             (i386-emit-byte buf count))))

(defun i386-emit-sar-reg-imm (buf reg count)
  "SAR reg, imm8 (arithmetic shift right)"
  (if (= count 1)
      (progn (i386-emit-byte buf #xD1)
             (i386-emit-byte buf (i386-modrm #b11 7 reg)))
      (progn (i386-emit-byte buf #xC1)
             (i386-emit-byte buf (i386-modrm #b11 7 reg))
             (i386-emit-byte buf count))))

;;; --- Multiply / Divide ---

(defun i386-emit-imul-reg-reg (buf dst src)
  "IMUL dst, src (two-operand signed multiply)"
  (i386-emit-byte buf #x0F)
  (i386-emit-byte buf #xAF)
  (i386-emit-byte buf (i386-modrm #b11 dst src)))

(defun i386-emit-idiv-reg (buf reg)
  "IDIV reg: signed divide EDX:EAX by reg, quotient->EAX, remainder->EDX"
  (i386-emit-byte buf #xF7)
  (i386-emit-byte buf (i386-modrm #b11 7 reg)))

(defun i386-emit-cdq (buf)
  "CDQ: sign-extend EAX into EDX:EAX"
  (i386-emit-byte buf #x99))

;;; --- NEG / NOT ---

(defun i386-emit-neg-reg (buf reg)
  "NEG reg (two's complement negate)"
  (i386-emit-byte buf #xF7)
  (i386-emit-byte buf (i386-modrm #b11 3 reg)))

(defun i386-emit-not-reg (buf reg)
  "NOT reg (bitwise complement)"
  (i386-emit-byte buf #xF7)
  (i386-emit-byte buf (i386-modrm #b11 2 reg)))

;;; --- LEA ---

(defun i386-emit-lea (buf dst base offset)
  "LEA dst, [base + offset]"
  (i386-emit-byte buf #x8D)
  (i386-emit-modrm-mem buf dst base offset))

;;; --- Jump / Call / Return ---

(defun i386-emit-jmp-rel32 (buf &optional label-id)
  "JMP rel32 (near unconditional jump)"
  (i386-emit-byte buf #xE9)
  (if label-id
      (i386-emit-fixup-rel32 buf label-id)
      (i386-emit-u32 buf 0)))

(defun i386-emit-jmp-reg (buf reg)
  "JMP reg (indirect near jump)"
  (i386-emit-byte buf #xFF)
  (i386-emit-byte buf (i386-modrm #b11 4 reg)))

(defun i386-emit-call-rel32 (buf &optional label-id)
  "CALL rel32 (near call)"
  (i386-emit-byte buf #xE8)
  (if label-id
      (i386-emit-fixup-rel32 buf label-id)
      (i386-emit-u32 buf 0)))

(defun i386-emit-call-reg (buf reg)
  "CALL reg (indirect near call)"
  (i386-emit-byte buf #xFF)
  (i386-emit-byte buf (i386-modrm #b11 2 reg)))

(defun i386-emit-ret (buf)
  "RET (near return)"
  (i386-emit-byte buf #xC3))

;;; --- Conditional Jumps ---

(defparameter *i386-cc-codes*
  '((:e  . #x4)  (:ne . #x5)
    (:l  . #xC)  (:ge . #xD)  (:le . #xE)  (:g  . #xF)
    (:b  . #x2)  (:ae . #x3)  (:be . #x6)  (:a  . #x7)
    (:z  . #x4)  (:nz . #x5)  (:s  . #x8)  (:ns . #x9))
  "Condition code keyword -> numeric encoding for Jcc.")

(defun i386-emit-jcc (buf cc &optional label-id)
  "Jcc rel32 (conditional jump, near form: 0F 80+cc)"
  (let ((code (cdr (assoc cc *i386-cc-codes*))))
    (unless code (error "i386: unknown condition code ~A" cc))
    (i386-emit-byte buf #x0F)
    (i386-emit-byte buf (+ #x80 code))
    (if label-id
        (i386-emit-fixup-rel32 buf label-id)
        (i386-emit-u32 buf 0))))

;;; --- Atomic Exchange ---

(defun i386-emit-xchg-mem-reg (buf base offset reg)
  "XCHG [base+offset], reg.  Implicitly locked when memory operand present."
  (i386-emit-byte buf #x87)
  (i386-emit-modrm-mem buf reg base offset))

;;; --- Special Instructions ---

(defun i386-emit-nop (buf) "NOP" (i386-emit-byte buf #x90))
(defun i386-emit-int3 (buf) "INT 3 (breakpoint)" (i386-emit-byte buf #xCC))
(defun i386-emit-int (buf n) "INT n" (i386-emit-byte buf #xCD) (i386-emit-byte buf n))
(defun i386-emit-cli (buf) "CLI (disable interrupts)" (i386-emit-byte buf #xFA))
(defun i386-emit-sti (buf) "STI (enable interrupts)" (i386-emit-byte buf #xFB))
(defun i386-emit-hlt (buf) "HLT (halt processor)" (i386-emit-byte buf #xF4))

(defun i386-emit-mfence (buf)
  "Memory fence.  Uses LOCK ADD [ESP], 0 for i386 compatibility
   (MFENCE is SSE2/i686+; LOCK ADD works on all i386+)."
  (i386-emit-byte buf #xF0)   ; LOCK prefix
  (i386-emit-byte buf #x83)   ; ADD r/m32, imm8
  (i386-emit-modrm-mem buf 0 +i386-esp+ 0)
  (i386-emit-s8 buf 0))

;;; --- I/O Port Instructions ---

(defun i386-emit-in-al-dx (buf)      (i386-emit-byte buf #xEC))
(defun i386-emit-in-ax-dx (buf)      (i386-emit-byte buf #x66) (i386-emit-byte buf #xED))
(defun i386-emit-in-eax-dx (buf)     (i386-emit-byte buf #xED))
(defun i386-emit-out-dx-al (buf)     (i386-emit-byte buf #xEE))
(defun i386-emit-out-dx-ax (buf)     (i386-emit-byte buf #x66) (i386-emit-byte buf #xEF))
(defun i386-emit-out-dx-eax (buf)    (i386-emit-byte buf #xEF))

(defun i386-emit-in-al-imm8 (buf port)
  "IN AL, imm8" (i386-emit-byte buf #xE4) (i386-emit-byte buf port))
(defun i386-emit-in-ax-imm8 (buf port)
  "IN AX, imm8" (i386-emit-byte buf #x66) (i386-emit-byte buf #xE5) (i386-emit-byte buf port))
(defun i386-emit-in-eax-imm8 (buf port)
  "IN EAX, imm8" (i386-emit-byte buf #xE5) (i386-emit-byte buf port))
(defun i386-emit-out-imm8-al (buf port)
  "OUT imm8, AL" (i386-emit-byte buf #xE6) (i386-emit-byte buf port))
(defun i386-emit-out-imm8-eax (buf port)
  "OUT imm8, EAX" (i386-emit-byte buf #xE7) (i386-emit-byte buf port))

;;; ============================================================
;;; Virtual Register Load/Store Helpers
;;; ============================================================
;;;
;;; On i386, most virtual registers spill to the stack. These helpers
;;; abstract the load/store pattern, generating MOV reg-reg when the
;;; vreg has a physical mapping, or MOV reg-mem / MOV mem-reg for spills.

(defun i386-load-vreg (buf scratch vreg)
  "Load virtual register VREG into physical register SCRATCH.
   If VREG already lives in SCRATCH, no code is emitted."
  (let ((phys (i386-vreg-phys vreg)))
    (if phys
        (unless (= phys scratch)
          (i386-emit-mov-reg-reg buf scratch phys))
        (i386-emit-mov-reg-mem buf scratch +i386-ebp+ (i386-spill-offset vreg)))))

(defun i386-store-vreg (buf vreg scratch)
  "Store physical register SCRATCH into virtual register VREG."
  (let ((phys (i386-vreg-phys vreg)))
    (if phys
        (unless (= phys scratch)
          (i386-emit-mov-reg-reg buf phys scratch))
        (i386-emit-mov-mem-reg buf +i386-ebp+ (i386-spill-offset vreg) scratch))))

(defun i386-vreg-or-scratch (buf vreg scratch)
  "If VREG has a physical register, return it.
   Otherwise load into SCRATCH and return SCRATCH."
  (let ((phys (i386-vreg-phys vreg)))
    (if phys phys
        (progn (i386-load-vreg buf scratch vreg) scratch))))

;;; ============================================================
;;; Prologue / Epilogue
;;; ============================================================

(defun i386-emit-prologue (buf)
  "Emit i386 function prologue.
   PUSH EBP; MOV EBP, ESP; SUB ESP, frame_size;
   save callee-saved EBX, ESI, EDI."
  (i386-emit-push-reg buf +i386-ebp+)
  (i386-emit-mov-reg-reg buf +i386-ebp+ +i386-esp+)
  (i386-emit-sub-reg-imm buf +i386-esp+ +frame-size+)
  ;; Save callee-saved registers
  (i386-emit-mov-mem-reg buf +i386-ebp+ +save-ebx-off+ +i386-ebx+)
  (i386-emit-mov-mem-reg buf +i386-ebp+ +save-esi-off+ +i386-esi+)
  (i386-emit-mov-mem-reg buf +i386-ebp+ +save-edi-off+ +i386-edi+))

(defun i386-emit-epilogue (buf)
  "Emit i386 function epilogue. Return value should be in EAX (VR)."
  ;; Restore callee-saved registers
  (i386-emit-mov-reg-mem buf +i386-ebx+ +i386-ebp+ +save-ebx-off+)
  (i386-emit-mov-reg-mem buf +i386-esi+ +i386-ebp+ +save-esi-off+)
  (i386-emit-mov-reg-mem buf +i386-edi+ +i386-ebp+ +save-edi-off+)
  ;; Tear down frame
  (i386-emit-mov-reg-reg buf +i386-esp+ +i386-ebp+)
  (i386-emit-pop-reg buf +i386-ebp+)
  (i386-emit-ret buf))

;;; ============================================================
;;; Translation State
;;; ============================================================

(defstruct i386-translate-state
  (buf nil)                     ; i386-buffer
  (mvm-bytes nil)               ; raw MVM bytecode vector
  (mvm-length 0)                ; length of bytecode region
  (mvm-offset 0)                ; start offset into mvm-bytes
  ;; Maps MVM bytecode position -> native code label
  (label-map (make-hash-table :test 'eql))
  ;; Function table: function-index -> native code label
  (function-table nil)
  ;; GC helper label
  (gc-label nil))

(defun i386-ensure-label-at (state mvm-pos)
  "Ensure a label exists for MVM bytecode position MVM-POS."
  (let ((ht (i386-translate-state-label-map state)))
    (or (gethash mvm-pos ht)
        (setf (gethash mvm-pos ht) (i386-make-label)))))

;;; ============================================================
;;; MVM Opcode Translation
;;; ============================================================
;;;
;;; Single-instruction translator.  Called from the main translation
;;; loop for each decoded MVM instruction.

(defun i386-translate-insn (state opcode operands mvm-next-pos)
  "Translate one MVM instruction to i386 native code.
   OPCODE: numeric MVM opcode.
   OPERANDS: list of decoded operands.
   MVM-NEXT-POS: bytecode position after this instruction."
  (let ((buf (i386-translate-state-buf state)))
    (macrolet ((op= (sym) `(= opcode ,sym)))
      (cond
        ;; ============================================
        ;; NOP / BREAK / TRAP
        ;; ============================================
        ((op= +op-nop+)
         (i386-emit-nop buf))

        ((op= +op-break+)
         (i386-emit-int3 buf))

        ((op= +op-trap+)
         (let ((code (first operands)))
           (cond
             ((< code #x0300)
              ;; Frame management: NOP (translator handles prologue/epilogue)
              nil)
             ((= code #x0300)
              ;; Serial write: V0 (ESI) contains tagged fixnum char code
              ;; mov eax, esi
              (i386-emit-byte buf #x89)
              (i386-emit-byte buf #xF0)
              ;; sar eax, 1 (untag fixnum)
              (i386-emit-byte buf #xD1)
              (i386-emit-byte buf #xF8)
              ;; mov dx, 0x3F8 (COM1 data port)
              (i386-emit-byte buf #x66)
              (i386-emit-byte buf #xBA)
              (i386-emit-byte buf #xF8)
              (i386-emit-byte buf #x03)
              ;; out dx, al
              (i386-emit-byte buf #xEE))
             (t
              ;; Real CPU trap
              (i386-emit-mov-reg-imm buf +i386-eax+ code)
              (i386-emit-int buf #x30)))))

        ;; ============================================
        ;; Data Movement
        ;; ============================================
        ((op= +op-mov+)
         ;; (mov Vd Vs)
         (let ((vd (first operands))
               (vs (second operands)))
           (let ((pd (i386-vreg-phys vd))
                 (ps (i386-vreg-phys vs)))
             (cond
               ((and pd ps)
                (unless (= pd ps)
                  (i386-emit-mov-reg-reg buf pd ps)))
               ((and (null pd) ps)
                (i386-emit-mov-mem-reg buf +i386-ebp+ (i386-spill-offset vd) ps))
               ((and pd (null ps))
                (i386-emit-mov-reg-mem buf pd +i386-ebp+ (i386-spill-offset vs)))
               (t ; both spill - route through scratch
                (i386-emit-mov-reg-mem buf +scratch0+ +i386-ebp+ (i386-spill-offset vs))
                (i386-emit-mov-mem-reg buf +i386-ebp+ (i386-spill-offset vd) +scratch0+))))))

        ((op= +op-li+)
         ;; (li Vd imm64) -- on i386, truncate to low 32 bits
         (let* ((vd (first operands))
                (imm (logand (second operands) #xFFFFFFFF))
                (pd (i386-vreg-phys vd)))
           (if pd
               (i386-emit-mov-reg-imm buf pd imm)
               (i386-emit-mov-mem-imm buf +i386-ebp+ (i386-spill-offset vd) imm))))

        ((op= +op-push+)
         ;; (push Vs)
         (let* ((vs (first operands))
                (ps (i386-vreg-phys vs)))
           (if ps
               (i386-emit-push-reg buf ps)
               (i386-emit-push-mem buf +i386-ebp+ (i386-spill-offset vs)))))

        ((op= +op-pop+)
         ;; (pop Vd)
         (let* ((vd (first operands))
                (pd (i386-vreg-phys vd)))
           (if pd
               (i386-emit-pop-reg buf pd)
               (progn
                 (i386-emit-pop-reg buf +scratch0+)
                 (i386-store-vreg buf vd +scratch0+)))))

        ;; ============================================
        ;; Arithmetic (tagged fixnum: value << 1, LSB=0)
        ;; ============================================
        ((op= +op-add+)
         ;; (add Vd Va Vb) -- tagged fixnums add directly (tags cancel)
         (let ((vd (first operands))
               (va (second operands))
               (vb (third operands)))
           (let ((pa (i386-vreg-or-scratch buf va +i386-eax+)))
             (unless (= pa +i386-eax+)
               (i386-emit-mov-reg-reg buf +i386-eax+ pa))
             (let ((pb (i386-vreg-phys vb)))
               (if pb
                   (i386-emit-add-reg-reg buf +i386-eax+ pb)
                   (i386-emit-add-reg-mem buf +i386-eax+ +i386-ebp+ (i386-spill-offset vb))))
             (i386-store-vreg buf vd +i386-eax+))))

        ((op= +op-sub+)
         ;; (sub Vd Va Vb) -- tagged fixnums subtract directly
         (let ((vd (first operands))
               (va (second operands))
               (vb (third operands)))
           (let ((pa (i386-vreg-or-scratch buf va +i386-eax+)))
             (unless (= pa +i386-eax+)
               (i386-emit-mov-reg-reg buf +i386-eax+ pa))
             (let ((pb (i386-vreg-phys vb)))
               (if pb
                   (i386-emit-sub-reg-reg buf +i386-eax+ pb)
                   (i386-emit-sub-reg-mem buf +i386-eax+ +i386-ebp+ (i386-spill-offset vb))))
             (i386-store-vreg buf vd +i386-eax+))))

        ((op= +op-mul+)
         ;; (mul Vd Va Vb) -- tagged multiply
         ;; Both inputs carry <<1 fixnum tag, so product has factor of 4
         ;; where we need 2.  SAR 1 corrects: (a<<1)*(b<<1) >> 1 = a*b<<1
         (let ((vd (first operands))
               (va (second operands))
               (vb (third operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (i386-emit-sar-reg-imm buf +i386-eax+ 1)   ; untag one operand
           (let ((pb (i386-vreg-phys vb)))
             (if pb
                 (i386-emit-imul-reg-reg buf +i386-eax+ pb)
                 (progn
                   (i386-load-vreg buf +scratch0+ vb)
                   (i386-emit-imul-reg-reg buf +i386-eax+ +scratch0+))))
           ;; Result is already correctly tagged (a * (b<<1) = (a*b)<<1)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-div+)
         ;; (div Vd Va Vb) -- tagged fixnum division
         ;; Untag both, IDIV, re-tag quotient
         (let ((vd (first operands))
               (va (second operands))
               (vb (third operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (i386-emit-sar-reg-imm buf +i386-eax+ 1)   ; untag dividend
           (i386-emit-cdq buf)                          ; sign-extend EAX -> EDX:EAX
           (i386-load-vreg buf +scratch0+ vb)
           (i386-emit-sar-reg-imm buf +scratch0+ 1)    ; untag divisor
           (i386-emit-idiv-reg buf +scratch0+)          ; EAX = quotient, EDX = remainder
           (i386-emit-shl-reg-imm buf +i386-eax+ 1)    ; re-tag quotient
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-mod+)
         ;; (mod Vd Va Vb) -- tagged fixnum modulus
         ;; Same as div but result is remainder in EDX
         (let ((vd (first operands))
               (va (second operands))
               (vb (third operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (i386-emit-sar-reg-imm buf +i386-eax+ 1)
           (i386-emit-cdq buf)
           (i386-load-vreg buf +scratch0+ vb)
           (i386-emit-sar-reg-imm buf +scratch0+ 1)
           (i386-emit-idiv-reg buf +scratch0+)
           ;; Remainder in EDX, re-tag
           (i386-emit-shl-reg-imm buf +i386-edx+ 1)
           (i386-store-vreg buf vd +i386-edx+)))

        ((op= +op-neg+)
         ;; (neg Vd Vs) -- negate tagged fixnum
         ;; NEG preserves the fixnum tag: -(n<<1) = (-n)<<1
         (let ((vd (first operands))
               (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-neg-reg buf +i386-eax+)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-inc+)
         ;; (inc Vd) -- add tagged fixnum 1 (raw value 2)
         (let* ((vd (first operands))
                (pd (i386-vreg-phys vd)))
           (if pd
               (i386-emit-add-reg-imm buf pd 2)
               (progn
                 (i386-load-vreg buf +i386-eax+ vd)
                 (i386-emit-add-reg-imm buf +i386-eax+ 2)
                 (i386-store-vreg buf vd +i386-eax+)))))

        ((op= +op-dec+)
         ;; (dec Vd) -- subtract tagged fixnum 1 (raw value 2)
         (let* ((vd (first operands))
                (pd (i386-vreg-phys vd)))
           (if pd
               (i386-emit-sub-reg-imm buf pd 2)
               (progn
                 (i386-load-vreg buf +i386-eax+ vd)
                 (i386-emit-sub-reg-imm buf +i386-eax+ 2)
                 (i386-store-vreg buf vd +i386-eax+)))))

        ;; ============================================
        ;; Bitwise Operations
        ;; ============================================
        ((op= +op-and+)
         (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (let ((pb (i386-vreg-phys vb)))
             (if pb
                 (i386-emit-and-reg-reg buf +i386-eax+ pb)
                 (i386-emit-and-reg-mem buf +i386-eax+ +i386-ebp+ (i386-spill-offset vb))))
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-or+)
         (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (let ((pb (i386-vreg-phys vb)))
             (if pb
                 (i386-emit-or-reg-reg buf +i386-eax+ pb)
                 (i386-emit-or-reg-mem buf +i386-eax+ +i386-ebp+ (i386-spill-offset vb))))
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-xor+)
         (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (let ((pb (i386-vreg-phys vb)))
             (if pb
                 (i386-emit-xor-reg-reg buf +i386-eax+ pb)
                 (i386-emit-xor-reg-mem buf +i386-eax+ +i386-ebp+ (i386-spill-offset vb))))
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-shl+)
         (let ((vd (first operands)) (vs (second operands)) (amt (third operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-shl-reg-imm buf +i386-eax+ amt)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-shr+)
         (let ((vd (first operands)) (vs (second operands)) (amt (third operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-shr-reg-imm buf +i386-eax+ amt)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-sar+)
         (let ((vd (first operands)) (vs (second operands)) (amt (third operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-sar-reg-imm buf +i386-eax+ amt)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-ldb+)
         ;; (ldb Vd Vs pos:imm8 size:imm8) -- bit field extract
         (let ((vd (first operands)) (vs (second operands))
               (pos (third operands)) (size (fourth operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (when (> pos 0)
             (i386-emit-shr-reg-imm buf +i386-eax+ pos))
           (i386-emit-and-reg-imm buf +i386-eax+ (logand (1- (ash 1 size)) #xFFFFFFFF))
           (i386-store-vreg buf vd +i386-eax+)))

        ;; ============================================
        ;; Comparison
        ;; ============================================
        ((op= +op-cmp+)
         ;; (cmp Va Vb) -- sets CPU flags
         (let ((va (first operands)) (vb (second operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (let ((pb (i386-vreg-phys vb)))
             (if pb
                 (i386-emit-cmp-reg-reg buf +i386-eax+ pb)
                 (i386-emit-cmp-reg-mem buf +i386-eax+ +i386-ebp+ (i386-spill-offset vb))))))

        ((op= +op-test+)
         ;; (test Va Vb) -- AND, sets flags, discards result
         (let ((va (first operands)) (vb (second operands)))
           (i386-load-vreg buf +i386-eax+ va)
           (let ((pb (i386-vreg-phys vb)))
             (if pb
                 (i386-emit-test-reg-reg buf +i386-eax+ pb)
                 (progn
                   (i386-load-vreg buf +scratch0+ vb)
                   (i386-emit-test-reg-reg buf +i386-eax+ +scratch0+))))))

        ;; ============================================
        ;; Branches
        ;; ============================================
        ;; MVM branch offsets are 16-bit signed, relative to the end
        ;; of the branch instruction in MVM bytecode.

        ((op= +op-br+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jmp-rel32 buf label)))

        ((op= +op-beq+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jcc buf :e label)))

        ((op= +op-bne+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jcc buf :ne label)))

        ((op= +op-blt+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jcc buf :l label)))

        ((op= +op-bge+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jcc buf :ge label)))

        ((op= +op-ble+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jcc buf :le label)))

        ((op= +op-bgt+)
         (let* ((off (first operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-emit-jcc buf :g label)))

        ((op= +op-bnull+)
         ;; (bnull Vs off16) -- compare Vs against NIL (VN in frame slot)
         (let* ((vs (first operands))
                (off (second operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-cmp-reg-mem buf +i386-eax+ +i386-ebp+ +vn-off+)
           (i386-emit-jcc buf :e label)))

        ((op= +op-bnnull+)
         ;; (bnnull Vs off16) -- branch if Vs is not NIL
         (let* ((vs (first operands))
                (off (second operands))
                (target-pos (+ mvm-next-pos off))
                (label (i386-ensure-label-at state target-pos)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-cmp-reg-mem buf +i386-eax+ +i386-ebp+ +vn-off+)
           (i386-emit-jcc buf :ne label)))

        ;; ============================================
        ;; List Operations (32-bit cons cells, 4-byte words)
        ;; ============================================
        ((op= +op-car+)
         ;; (car Vd Vs) -- load car from cons cell
         ;; Cons tag = 0x01, so untag: ptr - 1, car at [ptr-1+0] = [ptr-1]
         ;; With type check: verify low 4 bits == 0x01
         (let ((vd (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           ;; Type check
           (i386-emit-mov-reg-reg buf +scratch0+ +i386-eax+)
           (i386-emit-and-reg-imm buf +scratch0+ +tag-mask+)
           (i386-emit-cmp-reg-imm buf +scratch0+ +tag-cons+)
           (let ((ok-label (i386-make-label)))
             (i386-emit-jcc buf :e ok-label)
             (i386-emit-int3 buf)   ; trap on non-cons
             (i386-emit-label buf ok-label))
           ;; Strip tag, load car (word 0)
           (i386-emit-sub-reg-imm buf +i386-eax+ +tag-cons+)
           (i386-emit-mov-reg-mem buf +i386-eax+ +i386-eax+ 0)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-cdr+)
         ;; (cdr Vd Vs) -- load cdr from cons cell
         ;; cdr at [ptr - tag + 4] = [ptr - 1 + 4] = [ptr + 3]
         (let ((vd (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           ;; Type check
           (i386-emit-mov-reg-reg buf +scratch0+ +i386-eax+)
           (i386-emit-and-reg-imm buf +scratch0+ +tag-mask+)
           (i386-emit-cmp-reg-imm buf +scratch0+ +tag-cons+)
           (let ((ok-label (i386-make-label)))
             (i386-emit-jcc buf :e ok-label)
             (i386-emit-int3 buf)
             (i386-emit-label buf ok-label))
           ;; Strip tag, load cdr (word 1 = offset 4 on 32-bit)
           (i386-emit-sub-reg-imm buf +i386-eax+ +tag-cons+)
           (i386-emit-mov-reg-mem buf +i386-eax+ +i386-eax+ 4)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-cons+)
         ;; (cons Vd Va Vb) -- allocate cons cell via bump allocator
         ;; VA is in frame slot. [VA+0]=car, [VA+4]=cdr
         ;; result = VA | cons_tag, advance VA by 8
         (let ((vd (first operands)) (va-arg (second operands)) (vb-arg (third operands)))
           ;; Load alloc pointer into EDX
           (i386-emit-mov-reg-mem buf +i386-edx+ +i386-ebp+ +va-off+)
           ;; Store car
           (i386-load-vreg buf +i386-eax+ va-arg)
           (i386-emit-mov-mem-reg buf +i386-edx+ 0 +i386-eax+)
           ;; Store cdr
           (i386-load-vreg buf +scratch0+ vb-arg)
           (i386-emit-mov-mem-reg buf +i386-edx+ 4 +scratch0+)
           ;; Tag pointer as cons
           (i386-emit-mov-reg-reg buf +i386-eax+ +i386-edx+)
           (i386-emit-or-reg-imm buf +i386-eax+ +tag-cons+)
           ;; Bump alloc by 8 (two 4-byte words)
           (i386-emit-add-reg-imm buf +i386-edx+ 8)
           (i386-emit-mov-mem-reg buf +i386-ebp+ +va-off+ +i386-edx+)
           ;; Store result
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-setcar+)
         ;; (setcar Vd Vs) -- [Vd - tag] = Vs
         (let ((vd-reg (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vd-reg)
           (i386-emit-sub-reg-imm buf +i386-eax+ +tag-cons+)
           (i386-load-vreg buf +scratch0+ vs)
           (i386-emit-mov-mem-reg buf +i386-eax+ 0 +scratch0+)))

        ((op= +op-setcdr+)
         ;; (setcdr Vd Vs) -- [Vd - tag + 4] = Vs
         (let ((vd-reg (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vd-reg)
           (i386-emit-sub-reg-imm buf +i386-eax+ +tag-cons+)
           (i386-load-vreg buf +scratch0+ vs)
           (i386-emit-mov-mem-reg buf +i386-eax+ 4 +scratch0+)))

        ((op= +op-consp+)
         ;; (consp Vd Vs) -- test low 4 bits for cons tag
         (let ((vd (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-and-reg-imm buf +i386-eax+ +tag-mask+)
           (i386-emit-cmp-reg-imm buf +i386-eax+ +tag-cons+)
           (let ((true-label (i386-make-label))
                 (done-label (i386-make-label)))
             (i386-emit-jcc buf :e true-label)
             ;; False: load NIL
             (i386-emit-mov-reg-mem buf +i386-eax+ +i386-ebp+ +vn-off+)
             (i386-emit-jmp-rel32 buf done-label)
             ;; True: load T
             (i386-emit-label buf true-label)
             (i386-emit-mov-reg-imm buf +i386-eax+ +i386-mvm-t+)
             (i386-emit-label buf done-label))
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-atom+)
         ;; (atom Vd Vs) -- opposite of consp
         (let ((vd (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-and-reg-imm buf +i386-eax+ +tag-mask+)
           (i386-emit-cmp-reg-imm buf +i386-eax+ +tag-cons+)
           (let ((true-label (i386-make-label))
                 (done-label (i386-make-label)))
             (i386-emit-jcc buf :ne true-label)
             ;; Is cons -> return NIL
             (i386-emit-mov-reg-mem buf +i386-eax+ +i386-ebp+ +vn-off+)
             (i386-emit-jmp-rel32 buf done-label)
             ;; Not cons -> return T
             (i386-emit-label buf true-label)
             (i386-emit-mov-reg-imm buf +i386-eax+ +i386-mvm-t+)
             (i386-emit-label buf done-label))
           (i386-store-vreg buf vd +i386-eax+)))

        ;; ============================================
        ;; Object Operations (32-bit, 4-byte slots)
        ;; ============================================
        ((op= +op-alloc-obj+)
         ;; (alloc-obj Vd size:imm16 subtag:imm8)
         ;; Header word at [VA]: (subtag << 8) | tag_bits
         ;; Result = VA | object_tag, advance VA by aligned size
         (let ((vd (first operands)) (size (second operands)) (subtag (third operands)))
           (i386-emit-mov-reg-mem buf +i386-edx+ +i386-ebp+ +va-off+)
           ;; Write header: (subtag << 8) | +tag-object+
           (i386-emit-mov-mem-imm buf +i386-edx+ 0
                                  (logior (ash subtag 8) +tag-object+))
           ;; Tag pointer
           (i386-emit-mov-reg-reg buf +i386-eax+ +i386-edx+)
           (i386-emit-or-reg-imm buf +i386-eax+ +tag-object+)
           ;; Bump alloc: header (4) + size*4, aligned to 8
           (let ((total (logand (+ (* (1+ size) 4) 7) (lognot 7))))
             (i386-emit-add-reg-imm buf +i386-edx+ total))
           (i386-emit-mov-mem-reg buf +i386-ebp+ +va-off+ +i386-edx+)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-obj-ref+)
         ;; (obj-ref Vd Vobj idx:imm8) -- load object slot
         (let ((vd (first operands)) (vobj (second operands)) (idx (third operands)))
           (if (= vobj +vreg-vfp+)
               ;; Frame slot access: use safe EBP-relative offset below spill area
               (progn
                 (i386-emit-mov-reg-mem buf +i386-eax+ +i386-ebp+
                                        (+ +frame-slot-base+ (* idx -4)))
                 (i386-store-vreg buf vd +i386-eax+))
               ;; Normal object slot access
               (progn
                 (i386-load-vreg buf +i386-eax+ vobj)
                 (i386-emit-sub-reg-imm buf +i386-eax+ +tag-object+)
                 (i386-emit-mov-reg-mem buf +i386-eax+ +i386-eax+ (* (1+ idx) 4))
                 (i386-store-vreg buf vd +i386-eax+)))))

        ((op= +op-obj-set+)
         ;; (obj-set Vobj idx:imm8 Vs) -- store object slot
         (let ((vobj (first operands)) (idx (second operands)) (vs (third operands)))
           (if (= vobj +vreg-vfp+)
               ;; Frame slot store: use safe EBP-relative offset below spill area
               (progn
                 (i386-load-vreg buf +scratch0+ vs)
                 (i386-emit-mov-mem-reg buf +i386-ebp+
                                        (+ +frame-slot-base+ (* idx -4)) +scratch0+))
               ;; Normal object slot store
               (progn
                 (i386-load-vreg buf +i386-eax+ vobj)
                 (i386-emit-sub-reg-imm buf +i386-eax+ +tag-object+)
                 (i386-load-vreg buf +scratch0+ vs)
                 (i386-emit-mov-mem-reg buf +i386-eax+ (* (1+ idx) 4) +scratch0+)))))

        ((op= +op-obj-tag+)
         ;; (obj-tag Vd Vs) -- extract low 4-bit tag as tagged fixnum
         (let ((vd (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-and-reg-imm buf +i386-eax+ +tag-mask+)
           (i386-emit-shl-reg-imm buf +i386-eax+ 1)  ; tag as fixnum
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-obj-subtag+)
         ;; (obj-subtag Vd Vs) -- extract subtag from object header
         (let ((vd (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-sub-reg-imm buf +i386-eax+ +tag-object+)
           (i386-emit-mov-reg-mem buf +i386-eax+ +i386-eax+ 0)  ; load header
           (i386-emit-shr-reg-imm buf +i386-eax+ 8)             ; shift to subtag
           (i386-emit-and-reg-imm buf +i386-eax+ #xFF)          ; mask to 8 bits
           (i386-emit-shl-reg-imm buf +i386-eax+ 1)             ; tag as fixnum
           (i386-store-vreg buf vd +i386-eax+)))

        ;; ============================================
        ;; Raw Memory Operations
        ;; ============================================
        ((op= +op-load+)
         ;; (load Vd Vaddr width:imm8)
         (let ((vd (first operands)) (vaddr (second operands)) (width (third operands)))
           (i386-load-vreg buf +i386-eax+ vaddr)
           (ecase width
             (0 (i386-emit-movzx-byte buf +i386-eax+ +i386-eax+ 0))
             (1 (i386-emit-movzx-word buf +i386-eax+ +i386-eax+ 0))
             (2 (i386-emit-mov-reg-mem buf +i386-eax+ +i386-eax+ 0))
             (3 (i386-emit-mov-reg-mem buf +i386-eax+ +i386-eax+ 0)))  ; 64-bit: low 32
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-store+)
         ;; (store Vaddr Vs width:imm8)
         (let ((vaddr (first operands)) (vs (second operands)) (width (third operands)))
           (i386-load-vreg buf +i386-eax+ vaddr)
           (i386-load-vreg buf +scratch0+ vs)
           (ecase width
             (0 (i386-emit-mov-mem8-reg buf +i386-eax+ 0 +scratch0+))
             (1 (i386-emit-mov-mem16-reg buf +i386-eax+ 0 +scratch0+))
             (2 (i386-emit-mov-mem-reg buf +i386-eax+ 0 +scratch0+))
             (3 (i386-emit-mov-mem-reg buf +i386-eax+ 0 +scratch0+)))))

        ((op= +op-fence+)
         (i386-emit-mfence buf))

        ;; ============================================
        ;; Function Calling (cdecl convention)
        ;; ============================================
        ((op= +op-call+)
         ;; (call target:imm32)
         ;; Target operand is the bytecode offset of the called function.
         ;; ESI/EDI/EBX are callee-saved in cdecl, so they survive.
         ;; EAX/ECX/EDX are caller-saved and will be clobbered.
         (let* ((target-offset (first operands))
                (fn-table (i386-translate-state-function-table state))
                (label (when fn-table (gethash target-offset fn-table))))
           (if label
               (i386-emit-call-rel32 buf label)
               ;; Unknown target: emit with placeholder
               (i386-emit-call-rel32 buf nil))))

        ((op= +op-call-ind+)
         ;; (call-ind Vs) -- indirect call through register
         (let ((vs (first operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-call-reg buf +i386-eax+)))

        ((op= +op-ret+)
         ;; Return: emit full epilogue (restores callee-saved, pops frame)
         (i386-emit-epilogue buf))

        ((op= +op-tailcall+)
         ;; (tailcall target:imm32) -- tear down frame and jump
         ;; Target operand is the bytecode offset of the called function.
         (let* ((target-offset (first operands))
                (fn-table (i386-translate-state-function-table state))
                (label (when fn-table (gethash target-offset fn-table))))
           ;; Restore callee-saved before frame teardown
           (i386-emit-mov-reg-mem buf +i386-ebx+ +i386-ebp+ +save-ebx-off+)
           (i386-emit-mov-reg-mem buf +i386-esi+ +i386-ebp+ +save-esi-off+)
           (i386-emit-mov-reg-mem buf +i386-edi+ +i386-ebp+ +save-edi-off+)
           (i386-emit-mov-reg-reg buf +i386-esp+ +i386-ebp+)
           (i386-emit-pop-reg buf +i386-ebp+)
           ;; Jump instead of call
           (if label
               (i386-emit-jmp-rel32 buf label)
               (i386-emit-jmp-rel32 buf nil))))

        ;; ============================================
        ;; GC and Allocation
        ;; ============================================
        ((op= +op-alloc-cons+)
         ;; (alloc-cons Vd) -- bump-allocate cons cell, tag as cons
         (let ((vd (first operands)))
           (i386-emit-mov-reg-mem buf +i386-eax+ +i386-ebp+ +va-off+)
           ;; Tag as cons
           (i386-emit-mov-reg-reg buf +scratch0+ +i386-eax+)
           (i386-emit-or-reg-imm buf +scratch0+ +tag-cons+)
           ;; Bump alloc by 8
           (i386-emit-add-reg-imm buf +i386-eax+ 8)
           (i386-emit-mov-mem-reg buf +i386-ebp+ +va-off+ +i386-eax+)
           ;; Store tagged result
           (i386-store-vreg buf vd +scratch0+)))

        ((op= +op-gc-check+)
         ;; Compare VA (alloc ptr) against VL (alloc limit)
         ;; Both in frame slots. If VA >= VL, trigger GC.
         (i386-emit-mov-reg-mem buf +i386-eax+ +i386-ebp+ +va-off+)
         (i386-emit-cmp-reg-mem buf +i386-eax+ +i386-ebp+ +vl-off+)
         (let ((ok-label (i386-make-label)))
           (i386-emit-jcc buf :b ok-label)   ; unsigned below -> room left
           ;; GC needed
           (let ((gc-lbl (i386-translate-state-gc-label state)))
             (if gc-lbl
                 (i386-emit-call-rel32 buf gc-lbl)
                 (i386-emit-int buf #x31)))  ; trap to GC handler
           (i386-emit-label buf ok-label)))

        ((op= +op-write-barrier+)
         ;; (write-barrier Vobj) -- mark card table dirty (stub)
         (let ((vobj (first operands)))
           (i386-load-vreg buf +i386-eax+ vobj)
           (i386-emit-shr-reg-imm buf +i386-eax+ 12)
           ;; Card table write would go here; NOP for now
           (i386-emit-nop buf)))

        ;; ============================================
        ;; Actor / Concurrency
        ;; ============================================
        ((op= +op-save-ctx+)
         ;; Save register-resident state for actor context switch
         (i386-emit-push-reg buf +i386-esi+)     ; V0
         (i386-emit-push-reg buf +i386-edi+)     ; V1
         (i386-emit-push-reg buf +i386-ebx+)     ; V4
         ;; Also save VA/VL/VN from frame
         (i386-emit-push-mem buf +i386-ebp+ +va-off+)
         (i386-emit-push-mem buf +i386-ebp+ +vl-off+)
         (i386-emit-push-mem buf +i386-ebp+ +vn-off+))

        ((op= +op-restore-ctx+)
         ;; Restore (reverse order of save)
         (i386-emit-pop-reg buf +i386-eax+)
         (i386-emit-mov-mem-reg buf +i386-ebp+ +vn-off+ +i386-eax+)
         (i386-emit-pop-reg buf +i386-eax+)
         (i386-emit-mov-mem-reg buf +i386-ebp+ +vl-off+ +i386-eax+)
         (i386-emit-pop-reg buf +i386-eax+)
         (i386-emit-mov-mem-reg buf +i386-ebp+ +va-off+ +i386-eax+)
         (i386-emit-pop-reg buf +i386-ebx+)
         (i386-emit-pop-reg buf +i386-edi+)
         (i386-emit-pop-reg buf +i386-esi+))

        ((op= +op-yield+)
         ;; Preemption check: stub (NOP)
         (i386-emit-nop buf))

        ((op= +op-atomic-xchg+)
         ;; (atomic-xchg Vd Vaddr Vs) -- XCHG [Vaddr], Vs -> Vd
         (let ((vd (first operands)) (vaddr (second operands)) (vs (third operands)))
           (i386-load-vreg buf +i386-eax+ vs)         ; value to exchange
           (i386-load-vreg buf +scratch0+ vaddr)      ; address
           (i386-emit-xchg-mem-reg buf +scratch0+ 0 +i386-eax+)
           ;; Old value now in EAX
           (i386-store-vreg buf vd +i386-eax+)))

        ;; ============================================
        ;; I/O Port Operations
        ;; ============================================
        ((op= +op-io-read+)
         ;; (io-read Vd port:imm16 width:imm8)
         (let ((vd (first operands)) (port (second operands)) (width (third operands)))
           (cond
             ;; Short form for ports <= 255
             ((<= port 255)
              (ecase width
                (0 (i386-emit-in-al-imm8 buf port)
                   (i386-emit-and-reg-imm buf +i386-eax+ #xFF))
                (1 (i386-emit-in-ax-imm8 buf port)
                   (i386-emit-and-reg-imm buf +i386-eax+ #xFFFF))
                (2 (i386-emit-in-eax-imm8 buf port))
                (3 (i386-emit-in-eax-imm8 buf port))))
             ;; General form: port in DX
             (t
              (i386-emit-mov-reg-imm buf +i386-edx+ port)
              (ecase width
                (0 (i386-emit-in-al-dx buf)
                   (i386-emit-and-reg-imm buf +i386-eax+ #xFF))
                (1 (i386-emit-in-ax-dx buf)
                   (i386-emit-and-reg-imm buf +i386-eax+ #xFFFF))
                (2 (i386-emit-in-eax-dx buf))
                (3 (i386-emit-in-eax-dx buf)))))
           ;; Tag as fixnum: SHL 1
           (i386-emit-shl-reg-imm buf +i386-eax+ 1)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-io-write+)
         ;; (io-write port:imm16 Vs width:imm8)
         (let ((port (first operands)) (vs (second operands)) (width (third operands)))
           ;; Load value, untag
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-sar-reg-imm buf +i386-eax+ 1)
           (cond
             ((<= port 255)
              (ecase width
                (0 (i386-emit-out-imm8-al buf port))
                (1 (i386-emit-byte buf #x66) (i386-emit-out-imm8-eax buf port))
                (2 (i386-emit-out-imm8-eax buf port))
                (3 (i386-emit-out-imm8-eax buf port))))
             (t
              (i386-emit-mov-reg-imm buf +i386-edx+ port)
              (ecase width
                (0 (i386-emit-out-dx-al buf))
                (1 (i386-emit-out-dx-ax buf))
                (2 (i386-emit-out-dx-eax buf))
                (3 (i386-emit-out-dx-eax buf)))))))

        ((op= +op-halt+)
         ;; Infinite halt loop
         (let ((halt-label (i386-make-label)))
           (i386-emit-label buf halt-label)
           (i386-emit-cli buf)
           (i386-emit-hlt buf)
           (i386-emit-jmp-rel32 buf halt-label)))

        ((op= +op-cli+)
         (i386-emit-cli buf))

        ((op= +op-sti+)
         (i386-emit-sti buf))

        ;; ============================================
        ;; Per-CPU Data (FS segment on i386)
        ;; ============================================
        ((op= +op-percpu-ref+)
         ;; (percpu-ref Vd offset:imm16)
         ;; MOV EAX, FS:[disp32]
         (let ((vd (first operands)) (offset (second operands)))
           (i386-emit-byte buf #x64)   ; FS segment prefix
           (i386-emit-byte buf #x8B)   ; MOV r32, r/m32
           (i386-emit-byte buf (i386-modrm #b00 +i386-eax+ 5))  ; mod=00, rm=5 -> [disp32]
           (i386-emit-u32 buf offset)
           (i386-store-vreg buf vd +i386-eax+)))

        ((op= +op-percpu-set+)
         ;; (percpu-set offset:imm16 Vs)
         ;; MOV FS:[disp32], reg
         (let ((offset (first operands)) (vs (second operands)))
           (i386-load-vreg buf +i386-eax+ vs)
           (i386-emit-byte buf #x64)   ; FS segment prefix
           (i386-emit-byte buf #x89)   ; MOV r/m32, r32
           (i386-emit-byte buf (i386-modrm #b00 +i386-eax+ 5))
           (i386-emit-u32 buf offset)))

        ;; ============================================
        ;; Unknown Opcode
        ;; ============================================
        (t
         ;; Emit trap for unrecognised MVM instructions
         (i386-emit-int3 buf))))))

;;; ============================================================
;;; Branch Target Scanning (Pass 1)
;;; ============================================================

(defun i386-scan-branch-targets (state)
  "Pre-scan MVM bytecode to identify all branch targets and create labels."
  (let* ((bytes (i386-translate-state-mvm-bytes state))
         (offset (i386-translate-state-mvm-offset state))
         (length (i386-translate-state-mvm-length state))
         (pos offset)
         (limit (+ offset length)))
    (loop while (< pos limit)
          do (multiple-value-bind (opcode operands new-pos)
                 (decode-instruction bytes pos)
               (let ((info (gethash opcode *opcode-table*)))
                 (when info
                   (let ((op-types (opcode-info-operands info)))
                     (when (member :off16 op-types)
                       ;; Find the offset operand value
                       (let ((off-idx (position :off16 op-types)))
                         (when off-idx
                           (let* ((off (nth off-idx operands))
                                  (target-pos (+ new-pos off)))
                             (i386-ensure-label-at state target-pos))))))))
               (setf pos new-pos)))))

;;; ============================================================
;;; Main Translation Entry Points
;;; ============================================================

(defun translate-i386-function (bytecode offset length &optional target-buf)
  "Translate a single MVM function to i386 native code.
   Returns an i386-buffer with the translated code."
  (let* ((buf (or target-buf (make-i386-buffer)))
         (state (make-i386-translate-state
                 :buf buf
                 :mvm-bytes bytecode
                 :mvm-length length
                 :mvm-offset offset)))
    ;; Emit prologue
    (i386-emit-prologue buf)
    ;; Pass 1: scan for branch targets
    (i386-scan-branch-targets state)
    ;; Pass 2: translate instructions
    (let ((pos offset)
          (limit (+ offset length)))
      (loop while (< pos limit)
            do (progn
                 ;; Emit label if this position is a branch target
                 (let ((label (gethash pos (i386-translate-state-label-map state))))
                   (when label
                     (i386-emit-label buf label)))
                 ;; Decode and translate
                 (multiple-value-bind (opcode operands new-pos)
                     (decode-instruction bytecode pos)
                   (i386-translate-insn state opcode operands new-pos)
                   (setf pos new-pos)))))
    ;; Resolve label fixups
    (i386-fixup-labels buf)
    buf))

(defun translate-mvm-to-i386 (bytecode function-table)
  "Translate MVM bytecode to i386 native code.
   BYTECODE: vector of (unsigned-byte 8) containing MVM instructions.
   FUNCTION-TABLE: list of (name offset length) entries.
   Returns (VALUES i386-buffer function-name-to-label-map)."
  (let* ((buf (make-i386-buffer))
         (n-functions (length function-table))
         (fn-labels (make-array n-functions))
         (fn-map (make-hash-table :test 'equal))
         ;; Map bytecode-offset → native label for CALL resolution
         (fn-offset-to-label (make-hash-table :test 'eql)))
    ;; Allocate a label for each function
    (loop for i from 0 below n-functions
          for entry in function-table
          for name = (first entry)
          for offset = (second entry)
          do (let ((label (i386-make-label)))
               (setf (aref fn-labels i) label)
               (setf (gethash name fn-map) label)
               (setf (gethash offset fn-offset-to-label) label)))
    ;; Translate each function
    (loop for i from 0 below n-functions
          for entry in function-table
          for fn-offset = (second entry)
          for fn-length = (third entry)
          do (let* ((fn-label (aref fn-labels i))
                    (state (make-i386-translate-state
                            :buf buf
                            :mvm-bytes bytecode
                            :mvm-length fn-length
                            :mvm-offset fn-offset
                            :function-table fn-offset-to-label)))
               ;; Emit function label
               (i386-emit-label buf fn-label)
               ;; Emit prologue
               (i386-emit-prologue buf)
               ;; Pass 1: scan branch targets
               (i386-scan-branch-targets state)
               ;; Pass 2: translate
               (let ((pos fn-offset)
                     (limit (+ fn-offset fn-length)))
                 (loop while (< pos limit)
                       do (progn
                            (let ((label (gethash pos
                                                  (i386-translate-state-label-map state))))
                              (when label
                                (i386-emit-label buf label)))
                            (multiple-value-bind (opcode operands new-pos)
                                (decode-instruction bytecode pos)
                              (i386-translate-insn state opcode operands new-pos)
                              (setf pos new-pos)))))))
    ;; Resolve all label fixups
    (i386-fixup-labels buf)
    (values buf fn-map)))

;;; ============================================================
;;; Target Descriptor Installation
;;; ============================================================

(defun i386-translate-single-instruction (opcode operands target buf)
  "Translate one MVM instruction to i386 code.
   Conforms to the target translate-fn signature."
  (declare (ignore target))
  (let ((state (make-i386-translate-state :buf buf)))
    (i386-translate-insn state opcode operands 0)))

(defun install-i386-translator ()
  "Install the i386 translator into the *target-i386* descriptor."
  (setf (target-translate-fn modus64.mvm:*target-i386*)
        #'translate-mvm-to-i386)
  (setf (target-emit-prologue modus64.mvm:*target-i386*)
        (lambda (target buf) (declare (ignore target)) (i386-emit-prologue buf)))
  (setf (target-emit-epilogue modus64.mvm:*target-i386*)
        (lambda (target buf) (declare (ignore target)) (i386-emit-epilogue buf)))
  modus64.mvm:*target-i386*)

;;; ============================================================
;;; Debugging Utilities
;;; ============================================================

(defun i386-disassemble-native (buf &key (start 0) (end nil))
  "Print a hex dump of the native code in BUF."
  (let* ((bytes (i386-buffer-bytes buf))
         (limit (or end (fill-pointer bytes))))
    (loop for pos from start below limit
          do (when (zerop (mod (- pos start) 16))
               (when (> pos start) (terpri))
               (format t "  ~4,'0X: " pos))
             (format t "~2,'0X " (aref bytes pos)))
    (terpri)))

(defun i386-translation-statistics (bytecode-length native-buf)
  "Return (VALUES native-length expansion-ratio)."
  (let ((native-length (i386-current-pos native-buf)))
    (values native-length
            (if (zerop bytecode-length) 0.0
                (float (/ native-length bytecode-length))))))

;;; ============================================================
;;; Register Name Table
;;; ============================================================

(defparameter *i386-reg-names*
  #("EAX" "ECX" "EDX" "EBX" "ESP" "EBP" "ESI" "EDI"))

(defun i386-reg-name (reg)
  "Return the printable name of an i386 register."
  (if (< reg (length *i386-reg-names*))
      (aref *i386-reg-names* reg)
      (format nil "?~D" reg)))

(defun i386-describe-vreg-mapping ()
  "Print the virtual-to-physical register mapping for debugging."
  (format t "~&i386 Virtual Register Mapping (~D-bit):~%" (* 4 8))
  (format t "  ~20A ~8A ~A~%" "VREG" "PHYS" "SPILL")
  (format t "  ~20A ~8A ~A~%" "----" "----" "-----")
  (dotimes (i (length *i386-vreg-map*))
    (let ((phys (aref *i386-vreg-map* i))
          (name (if (< i (length modus64.mvm::*vreg-names*))
                    (aref modus64.mvm::*vreg-names* i)
                    (format nil "?~D" i))))
      (if phys
          (format t "  ~20A ~8A~%" name (i386-reg-name phys))
          (format t "  ~20A ~8A [EBP~@D]~%" name "spill"
                  (handler-case (i386-spill-offset i)
                    (error () 0)))))))
