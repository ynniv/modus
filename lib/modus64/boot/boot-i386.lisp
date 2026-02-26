;;;; boot-i386.lisp - i386 (32-bit x86) Boot Sequence for Modus64
;;;;
;;;; Boot protocol for i386 (Multiboot1 via QEMU -kernel or GRUB):
;;;;   1. Multiboot1 header at 0x100000 (1MB)
;;;;   2. GRUB hands off in 32-bit protected mode (A20 enabled, paging off)
;;;;   3. EAX = Multiboot magic (0x2BADB002), EBX = multiboot info pointer
;;;;   4. Set up flat GDT (code + data segments)
;;;;   5. Set up stack
;;;;   6. Initialize serial console (COM1 @ 0x3F8)
;;;;   7. Initialize allocation state in stack frame:
;;;;      VA (alloc ptr) -> [EBP - 16]
;;;;      VL (alloc limit) -> [EBP - 20]
;;;;      VN (NIL const) -> [EBP - 24]
;;;;      (i386 has no dedicated alloc registers -- all spilled)
;;;;   8. Call kernel-main
;;;;
;;;; This is simpler than x86-64: no long mode transition, no page tables
;;;; needed for identity-mapped 32-bit operation.

(in-package :modus64.mvm)

;;; ============================================================
;;; i386 Boot Constants
;;; ============================================================

(defconstant +i386-kernel-load-addr+ #x100000)     ; 1MB - standard Multiboot load
(defconstant +i386-stack-top+        #x400000)     ; 4MB - initial stack top

;; Memory regions (32-bit addresses)
(defconstant +i386-cons-base+        #x02000000)   ; 32MB - cons space
(defconstant +i386-general-base+     #x03000000)   ; 48MB - general heap

;; Per-CPU structures
(defconstant +i386-percpu-base+      #x360000)     ; Per-CPU data area
(defconstant +i386-percpu-stride+    #x20)          ; 32 bytes per CPU (4-byte pointers)

;; Multiboot1 constants
(defconstant +i386-multiboot1-magic+    #x1BADB002)
(defconstant +i386-multiboot1-aout-kludge+ #x00010000) ; Use address fields
(defconstant +i386-multiboot1-flags+    (logior #x00000003  ; Page-align + memory info
                                                +i386-multiboot1-aout-kludge+))
(defconstant +i386-multiboot1-bl-magic+ #x2BADB002) ; Bootloader writes this to EAX

;; Serial port
(defconstant +i386-com1-base+ #x3F8)

;;; ============================================================
;;; i386 Multiboot1 Header
;;; ============================================================

(defun emit-i386-multiboot-header (buf)
  "Emit Multiboot1 header with aout-kludge for QEMU -kernel loading.
   With aout-kludge, header is 32 bytes:
     magic(4) flags(4) checksum(4) header_addr(4) load_addr(4)
     load_end_addr(4) bss_end_addr(4) entry_addr(4)
   Entry code starts immediately after this header at load_addr + 32."
  (let* ((load-addr +i386-kernel-load-addr+)
         (entry-addr (+ load-addr 32)))  ; entry right after 32-byte header
    ;; Magic number
    (mvm-emit-u32 buf +i386-multiboot1-magic+)
    ;; Flags: page-align + memory info + aout-kludge
    (mvm-emit-u32 buf +i386-multiboot1-flags+)
    ;; Checksum: -(magic + flags) mod 2^32
    (mvm-emit-u32 buf (logand #xFFFFFFFF
                               (- (+ +i386-multiboot1-magic+
                                     +i386-multiboot1-flags+))))
    ;; Address fields (aout-kludge)
    (mvm-emit-u32 buf load-addr)    ; header_addr (where header is in memory)
    (mvm-emit-u32 buf load-addr)    ; load_addr (where to load file)
    (mvm-emit-u32 buf 0)            ; load_end_addr (0 = load entire file)
    (mvm-emit-u32 buf 0)            ; bss_end_addr
    (mvm-emit-u32 buf entry-addr))) ; entry_addr

;;; ============================================================
;;; i386 Serial Port Initialization
;;; ============================================================

(defun i386-init-serial (buf)
  "Emit i386 machine code to initialize COM1 (0x3F8) for 115200 8N1.
   Uses: DX (port number), AL (data byte), OUT instruction.
   Encoding: mov dx, imm16 = 66 BA lo hi
             mov al, imm8  = B0 imm
             out dx, al    = EE"
  (labels ((serial-out (port val)
             ;; mov dx, port (16-bit immediate with operand size prefix)
             (mvm-emit-byte buf #x66)
             (mvm-emit-byte buf #xBA)
             (mvm-emit-u16 buf port)
             ;; mov al, val
             (mvm-emit-byte buf #xB0)
             (mvm-emit-byte buf val)
             ;; out dx, al
             (mvm-emit-byte buf #xEE)))
    (let ((base +i386-com1-base+))
      ;; Disable interrupts
      (serial-out (+ base 1) #x00)
      ;; Enable DLAB (set baud rate)
      (serial-out (+ base 3) #x80)
      ;; Set divisor = 1 (115200 baud), low byte
      (serial-out (+ base 0) #x01)
      ;; Divisor high byte
      (serial-out (+ base 1) #x00)
      ;; 8 bits, no parity, 1 stop bit (8N1), clear DLAB
      (serial-out (+ base 3) #x03)
      ;; Enable FIFO, clear, 14-byte threshold
      (serial-out (+ base 2) #xC7))))

;;; ============================================================
;;; i386 32-bit Entry Point
;;; ============================================================

(defun emit-i386-entry (buf)
  "Emit 32-bit protected mode entry point for i386.
   Multiboot spec guarantees: EAX = 0x2BADB002, EBX = multiboot info ptr,
   CS/DS/ES/FS/GS/SS = valid flat 32-bit segments, A20 enabled, paging off.

   We rely on bootloader segments (no GDT reload needed for initial boot).

   Register usage in the i386 translator (from translate-i386.lisp):
     V0=ESI, V1=EDI, V4=EBX (callee-saved GPRs)
     VR=EAX (return value)
     VA,VL,VN = stack slots at [EBP-16], [EBP-20], [EBP-24]
     Scratch: ECX, EDX"
  ;; --- CLI (redundant but safe) ---
  (mvm-emit-byte buf #xFA)                         ; cli

  ;; --- Save multiboot info pointer (EBX) to scratch location ---
  ;; mov [0x500], ebx
  (mvm-emit-byte buf #x89)                         ; mov [disp32], ebx
  (mvm-emit-byte buf #x1D)                         ; ModR/M: EBX -> [disp32]
  (mvm-emit-u32 buf #x500)

  ;; --- Set up stack ---
  ;; mov esp, +i386-stack-top+
  (mvm-emit-byte buf #xBC)                         ; mov esp, imm32
  (mvm-emit-u32 buf +i386-stack-top+)

  ;; --- Set up frame pointer ---
  ;; push ebp; mov ebp, esp
  (mvm-emit-byte buf #x55)                         ; push ebp
  (mvm-emit-byte buf #x89)                         ; mov ebp, esp
  (mvm-emit-byte buf #xE5)
  ;; sub esp, 80 (reserve frame: 76 bytes rounded to 80 for alignment)
  (mvm-emit-byte buf #x83)                         ; sub esp, imm8
  (mvm-emit-byte buf #xEC)
  (mvm-emit-byte buf 80)

  ;; --- Initialize alloc/limit/NIL in stack frame ---
  ;; mov [ebp - 16], +i386-cons-base+  (VA = alloc pointer)
  (mvm-emit-byte buf #xC7)                         ; mov [ebp+disp8], imm32
  (mvm-emit-byte buf #x45)                         ; ModR/M: [EBP + disp8]
  (mvm-emit-byte buf (logand #xFF -16))             ; disp8 = -16 (0xF0)
  (mvm-emit-u32 buf +i386-cons-base+)
  ;; mov [ebp - 20], +i386-general-base+  (VL = alloc limit)
  (mvm-emit-byte buf #xC7)
  (mvm-emit-byte buf #x45)
  (mvm-emit-byte buf (logand #xFF -20))             ; disp8 = -20 (0xEC)
  (mvm-emit-u32 buf +i386-general-base+)
  ;; mov [ebp - 24], 0x09  (VN = NIL placeholder, object-tagged null)
  (mvm-emit-byte buf #xC7)
  (mvm-emit-byte buf #x45)
  (mvm-emit-byte buf (logand #xFF -24))             ; disp8 = -24 (0xE8)
  (mvm-emit-u32 buf #x09)                          ; tagged NIL (object tag, addr 0)

  ;; --- Initialize serial port ---
  (i386-init-serial buf)

  ;; --- Fall through to compiled native code ---
  ;; The image builder appends translated Lisp code immediately after.
  )

;;; ============================================================
;;; i386 Per-CPU Layout
;;; ============================================================

(defun i386-percpu-layout ()
  "Per-CPU structure for i386. 32 bytes per CPU.
   Accessed via a fixed base address + cpu_id * stride.
   All fields are 4 bytes (32-bit pointers/values)."
  '((:self-ptr       0   4)   ; Pointer to this per-CPU struct
    (:reduction       4   4)   ; Reduction counter (tagged fixnum)
    (:cpu-id          8   4)   ; CPU number (tagged fixnum)
    (:current-actor  12   4)   ; Current actor pointer
    (:obj-alloc      16   4)   ; Per-actor object alloc pointer
    (:obj-limit      20   4)   ; Per-actor object alloc limit
    (:idle-stack     24   4)   ; Idle stack top for this CPU
    (:reserved       28   4))) ; Padding to 32-byte stride

;;; ============================================================
;;; i386 Boot Integration
;;; ============================================================

(defun i386-boot-descriptor ()
  "Return the i386 boot descriptor for image building.
   i386 is simpler than x86-64: no long mode, no page tables needed
   for the initial identity-mapped 32-bit flat model."
  (list :arch :i386
        :multiboot-header-fn #'emit-i386-multiboot-header
        :entry-fn #'emit-i386-entry
        :serial-init-fn #'i386-init-serial
        :percpu-layout-fn #'i386-percpu-layout
        :load-addr +i386-kernel-load-addr+
        :stack-top +i386-stack-top+
        :cons-base +i386-cons-base+
        :general-base +i386-general-base+
        :percpu-base +i386-percpu-base+
        :percpu-stride +i386-percpu-stride+))
