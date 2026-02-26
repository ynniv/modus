;;;; boot-x64.lisp - x86-64 Boot Sequence for Modus64
;;;;
;;;; Refactored from the original monolithic boot code.
;;;; This file contains the x86-64-specific boot sequence that runs
;;;; before the platform-independent kernel-main.
;;;;
;;;; Boot protocol for x86-64 (BIOS/Multiboot):
;;;;   1. Multiboot header at 0x100000
;;;;   2. 32-bit protected mode entry (from GRUB/bootloader)
;;;;   3. Set up page tables (identity map + higher half)
;;;;   4. Enable long mode (64-bit)
;;;;   5. Jump to 64-bit entry point
;;;;   6. Set up GDT, IDT, TSS
;;;;   7. Initialize serial console
;;;;   8. Set up GC metadata, NFN table, symbol table
;;;;   9. Initialize allocation registers (R12=alloc, R14=limit, R15=NIL)
;;;;  10. Call kernel-main

(in-package :modus64.mvm)

;;; ============================================================
;;; x86-64 Boot Constants
;;; ============================================================

(defconstant +x64-kernel-load-addr+ #x100000)     ; 1MB - multiboot load address
(defconstant +x64-page-tables-addr+ #x200000)     ; 2MB - page table location
(defconstant +x64-stack-top+        #x400000)     ; 4MB - initial stack top
(defconstant +x64-kernel64-addr+    #x100100)     ; 64-bit entry point

;; Memory regions
(defconstant +x64-wired-base+    #x02000000)      ; 32MB - wired memory
(defconstant +x64-pinned-base+   #x03000000)      ; 48MB - pinned memory
(defconstant +x64-fn-base+       #x03800000)      ; 56MB - function space
(defconstant +x64-cons-base+     #x04000000)      ; 64MB - cons space
(defconstant +x64-general-base+  #x05000000)      ; 80MB - general heap

;; Per-CPU structures
(defconstant +x64-percpu-base+   #x360000)        ; Per-CPU data area
(defconstant +x64-percpu-stride+ #x40)            ; 64 bytes per CPU

;; AP trampoline
(defconstant +x64-ap-trampoline+ #x8000)          ; Real-mode AP startup code

;;; ============================================================
;;; x86-64 Boot Code Generation
;;; ============================================================

(defun emit-x64-multiboot-header (buf)
  "Emit Multiboot1 header with aout-kludge for QEMU -kernel loading.
   32 bytes: magic(4) flags(4) checksum(4) header_addr(4) load_addr(4)
   load_end_addr(4) bss_end_addr(4) entry_addr(4).
   Entry point (boot32 code) starts immediately after at load_addr + 32."
  (let* ((magic #x1BADB002)
         (flags (logior #x00000003   ; page-align + memory info
                        #x00010000)) ; aout-kludge (address fields)
         (load-addr +x64-kernel-load-addr+)
         (entry-addr (+ load-addr 32)))  ; boot32 starts right after header
    (mvm-emit-u32 buf magic)
    (mvm-emit-u32 buf flags)
    (mvm-emit-u32 buf (logand #xFFFFFFFF (- (+ magic flags))))
    ;; Address fields
    (mvm-emit-u32 buf load-addr)     ; header_addr
    (mvm-emit-u32 buf load-addr)     ; load_addr
    (mvm-emit-u32 buf 0)            ; load_end_addr (0 = whole file)
    (mvm-emit-u32 buf 0)            ; bss_end_addr
    (mvm-emit-u32 buf entry-addr))) ; entry_addr → boot32 code

(defun emit-x64-boot32 (buf)
  "Emit 32-bit protected mode boot stub.
   Multiboot enters here in 32-bit protected mode with flat segments.
   Sets up page tables at 0x110000, enables PAE + long mode + paging,
   then far-jumps to 64-bit code segment.
   The 64-bit entry follows immediately after this code."
  (let ((base-addr +x64-kernel-load-addr+)
        (pml4-addr #x110000)
        (boot32-start (mvm-buffer-position buf)))
    ;; cli
    (mvm-emit-byte buf #xFA)

    ;; Save multiboot info: mov [0x500], ebx
    (mvm-emit-byte buf #x89)
    (mvm-emit-byte buf #x1D)
    (mvm-emit-u32 buf #x500)

    ;; Set up stack: mov esp, 0x120000
    (mvm-emit-byte buf #xBC)
    (mvm-emit-u32 buf #x120000)

    ;; Clear page table area (16KB at pml4-addr)
    ;; mov edi, pml4-addr
    (mvm-emit-byte buf #xBF)
    (mvm-emit-u32 buf pml4-addr)
    ;; mov ecx, 4096  (16KB / 4 bytes)
    (mvm-emit-byte buf #xB9)
    (mvm-emit-u32 buf 4096)
    ;; xor eax, eax
    (mvm-emit-byte buf #x31)
    (mvm-emit-byte buf #xC0)
    ;; rep stosd
    (mvm-emit-byte buf #xF3)
    (mvm-emit-byte buf #xAB)

    ;; PML4[0] -> PDPT  (pml4_addr+0x1000 | 3)
    (mvm-emit-byte buf #xC7)  ; mov [addr], imm32
    (mvm-emit-byte buf #x05)
    (mvm-emit-u32 buf pml4-addr)
    (mvm-emit-u32 buf (logior (+ pml4-addr #x1000) 3))

    ;; PDPT[0] -> PD  (pml4_addr+0x2000 | 3)
    (mvm-emit-byte buf #xC7)
    (mvm-emit-byte buf #x05)
    (mvm-emit-u32 buf (+ pml4-addr #x1000))
    (mvm-emit-u32 buf (logior (+ pml4-addr #x2000) 3))

    ;; Fill PD with 512 x 2MB pages (identity map first 1GB)
    ;; mov edi, pd_addr
    (mvm-emit-byte buf #xBF)
    (mvm-emit-u32 buf (+ pml4-addr #x2000))
    ;; mov eax, 0x83  (present + writable + 2MB page)
    (mvm-emit-byte buf #xB8)
    (mvm-emit-u32 buf #x83)
    ;; mov ecx, 512
    (mvm-emit-byte buf #xB9)
    (mvm-emit-u32 buf 512)
    ;; loop: stosd; add eax,0x200000; mov [edi],0; add edi,4; loop
    (let ((loop-start (mvm-buffer-position buf)))
      (mvm-emit-byte buf #xAB)        ; stosd (store eax to [edi], edi+=4)
      (mvm-emit-byte buf #x05)        ; add eax, 0x200000
      (mvm-emit-u32 buf #x200000)
      (mvm-emit-byte buf #xC7)        ; mov dword [edi], 0  (high 32 bits)
      (mvm-emit-byte buf #x07)
      (mvm-emit-u32 buf 0)
      (mvm-emit-byte buf #x83)        ; add edi, 4
      (mvm-emit-byte buf #xC7)
      (mvm-emit-byte buf #x04)
      (mvm-emit-byte buf #xE2)        ; loop
      (mvm-emit-byte buf (logand #xFF (- loop-start (mvm-buffer-position buf) 1))))

    ;; Load CR3 with PML4
    (mvm-emit-byte buf #xB8)          ; mov eax, pml4
    (mvm-emit-u32 buf pml4-addr)
    (mvm-emit-byte buf #x0F)          ; mov cr3, eax
    (mvm-emit-byte buf #x22)
    (mvm-emit-byte buf #xD8)

    ;; Enable PAE (CR4.PAE = bit 5)
    (mvm-emit-byte buf #x0F)          ; mov eax, cr4
    (mvm-emit-byte buf #x20)
    (mvm-emit-byte buf #xE0)
    (mvm-emit-byte buf #x83)          ; or eax, 0x20
    (mvm-emit-byte buf #xC8)
    (mvm-emit-byte buf #x20)
    (mvm-emit-byte buf #x0F)          ; mov cr4, eax
    (mvm-emit-byte buf #x22)
    (mvm-emit-byte buf #xE0)

    ;; Enable long mode (IA32_EFER.LME = bit 8)
    (mvm-emit-byte buf #xB9)          ; mov ecx, 0xC0000080 (IA32_EFER)
    (mvm-emit-u32 buf #xC0000080)
    (mvm-emit-byte buf #x0F)          ; rdmsr
    (mvm-emit-byte buf #x32)
    (mvm-emit-byte buf #x0D)          ; or eax, 0x100
    (mvm-emit-u32 buf #x100)
    (mvm-emit-byte buf #x0F)          ; wrmsr
    (mvm-emit-byte buf #x30)

    ;; Enable paging (CR0.PG = bit 31)
    (mvm-emit-byte buf #x0F)          ; mov eax, cr0
    (mvm-emit-byte buf #x20)
    (mvm-emit-byte buf #xC0)
    (mvm-emit-byte buf #x0D)          ; or eax, 0x80000000
    (mvm-emit-u32 buf #x80000000)
    (mvm-emit-byte buf #x0F)          ; mov cr0, eax
    (mvm-emit-byte buf #x22)
    (mvm-emit-byte buf #xC0)

    ;; We need a GDT with a 64-bit code segment for the far jump.
    ;; Emit GDT inline, then lgdt, then far jump.
    ;; GDT is right here in the code stream — we jump over it.
    ;; jmp short past_gdt (2-byte instruction, patched below)
    (let ((jmp-pos (mvm-buffer-position buf)))
      (mvm-emit-byte buf #xEB)        ; jmp rel8
      (mvm-emit-byte buf 0)           ; placeholder

      ;; GDT data (3 descriptors = 24 bytes)
      (let ((gdt-pos (mvm-buffer-position buf)))
        ;; Null descriptor
        (mvm-emit-u32 buf 0) (mvm-emit-u32 buf 0)
        ;; 32-bit code (selector 0x08) — not needed after jump but harmless
        (mvm-emit-u32 buf #x0000FFFF) (mvm-emit-u32 buf #x00CF9A00)
        ;; 64-bit code (selector 0x10)
        (mvm-emit-u32 buf #x0000FFFF) (mvm-emit-u32 buf #x00AF9A00)

        ;; GDTR (6 bytes: limit u16 + base u32)
        (let ((gdtr-pos (mvm-buffer-position buf))
              (gdt-addr (+ base-addr gdt-pos)))
          (mvm-emit-u16 buf 23)       ; limit = 3*8 - 1
          (mvm-emit-u32 buf gdt-addr)

          ;; Patch jmp rel8 to skip past GDT+GDTR (land here)
          (let ((after-gdt (mvm-buffer-position buf))
                (bytes (mvm-buffer-bytes buf)))
            (setf (aref bytes (1+ jmp-pos))
                  (logand #xFF (- after-gdt jmp-pos 2)))

            ;; lgdt [gdtr_addr]
            (mvm-emit-byte buf #x0F)
            (mvm-emit-byte buf #x01)
            (mvm-emit-byte buf #x15)  ; lgdt [disp32]
            (mvm-emit-u32 buf (+ base-addr gdtr-pos))

            ;; Far jump to 64-bit code: jmp far 0x10:entry64_addr
            ;; entry64 is the next thing emitted (by emit-x64-kernel64-entry)
            ;; We don't know the exact offset yet, so emit placeholder and patch
            (let ((jmp64-pos (mvm-buffer-position buf)))
              (mvm-emit-byte buf #xEA)  ; jmp far ptr16:32
              (mvm-emit-u32 buf 0)      ; placeholder entry64 addr
              (mvm-emit-u16 buf #x0010) ; 64-bit code selector

              ;; hlt (shouldn't reach)
              (mvm-emit-byte buf #xF4)

              ;; Record the patch location for emit-x64-kernel64-entry to fill
              ;; Store it as a property on the buffer's labels hash
              (setf (gethash :jmp64-patch (mvm-buffer-labels buf))
                    (1+ jmp64-pos)))))))))

(defun emit-x64-kernel64-entry (buf)
  "Emit 64-bit kernel entry point.
   Called after long mode is established by boot32."
  (let ((base-addr +x64-kernel-load-addr+)
        (entry64-pos (mvm-buffer-position buf)))
    ;; Patch boot32's far-jump target to point here
    (let ((patch-offset (gethash :jmp64-patch (mvm-buffer-labels buf))))
      (when patch-offset
        (let ((entry64-addr (+ base-addr entry64-pos))
              (bytes (mvm-buffer-bytes buf)))
          (setf (aref bytes (+ patch-offset 0)) (ldb (byte 8  0) entry64-addr))
          (setf (aref bytes (+ patch-offset 1)) (ldb (byte 8  8) entry64-addr))
          (setf (aref bytes (+ patch-offset 2)) (ldb (byte 8 16) entry64-addr))
          (setf (aref bytes (+ patch-offset 3)) (ldb (byte 8 24) entry64-addr)))))

    ;; Reload data segments with 64-bit selector (GDT entry 2 = 0x10 is code;
    ;; we don't have a separate 64-bit data selector, use null/0 which is fine
    ;; in long mode where segment bases are ignored except FS/GS)
    ;; mov ax, 0
    (mvm-emit-byte buf #x66)
    (mvm-emit-byte buf #xB8)
    (mvm-emit-u16 buf #x0000)
    ;; mov ds, ax
    (mvm-emit-byte buf #x8E) (mvm-emit-byte buf #xD8)
    ;; mov es, ax
    (mvm-emit-byte buf #x8E) (mvm-emit-byte buf #xC0)
    ;; mov ss, ax
    (mvm-emit-byte buf #x8E) (mvm-emit-byte buf #xD0)

    ;; Set up 64-bit stack: mov rsp, 0x200000
    (mvm-emit-byte buf #x48)          ; REX.W
    (mvm-emit-byte buf #xBC)          ; mov rsp, imm64
    (mvm-emit-u32 buf #x200000)
    (mvm-emit-u32 buf 0)              ; high 32 bits

    ;; Initialize serial console (COM1 = 0x3F8)
    ;; Disable interrupts
    (mvm-emit-byte buf #x66) (mvm-emit-byte buf #xBA) (mvm-emit-u16 buf #x03F9)
    (mvm-emit-byte buf #xB0) (mvm-emit-byte buf #x00)
    (mvm-emit-byte buf #xEE)
    ;; DLAB
    (mvm-emit-byte buf #x66) (mvm-emit-byte buf #xBA) (mvm-emit-u16 buf #x03FB)
    (mvm-emit-byte buf #xB0) (mvm-emit-byte buf #x80)
    (mvm-emit-byte buf #xEE)
    ;; Baud 115200 (divisor=1)
    (mvm-emit-byte buf #x66) (mvm-emit-byte buf #xBA) (mvm-emit-u16 buf #x03F8)
    (mvm-emit-byte buf #xB0) (mvm-emit-byte buf #x01)
    (mvm-emit-byte buf #xEE)
    (mvm-emit-byte buf #x66) (mvm-emit-byte buf #xBA) (mvm-emit-u16 buf #x03F9)
    (mvm-emit-byte buf #xB0) (mvm-emit-byte buf #x00)
    (mvm-emit-byte buf #xEE)
    ;; 8N1
    (mvm-emit-byte buf #x66) (mvm-emit-byte buf #xBA) (mvm-emit-u16 buf #x03FB)
    (mvm-emit-byte buf #xB0) (mvm-emit-byte buf #x03)
    (mvm-emit-byte buf #xEE)
    ;; FIFO
    (mvm-emit-byte buf #x66) (mvm-emit-byte buf #xBA) (mvm-emit-u16 buf #x03FA)
    (mvm-emit-byte buf #xB0) (mvm-emit-byte buf #xC7)
    (mvm-emit-byte buf #xEE)

    ;; Fall through to native code
    ))

(defun emit-x64-ap-trampoline (buf)
  "Emit AP (Application Processor) startup trampoline for SMP.
   This code runs in real mode at a low physical address,
   transitions through protected mode to long mode,
   then jumps to the AP entry point."
  ;; Real mode → protected mode → long mode → ap-entry
  ;; The trampoline is copied to physical address 0x8000
  ;; AP processors start here after INIT-SIPI-SIPI
  (dotimes (i 512)
    (mvm-emit-byte buf #x90)))  ; Placeholder

;;; ============================================================
;;; x86-64 Platform Initialization
;;; ============================================================

(defun x64-init-serial (port)
  "Generate code to initialize a serial port (COM1 = 0x3F8).
   Returns a list of (port value) pairs for OUT instructions."
  (let ((base port))
    (list
     ;; Disable interrupts
     (cons (+ base 1) #x00)
     ;; Enable DLAB
     (cons (+ base 3) #x80)
     ;; Set baud rate divisor = 1 (115200 baud)
     (cons (+ base 0) #x01)
     (cons (+ base 1) #x00)
     ;; 8N1 (8 bits, no parity, 1 stop bit)
     (cons (+ base 3) #x03)
     ;; Enable FIFO
     (cons (+ base 2) #xC7)
     ;; RTS/DSR set
     (cons (+ base 4) #x0B))))

(defun x64-init-lapic ()
  "Generate LAPIC initialization sequence for the BSP.
   The LAPIC is memory-mapped at 0xFEE00000."
  ;; Spurious interrupt vector: 0xFF, enable LAPIC
  ;; Timer: periodic mode, vector 0x40
  ;; Divide configuration: divide by 16
  '((:lapic-svr   . #xFEE000F0)
    (:lapic-timer  . #xFEE00320)
    (:lapic-divide . #xFEE003E0)
    (:lapic-count  . #xFEE00380)))

;;; ============================================================
;;; x86-64 Interrupt Handling
;;; ============================================================

(defun x64-idt-entry (vector handler-addr ist dpl)
  "Create an IDT entry for the given vector.
   Returns an 16-byte IDT gate descriptor."
  (let ((offset-low (logand handler-addr #xFFFF))
        (offset-mid (logand (ash handler-addr -16) #xFFFF))
        (offset-high (logand (ash handler-addr -32) #xFFFFFFFF))
        (selector #x08)  ; 64-bit code segment
        (type-attr (logior #x8E (ash dpl 5))))  ; Present, interrupt gate
    (list offset-low selector ist type-attr offset-mid offset-high 0)))

;;; ============================================================
;;; x86-64 SMP (Symmetric Multi-Processing)
;;; ============================================================

(defun x64-init-smp-sequence ()
  "Return the SMP initialization sequence for x86-64.
   Uses INIT-SIPI-SIPI protocol:
   1. Send INIT IPI to all APs
   2. Wait 10ms
   3. Send SIPI with trampoline address
   4. Wait 200us
   5. Send SIPI again (some CPUs need two)
   6. APs start executing trampoline"
  '(:init-ipi :wait-10ms :sipi :wait-200us :sipi))

(defun x64-percpu-layout ()
  "Return the per-CPU structure layout for x86-64.
   Accessed via GS segment base."
  '((:self-ptr     0   8)   ; Pointer to this per-CPU struct
    (:reduction     8   8)   ; Reduction counter (tagged fixnum)
    (:cpu-id       16   8)   ; CPU number (tagged fixnum)
    (:current-actor 24  8)   ; Current actor pointer
    (:obj-alloc    40   8)   ; Per-actor object alloc pointer
    (:obj-limit    48   8)   ; Per-actor object alloc limit
    (:idle-stack   56   8))) ; Idle stack top for this CPU

;;; ============================================================
;;; x86-64 Boot Integration
;;; ============================================================

(defun x64-boot-descriptor ()
  "Return the x86-64 boot descriptor for image building"
  (list :arch :x86-64
        :multiboot-header-fn #'emit-x64-multiboot-header
        :boot32-fn #'emit-x64-boot32
        :kernel64-entry-fn #'emit-x64-kernel64-entry
        :ap-trampoline-fn #'emit-x64-ap-trampoline
        :serial-init-fn #'x64-init-serial
        :smp-sequence-fn #'x64-init-smp-sequence
        :percpu-layout-fn #'x64-percpu-layout
        :load-addr +x64-kernel-load-addr+
        :stack-top +x64-stack-top+
        :cons-base +x64-cons-base+
        :general-base +x64-general-base+))
