;;;; boot32.lisp - 32-bit Boot Stub
;;;;
;;;; This code runs after GRUB loads us. It:
;;;; 1. Sets up a simple GDT
;;;; 2. Enables PAE paging with identity mapping
;;;; 3. Enables long mode (IA-32e)
;;;; 4. Jumps to 64-bit kernel code
;;;;
;;;; All code here is 32-bit, emitted directly as bytes.

(in-package :modus64.cross)

;;; ============================================================
;;; Memory Layout
;;; ============================================================
;;;
;;; 0x00100000 (1MB)   - Kernel load address
;;; 0x00110000         - Page tables (64KB reserved)
;;; 0x00120000         - Stack top (grows down)
;;; 0x00130000         - 64-bit kernel code starts here

(defconstant +kernel-load-addr+ #x00100000)
(defconstant +page-tables-addr+ #x00110000)
(defconstant +stack-top+        #x00120000)
(defconstant +kernel64-addr+    #x00130000)

;;; ============================================================
;;; GDT (Global Descriptor Table)
;;; ============================================================
;;;
;;; Minimal GDT for switching to long mode:
;;;   0x00: Null descriptor
;;;   0x08: 32-bit code segment (for boot stub)
;;;   0x10: 32-bit data segment
;;;   0x18: 64-bit code segment
;;;   0x20: 64-bit data segment

(defun emit-gdt (buf)
  "Emit GDT and GDTR"
  (let ((gdt-start (code-buffer-position buf)))
    ;; Null descriptor (required)
    (emit-u64 buf 0)

    ;; 32-bit code segment: base=0, limit=4GB, DPL=0, type=code
    ;; Flags: G=1 (4KB granularity), D=1 (32-bit), L=0, AVL=0
    ;; Access: P=1, DPL=00, S=1, Type=1010 (exec/read)
    (emit-u64 buf #x00CF9A000000FFFF)

    ;; 32-bit data segment: base=0, limit=4GB, DPL=0, type=data
    ;; Flags: G=1, D=1, L=0, AVL=0
    ;; Access: P=1, DPL=00, S=1, Type=0010 (read/write)
    (emit-u64 buf #x00CF92000000FFFF)

    ;; 64-bit code segment: L=1, D=0 (required for long mode)
    ;; Access: P=1, DPL=00, S=1, Type=1010 (exec/read)
    (emit-u64 buf #x00AF9A000000FFFF)

    ;; 64-bit data segment
    ;; Access: P=1, DPL=00, S=1, Type=0010 (read/write)
    (emit-u64 buf #x00AF92000000FFFF)

    (let ((gdt-size (- (code-buffer-position buf) gdt-start)))
      (values gdt-start gdt-size))))

(defun emit-gdtr (buf gdt-addr gdt-size)
  "Emit GDTR structure (6 bytes: limit + base)"
  (emit-u16 buf (1- gdt-size))  ; Limit = size - 1
  (emit-u32 buf gdt-addr))       ; Base address (32-bit for now)

;;; ============================================================
;;; Page Tables
;;; ============================================================
;;;
;;; For long mode, we need 4-level paging:
;;;   PML4 -> PDPT -> PD -> PT (or 2MB pages)
;;;
;;; We'll use 2MB pages for simplicity (identity-mapped first 4GB).

(defconstant +page-present+    #x001)
(defconstant +page-writable+   #x002)
(defconstant +page-user+       #x004)
(defconstant +page-2mb+        #x080)  ; PS bit for 2MB pages

(defun emit-page-tables-setup (buf pml4-addr)
  "Emit code to set up identity-mapped page tables at PML4-ADDR.
   Uses 2MB pages, maps first 4GB."

  ;; Clear page table area (16KB = 4 pages worth)
  ;; mov edi, pml4_addr
  ;; mov ecx, 4096 (number of dwords = 16KB/4)
  ;; xor eax, eax
  ;; rep stosd
  (emit-bytes buf #xBF)  ; mov edi, imm32
  (emit-u32 buf pml4-addr)
  (emit-bytes buf #xB9)  ; mov ecx, imm32
  (emit-u32 buf 4096)
  (emit-bytes buf #x31 #xC0)  ; xor eax, eax
  (emit-bytes buf #xF3 #xAB)  ; rep stosd

  ;; PML4[0] -> PDPT
  ;; mov dword [pml4_addr], pdpt_addr | PRESENT | WRITABLE
  (emit-bytes buf #xC7 #x05)  ; mov [imm32], imm32
  (emit-u32 buf pml4-addr)
  (emit-u32 buf (logior (+ pml4-addr #x1000) +page-present+ +page-writable+))

  ;; PDPT[0..3] -> PD[0..3] (4GB coverage)
  ;; Each PDPT entry points to a page directory
  (let ((pdpt-addr (+ pml4-addr #x1000))
        (pd-base (+ pml4-addr #x2000)))
    (dotimes (i 4)
      ;; mov dword [pdpt_addr + i*8], pd_addr + i*0x1000 | flags
      (emit-bytes buf #xC7 #x05)  ; mov [imm32], imm32
      (emit-u32 buf (+ pdpt-addr (* i 8)))
      (emit-u32 buf (logior (+ pd-base (* i #x1000))
                            +page-present+ +page-writable+))))

  ;; PD entries: 2MB pages, identity mapped
  ;; Each PD has 512 entries, each mapping 2MB = 1GB per PD
  ;; We need 4 PDs for 4GB
  (let ((pd-base (+ pml4-addr #x2000)))
    ;; mov edi, pd_base
    (emit-bytes buf #xBF)
    (emit-u32 buf pd-base)
    ;; mov eax, 0x83 (present + writable + 2MB page)
    (emit-bytes buf #xB8)
    (emit-u32 buf (logior +page-present+ +page-writable+ +page-2mb+))
    ;; mov ecx, 2048 (512 entries * 4 PDs)
    (emit-bytes buf #xB9)
    (emit-u32 buf 2048)

    ;; Loop: store entry, add 2MB to address
    (let ((loop-label (code-buffer-position buf)))
      ;; stosd (store eax to [edi], edi += 4)
      (emit-bytes buf #xAB)
      ;; add eax, 0x200000 (2MB)
      (emit-bytes buf #x05)
      (emit-u32 buf #x200000)
      ;; mov dword [edi], 0 (high 32 bits = 0)
      (emit-bytes buf #xC7 #x07)
      (emit-u32 buf 0)
      ;; add edi, 4
      (emit-bytes buf #x83 #xC7 #x04)
      ;; loop
      (emit-bytes buf #xE2)
      (emit-byte buf (- loop-label (code-buffer-position buf) 1)))))

;;; ============================================================
;;; Long Mode Enable
;;; ============================================================

(defun emit-enable-long-mode (buf pml4-addr kernel64-entry)
  "Emit code to enable long mode and jump to 64-bit code"

  ;; Disable interrupts
  (emit-byte buf #xFA)  ; cli

  ;; Load PML4 into CR3
  ;; mov eax, pml4_addr
  ;; mov cr3, eax
  (emit-bytes buf #xB8)
  (emit-u32 buf pml4-addr)
  (emit-bytes buf #x0F #x22 #xD8)  ; mov cr3, eax

  ;; Enable PAE in CR4
  ;; mov eax, cr4
  ;; or eax, 0x20 (PAE bit)
  ;; mov cr4, eax
  (emit-bytes buf #x0F #x20 #xE0)  ; mov eax, cr4
  (emit-bytes buf #x83 #xC8 #x20)  ; or eax, 0x20
  (emit-bytes buf #x0F #x22 #xE0)  ; mov cr4, eax

  ;; Enable long mode in EFER MSR
  ;; mov ecx, 0xC0000080 (EFER MSR)
  ;; rdmsr
  ;; or eax, 0x100 (LME bit)
  ;; wrmsr
  (emit-bytes buf #xB9)
  (emit-u32 buf #xC0000080)
  (emit-bytes buf #x0F #x32)       ; rdmsr
  (emit-bytes buf #x0D)            ; or eax, imm32
  (emit-u32 buf #x100)
  (emit-bytes buf #x0F #x30)       ; wrmsr

  ;; Enable paging in CR0 (activates long mode)
  ;; mov eax, cr0
  ;; or eax, 0x80000000 (PG bit)
  ;; mov cr0, eax
  (emit-bytes buf #x0F #x20 #xC0)  ; mov eax, cr0
  (emit-bytes buf #x0D)            ; or eax, imm32
  (emit-u32 buf #x80000000)
  (emit-bytes buf #x0F #x22 #xC0)  ; mov cr0, eax

  ;; Far jump to 64-bit code segment
  ;; This must be an absolute far jump to the 64-bit code segment (0x18)
  ;; jmp 0x18:kernel64_entry
  (emit-bytes buf #xEA)            ; jmp far ptr16:32
  (emit-u32 buf kernel64-entry)
  (emit-u16 buf #x18))             ; 64-bit code segment selector

;;; ============================================================
;;; Boot Stub Entry Point
;;; ============================================================

(defun emit-boot32-stub (buf kernel64-entry)
  "Emit the complete 32-bit boot stub.
   Returns the entry point address (relative to buf start)."
  (let ((entry-point (code-buffer-position buf)))

    ;; Save multiboot info pointer (in ebx from GRUB)
    ;; push ebx
    (emit-bytes buf #x53)

    ;; Set up stack
    ;; mov esp, STACK_TOP
    (emit-bytes buf #xBC)
    (emit-u32 buf +stack-top+)

    ;; Save multiboot pointer to known location
    ;; pop eax
    ;; mov [0x500], eax  ; Store at safe low memory
    (emit-bytes buf #x58)
    (emit-bytes buf #xA3)
    (emit-u32 buf #x500)

    ;; Set up page tables
    (emit-page-tables-setup buf +page-tables-addr+)

    ;; Enable long mode and jump to 64-bit code
    (emit-enable-long-mode buf +page-tables-addr+ kernel64-entry)

    ;; Should never reach here, but just in case
    ;; hlt
    (emit-byte buf #xF4)

    entry-point))

;;; ============================================================
;;; GDT Loading (needs to happen before paging)
;;; ============================================================

(defun emit-boot32-with-gdt (buf kernel64-entry)
  "Emit boot stub with embedded GDT"
  (let* ((gdt-offset (code-buffer-position buf))
         (gdt-start gdt-offset))

    ;; Emit GDT
    (multiple-value-bind (gdt-start gdt-size)
        (emit-gdt buf)
      (declare (ignore gdt-start))

      ;; Emit GDTR
      (let ((gdtr-offset (code-buffer-position buf)))
        (emit-gdtr buf (+ +kernel-load-addr+ gdt-offset) gdt-size)

        ;; Now emit the actual boot code
        (let ((entry-point (code-buffer-position buf)))

          ;; Load GDT
          ;; lgdt [gdtr_addr]
          (emit-bytes buf #x0F #x01 #x15)
          (emit-u32 buf (+ +kernel-load-addr+ gdtr-offset))

          ;; Reload segments with new GDT
          ;; mov ax, 0x10 (32-bit data segment)
          ;; mov ds, ax
          ;; mov es, ax
          ;; mov fs, ax
          ;; mov gs, ax
          ;; mov ss, ax
          (emit-bytes buf #x66 #xB8 #x10 #x00)  ; mov ax, 0x10
          (emit-bytes buf #x8E #xD8)            ; mov ds, ax
          (emit-bytes buf #x8E #xC0)            ; mov es, ax
          (emit-bytes buf #x8E #xE0)            ; mov fs, ax
          (emit-bytes buf #x8E #xE8)            ; mov gs, ax
          (emit-bytes buf #x8E #xD0)            ; mov ss, ax

          ;; Far jump to reload CS with 32-bit code segment
          ;; jmp 0x08:next
          (emit-bytes buf #xEA)
          (let ((next-addr (+ +kernel-load-addr+ (code-buffer-position buf) 6)))
            (emit-u32 buf next-addr))
          (emit-u16 buf #x08)

          ;; Continue with boot stub
          (emit-boot32-stub buf kernel64-entry)

          entry-point)))))

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-boot32 ()
  "Test boot32 stub generation"
  (let ((buf (make-code-buffer)))
    (let ((entry (emit-boot32-with-gdt buf #x00130000)))
      (format t "Boot32 stub: ~D bytes, entry at offset ~D~%"
              (code-buffer-position buf) entry)
      (format t "First 64 bytes: ~{~2,'0X ~}~%"
              (coerce (subseq (code-buffer-bytes buf) 0
                             (min 64 (code-buffer-position buf)))
                      'list))
      buf)))
