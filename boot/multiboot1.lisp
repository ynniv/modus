;;;; multiboot1.lisp - Multiboot1 Header Generator
;;;;
;;;; Multiboot1 is simpler than Multiboot2 and QEMU can load it directly.
;;;; Reference: https://www.gnu.org/software/grub/manual/multiboot/multiboot.html

(in-package :modus64.cross)

;;; ============================================================
;;; Multiboot1 Constants
;;; ============================================================

(defconstant +multiboot1-magic+ #x1BADB002)
(defconstant +multiboot1-bootloader-magic+ #x2BADB002)

;; Flags
(defconstant +multiboot1-page-align+  #x00000001)  ; Align modules on 4KB
(defconstant +multiboot1-memory-info+ #x00000002)  ; Provide memory map
(defconstant +multiboot1-video-mode+  #x00000004)  ; Video mode info
(defconstant +multiboot1-aout-kludge+ #x00010000)  ; Use address fields

;;; ============================================================
;;; Header Generation
;;; ============================================================

(defun emit-multiboot1-header (buf &key load-addr entry-addr)
  "Emit Multiboot1 header.
   If LOAD-ADDR and ENTRY-ADDR are provided, use aout-kludge format."
  (let ((flags (logior +multiboot1-page-align+
                       +multiboot1-memory-info+
                       (if load-addr +multiboot1-aout-kludge+ 0))))
    ;; Magic
    (emit-u32 buf +multiboot1-magic+)
    ;; Flags
    (emit-u32 buf flags)
    ;; Checksum (magic + flags + checksum = 0)
    (emit-u32 buf (logand #xFFFFFFFF (- (+ +multiboot1-magic+ flags))))

    ;; Address fields (only if aout-kludge flag set)
    (when load-addr
      (emit-u32 buf load-addr)      ; header_addr
      (emit-u32 buf load-addr)      ; load_addr
      (emit-u32 buf 0)              ; load_end_addr (0 = load entire file)
      (emit-u32 buf 0)              ; bss_end_addr
      (emit-u32 buf entry-addr))))  ; entry_addr

;;; ============================================================
;;; Complete Bootable Image Builder
;;; ============================================================

(defun build-multiboot1-image (output-path &key (lisp-forms nil))
  "Build a Multiboot1 bootable kernel image.
   This can be loaded directly by QEMU with -kernel."
  (let ((buf (make-code-buffer))
        (*functions* (make-hash-table :test 'eq))
        (*constants* nil))

    ;; The image layout:
    ;; 0x00000: Multiboot1 header (with aout-kludge)
    ;; 0x00030: 32-bit boot code (GDT, long mode switch)
    ;; 0x00xxx: 64-bit kernel entry
    ;; 0x00xxx: Compiled Lisp code

    ;; We'll use absolute addresses starting at 1MB (0x100000)
    (let* ((base-addr #x100000)
           (header-size 48)           ; Multiboot1 header with aout-kludge
           (boot32-offset header-size)
           (boot32-addr (+ base-addr boot32-offset)))

      ;; First pass: emit everything to calculate sizes
      ;; Emit placeholder header
      (dotimes (i header-size)
        (emit-byte buf 0))

      ;; Emit 32-bit boot stub
      (let* ((boot32-start (code-buffer-position buf)))
        ;; The boot32 code needs to know where 64-bit code starts
        ;; We'll emit it and patch the jump target later

        ;; === GDT ===
        (let ((gdt-offset (code-buffer-position buf)))
          ;; Null descriptor
          (emit-u64 buf 0)
          ;; 32-bit code segment (selector 0x08)
          (emit-u64 buf #x00CF9A000000FFFF)
          ;; 32-bit data segment (selector 0x10)
          (emit-u64 buf #x00CF92000000FFFF)
          ;; 64-bit code segment (selector 0x18)
          (emit-u64 buf #x00AF9A000000FFFF)
          ;; 64-bit data segment (selector 0x20)
          (emit-u64 buf #x00AF92000000FFFF)

          ;; GDTR (limit + base)
          (let ((gdtr-offset (code-buffer-position buf))
                (gdt-addr (+ base-addr gdt-offset)))
            (emit-u16 buf 39)         ; 5 entries * 8 - 1
            (emit-u32 buf gdt-addr)

            ;; === 32-bit entry point ===
            (let ((entry32-offset (code-buffer-position buf))
                  (entry32-addr (+ base-addr (code-buffer-position buf))))

              ;; Disable interrupts
              (emit-byte buf #xFA)     ; cli

              ;; Load GDT
              (emit-bytes buf #x0F #x01 #x15)  ; lgdt [addr]
              (emit-u32 buf (+ base-addr gdtr-offset))

              ;; Reload segments
              (emit-bytes buf #x66 #xB8 #x10 #x00)  ; mov ax, 0x10
              (emit-bytes buf #x8E #xD8)            ; mov ds, ax
              (emit-bytes buf #x8E #xC0)            ; mov es, ax
              (emit-bytes buf #x8E #xE0)            ; mov fs, ax
              (emit-bytes buf #x8E #xE8)            ; mov gs, ax
              (emit-bytes buf #x8E #xD0)            ; mov ss, ax

              ;; Far jump to reload CS
              (emit-byte buf #xEA)     ; jmp far
              (let ((after-jmp (+ base-addr (code-buffer-position buf) 6)))
                (emit-u32 buf after-jmp)
                (emit-u16 buf #x08))   ; 32-bit code selector

              ;; Save multiboot info (EBX from bootloader)
              (emit-bytes buf #x89 #x1D)  ; mov [addr], ebx
              (emit-u32 buf #x500)        ; Store at 0x500

              ;; Set up stack
              (emit-byte buf #xBC)     ; mov esp, imm32
              (emit-u32 buf #x120000)  ; Stack at 1.125MB

              ;; Set up page tables at 0x110000
              (let ((pml4-addr #x110000))
                ;; Clear page table area (16KB)
                (emit-bytes buf #xBF)  ; mov edi, imm32
                (emit-u32 buf pml4-addr)
                (emit-bytes buf #xB9)  ; mov ecx, imm32
                (emit-u32 buf 4096)    ; 16KB / 4
                (emit-bytes buf #x31 #xC0)  ; xor eax, eax
                (emit-bytes buf #xF3 #xAB)  ; rep stosd

                ;; PML4[0] -> PDPT
                (emit-bytes buf #xC7 #x05)  ; mov [addr], imm32
                (emit-u32 buf pml4-addr)
                (emit-u32 buf (logior (+ pml4-addr #x1000) 3))

                ;; PDPT[0] -> PD
                (emit-bytes buf #xC7 #x05)
                (emit-u32 buf (+ pml4-addr #x1000))
                (emit-u32 buf (logior (+ pml4-addr #x2000) 3))

                ;; PD: 512 entries, 2MB pages, identity mapped
                (emit-bytes buf #xBF)  ; mov edi, pd_addr
                (emit-u32 buf (+ pml4-addr #x2000))
                (emit-bytes buf #xB8)  ; mov eax, 0x83 (present+writable+2MB)
                (emit-u32 buf #x83)
                (emit-bytes buf #xB9)  ; mov ecx, 512
                (emit-u32 buf 512)
                ;; Loop
                (let ((loop-start (code-buffer-position buf)))
                  (emit-byte buf #xAB)        ; stosd
                  (emit-bytes buf #x05)       ; add eax, 0x200000
                  (emit-u32 buf #x200000)
                  (emit-bytes buf #xC7 #x07)  ; mov [edi], 0
                  (emit-u32 buf 0)
                  (emit-bytes buf #x83 #xC7 #x04)  ; add edi, 4
                  (emit-bytes buf #xE2)       ; loop
                  (emit-byte buf (- loop-start (code-buffer-position buf) 1)))

                ;; Load CR3
                (emit-bytes buf #xB8)  ; mov eax, pml4
                (emit-u32 buf pml4-addr)
                (emit-bytes buf #x0F #x22 #xD8)  ; mov cr3, eax

                ;; Enable PAE
                (emit-bytes buf #x0F #x20 #xE0)  ; mov eax, cr4
                (emit-bytes buf #x83 #xC8 #x20)  ; or eax, 0x20
                (emit-bytes buf #x0F #x22 #xE0)  ; mov cr4, eax

                ;; Enable long mode (EFER.LME)
                (emit-bytes buf #xB9)  ; mov ecx, 0xC0000080
                (emit-u32 buf #xC0000080)
                (emit-bytes buf #x0F #x32)  ; rdmsr
                (emit-bytes buf #x0D)       ; or eax, 0x100
                (emit-u32 buf #x100)
                (emit-bytes buf #x0F #x30)  ; wrmsr

                ;; Enable paging
                (emit-bytes buf #x0F #x20 #xC0)  ; mov eax, cr0
                (emit-bytes buf #x0D)            ; or eax, 0x80000000
                (emit-u32 buf #x80000000)
                (emit-bytes buf #x0F #x22 #xC0)) ; mov cr0, eax

              ;; Far jump to 64-bit code
              ;; We need to patch this address later
              (let ((jmp64-patch-offset (code-buffer-position buf)))
                (emit-byte buf #xEA)  ; jmp far
                (emit-u32 buf 0)      ; placeholder for 64-bit entry
                (emit-u16 buf #x18)   ; 64-bit code selector

                ;; Halt (shouldn't reach)
                (emit-byte buf #xF4)

                ;; Align to 16 bytes
                (loop while (not (zerop (mod (code-buffer-position buf) 16)))
                      do (emit-byte buf #x90))

                ;; === 64-bit code ===
                (let ((entry64-offset (code-buffer-position buf))
                      (entry64-addr (+ base-addr (code-buffer-position buf))))

                  ;; Patch the jump target
                  (let ((bytes (code-buffer-bytes buf)))
                    (setf (aref bytes (+ jmp64-patch-offset 1)) (ldb (byte 8 0) entry64-addr))
                    (setf (aref bytes (+ jmp64-patch-offset 2)) (ldb (byte 8 8) entry64-addr))
                    (setf (aref bytes (+ jmp64-patch-offset 3)) (ldb (byte 8 16) entry64-addr))
                    (setf (aref bytes (+ jmp64-patch-offset 4)) (ldb (byte 8 24) entry64-addr)))

                  ;; 64-bit code: reload segments
                  (emit-bytes buf #x66 #xB8 #x20 #x00)  ; mov ax, 0x20
                  (emit-bytes buf #x8E #xD8)            ; mov ds, ax
                  (emit-bytes buf #x8E #xC0)            ; mov es, ax
                  (emit-bytes buf #x8E #xE0)            ; mov fs, ax
                  (emit-bytes buf #x8E #xE8)            ; mov gs, ax
                  (emit-bytes buf #x8E #xD0)            ; mov ss, ax

                  ;; Set up 64-bit stack
                  (emit-byte buf #x48)  ; REX.W
                  (emit-byte buf #xBC)  ; mov rsp, imm64
                  (emit-u64 buf #x200000)

                  ;; Initialize serial (COM1 = 0x3F8)
                  ;; Disable interrupts
                  (emit-bytes buf #x66 #xBA #xF9 #x03)  ; mov dx, 0x3F9
                  (emit-bytes buf #xB0 #x00)            ; mov al, 0
                  (emit-byte buf #xEE)                  ; out dx, al

                  ;; Set DLAB
                  (emit-bytes buf #x66 #xBA #xFB #x03)  ; mov dx, 0x3FB
                  (emit-bytes buf #xB0 #x80)            ; mov al, 0x80
                  (emit-byte buf #xEE)                  ; out dx, al

                  ;; Set baud rate (115200)
                  (emit-bytes buf #x66 #xBA #xF8 #x03)  ; mov dx, 0x3F8
                  (emit-bytes buf #xB0 #x01)            ; mov al, 1
                  (emit-byte buf #xEE)
                  (emit-bytes buf #x66 #xBA #xF9 #x03)
                  (emit-bytes buf #xB0 #x00)
                  (emit-byte buf #xEE)

                  ;; 8N1
                  (emit-bytes buf #x66 #xBA #xFB #x03)
                  (emit-bytes buf #xB0 #x03)
                  (emit-byte buf #xEE)

                  ;; Enable FIFO
                  (emit-bytes buf #x66 #xBA #xFA #x03)
                  (emit-bytes buf #xB0 #xC7)
                  (emit-byte buf #xEE)

                  ;; Print boot message
                  (let ((message "Modus64 OK!"))
                    (loop for char across message do
                      ;; Wait for THR empty
                      (let ((wait-loop (code-buffer-position buf)))
                        (emit-bytes buf #x66 #xBA #xFD #x03)  ; mov dx, 0x3FD
                        (emit-byte buf #xEC)                  ; in al, dx
                        (emit-bytes buf #xA8 #x20)            ; test al, 0x20
                        (emit-bytes buf #x74)                 ; jz wait
                        (emit-byte buf (- wait-loop (code-buffer-position buf) 1)))
                      ;; Send char
                      (emit-bytes buf #x66 #xBA #xF8 #x03)  ; mov dx, 0x3F8
                      (emit-bytes buf #xB0 (char-code char)) ; mov al, char
                      (emit-byte buf #xEE)))                 ; out dx, al

                  ;; Newline
                  (let ((wait-loop (code-buffer-position buf)))
                    (emit-bytes buf #x66 #xBA #xFD #x03)
                    (emit-byte buf #xEC)
                    (emit-bytes buf #xA8 #x20)
                    (emit-bytes buf #x74)
                    (emit-byte buf (- wait-loop (code-buffer-position buf) 1)))
                  (emit-bytes buf #x66 #xBA #xF8 #x03)
                  (emit-bytes buf #xB0 #x0D)
                  (emit-byte buf #xEE)
                  (let ((wait-loop (code-buffer-position buf)))
                    (emit-bytes buf #x66 #xBA #xFD #x03)
                    (emit-byte buf #xEC)
                    (emit-bytes buf #xA8 #x20)
                    (emit-bytes buf #x74)
                    (emit-byte buf (- wait-loop (code-buffer-position buf) 1)))
                  (emit-bytes buf #x66 #xBA #xF8 #x03)
                  (emit-bytes buf #xB0 #x0A)
                  (emit-byte buf #xEE)

                  ;; Halt loop
                  (let ((halt-loop (code-buffer-position buf)))
                    (emit-byte buf #xF4)  ; hlt
                    (emit-bytes buf #xEB)
                    (emit-byte buf (- halt-loop (code-buffer-position buf) 1)))

                  ;; Now patch the multiboot header at the start
                  (let ((total-size (code-buffer-position buf))
                        (header-buf (make-code-buffer)))
                    (emit-multiboot1-header header-buf
                                            :load-addr base-addr
                                            :entry-addr entry32-addr)
                    ;; Copy header to start
                    (replace (code-buffer-bytes buf)
                             (code-buffer-bytes header-buf)
                             :start1 0
                             :end2 (code-buffer-position header-buf)))))))))

      ;; Write to file
      (with-open-file (out output-path
                           :direction :output
                           :element-type '(unsigned-byte 8)
                           :if-exists :supersede)
        (write-sequence (subseq (code-buffer-bytes buf) 0 (code-buffer-position buf))
                        out))

      (format t "Multiboot1 kernel written to ~A (~D bytes)~%"
              output-path (code-buffer-position buf))
      buf)))

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-multiboot1 ()
  "Build and test multiboot1 image"
  (build-multiboot1-image "/tmp/modus64.elf")
  (format t "~%To test: qemu-system-x86_64 -kernel /tmp/modus64.elf -nographic~%"))
