;;;; kernel64.lisp - 64-bit Kernel Entry Point
;;;;
;;;; This is the first 64-bit code that runs after boot32.lisp
;;;; switches to long mode. It:
;;;; 1. Sets up 64-bit segments
;;;; 2. Initializes serial output for debugging
;;;; 3. Sets up runtime registers (NIL, alloc, etc.)
;;;; 4. Jumps to the Lisp runtime

(in-package :modus64.cross)

;;; ============================================================
;;; Serial Port Constants (COM1 at 0x3F8)
;;; ============================================================

(defconstant +serial-port+ #x3F8)
(defconstant +serial-data+ #x3F8)
(defconstant +serial-ier+  #x3F9)  ; Interrupt Enable Register
(defconstant +serial-fcr+  #x3FA)  ; FIFO Control Register
(defconstant +serial-lcr+  #x3FB)  ; Line Control Register
(defconstant +serial-mcr+  #x3FC)  ; Modem Control Register
(defconstant +serial-lsr+  #x3FD)  ; Line Status Register

;;; ============================================================
;;; Initial 64-bit Stack
;;; ============================================================

(defconstant +kernel64-stack+ #x00200000)  ; 2MB, grows down

;;; ============================================================
;;; 64-bit Code Generation Helpers
;;; ============================================================

(defun emit64-mov-rax-imm64 (buf value)
  "MOV RAX, imm64"
  (emit-byte buf #x48)  ; REX.W
  (emit-byte buf #xB8)  ; MOV RAX, imm64
  (emit-u64 buf value))

(defun emit64-mov-reg-imm64 (buf reg value)
  "MOV reg, imm64 for any 64-bit register"
  (let ((reg-code (reg-code reg))
        (extended (reg-extended-p reg)))
    (emit-byte buf (logior #x48 (if extended #x01 0)))  ; REX.W + REX.B if needed
    (emit-byte buf (+ #xB8 (logand reg-code 7)))
    (emit-u64 buf value)))

(defun emit64-out-dx-al (buf)
  "OUT DX, AL"
  (emit-byte buf #xEE))

(defun emit64-in-al-dx (buf)
  "IN AL, DX"
  (emit-byte buf #xEC))

(defun emit64-mov-dx-imm16 (buf value)
  "MOV DX, imm16"
  (emit-byte buf #x66)  ; Operand size prefix
  (emit-byte buf #xBA)  ; MOV DX, imm16
  (emit-u16 buf value))

(defun emit64-mov-al-imm8 (buf value)
  "MOV AL, imm8"
  (emit-byte buf #xB0)  ; MOV AL, imm8
  (emit-byte buf value))

(defun emit64-test-al-imm8 (buf value)
  "TEST AL, imm8"
  (emit-bytes buf #xA8)  ; TEST AL, imm8
  (emit-byte buf value))

;;; ============================================================
;;; Serial Initialization
;;; ============================================================

(defun emit-serial-init (buf)
  "Emit code to initialize the serial port"
  ;; Disable interrupts
  ;; mov dx, COM1+1 (IER)
  ;; mov al, 0
  ;; out dx, al
  (emit64-mov-dx-imm16 buf (+ +serial-port+ 1))
  (emit64-mov-al-imm8 buf 0)
  (emit64-out-dx-al buf)

  ;; Enable DLAB (divisor latch access bit)
  ;; mov dx, COM1+3 (LCR)
  ;; mov al, 0x80
  ;; out dx, al
  (emit64-mov-dx-imm16 buf (+ +serial-port+ 3))
  (emit64-mov-al-imm8 buf #x80)
  (emit64-out-dx-al buf)

  ;; Set divisor to 1 (115200 baud)
  ;; mov dx, COM1+0 (DLL)
  ;; mov al, 1
  ;; out dx, al
  (emit64-mov-dx-imm16 buf +serial-port+)
  (emit64-mov-al-imm8 buf 1)
  (emit64-out-dx-al buf)

  ;; mov dx, COM1+1 (DLM)
  ;; mov al, 0
  ;; out dx, al
  (emit64-mov-dx-imm16 buf (+ +serial-port+ 1))
  (emit64-mov-al-imm8 buf 0)
  (emit64-out-dx-al buf)

  ;; 8 bits, no parity, 1 stop bit
  ;; mov dx, COM1+3 (LCR)
  ;; mov al, 0x03
  ;; out dx, al
  (emit64-mov-dx-imm16 buf (+ +serial-port+ 3))
  (emit64-mov-al-imm8 buf #x03)
  (emit64-out-dx-al buf)

  ;; Enable FIFO
  ;; mov dx, COM1+2 (FCR)
  ;; mov al, 0xC7
  ;; out dx, al
  (emit64-mov-dx-imm16 buf (+ +serial-port+ 2))
  (emit64-mov-al-imm8 buf #xC7)
  (emit64-out-dx-al buf)

  ;; Enable IRQs, RTS/DSR set
  ;; mov dx, COM1+4 (MCR)
  ;; mov al, 0x0B
  ;; out dx, al
  (emit64-mov-dx-imm16 buf (+ +serial-port+ 4))
  (emit64-mov-al-imm8 buf #x0B)
  (emit64-out-dx-al buf))

(defun emit-serial-putchar (buf)
  "Emit code to output character in AL to serial port.
   Trashes: DX, AH (via IN)"
  (let ((wait-label (make-label))
        (done-label (make-label)))
    ;; Save char
    ;; mov ah, al
    (emit-bytes buf #x88 #xC4)

    ;; Wait for transmit buffer empty
    (emit-label buf wait-label)
    ;; mov dx, COM1+5 (LSR)
    (emit64-mov-dx-imm16 buf (+ +serial-port+ 5))
    ;; in al, dx
    (emit64-in-al-dx buf)
    ;; test al, 0x20 (THR empty)
    (emit64-test-al-imm8 buf #x20)
    ;; jz wait
    (emit-jcc buf :z wait-label)

    ;; Send character
    ;; mov al, ah
    (emit-bytes buf #x88 #xE0)
    ;; mov dx, COM1
    (emit64-mov-dx-imm16 buf +serial-port+)
    ;; out dx, al
    (emit64-out-dx-al buf)))

(defun emit-serial-print-string (buf string)
  "Emit code to print a constant string to serial"
  (loop for char across string do
    (emit64-mov-al-imm8 buf (char-code char))
    (emit-serial-putchar buf)))

;;; ============================================================
;;; 64-bit Kernel Entry
;;; ============================================================

(defun emit-kernel64-entry (buf lisp-entry-addr)
  "Emit the 64-bit kernel entry code.
   LISP-ENTRY-ADDR is where the compiled Lisp code starts."
  (let ((entry-point (code-buffer-position buf)))

    ;; We're now in 64-bit mode!
    ;; Reload data segments with 64-bit data segment (0x20)
    ;; mov ax, 0x20
    ;; mov ds, ax
    ;; mov es, ax
    ;; mov fs, ax
    ;; mov gs, ax
    ;; mov ss, ax
    (emit-bytes buf #x66 #xB8 #x20 #x00)  ; mov ax, 0x20
    (emit-bytes buf #x8E #xD8)            ; mov ds, ax
    (emit-bytes buf #x8E #xC0)            ; mov es, ax
    (emit-bytes buf #x8E #xE0)            ; mov fs, ax
    (emit-bytes buf #x8E #xE8)            ; mov gs, ax
    (emit-bytes buf #x8E #xD0)            ; mov ss, ax

    ;; Set up 64-bit stack
    (emit64-mov-reg-imm64 buf 'rsp +kernel64-stack+)

    ;; Initialize serial port
    (emit-serial-init buf)

    ;; Print boot message
    (emit-serial-print-string buf "Modus64: 64-bit mode active!")
    (emit64-mov-al-imm8 buf 13)  ; CR
    (emit-serial-putchar buf)
    (emit64-mov-al-imm8 buf 10)  ; LF
    (emit-serial-putchar buf)

    ;; Set up Lisp runtime registers
    ;; R15 = NIL (will be set properly later, for now use placeholder)
    (emit64-mov-reg-imm64 buf 'r15 +nil-placeholder+)

    ;; R12 = allocation pointer (start of general heap)
    (emit64-mov-reg-imm64 buf 'r12 #x05000000)  ; 80MB, per allocator design

    ;; R14 = allocation limit
    (emit64-mov-reg-imm64 buf 'r14 #x06000000)  ; 96MB

    ;; Jump to Lisp entry point
    (emit64-mov-reg-imm64 buf 'rax lisp-entry-addr)
    (emit-bytes buf #xFF #xE0)  ; jmp rax

    ;; Should never reach here
    (let ((halt-loop (make-label)))
      (emit-label buf halt-loop)
      (emit-byte buf #xF4)  ; hlt
      (emit-jmp buf halt-loop))

    entry-point))

;;; ============================================================
;;; Complete Image Builder
;;; ============================================================

(defun build-kernel-image (output-path &key (lisp-forms nil))
  "Build a complete bootable kernel image.
   OUTPUT-PATH: Where to write the image.
   LISP-FORMS: List of Lisp forms to compile into the kernel."
  (let ((buf (make-code-buffer))
        (*functions* (make-hash-table :test 'eq))
        (*constants* nil)
        (*code-buffer* nil))

    ;; Reserve space for Multiboot header at the start
    ;; (will be filled in last when we know the entry point)
    (let ((header-size 64))  ; Reserve 64 bytes for header
      (dotimes (i header-size)
        (emit-byte buf 0)))

    ;; Emit 32-bit boot stub (immediately after header)
    ;; This needs to be at a known offset for the multiboot entry
    (let ((boot32-offset (code-buffer-position buf)))
      ;; The boot32 code will jump to our 64-bit entry
      ;; We need to calculate where that will be
      (let* ((estimated-boot32-size 300)  ; Estimate, will be fixed up
             (kernel64-addr (+ +kernel-load-addr+ boot32-offset estimated-boot32-size)))

        ;; Emit boot32 stub
        (let ((boot32-entry (emit-boot32-with-gdt buf kernel64-addr)))

          ;; Pad to align 64-bit code
          (loop while (not (zerop (mod (code-buffer-position buf) 16)))
                do (emit-byte buf #x90))  ; NOP

          ;; Record actual 64-bit kernel location
          (let ((actual-kernel64-offset (code-buffer-position buf)))

            ;; Emit 64-bit kernel entry
            ;; Calculate where Lisp code will be
            (let* ((estimated-kernel64-size 512)
                   (lisp-addr (+ +kernel-load-addr+ actual-kernel64-offset estimated-kernel64-size)))

              (emit-kernel64-entry buf lisp-addr)

              ;; Pad before Lisp code
              (loop while (not (zerop (mod (code-buffer-position buf) 16)))
                    do (emit-byte buf #x90))

              ;; Compile Lisp forms
              (let ((*code-buffer* buf))
                (dolist (form lisp-forms)
                  (compile-toplevel form))
                (fixup-labels buf))

              ;; Now fix up the Multiboot header at the start
              ;; The entry point is the boot32 stub
              (let ((temp-buf (make-code-buffer))
                    (entry-addr (+ +kernel-load-addr+ boot32-offset boot32-entry)))
                (emit-multiboot2-header temp-buf entry-addr)
                ;; Copy header to start of main buffer
                (replace (code-buffer-bytes buf)
                         (code-buffer-bytes temp-buf)
                         :start1 0
                         :end2 (code-buffer-position temp-buf))))))))

    ;; Write to file
    (with-open-file (out output-path
                         :direction :output
                         :element-type '(unsigned-byte 8)
                         :if-exists :supersede)
      (write-sequence (subseq (code-buffer-bytes buf) 0 (code-buffer-position buf))
                      out))

    (format t "Kernel image written to ~A (~D bytes)~%"
            output-path (code-buffer-position buf))
    buf))

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-kernel64 ()
  "Test 64-bit kernel entry generation"
  (let ((buf (make-code-buffer)))
    (let ((entry (emit-kernel64-entry buf #x00200000)))
      (fixup-labels buf)
      (format t "Kernel64 entry: ~D bytes, entry at offset ~D~%"
              (code-buffer-position buf) entry)
      (format t "First 64 bytes: ~{~2,'0X ~}~%"
              (coerce (subseq (code-buffer-bytes buf) 0
                             (min 64 (code-buffer-position buf)))
                      'list))
      buf)))

(defun test-build-image ()
  "Test building a complete kernel image"
  (build-kernel-image "/tmp/modus64-test.img"
                      :lisp-forms '((defun hello ()
                                     (+ 1 2 3)))))
