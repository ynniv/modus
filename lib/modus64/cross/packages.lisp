;;;; packages.lisp - Package definitions for Modus64 cross-compiler
;;;;
;;;; Load order: packages.lisp -> x64-asm.lisp -> cross-compile.lisp

(defpackage :modus64.asm
  (:use :cl)
  (:export
   ;; Code buffer
   #:make-code-buffer
   #:emit-byte
   #:emit-bytes
   #:emit-u16
   #:emit-u32
   #:emit-u64
   #:emit-s32
   #:code-buffer-bytes
   #:code-buffer-position
   ;; Labels
   #:make-label
   #:label-p
   #:label-position
   #:emit-label
   #:fixup-labels
   ;; Registers
   #:rax #:rcx #:rdx #:rbx #:rsp #:rbp #:rsi #:rdi
   #:r8 #:r9 #:r10 #:r11 #:r12 #:r13 #:r14 #:r15
   #:eax #:ecx #:edx #:ebx #:esp #:ebp #:esi #:edi
   #:al #:cl #:dl #:bl #:spl #:bpl #:sil #:dil
   #:reg-code #:reg-size #:reg-needs-rex-p #:reg-extended-p
   ;; Instructions
   #:emit-ret
   #:emit-nop
   #:emit-push
   #:emit-pop
   #:emit-mov-reg-reg
   #:emit-mov-reg-imm
   #:emit-mov-reg-mem
   #:emit-mov-mem-reg
   #:emit-add-reg-reg
   #:emit-add-reg-imm
   #:emit-sub-reg-reg
   #:emit-sub-reg-imm
   #:emit-cmp-reg-reg
   #:emit-cmp-reg-imm
   #:emit-and-reg-reg
   #:emit-and-reg-imm
   #:emit-or-reg-reg
   #:emit-or-reg-imm
   #:emit-xor-reg-reg
   #:emit-xor-reg-imm
   #:emit-shl-reg-imm
   #:emit-shr-reg-imm
   #:emit-sar-reg-imm
   #:emit-test-reg-reg
   #:emit-test-reg-imm
   #:emit-jmp
   #:emit-jmp-reg
   #:emit-call
   #:emit-call-reg
   #:emit-jcc
   #:emit-lea
   #:emit-int
   ;; Testing
   #:test-assembler))

(defpackage :modus64.cross
  (:use :cl :modus64.asm)
  (:export
   ;; Compilation
   #:compile-toplevel
   #:compile-function
   #:compile-form
   ;; Environment
   #:make-compile-env
   #:make-empty-env
   #:env-lookup
   #:env-extend
   ;; Constants
   #:+tag-fixnum+
   #:+tag-cons+
   #:+tag-object+
   #:+tag-immediate+
   #:+fixnum-shift+
   ;; Output
   #:*code-buffer*
   #:*functions*
   #:*constants*
   ;; Testing
   #:test-cross-compiler
   ;; Boot code
   #:emit-multiboot2-header
   #:emit-boot32-with-gdt
   #:test-multiboot2-header
   #:test-boot32
   ;; Boot constants
   #:+kernel-load-addr+
   #:+page-tables-addr+
   #:+stack-top+
   #:+kernel64-addr+
   ;; 64-bit kernel
   #:emit-kernel64-entry
   #:build-kernel-image
   #:test-kernel64
   #:test-build-image
   ;; Multiboot1 (QEMU-loadable)
   #:build-multiboot1-image
   #:test-multiboot1))

(defpackage :modus64.image
  (:use :cl :modus64.asm :modus64.cross)
  (:export
   #:build-image
   #:write-image))
