;;;; build.lisp - Modus64 Kernel Image Builder
;;;;
;;;; This file ties together the cross-compiler, boot code, and runtime
;;;; to produce a bootable kernel image.
;;;;
;;;; Usage:
;;;;   (modus64.build:build-kernel "modus64.elf")
;;;;   qemu-system-x86_64 -kernel modus64.elf -nographic

(defpackage :modus64.build
  (:use :cl :modus64.asm :modus64.cross)
  (:export #:build-kernel
           #:build-kernel-mvm
           #:test-build))

(in-package :modus64.build)

;;; ============================================================
;;; Kernel Entry Point (Lisp code to run after boot)
;;; ============================================================

(defparameter *kernel-init-code*
  '(;; Initialize allocator pointers
    ;; R12 = general alloc ptr, R14 = limit
    ;; These are set by boot code, we just verify

    ;; Print boot message
    (print-boot-message)

    ;; Test cons allocation
    (test-cons)

    ;; Halt
    (halt-loop))
  "Lisp code for kernel initialization")

;;; ============================================================
;;; Hash Function (SBCL side) - used at build time
;;; ============================================================

(defun compute-hash-chars (name-string)
  "Compute dual-FNV-1a hash for a function name.
   Two independent FNV-1a-32 hashes combined into a 60-bit value.
   Collision probability ~4e-10 with ~200 functions."
  (let ((h1 2166136261) (h2 3735928559))
    (loop for c across name-string
          do (setq h1 (logand (* (logxor h1 (char-code c)) 16777619) #xFFFFFFFF))
             (setq h2 (logand (* (logxor h2 (char-code c)) 805306457) #xFFFFFFFF)))
    (let ((combined (logior (ash (logand h1 #x3FFFFFFF) 30)
                            (logand h2 #x3FFFFFFF))))
      (if (zerop combined) 1 combined))))

(defun expand-hash-of (tree)
  "Walk TREE replacing (hash-of \"name\") with computed hash values."
  (cond
    ((null tree) nil)
    ((atom tree) tree)
    ((and (eq (car tree) 'hash-of) (stringp (cadr tree)))
     (compute-hash-chars (cadr tree)))
    (t (cons (expand-hash-of (car tree))
             (expand-hash-of (cdr tree))))))

(defparameter *runtime-functions*
  (expand-hash-of
   '(;; Serial wait - no-op for QEMU virtual UART
    ;; QEMU's 16550 FIFO + chardev backend handles buffering internally.
    ;; Polling THRE via 'in al,dx' causes KVM VM exits that starve QEMU's
    ;; event loop, deadlocking when stdout has O_NONBLOCK.
    (defun serial-wait ()
      nil)

    ;; Write byte to serial port with wait
    ;; Supports SSH output redirect: 0x300014 flags (bit0=capture, bit1=suppress serial)
    ;; Output buffer at 0x300100, position at 0x300018
    (defun write-byte (b)
      (let ((flags (mem-ref #x300014 :u32)))
        (when (zerop (logand flags 2))
          (serial-wait)
          (io-out-byte #x3F8 b))
        (when (not (zerop (logand flags 1)))
          (let ((pos (mem-ref #x300018 :u32)))
            (when (< pos 4096)
              (setf (mem-ref (+ #x300100 pos) :u8) b)
              (setf (mem-ref #x300018 :u32) (+ pos 1)))))))

    ;; Print a hex digit (0-15)
    (defun print-hex-digit (n)
      (if (< n 10)
          (write-byte (+ n 48))    ; '0' = 48
          (write-byte (+ n 55))))  ; 'A' - 10 = 55

    ;; Print a byte as 2 hex digits
    ;; Note: compute both values before any calls to preserve b
    (defun print-hex-byte (b)
      (let ((hi (logand (ash b -4) 15))
            (lo (logand b 15)))
        (print-hex-digit hi)
        (print-hex-digit lo)))

    ;; Print low 16 bits as hex (simpler, for debugging)
    (defun print-hex16 (n)
      (print-hex-byte (logand (ash n -8) 255))
      (print-hex-byte (logand n 255)))

    ;; Read a character from serial (blocking)
    (defun read-char ()
      ;; Wait for data available (LSR bit 0)
      (loop
        (if (not (zerop (logand (io-in-byte #x3FD) 1)))
            (return (code-char (io-in-byte #x3F8))))))

    ;; Check if input is available (non-blocking)
    (defun char-ready-p ()
      (not (zerop (logand (io-in-byte #x3FD) 1))))

    ;; Print a character
    (defun print-char (ch)
      (write-byte (char-code ch)))

    ;; Test memory store/load first
    (defun test-mem ()
      ;; Write to 0x300000 (NOT stack which is at 0x200000!)
      (setf (mem-ref #x300000 :u64) 66)  ; Store 66 (tagged 33)
      ;; Read it back - will be tagged again on read, so 132
      ;; write-byte untags: 132 >> 1 = 66 = 'B'
      (let ((v (mem-ref #x300000 :u64)))
        (write-byte 77)   ; 'M'
        (write-byte 61)   ; '='
        (write-byte v)    ; Should print 'B' (66)
        (write-byte 10)))

    ;; Test direct memory at a known-good address (near kernel)
    (defun test-mem-direct ()
      ;; Write 65 to 0x150000 (should be valid, after kernel)
      (setf (mem-ref #x150000 :u8) 65)
      ;; Read it back - should print 'A'
      (write-byte (mem-ref #x150000 :u8))
      (write-byte 10))

    ;; Print a 32-bit value as 8 hex digits
    (defun print-hex32 (n)
      (print-hex-byte (logand (ash n -24) 255))
      (print-hex-byte (logand (ash n -16) 255))
      (print-hex-byte (logand (ash n -8) 255))
      (print-hex-byte (logand n 255)))

    ;; Print full 64-bit value as 16 hex digits
    (defun print-hex64 (n)
      (print-hex-byte (logand (ash n -56) 255))
      (print-hex-byte (logand (ash n -48) 255))
      (print-hex-byte (logand (ash n -40) 255))
      (print-hex-byte (logand (ash n -32) 255))
      (print-hex-byte (logand (ash n -24) 255))
      (print-hex-byte (logand (ash n -16) 255))
      (print-hex-byte (logand (ash n -8) 255))
      (print-hex-byte (logand n 255)))

    ;; Print a number in decimal (iterative - avoids cross-compiled recursion issues)
    (defun print-dec (n)
      (if (< n 0)
          (progn
            (write-byte 45)          ; '-'
            (print-dec-pos (- 0 n)))
          (print-dec-pos n)))

    ;; Print exactly 9 digits with leading zeros (for chunk-based decimal printing)
    (defun print-dec-9pad (n)
      (write-byte (+ (truncate n 100000000) 48))
      (write-byte (+ (truncate (mod n 100000000) 10000000) 48))
      (write-byte (+ (truncate (mod n 10000000) 1000000) 48))
      (write-byte (+ (truncate (mod n 1000000) 100000) 48))
      (write-byte (+ (truncate (mod n 100000) 10000) 48))
      (write-byte (+ (truncate (mod n 10000) 1000) 48))
      (write-byte (+ (truncate (mod n 1000) 100) 48))
      (write-byte (+ (truncate (mod n 100) 10) 48))
      (write-byte (+ (mod n 10) 48)))

    ;; Print 1-10 digit number (non-recursive helper for high part)
    (defun print-dec-hi (n)
      (if (< n 10)
          (write-byte (+ n 48))
          (if (< n 100)
              (progn
                (write-byte (+ (truncate n 10) 48))
                (write-byte (+ (mod n 10) 48)))
              (if (< n 1000)
                  (progn
                    (write-byte (+ (truncate n 100) 48))
                    (write-byte (+ (truncate (mod n 100) 10) 48))
                    (write-byte (+ (mod n 10) 48)))
                  (if (< n 10000)
                      (progn
                        (write-byte (+ (truncate n 1000) 48))
                        (write-byte (+ (truncate (mod n 1000) 100) 48))
                        (write-byte (+ (truncate (mod n 100) 10) 48))
                        (write-byte (+ (mod n 10) 48)))
                      (if (< n 100000)
                          (progn
                            (write-byte (+ (truncate n 10000) 48))
                            (write-byte (+ (truncate (mod n 10000) 1000) 48))
                            (write-byte (+ (truncate (mod n 1000) 100) 48))
                            (write-byte (+ (truncate (mod n 100) 10) 48))
                            (write-byte (+ (mod n 10) 48)))
                          (if (< n 1000000)
                              (progn
                                (write-byte (+ (truncate n 100000) 48))
                                (write-byte (+ (truncate (mod n 100000) 10000) 48))
                                (write-byte (+ (truncate (mod n 10000) 1000) 48))
                                (write-byte (+ (truncate (mod n 1000) 100) 48))
                                (write-byte (+ (truncate (mod n 100) 10) 48))
                                (write-byte (+ (mod n 10) 48)))
                              (if (< n 10000000)
                                  (progn
                                    (write-byte (+ (truncate n 1000000) 48))
                                    (write-byte (+ (truncate (mod n 1000000) 100000) 48))
                                    (write-byte (+ (truncate (mod n 100000) 10000) 48))
                                    (write-byte (+ (truncate (mod n 10000) 1000) 48))
                                    (write-byte (+ (truncate (mod n 1000) 100) 48))
                                    (write-byte (+ (truncate (mod n 100) 10) 48))
                                    (write-byte (+ (mod n 10) 48)))
                                  (if (< n 100000000)
                                      (progn
                                        (write-byte (+ (truncate n 10000000) 48))
                                        (write-byte (+ (truncate (mod n 10000000) 1000000) 48))
                                        (write-byte (+ (truncate (mod n 1000000) 100000) 48))
                                        (write-byte (+ (truncate (mod n 100000) 10000) 48))
                                        (write-byte (+ (truncate (mod n 10000) 1000) 48))
                                        (write-byte (+ (truncate (mod n 1000) 100) 48))
                                        (write-byte (+ (truncate (mod n 100) 10) 48))
                                        (write-byte (+ (mod n 10) 48)))
                                      (if (< n 1000000000)
                                          (progn
                                            (write-byte (+ (truncate n 100000000) 48))
                                            (write-byte (+ (truncate (mod n 100000000) 10000000) 48))
                                            (write-byte (+ (truncate (mod n 10000000) 1000000) 48))
                                            (write-byte (+ (truncate (mod n 1000000) 100000) 48))
                                            (write-byte (+ (truncate (mod n 100000) 10000) 48))
                                            (write-byte (+ (truncate (mod n 10000) 1000) 48))
                                            (write-byte (+ (truncate (mod n 1000) 100) 48))
                                            (write-byte (+ (truncate (mod n 100) 10) 48))
                                            (write-byte (+ (mod n 10) 48)))
                                          (progn
                                            (write-byte (+ (truncate n 1000000000) 48))
                                            (write-byte (+ (truncate (mod n 1000000000) 100000000) 48))
                                            (write-byte (+ (truncate (mod n 100000000) 10000000) 48))
                                            (write-byte (+ (truncate (mod n 10000000) 1000000) 48))
                                            (write-byte (+ (truncate (mod n 1000000) 100000) 48))
                                            (write-byte (+ (truncate (mod n 100000) 10000) 48))
                                            (write-byte (+ (truncate (mod n 10000) 1000) 48))
                                            (write-byte (+ (truncate (mod n 1000) 100) 48))
                                            (write-byte (+ (truncate (mod n 100) 10) 48))
                                            (write-byte (+ (mod n 10) 48)))))))))))))

    ;; Print positive number in decimal (iterative - avoids cross-compiled recursion issues)
    ;; Handles any 63-bit fixnum using chunk-based approach at 10^9 boundary
    (defun print-dec-pos (n)
      (if (< n 1000000000)
          ;; 1-9 digits: use direct iterative extraction
          (print-dec-hi n)
          ;; >= 10^9: split into high part (1-10 digits) + low 9 padded digits
          (progn
            (print-dec-hi (truncate n 1000000000))
            (print-dec-9pad (mod n 1000000000)))))

    ;; Allocate a string of given length (char count)
    ;; Returns tagged object pointer (tag 11, subtag 0x31)
    (defun make-string (len)
      ;; Uses try-alloc-obj with subtag 0x31 (string)
      ;; On OOM, calls GC helper and retries
      (let ((result (try-alloc-obj len #x31)))
        (if (not (zerop result))
            result
            ;; OOM: try GC and retry
            (let ((gc-fn (mem-ref #x395000 :u64)))
              (if (not (zerop gc-fn))
                  (progn
                    (funcall gc-fn)
                    (let ((result2 (try-alloc-obj len #x31)))
                      (if (not (zerop result2))
                          result2
                          (progn (write-byte 79) (write-byte 79) (write-byte 83) 0))))
                  (progn (write-byte 79) (write-byte 79) (write-byte 83) 0))))))

    ;; Read char at index (returns fixnum char code)
    (defun string-ref (str idx)
      ;; Strip tag and convert to tagged fixnum for mem-ref
      ;; logand gives raw phys addr; ash 1 doubles it so mem-ref's sar undoes it
      (let ((raw (ash (logand str (- 0 4)) 1)))
        ;; Data starts at raw+8, char at raw+8+idx
        (mem-ref (+ raw 8 idx) :u8)))

    ;; Write char at index
    (defun string-set (str idx ch)
      (let ((raw (ash (logand str (- 0 4)) 1)))
        (setf (mem-ref (+ raw 8 idx) :u8) ch)))

    ;; Get string length (char count from header)
    ;; Header format: (raw_len << 16) | subtag. After SAR(header, 15):
    ;; (raw_len << 16) >> 15 = raw_len << 1 = tagged fixnum
    (defun string-length (str)
      (let ((raw (ash (logand str (- 0 4)) 1)))
        (ash (mem-ref raw :u64) -15)))

    ;; Check if object is a string (tag=11, subtag=0x31)
    (defun stringp (obj)
      (if (eq (logand obj 3) 3)
          ;; Has object tag, check subtag
          (eq (logand (mem-ref (logand obj (- 0 4)) :u8) 255) #x31)
          ()))

    ;; Print string contents to serial
    (defun print-string (str)
      (let ((len (string-length str))
            (i 0))
        (loop
          (if (< i len)
              (progn
                (write-byte (string-ref str i))
                (setq i (+ i 1)))
              (return ())))))

    ;; ================================================================
    ;; Byte Arrays (Phase 5.5)
    ;; ================================================================
    ;; Subtag 0x32, same layout as strings but different subtag
    ;; Header: [0x32][0][length:48], data at offset 8

    ;; Try to allocate an object of given size with given subtag byte.
    ;; Returns tagged object pointer on success, 0 on OOM.
    ;; subtag: #x31 for string, #x32 for byte array
    (defun try-alloc-obj (len subtag)
      ;; Read object alloc ptr (raw, untagged address)
      (let ((ptr (percpu-ref 40)))
        ;; Pre-double ptr so mem-ref's SAR gives correct physical address
        (let ((ptr2 (ash ptr 1)))
          (let ((data-size (+ len 1)))
            (let ((padded (logand (+ data-size 15) (- 0 16))))
              (let ((total (+ 8 padded)))
                ;; OOM check: compare in doubled (ptr2) scale
                (let ((lim2 (ash (percpu-ref 48) 1)))
                  (if (< (+ ptr2 total) lim2)
                      (progn
                        ;; Header: (raw_len << 16) | subtag
                        ;; Use (untag subtag) not (ash subtag -1): ash's AND -2 clears bit 0,
                        ;; corrupting odd subtags like 0x31 (string) to 0x30 (bignum)
                        (let ((header (logior (ash len 15) (untag subtag))))
                          (setf (mem-ref ptr2 :u64) header))
                        (let ((i 0))
                          (loop
                            (if (< i padded)
                                (progn
                                  (setf (mem-ref (+ ptr2 8 i) :u64) 0)
                                  (setq i (+ i 8)))
                                (return ()))))
                        (percpu-set 40 (ash (+ ptr2 total) -1))
                        (setf (mem-ref #x4FF038 :u64) ptr)
                        (let ((b0 (mem-ref #x4FF038 :u8)))
                          (setf (mem-ref #x4FF038 :u8) (logior b0 3)))
                        (mem-ref #x4FF038 :u64))
                      0))))))))

    ;; Allocate a byte array of given length.
    ;; On OOM, calls the GC helper (if available) and retries once.
    ;; GC helper address stored at 0x395000 by init-gc-helper.
    (defun make-array (len)
      (let ((result (try-alloc-obj len #x32)))
        (if (not (zerop result))
            result
            ;; OOM: try GC and retry
            (let ((gc-fn (mem-ref #x395000 :u64)))
              (if (not (zerop gc-fn))
                  (progn
                    (write-byte 91)  ; '[' before funcall
                    (funcall gc-fn)
                    (write-byte 93)  ; ']' after funcall
                    (let ((result2 (try-alloc-obj len #x32)))
                      (write-byte 61)  ; '=' after retry
                      (if (not (zerop result2))
                          (progn (write-byte 82) result2)  ; 'R' then return
                          (progn (write-byte 79) (write-byte 79) (write-byte 65) 0))))
                  (progn (write-byte 79) (write-byte 79) (write-byte 65) 0))))))

    ;; Print one hex nibble (val must be 0-15)
    (defun print-hex-nib (val)
      (if (< val 10) (write-byte (+ val 48)) (write-byte (+ val 55))))

    ;; Read byte at index
    (defun aref (arr idx)
      (let ((raw (ash (logand arr (- 0 4)) 1)))
        (if (< raw #x20000000)
            (mem-ref (+ raw 8 idx) :u8)
            (progn
              ;; First bad arr: print full value as hex
              (when (zerop (mem-ref #x03F000A0 :u32))
                (setf (mem-ref #x03F000A0 :u32) 1)
                (setf (mem-ref #x03F000B0 :u64) arr)
                ;; Print 'Z=' then 8 hex digits from stored bytes
                (write-byte 90) (write-byte 61)  ; 'Z='
                ;; Byte 3 (bits 31-24)
                (let ((b3 (mem-ref #x03F000B3 :u8)))
                  (print-hex-nib (logand (ash b3 -4) 15))
                  (print-hex-nib (logand b3 15)))
                ;; Byte 2 (bits 23-16)
                (let ((b2 (mem-ref #x03F000B2 :u8)))
                  (print-hex-nib (logand (ash b2 -4) 15))
                  (print-hex-nib (logand b2 15)))
                ;; Byte 1 (bits 15-8)
                (let ((b1 (mem-ref #x03F000B1 :u8)))
                  (print-hex-nib (logand (ash b1 -4) 15))
                  (print-hex-nib (logand b1 15)))
                ;; Byte 0 (bits 7-0)
                (let ((b0 (mem-ref #x03F000B0 :u8)))
                  (print-hex-nib (logand (ash b0 -4) 15))
                  (print-hex-nib (logand b0 15)))
                ;; Also print bytes 7-4 (upper 32 bits)
                (write-byte 58)  ; ':'
                (let ((b7 (mem-ref #x03F000B7 :u8)))
                  (print-hex-nib (logand (ash b7 -4) 15))
                  (print-hex-nib (logand b7 15)))
                (let ((b6 (mem-ref #x03F000B6 :u8)))
                  (print-hex-nib (logand (ash b6 -4) 15))
                  (print-hex-nib (logand b6 15)))
                (let ((b5 (mem-ref #x03F000B5 :u8)))
                  (print-hex-nib (logand (ash b5 -4) 15))
                  (print-hex-nib (logand b5 15)))
                (let ((b4 (mem-ref #x03F000B4 :u8)))
                  (print-hex-nib (logand (ash b4 -4) 15))
                  (print-hex-nib (logand b4 15)))
                (write-byte 32))  ; space
              (write-byte 90)  ; 'Z'
              0))))

    ;; Write byte at index
    (defun aset (arr idx val)
      (let ((raw (ash (logand arr (- 0 4)) 1)))
        (setf (mem-ref (+ raw 8 idx) :u8) val)))

    ;; Get array length from header
    ;; Header format: (raw_len << 16) | subtag. After SAR(header, 15):
    ;; (raw_len << 16) >> 15 = raw_len << 1 = tagged fixnum
    (defun array-length (arr)
      (let ((raw (ash (logand arr (- 0 4)) 1)))
        (ash (mem-ref raw :u64) -15)))

    ;; Check if object is a byte array (tag=11, subtag=0x32)
    (defun arrayp (obj)
      (if (eq (logand obj 3) 3)
          (eq (logand (mem-ref (logand obj (- 0 4)) :u8) 255) #x32)
          ()))

    ;; Test multiplication
    (defun test-mul ()
      (write-byte 77)  ; 'M' for mul test
      ;; 5 * 5 = 25 = 0x19
      (let ((r1 (* 5 5)))
        (write-byte (+ 48 (logand (ash r1 -4) 15)))  ; high nibble
        (write-byte (+ 48 (logand r1 15))))         ; low nibble (9)
      ;; 7 * 11 = 77 = 0x4D = 'M'
      (write-byte (* 7 11))
      ;; 10 * 3 = 30 - print as '0' + 30 = '>'
      (let ((r2 (* 10 3)))
        (write-byte (+ 48 r2)))  ; 48 + 30 = 78 = 'N'... wait that's wrong
      (write-byte 10))

    ;; Test cons allocation - comprehensive verification
    (defun test-cons ()
      ;; Test 1: Basic cons and car/cdr
      (write-byte 49)  ; '1'
      (let ((c (cons 65 66)))  ; cons('A', 'B')
        (write-byte (car c))    ; Should print 'A'
        (write-byte (cdr c)))   ; Should print 'B'
      (write-byte 10)

      ;; Test 2: Nested cons (list)
      (write-byte 50)  ; '2'
      (let ((lst (cons 72 (cons 73 (cons 33 0)))))  ; "HI!"
        (write-byte (car lst))                       ; 'H'
        (write-byte (car (cdr lst)))                 ; 'I'
        (write-byte (car (cdr (cdr lst)))))          ; '!'
      (write-byte 10)

      ;; Test 3: Multiple cons cells
      (write-byte 51)  ; '3'
      (let ((c1 (cons 88 89))    ; 'X', 'Y'
            (c2 (cons 90 87)))   ; 'Z', 'W'
        (write-byte (car c1))   ; 'X'
        (write-byte (cdr c1))   ; 'Y'
        (write-byte (car c2))   ; 'Z'
        (write-byte (cdr c2)))  ; 'W'
      (write-byte 10)

      ;; All tests passed
      (write-byte 79)   ; 'O'
      (write-byte 75)   ; 'K'
      (write-byte 10))

    ;; Test type predicates
    (defun test-types ()
      (write-byte 84)  ; 'T' for types test
      (let ((c (cons 1 2))
            (n 42))
        ;; Test consp: cons should be true, fixnum should be false
        (if (consp c)
            (write-byte 67)   ; 'C' - consp works on cons
            (write-byte 33))  ; '!' - error
        (if (consp n)
            (write-byte 33)   ; '!' - error
            (write-byte 99))  ; 'c' - consp correctly false for fixnum

        ;; Test fixnump: fixnum should be true, cons should be false
        (if (fixnump n)
            (write-byte 70)   ; 'F' - fixnump works on fixnum
            (write-byte 33))
        (if (fixnump c)
            (write-byte 33)
            (write-byte 102)) ; 'f' - fixnump correctly false for cons

        ;; Test atom: fixnum should be true, cons should be false
        (if (atom n)
            (write-byte 65)   ; 'A' - atom works on fixnum
            (write-byte 33))
        (if (atom c)
            (write-byte 33)
            (write-byte 97))  ; 'a' - atom correctly false for cons

        ;; Test listp: cons should be true, fixnum should be false
        (if (listp c)
            (write-byte 76)   ; 'L' - listp works on cons
            (write-byte 33))
        (if (listp n)
            (write-byte 33)
            (write-byte 108))) ; 'l' - listp correctly false for fixnum
      (write-byte 10)
      (write-byte 79)   ; 'O'
      (write-byte 75)   ; 'K'
      (write-byte 10))

    ;; List length - implemented in Lisp
    (defun length (list)
      (let ((count 0))
        (loop
          (if (null list) (return count))
          (setq count (1+ count))
          (setq list (cdr list)))))

    ;; Nth element of a list
    (defun nth (n list)
      (loop
        (if (zerop n) (return (car list)))
        (setq n (1- n))
        (setq list (cdr list))))

    ;; Test list operations (length, nth, cadr etc)
    (defun test-list-ops ()
      (write-byte 76)  ; 'L' for list ops test
      (let ((lst (cons 65 (cons 66 (cons 67 (cons 68 0))))))  ; A B C D
        ;; Test length: should be 4
        (let ((len (length lst)))
          (write-byte (+ len 48)))  ; Print '4'

        ;; Test nth
        (write-byte (nth 0 lst))    ; 'A'
        (write-byte (nth 1 lst))    ; 'B'
        (write-byte (nth 2 lst))    ; 'C'

        ;; Test cadr (second element)
        (write-byte (cadr lst))     ; 'B'

        ;; Test cddr (cdr of cdr)
        (write-byte (car (cddr lst)))) ; 'C'
      (write-byte 10)
      (write-byte 79)   ; 'O'
      (write-byte 75)   ; 'K'
      (write-byte 10))

    ;; Test character operations
    (defun test-chars ()
      (write-byte 67)  ; 'C' for chars test
      ;; Test code-char: convert code to char and back
      (let ((ch (code-char 72)))  ; 'H'
        ;; char-code should return 72
        (write-byte (char-code ch)))  ; Prints 'H'

      ;; Test characterp
      (if (characterp (code-char 73))  ; #\I
          (write-byte 73)              ; 'I' - yes it's a char
          (write-byte 78))             ; 'N' - not a char

      ;; characterp on a fixnum should be false
      (if (characterp 74)
          (write-byte 89)              ; 'Y' - wrong!
          (write-byte 74))             ; 'J' - correct, not a char

      ;; characterp on nil should be false
      (if (characterp ())
          (write-byte 89)              ; 'Y' - wrong!
          (write-byte 75))             ; 'K' - correct, nil is not a char
      (write-byte 10)
      (write-byte 79)   ; 'O'
      (write-byte 75)   ; 'K'
      (write-byte 10))

    ;; print-string for string objects is defined at line ~298
    ;; (the old character-list version was removed — it shadowed the real one)

    ;; Check if character is a digit
    (defun digitp (ch)
      (let ((code (char-code ch)))
        (if (< code 48) ()            ; < '0'
            (if (> code 57) () t))))  ; > '9'

    ;; Convert digit character to value
    (defun digit-value (ch)
      (- (char-code ch) 48))

    ;; Read a number - accumulates digits, returns on non-digit
    ;; Returns cons of (number . terminating-char)
    (defun read-number (first-char)
      (let ((n (digit-value first-char)))
        (loop
          (let ((ch (read-char)))
            (if (digitp ch)
                (setq n (+ (* n 10) (digit-value ch)))
                (return (cons n ch)))))))

    ;; Print help message
    (defun print-help ()
      ;; "Modus64 REPL\n"
      (write-byte 77) (write-byte 111) (write-byte 100) (write-byte 117)
      (write-byte 115) (write-byte 54) (write-byte 52) (write-byte 32)
      (write-byte 82) (write-byte 69) (write-byte 80) (write-byte 76)
      (write-byte 10)
      ;; "h=help m=mem q=quit (expr)\n"
      (write-byte 104) (write-byte 61) (write-byte 104) (write-byte 101)
      (write-byte 108) (write-byte 112) (write-byte 32)
      (write-byte 109) (write-byte 61) (write-byte 109) (write-byte 101)
      (write-byte 109) (write-byte 32)
      (write-byte 113) (write-byte 61) (write-byte 113) (write-byte 117)
      (write-byte 105) (write-byte 116) (write-byte 32)
      (write-byte 40) (write-byte 101) (write-byte 120) (write-byte 112)
      (write-byte 114) (write-byte 41)
      (write-byte 10)
      ;; "Tab ^A ^E ^U ^K arrows\n"
      (write-byte 84) (write-byte 97) (write-byte 98) (write-byte 32)
      (write-byte 94) (write-byte 65) (write-byte 32)
      (write-byte 94) (write-byte 69) (write-byte 32)
      (write-byte 94) (write-byte 85) (write-byte 32)
      (write-byte 94) (write-byte 75) (write-byte 32)
      (write-byte 97) (write-byte 114) (write-byte 114)
      (write-byte 111) (write-byte 119) (write-byte 115)
      (write-byte 10))

    ;; Show memory info
    (defun show-mem ()
      (write-byte 65) (write-byte 108) (write-byte 108)  ; "All"
      (write-byte 111) (write-byte 99) (write-byte 58)   ; "oc:"
      (write-byte 32)                                     ; " "
      (print-hex32 (get-alloc-ptr))
      (write-byte 10))

    ;; Wait for serial input (blocking, yields to other actors)
    ;; Uses direct (yield) call. Forward reference is handled by
    ;; both the cross-compiler (CALL rel32 patching) and native
    ;; compiler in image mode (img-fwd-record/img-patch-forward-refs).
    (defun wait-for-input ()
      (let ((count 0))
        (loop
          ;; Check LSR bit 0 (data ready)
          (if (not (zerop (logand (io-in-byte #x3FD) 1)))
              (return nil)
              (progn
                (setq count (+ count 1))
                (when (> count 5000)
                  (setq count 0)
                  (yield)))))))

    ;; Lookahead buffer at fixed memory location
    ;; 0 = no lookahead, >0 = lookahead byte value
    ;; Using :u8 to properly handle fixnum tagging
    (defun get-lookahead ()
      (mem-ref #x300010 :u8))

    (defun set-lookahead (val)
      (setf (mem-ref #x300010 :u8) val))

    ;; Read byte with lookahead support
    ;; Supports input FIFO: pos at 0x300020, len at 0x300024, data at 0x300028
    (defun read-byte-la ()
      (let ((la (get-lookahead)))
        (if (not (eq la 0))
            (progn
              (set-lookahead 0)
              la)
            ;; Check input FIFO first
            (let ((fifo-len (mem-ref #x300024 :u32)))
              (if (not (zerop fifo-len))
                  (let ((fifo-pos (mem-ref #x300020 :u32)))
                    (if (< fifo-pos fifo-len)
                        (let ((b (mem-ref (+ #x300028 fifo-pos) :u8)))
                          (setf (mem-ref #x300020 :u32) (+ fifo-pos 1))
                          b)
                        ;; FIFO exhausted - return space to terminate
                        (progn
                          (setf (mem-ref #x300024 :u32) 0)
                          32)))  ; space terminates any symbol
                  (progn
                    (wait-for-input)
                    (io-in-byte #x3F8)))))))

    ;; Put a byte back (for next read-byte-la)
    (defun unread-byte (b)
      (set-lookahead b))

    ;; Check if raw byte is a digit ('0'-'9' = 48-57)
    (defun raw-digitp (raw)
      (if (< raw 48)
          ()
          (if (> raw 57)
              ()
              t)))

    ;; Convert raw digit byte to value (0-9)
    (defun raw-digit-value (raw)
      (- raw 48))

    ;; Check if raw byte is a hex digit (0-9, a-f, A-F)
    (defun raw-hex-digitp (raw)
      (if (raw-digitp raw)
          t
          (if (< raw 65)  ; before 'A'
              ()
              (if (< raw 71)  ; 'A'-'F' (65-70)
                  t
                  (if (< raw 97)  ; before 'a'
                      ()
                      (if (< raw 103)  ; 'a'-'f' (97-102)
                          t
                          ()))))))

    ;; Convert raw hex digit to value (0-15)
    (defun raw-hex-digit-value (raw)
      (if (raw-digitp raw)
          (- raw 48)
          (if (< raw 97)  ; uppercase
              (- raw 55)  ; 'A'=65 -> 10, so 65-55=10
              (- raw 87))))  ; 'a'=97 -> 10, so 97-87=10

    ;; Parse hex number and print result
    (defun parse-hex-number ()
      (let ((num 0)
            (done ()))
        (loop
          (if done
              (return num)
              (progn
                (wait-for-input)
                (let ((raw (io-in-byte #x3F8)))
                  (if (raw-hex-digitp raw)
                      (progn
                        (write-byte raw)
                        (setq num (+ (* num 16) (raw-hex-digit-value raw))))
                      (progn
                        (write-byte 10)
                        (write-byte 61)
                        (write-byte 32)
                        (print-dec num)
                        (write-byte 10)
                        (setq done t)))))))))

    ;; Parse number starting with first-digit and print result
    ;; Supports decimal (123) and hex with 0x prefix (0xFF)
    (defun parse-and-print-number (first-digit)
      (write-byte first-digit)  ; echo first digit
      (let ((num (raw-digit-value first-digit))
            (done ())
            (hex-mode ()))
        (loop
          (if done
              (return num)
              (progn
                (wait-for-input)
                (let ((raw (io-in-byte #x3F8)))
                  ;; Check for 0x prefix (only if num=0 and we see 'x')
                  (if (if (eq num 0)
                          (if (eq raw 120) t ())  ; 'x' = 120
                          ())
                      (progn
                        (write-byte raw)
                        (parse-hex-number)
                        (setq done t))
                      ;; Normal decimal digit?
                      (if (raw-digitp raw)
                          (progn
                            (write-byte raw)
                            (setq num (+ (* num 10) (raw-digit-value raw))))
                          ;; Not a digit - done
                          (progn
                            (write-byte 10)
                            (write-byte 61)
                            (write-byte 32)
                            (print-dec num)
                            (write-byte 10)
                            (setq done t))))))))))

    ;; Skip whitespace, return first non-whitespace char
    (defun skip-ws ()
      (let ((done ())
            (ch 0))
        (loop
          (if done
              (return ch)
              (progn
                (setq ch (read-byte-la))
                (if (eq ch 32)  ; space
                    (write-byte ch)
                    (if (eq ch 9)  ; tab
                        (write-byte ch)
                        (setq done t))))))))

    ;; Read a number, return its value
    ;; Assumes first digit already read and passed in
    ;; Does NOT consume the terminating character (uses unread-byte)
    (defun read-num (first-char)
      (write-byte first-char)
      (let ((num (raw-digit-value first-char))
            (hex-mode ())
            (ndigits 1)
            (done ()))
        (loop
          (if done
              (return num)
              (let ((raw (read-byte-la)))
                ;; Check for 0x prefix
                (if (if (eq num 0)
                        (if (eq raw 120) t ())
                        ())
                    (progn
                      (write-byte raw)
                      (setq hex-mode t)
                      (setq ndigits 0))
                    (if hex-mode
                        ;; Hex mode (max 15 hex digits for 60-bit fixnum)
                        (if (if (raw-hex-digitp raw) (< ndigits 15) ())
                            (progn
                              (write-byte raw)
                              (setq num (+ (* num 16) (raw-hex-digit-value raw)))
                              (setq ndigits (1+ ndigits)))
                            (progn
                              ;; Echo overflow digits but don't accumulate
                              (if (raw-hex-digitp raw)
                                  (write-byte raw)
                                  (unread-byte raw))
                              (setq done t)))
                        ;; Decimal mode (max 18 digits for ~62-bit fixnum)
                        (if (if (raw-digitp raw) (< ndigits 18) ())
                            (progn
                              (write-byte raw)
                              (setq num (+ (* num 10) (raw-digit-value raw)))
                              (setq ndigits (1+ ndigits)))
                            (progn
                              ;; Echo overflow digits but don't accumulate
                              (if (raw-digitp raw)
                                  (write-byte raw)
                                  (unread-byte raw))
                              (setq done t))))))))))

    ;; Print an object (fixnum, cons, bignum, or string)
    (defun print-obj (obj)
      (if (null obj)
          (progn
            (write-byte 78)   ; 'N'
            (write-byte 73)   ; 'I'
            (write-byte 76))  ; 'L'
          (if (consp obj)
              (progn
                (write-byte 40)  ; '('
                (print-list-elements obj)
                (write-byte 41)) ; ')'
              (if (stringp obj)
                  ;; String: print with quotes
                  (progn
                    (write-byte 34)   ; '"'
                    (print-string obj)
                    (write-byte 34))  ; '"'
                  (if (bignump obj)
                      ;; Bignum: print as decimal if fits in u32, else hex of limb
                      ;; ash 1 converts raw phys addr to tagged fixnum for mem-ref
                      (let ((addr (ash (logand obj (- 0 4)) 1)))
                        (if (eq (mem-ref (+ addr 12) :u32) 0)
                            ;; High 32 bits zero - value fits in u32, print as decimal
                            (print-dec (mem-ref (+ addr 8) :u32))
                            ;; Large value - print #B + 16 hex digits of limb 0
                            (progn
                              (write-byte 35)   ; '#'
                              (write-byte 66)   ; 'B'
                              (print-hex32 (mem-ref (+ addr 12) :u32))
                              (print-hex32 (mem-ref (+ addr 8) :u32)))))
                      (if (arrayp obj)
                          ;; Array: print #A(len)
                          (progn
                            (write-byte 35)    ; '#'
                            (write-byte 65)    ; 'A'
                            (write-byte 40)    ; '('
                            (print-dec (array-length obj))
                            (write-byte 41))   ; ')'
                          ;; Fixnum: print as decimal
                          (print-dec obj)))))))

    ;; Print elements of a proper list
    (defun print-list-elements (lst)
      (if (null lst)
          ()
          (progn
            (print-obj (car lst))
            (if (null (cdr lst))
                ()
                (progn
                  (write-byte 32)  ; space
                  (if (consp (cdr lst))
                      (print-list-elements (cdr lst))
                      ;; Dotted pair
                      (progn
                        (write-byte 46)  ; '.'
                        (write-byte 32)  ; space
                        (print-obj (cdr lst)))))))))

    ;; Reverse a list
    (defun reverse-list (lst)
      (let ((result ())
            (done ()))
        (loop
          (if done
              (return result)
              (if (null lst)
                  (setq done t)
                  (progn
                    (setq result (cons (car lst) result))
                    (setq lst (cdr lst))))))))

    ;; Read a list: assumes '(' already consumed
    ;; Builds list in reverse, then reverses at end
    (defun read-list ()
      (let ((result ())
            (done ())
            (ch 0)
            (elem 0))
        (loop
          (if done
              (return (reverse-list result))
              (progn
                (setq ch (skip-ws))
                (if (eq ch 41)  ; ')'
                    (progn
                      (write-byte ch)
                      (setq done t))
                    ;; Read an element and prepend
                    (progn
                      (setq elem (read-obj ch))
                      (setq result (cons elem result)))))))))

    ;; Check if byte is alphabetic (a-z, A-Z)
    (defun raw-alphap (raw)
      (if (< raw 65)
          ()
          (if (< raw 91)
              t
              (if (< raw 97)
                  ()
                  (if (< raw 123)
                      t
                      ())))))

    ;; Check if byte can be part of a symbol (after first char)
    ;; Includes alphas, operators, and digits
    (defun raw-symbolp (raw)
      (if (raw-alphap raw)
          t
          (if (raw-digitp raw) t  ; digits allowed after first char
              (if (eq raw 43) t   ; +
                  (if (eq raw 45) t  ; -
                      (if (eq raw 42) t  ; *
                          (if (eq raw 60) t  ; <
                              (if (eq raw 62) t  ; >
                                  (if (eq raw 61) t  ; =
                                      ())))))))))

    ;; Symbol IDs
    (defun sym-plus () 1)
    (defun sym-minus () 2)
    (defun sym-times () 3)
    (defun sym-car () 10)
    (defun sym-cdr () 11)
    (defun sym-cons () 12)
    (defun sym-list () 13)
    (defun sym-if () 20)
    (defun sym-eq () 21)
    (defun sym-null () 22)
    (defun sym-quote () 23)
    (defun sym-t () (hash-of "t"))
    (defun sym-let () 25)
    (defun sym-defun () 26)
    (defun sym-lt () 27)   ; <
    (defun sym-gt () 28)   ; >
    (defun sym-loop () 29)
    (defun sym-return () 30)
    (defun sym-setq () 31)
    (defun sym-progn () 32)
    (defun sym-zerop () 33)
    (defun sym-not () 34)
    (defun sym-logand () 35)
    (defun sym-cadr () 36)
    (defun sym-cddr () 37)
    (defun sym-caddr () 38)
    (defun sym-1plus () 39)   ; 1+
    (defun sym-1minus () 40)  ; 1-
    (defun sym-consp () 41)
    (defun sym-atom () 42)
    (defun sym-length () 43)
    (defun sym-nth () 44)
    ;; Control flow
    (defun sym-and () 45)
    (defun sym-or () 46)
    (defun sym-cond () 47)
    ;; More predicates
    (defun sym-listp () 48)
    (defun sym-numberp () 49)
    ;; More list ops
    (defun sym-append () 50)
    (defun sym-reverse () 51)
    (defun sym-member () 52)
    (defun sym-assoc () 53)
    ;; I/O operations
    (defun sym-io-in-byte () 60)
    (defun sym-io-out-byte () 61)
    ;; Memory operations
    (defun sym-mem-ref () 62)
    (defun sym-setf () 63)
    ;; More bit operations
    (defun sym-ash () 64)
    (defun sym-logior () 65)
    (defun sym-logxor () 66)
    ;; GC operations
    (defun sym-gc () 67)
    ;; Mutation with write barrier
    (defun sym-rplaca () 68)
    (defun sym-rplacd () 69)
    ;; Bignum operations
    (defun sym-bignump () 70)
    (defun sym-integerp () 71)
    (defun sym-make-bignum () 72)
    (defun sym-bignum-ref () 73)
    (defun sym-bignum-set () 74)
    (defun sym-bignum-add () 75)
    (defun sym-bignum-sub () 76)
    (defun sym-bignum-mul () 77)
    (defun sym-print-bignum () 78)
    (defun sym-truncate () 79)
    (defun sym-mod () 80)
    (defun sym-make-string () (hash-of "make-string"))
    (defun sym-string-ref () (hash-of "string-ref"))
    (defun sym-string-set () (hash-of "string-set"))
    (defun sym-string-length () (hash-of "string-length"))
    (defun sym-stringp () 85)
    (defun sym-print-string () (hash-of "print-string"))
    (defun sym-print-dec () 87)
    (defun sym-let-star () 88)
    (defun sym-when () 89)
    (defun sym-unless () 90)
    (defun sym-dotimes () 91)
    (defun sym-make-array () (hash-of "make-array"))
    (defun sym-aref () (hash-of "aref"))
    (defun sym-aset () (hash-of "aset"))
    (defun sym-array-length () (hash-of "array-length"))
    (defun sym-arrayp () 96)
    (defun sym-function () 97)
    (defun sym-funcall () 98)
    (defun sym-write-byte () 99)
    ;; 32-bit I/O port operations (IDs 130+ to avoid single-letter collision)
    (defun sym-io-in-dword () 130)
    (defun sym-io-out-dword () 131)
    ;; PCI and E1000 networking functions
    (defun sym-pci-config-read () 132)
    (defun sym-pci-config-write () 158)
    (defun sym-pci-find-e1000 () 133)
    (defun sym-e1000-write-reg () 134)
    (defun sym-e1000-read-reg () 135)
    (defun sym-e1000-read-eeprom () 136)
    (defun sym-e1000-init () 137)
    (defun sym-e1000-send () 138)
    (defun sym-e1000-receive () 139)
    (defun sym-e1000-probe () 140)
    ;; ARP/IP/UDP
    (defun sym-arp-request () 141)
    (defun sym-arp-resolve () 142)
    (defun sym-ip-checksum () 143)
    (defun sym-ip-send () 144)
    (defun sym-udp-send () 145)
    (defun sym-net-receive () 146)
    (defun sym-htons () 147)
    (defun sym-htonl () 148)
    ;; TCP
    (defun sym-tcp-connect () 149)
    (defun sym-tcp-send () 150)
    (defun sym-tcp-receive () 151)
    (defun sym-tcp-close () 152)
    (defun sym-tcp-checksum () 153)
    ;; High-level networking
    (defun sym-net-init () 154)
    (defun sym-net-state () 155)
    (defun sym-e1000-init-rx () 156)
    (defun sym-e1000-init-tx () 157)
    ;; Self-hosting: comparison operators and missing forms
    ;; Short operators use fixed IDs 160+; longer names use hash-chars (dual-FNV)
    (defun sym-equals () (hash-of "="))
    (defun sym-le () (hash-of "<="))
    (defun sym-ge () (hash-of ">="))
    (defun sym-caar () (hash-of "caar"))
    (defun sym-cdar () (hash-of "cdar"))
    (defun sym-set-car () (hash-of "set-car"))
    (defun sym-set-cdr () (hash-of "set-cdr"))
    (defun sym-ldb () (hash-of "ldb"))
    (defun sym-fixnump () (hash-of "fixnump"))
    (defun sym-characterp () (hash-of "characterp"))
    (defun sym-char-code () (hash-of "char-code"))
    (defun sym-code-char () (hash-of "code-char"))
    (defun sym-untag () (hash-of "untag"))
    (defun sym-get-alloc-ptr () (hash-of "get-alloc-ptr"))
    (defun sym-set-alloc-ptr () (hash-of "set-alloc-ptr"))
    (defun sym-get-alloc-limit () (hash-of "get-alloc-limit"))
    (defun sym-set-alloc-limit () (hash-of "set-alloc-limit"))
    (defun sym-save-context () (hash-of "save-context"))
    (defun sym-restore-context () (hash-of "restore-context"))
    (defun sym-call-native () (hash-of "call-native"))
    (defun sym-xchg-mem () (hash-of "xchg-mem"))
    (defun sym-pause () (hash-of "pause"))
    (defun sym-mfence () (hash-of "mfence"))
    (defun sym-hlt () (hash-of "hlt"))
    (defun sym-sti () (hash-of "sti"))
    (defun sym-cli () (hash-of "cli"))
    (defun sym-sti-hlt () (hash-of "sti-hlt"))
    (defun sym-wrmsr () (hash-of "wrmsr"))
    (defun sym-percpu-ref () (hash-of "percpu-ref"))
    (defun sym-percpu-set () (hash-of "percpu-set"))
    (defun sym-switch-idle-stack () (hash-of "switch-idle-stack"))
    (defun sym-set-rsp () (hash-of "set-rsp"))
    (defun sym-lidt () (hash-of "lidt"))
    (defun sym-block () (hash-of "block"))
    (defun sym-tagbody () (hash-of "tagbody"))
    (defun sym-go () (hash-of "go"))
    (defun sym-lambda () (hash-of "lambda"))
    ;; Common variable names (single letter) - all a-z
    ;; Use hash-of to avoid collision with small integer literals (ASCII codes etc.)
    (defun sym-a () (hash-of "a"))
    (defun sym-b () (hash-of "b"))
    (defun sym-c () (hash-of "c"))
    (defun sym-d () (hash-of "d"))
    (defun sym-e () (hash-of "e"))
    (defun sym-f () (hash-of "f"))
    (defun sym-g () (hash-of "g"))
    (defun sym-h () (hash-of "h"))
    (defun sym-i () (hash-of "i"))
    (defun sym-j () (hash-of "j"))
    (defun sym-k () (hash-of "k"))
    (defun sym-l () (hash-of "l"))
    (defun sym-m () (hash-of "m"))
    (defun sym-n () (hash-of "n"))
    (defun sym-o () (hash-of "o"))
    (defun sym-p () (hash-of "p"))
    (defun sym-q () (hash-of "q"))
    (defun sym-r () (hash-of "r"))
    (defun sym-s () (hash-of "s"))
    (defun sym-u () (hash-of "u"))
    (defun sym-v () (hash-of "v"))
    (defun sym-w () (hash-of "w"))
    (defun sym-x () (hash-of "x"))
    (defun sym-y () (hash-of "y"))
    (defun sym-z () (hash-of "z"))
    (defun sym-unknown () (hash-of "unknown"))

    ;; Match a single-char symbol: +, -, *, <, >, t, a-z
    (defun match-1char (c)
      (if (eq c 43) (sym-plus)  ; '+'
          (if (eq c 45) (sym-minus)  ; '-'
              (if (eq c 42) (sym-times)  ; '*'
                  (if (eq c 60) (sym-lt)  ; '<'
                      (if (eq c 62) (sym-gt)  ; '>'
                          (if (eq c 116) (sym-t)  ; 't'
                              (if (eq c 97) (sym-a)  ; 'a'
                                  (if (eq c 98) (sym-b)  ; 'b'
                                      (if (eq c 99) (sym-c)  ; 'c'
                                          (if (eq c 100) (sym-d)  ; 'd'
                                              (if (eq c 101) (sym-e)  ; 'e'
                                                  (if (eq c 102) (sym-f)  ; 'f'
                                                      (if (eq c 103) (sym-g)  ; 'g'
                                                          (if (eq c 104) (sym-h)  ; 'h'
                                                              (if (eq c 105) (sym-i)  ; 'i'
                                                                  (if (eq c 106) (sym-j)  ; 'j'
                                                                      (if (eq c 107) (sym-k)  ; 'k'
                                                                          (if (eq c 108) (sym-l)  ; 'l'
                                                                              (if (eq c 109) (sym-m)  ; 'm'
                                                                                  (if (eq c 110) (sym-n)  ; 'n'
                                                                                      (if (eq c 111) (sym-o)  ; 'o'
                                                                                          (if (eq c 112) (sym-p)  ; 'p'
                                                                                              (if (eq c 113) (sym-q)  ; 'q'
                                                                                                  (if (eq c 114) (sym-r)  ; 'r'
                                                                                                      (if (eq c 115) (sym-s)  ; 's'
                                                                                                          (if (eq c 117) (sym-u)  ; 'u'
                                                                                                              (if (eq c 118) (sym-v)  ; 'v'
                                                                                                                  (if (eq c 119) (sym-w)  ; 'w'
                                                                                                                      (if (eq c 120) (sym-x)  ; 'x'
                                                                                                                          (if (eq c 121) (sym-y)  ; 'y'
                                                                                                                              (if (eq c 122) (sym-z)  ; 'z'
                                                                                                                                  (sym-unknown)))))))))))))))))))))))))))))))))

    ;; Match a 2-char symbol: if, eq, or, gc
    (defun match-2char (c1 c2)
      (if (eq c1 105)  ; 'i'
          (if (eq c2 102) (sym-if) (sym-unknown))  ; 'f'
          (if (eq c1 101)  ; 'e'
              (if (eq c2 113) (sym-eq) (sym-unknown))  ; 'q'
              (if (eq c1 111)  ; 'o' for or
                  (if (eq c2 114) (sym-or) (sym-unknown))  ; 'r'
                  (if (eq c1 103)  ; 'g' for gc
                      (if (eq c2 99) (sym-gc) (sym-unknown))  ; 'c'
                      (sym-unknown))))))

    ;; Match a 3-char symbol: car, cdr, let, not, inc, dec, and
    (defun match-3char (c1 c2 c3)
      (if (eq c1 99)  ; 'c'
          (if (eq c2 97)  ; 'a'
              (if (eq c3 114) (sym-car) (sym-unknown))  ; 'r'
              (if (eq c2 100)  ; 'd'
                  (if (eq c3 114) (sym-cdr) (sym-unknown))  ; 'r'
                  (sym-unknown)))
          (if (eq c1 108)  ; 'l'
              (if (eq c2 101)  ; 'e'
                  (if (eq c3 116) (sym-let) (sym-unknown))  ; 't'
                  (sym-unknown))
              (if (eq c1 110)  ; 'n' for nil, not, nth
                  (if (eq c2 105)  ; 'i' for nil
                      (if (eq c3 108) () (sym-unknown))  ; 'l' -> nil = ()
                      (if (eq c2 111)  ; 'o' for not
                          (if (eq c3 116) (sym-not) (sym-unknown))  ; 't'
                          (if (eq c2 116)  ; 't' for nth
                              (if (eq c3 104) (sym-nth) (sym-unknown))  ; 'h'
                              (sym-unknown))))
                  (if (eq c1 105)  ; 'i' for inc
                      (if (eq c2 110)  ; 'n'
                          (if (eq c3 99) (sym-1plus) (sym-unknown))  ; 'c' -> same as 1+
                          (sym-unknown))
                      (if (eq c1 100)  ; 'd' for dec
                          (if (eq c2 101)  ; 'e'
                              (if (eq c3 99) (sym-1minus) (sym-unknown))  ; 'c' -> same as 1-
                              (sym-unknown))
                          (if (eq c1 97)  ; 'a' for and, ash
                              (if (eq c2 110)  ; 'n' for and
                                  (if (eq c3 100) (sym-and) (sym-unknown))  ; 'd'
                                  (if (eq c2 115)  ; 's' for ash
                                      (if (eq c3 104) (sym-ash) (sym-unknown))  ; 'h'
                                      (sym-unknown)))
                              (if (eq c1 109)  ; 'm' for mod
                                  (if (eq c2 111)  ; 'o'
                                      (if (eq c3 100) (sym-mod) (sym-unknown))  ; 'd'
                                      (sym-unknown))
                                  (sym-unknown)))))))))

    ;; Match a 4-char symbol: cons, cadr, cddr, list, loop, null, setq
    (defun match-4char (c1 c2 c3 c4)
      (if (eq c1 99)  ; 'c' for cons, cond, cadr, cddr
          (if (eq c2 111)  ; 'o' for cons, cond
              (if (eq c3 110)
                  (if (eq c4 115) (sym-cons)           ; cons (s=115)
                      (if (eq c4 100) (sym-cond)       ; cond (d=100)
                          (sym-unknown)))
                  (sym-unknown))
              (if (eq c2 97)  ; 'a' for cadr
                  (if (eq c3 100)
                      (if (eq c4 114) (sym-cadr) (sym-unknown))
                      (sym-unknown))
                  (if (eq c2 100)  ; 'd' for cddr
                      (if (eq c3 100)
                          (if (eq c4 114) (sym-cddr) (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))))
          (if (eq c1 108)  ; 'l' for list/loop/let*
              (if (eq c2 105)  ; 'i' for list
                  (if (eq c3 115)
                      (if (eq c4 116) (sym-list) (sym-unknown))
                      (sym-unknown))
                  (if (eq c2 111)  ; 'o' for loop
                      (if (eq c3 111)
                          (if (eq c4 112) (sym-loop) (sym-unknown))
                          (sym-unknown))
                      (if (eq c2 101)  ; 'e' for let*
                          (if (eq c3 116)  ; 't'
                              (if (eq c4 42) (sym-let-star) (sym-unknown))  ; '*'
                              (sym-unknown))
                          (sym-unknown))))
              (if (eq c1 110)  ; 'n' for null
                  (if (eq c2 117)  ; 'u'
                      (if (eq c3 108)  ; 'l'
                          (if (eq c4 108) (sym-null) (sym-unknown))  ; 'l'
                          (sym-unknown))
                      (sym-unknown))
                  (if (eq c1 97)  ; 'a' for atom, aref, aset
                      (if (eq c2 116)  ; 't' for atom
                          (if (eq c3 111)  ; 'o'
                              (if (eq c4 109) (sym-atom) (sym-unknown))  ; 'm'
                              (sym-unknown))
                          (if (eq c2 114)  ; 'r' for aref
                              (if (eq c3 101)  ; 'e'
                                  (if (eq c4 102) (sym-aref) (sym-unknown))  ; 'f'
                                  (sym-unknown))
                              (if (eq c2 115)  ; 's' for aset
                                  (if (eq c3 101)  ; 'e'
                                      (if (eq c4 116) (sym-aset) (sym-unknown))  ; 't'
                                      (sym-unknown))
                                  (sym-unknown))))
                      (if (eq c1 115)  ; 's' for setq, setf
                          (if (eq c2 101)  ; 'e'
                              (if (eq c3 116)  ; 't'
                                  (if (eq c4 113) (sym-setq)     ; 'q' -> setq
                                      (if (eq c4 102) (sym-setf) ; 'f' -> setf
                                          (sym-unknown)))
                                  (sym-unknown))
                              (sym-unknown))
                          (if (eq c1 119)  ; 'w' for when
                              (if (eq c2 104)  ; 'h'
                                  (if (eq c3 101)  ; 'e'
                                      (if (eq c4 110) (sym-when) (sym-unknown))  ; 'n'
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))))))))

    ;; Match a 5-char symbol: quote, defun, progn, zerop, caddr, consp
    (defun match-5char (c1 c2 c3 c4 c5)
      (if (eq c1 113)  ; 'q' for quote
          (if (eq c2 117)  ; 'u'
              (if (eq c3 111)  ; 'o'
                  (if (eq c4 116)  ; 't'
                      (if (eq c5 101) (sym-quote) (sym-unknown))  ; 'e'
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))
          (if (eq c1 100)  ; 'd' for defun
              (if (eq c2 101)  ; 'e'
                  (if (eq c3 102)  ; 'f'
                      (if (eq c4 117)  ; 'u'
                          (if (eq c5 110) (sym-defun) (sym-unknown))  ; 'n'
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (if (eq c1 112)  ; 'p' for progn
                  (if (eq c2 114)  ; 'r'
                      (if (eq c3 111)  ; 'o'
                          (if (eq c4 103)  ; 'g'
                              (if (eq c5 110) (sym-progn) (sym-unknown))  ; 'n'
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (if (eq c1 122)  ; 'z' for zerop
                      (if (eq c2 101)  ; 'e'
                          (if (eq c3 114)  ; 'r'
                              (if (eq c4 111)  ; 'o'
                                  (if (eq c5 112) (sym-zerop) (sym-unknown))  ; 'p'
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (if (eq c1 99)  ; 'c' for caddr, consp
                          (if (eq c2 97)  ; 'a' for caddr
                              (if (eq c3 100)  ; 'd'
                                  (if (eq c4 100)  ; 'd'
                                      (if (eq c5 114) (sym-caddr) (sym-unknown))  ; 'r'
                                      (sym-unknown))
                                  (sym-unknown))
                              (if (eq c2 111)  ; 'o' for consp
                                  (if (eq c3 110)  ; 'n'
                                      (if (eq c4 115)  ; 's'
                                          (if (eq c5 112) (sym-consp) (sym-unknown))  ; 'p'
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown)))
                          (sym-unknown)))))))

    ;; Match a 6-char symbol: return, logand
    (defun match-6char (c1 c2 c3 c4 c5 c6)
      (if (eq c1 114)  ; 'r' for return, rplaca, rplacd
          (if (eq c2 101)  ; 'e' for return
              (if (eq c3 116)  ; 't'
                  (if (eq c4 117)  ; 'u'
                      (if (eq c5 114)  ; 'r'
                          (if (eq c6 110) (sym-return) (sym-unknown))  ; 'n'
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (if (eq c2 112)  ; 'p' for rplaca, rplacd
                  (if (eq c3 108)  ; 'l'
                      (if (eq c4 97)  ; 'a'
                          (if (eq c5 99)  ; 'c'
                              (if (eq c6 97) (sym-rplaca)   ; 'a' -> rplaca
                                  (if (eq c6 100) (sym-rplacd)  ; 'd' -> rplacd
                                      (sym-unknown)))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown)))
          (if (eq c1 108)  ; 'l' for logand, logior, logxor, length
              (if (eq c2 111)  ; 'o' for logand, logior, logxor
                  (if (eq c3 103)  ; 'g'
                      (if (eq c4 97)  ; 'a' for logand
                          (if (eq c5 110)  ; 'n'
                              (if (eq c6 100) (sym-logand) (sym-unknown))  ; 'd'
                              (sym-unknown))
                          (if (eq c4 105)  ; 'i' for logior
                              (if (eq c5 111)  ; 'o'
                                  (if (eq c6 114) (sym-logior) (sym-unknown))  ; 'r'
                                  (sym-unknown))
                              (if (eq c4 120)  ; 'x' for logxor
                                  (if (eq c5 111)  ; 'o'
                                      (if (eq c6 114) (sym-logxor) (sym-unknown))  ; 'r'
                                      (sym-unknown))
                                  (sym-unknown))))
                      (sym-unknown))
                  (if (eq c2 101)  ; 'e' for length
                      (if (eq c3 110)  ; 'n'
                          (if (eq c4 103)  ; 'g'
                              (if (eq c5 116)  ; 't'
                                  (if (eq c6 104) (sym-length) (sym-unknown))  ; 'h'
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown)))
              (if (eq c1 117)  ; 'u' for unless
                  (if (eq c2 110)  ; 'n'
                      (if (eq c3 108)  ; 'l'
                          (if (eq c4 101)  ; 'e'
                              (if (eq c5 115)  ; 's'
                                  (if (eq c6 115) (sym-unless) (sym-unknown))  ; 's'
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (if (eq c1 97)  ; 'a' for arrayp
                      (if (eq c2 114)  ; 'r'
                          (if (eq c3 114)  ; 'r'
                              (if (eq c4 97)  ; 'a'
                                  (if (eq c5 121)  ; 'y'
                                      (if (eq c6 112) (sym-arrayp) (sym-unknown))  ; 'p'
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))))))

    ;; Match a 7-char symbol: mem-ref, bignump
    ;; m(109) e(101) m(109) -(45) r(114) e(101) f(102)
    ;; b(98) i(105) g(103) n(110) u(117) m(109) p(112)
    (defun match-7char (c1 c2 c3 c4 c5 c6 c7)
      (if (eq c1 109)  ; 'm'
          (if (eq c2 101)  ; 'e'
              (if (eq c3 109)  ; 'm'
                  (if (eq c4 45)  ; '-'
                      (if (eq c5 114)  ; 'r'
                          (if (eq c6 101)  ; 'e'
                              (if (eq c7 102) (sym-mem-ref) (sym-unknown))  ; 'f'
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))
          (if (eq c1 98)  ; 'b' for bignump
              (if (eq c2 105)  ; 'i'
                  (if (eq c3 103)  ; 'g'
                      (if (eq c4 110)  ; 'n'
                          (if (eq c5 117)  ; 'u'
                              (if (eq c6 109)  ; 'm'
                                  (if (eq c7 112) (sym-bignump) (sym-unknown))  ; 'p'
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (if (eq c1 115)  ; 's' for stringp
                  (if (eq c2 116)  ; 't'
                      (if (eq c3 114)  ; 'r'
                          (if (eq c4 105)  ; 'i'
                              (if (eq c5 110)  ; 'n'
                                  (if (eq c6 103)  ; 'g'
                                      (if (eq c7 112) (sym-stringp) (sym-unknown))  ; 'p'
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (if (eq c1 100)  ; 'd' for dotimes
                      (if (eq c2 111)  ; 'o'
                          (if (eq c3 116)  ; 't'
                              (if (eq c4 105)  ; 'i'
                                  (if (eq c5 109)  ; 'm'
                                      (if (eq c6 101)  ; 'e'
                                          (if (eq c7 115) (sym-dotimes) (sym-unknown))  ; 's'
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (if (eq c1 102)  ; 'f' for funcall
                          (if (eq c2 117)  ; 'u'
                              (if (eq c3 110)  ; 'n'
                                  (if (eq c4 99)  ; 'c'
                                      (if (eq c5 97)  ; 'a'
                                          (if (eq c6 108)  ; 'l'
                                              (if (eq c7 108) (sym-funcall) (sym-unknown))  ; 'l'
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown)))))))

    ;; Match 8-char symbols: integerp, truncate, stringp
    ;; integerp: i(105) n(110) t(116) e(101) g(103) e(101) r(114) p(112)
    ;; truncate: t(116) r(114) u(117) n(110) c(99) a(97) t(116) e(101)
    ;; stringp:  s(115) t(116) r(114) i(105) n(110) g(103) p(112) _  -- actually 7 chars, will be in match-7char
    (defun match-8char (c1 c2 c3 c4 c5 c6 c7 c8)
      (if (eq c1 105)  ; 'i' for integerp
          (if (eq c2 110)  ; 'n'
              (if (eq c3 116)  ; 't'
                  (if (eq c4 101)  ; 'e'
                      (if (eq c5 103)  ; 'g'
                          (if (eq c6 101)  ; 'e'
                              (if (eq c7 114)  ; 'r'
                                  (if (eq c8 112) (sym-integerp) (sym-unknown))  ; 'p'
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))
          (if (eq c1 116)  ; 't' for truncate
              (if (eq c2 114)  ; 'r'
                  (if (eq c3 117)  ; 'u'
                      (if (eq c4 110)  ; 'n'
                          (if (eq c5 99)  ; 'c'
                              (if (eq c6 97)  ; 'a'
                                  (if (eq c7 116)  ; 't'
                                      (if (eq c8 101) (sym-truncate) (sym-unknown))  ; 'e'
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (if (eq c1 102)  ; 'f' for function
                  (if (eq c2 117)  ; 'u'
                      (if (eq c3 110)  ; 'n'
                          (if (eq c4 99)  ; 'c'
                              (if (eq c5 116)  ; 't'
                                  (if (eq c6 105)  ; 'i'
                                      (if (eq c7 111)  ; 'o'
                                          (if (eq c8 110) (sym-function) (sym-unknown))  ; 'n'
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown)))))

    ;; Match 9-char symbols: print-dec
    ;; print-dec: p(112) r(114) i(105) n(110) t(116) -(45) d(100) e(101) c(99)
    (defun match-9char (c1 c2 c3 c4 c5 c6 c7 c8 c9)
      (if (eq c1 112)  ; 'p' for print-dec
          (if (eq c2 114)  ; 'r'
              (if (eq c3 105)  ; 'i'
                  (if (eq c4 110)  ; 'n'
                      (if (eq c5 116)  ; 't'
                          (if (eq c6 45)  ; '-'
                              (if (eq c7 100)  ; 'd'
                                  (if (eq c8 101)  ; 'e'
                                      (if (eq c9 99) (sym-print-dec) (sym-unknown))  ; 'c'
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))
          (sym-unknown)))

    ;; Match 10-char symbols: io-in-byte, bignum-ref, bignum-set, bignum-add, bignum-sub, bignum-mul
    ;; io-in-byte: i(105) o(111) -(45) i(105) n(110) -(45) b(98) y(121) t(116) e(101)
    ;; bignum-XXX: b(98) i(105) g(103) n(110) u(117) m(109) -(45) ...
    (defun match-10char (c1 c2 c3 c4 c5 c6 c7 c8 c9 c10)
      (if (eq c1 105)  ; 'i' for io-in-byte
          (if (eq c2 111)  ; 'o'
              (if (eq c3 45)  ; '-'
                  (if (eq c4 105)  ; 'i'
                      (if (eq c5 110)  ; 'n'
                          (if (eq c6 45)  ; '-'
                              (if (eq c7 98)  ; 'b'
                                  (if (eq c8 121)  ; 'y'
                                      (if (eq c9 116)  ; 't'
                                          (if (eq c10 101) (sym-io-in-byte) (sym-unknown))  ; 'e'
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))
          (if (eq c1 98)  ; 'b' for bignum-XXX
              (if (eq c2 105)  ; 'i'
                  (if (eq c3 103)  ; 'g'
                      (if (eq c4 110)  ; 'n'
                          (if (eq c5 117)  ; 'u'
                              (if (eq c6 109)  ; 'm'
                                  (if (eq c7 45)  ; '-'
                                      ;; Dispatch on c8: r(ref), s(set/sub), a(add), m(mul)
                                      (if (eq c8 114)  ; 'r' for ref
                                          (if (eq c9 101)  ; 'e'
                                              (if (eq c10 102) (sym-bignum-ref) (sym-unknown))  ; 'f'
                                              (sym-unknown))
                                          (if (eq c8 115)  ; 's' for set or sub
                                              (if (eq c9 101)  ; 'e' for set
                                                  (if (eq c10 116) (sym-bignum-set) (sym-unknown))  ; 't'
                                                  (if (eq c9 117)  ; 'u' for sub
                                                      (if (eq c10 98) (sym-bignum-sub) (sym-unknown))  ; 'b'
                                                      (sym-unknown)))
                                              (if (eq c8 97)  ; 'a' for add
                                                  (if (eq c9 100)  ; 'd'
                                                      (if (eq c10 100) (sym-bignum-add) (sym-unknown))  ; 'd'
                                                      (sym-unknown))
                                                  (if (eq c8 109)  ; 'm' for mul
                                                      (if (eq c9 117)  ; 'u'
                                                          (if (eq c10 108) (sym-bignum-mul) (sym-unknown))  ; 'l'
                                                          (sym-unknown))
                                                      (sym-unknown)))))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (if (eq c1 109)  ; 'm' for make-array
                  (if (eq c2 97)  ; 'a'
                      (if (eq c3 107)  ; 'k'
                          (if (eq c4 101)  ; 'e'
                              (if (eq c5 45)  ; '-'
                                  (if (eq c6 97)  ; 'a'
                                      (if (eq c7 114)  ; 'r'
                                          (if (eq c8 114)  ; 'r'
                                              (if (eq c9 97)  ; 'a'
                                                  (if (eq c10 121) (sym-make-array) (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (if (eq c1 115)  ; 's' for string-ref, string-set
                      (if (eq c2 116)  ; 't'
                          (if (eq c3 114)  ; 'r'
                              (if (eq c4 105)  ; 'i'
                                  (if (eq c5 110)  ; 'n'
                                      (if (eq c6 103)  ; 'g'
                                          (if (eq c7 45)  ; '-'
                                              (if (eq c8 114)  ; 'r' for string-ref
                                                  (if (eq c9 101)
                                                      (if (eq c10 102) (sym-string-ref) (sym-unknown))
                                                      (sym-unknown))
                                                  (if (eq c8 115)  ; 's' for string-set
                                                      (if (eq c9 101)
                                                          (if (eq c10 116) (sym-string-set) (sym-unknown))
                                                          (sym-unknown))
                                                      (sym-unknown)))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (if (eq c1 119)  ; 'w' for write-byte
                          (if (eq c2 114)  ; 'r'
                              (if (eq c3 105)  ; 'i'
                                  (if (eq c4 116)  ; 't'
                                      (if (eq c5 101)  ; 'e'
                                          (if (eq c6 45)  ; '-'
                                              (if (eq c7 98)  ; 'b'
                                                  (if (eq c8 121)  ; 'y'
                                                      (if (eq c9 116)  ; 't'
                                                          (if (eq c10 101) (sym-write-byte) (sym-unknown))
                                                          (sym-unknown))
                                                      (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown)))))))

    ;; Match 11-char symbols: io-out-byte, io-in-dword, make-bignum
    ;; io-out-byte: i(105) o(111) -(45) o(111) u(117) t(116) -(45) b(98) y(121) t(116) e(101)
    ;; io-in-dword: i(105) o(111) -(45) i(105) n(110) -(45) d(100) w(119) o(111) r(114) d(100)
    ;; make-bignum: m(109) a(97) k(107) e(101) -(45) b(98) i(105) g(103) n(110) u(117) m(109)
    (defun match-11char (c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11)
      (if (eq c1 105)  ; 'i' for io-out-byte or io-in-dword
          (if (eq c2 111)  ; 'o'
              (if (eq c3 45)  ; '-'
                  (if (eq c4 111)  ; 'o' for io-out-byte
                      (if (eq c5 117)  ; 'u'
                          (if (eq c6 116)  ; 't'
                              (if (eq c7 45)  ; '-'
                                  (if (eq c8 98)  ; 'b'
                                      (if (eq c9 121)  ; 'y'
                                          (if (eq c10 116)  ; 't'
                                              (if (eq c11 101) (sym-io-out-byte) (sym-unknown))  ; 'e'
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (if (eq c4 105)  ; 'i' for io-in-dword
                          (if (eq c5 110)  ; 'n'
                              (if (eq c6 45)  ; '-'
                                  (if (eq c7 100)  ; 'd'
                                      (if (eq c8 119)  ; 'w'
                                          (if (eq c9 111)  ; 'o'
                                              (if (eq c10 114)  ; 'r'
                                                  (if (eq c11 100) (sym-io-in-dword) (sym-unknown))  ; 'd'
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown)))
                  (sym-unknown))
              (sym-unknown))
          (if (eq c1 109)  ; 'm' for make-bignum, make-string
              (if (eq c2 97)  ; 'a'
                  (if (eq c3 107)  ; 'k'
                      (if (eq c4 101)  ; 'e'
                          (if (eq c5 45)  ; '-'
                              (if (eq c6 98)  ; 'b' for make-bignum
                                  (if (eq c7 105)  ; 'i'
                                      (if (eq c8 103)  ; 'g'
                                          (if (eq c9 110)  ; 'n'
                                              (if (eq c10 117)  ; 'u'
                                                  (if (eq c11 109) (sym-make-bignum) (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (if (eq c6 115)  ; 's' for make-string
                                      (if (eq c7 116)  ; 't'
                                          (if (eq c8 114)  ; 'r'
                                              (if (eq c9 105)  ; 'i'
                                                  (if (eq c10 110)  ; 'n'
                                                      (if (eq c11 103) (sym-make-string) (sym-unknown))
                                                      (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown)))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))))

    ;; Match 12-char symbols: print-bignum, print-string, array-length, io-out-dword
    ;; io-out-dword: i(105) o(111) -(45) o(111) u(117) t(116) -(45) d(100) w(119) o(111) r(114) d(100)
    (defun match-12char (c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12)
      (if (eq c1 112)  ; 'p' for print-bignum, print-string
          (if (eq c2 114)  ; 'r'
              (if (eq c3 105)  ; 'i'
                  (if (eq c4 110)  ; 'n'
                      (if (eq c5 116)  ; 't'
                          (if (eq c6 45)  ; '-'
                              (if (eq c7 98)  ; 'b' for print-bignum
                                  (if (eq c8 105)
                                      (if (eq c9 103)
                                          (if (eq c10 110)
                                              (if (eq c11 117)
                                                  (if (eq c12 109) (sym-print-bignum) (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (if (eq c7 115)  ; 's' for print-string
                                      (if (eq c8 116)
                                          (if (eq c9 114)
                                              (if (eq c10 105)
                                                  (if (eq c11 110)
                                                      (if (eq c12 103) (sym-print-string) (sym-unknown))
                                                      (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown)))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (sym-unknown))
          (if (eq c1 97)  ; 'a' for array-length
              (if (eq c2 114)
                  (if (eq c3 114)
                      (if (eq c4 97)
                          (if (eq c5 121)
                              (if (eq c6 45)
                                  (if (eq c7 108)
                                      (if (eq c8 101)
                                          (if (eq c9 110)
                                              (if (eq c10 103)
                                                  (if (eq c11 116)
                                                      (if (eq c12 104) (sym-array-length) (sym-unknown))
                                                      (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown))
              (if (eq c1 105)  ; 'i' for io-out-dword
                  (if (eq c2 111)  ; 'o'
                      (if (eq c3 45)  ; '-'
                          (if (eq c4 111)  ; 'o'
                              (if (eq c5 117)  ; 'u'
                                  (if (eq c6 116)  ; 't'
                                      (if (eq c7 45)  ; '-'
                                          (if (eq c8 100)  ; 'd'
                                              (if (eq c9 119)  ; 'w'
                                                  (if (eq c10 111)  ; 'o'
                                                      (if (eq c11 114)  ; 'r'
                                                          (if (eq c12 100) (sym-io-out-dword) (sym-unknown))
                                                          (sym-unknown))
                                                      (sym-unknown))
                                                  (sym-unknown))
                                              (sym-unknown))
                                          (sym-unknown))
                                      (sym-unknown))
                                  (sym-unknown))
                              (sym-unknown))
                          (sym-unknown))
                      (sym-unknown))
                  (sym-unknown)))))

    ;; Helper: get nth element of list (0-indexed)
    (defun list-nth (lst n)
      (if (eq n 0)
          (car lst)
          (list-nth (cdr lst) (- n 1))))

    ;; Dual FNV-1a hash for collision-free function name lookup.
    ;; Two independent FNV-1a-32 hashes combined into a 60-bit value.
    ;; With 60 bits and ~200 functions, collision probability ~4e-10.
    (defun fnv-hash1 (chars)
      (let ((h 2166136261)
            (rest chars))
        (loop
          (if (null rest)
              (return (logand h 1073741823))
              (progn
                (setq h (logxor h (car rest)))
                (setq h (logand (* h 16777619) 4294967295))
                (setq rest (cdr rest)))))))

    (defun fnv-hash2 (chars)
      (let ((h 3735928559)
            (rest chars))
        (loop
          (if (null rest)
              (return (logand h 1073741823))
              (progn
                (setq h (logxor h (car rest)))
                (setq h (logand (* h 805306457) 4294967295))
                (setq rest (cdr rest)))))))

    (defun hash-chars (chars len)
      (let ((v1 (fnv-hash1 chars)))
        (let ((v2 (fnv-hash2 chars)))
          (let ((combined (logior (ash v1 30) v2)))
            (if (eq combined 0) 1 combined)))))

    ;; Match symbol from list of chars
    (defun match-symbol (chars len)
      (if (eq len 1)
          (match-1char (car chars))
          (if (eq len 2)
              (match-2char (car chars) (cadr chars))
              (if (eq len 3)
                  (match-3char (car chars) (cadr chars)
                               (car (cdr (cdr chars))))
                  (if (eq len 4)
                      (match-4char (car chars) (cadr chars)
                                   (car (cdr (cdr chars)))
                                   (car (cdr (cdr (cdr chars)))))
                      (if (eq len 5)
                          (match-5char (car chars) (cadr chars)
                                       (car (cdr (cdr chars)))
                                       (car (cdr (cdr (cdr chars))))
                                       (car (cdr (cdr (cdr (cdr chars))))))
                          (if (eq len 6)
                              (match-6char (car chars) (cadr chars)
                                           (car (cdr (cdr chars)))
                                           (car (cdr (cdr (cdr chars))))
                                           (car (cdr (cdr (cdr (cdr chars)))))
                                           (car (cdr (cdr (cdr (cdr (cdr chars)))))))
                              (if (eq len 7)
                                  (match-7char (list-nth chars 0) (list-nth chars 1)
                                               (list-nth chars 2) (list-nth chars 3)
                                               (list-nth chars 4) (list-nth chars 5)
                                               (list-nth chars 6))
                                  (if (eq len 8)
                                      (match-8char (list-nth chars 0) (list-nth chars 1)
                                                   (list-nth chars 2) (list-nth chars 3)
                                                   (list-nth chars 4) (list-nth chars 5)
                                                   (list-nth chars 6) (list-nth chars 7))
                                      (if (eq len 9)
                                          (match-9char (list-nth chars 0) (list-nth chars 1)
                                                       (list-nth chars 2) (list-nth chars 3)
                                                       (list-nth chars 4) (list-nth chars 5)
                                                       (list-nth chars 6) (list-nth chars 7)
                                                       (list-nth chars 8))
                                          (if (eq len 10)
                                          (match-10char (list-nth chars 0) (list-nth chars 1)
                                                        (list-nth chars 2) (list-nth chars 3)
                                                        (list-nth chars 4) (list-nth chars 5)
                                                        (list-nth chars 6) (list-nth chars 7)
                                                        (list-nth chars 8) (list-nth chars 9))
                                          (if (eq len 11)
                                              (match-11char (list-nth chars 0) (list-nth chars 1)
                                                            (list-nth chars 2) (list-nth chars 3)
                                                            (list-nth chars 4) (list-nth chars 5)
                                                            (list-nth chars 6) (list-nth chars 7)
                                                            (list-nth chars 8) (list-nth chars 9)
                                                            (list-nth chars 10))
                                              (if (eq len 12)
                                                  (match-12char (list-nth chars 0) (list-nth chars 1)
                                                                (list-nth chars 2) (list-nth chars 3)
                                                                (list-nth chars 4) (list-nth chars 5)
                                                                (list-nth chars 6) (list-nth chars 7)
                                                                (list-nth chars 8) (list-nth chars 9)
                                                                (list-nth chars 10) (list-nth chars 11))
                                                  (sym-unknown))))))))))))))

    ;; Read a symbol (first char already read)
    (defun read-symbol (ch)
      (write-byte ch)
      (let ((chars (cons ch ()))
            (len 1)
            (done ()))
        (loop
          (if done
              (let ((sym (match-symbol (reverse-list chars) len)))
                (return (if (eq sym (sym-unknown))
                            (hash-chars (reverse-list chars) len)
                            sym)))
              (let ((raw (read-byte-la)))
                (if (raw-symbolp raw)
                    (progn
                      (write-byte raw)
                      (setq chars (cons raw chars))
                      (setq len (1+ len)))
                    (if (raw-alphap raw)
                        (progn
                          (write-byte raw)
                          (setq chars (cons raw chars))
                          (setq len (1+ len)))
                        (progn
                          (unread-byte raw)
                          (setq done t)))))))))

    ;; Read a string literal: opening " already consumed
    ;; Reads chars until closing ", allocates string, returns tagged pointer
    (defun read-string-literal ()
      (write-byte 34)  ; echo opening "
      ;; First pass: collect chars into a list and count
      (let ((chars ())
            (len 0)
            (done ()))
        (loop
          (if done
              (return ())
              (let ((raw (read-byte-la)))
                (if (eq raw 34)  ; closing "
                    (progn
                      (write-byte 34)  ; echo closing "
                      (setq done t))
                    (progn
                      (write-byte raw)
                      (setq chars (cons raw chars))
                      (setq len (+ len 1)))))))
        ;; Now allocate and fill string
        (let ((str (make-string len))
              (rev-chars (reverse-list chars))
              (i 0))
          (loop
            (if (null rev-chars)
                (return str)
                (progn
                  (string-set str i (car rev-chars))
                  (setq rev-chars (cdr rev-chars))
                  (setq i (+ i 1))))))))

    ;; Read an object: number, symbol, list, or string
    ;; ch is the first character already read
    ;; Note: source constants are TAGGED by compiler (N becomes 2*N)
    ;; So (eq ch 49) compares ch with tagged '1' (49*2=98 at runtime)
    (defun read-obj (ch)
      (if (eq ch 40)  ; '(' (ASCII 40, tagged by compiler to 80)
          (progn
            (write-byte ch)
            (read-list))
          (if (eq ch 34)  ; '"' - string literal
              (read-string-literal)
              (if (raw-digitp ch)
                  ;; Check for special 1+ and 1- symbols
                  (if (eq ch 49)  ; '1' (ASCII 49)
                      (let ((next (read-byte-la)))
                        (if (eq next 43)  ; '+' (ASCII 43)
                            (progn
                              (write-byte ch)
                              (write-byte next)
                              (sym-1plus))
                            (if (eq next 45)  ; '-' (ASCII 45)
                                (progn
                                  (write-byte ch)
                                  (write-byte next)
                                  (sym-1minus))
                                (progn
                                  (unread-byte next)
                                  (read-num ch)))))
                      (read-num ch))
                  (if (raw-symbolp ch)
                      (read-symbol ch)
                      (if (raw-alphap ch)
                          (read-symbol ch)
                          (progn
                            (write-byte ch)
                            0)))))))

    ;; Environment: association list of (symbol-id . value) pairs
    ;; env-lookup returns the value or nil if not found
    (defun env-lookup (env sym)
      (if (null env)
          ()
          (if (eq (car (car env)) sym)
              (cdr (car env))
              (env-lookup (cdr env) sym))))

    ;; Check if symbol is bound in environment
    (defun env-bound-p (env sym)
      (if (null env)
          ()
          (if (eq (car (car env)) sym)
              t
              (env-bound-p (cdr env) sym))))

    ;; env-extend: add a binding to the environment
    (defun env-extend (env sym val)
      (cons (cons sym val) env))

    ;; Global function table: stored at fixed memory location
    ;; Each entry is (name params . body)
    ;; 0x300020 = function table pointer
    (defun get-fntable ()
      (mem-ref #x300020 :u64))

    (defun set-fntable (tbl)
      (setf (mem-ref #x300020 :u64) tbl))

    ;; Initialize function table (call once at startup)
    (defun init-fntable ()
      (set-fntable ()))

    ;; Look up a function by name (symbol ID)
    (defun fn-lookup (name)
      (let ((tbl (get-fntable)))
        (if (null tbl)
            ()
            (fn-lookup-in tbl name))))

    (defun fn-lookup-in (tbl name)
      (if (null tbl)
          ()
          (let ((entry (car tbl)))
            (let ((entry-name (car entry)))
              (if (eq entry-name name)
                  entry
                  (fn-lookup-in (cdr tbl) name))))))

    ;; Define a function: (defun name (params) body)
    ;; Stores (name params . body) in function table
    (defun fn-define (name params body)
      (let ((inner (cons params body)))
        (let ((entry (cons name inner)))
          (let ((old-tbl (get-fntable)))
            (let ((new-tbl (cons entry old-tbl)))
              (set-fntable new-tbl)
              name)))))

    ;; Bind parameters to arguments
    (defun bind-params (params args env)
      (if (null params)
          env
          (bind-params (cdr params) (cdr args)
                       (env-extend env (car params) (car args)))))

    ;; Apply a user function
    ;; fn-entry is (name params . body)
    (defun apply-fn (fn-entry args env)
      (let ((params (cadr fn-entry))
            (body (cdr (cdr fn-entry))))
        (let ((arg-vals (eval-args args env)))
          (let ((fn-env (bind-params params arg-vals ())))
            (eval-fn-body body fn-env)))))

    ;; Evaluate arguments (like eval-list-args)
    (defun eval-args (args env)
      (if (null args)
          ()
          (cons (eval-form (car args) env)
                (eval-args (cdr args) env))))

    ;; Evaluate function body (multiple forms)
    (defun eval-fn-body (body env)
      (if (null body)
          ()
          (if (null (cdr body))
              (eval-form (car body) env)
              (progn
                (eval-form (car body) env)
                (eval-fn-body (cdr body) env)))))

    ;; Evaluate arithmetic: +, -, *, 1+, 1-
    ;; Helper: compute list length iteratively
    (defun eval-length (lst)
      (let ((count 0))
        (loop
          (if (null lst)
              (return count)
              (progn
                (setq count (+ count 1))
                (setq lst (cdr lst)))))))

    ;; Helper: get nth element iteratively
    (defun eval-nth (n lst)
      (loop
        (if (eq n 0)
            (return (car lst))
            (progn
              (setq n (- n 1))
              (setq lst (cdr lst))))))

    (defun eval-arith (op args env)
      (if (eq op (sym-plus))
          (+ (eval-form (car args) env) (eval-form (cadr args) env))
          (if (eq op (sym-minus))
              (- (eval-form (car args) env) (eval-form (cadr args) env))
              (if (eq op (sym-times))
                  (* (eval-form (car args) env) (eval-form (cadr args) env))
                  (if (eq op (sym-1plus))
                      (1+ (eval-form (car args) env))
                      (1- (eval-form (car args) env)))))))

    ;; Evaluate list ops: car, cdr, cons, list, cadr, cddr, caddr, consp
    (defun eval-list-op (op args env)
      (if (eq op (sym-car))
          (car (eval-form (car args) env))
          (if (eq op (sym-cdr))
              (cdr (eval-form (car args) env))
              (if (eq op (sym-cons))
                  (cons (eval-form (car args) env) (eval-form (cadr args) env))
                  (if (eq op (sym-list))
                      (eval-list-args args env)
                      (if (eq op (sym-cadr))
                          (car (cdr (eval-form (car args) env)))
                          (if (eq op (sym-cddr))
                              (cdr (cdr (eval-form (car args) env)))
                              (if (eq op (sym-caddr))
                                  (car (cdr (cdr (eval-form (car args) env))))
                                  (if (eq op (sym-consp))
                                      ;; consp - check if cons cell
                                      (if (consp (eval-form (car args) env))
                                          (sym-t)
                                          ())
                                      (if (eq op (sym-length))
                                          ;; length - count list elements  
                                          (eval-length (eval-form (car args) env))
                                          ;; nth - get element at index
                                          (eval-nth (eval-form (car args) env)
                                                    (eval-form (cadr args) env))))))))))))

    ;; Evaluate let bindings, return extended env
    ;; bindings is ((sym1 val1) (sym2 val2) ...)
    (defun eval-let-bindings (bindings env)
      (if (null bindings)
          env
          (let ((binding (car bindings)))
            (let ((sym (car binding))
                  (val (eval-form (cadr binding) env)))
              (eval-let-bindings (cdr bindings)
                                 (env-extend env sym val))))))

    ;; Evaluate let body (multiple forms, return last)
    (defun eval-let-body (body env)
      (if (null body)
          ()
          (if (null (cdr body))
              (eval-form (car body) env)
              (progn
                (eval-form (car body) env)
                (eval-let-body (cdr body) env)))))

    ;; Evaluate special forms: if, eq, null, quote, let, defun
    (defun eval-special (op args env)
      (if (eq op (sym-if))
          ;; (if test then else)
          (if (eval-form (car args) env)
              (eval-form (cadr args) env)
              (eval-form (car (cdr (cdr args))) env))
          (if (eq op (sym-eq))
              ;; (eq a b) - return t or nil
              (if (eq (eval-form (car args) env) (eval-form (cadr args) env))
                  (sym-t)
                  ())
              (if (eq op (sym-null))
                  ;; (null x) - return t if nil
                  (if (null (eval-form (car args) env))
                      (sym-t)
                      ())
                  (if (eq op (sym-quote))
                      ;; (quote x) - return unevaluated
                      (car args)
                      (if (eq op (sym-let))
                          ;; (let ((v1 e1) ...) body...)
                          (let ((new-env (eval-let-bindings (car args) env)))
                            (eval-let-body (cdr args) new-env))
                          (if (eq op (sym-defun))
                              ;; (defun name (params) body...)
                              (let ((name (car args))
                                    (params (cadr args))
                                    (body (cdr (cdr args))))
                                (fn-define name params body)
                                name)
                              (if (eq op (sym-progn))
                                  ;; (progn form1 form2 ...) - eval all, return last
                                  (eval-progn-forms args env)
                                  (if (eq op (sym-zerop))
                                      ;; (zerop x) - return t if zero
                                      (if (eq (eval-form (car args) env) 0)
                                          (sym-t)
                                          ())
                                      (if (eq op (sym-not))
                                          ;; (not x) - return t if nil
                                          (if (null (eval-form (car args) env))
                                              (sym-t)
                                              ())
                                          (if (eq op (sym-logand))
                                              ;; (logand a b) - bitwise and
                                              (logand (eval-form (car args) env)
                                                      (eval-form (cadr args) env))
                                              (if (eq op (sym-atom))
                                                  ;; (atom x) - return t if not a cons
                                                  (if (consp (eval-form (car args) env))
                                                      ()
                                                      (sym-t))
                                                  ;; (setq var val) - modify existing binding
                                                  (eval-setq (car args) (eval-form (cadr args) env) env)))))))))))))

    ;; Evaluate progn forms - return value of last form
    (defun eval-progn-forms (forms env)
      (if (null forms)
          ()
          (if (null (cdr forms))
              (eval-form (car forms) env)
              (progn
                (eval-form (car forms) env)
                (eval-progn-forms (cdr forms) env)))))

    ;; Evaluate setq - set variable value in environment
    ;; Note: In this simple interpreter, we can't actually modify the environment
    ;; since it's an immutable assoc list. For now, just return the value.
    (defun eval-setq (var val env)
      ;; In real implementation, would need mutable bindings
      ;; For now, just return the value
      val)

    ;; Check if op is arithmetic
    (defun arith-op-p (op)
      (if (eq op (sym-plus)) t
          (if (eq op (sym-minus)) t
              (if (eq op (sym-times)) t
                  (if (eq op (sym-1plus)) t
                      (if (eq op (sym-1minus)) t ()))))))

    ;; Check if op is list operation
    (defun list-op-p (op)
      (if (eq op (sym-car)) t
          (if (eq op (sym-cdr)) t
              (if (eq op (sym-cons)) t
                  (if (eq op (sym-list)) t
                      (if (eq op (sym-cadr)) t
                          (if (eq op (sym-cddr)) t
                              (if (eq op (sym-caddr)) t
                                  (if (eq op (sym-consp)) t
                                      (if (eq op (sym-length)) t
                                          (if (eq op (sym-nth)) t ())))))))))))

    ;; Check if op is comparison
    (defun compare-op-p (op)
      (if (eq op (sym-lt)) t
          (if (eq op (sym-gt)) t ())))

    ;; Evaluate comparison (< or >)
    (defun eval-compare (op args env)
      (let ((a (eval-form (car args) env))
            (b (eval-form (cadr args) env)))
        (if (eq op (sym-lt))
            (if (< a b) (sym-t) ())
            (if (eq op (sym-gt))
                (if (> a b) (sym-t) ())
                ()))))

    ;; Check if op is special form
    (defun special-op-p (op)
      (if (eq op (sym-if)) t
          (if (eq op (sym-eq)) t
              (if (eq op (sym-null)) t
                  (if (eq op (sym-quote)) t
                      (if (eq op (sym-let)) t
                          (if (eq op (sym-defun)) t
                              (if (eq op (sym-progn)) t
                                  (if (eq op (sym-setq)) t
                                      (if (eq op (sym-zerop)) t
                                          (if (eq op (sym-not)) t
                                              (if (eq op (sym-logand)) t
                                                  (if (eq op (sym-atom)) t ())))))))))))))

    ;; Check if symbol is a variable (not a known symbol)
    ;; Returns the symbol ID if it's a potential variable
    (defun variable-p (sym)
      (if (eq sym (sym-t)) ()
          (if (eq sym (sym-unknown)) ()
              (if (arith-op-p sym) ()
                  (if (list-op-p sym) ()
                      (if (compare-op-p sym) ()
                          (if (special-op-p sym) ()
                              t)))))))

    ;; Evaluate a form: numbers self-evaluate, lists are function calls
    (defun eval-form (form env)
      (if (null form)
          ()
          (if (consp form)
              (let ((op (car form))
                    (args (cdr form)))
                (if (arith-op-p op)
                    (eval-arith op args env)
                    (if (list-op-p op)
                        (eval-list-op op args env)
                        (if (compare-op-p op)
                            (eval-compare op args env)
                            (if (special-op-p op)
                                (eval-special op args env)
                                ;; Try user-defined function
                                (let ((fn-entry (fn-lookup op)))
                                  (if fn-entry
                                      (apply-fn fn-entry args env)
                                      ;; Unknown - return 0
                                      0)))))))
              ;; Atom - check for t symbol, then variable lookup
              (if (eq form (sym-t))
                  (sym-t)
                  (if (env-bound-p env form)
                      (env-lookup env form)  ; Return value (even if nil)
                      form)))))  ; Not found - return symbol as-is

    ;; Evaluate list args (for 'list' function)
    (defun eval-list-args (args env)
      (if (null args)
          ()
          (cons (eval-form (car args) env)
                (eval-list-args (cdr args) env))))

    ;; ================================================================
    ;; Native Evaluation - compile to native code and execute
    ;; ================================================================

    ;; Native eval - compile a form to native code and execute it
    (defun native-eval (form)
      ;; Check for defun - handle specially
      (if (if (consp form) (eq (car form) (sym-defun)) ())
          ;; defun - compile and register, return the name
          (progn
            (rt-compile-defun (cdr form))
            (car (cdr form)))
          ;; Regular expression - compile at current position and execute
          (let ((start-addr (+ #x500008 (code-pos))))
            (rt-compile-expr-env form () 0)
            (emit-ret)
            (call-native start-addr 0 0))))

    ;; Output prompt based on mode flag at 0x312A00
    ;; mode 0 = "> " (serial), mode 1 = "modus64> " (SSH)
    (defun emit-prompt ()
      (if (zerop (mem-ref #x312A00 :u64))
          (progn (write-byte 62) (write-byte 32))
          (progn
            (write-byte 109) (write-byte 111)
            (write-byte 100) (write-byte 117)
            (write-byte 115) (write-byte 54)
            (write-byte 52) (write-byte 62) (write-byte 32))))

    ;; Process a single byte of input for line editing
    ;; Returns: 0 = continue, 1 = enter pressed, 2 = ctrl-d (quit)
    ;; Uses shared edit state at 0x312800 (line-len, cursor-pos, esc-state)
    ;; Return code stored at 0x312A08 (avoids bare integer literal returns)
    (defun handle-edit-byte (b)
      (let ((esc (mem-ref #x312810 :u64)))
        (setf (mem-ref #x312A08 :u64) 0)
        ;; Escape sequence state machine
        ;; States: 0=normal, 1=ESC, 2=ESC[, 3=ESC[1, 4=ESC[1;, 5=ESC[1;N
        (if (eq esc 1)
            ;; Got ESC: '[' -> state 2, 'f' -> word-right, 'b' -> word-left
            (if (eq b 91)
                (setf (mem-ref #x312810 :u64) 2)
                (progn
                  (setf (mem-ref #x312810 :u64) 0)
                  (if (eq b 102) (word-right)
                      (if (eq b 98) (word-left)
                          nil))))
            (if (eq esc 2)
                ;; Got ESC[: A/B/C/D or '1' for extended
                (if (eq b 49)
                    (setf (mem-ref #x312810 :u64) 3)
                    (progn
                      (setf (mem-ref #x312810 :u64) 0)
                      (if (eq b 65)
                          (history-up)
                          (if (eq b 66)
                              (history-down)
                              (if (eq b 67)
                                  (when (< (edit-cursor-pos) (edit-line-len))
                                    (edit-set-cursor-pos (+ (edit-cursor-pos) 1))
                                    (cursor-right 1))
                                  (if (eq b 68)
                                      (when (> (edit-cursor-pos) 0)
                                        (edit-set-cursor-pos (- (edit-cursor-pos) 1))
                                        (cursor-left 1))
                                      nil))))))
                (if (eq esc 3)
                    ;; Got ESC[1: expect ';'
                    (if (eq b 59)
                        (setf (mem-ref #x312810 :u64) 4)
                        (setf (mem-ref #x312810 :u64) 0))
                    (if (eq esc 4)
                        ;; Got ESC[1;: accept modifier digit -> state 5
                        (setf (mem-ref #x312810 :u64) 5)
                        (if (eq esc 5)
                            ;; Got ESC[1;N: C -> word-right, D -> word-left
                            (progn
                              (setf (mem-ref #x312810 :u64) 0)
                              (if (eq b 67) (word-right)
                                  (if (eq b 68) (word-left)
                                      nil)))
                            ;; Normal state (esc=0)
                (if (eq b 27)
                    (setf (mem-ref #x312810 :u64) 1)
                    (if (if (eq b 127) t (eq b 8))
                        (line-delete-back)
                        (if (if (eq b 10) t (eq b 13))
                            (progn
                              (history-save)
                              (let ((len (edit-line-len)))
                                (setf (mem-ref #x300024 :u32) len)
                                (setf (mem-ref #x300020 :u32) 0))
                              (setf (mem-ref #x312A08 :u64) 1))
                            (if (eq b 4)
                                (when (zerop (edit-line-len))
                                  (setf (mem-ref #x312A08 :u64) 2))
                                (if (eq b 3)
                                    (progn
                                      (write-byte 94) (write-byte 67)
                                      (write-byte 10)
                                      (edit-set-line-len 0)
                                      (edit-set-cursor-pos 0)
                                      (emit-prompt))
                                    (if (eq b 21)
                                        (progn
                                          (edit-set-line-len 0)
                                          (edit-set-cursor-pos 0)
                                          (line-redraw-full))
                                        (if (eq b 1)
                                            (cursor-to-start)
                                            (if (eq b 5)
                                                (let ((dist (- (edit-line-len) (edit-cursor-pos))))
                                                  (when (> dist 0)
                                                    (cursor-right dist)
                                                    (edit-set-cursor-pos (edit-line-len))))
                                                (if (eq b 11)
                                                    (progn
                                                      (edit-set-line-len (edit-cursor-pos))
                                                      (erase-to-eol))
                                                    (if (eq b 9)
                                                        (tab-complete)
                                                        (when (> b 31)
                                                          (when (< b 127)
                                                            (line-insert-byte b))))))))))))))))))
        (mem-ref #x312A08 :u64)))

    ;; Read a line from serial with full editing support
    ;; Features: cursor movement, backspace at any position, ctrl keys,
    ;;   arrow keys (VT100 escape sequences), command history, tab completion
    ;; Stores result at 0x300028+, length at 0x300024, read-pos at 0x300020
    ;; Edit state at 0x312800: line-len, cursor-pos, escape-state
    ;; Returns 0 on Enter, 1 on Ctrl-D (EOF)
    (defun read-line-edit ()
      (edit-set-line-len 0)
      (edit-set-cursor-pos 0)
      (setf (mem-ref #x312810 :u64) 0)
      (loop
        (wait-for-input)
        (let ((rc (handle-edit-byte (io-in-byte #x3F8))))
          (if (eq rc 1) (return 0)
              (if (eq rc 2) (return 1)
                  ())))))

    ;; Read and evaluate an expression using native compilation
    ;; '(' already consumed (legacy path for SSH eval)
    (defun eval-expr ()
      (write-byte 40)  ; echo '('
      (let ((edited 0))
        ;; If FIFO empty (serial input), read line with editing support
        (when (zerop (mem-ref #x300024 :u32))
          (read-line-edit)
          ;; Suppress serial echo during reader parse (already echoed)
          (setf (mem-ref #x300014 :u32) 2)
          (setq edited 1))
        ;; Read the full list (from FIFO buffer)
        (let ((lst (read-list)))
          ;; Restore serial output
          (when (not (zerop edited))
            (setf (mem-ref #x300014 :u32) 0))
          (write-byte 10)
          (write-byte 61) (write-byte 32)  ; "= "
          (print-obj (native-eval lst))
          (write-byte 10))))


    ;; Line-based REPL with full editing support
    ;; Type command + Enter. Arrow keys, history, tab completion.
    (defun repl ()
      ;; Initialize function table for user functions
      (code-set-pos #x10000)
      (init-nfntable)
      ;; Clear reader state
      (set-lookahead 0)
      ;; Register cross-compiled builtin functions for REPL access.
      ;; Uses call-native via fixed address because register-builtins is
      ;; compiled by the old cross-compiler (not MVM), so MVM cannot
      ;; resolve it as a direct call.
      (call-native (mem-ref #x4FF0B0 :u64))
      ;; Initialize GC helper early so make-byte-array can trigger GC from any actor
      (init-gc-helper)
      ;; Initialize symbol name table for tab completion
      (init-symbol-table)
      (eval-cmdline)
      (print-help)
      (loop
        (emit-prompt)
        (let ((rc (read-line-edit)))
          (if (eq rc 1)  ; Ctrl-D -> shutdown
              (halt)
              ;; Dispatch on line content
              (let ((len (edit-line-len)))
                (if (zerop len)
                    (write-byte 10)  ; empty line, just newline
                    (let ((b0 (mem-ref #x300028 :u8)))
                      (write-byte 10)  ; newline after input
                      (if (eq b0 40)  ; '(' - expression
                          ;; Set up FIFO: skip '(', reader will consume rest
                          (progn
                            (setf (mem-ref #x300020 :u32) 1)
                            (setf (mem-ref #x300024 :u32) len)
                            (eval-line-expr))
                          (if (eq b0 104)  ; 'h'
                              (print-help)
                              (if (eq b0 109)  ; 'm'
                                  (show-mem)
                                  (if (eq b0 113)  ; 'q'
                                      (halt)
                                      (if (eq b0 99)  ; 'c'
                                          (test-compile-cmd)
                                          (if (raw-digitp b0)
                                              (parse-print-line-number)
                                              ;; Unknown command
                                              (progn
                                                (write-byte 63)  ; '?'
                                                (write-byte 10)))))))))))))))

    ;; Test compile command - run native compiler tests
    (defun test-compile-cmd ()
      ;; PJ: Test patch-jump writes correct byte (should be 0A)
      (code-init)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (patch-jump 2 16)
      (write-byte 80) (write-byte 74) (write-byte 58)  ;; 'PJ:'
      (print-hex-byte (mem-ref #x50000A :u8))
      (write-byte 10)
      ;; PR: Test patch-rel32 (should be 0A)
      (code-init)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (patch-rel32 2 16)
      (write-byte 80) (write-byte 82) (write-byte 58)  ;; 'PR:'
      (print-hex-byte (mem-ref #x50000A :u8))
      (write-byte 10)
      ;; NA: Test native-compiled (+ 10 20) => 30
      (write-byte 78) (write-byte 65) (write-byte 58)  ;; 'NA:'
      (print-dec (test-native-add 10 20))
      (write-byte 10)
      ;; NS: Test native-compiled (- 50 17) => 33
      (write-byte 78) (write-byte 83) (write-byte 58)  ;; 'NS:'
      (print-dec (test-native-sub 50 17))
      (write-byte 10)
      ;; NM: Test native-compiled (* 6 7) => 42
      (write-byte 78) (write-byte 77) (write-byte 58)  ;; 'NM:'
      (print-dec (test-native-mul 6 7))
      (write-byte 10))

    ;; Boot message
    (defun print-boot-message ()
      ;; Initialize lookahead buffer to 0
      (set-lookahead 0)
      ;; Initialize function table (interpreter)
      (init-fntable)
      ;; Initialize native function table
      (init-nfntable)
      ;; Initialize code buffer
      (code-init)
      (write-byte 79)   ; 'O'
      (write-byte 75)   ; 'K'
      (write-byte 10))  ; newline

    ;;; ============================================================
    ;;; Runtime Assembler (Phase 4)
    ;;; ============================================================

    ;; Code buffer at 0x500000: position at [0], code at [8+]
    (defun code-init ()
      (setf (mem-ref #x500000 :u64) 0))

    ;; Raw constants for address arithmetic (stored untagged)
    ;; These avoid mixing tagged constants with untagged code-pos
    ;; Constants stored at init time using (ash x -1) to untag
    ;; Address: 0x4FF020 = code base (0x500008)
    ;; Address: 0x4FF028 = five (5)
    (defun init-raw-constants ()
      (setf (mem-ref #x4FF020 :u64) (ash #x500008 -1))
      (setf (mem-ref #x4FF028 :u64) (ash 5 -1))
      ;; Clear image-compile mode flag (may be non-zero if kernel image
      ;; extends past 0x4FF080 and loaded data overwrites it)
      (setf (mem-ref #x4FF080 :u64) 0)
      ;; Clear code buffer position
      (setf (mem-ref #x500000 :u64) 0))

    (defun raw-code-base ()
      (mem-ref #x4FF020 :u64))

    (defun raw-five ()
      (mem-ref #x4FF028 :u64))

    ;; Emit a raw (untagged) u32 value - for relative offsets
    (defun code-emit-u32-raw (v)
      ;; v is already untagged, store directly and emit bytes
      (setf (mem-ref #x4FF030 :u64) v)
      (code-emit (mem-ref #x4FF030 :u8))
      (code-emit (mem-ref #x4FF031 :u8))
      (code-emit (mem-ref #x4FF032 :u8))
      (code-emit (mem-ref #x4FF033 :u8)))

    (defun code-emit-u64-raw (v)
      ;; Emit raw bytes of v (including tag bits) to code buffer.
      ;; Stores tagged value as u64 (no untagging), reads bytes as u8
      ;; (tags each byte), passes to code-emit (untags) - net: raw bytes.
      (setf (mem-ref #x4FF030 :u64) v)
      (code-emit (mem-ref #x4FF030 :u8))
      (code-emit (mem-ref #x4FF031 :u8))
      (code-emit (mem-ref #x4FF032 :u8))
      (code-emit (mem-ref #x4FF033 :u8))
      (code-emit (mem-ref #x4FF034 :u8))
      (code-emit (mem-ref #x4FF035 :u8))
      (code-emit (mem-ref #x4FF036 :u8))
      (code-emit (mem-ref #x4FF037 :u8)))

    (defun code-pos ()
      (if (not (zerop (mem-ref #x4FF080 :u64)))
          ;; Image mode: return image buffer position
          (mem-ref #x4FF040 :u64)
          (mem-ref #x500000 :u64)))

    (defun code-set-pos (p)
      (if (not (zerop (mem-ref #x4FF080 :u64)))
          (setf (mem-ref #x4FF040 :u64) p)
          (setf (mem-ref #x500000 :u64) p)))

    (defun code-emit (b)
      (if (not (zerop (mem-ref #x4FF080 :u64)))
          ;; Image mode: emit to image buffer
          (let ((pos (mem-ref #x4FF040 :u64)))
            (setf (mem-ref (+ #x08000000 pos) :u8) b)
            (setf (mem-ref #x4FF040 :u64) (+ pos 1)))
          ;; Normal mode: emit to code buffer
          (let ((pos (mem-ref #x500000 :u64)))
            (setf (mem-ref (+ #x500008 pos) :u8) b)
            (setf (mem-ref #x500000 :u64) (+ pos 1)))))

    ;; Patch a byte at a previous position (for jump offsets)
    (defun code-patch (pos val)
      (if (not (zerop (mem-ref #x4FF080 :u64)))
          (setf (mem-ref (+ #x08000000 pos) :u8) val)
          (setf (mem-ref (+ #x500008 pos) :u8) val)))

    ;; Emit a 64-bit value as 8 bytes (little-endian)
    ;; v is the logical value we want as bytes
    ;; Extract each byte using logand/ash - this preserves all bits including low bit
    (defun code-emit-u64 (v)
      (code-emit (logand v 255))
      (code-emit (logand (ash v -8) 255))
      (code-emit (logand (ash v -16) 255))
      (code-emit (logand (ash v -24) 255))
      (code-emit (logand (ash v -32) 255))
      (code-emit (logand (ash v -40) 255))
      (code-emit (logand (ash v -48) 255))
      (code-emit (logand (ash v -56) 255)))

    ;; Emit a 32-bit value as 4 bytes (little-endian)
    (defun code-emit-u32 (v)
      (code-emit (logand v 255))
      (code-emit (logand (ash v -8) 255))
      (code-emit (logand (ash v -16) 255))
      (code-emit (logand (ash v -24) 255)))

    ;; x86-64 instruction encoders
    (defun emit-rex-w () (code-emit #x48))
    (defun emit-ret () (code-emit #xC3))

    (defun emit-mov-rax-imm64 (imm)
      (emit-rex-w)
      (code-emit #xB8)
      (code-emit-u64 imm))

    ;; Emit mov rax, <raw-tagged-value>
    ;; Form is already a tagged fixnum in the runtime. This emits its raw
    ;; bytes as the immediate, avoiding overflow from (* form 2).
    (defun emit-mov-rax-tagged (form)
      (emit-rex-w)
      (code-emit #xB8)
      (code-emit-u64-raw form))

    (defun emit-add-rax-rdi ()
      (emit-rex-w)
      (code-emit #x01)
      (code-emit #xF8))

    (defun emit-sub-rax-rdi ()
      (emit-rex-w)
      (code-emit #x29)
      (code-emit #xF8))

    (defun emit-shl-rax-1 ()
      (emit-rex-w)
      (code-emit #xD1)
      (code-emit #xE0))

    (defun emit-sar-rax-1 ()
      (emit-rex-w)
      (code-emit #xD1)
      (code-emit #xF8))

    (defun emit-sar-rdi-1 ()
      (emit-rex-w)
      (code-emit #xD1)
      (code-emit #xFF))

    (defun emit-mov-rax-rsi ()
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xF0))

    (defun emit-mov-rax-rdi ()
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xF8))

    ;; Compile binary arithmetic: compile both args, operate, result in RAX
    ;; Uses stack to save intermediate results

    ;; push rax
    (defun emit-push-rax ()
      (code-emit #x50))

    ;; pop rdi
    (defun emit-pop-rdi ()
      (code-emit #x5F))

    ;; Compile (+ a b) with arbitrary subexpressions
    (defun rt-compile-add (args)
      (rt-compile-expr (car args))         ; compile first arg -> RAX
      (emit-push-rax)                       ; save on stack
      (rt-compile-expr (car (cdr args)))   ; compile second arg -> RAX
      (emit-mov-rax-rdi)                   ; move to RDI (second operand)
      (emit-pop-rdi)                       ; WRONG - need first in RAX
      ;; Actually: first is on stack, second in RAX
      ;; pop first into RDI, then add RDI to RAX? No...
      ;; Let me redo: save second, pop first to RAX
      )

    ;; Better approach: result always in RAX, use RDI as scratch
    ;; With environment tracking for let bindings
    (defun rt-compile-binop-env (op args env depth)
      ;; Handle 3+ args by reducing to nested binary: (+ a b c) -> (+ (+ a b) c)
      (if (cdr (cdr args))
          ;; 3+ args: reduce left-to-right
          (rt-compile-binop-env op
            (cons (cons op (cons (car args) (cons (car (cdr args)) ())))
                  (cdr (cdr args)))
            env depth)
          ;; Normal 2-arg case:
          (progn
            ;; Compile first arg -> RAX, push
            (rt-compile-expr-env (car args) env depth)
            (emit-push-rax)
            ;; Compile second arg with incremented depth (we pushed one value)
            (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
            (emit-mov-reg-rax-to-rdi)
            ;; Pop first arg back to RAX
            (emit-pop-rax)
            ;; Now: RAX = first, RDI = second
            ;; Untag both
            (emit-sar-rax-1)
            (emit-sar-rdi-1)
            ;; Do the operation
            (if (eq op (sym-times))
                ;; Multiply: no overflow promotion (for now)
                (progn
                  (emit-imul-rax-rdi)
                  (emit-shl-rax-1))
                ;; Add/Sub: with overflow -> bignum promotion
                (progn
                  (if (eq op (sym-plus))
                      (emit-add-rax-rdi)
                      (emit-sub-rax-rdi))
                  ;; Save untagged result, try to tag
                  (emit-push-rax)       ; save untagged result on stack
                  (emit-shl-rax-1)      ; tag result (sets OF if doesn't fit)
                  ;; jno .fits - skip overflow handler (normal path, predicted taken)
                  (let ((fits-patch (emit-jno-placeholder)))
                    ;; --- Overflow path: create 1-limb bignum ---
                    ;; Pop untagged result into RDI (64-bit value for limb)
                    (emit-pop-rdi)
                    ;; Save untagged value for later store
                    (code-emit #x57)  ; push rdi
                    ;; Allocate 1-limb bignum: set RAX = tagged 1
                    (emit-rex-w) (code-emit #xC7) (code-emit #xC0)  ; mov eax, 2 (tagged 1)
                    (code-emit #x02) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                    (emit-alloc-bignum)  ; RAX = tagged bignum pointer
                    ;; Pop untagged value -> RDI
                    (emit-pop-rdi)
                    ;; Store limb 0 at [rax - 3 + 8] = [rax + 5]
                    (emit-rex-w) (code-emit #x89) (code-emit #x78) (code-emit #x05)  ; mov [rax+5], rdi
                    ;; Jump past normal path cleanup
                    (let ((end-patch (emit-jmp-placeholder)))
                      ;; --- Normal path: discard saved untagged value ---
                      (patch-jump fits-patch (code-pos))
                      ;; add rsp, 8 (discard saved untagged value)
                      (emit-rex-w) (code-emit #x83) (code-emit #xC4) (code-emit #x08)
                      ;; --- End: RAX has tagged fixnum or bignum pointer ---
                      (patch-jump end-patch (code-pos)))))))))

    ;; Wrapper for backward compatibility
    (defun rt-compile-binop (op args)
      (rt-compile-binop-env op args () 0))

    ;; mov rdi, rax
    (defun emit-mov-reg-rax-to-rdi ()
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xC7))  ; ModRM: rax -> rdi

    ;; pop rax
    (defun emit-pop-rax ()
      (code-emit #x58))

    ;; imul rax, rdi (signed multiply)
    (defun emit-imul-rax-rdi ()
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xAF)
      (code-emit #xC7))  ; ModRM: rax *= rdi

    ;; cmp rax, 0 (check if nil - nil is 0 in our representation)
    (defun emit-cmp-rax-nil ()
      (emit-rex-w)
      (code-emit #x83)  ; cmp r/m64, imm8
      (code-emit #xF8)  ; ModRM: cmp rax
      (code-emit #x00)) ; immediate 0

    ;; je rel32 - jump equal (if zero/equal)
    ;; Returns the position of the rel32 bytes for patching
    (defun emit-je-placeholder ()
      (code-emit #x0F)
      (code-emit #x84)  ; je rel32
      (let ((rel32-pos (code-pos)))  ; position of rel32 bytes
        (code-emit-u32 0) ; placeholder - will be patched
        rel32-pos))

    ;; jno rel32 - jump if no overflow
    ;; Returns the position of the rel32 bytes for patching
    (defun emit-jno-placeholder ()
      (code-emit #x0F)
      (code-emit #x81)  ; jno rel32
      (let ((rel32-pos (code-pos)))  ; position of rel32 bytes
        (code-emit-u32 0) ; placeholder
        rel32-pos))

    ;; jmp rel32 - unconditional jump
    ;; Returns the position of the rel32 bytes for patching
    (defun emit-jmp-placeholder ()
      (code-emit #xE9)  ; jmp rel32
      (let ((rel32-pos (code-pos)))  ; position of rel32 bytes
        (code-emit-u32 0) ; placeholder
        rel32-pos))

    ;; Patch a relative jump - rel32-pos is position of the 4 rel32 bytes
    ;; rel32 is relative to the END of these 4 bytes (rel32-pos + 4)
    ;; NOTE: All position values are tagged (2x actual), so computed offset is 2x actual
    ;; Strategy: extract bytes at positions 0,8,16,24 from rel-double, then :u8 untags (>>1)
    ;; This effectively gives us bytes of (rel-double/2) which is the actual offset
    (defun patch-jump (rel32-pos target-pos)
      (let ((rel-double (- target-pos (+ rel32-pos 4))))
        ;; rel-double is tagged (= 2 * actual_offset).
        ;; :u8 setf untags via sar 1 then writes al (low byte only).
        ;; For byte 0: sar gives actual_offset, al = byte 0 of offset.
        ;; For byte N: (ash rel-double -8N) shifts tagged value, sar untags,
        ;;   al = byte N of offset. (Same approach as code-emit-u32.)
        (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                        #x08000000
                        #x500008)))
          (let ((addr (+ base rel32-pos)))
            (setf (mem-ref addr :u8) rel-double)
            (setf (mem-ref (+ addr 1) :u8) (ash rel-double -8))
            (setf (mem-ref (+ addr 2) :u8) (ash rel-double -16))
            (setf (mem-ref (+ addr 3) :u8) (ash rel-double -24))))))

    ;; Compile (if test then else) with environment
    (defun rt-compile-if-env (args env depth)
      ;; Safe access: avoid (car nil) crash on 2-arg if (no else clause)
      (let ((test-form (car args))
            (then-form (car (cdr args)))
            (rest2 (cdr (cdr args))))
        (let ((else-form (if rest2 (car rest2) ())))
          ;; Compile test
          (rt-compile-expr-env test-form env depth)
          ;; Compare to NIL
          (emit-cmp-rax-nil)
          ;; Jump to else if equal to nil
          (let ((else-patch (emit-je-placeholder)))
            ;; Compile then branch
            (rt-compile-expr-env then-form env depth)
            ;; Jump over else
            (let ((end-patch (emit-jmp-placeholder)))
              ;; Mark else branch position and patch the je
              (let ((else-pos (code-pos)))
                (patch-jump else-patch else-pos)
                ;; Compile else branch (or load nil if none)
                (if else-form
                    (rt-compile-expr-env else-form env depth)
                    (emit-mov-rax-imm64 0))  ; nil = 0
                ;; Mark end and patch the jmp
                (let ((end-pos (code-pos)))
                  (patch-jump end-patch end-pos))))))))

    ;; Wrapper for backward compatibility
    (defun rt-compile-if (args)
      (rt-compile-if-env args () 0))

    ;; Compile lambda and return code address
    (defun rt-compile-lambda (params body)
      (let ((start-addr (if (not (zerop (mem-ref #x4FF080 :u64)))
                            (+ #x100000 (code-pos))
                            (+ #x500008 (code-pos)))))
        (let ((nparams (list-len params)))
          ;; Save params to stack at function entry
          (emit-save-params nparams)
          (let ((env (build-param-env-stack params 0)))
            (rt-compile-expr-env body env nparams))
          ;; Clean up saved params
          (if (> nparams 0)
              (emit-add-rsp (* nparams 8))))
        (emit-ret)
        start-addr))

    ;; Compile (eq a b) with environment - returns t (non-zero) or nil (0)
    (defun rt-compile-eq-env (args env depth)
      ;; Compile first arg -> RAX, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile second arg with incremented depth
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-mov-reg-rax-to-rdi)
      ;; Pop first arg to RAX
      (emit-pop-rax)
      ;; cmp rax, rdi
      (emit-rex-w)
      (code-emit #x39)  ; cmp r/m64, r64
      (code-emit #xF8)  ; ModRM: cmp rax, rdi
      ;; sete al - set AL to 1 if equal
      (code-emit #x0F)
      (code-emit #x94)
      (code-emit #xC0)  ; sete al
      ;; movzx rax, al - zero extend
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)  ; movzx rax, al
      ;; Tag as fixnum (0 or 2 - but we want nil=0 or t=non-zero)
      ;; Actually just return 0 or 1 as tagged fixnum
      (emit-shl-rax-1))

    ;; Wrapper for backward compatibility
    (defun rt-compile-eq (args)
      (rt-compile-eq-env args () 0))

    ;; ================================================================
    ;; List Primitives: car, cdr, cons, null
    ;; ================================================================
    ;; Cons cell tag is 1 (low bit). Layout: [car:8][cdr:8]

    ;; Compile (car x) - load car from cons cell
    (defun rt-compile-car (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; RAX has tagged cons pointer, clear low bit and load
      ;; lea rax, [rax-1]  ; clear tag
      (emit-rex-w)
      (code-emit #x8D)  ; lea
      (code-emit #x40)  ; [rax + disp8]
      (code-emit #xFF)  ; -1 (255 as unsigned = -1 as signed byte)
      ;; mov rax, [rax]
      (emit-rex-w)
      (code-emit #x8B)  ; mov r64, r/m64
      (code-emit #x00)) ; ModRM: [rax]

    ;; Compile (cdr x) - load cdr from cons cell
    (defun rt-compile-cdr (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; RAX has tagged cons pointer
      ;; Load from [rax-1+8] = [rax+7]
      (emit-rex-w)
      (code-emit #x8B)  ; mov r64, r/m64
      (code-emit #x40)  ; [rax + disp8]
      (code-emit #x07)) ; +7 = -1 (clear tag) + 8 (cdr offset)

    ;; Write barrier DISABLED for per-actor GC (full collection, no generational)
    ;; Previously marked card table dirty; no longer needed
    (defun emit-write-barrier ()
      ;; No-op: per-actor GC does full collection, card table not used
      )

    ;; Compile (rplaca cons new-car) - mutate car, with write barrier
    ;; Returns the cons cell
    (defun rt-compile-rplaca (args env depth)
      ;; Compile cons cell -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile new value -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Pop cons -> RDX (tagged)
      (code-emit #x5A)  ; pop rdx
      ;; Save new value
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax
      ;; Clear tag: lea rdx, [rdx - 1]
      (emit-rex-w) (code-emit #x8D) (code-emit #x52) (code-emit #xFF)
      ;; Store new car: mov [rdx], rcx
      (emit-rex-w) (code-emit #x89) (code-emit #x0A)
      ;; Write barrier
      (emit-write-barrier)
      ;; Return cons cell: lea rax, [rdx + 1]
      (emit-rex-w) (code-emit #x8D) (code-emit #x42) (code-emit #x01))

    ;; Compile (rplacd cons new-cdr) - mutate cdr, with write barrier
    ;; Returns the cons cell
    (defun rt-compile-rplacd (args env depth)
      ;; Compile cons cell -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile new value -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Pop cons -> RDX (tagged)
      (code-emit #x5A)  ; pop rdx
      ;; Save new value
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax
      ;; Clear tag: lea rdx, [rdx - 1]
      (emit-rex-w) (code-emit #x8D) (code-emit #x52) (code-emit #xFF)
      ;; Store new cdr: mov [rdx + 8], rcx
      (emit-rex-w) (code-emit #x89) (code-emit #x4A) (code-emit #x08)
      ;; Write barrier
      (emit-write-barrier)
      ;; Return cons cell: lea rax, [rdx + 1]
      (emit-rex-w) (code-emit #x8D) (code-emit #x42) (code-emit #x01))

    ;; ================================================================
    ;; Bignum Allocation and Access
    ;; ================================================================
    ;; Object heap uses separate alloc ptr at 0x03F00040
    ;; Object header: [subtag:8][flags:8][limb-count:48]
    ;; Subtag 0x30 = bignum
    ;; Pointer tag: low 2 bits = 0b11

    ;; Emit code to allocate a bignum with N limbs (N in RAX, tagged fixnum)
    ;; Returns tagged object pointer in RAX
    (defun emit-alloc-bignum ()
      ;; RAX = number of limbs (tagged fixnum, shift right 1 to untag)
      (emit-sar-rax-1)  ; untag limb count
      ;; Save limb count in RCX
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax
      ;; Load object alloc ptr from GS:[0x28] -> RDX (per-CPU)
      (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x14) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Check space: compute needed = 8 + 8*n, round up to 16-byte alignment
      ;; RBX = 8 + 8*n = 8*(1+n)
      (emit-rex-w) (code-emit #x8D) (code-emit #x44) (code-emit #xC8) (code-emit #x08)
      ;; ^ lea rax, [rax*8 + 8] - but that uses rax as index... let me use different encoding
      ;; Actually: compute size = (1 + limb_count) * 8, rounded to 16
      ;; lea rbx, [rcx + 1]  ; rbx = n + 1
      (emit-rex-w) (code-emit #x8D) (code-emit #x59) (code-emit #x01)
      ;; shl rbx, 3  ; rbx = (n+1)*8 = total bytes
      (emit-rex-w) (code-emit #xC1) (code-emit #xE3) (code-emit #x03)
      ;; Round up to 16: add rbx, 15; and rbx, ~15
      (emit-rex-w) (code-emit #x83) (code-emit #xC3) (code-emit #x0F)  ; add rbx, 15
      (emit-rex-w) (code-emit #x83) (code-emit #xE3) (code-emit #xF0)  ; and rbx, -16
      ;; Check limit: rdx + rbx vs object limit at GS:[0x30] (per-CPU)
      (emit-rex-w) (code-emit #x89) (code-emit #xD0)  ; mov rax, rdx (save alloc ptr)
      (emit-rex-w) (code-emit #x01) (code-emit #xDA)  ; add rdx, rbx (new alloc end)
      ;; cmp rdx, GS:[0x30] (per-CPU object limit)
      (code-emit #x65) (emit-rex-w) (code-emit #x3B) (code-emit #x14) (code-emit #x25)
      (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x0F) (code-emit #x82)  ; jb ok (rel32 - GC code is >127 bytes)
      (let ((ok-jmp (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; OOM: save limb count, run GC, restore, retry once
        (code-emit #x51)  ; push rcx (save untagged limb count)
        (emit-per-actor-gc)
        (code-emit #x59)  ; pop rcx (restore limb count)
        ;; Retry: reload alloc ptr (GC updated it) and recompute size
        ;; mov rdx, GS:[0x28] (per-CPU obj-alloc)
        (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x14) (code-emit #x25)
        (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; lea rbx, [rcx + 1]
        (emit-rex-w) (code-emit #x8D) (code-emit #x59) (code-emit #x01)
        ;; shl rbx, 3
        (emit-rex-w) (code-emit #xC1) (code-emit #xE3) (code-emit #x03)
        ;; add rbx, 15
        (emit-rex-w) (code-emit #x83) (code-emit #xC3) (code-emit #x0F)
        ;; and rbx, -16
        (emit-rex-w) (code-emit #x83) (code-emit #xE3) (code-emit #xF0)
        ;; mov rax, rdx
        (emit-rex-w) (code-emit #x89) (code-emit #xD0)
        ;; add rdx, rbx
        (emit-rex-w) (code-emit #x01) (code-emit #xDA)
        ;; cmp rdx, GS:[0x30] (per-CPU obj-limit)
        (code-emit #x65) (emit-rex-w) (code-emit #x3B) (code-emit #x14) (code-emit #x25)
        (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        (code-emit #x72)  ; jb ok2 (rel8 - only skips OOM halt)
        (let ((ok2-pos (code-pos)))
          (code-emit #x00)
          ;; Real OOM after GC
          (emit-gc-print-char #x4F) (emit-gc-print-char #x4F) (emit-gc-print-char #x42)  ; "OOB"
          (code-emit #xF4)  ; hlt
          (patch-rel8 ok2-pos (code-pos)))
        (patch-rel32 ok-jmp (code-pos)))
      ;; rax = alloc ptr (object address), rdx = new end
      ;; Store new alloc ptr to GS:[0x28] (per-CPU)
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x14) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Write header: [subtag=0x30][flags=0][limb-count=rcx]
      ;; header = rcx << 16 | 0x30
      (code-emit #x53)  ; push rbx (save size)
      (emit-rex-w) (code-emit #x89) (code-emit #xCB)  ; mov rbx, rcx
      (emit-rex-w) (code-emit #xC1) (code-emit #xE3) (code-emit #x10)  ; shl rbx, 16
      (emit-rex-w) (code-emit #x83) (code-emit #xCB) (code-emit #x30)  ; or rbx, 0x30
      (emit-rex-w) (code-emit #x89) (code-emit #x18)  ; mov [rax], rbx (store header)
      (code-emit #x5B)  ; pop rbx
      ;; Tag pointer: rax | 3
      (emit-rex-w) (code-emit #x83) (code-emit #xC8) (code-emit #x03)  ; or rax, 3
      )

    ;; Compile (make-bignum n-limbs value) - create bignum with 1 limb
    ;; Args: n-limbs = number of limbs, value = value for limb 0
    (defun rt-compile-make-bignum (args env depth)
      ;; Compile n-limbs -> RAX
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile value -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-push-rax)  ; save value
      ;; Get n-limbs back
      (emit-rex-w) (code-emit #x8B) (code-emit #x44) (code-emit #x24) (code-emit #x08)
      ;; ^ mov rax, [rsp+8]
      ;; Allocate bignum
      (emit-alloc-bignum)
      ;; RAX = tagged bignum pointer
      ;; Pop value -> RCX
      (code-emit #x59)  ; pop rcx (value, tagged)
      (emit-rex-w) (code-emit #xD1) (code-emit #xF9)  ; sar rcx, 1 (untag value)
      ;; Store value at limb 0: [rax - 3 + 8] = [rax + 5]
      (emit-rex-w) (code-emit #x89) (code-emit #x48) (code-emit #x05)  ; mov [rax+5], rcx
      ;; Clean up n-limbs from stack
      (emit-rex-w) (code-emit #x83) (code-emit #xC4) (code-emit #x08)  ; add rsp, 8
      )

    ;; Compile (bignum-ref bign index) - read limb (returns tagged fixnum)
    (defun rt-compile-bignum-ref (args env depth)
      ;; Compile bignum -> RAX, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile index -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; RAX = index (tagged), untag
      (emit-sar-rax-1)
      ;; RDI = RAX (index)
      (emit-rex-w) (code-emit #x89) (code-emit #xC7)  ; mov rdi, rax
      ;; Pop bignum -> RAX
      (emit-pop-rax)
      ;; Clear tag: rax = rax & ~3 = rax - 3 (since tag is 3)
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4 (~3)
      ;; Load limb: rax = [rax + 8 + rdi*8]
      (emit-rex-w) (code-emit #x8B) (code-emit #x44) (code-emit #xF8) (code-emit #x08)
      ;; ^ mov rax, [rax + rdi*8 + 8]
      ;; Tag result as fixnum (shl 1) - NOTE: only works for values < 2^62
      (emit-shl-rax-1))

    ;; Compile (bignum-set bign index value) - write limb
    (defun rt-compile-bignum-set (args env depth)
      ;; Compile bignum -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile index -> push
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-push-rax)
      ;; Compile value -> RAX
      (rt-compile-expr-env (car (cdr (cdr args))) env (+ depth 2))
      ;; Untag value
      (emit-sar-rax-1)
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (value)
      ;; Pop index -> RDI
      (code-emit #x5F)  ; pop rdi
      (emit-rex-w) (code-emit #xD1) (code-emit #xFF)  ; sar rdi, 1 (untag index)
      ;; Pop bignum -> RAX
      (emit-pop-rax)
      ;; Clear tag
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
      ;; Store: [rax + 8 + rdi*8] = rcx
      (emit-rex-w) (code-emit #x89) (code-emit #x4C) (code-emit #xF8) (code-emit #x08)
      ;; ^ mov [rax + rdi*8 + 8], rcx
      ;; Return value (re-tag)
      (emit-rex-w) (code-emit #x89) (code-emit #xC8)  ; mov rax, rcx
      (emit-shl-rax-1))

    ;; Compile (bignump x) - check if x is a bignum (tag=11, subtag=0x30)
    (defun rt-compile-bignump (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Check low 2 bits = 0b11
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (save)
      (code-emit #x24) (code-emit #x03)  ; and al, 3
      (code-emit #x3C) (code-emit #x03)  ; cmp al, 3
      (code-emit #x0F) (code-emit #x85)  ; jne not_bignum (rel32)
      (let ((not-bn (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; Tag matches, check subtag
        ;; Load header: [rcx & ~3]
        (emit-rex-w) (code-emit #x83) (code-emit #xE1) (code-emit #xFC)  ; and rcx, -4
        (emit-rex-w) (code-emit #x8B) (code-emit #x01)  ; mov rax, [rcx]
        ;; Check low byte of header = 0x30
        (code-emit #x3C) (code-emit #x30)  ; cmp al, 0x30
        (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al
        (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)  ; movzx rax, al
        (emit-shl-rax-1)
        (code-emit #xEB)  ; jmp done
        (let ((done-jmp (code-pos)))
          (code-emit #x00)
          ;; not_bignum:
          (patch-rel32 not-bn (code-pos))
          (emit-mov-rax-imm64 0)  ; return 0 (nil/false)
          ;; done:
          (patch-rel8 done-jmp (code-pos)))))

    ;; Compile (integerp x) - true if fixnum OR bignum
    (defun rt-compile-integerp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Check: fixnum (low bit 0, non-nil) OR bignum (low 2 bits = 11)
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (save)
      ;; First check fixnum: low bit 0 AND nonzero
      (code-emit #xA8) (code-emit #x01)  ; test al, 1
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al (1 if even = possible fixnum)
      ;; But exclude nil (0): test rcx, rcx
      (emit-rex-w) (code-emit #x85) (code-emit #xC9)  ; test rcx, rcx
      (code-emit #x0F) (code-emit #x95) (code-emit #xC2)  ; setnz dl (1 if nonzero)
      (code-emit #x20) (code-emit #xD0)  ; and al, dl (fixnum = even AND nonzero)
      ;; Now check bignum: (rcx & 3) == 3
      (emit-rex-w) (code-emit #x89) (code-emit #xCA)  ; mov rdx, rcx
      (code-emit #x80) (code-emit #xE2) (code-emit #x03)  ; and dl, 3
      (code-emit #x80) (code-emit #xFA) (code-emit #x03)  ; cmp dl, 3
      (code-emit #x0F) (code-emit #x94) (code-emit #xC2)  ; sete dl
      ;; Result = fixnum OR bignum
      (code-emit #x08) (code-emit #xD0)  ; or al, dl
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)  ; movzx rax, al
      (emit-shl-rax-1))

    ;; Compile (stringp x) - true if x has object tag and subtag 0x31
    (defun rt-compile-stringp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Check low 2 bits = 0b11
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (save)
      (code-emit #x24) (code-emit #x03)  ; and al, 3
      (code-emit #x3C) (code-emit #x03)  ; cmp al, 3
      (code-emit #x0F) (code-emit #x85)  ; jne not_string (rel32)
      (let ((not-str (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; Tag matches, check subtag
        (emit-rex-w) (code-emit #x83) (code-emit #xE1) (code-emit #xFC)  ; and rcx, -4
        (emit-rex-w) (code-emit #x8B) (code-emit #x01)  ; mov rax, [rcx]
        ;; Check low byte of header = 0x31
        (code-emit #x3C) (code-emit #x31)  ; cmp al, 0x31
        (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al
        (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)  ; movzx rax, al
        (emit-shl-rax-1)
        (code-emit #xEB)  ; jmp done
        (let ((done-jmp (code-pos)))
          (code-emit #x00)
          ;; not_string:
          (patch-rel32 not-str (code-pos))
          (emit-mov-rax-imm64 0)  ; return 0 (nil/false)
          ;; done:
          (patch-rel8 done-jmp (code-pos)))))

    ;; ================================================================
    ;; Bignum Arithmetic
    ;; ================================================================

    ;; Helper: read bignum limb count from tagged pointer in RAX
    ;; Result in RAX (untagged), clobbers RDX
    ;; Assumes RAX is a tagged bignum (tag 11)
    (defun emit-bignum-count ()
      ;; rax & ~3 -> raw address
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
      ;; load header
      (emit-rex-w) (code-emit #x8B) (code-emit #x00)  ; mov rax, [rax]
      ;; shr rax, 16
      (emit-rex-w) (code-emit #xC1) (code-emit #xE8) (code-emit #x10))

    ;; Compile (bignum-add a b) - add two bignums, return new bignum
    ;; Simple implementation: assumes both are same-size bignums
    ;; Uses ADC for carry propagation
    (defun rt-compile-bignum-add (args env depth)
      ;; Compile a -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile b -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Save b
      (emit-push-rax)
      ;; Get limb count from a (on stack at [rsp+8])
      (emit-rex-w) (code-emit #x8B) (code-emit #x44) (code-emit #x24) (code-emit #x08)
      ;; ^ mov rax, [rsp+8]
      (emit-bignum-count)
      ;; rax = limb count, save in rdi
      (emit-rex-w) (code-emit #x89) (code-emit #xC7)  ; mov rdi, rax
      ;; Allocate result bignum: need rdi+1 limbs (for possible carry)
      (emit-rex-w) (code-emit #x8D) (code-emit #x47) (code-emit #x01)  ; lea rax, [rdi+1]
      (emit-shl-rax-1)  ; tag as fixnum for alloc
      (emit-push-rax)  ; save extra-limb count
      (emit-alloc-bignum)  ; rax = tagged result bignum
      ;; Save result
      (emit-rex-w) (code-emit #x89) (code-emit #xC3)  ; mov rbx, rax (result bignum)
      ;; Pop extra count, b, a
      (emit-rex-w) (code-emit #x83) (code-emit #xC4) (code-emit #x08)  ; add rsp, 8 (discard saved count)
      (code-emit #x59)  ; pop rcx = b (tagged)
      (code-emit #x5E)  ; pop rsi = a (tagged, now in rsi)
      ;; Untag all: clear low 2 bits
      (emit-rex-w) (code-emit #x83) (code-emit #xE6) (code-emit #xFC)  ; and rsi, -4 (a raw)
      (emit-rex-w) (code-emit #x83) (code-emit #xE1) (code-emit #xFC)  ; and rcx, -4 (b raw)
      (emit-rex-w) (code-emit #x89) (code-emit #xD8)  ; mov rax, rbx
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4 (result raw)
      ;; rsi = a raw, rcx = b raw, rax = result raw, rdi = limb count
      ;; Clear carry flag
      (code-emit #xF8)  ; clc
      ;; Loop: add limbs with carry
      (emit-rex-w) (code-emit #x89) (code-emit #xFA)  ; mov rdx, rdi (counter)
      (let ((add-loop (code-pos)))
        ;; Load a limb: r10 = [rsi + 8] (skip header, advance below)
        (code-emit #x4C) (code-emit #x8B) (code-emit #x56) (code-emit #x08)  ; mov r10, [rsi+8]
        ;; ADC with b limb: r10 += [rcx + 8] + CF
        (code-emit #x4C) (code-emit #x13) (code-emit #x51) (code-emit #x08)  ; adc r10, [rcx+8]
        ;; Store to result: [rax + 8] = r10
        (code-emit #x4C) (code-emit #x89) (code-emit #x50) (code-emit #x08)  ; mov [rax+8], r10
        ;; Advance pointers
        (emit-rex-w) (code-emit #x83) (code-emit #xC6) (code-emit #x08)  ; add rsi, 8
        (emit-rex-w) (code-emit #x83) (code-emit #xC1) (code-emit #x08)  ; add rcx, 8
        (emit-rex-w) (code-emit #x83) (code-emit #xC0) (code-emit #x08)  ; add rax, 8
        ;; dec rdx (doesn't affect CF!)
        (emit-rex-w) (code-emit #xFF) (code-emit #xCA)  ; dec rdx
        ;; Use lea to test zero without affecting flags, then conditional jump
        ;; Actually dec DOES set ZF. But it preserves CF. So jnz is safe.
        (code-emit #x75)  ; jnz add-loop (rel8)
        (code-emit (logand (- add-loop (code-pos) 1) #xFF)))
      ;; After loop, check carry flag
      ;; If CF=1, store 1 in extra limb
      (code-emit #x0F) (code-emit #x82)  ; jc has_carry (rel32)
      (let ((carry-jmp (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; No carry - fix up the limb count in header (was n+1, should be n)
        ;; Result raw address = rbx & ~3
        (emit-rex-w) (code-emit #x89) (code-emit #xD8)  ; mov rax, rbx
        (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
        ;; Load header, subtract 1 from count field (count is bits 16+)
        (emit-rex-w) (code-emit #x8B) (code-emit #x10)  ; mov rdx, [rax]
        (emit-rex-w) (code-emit #x81) (code-emit #xEA)  ; sub rdx, 0x10000 (1 << 16)
        (code-emit #x00) (code-emit #x00) (code-emit #x01) (code-emit #x00)
        (emit-rex-w) (code-emit #x89) (code-emit #x10)  ; mov [rax], rdx
        (code-emit #xEB)  ; jmp done (rel8)
        (let ((done-jmp (code-pos)))
          (code-emit #x00)
          ;; has_carry: store 1 in extra limb (already at [rax+8] position)
          (patch-rel32 carry-jmp (code-pos))
          (emit-rex-w) (code-emit #xC7) (code-emit #x40) (code-emit #x08)  ; mov dword [rax+8], 1
          (code-emit #x01) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          ;; Also zero upper 32 bits: mov dword [rax+12], 0
          (code-emit #xC7) (code-emit #x40) (code-emit #x0C)
          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          ;; done:
          (patch-rel8 done-jmp (code-pos))))
      ;; Return result (rbx is still tagged)
      (emit-rex-w) (code-emit #x89) (code-emit #xD8))  ; mov rax, rbx

    ;; Compile (bignum-sub a b) - subtract two bignums, return new bignum
    ;; Assumes a >= b (unsigned), same number of limbs
    (defun rt-compile-bignum-sub (args env depth)
      ;; Compile a -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile b -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-push-rax)
      ;; Get limb count from a
      (emit-rex-w) (code-emit #x8B) (code-emit #x44) (code-emit #x24) (code-emit #x08)
      (emit-bignum-count)
      (emit-rex-w) (code-emit #x89) (code-emit #xC7)  ; mov rdi, rax (count)
      ;; Allocate result with same count
      (emit-shl-rax-1)
      (emit-alloc-bignum)
      (emit-rex-w) (code-emit #x89) (code-emit #xC3)  ; mov rbx, rax (result)
      (code-emit #x59)  ; pop rcx = b
      (code-emit #x5E)  ; pop rsi = a
      ;; Untag
      (emit-rex-w) (code-emit #x83) (code-emit #xE6) (code-emit #xFC)
      (emit-rex-w) (code-emit #x83) (code-emit #xE1) (code-emit #xFC)
      (emit-rex-w) (code-emit #x89) (code-emit #xD8)
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)
      ;; Clear carry
      (code-emit #xF8)
      (emit-rex-w) (code-emit #x89) (code-emit #xFA)  ; mov rdx, rdi
      (let ((sub-loop (code-pos)))
        (code-emit #x4C) (code-emit #x8B) (code-emit #x56) (code-emit #x08)  ; mov r10, [rsi+8]
        (code-emit #x4C) (code-emit #x1B) (code-emit #x51) (code-emit #x08)  ; sbb r10, [rcx+8]
        (code-emit #x4C) (code-emit #x89) (code-emit #x50) (code-emit #x08)  ; mov [rax+8], r10
        (emit-rex-w) (code-emit #x83) (code-emit #xC6) (code-emit #x08)
        (emit-rex-w) (code-emit #x83) (code-emit #xC1) (code-emit #x08)
        (emit-rex-w) (code-emit #x83) (code-emit #xC0) (code-emit #x08)
        (emit-rex-w) (code-emit #xFF) (code-emit #xCA)  ; dec rdx
        (code-emit #x75) (code-emit (logand (- sub-loop (code-pos) 1) #xFF)))
      (emit-rex-w) (code-emit #x89) (code-emit #xD8))  ; mov rax, rbx

    ;; Compile (bignum-mul a b) - schoolbook multiply
    ;; Uses scratch memory at 0x300020-0x300048 for state
    ;; Result has a.count + b.count limbs
    (defun rt-compile-bignum-mul (args env depth)
      ;; Compile a -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile b -> push
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-push-rax)
      ;; Get a_count from a (at [rsp+8])
      (emit-rex-w) (code-emit #x8B) (code-emit #x44) (code-emit #x24) (code-emit #x08) ; mov rax,[rsp+8]
      (emit-bignum-count)
      (emit-rex-w) (code-emit #x89) (code-emit #xC7)  ; mov rdi, rax (a_count)
      ;; Get b_count from b (at [rsp])
      (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x24)  ; mov rax, [rsp]
      (emit-bignum-count)
      (emit-rex-w) (code-emit #x89) (code-emit #xC6)  ; mov rsi, rax (b_count)
      ;; Allocate result: rdi + rsi limbs
      (emit-rex-w) (code-emit #x8D) (code-emit #x04) (code-emit #x37)  ; lea rax, [rdi+rsi]
      (emit-shl-rax-1)  ; tag for alloc
      (emit-alloc-bignum)
      (emit-rex-w) (code-emit #x89) (code-emit #xC3)  ; mov rbx, rax (save result, tagged)
      ;; Pop b, a from stack and untag
      (code-emit #x59)  ; pop rcx = b (tagged)
      (code-emit #x5E)  ; pop rsi = a (tagged)... wait, we pushed a first then b
      ;; Stack was: push a, push b. So pop b first (rcx), then pop a (rsi)
      ;; Actually pop order: [rsp] = b, [rsp+8] = a. pop rcx=b, pop rsi=a. ✓
      (emit-rex-w) (code-emit #x83) (code-emit #xE6) (code-emit #xFC)  ; and rsi, -4 (a raw)
      (emit-rex-w) (code-emit #x83) (code-emit #xE1) (code-emit #xFC)  ; and rcx, -4 (b raw)
      (emit-rex-w) (code-emit #x89) (code-emit #xD8)  ; mov rax, rbx
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4 (result raw)
      ;; Store to scratch: [0x300020]=a_raw, [0x300028]=b_raw, [0x300030]=result_raw
      ;; [0x300038]=a_count, [0x300040]=b_count
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)
      (code-emit #x20) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x89) (code-emit #x0C) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x89) (code-emit #x04) (code-emit #x25)
      (code-emit #x30) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      ;; Get counts from bignums again since rdi/rsi were clobbered
      (emit-rex-w) (code-emit #x8B) (code-emit #x36)  ; mov rsi, [rsi] (a header, rsi=a_raw)
      ;; Wait, rsi was set to a_raw above. Let me reload.
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x300020]
      (code-emit #x20) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x8B) (code-emit #x36)  ; mov rsi, [rsi] (a header)
      (emit-rex-w) (code-emit #xC1) (code-emit #xEE) (code-emit #x10)  ; shr rsi, 16
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)
      (code-emit #x38) (code-emit #x00) (code-emit #x30) (code-emit #x00)  ; a_count
      (emit-rex-w) (code-emit #x8B) (code-emit #x0C) (code-emit #x25)  ; mov rcx, [0x300028]
      (code-emit #x28) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x8B) (code-emit #x09)  ; mov rcx, [rcx] (b header)
      (emit-rex-w) (code-emit #xC1) (code-emit #xE9) (code-emit #x10)  ; shr rcx, 16
      (emit-rex-w) (code-emit #x89) (code-emit #x0C) (code-emit #x25)
      (code-emit #x40) (code-emit #x00) (code-emit #x30) (code-emit #x00)  ; b_count
      ;; Zero all result limbs
      ;; rax = result_raw (still from above)
      (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)  ; mov rax, [0x300030]
      (code-emit #x30) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x8D) (code-emit #x0C) (code-emit #x37)  ; lea rcx, [rdi+rsi] ... wait
      ;; rdi and rsi were clobbered. Load counts from memory.
      (emit-rex-w) (code-emit #x8B) (code-emit #x3C) (code-emit #x25)  ; mov rdi, [0x300038]
      (code-emit #x38) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x300040]
      (code-emit #x40) (code-emit #x00) (code-emit #x30) (code-emit #x00)
      (emit-rex-w) (code-emit #x8D) (code-emit #x0C) (code-emit #x37)  ; lea rcx, [rdi+rsi]
      (let ((zloop (code-pos)))
        ;; Zero limb: mov qword [rax + rcx*8], 0
        ;; We zero from index count down to 1 (limbs are at +8, +16, etc)
        (emit-rex-w) (code-emit #xC7) (code-emit #x44) (code-emit #xC8) (code-emit #x00)
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        (code-emit #xC7) (code-emit #x44) (code-emit #xC8) (code-emit #x04)
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        (emit-rex-w) (code-emit #xFF) (code-emit #xC9)  ; dec rcx
        (code-emit #x75) (code-emit (logand (- zloop (code-pos) 1) #xFF)))

      ;; Schoolbook multiply: for each i, for each j:
      ;;   (hi:lo) = a[i]*b[j] + result[i+j] + carry
      ;;   result[i+j] = lo, carry = hi
      ;; After inner loop: result[i+b_count] += carry

      ;; Outer loop: rdi = i
      (emit-rex-w) (code-emit #x31) (code-emit #xFF)  ; xor edi, edi -> xor rdi, rdi...
      ;; Actually xor edi, edi = 31 FF (2 bytes, zero-extends)
      (let ((outer-loop (code-pos)))
        ;; Precompute a[i] and save to [0x300048]
        (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)  ; mov rax, [0x300020]
        (code-emit #x20) (code-emit #x00) (code-emit #x30) (code-emit #x00)
        (emit-rex-w) (code-emit #x8D) (code-emit #x44) (code-emit #xF8) (code-emit #x08) ; lea rax,[rax+rdi*8+8]
        (emit-rex-w) (code-emit #x8B) (code-emit #x00)  ; mov rax, [rax]
        (emit-rex-w) (code-emit #x89) (code-emit #x04) (code-emit #x25)  ; mov [0x300048], rax
        (code-emit #x48) (code-emit #x00) (code-emit #x30) (code-emit #x00)
        ;; Clear carry (r10) and j (rsi)
        (code-emit #x45) (code-emit #x31) (code-emit #xD2)  ; xor r10d, r10d
        (code-emit #x31) (code-emit #xF6)  ; xor esi, esi

        ;; Inner loop
        (let ((inner-loop (code-pos)))
          ;; Load a[i] from scratch
          (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
          (code-emit #x48) (code-emit #x00) (code-emit #x30) (code-emit #x00)
          ;; Load b[j]
          (code-emit #x4C) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)  ; mov r11, [0x300028]
          (code-emit #x28) (code-emit #x00) (code-emit #x30) (code-emit #x00)
          (code-emit #x4D) (code-emit #x8D) (code-emit #x5C) (code-emit #xF3) (code-emit #x08) ; lea r11,[r11+rsi*8+8]
          (code-emit #x4D) (code-emit #x8B) (code-emit #x1B)  ; mov r11, [r11]
          ;; mul r11: rdx:rax = rax * r11
          (code-emit #x49) (code-emit #xF7) (code-emit #xE3)  ; mul r11
          ;; Add carry from previous
          (code-emit #x49) (code-emit #x03) (code-emit #xC2)  ; add rax, r10
          (emit-rex-w) (code-emit #x83) (code-emit #xD2) (code-emit #x00)  ; adc rdx, 0
          ;; Add result[i+j]
          (code-emit #x4C) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)  ; mov r11, [0x300030]
          (code-emit #x30) (code-emit #x00) (code-emit #x30) (code-emit #x00)
          (emit-rex-w) (code-emit #x8D) (code-emit #x0C) (code-emit #x37)  ; lea rcx, [rdi+rsi]
          (code-emit #x4D) (code-emit #x8D) (code-emit #x5C) (code-emit #xCB) (code-emit #x08) ; lea r11,[r11+rcx*8+8]
          (code-emit #x49) (code-emit #x03) (code-emit #x03)  ; add rax, [r11]
          (emit-rex-w) (code-emit #x83) (code-emit #xD2) (code-emit #x00)  ; adc rdx, 0
          ;; Store low to result[k]
          (code-emit #x49) (code-emit #x89) (code-emit #x03)  ; mov [r11], rax
          ;; carry = high
          (code-emit #x4C) (code-emit #x8B) (code-emit #xD2)  ; mov r10, rdx
          ;; Next j
          (emit-rex-w) (code-emit #xFF) (code-emit #xC6)  ; inc rsi
          (emit-rex-w) (code-emit #x3B) (code-emit #x34) (code-emit #x25)  ; cmp rsi, [0x300040]
          (code-emit #x40) (code-emit #x00) (code-emit #x30) (code-emit #x00)
          (code-emit #x72)  ; jb inner-loop (rel8)
          (code-emit (logand (- inner-loop (code-pos) 1) #xFF)))

        ;; After inner loop: store carry to result[i + b_count]
        ;; rsi == b_count at this point
        (code-emit #x4C) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)  ; mov r11, [0x300030]
        (code-emit #x30) (code-emit #x00) (code-emit #x30) (code-emit #x00)
        (emit-rex-w) (code-emit #x8D) (code-emit #x0C) (code-emit #x37)  ; lea rcx, [rdi+rsi]
        (code-emit #x4D) (code-emit #x8D) (code-emit #x5C) (code-emit #xCB) (code-emit #x08)
        (code-emit #x4D) (code-emit #x01) (code-emit #x13)  ; add [r11], r10
        ;; Next i
        (emit-rex-w) (code-emit #xFF) (code-emit #xC7)  ; inc rdi
        (emit-rex-w) (code-emit #x3B) (code-emit #x3C) (code-emit #x25)  ; cmp rdi, [0x300038]
        (code-emit #x38) (code-emit #x00) (code-emit #x30) (code-emit #x00)
        (code-emit #x0F) (code-emit #x82)  ; jb outer-loop (rel32)
        (emit-rel32 outer-loop (+ (code-pos) 4)))
      ;; Return result (rbx is still tagged)
      (emit-rex-w) (code-emit #x89) (code-emit #xD8))  ; mov rax, rbx

    ;; Compile (truncate a b) - integer division, quotient in RAX
    (defun rt-compile-truncate (args env depth)
      (rt-compile-expr-env (car args) env depth)        ; dividend -> RAX
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))  ; divisor -> RAX
      (emit-sar-rax-1)                                   ; untag divisor
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)    ; mov rcx, rax
      (emit-pop-rax)
      (emit-sar-rax-1)                                   ; untag dividend
      (emit-rex-w) (code-emit #x99)                      ; cqo (sign-extend)
      (emit-rex-w) (code-emit #xF7) (code-emit #xF9)    ; idiv rcx
      (emit-shl-rax-1))                                  ; re-tag quotient

    ;; Compile (mod a b) - integer division, remainder
    (defun rt-compile-mod (args env depth)
      (rt-compile-expr-env (car args) env depth)        ; dividend -> RAX
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))  ; divisor -> RAX
      (emit-sar-rax-1)                                   ; untag divisor
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)    ; mov rcx, rax
      (emit-pop-rax)
      (emit-sar-rax-1)                                   ; untag dividend
      (emit-rex-w) (code-emit #x99)                      ; cqo (sign-extend)
      (emit-rex-w) (code-emit #xF7) (code-emit #xF9)    ; idiv rcx
      (emit-rex-w) (code-emit #x89) (code-emit #xD0)    ; mov rax, rdx (remainder)
      (emit-shl-rax-1))                                  ; re-tag remainder

    ;; Emit: wait for serial TX ready then write byte in CL to serial port
    ;; Clobbers RAX, RDX (preserves RDI, R11, RCX upper bits)
    (defun emit-serial-write-cl ()
      ;; mov edx, 0x3FD
      (code-emit #xBA) (code-emit #xFD) (code-emit #x03) (code-emit #x00) (code-emit #x00)
      ;; .wait: in al, dx
      (code-emit #xEC)
      ;; test al, 0x20
      (code-emit #xA8) (code-emit #x20)
      ;; jz -5 (back to 'in al, dx': IP after jz = +10, target = +5, rel = -5)
      (code-emit #x74) (code-emit #xFB)
      ;; mov al, cl
      (code-emit #x88) (code-emit #xC8)
      ;; mov edx, 0x3F8
      (code-emit #xBA) (code-emit #xF8) (code-emit #x03) (code-emit #x00) (code-emit #x00)
      ;; out dx, al
      (code-emit #xEE))

    ;; Compile (print-bignum bg) - print bignum value
    ;; For 1-limb bignums: prints decimal using div loop
    ;; For multi-limb: prints #B<hex>
    ;; Returns nil
    (defun rt-compile-print-bignum (args env depth)
      ;; Compile arg -> RAX (tagged bignum pointer)
      (rt-compile-expr-env (car args) env depth)
      ;; Strip tag bits: and rax, -4
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
      ;; Save raw address on stack
      (emit-push-rax)
      ;; Read header to get limb count
      (emit-rex-w) (code-emit #x8B) (code-emit #x08)  ; mov rcx, [rax]
      ;; shr rcx, 16 to get limb count
      (emit-rex-w) (code-emit #xC1) (code-emit #xE9) (code-emit #x10)  ; shr rcx, 16
      ;; Check if limb count == 1
      (emit-rex-w) (code-emit #x83) (code-emit #xF9) (code-emit #x01)  ; cmp rcx, 1
      (code-emit #x0F) (code-emit #x85)  ; jne hex_path (rel32)
      (let ((hex-jmp (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)

        ;; === Decimal path: 1-limb bignum ===
        ;; Load limb 0 (64-bit raw value)
        (emit-rex-w) (code-emit #x8B) (code-emit #x40) (code-emit #x08)  ; mov rax, [rax+8]
        ;; Save value in RDI
        (emit-rex-w) (code-emit #x89) (code-emit #xC7)  ; mov rdi, rax
        ;; Use R11 as digit counter
        (code-emit #x4D) (code-emit #x31) (code-emit #xDB)  ; xor r11, r11
        ;; mov rcx, 10 (divisor)
        (emit-rex-w) (code-emit #xC7) (code-emit #xC1)  ; mov ecx, 10
        (code-emit #x0A) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; RAX = value to divide
        (emit-rex-w) (code-emit #x89) (code-emit #xF8)  ; mov rax, rdi
        ;; .digit_loop: divide by 10, push remainder
        (let ((digit-loop (code-pos)))
          ;; xor rdx, rdx (clear high 64 bits for div)
          (emit-rex-w) (code-emit #x31) (code-emit #xD2)  ; xor rdx, rdx
          ;; div rcx (rax = quotient, rdx = remainder)
          (emit-rex-w) (code-emit #xF7) (code-emit #xF1)  ; div rcx
          ;; Push remainder (digit)
          (code-emit #x52)  ; push rdx
          ;; Increment digit counter
          (code-emit #x49) (code-emit #xFF) (code-emit #xC3)  ; inc r11
          ;; test rax, rax (more digits?)
          (emit-rex-w) (code-emit #x85) (code-emit #xC0)  ; test rax, rax
          ;; jnz digit_loop
          (code-emit #x0F) (code-emit #x85)  ; jnz rel32
          (emit-rel32 digit-loop (+ (code-pos) 4)))
        ;; Now print digits (they're on stack in reverse order)
        ;; .print_loop:
        (let ((print-loop (code-pos)))
          ;; Pop digit -> RCX
          (code-emit #x59)  ; pop rcx
          ;; add cl, '0' (48)
          (code-emit #x80) (code-emit #xC1) (code-emit #x30)  ; add cl, 48
          ;; Write to serial
          (emit-serial-write-cl)
          ;; dec r11
          (code-emit #x49) (code-emit #xFF) (code-emit #xCB)  ; dec r11
          ;; jnz print_loop
          (code-emit #x0F) (code-emit #x85)  ; jnz rel32
          (emit-rel32 print-loop (+ (code-pos) 4)))
        ;; Jump to end
        (code-emit #xE9)  ; jmp end (rel32)
        (let ((end-jmp (code-pos)))
          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)

          ;; === Hex path: multi-limb bignum ===
          (patch-rel32 hex-jmp (code-pos))
          ;; Reload raw address from stack
          (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x24)  ; mov rax, [rsp]
          ;; Print "#B" prefix
          (code-emit #xB1) (code-emit #x23)  ; mov cl, '#'
          (emit-serial-write-cl)
          (code-emit #xB1) (code-emit #x42)  ; mov cl, 'B'
          (emit-serial-write-cl)
          ;; Load limb 0 for hex display
          (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x24)  ; mov rax, [rsp]
          (emit-rex-w) (code-emit #x8B) (code-emit #x78) (code-emit #x08)  ; mov rdi, [rax+8]
          ;; Print 16 hex digits
          (code-emit #x49) (code-emit #xC7) (code-emit #xC3)  ; mov r11d, 15
          (code-emit #x0F) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          (let ((hex-loop (code-pos)))
            (emit-rex-w) (code-emit #x89) (code-emit #xF8)  ; mov rax, rdi
            (code-emit #x44) (code-emit #x88) (code-emit #xD9)  ; mov cl, r11b
            (code-emit #xC0) (code-emit #xE1) (code-emit #x02)  ; shl cl, 2
            (emit-rex-w) (code-emit #xD3) (code-emit #xE8)  ; shr rax, cl
            (code-emit #x24) (code-emit #x0F)  ; and al, 0x0F
            (code-emit #x3C) (code-emit #x0A)  ; cmp al, 10
            (code-emit #x72) (code-emit #x04)  ; jb .digit
            (code-emit #x04) (code-emit #x37)  ; add al, 55
            (code-emit #xEB) (code-emit #x02)  ; jmp .write
            (code-emit #x04) (code-emit #x30)  ; add al, 48
            (code-emit #x88) (code-emit #xC1)  ; mov cl, al
            (emit-serial-write-cl)
            (code-emit #x49) (code-emit #xFF) (code-emit #xCB)  ; dec r11
            (code-emit #x0F) (code-emit #x89)  ; jns rel32
            (emit-rel32 hex-loop (+ (code-pos) 4)))

          ;; === End ===
          (patch-rel32 end-jmp (code-pos))))
      ;; Clean up stack (1 push)
      (emit-rex-w) (code-emit #x83) (code-emit #xC4) (code-emit #x08)  ; add rsp, 8
      ;; Return nil
      (emit-mov-rax-imm64 0))

    ;; Compile (cons a b) - allocate and create cons cell
    ;; Uses R12 as allocation pointer, R14 as limit
    ;; Checks for heap overflow before allocating
    (defun rt-compile-cons (args env depth)
      ;; Compile first arg (car) -> RAX, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile second arg (cdr) -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Check heap space: cmp r12, r14
      (code-emit #x4D) (code-emit #x39) (code-emit #xF4)  ; cmp r12, r14
      (code-emit #x0F) (code-emit #x82)  ; jb ok (rel32 - GC body is large)
      (let ((ok-pos (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; Cons heap full: save cdr (in RAX), run GC, restore, retry
        (emit-push-rax)       ; save cdr on stack (will be scanned by GC)
        (emit-per-actor-gc)   ; run per-actor GC
        (emit-pop-rax)        ; restore cdr (possibly updated by GC)
        ;; Retry allocation
        (code-emit #x4D) (code-emit #x39) (code-emit #xF4)  ; cmp r12, r14
        (code-emit #x72)  ; jb ok2 (rel8)
        (let ((ok2-pos (code-pos)))
          (code-emit #x00)
          ;; True OOM - GC couldn't free enough space
          (emit-gc-print-char #x4F)  ; 'O'
          (emit-gc-print-char #x4F)  ; 'O'
          (emit-gc-print-char #x4D)  ; 'M'
          (code-emit #xF4)  ; hlt
          (patch-rel8 ok2-pos (code-pos)))
        (patch-rel32 ok-pos (code-pos)))
      ;; Store cdr at [r12+8]
      (code-emit #x49)  ; REX.WB
      (code-emit #x89)  ; mov r/m64, r64
      (code-emit #x44)  ; [r12 + disp8]
      (code-emit #x24)  ; SIB for r12
      (code-emit #x08)  ; offset 8
      ;; Pop car -> RAX
      (emit-pop-rax)
      ;; Store car at [r12]
      (code-emit #x49)  ; REX.WB
      (code-emit #x89)  ; mov r/m64, r64
      (code-emit #x04)  ; [r12]
      (code-emit #x24)  ; SIB for r12
      ;; Result = r12 | 1 (tag as cons)
      ;; lea rax, [r12+1]
      (code-emit #x49)  ; REX.WB (W=64-bit, B=R12 extension)
      (code-emit #x8D)  ; lea
      (code-emit #x44)  ; [r12 + disp8] with SIB
      (code-emit #x24)  ; SIB: base=r12
      (code-emit #x01)  ; +1 for cons tag
      ;; Bump allocation pointer: add r12, 16
      (code-emit #x49)  ; REX.WB
      (code-emit #x83)  ; add r/m64, imm8
      (code-emit #xC4)  ; ModRM: r12
      (code-emit #x10)) ; +16

    ;; Compile (null x) - check if x is nil (0)
    (defun rt-compile-null (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; test rax, rax
      (emit-rex-w)
      (code-emit #x85)
      (code-emit #xC0)
      ;; sete al
      (code-emit #x0F)
      (code-emit #x94)
      (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (cadr x) = (car (cdr x))
    (defun rt-compile-cadr (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; First do cdr: mov rax, [rax+7]
      (emit-rex-w)
      (code-emit #x8B)  ; mov r64, r/m64
      (code-emit #x40)  ; [rax + disp8]
      (code-emit #x07)  ; +7
      ;; Then do car: lea rax, [rax-1]; mov rax, [rax]
      (emit-rex-w)
      (code-emit #x8D)  ; lea
      (code-emit #x40)  ; [rax + disp8]
      (code-emit #xFF)  ; -1
      (emit-rex-w)
      (code-emit #x8B)  ; mov r64, r/m64
      (code-emit #x00)) ; [rax]

    ;; Compile (cddr x) = (cdr (cdr x))
    (defun rt-compile-cddr (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; First cdr: mov rax, [rax+7]
      (emit-rex-w)
      (code-emit #x8B)
      (code-emit #x40)
      (code-emit #x07)
      ;; Second cdr: mov rax, [rax+7]
      (emit-rex-w)
      (code-emit #x8B)
      (code-emit #x40)
      (code-emit #x07))

    ;; Compile (caddr x) = (car (cdr (cdr x)))
    (defun rt-compile-caddr (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; First cdr
      (emit-rex-w)
      (code-emit #x8B)
      (code-emit #x40)
      (code-emit #x07)
      ;; Second cdr
      (emit-rex-w)
      (code-emit #x8B)
      (code-emit #x40)
      (code-emit #x07)
      ;; Then car
      (emit-rex-w)
      (code-emit #x8D)
      (code-emit #x40)
      (code-emit #xFF)
      (emit-rex-w)
      (code-emit #x8B)
      (code-emit #x00))

    ;; Compile (consp x) - check if x is a cons (tag = 0b01)
    (defun rt-compile-consp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; and al, 3; cmp al, 1; sete al
      (code-emit #x24) (code-emit #x03)  ; and al, 3
      (code-emit #x3C) (code-emit #x01)  ; cmp al, 1
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (atom x) - check if x is NOT a cons (tag != 0b01)
    (defun rt-compile-atom (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; and al, 3; cmp al, 1; setne al
      (code-emit #x24) (code-emit #x03)  ; and al, 3
      (code-emit #x3C) (code-emit #x01)  ; cmp al, 1
      (code-emit #x0F) (code-emit #x95) (code-emit #xC0)  ; setne al
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (length lst) - count list elements
    ;; Uses RCX as counter, RAX as list pointer
    (defun rt-compile-length (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; xor ecx, ecx (counter = 0)
      (code-emit #x31)
      (code-emit #xC9)
      (let ((loop-start (code-pos)))
        ;; test rax, rax (check for nil = 0)
        (emit-rex-w)
        (code-emit #x85)
        (code-emit #xC0)
        ;; jz done
        (code-emit #x74)
        (let ((jz-offset (code-pos)))
          (code-emit #x00)  ; placeholder
          ;; inc rcx
          (emit-rex-w)
          (code-emit #xFF)
          (code-emit #xC1)
          ;; Get cdr: rax = [rax + 7] (untag + offset 8 - 1 = +7)
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x40)
          (code-emit #x07)
          ;; jmp loop-start
          (code-emit #xEB)
          (let ((jmp-offset (- loop-start (code-pos) 1)))
            (code-emit (logand jmp-offset #xFF)))
          ;; done: mov rax, rcx
          (code-patch jz-offset (- (code-pos) jz-offset 1))
          (emit-rex-w)
          (code-emit #x89)
          (code-emit #xC8)
          ;; Tag result (shl rax, 1)
          (emit-shl-rax-1))))

    ;; Compile (nth n lst) - get nth element
    ;; n in first arg, lst in second
    (defun rt-compile-nth (args env depth)
      ;; Evaluate n first, push to stack
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Evaluate lst
      (rt-compile-expr-env (cadr args) env (+ depth 1))
      ;; Pop n into RCX (untagged: shr by 1)
      (code-emit #x59)  ; POP RCX
      (emit-rex-w)
      (code-emit #xD1)  ; shr rcx, 1
      (code-emit #xE9)
      (let ((loop-start (code-pos)))
        ;; test rcx, rcx
        (emit-rex-w)
        (code-emit #x85)
        (code-emit #xC9)
        ;; jz done - n is 0, return car
        (code-emit #x74)
        (let ((jz-offset (code-pos)))
          (code-emit #x00)
          ;; dec rcx
          (emit-rex-w)
          (code-emit #xFF)
          (code-emit #xC9)
          ;; cdr: rax = [rax + 7]
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x40)
          (code-emit #x07)
          ;; jmp loop
          (code-emit #xEB)
          (let ((jmp-offset (- loop-start (code-pos) 1)))
            (code-emit (logand jmp-offset #xFF)))
          ;; done: car: rax = [rax - 1]
          (code-patch jz-offset (- (code-pos) jz-offset 1))
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x40)
          (code-emit #xFF))))

    ;; Compile (list ...) - build a list from arguments
    ;; Strategy: evaluate args right-to-left, cons each onto accumulator
    (defun rt-compile-list (args env depth)
      (if (null args)
          ;; (list) = nil
          (progn
            (emit-rex-w)
            (code-emit #x31)  ; xor rax, rax
            (code-emit #xC0))
          (if (null (cdr args))
              ;; (list a) = (cons a nil)
              (progn
                (rt-compile-expr-env (car args) env depth)
                (emit-push-rax)
                ;; Load nil into RDI
                (emit-rex-w)
                (code-emit #x31)  ; xor rdi, rdi
                (code-emit #xFF)
                (emit-pop-rax)
                ;; Now cons: store car at [r12], cdr at [r12+8]
                (code-emit #x49)  ; REX.WB for R12
                (code-emit #x89)  ; mov [r12], rax
                (code-emit #x04)
                (code-emit #x24)
                (code-emit #x49)  ; REX.WB for R12
                (code-emit #x89)  ; mov [r12+8], rdi
                (code-emit #x7C)
                (code-emit #x24)
                (code-emit #x08)
                ;; Result = r12 | 1
                (code-emit #x49)  ; REX.WB for R12
                (code-emit #x8D)  ; lea rax, [r12+1]
                (code-emit #x44)
                (code-emit #x24)
                (code-emit #x01)
                ;; Bump r12 by 16
                (code-emit #x49)
                (code-emit #x83)
                (code-emit #xC4)
                (code-emit #x10))
              ;; 2+ args: recurse to build rest, then cons first element
              (progn
                ;; First compile all remaining args as a list
                (rt-compile-list (cdr args) env depth)
                (emit-push-rax)  ; push rest of list
                ;; Compile first arg
                (rt-compile-expr-env (car args) env (+ depth 1))
                ;; RAX = first element, stack top = rest of list
                (emit-pop-rdi)   ; RDI = rest of list
                ;; Cons: car=[r12], cdr=[r12+8]
                (code-emit #x49)  ; REX.WB for R12
                (code-emit #x89)  ; mov [r12], rax
                (code-emit #x04)
                (code-emit #x24)
                (code-emit #x49)  ; REX.WB for R12
                (code-emit #x89)  ; mov [r12+8], rdi
                (code-emit #x7C)
                (code-emit #x24)
                (code-emit #x08)
                ;; Result = r12 | 1
                (code-emit #x49)  ; REX.WB for R12
                (code-emit #x8D)  ; lea rax, [r12+1]
                (code-emit #x44)
                (code-emit #x24)
                (code-emit #x01)
                ;; Bump r12 by 16
                (code-emit #x49)
                (code-emit #x83)
                (code-emit #xC4)
                (code-emit #x10)))))

    ;; ================================================================
    ;; More List Operations: reverse, append, member, assoc
    ;; ================================================================

    ;; Compile (reverse lst) - reverse a list in place using iteration
    ;; Uses RCX as current, RDX as prev, RAX as next
    (defun rt-compile-reverse (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; RAX = current list
      ;; xor rdx, rdx (prev = nil)
      (emit-rex-w)
      (code-emit #x31)
      (code-emit #xD2)
      (let ((loop-start (code-pos)))
        ;; test rax, rax
        (emit-rex-w)
        (code-emit #x85)
        (code-emit #xC0)
        ;; jz done
        (code-emit #x74)
        (let ((jz-pos (code-pos)))
          (code-emit #x00)
          ;; rcx = cdr(rax) = [rax+7]
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x48)
          (code-emit #x07)
          ;; [rax+7] = rdx (set cdr to prev)
          (emit-rex-w)
          (code-emit #x89)
          (code-emit #x50)
          (code-emit #x07)
          ;; rdx = rax (prev = current)
          (emit-rex-w)
          (code-emit #x89)
          (code-emit #xC2)
          ;; rax = rcx (current = next)
          (emit-rex-w)
          (code-emit #x89)
          (code-emit #xC8)
          ;; jmp loop
          (code-emit #xEB)
          (code-emit (logand (- loop-start (code-pos) 1) #xFF))
          ;; done: mov rax, rdx
          (code-patch jz-pos (- (code-pos) jz-pos 1))
          (emit-rex-w)
          (code-emit #x89)
          (code-emit #xD0))))

    ;; Compile (append lst1 lst2) - append two lists
    ;; Strategy: copy lst1, set last cdr to lst2
    (defun rt-compile-append (args env depth)
      ;; Compile lst1
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile lst2
      (rt-compile-expr-env (cadr args) env (+ depth 1))
      ;; RDI = lst2
      (emit-mov-reg-rax-to-rdi)
      ;; Pop lst1 to RAX
      (emit-pop-rax)
      ;; If lst1 is nil, return lst2
      (emit-rex-w)
      (code-emit #x85)
      (code-emit #xC0)
      (code-emit #x74)  ; jz return-lst2
      (let ((jz-pos (code-pos)))
        (code-emit #x00)
        ;; lst1 not nil - find last cons and set its cdr to lst2
        ;; Save start of lst1 in RCX
        (emit-rex-w)
        (code-emit #x89)
        (code-emit #xC1)
        (let ((loop-start (code-pos)))
          ;; RDX = cdr(RAX) = [RAX+7]
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x50)
          (code-emit #x07)
          ;; test rdx, rdx
          (emit-rex-w)
          (code-emit #x85)
          (code-emit #xD2)
          ;; jz found-last
          (code-emit #x74)
          (let ((jz2-pos (code-pos)))
            (code-emit #x00)
            ;; rax = rdx
            (emit-rex-w)
            (code-emit #x89)
            (code-emit #xD0)
            ;; jmp loop
            (code-emit #xEB)
            (code-emit (logand (- loop-start (code-pos) 1) #xFF))
            ;; found-last: [rax+7] = rdi (set cdr to lst2)
            (code-patch jz2-pos (- (code-pos) jz2-pos 1))
            (emit-rex-w)
            (code-emit #x89)
            (code-emit #x78)
            (code-emit #x07)
            ;; Return original lst1 (in RCX)
            (emit-rex-w)
            (code-emit #x89)
            (code-emit #xC8)
            ;; Skip the return-lst2 code
            (code-emit #xEB)
            (let ((skip-pos (code-pos)))
              (code-emit #x00)
              ;; return-lst2: rax = rdi
              (code-patch jz-pos (- (code-pos) jz-pos 1))
              (emit-rex-w)
              (code-emit #x89)
              (code-emit #xF8)
              ;; Patch skip jump
              (code-patch skip-pos (- (code-pos) skip-pos 1)))))))

    ;; Compile (member item lst) - find item in list using eq
    ;; Returns sublist starting at item, or nil
    (defun rt-compile-member (args env depth)
      ;; Compile item
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile lst
      (rt-compile-expr-env (cadr args) env (+ depth 1))
      ;; RAX = lst, stack top = item
      (emit-pop-rdi)  ; RDI = item
      (let ((loop-start (code-pos)))
        ;; test rax, rax
        (emit-rex-w)
        (code-emit #x85)
        (code-emit #xC0)
        ;; jz done (return nil)
        (code-emit #x74)
        (let ((jz-pos (code-pos)))
          (code-emit #x00)
          ;; RCX = car(RAX) = [RAX-1]
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x48)
          (code-emit #xFF)
          ;; cmp rcx, rdi
          (emit-rex-w)
          (code-emit #x39)
          (code-emit #xF9)
          ;; je found (return current rax)
          (code-emit #x74)
          (let ((je-pos (code-pos)))
            (code-emit #x00)
            ;; rax = cdr(rax) = [rax+7]
            (emit-rex-w)
            (code-emit #x8B)
            (code-emit #x40)
            (code-emit #x07)
            ;; jmp loop
            (code-emit #xEB)
            (code-emit (logand (- loop-start (code-pos) 1) #xFF))
            ;; found: keep rax as-is (current sublist)
            (code-patch je-pos (- (code-pos) je-pos 1))
            ;; Patch nil return
            (code-patch jz-pos (- (code-pos) jz-pos 1))))))

    ;; Compile (assoc key alist) - find key in association list
    ;; Returns (key . value) pair, or nil
    (defun rt-compile-assoc (args env depth)
      ;; Compile key
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile alist
      (rt-compile-expr-env (cadr args) env (+ depth 1))
      ;; RAX = alist, stack top = key
      (emit-pop-rdi)  ; RDI = key
      (let ((loop-start (code-pos)))
        ;; test rax, rax
        (emit-rex-w)
        (code-emit #x85)
        (code-emit #xC0)
        ;; jz done (return nil)
        (code-emit #x74)
        (let ((jz-pos (code-pos)))
          (code-emit #x00)
          ;; RCX = car(RAX) = [RAX-1] (this is the pair)
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x48)
          (code-emit #xFF)
          ;; RDX = car(RCX) = [RCX-1] (this is the key of pair)
          (emit-rex-w)
          (code-emit #x8B)
          (code-emit #x51)
          (code-emit #xFF)
          ;; cmp rdx, rdi (compare pair's key with our key)
          (emit-rex-w)
          (code-emit #x39)
          (code-emit #xFA)
          ;; je found
          (code-emit #x74)
          (let ((je-pos (code-pos)))
            (code-emit #x00)
            ;; rax = cdr(rax) = [rax+7]
            (emit-rex-w)
            (code-emit #x8B)
            (code-emit #x40)
            (code-emit #x07)
            ;; jmp loop
            (code-emit #xEB)
            (code-emit (logand (- loop-start (code-pos) 1) #xFF))
            ;; found: rax = rcx (return the pair)
            (code-patch je-pos (- (code-pos) je-pos 1))
            (emit-rex-w)
            (code-emit #x89)
            (code-emit #xC8)
            ;; Patch nil return (falls through to here for nil case)
            (code-patch jz-pos (- (code-pos) jz-pos 1))))))

    ;; ================================================================
    ;; Comparisons: <, >
    ;; ================================================================

    ;; Compile (< a b) - returns tagged 0 or 2
    (defun rt-compile-lt (args env depth)
      ;; Compile first arg, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile second arg
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-mov-reg-rax-to-rdi)
      ;; Pop first to RAX
      (emit-pop-rax)
      ;; cmp rax, rdi (comparing tagged values works for fixnums)
      (emit-rex-w)
      (code-emit #x39)
      (code-emit #xF8)
      ;; setl al (set if less than, signed)
      (code-emit #x0F)
      (code-emit #x9C)
      (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (> a b) - returns tagged 0 or 2
    (defun rt-compile-gt (args env depth)
      ;; Compile first arg, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile second arg
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-mov-reg-rax-to-rdi)
      ;; Pop first to RAX
      (emit-pop-rax)
      ;; cmp rax, rdi
      (emit-rex-w)
      (code-emit #x39)
      (code-emit #xF8)
      ;; setg al (set if greater than, signed)
      (code-emit #x0F)
      (code-emit #x9F)
      (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; ================================================================
    ;; Control Flow: loop, return, progn, setq
    ;; ================================================================

    ;; Global for loop context - stores position to patch for return jumps
    ;; Uses memory at 0x300060 for loop nesting:
    ;; +0: current loop end patch position (for return)
    ;; +8: saved outer loop end position (for nesting)
    (defun get-loop-end ()
      (mem-ref #x300060 :u64))

    (defun set-loop-end (pos)
      (setf (mem-ref #x300060 :u64) pos))

    ;; List of return positions to patch (uses cons cells)
    (defun get-return-patches ()
      (mem-ref #x300068 :u64))

    (defun set-return-patches (lst)
      (setf (mem-ref #x300068 :u64) lst))

    ;; Loop entry depth: used by return to compute stack adjustment
    ;; when returning from inside let bindings within a loop.
    (defun get-loop-depth ()
      (mem-ref #x300070 :u64))

    (defun set-loop-depth (d)
      (setf (mem-ref #x300070 :u64) d))

    ;; Compile (loop body-forms...)
    ;; Returns via (return value) which exits the loop
    (defun rt-compile-loop (forms env depth)
      ;; Save outer loop context
      (let ((outer-patches (get-return-patches)))
        (let ((outer-loop-depth (get-loop-depth)))
          (set-return-patches ())  ; new empty list for this loop
          (set-loop-depth depth)   ; record stack depth at loop entry
          ;; Record loop start position
          (let ((loop-start (code-pos)))
          ;; Compile body forms (progn style)
          (rt-compile-loop-body forms env depth)
          ;; === Reduction counter check (preemptive multitasking) ===
          ;; Same logic as cross-compile.lisp: decrement per-CPU counter at GS:[8],
          ;; call yield when it hits zero. Enables LAPIC timer preemption for
          ;; native-compiled loops (timer ISR zeroes counter, next iteration yields).
          (let ((yield-addr (nfn-lookup (hash-of "yield"))))
            (if yield-addr
                (progn
                  ;; MOV RAX, GS:[8] — load per-CPU reduction counter
                  (code-emit #x65) (code-emit #x48) (code-emit #x8B) (code-emit #x04)
                  (code-emit #x25) (code-emit #x08) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                  ;; SUB RAX, 2 — subtract tagged 1
                  (code-emit #x48) (code-emit #x83) (code-emit #xE8) (code-emit #x02)
                  ;; MOV GS:[8], RAX — store decremented value back
                  (code-emit #x65) (code-emit #x48) (code-emit #x89) (code-emit #x04)
                  (code-emit #x25) (code-emit #x08) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                  ;; JG +27 — skip yield call if counter > 0 signed (rel32)
                  ;; Must use JG not JNZ: LAPIC timer zeroes counter, 0-2=-2 is
                  ;; not zero but IS negative → must yield. JG catches both 0 and <0.
                  ;; Skip size: 13 (reset) + 2 (xor ecx) + 12 (call) = 27
                  (code-emit #x0F) (code-emit #x8F)
                  (code-emit-u32 27)
                  ;; Counter hit zero: reset to 4000 (tagged 2000 iterations)
                  ;; MOV QWORD GS:[8], 4000
                  (code-emit #x65) (code-emit #x48) (code-emit #xC7) (code-emit #x04)
                  (code-emit #x25) (code-emit #x08) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                  (code-emit #xA0) (code-emit #x0F) (code-emit #x00) (code-emit #x00)
                  ;; XOR ECX, ECX — nargs=0 for yield call
                  (code-emit #x31) (code-emit #xC9)
                  ;; CALL yield (mov rax, imm64 + call rax = 12 bytes)
                  (emit-call-rel32 yield-addr))
                ()))
          ;; Emit unconditional jump back to start
          (code-emit #xE9)  ; JMP rel32
          (let ((jump-offset (- loop-start (+ (code-pos) 4))))
            (code-emit-u32 jump-offset))
          ;; Now patch all return jumps to here
          (let ((patches (get-return-patches)))
            (patch-return-jumps patches (code-pos)))
          ;; Restore outer loop context
          (set-return-patches outer-patches)
          (set-loop-depth outer-loop-depth)))))

    ;; Compile body forms for loop (like progn)
    (defun rt-compile-loop-body (forms env depth)
      (if (null forms)
          ()
          (if (null (cdr forms))
              ;; Last form
              (rt-compile-expr-env (car forms) env depth)
              (progn
                (rt-compile-expr-env (car forms) env depth)
                (rt-compile-loop-body (cdr forms) env depth)))))

    ;; Patch return jumps to target position
    (defun patch-return-jumps (patches target)
      (if (null patches)
          ()
          (progn
            (patch-jmp32-at (car patches) target)
            (patch-return-jumps (cdr patches) target))))

    ;; Patch a jmp rel32 at position to jump to target
    (defun patch-jmp32-at (pos target)
      ;; Delegate to patch-jump which is known to work correctly.
      ;; Both have identical semantics: patch 4 bytes at pos with
      ;; the relative offset from pos+4 to target.
      (patch-jump pos target))

    ;; Patch a u32 value at position in code buffer
    (defun code-patch-u32 (pos val)
      (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                      #x08000000
                      #x500008)))
        (setf (mem-ref (+ base pos) :u8) (logand val #xFF))
        (setf (mem-ref (+ base pos 1) :u8) (logand (ash val (- 0 8)) #xFF))
        (setf (mem-ref (+ base pos 2) :u8) (logand (ash val (- 0 16)) #xFF))
        (setf (mem-ref (+ base pos 3) :u8) (logand (ash val (- 0 24)) #xFF))))

    ;; Compile (return value)
    (defun rt-compile-return (args env depth)
      ;; Compile the return value
      (if args
          (rt-compile-expr-env (car args) env depth)
          (emit-mov-rax-imm64 0))  ; default nil
      ;; Adjust stack for let bindings between loop entry and here.
      ;; When return is inside let bindings within a loop, the stack has
      ;; extra slots that need to be cleaned up before jumping to loop end.
      (let ((loop-depth (get-loop-depth)))
        (let ((adjust (- depth loop-depth)))
          (if (> adjust 0)
              (emit-add-rsp (* adjust 8)))))
      ;; Emit jump with placeholder offset
      (code-emit #xE9)  ; JMP rel32
      (let ((patch-pos (code-pos)))
        ;; Emit placeholder offset (will be patched)
        (code-emit-u32 0)
        ;; Record this position for patching
        (set-return-patches (cons patch-pos (get-return-patches)))))

    ;; Compile (progn form1 form2 ...)
    (defun rt-compile-progn (forms env depth)
      (if (null forms)
          (emit-mov-rax-imm64 0)  ; return nil
          (if (null (cdr forms))
              (rt-compile-expr-env (car forms) env depth)
              (progn
                (rt-compile-expr-env (car forms) env depth)
                (rt-compile-progn (cdr forms) env depth)))))

    ;; Compile (setq var value)
    ;; Modifies an existing binding in the environment
    (defun rt-compile-setq (args env depth)
      (let ((var (car args))
            (val (car (cdr args))))
        ;; Compile the value
        (rt-compile-expr-env val env depth)
        ;; Find the variable's position
        (let ((binding-depth (env-find var env)))
          (if binding-depth
              ;; Store to stack position
              (if (< binding-depth 0)
                  ;; Register param - can't modify in this simple impl
                  ()  ; TODO: save to stack if needed
                  ;; Stack variable
                  (let ((offset (* (- depth binding-depth) 8)))
                    (emit-store-stack offset)))
              ;; Variable not found - ignore
              ()))))

    ;; Emit: mov [rsp + offset], rax
    (defun emit-store-stack (offset)
      (emit-rex-w)
      (if (eq offset 0)
          (progn
            (code-emit #x89)
            (code-emit #x04)  ; SIB for [rsp]
            (code-emit #x24))
          (if (< offset 128)
              (progn
                (code-emit #x89)
                (code-emit #x44)  ; ModRM: [rsp + disp8]
                (code-emit #x24)  ; SIB
                (code-emit offset))  ; disp8
              (progn
                (code-emit #x89)
                (code-emit #x84)  ; ModRM: [rsp + disp32]
                (code-emit #x24)  ; SIB
                (code-emit-u32 offset)))))

    ;; ================================================================
    ;; Predicates: zerop, not, logand
    ;; ================================================================

    ;; Compile (zerop x) - returns t if x is zero
    (defun rt-compile-zerop (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; test rax, rax
      (emit-rex-w)
      (code-emit #x85)
      (code-emit #xC0)
      ;; setz al
      (code-emit #x0F)
      (code-emit #x94)
      (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (not x) - returns t if x is nil (zero)
    (defun rt-compile-not (args env depth)
      ;; Same as zerop
      (rt-compile-zerop args env depth))

    ;; Compile (logand a b)
    (defun rt-compile-logand (args env depth)
      ;; Handle 3+ args by reducing: (logand a b c) -> (logand (logand a b) c)
      (if (cdr (cdr args))
          (rt-compile-logand
            (cons (cons (sym-logand) (cons (car args) (cons (car (cdr args)) ())))
                  (cdr (cdr args)))
            env depth)
          (progn
            ;; Compile first arg, push
            (rt-compile-expr-env (car args) env depth)
            (emit-push-rax)
            ;; Compile second arg
            (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
            (emit-mov-reg-rax-to-rdi)
            ;; Pop first to RAX
            (emit-pop-rax)
            ;; and rax, rdi
            (emit-rex-w)
            (code-emit #x21)
            (code-emit #xF8))))

    ;; Compile (logior a b ...) — handles 3+ args via reduction
    (defun rt-compile-logior (args env depth)
      (if (cdr (cdr args))
          (rt-compile-logior
            (cons (cons (sym-logior) (cons (car args) (cons (car (cdr args)) ())))
                  (cdr (cdr args)))
            env depth)
          (progn
            ;; Compile first arg, push
            (rt-compile-expr-env (car args) env depth)
            (emit-push-rax)
            ;; Compile second arg
            (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
            (emit-mov-reg-rax-to-rdi)
            ;; Pop first to RAX
            (emit-pop-rax)
            ;; or rax, rdi
            (emit-rex-w)
            (code-emit #x09)
            (code-emit #xF8))))

    ;; Compile (logxor a b ...) — handles 3+ args via reduction
    (defun rt-compile-logxor (args env depth)
      (if (cdr (cdr args))
          (rt-compile-logxor
            (cons (cons (sym-logxor) (cons (car args) (cons (car (cdr args)) ())))
                  (cdr (cdr args)))
            env depth)
          (progn
            ;; Compile first arg, push
            (rt-compile-expr-env (car args) env depth)
            (emit-push-rax)
            ;; Compile second arg
            (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
            (emit-mov-reg-rax-to-rdi)
            ;; Pop first to RAX
            (emit-pop-rax)
            ;; xor rax, rdi
            (emit-rex-w)
            (code-emit #x31)
            (code-emit #xF8))))

    ;; Compile (ash n count) - arithmetic shift
    ;; Positive count = shift left, negative = shift right
    ;; Arithmetic shift: positive = left, negative = right
    (defun rt-compile-ash (args env depth)
      ;; Compile value -> RAX (tagged)
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile shift count -> RAX (tagged)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Untag shift: sar rax, 1
      (emit-sar-rax-1)
      ;; Move shift to RCX for variable shift
      ;; mov rcx, rax
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xC1)  ; mov rcx, rax
      ;; Pop value to RAX
      (emit-pop-rax)
      ;; Untag value: sar rax, 1
      (emit-sar-rax-1)
      ;; Check if shift is negative: test rcx, rcx
      (emit-rex-w)
      (code-emit #x85)
      (code-emit #xC9)  ; test rcx, rcx
      ;; js .right_shift
      (code-emit #x78)  ; js rel8
      (code-emit #x05)  ; skip 5 bytes (3 for shl rax,cl + 2 for jmp rel8)
      ;; Positive: shl rax, cl
      (emit-rex-w)
      (code-emit #xD3)
      (code-emit #xE0)  ; shl rax, cl
      ;; jmp .done (skip right shift)
      (code-emit #xEB)  ; jmp rel8
      (code-emit #x06)  ; skip 6 bytes (neg + sar)
      ;; .right_shift: neg rcx
      (emit-rex-w)
      (code-emit #xF7)
      (code-emit #xD9)  ; neg rcx
      ;; sar rax, cl
      (emit-rex-w)
      (code-emit #xD3)
      (code-emit #xF8)  ; sar rax, cl
      ;; .done: Re-tag result: shl rax, 1
      (emit-shl-rax-1))

    ;; Compile (quote x) - return x unevaluated
    ;; For atoms (numbers): emit tagged value
    ;; For nil: emit 0
    ;; For lists: not yet supported (use explicit cons calls)
    ;; Compile a quoted datum (recursive helper)
    ;; Emits code that leaves the quoted value in RAX
    (defun rt-compile-quote-datum (datum)
      (if (null datum)
          ;; nil = 0
          (emit-mov-rax-imm64 0)
          (if (consp datum)
              ;; List - build from right to left
              ;; First build cdr, then cons car onto it
              (progn
                ;; Recursively compile cdr -> RAX
                (rt-compile-quote-datum (cdr datum))
                ;; Push cdr value
                (emit-push-rax)
                ;; Recursively compile car -> RAX
                (rt-compile-quote-datum (car datum))
                ;; Now RAX = car, stack top = cdr
                ;; Store car at [r12]
                (code-emit #x49)  ; REX.WB
                (code-emit #x89)  ; mov r/m64, r64
                (code-emit #x04)  ; [r12]
                (code-emit #x24)  ; SIB for r12
                ;; Pop cdr -> RDI (temp)
                (code-emit #x5F)  ; pop rdi
                ;; Store cdr at [r12+8]
                (code-emit #x49)  ; REX.WB
                (code-emit #x89)  ; mov r/m64, r64
                (code-emit #x7C)  ; [r12 + disp8] with RDI
                (code-emit #x24)  ; SIB for r12
                (code-emit #x08)  ; offset 8
                ;; Result = r12 | 1 (tag as cons)
                ;; lea rax, [r12+1]
                (code-emit #x49)  ; REX.WB
                (code-emit #x8D)  ; lea
                (code-emit #x44)  ; [r12 + disp8] with SIB
                (code-emit #x24)  ; SIB: base=r12
                (code-emit #x01)  ; +1 for cons tag
                ;; Bump allocation pointer: add r12, 16
                (code-emit #x49)  ; REX.WB
                (code-emit #x83)  ; add r/m64, imm8
                (code-emit #xC4)  ; ModRM: r12
                (code-emit #x10)) ; +16
              ;; Atom (number) - emit tagged value
              (emit-mov-rax-imm64 (* datum 2)))))

    ;; Compile (quote x) - return x unevaluated
    (defun rt-compile-quote (args env depth)
      (rt-compile-quote-datum (car args)))

    ;; ================================================================
    ;; I/O Port Operations
    ;; ================================================================

    ;; Compile (io-in-byte port) - read byte from I/O port
    ;; Returns tagged fixnum (byte value * 2)
    (defun rt-compile-io-in-byte (args env depth)
      ;; Compile port expression -> RAX (tagged)
      (rt-compile-expr-env (car args) env depth)
      ;; Untag port: sar rax, 1
      (emit-sar-rax-1)
      ;; mov dx, ax (port to DX for I/O instruction)
      (code-emit #x66)  ; operand size prefix for 16-bit
      (code-emit #x89)  ; mov r/m16, r16
      (code-emit #xC2)  ; ModRM: ax -> dx
      ;; xor rax, rax (clear for input)
      (emit-rex-w)
      (code-emit #x31)
      (code-emit #xC0)
      ;; in al, dx
      (code-emit #xEC)
      ;; Tag result: shl rax, 1
      (emit-shl-rax-1))

    ;; Compile (io-out-byte port value) - write byte to I/O port
    ;; Returns nil (0)
    (defun rt-compile-io-out-byte (args env depth)
      ;; Compile port -> RAX, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile value -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Save value in RDI
      (emit-mov-reg-rax-to-rdi)
      ;; Pop port to RAX
      (emit-pop-rax)
      ;; Untag port: sar rax, 1
      (emit-sar-rax-1)
      ;; mov dx, ax (port to DX)
      (code-emit #x66)  ; operand size prefix
      (code-emit #x89)
      (code-emit #xC2)  ; ax -> dx
      ;; mov rax, rdi (get value back)
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xF8)  ; rdi -> rax
      ;; Untag value: sar rax, 1
      (emit-sar-rax-1)
      ;; out dx, al
      (code-emit #xEE)
      ;; Return nil (0)
      (emit-mov-rax-imm64 0))

    ;; Compile (io-in-dword port) - read 32-bit value from I/O port
    ;; Returns tagged fixnum (dword value * 2)
    (defun rt-compile-io-in-dword (args env depth)
      ;; Compile port expression -> RAX (tagged)
      (rt-compile-expr-env (car args) env depth)
      ;; Untag port: sar rax, 1
      (emit-sar-rax-1)
      ;; mov dx, ax (port to DX for I/O instruction)
      (code-emit #x66)  ; operand size prefix for 16-bit
      (code-emit #x89)  ; mov r/m16, r16
      (code-emit #xC2)  ; ModRM: ax -> dx
      ;; xor rax, rax (clear for input)
      (emit-rex-w)
      (code-emit #x31)
      (code-emit #xC0)
      ;; in eax, dx (32-bit read)
      (code-emit #xED)
      ;; Tag result: shl rax, 1 (safe - EAX result fits in 32 bits, tagged in 33)
      (emit-shl-rax-1))

    ;; Compile (io-out-dword port value) - write 32-bit value to I/O port
    ;; Returns nil (0)
    (defun rt-compile-io-out-dword (args env depth)
      ;; Compile port -> RAX, push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile value -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Save value in RDI
      (emit-mov-reg-rax-to-rdi)
      ;; Pop port to RAX
      (emit-pop-rax)
      ;; Untag port: sar rax, 1
      (emit-sar-rax-1)
      ;; mov dx, ax (port to DX)
      (code-emit #x66)  ; operand size prefix
      (code-emit #x89)
      (code-emit #xC2)  ; ax -> dx
      ;; mov rax, rdi (get value back)
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xF8)  ; rdi -> rax
      ;; Untag value: sar rax, 1
      (emit-sar-rax-1)
      ;; out dx, eax (32-bit write)
      (code-emit #xEF)
      ;; Return nil (0)
      (emit-mov-rax-imm64 0))

    ;; Compile (write-byte val) - calls runtime write-byte which checks
    ;; capture flags at 0x300014 for SSH output routing.
    (defun rt-compile-write-byte (args env depth)
      ;; Compile value -> RAX
      (rt-compile-expr-env (car args) env depth)
      ;; Move arg to RSI (first parameter register)
      (emit-rex-w) (code-emit #x89) (code-emit #xC6)  ; mov rsi, rax
      ;; Call runtime write-byte via NFN table (sym-write-byte=99, matching
      ;; the fixed ID in *known-symbol-ids* used for source serialization)
      (let ((wb-addr (nfn-lookup (sym-write-byte))))
        (if wb-addr
            (progn
              (emit-call-rel32 wb-addr)
              (emit-mov-rax-imm64 0))
            ;; Fallback: direct serial if write-byte not yet compiled
            (progn
              (emit-rex-w) (code-emit #x89) (code-emit #xF0)  ; mov rax, rsi
              (emit-sar-rax-1)
              (code-emit #x66) (code-emit #xBA) (code-emit #xF8) (code-emit #x03)
              (code-emit #xEE)
              (emit-mov-rax-imm64 0)))))

    ;; Compile (mem-ref addr type) where type is 1=u8, 2=u16, 4=u32, 8=u64
    (defun rt-compile-mem-ref (args env depth)
      ;; Compile address -> RAX
      (rt-compile-expr-env (car args) env depth)
      ;; Untag address: sar rax, 1
      (emit-sar-rax-1)
      ;; Move address to RDI to preserve it
      (emit-mov-reg-rax-to-rdi)
      ;; Get type argument (second arg, should be 1=u8, 2=u16, 4=u32, 8=u64)
      ;; Source keywords :u8/:u16/:u32/:u64 are serialized as integers 1/2/4/8
      (let ((type-arg (car (cdr args))))
        (if (eq type-arg 1)
            ;; u8: movzx rax, byte [rdi]
            (progn
              (emit-rex-w)
              (code-emit #x0F)
              (code-emit #xB6)
              (code-emit #x07)  ; ModRM: [rdi] -> rax
              ;; Tag result: shl rax, 1
              (emit-shl-rax-1))
            (if (eq type-arg 2)
                ;; u16: movzx eax, word [rdi]
                (progn
                  (code-emit #x0F)
                  (code-emit #xB7)
                  (code-emit #x07)  ; ModRM: [rdi] -> eax (zero-extends to rax)
                  ;; Tag result: shl rax, 1
                  (emit-shl-rax-1))
                (if (eq type-arg 4)
                    ;; u32: mov eax, [rdi] (zero-extends to rax)
                    (progn
                      (code-emit #x8B)
                      (code-emit #x07)  ; ModRM: [rdi] -> eax
                      ;; Tag result: shl rax, 1
                      (emit-shl-rax-1))
                    ;; u64: mov rax, [rdi] - no tagging (raw pointer)
                    (progn
                      (emit-rex-w)
                      (code-emit #x8B)
                      (code-emit #x07)))))))  ; ModRM: [rdi] -> rax

    ;; Compile (setf (mem-ref addr type) value)
    ;; Form is: (setf place value) where place is (mem-ref addr type)
    (defun rt-compile-setf (args env depth)
      ;; args is ((mem-ref addr type) value)
      (let ((place (car args))
            (value (car (cdr args))))
        ;; Check if place is a mem-ref form
        (if (consp place)
            ;; place should be (mem-ref addr type)
            (let ((place-op (car place)))
              (if (eq place-op (sym-mem-ref))
                  ;; Setf mem-ref: compile value, push, compile addr, store
                  (let ((addr-form (car (cdr place)))
                        (type-arg (car (cdr (cdr place)))))
                    ;; Compile value -> RAX
                    (rt-compile-expr-env value env depth)
                    (emit-push-rax)
                    ;; Compile address -> RAX
                    (rt-compile-expr-env addr-form env (+ depth 1))
                    ;; Untag address, move to RDI
                    (emit-sar-rax-1)
                    (emit-mov-reg-rax-to-rdi)
                    ;; Pop value to RAX
                    (emit-pop-rax)
                    ;; Store based on type (1=u8, 2=u16, 4=u32, 8=u64)
                    (if (eq type-arg 1)
                        ;; u8: untag value, mov [rdi], al, re-tag return
                        (progn
                          (emit-sar-rax-1)
                          (code-emit #x88)
                          (code-emit #x07)   ; mov [rdi], al
                          (emit-shl-rax-1))  ; re-tag return value
                        (if (eq type-arg 2)
                            ;; u16: untag value, mov [rdi], ax, re-tag return
                            (progn
                              (emit-sar-rax-1)
                              (code-emit #x66)   ; operand size prefix
                              (code-emit #x89)
                              (code-emit #x07)   ; mov [rdi], ax
                              (emit-shl-rax-1))  ; re-tag return value
                            (if (eq type-arg 4)
                                ;; u32: untag value, mov [rdi], eax, re-tag return
                                (progn
                                  (emit-sar-rax-1)
                                  (code-emit #x89)
                                  (code-emit #x07)   ; mov [rdi], eax
                                  (emit-shl-rax-1))  ; re-tag return value
                                ;; u64: mov [rdi], rax (no untagging - raw pointer)
                                (progn
                                  (emit-rex-w)
                                  (code-emit #x89)
                                  (code-emit #x07))))))  ; mov [rdi], rax
                  ;; Not mem-ref, unsupported setf place
                  (emit-mov-rax-imm64 0)))
            ;; Not a cons - might be setq (variable)
            (rt-compile-setq (cons place (cons value ())) env depth))))

    ;; ================================================================
    ;; Garbage Collection - Cheney's Copying Collector
    ;; ================================================================
    ;;
    ;; Memory layout:
    ;;   0x03F00000 - GC metadata
    ;;   0x04000000 - Cons from-space (4MB)
    ;;   0x04400000 - Cons to-space (4MB)
    ;;   0x04800000 - Object from-space (4MB)
    ;;   0x04C00000 - Object to-space (4MB)
    ;;
    ;; GC metadata at 0x03F00000:
    ;;   +0x00 = cons to-space start
    ;;   +0x08 = cons to-space alloc ptr (used during GC)
    ;;   +0x10 = cons to-space limit
    ;;   +0x18 = cons from-space start
    ;;   +0x28 = scan ptr (used during GC)
    ;;   +0x30 = card table base
    ;;   +0x38 = object from-space start
    ;;   +0x40 = object alloc ptr
    ;;   +0x48 = object from-space limit
    ;;   +0x50 = object to-space start
    ;;   +0x58 = object to-space limit
    ;;
    ;; Tag scheme (2-bit):
    ;;   00 = fixnum (shifted left 1, low bit always 0)
    ;;   01 = cons pointer
    ;;   11 = object pointer (bignum, etc.)
    ;;   10 = reserved
    ;;
    ;; Object format:
    ;;   Cons cell: 16 bytes [car:8][cdr:8]
    ;;   Object: [header:8][data...] - header = [subtag:8][flags:8][size:48]
    ;;   Subtag 0x30 = bignum, size = number of 64-bit limbs
    ;;   Forwarding: bit 1 = 1 in car/header means forwarded, bits 63:2 = new addr

    ;; Patch a rel8 jump at given position to jump to target
    ;; pos and target are code buffer positions (tagged)
    (defun patch-rel8 (pos target)
      (let ((rel (- target (+ pos 1))))  ; rel8 is relative to instruction AFTER the byte
        (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                        #x08000000
                        #x500008)))
          (setf (mem-ref (+ base pos) :u8)
                (logand rel #xFF)))))

    ;; Patch a rel32 jump at given position to jump to target
    ;; pos is position of first byte of the 4-byte displacement
    (defun patch-rel32 (pos target)
      (let ((rel (- target (+ pos 4))))  ; rel32 is relative to instruction AFTER the 4 bytes
        (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                        #x08000000
                        #x500008)))
          (let ((addr (+ base pos)))
            (setf (mem-ref addr :u8) (logand rel #xFF))
            (setf (mem-ref (+ addr 1) :u8) (logand (ash rel -8) #xFF))
            (setf (mem-ref (+ addr 2) :u8) (logand (ash rel -16) #xFF))
            (setf (mem-ref (+ addr 3) :u8) (logand (ash rel -24) #xFF))))))

    ;; Emit a rel32 displacement (little-endian)
    (defun emit-rel32 (target from-after)
      (let ((rel (- target from-after)))
        (code-emit (logand rel #xFF))
        (code-emit (logand (ash rel -8) #xFF))
        (code-emit (logand (ash rel -16) #xFF))
        (code-emit (logand (ash rel -24) #xFF))))

    ;; Emit per-actor GC body (inline machine code)
    ;; Computes semispace bounds from R14 (from-space limit).
    ;; Full stack scan from RSP to actor's stack top.
    ;; No card table (write barrier disabled for per-actor GC).
    ;; Objects are GC'd via emit-gc-copy-if-needed (0x03F00038 set per GC run).
    ;; Register usage: RBX, RDI = scan; RCX = from-start; R8 = from-limit;
    ;;   R9 = to-alloc; R10, R11 = copy scratch; RSI = current value
    (defun emit-per-actor-gc ()
      ;; === Acquire GC spinlock at 0x03F00020 (SMP safety) ===
      ;; Must acquire BEFORE saving registers to static memory (protected by lock).
      ;; Global GC temporaries (0x03F00028, 0x03F00038, 0x03F00060) are shared
      ;; across CPUs. Without this lock, concurrent GC on two CPUs corrupts state.
      (code-emit #xB8) (code-emit #x01) (code-emit #x00) (code-emit #x00) (code-emit #x00)  ; mov eax, 1
      (code-emit #x87) (code-emit #x04) (code-emit #x25)  ; xchg [0x03F00020], eax
      (code-emit #x20) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (code-emit #x85) (code-emit #xC0)  ; test eax, eax
      (code-emit #x75) (code-emit #xF0)  ; jnz -16 (retry loop)

      ;; Save registers to STATIC MEMORY at 0x03F00070-0x03F00090 (not stack!)
      ;; CRITICAL FIX: Previously used PUSH which put stale values on the stack.
      ;; GC's stack scan found those stale values, interpreted them as object
      ;; pointers (tag bits matched), triggered false forwarding that corrupted
      ;; real objects. Saving to static memory keeps them out of the scan range.
      ;; mov [0x03F00070], rbx
      (emit-rex-w) (code-emit #x89) (code-emit #x1C) (code-emit #x25)
      (code-emit #x70) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov [0x03F00078], r8
      (code-emit #x4C) (code-emit #x89) (code-emit #x04) (code-emit #x25)
      (code-emit #x78) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov [0x03F00080], r9
      (code-emit #x4C) (code-emit #x89) (code-emit #x0C) (code-emit #x25)
      (code-emit #x80) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov [0x03F00088], r10
      (code-emit #x4C) (code-emit #x89) (code-emit #x14) (code-emit #x25)
      (code-emit #x88) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov [0x03F00090], r11
      (code-emit #x4C) (code-emit #x89) (code-emit #x1C) (code-emit #x25)
      (code-emit #x90) (code-emit #x00) (code-emit #xF0) (code-emit #x03)

      ;; === Step 1: Compute per-actor semispace bounds from R14 ===
      ;; Each actor has 1MB: cons-A (256KB), cons-B (256KB), obj (256KB), pad
      ;; R14 = current from-space limit (raw address)
      ;; from_start = R14 - 0x40000
      (code-emit #x4C) (code-emit #x89) (code-emit #xF1)  ; mov rcx, r14
      (emit-rex-w) (code-emit #x81) (code-emit #xE9)      ; sub rcx, 0x40000
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      ;; R8 = from_limit = R14
      (code-emit #x4D) (code-emit #x89) (code-emit #xF0)  ; mov r8, r14
      ;; R9 = to_start = from_start XOR 0x40000 (toggles between semispace A/B)
      (code-emit #x49) (code-emit #x89) (code-emit #xC9)  ; mov r9, rcx
      (code-emit #x49) (code-emit #x81) (code-emit #xF1)  ; xor r9, 0x40000
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      ;; Store scan ptr = R9 (to_start) at 0x03F00028
      (code-emit #x4C) (code-emit #x89) (code-emit #x0C) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #xF0) (code-emit #x03)

      ;; === Object GC setup: enable object from-space detection ===
      ;; Compute object semispace bounds from obj-limit at GS:[0x30] (per-CPU)
      ;; mov rax, GS:[0x30]  ; obj-limit (end of current from-space)
      (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
      (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; sub rax, 0x40000  ; obj_from_start = limit - 256KB
      (emit-rex-w) (code-emit #x2D)
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      ;; mov [0x03F00038], rax  ; enable object from-space detection
      (emit-rex-w) (code-emit #x89) (code-emit #x04) (code-emit #x25)
      (code-emit #x38) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; Compute obj_to_start = obj_from_start XOR 0x40000 (toggles A<->B)
      ;; Object semispaces A (+0x80000) and B (+0xC0000) differ by bit 18
      ;; mov rdx, rax
      (emit-rex-w) (code-emit #x89) (code-emit #xC2)
      ;; xor rdx, 0x40000
      (emit-rex-w) (code-emit #x81) (code-emit #xF2)
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      ;; mov [0x03F00060], rdx  ; obj to-space alloc ptr = to_start
      (emit-rex-w) (code-emit #x89) (code-emit #x14) (code-emit #x25)
      (code-emit #x60) (code-emit #x00) (code-emit #xF0) (code-emit #x03)

      ;; === Step 2: Full stack scan ===
      ;; Compute actor's stack top = 0x05210000 + (raw_id << 16)
      ;; mov rdi, GS:[0x00]  ; per-CPU current-actor
      (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x3C) (code-emit #x25)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (emit-rex-w) (code-emit #xD1) (code-emit #xFF)                   ; sar rdi, 1 (untag)
      (emit-rex-w) (code-emit #xC1) (code-emit #xE7) (code-emit #x10) ; shl rdi, 16
      (emit-rex-w) (code-emit #x81) (code-emit #xC7)                   ; add rdi, 0x05210000
      (code-emit #x00) (code-emit #x00) (code-emit #x21) (code-emit #x05)
      ;; RBX = RSP (scan from RSP to stack top)
      (emit-rex-w) (code-emit #x89) (code-emit #xE3)                   ; mov rbx, rsp

      ;; Stack scan loop (full scan from RSP to stack top)
      (let ((stack-loop (code-pos)))
        (emit-rex-w) (code-emit #x39) (code-emit #xFB)                 ; cmp rbx, rdi
        (code-emit #x0F) (code-emit #x83)                               ; jae stack_done (rel32)
        (let ((stack-done-jmp (code-pos)))
          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          (emit-rex-w) (code-emit #x8B) (code-emit #x33)               ; mov rsi, [rbx]
          (emit-gc-copy-if-needed)
          (emit-rex-w) (code-emit #x89) (code-emit #x33)               ; mov [rbx], rsi
          (emit-rex-w) (code-emit #x83) (code-emit #xC3) (code-emit #x08)  ; add rbx, 8
          (code-emit #xE9)                                               ; jmp stack_loop (rel32)
          (emit-rel32 stack-loop (+ (code-pos) 4))
          (patch-rel32 stack-done-jmp (code-pos))))

      ;; === Forward saved registers at 0x03F00070-0x03F00090 ===
      ;; These may contain live object pointers that need forwarding.
      ;; Previously NOT forwarded, causing stale pointers after GC.
      ;; Forward saved RBX at [0x03F00070]
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x03F00070]
      (code-emit #x70) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (emit-gc-copy-if-needed)
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)  ; mov [0x03F00070], rsi
      (code-emit #x70) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; Forward saved R8 at [0x03F00078]
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x03F00078]
      (code-emit #x78) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (emit-gc-copy-if-needed)
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)  ; mov [0x03F00078], rsi
      (code-emit #x78) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; Forward saved R9 at [0x03F00080]
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x03F00080]
      (code-emit #x80) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (emit-gc-copy-if-needed)
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)  ; mov [0x03F00080], rsi
      (code-emit #x80) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; Forward saved R10 at [0x03F00088]
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x03F00088]
      (code-emit #x88) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (emit-gc-copy-if-needed)
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)  ; mov [0x03F00088], rsi
      (code-emit #x88) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; Forward saved R11 at [0x03F00090]
      (emit-rex-w) (code-emit #x8B) (code-emit #x34) (code-emit #x25)  ; mov rsi, [0x03F00090]
      (code-emit #x90) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (emit-gc-copy-if-needed)
      (emit-rex-w) (code-emit #x89) (code-emit #x34) (code-emit #x25)  ; mov [0x03F00090], rsi
      (code-emit #x90) (code-emit #x00) (code-emit #xF0) (code-emit #x03)

      ;; === Step 3: Cheney scan loop ===
      (emit-rex-w) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)  ; mov rbx, [0x03F00028]
      (code-emit #x28) (code-emit #x00) (code-emit #xF0) (code-emit #x03)

      (let ((scan-loop-start (code-pos)))
        (code-emit #x4C) (code-emit #x39) (code-emit #xCB)             ; cmp rbx, r9
        (code-emit #x0F) (code-emit #x83)                               ; jae done (rel32)
        (let ((done-jmp-pos (code-pos)))
          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          ;; Process car
          (emit-rex-w) (code-emit #x8B) (code-emit #x33)               ; mov rsi, [rbx]
          (emit-gc-copy-if-needed)
          (emit-rex-w) (code-emit #x89) (code-emit #x33)               ; mov [rbx], rsi
          ;; Process cdr
          (emit-rex-w) (code-emit #x8B) (code-emit #x73) (code-emit #x08)  ; mov rsi, [rbx+8]
          (emit-gc-copy-if-needed)
          (emit-rex-w) (code-emit #x89) (code-emit #x73) (code-emit #x08)  ; mov [rbx+8], rsi
          ;; Advance scan
          (emit-rex-w) (code-emit #x83) (code-emit #xC3) (code-emit #x10)  ; add rbx, 16
          (code-emit #xE9)                                               ; jmp scan_loop (rel32)
          (emit-rel32 scan-loop-start (+ (code-pos) 4))
          (patch-rel32 done-jmp-pos (code-pos))))

      ;; === Step 4: Flip spaces ===
      ;; R12 = R9 (new alloc ptr = to-space allocation position after copy)
      (code-emit #x4D) (code-emit #x89) (code-emit #xCC)              ; mov r12, r9
      ;; R14 = new from-limit = (old_from_start XOR 0x40000) + 0x40000
      ;; RCX still = old from_start (preserved through copy-if-needed)
      (emit-rex-w) (code-emit #x89) (code-emit #xC8)                  ; mov rax, rcx
      (emit-rex-w) (code-emit #x35)                                    ; xor rax, 0x40000
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      (emit-rex-w) (code-emit #x05)                                    ; add rax, 0x40000
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      (code-emit #x49) (code-emit #x89) (code-emit #xC6)              ; mov r14, rax

      ;; === Object semispace flip ===
      ;; New obj alloc ptr = where copying ended (obj to-space alloc at [0x03F00060])
      ;; mov rax, [0x03F00060]  (GC temp, stays global for now)
      (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
      (code-emit #x60) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov GS:[0x28], rax  ; new obj alloc ptr (per-CPU)
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x04) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; New obj limit = old_from_start XOR 0x40000 + 0x40000
      ;; (old_to_start + 0x40000 = new from-space end)
      ;; mov rax, [0x03F00038]  ; old from-start (GC temp, stays global)
      (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
      (code-emit #x38) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; xor rax, 0x40000  ; old to-start = new from-start
      (emit-rex-w) (code-emit #x35)
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      ;; add rax, 0x40000  ; new from-limit
      (emit-rex-w) (code-emit #x05)
      (code-emit #x00) (code-emit #x00) (code-emit #x04) (code-emit #x00)
      ;; mov GS:[0x30], rax  ; update obj limit (per-CPU)
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x04) (code-emit #x25)
      (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)

      ;; Restore registers from static memory (before releasing spinlock)
      ;; mov rbx, [0x03F00070]
      (emit-rex-w) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)
      (code-emit #x70) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov r8, [0x03F00078]
      (code-emit #x4C) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
      (code-emit #x78) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov r9, [0x03F00080]
      (code-emit #x4C) (code-emit #x8B) (code-emit #x0C) (code-emit #x25)
      (code-emit #x80) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov r10, [0x03F00088]
      (code-emit #x4C) (code-emit #x8B) (code-emit #x14) (code-emit #x25)
      (code-emit #x88) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      ;; mov r11, [0x03F00090]
      (code-emit #x4C) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)
      (code-emit #x90) (code-emit #x00) (code-emit #xF0) (code-emit #x03)

      ;; === Release GC spinlock ===
      (code-emit #xC7) (code-emit #x04) (code-emit #x25)  ; mov dword [0x03F00020], 0
      (code-emit #x20) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)

      ;; Return 0
      (emit-mov-rax-imm64 0))

    ;; Compile (gc) - Per-actor Cheney's copying GC
    (defun rt-compile-gc (args env depth)
      (emit-per-actor-gc))

    ;; Helper: emit code to copy RSI if it's a from-space heap pointer (cons or object)
    ;; Input: RSI = value, RCX = cons from-start, R8 = cons from-limit, R9 = cons to-alloc
    ;; Object space uses metadata at 0x03F00038/48 for bounds, 0x03F00060 for to-alloc
    ;; Output: RSI = possibly updated pointer, R9 = possibly incremented (cons only)
    ;; Clobbers: RAX, RDX, R10, R11
    (defun emit-gc-copy-if-needed ()
      ;; test sil, 1 - check if heap pointer (bit 0 set)
      (code-emit #x40) (code-emit #xF6) (code-emit #xC6) (code-emit #x01)
      (code-emit #x0F) (code-emit #x84)  ; jz skip_all (rel32)
      (let ((skip1 (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; Get raw address: mov rax, rsi; and rax, -4 (clear 2 tag bits)
        (emit-rex-w) (code-emit #x89) (code-emit #xF0)
        (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)
        ;; Branch on tag bit 1: cons=01 vs object=11
        (code-emit #x40) (code-emit #xF6) (code-emit #xC6) (code-emit #x02)  ; test sil, 2
        (code-emit #x0F) (code-emit #x85)  ; jnz object_path (rel32)
        (let ((obj-jmp (code-pos)))
          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          ;; === CONS PATH (tag 01) ===
          (emit-rex-w) (code-emit #x39) (code-emit #xC8)  ; cmp rax, rcx (>= from-start?)
          (code-emit #x0F) (code-emit #x82)  ; jb skip (rel32)
          (let ((skip2 (code-pos)))
            (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
            (code-emit #x4C) (code-emit #x39) (code-emit #xC0)  ; cmp rax, r8 (< from-limit?)
            (code-emit #x0F) (code-emit #x83)  ; jae skip (rel32)
            (let ((skip3 (code-pos)))
              (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
              ;; Check forwarding
              (emit-rex-w) (code-emit #x8B) (code-emit #x10)  ; mov rdx, [rax]
              (emit-rex-w) (code-emit #x81) (code-emit #xFA)  ; cmp rdx, 0x04000000
              (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x04)
              (code-emit #x0F) (code-emit #x82)  ; jb not_fwd_cons (rel32)
              (let ((nfc1 (code-pos)))
                (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                ;; CRITICAL FIX: Check bit 0 first - object pointers (tag 11) have
                ;; bit 1 set and were being misidentified as forwarding pointers.
                ;; Forwarding markers have bits 10 (bit 1 set, bit 0 CLEAR).
                (code-emit #xF6) (code-emit #xC2) (code-emit #x01)  ; test dl, 1
                (code-emit #x0F) (code-emit #x85)  ; jnz not_fwd_cons (rel32)
                (let ((nfc3 (code-pos)))
                  (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                (code-emit #xF6) (code-emit #xC2) (code-emit #x02)  ; test dl, 2
                (code-emit #x0F) (code-emit #x84)  ; jz not_fwd_cons (rel32)
                (let ((nfc2 (code-pos)))
                  (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                  ;; Forwarded cons: rsi = (rdx & ~3) | 1
                  (emit-rex-w) (code-emit #x89) (code-emit #xD6)  ; mov rsi, rdx
                  (emit-rex-w) (code-emit #x83) (code-emit #xE6) (code-emit #xFC)  ; and rsi, -4
                  (emit-rex-w) (code-emit #x83) (code-emit #xCE) (code-emit #x01)  ; or rsi, 1
                  (code-emit #xE9)  ; jmp end (rel32)
                  (let ((ej1 (code-pos)))
                    (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                    ;; not_fwd_cons:
                    (patch-rel32 nfc1 (code-pos))
                    (patch-rel32 nfc2 (code-pos))
                    (patch-rel32 nfc3 (code-pos))
                    ;; Copy 16 bytes
                    (code-emit #x4C) (code-emit #x8B) (code-emit #x10)  ; mov r10, [rax]
                    (code-emit #x4C) (code-emit #x8B) (code-emit #x58) (code-emit #x08)  ; mov r11, [rax+8]
                    (code-emit #x4D) (code-emit #x89) (code-emit #x11)  ; mov [r9], r10
                    (code-emit #x4D) (code-emit #x89) (code-emit #x59) (code-emit #x08)  ; mov [r9+8], r11
                    ;; Forward: [rax] = r9 | 2
                    (code-emit #x4C) (code-emit #x89) (code-emit #xCA)  ; mov rdx, r9
                    (emit-rex-w) (code-emit #x83) (code-emit #xCA) (code-emit #x02)  ; or rdx, 2
                    (emit-rex-w) (code-emit #x89) (code-emit #x10)  ; mov [rax], rdx
                    ;; rsi = r9 | 1
                    (code-emit #x4C) (code-emit #x89) (code-emit #xCE)  ; mov rsi, r9
                    (emit-rex-w) (code-emit #x83) (code-emit #xCE) (code-emit #x01)  ; or rsi, 1
                    ;; r9 += 16
                    (code-emit #x49) (code-emit #x83) (code-emit #xC1) (code-emit #x10)
                    (code-emit #xE9)  ; jmp end (rel32)
                    (let ((ej2 (code-pos)))
                      (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)

                      ;; === OBJECT PATH (tag 11) ===
                      (patch-rel32 obj-jmp (code-pos))
                      ;; Check object from-space: cmp rax, [0x03F00038]
                      (emit-rex-w) (code-emit #x3B) (code-emit #x04) (code-emit #x25)
                      (code-emit #x38) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
                      (code-emit #x0F) (code-emit #x82)  ; jb skip (rel32)
                      (let ((skip4 (code-pos)))
                        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                        ;; cmp rax, GS:[0x30] (per-CPU obj-limit)
                        (code-emit #x65) (emit-rex-w) (code-emit #x3B) (code-emit #x04) (code-emit #x25)
                        (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                        (code-emit #x0F) (code-emit #x83)  ; jae skip (rel32)
                        (let ((skip5 (code-pos)))
                          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                          ;; Check forwarding
                          (emit-rex-w) (code-emit #x8B) (code-emit #x10)  ; mov rdx, [rax]
                          (emit-rex-w) (code-emit #x81) (code-emit #xFA)  ; cmp rdx, 0x04000000
                          (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x04)
                          (code-emit #x0F) (code-emit #x82)  ; jb not_fwd_obj (rel32)
                          (let ((nfo1 (code-pos)))
                            (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                            ;; CRITICAL FIX: Check bit 0 first - same fix as cons path.
                            ;; Also prevents subtag 0x31 (string) from being misidentified.
                            ;; Note: subtag 0x32 (array) with count >= 1024 could still
                            ;; collide (bits 10 match forwarding marker), but the >= 0x04000000
                            ;; threshold protects arrays < 1024 bytes.
                            (code-emit #xF6) (code-emit #xC2) (code-emit #x01)  ; test dl, 1
                            (code-emit #x0F) (code-emit #x85)  ; jnz not_fwd_obj (rel32)
                            (let ((nfo3 (code-pos)))
                              (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                            (code-emit #xF6) (code-emit #xC2) (code-emit #x02)  ; test dl, 2
                            (code-emit #x0F) (code-emit #x84)  ; jz not_fwd_obj (rel32)
                            (let ((nfo2 (code-pos)))
                              (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                              ;; Forwarded object: rsi = (rdx & ~3) | 3
                              (emit-rex-w) (code-emit #x89) (code-emit #xD6)  ; mov rsi, rdx
                              (emit-rex-w) (code-emit #x83) (code-emit #xE6) (code-emit #xFC)  ; and rsi, -4
                              (emit-rex-w) (code-emit #x83) (code-emit #xCE) (code-emit #x03)  ; or rsi, 3
                              (code-emit #xE9)  ; jmp end (rel32)
                              (let ((ej3 (code-pos)))
                                (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                                ;; not_fwd_obj:
                                (patch-rel32 nfo1 (code-pos))
                                (patch-rel32 nfo2 (code-pos))
                                (patch-rel32 nfo3 (code-pos))
                                ;; Compute size based on subtag:
                                ;; Bignum (0x30): size = (limb_count+1)*8, round to 16
                                ;; String (0x31)/Array (0x32): size = count + 9, round to 16
                                (code-emit #x4C) (code-emit #x8B) (code-emit #xD2)  ; mov r10, rdx (header)
                                ;; Check subtag: cmp dl, 0x30 (bignum?)
                                (code-emit #x80) (code-emit #xFA) (code-emit #x30)  ; cmp dl, 0x30
                                (code-emit #x0F) (code-emit #x85)  ; jne byte_size (string or array)
                                (let ((str-size-jmp (code-pos)))
                                  (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                                  ;; Bignum path: (count+1)*8
                                  (code-emit #x49) (code-emit #xC1) (code-emit #xEA) (code-emit #x10) ; shr r10, 16
                                  (code-emit #x49) (code-emit #xFF) (code-emit #xC2)  ; inc r10
                                  (code-emit #x49) (code-emit #xC1) (code-emit #xE2) (code-emit #x03) ; shl r10, 3
                                  (code-emit #xEB)  ; jmp size_align (rel8)
                                  (let ((align-jmp (code-pos)))
                                    (code-emit #x00)
                                    ;; String/Array path: 8 (header) + count bytes
                                    (patch-rel32 str-size-jmp (code-pos))
                                    (code-emit #x49) (code-emit #xC1) (code-emit #xEA) (code-emit #x10) ; shr r10, 16
                                    (code-emit #x49) (code-emit #x83) (code-emit #xC2) (code-emit #x08) ; add r10, 8
                                    ;; size_align:
                                    (patch-rel8 align-jmp (code-pos))))
                                (code-emit #x49) (code-emit #x83) (code-emit #xC2) (code-emit #x0F) ; add r10, 15
                                (code-emit #x49) (code-emit #x83) (code-emit #xE2) (code-emit #xF0) ; and r10, -16
                                ;; Load obj to-space alloc -> r11
                                (code-emit #x4C) (code-emit #x8B) (code-emit #x1C) (code-emit #x25)
                                (code-emit #x60) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
                                ;; Save rax (source) and rcx (cons from-start)
                                (code-emit #x50) (code-emit #x51)  ; push rax, push rcx
                                ;; Copy loop: rcx = qword count
                                (code-emit #x4C) (code-emit #x89) (code-emit #xD1)  ; mov rcx, r10
                                (emit-rex-w) (code-emit #xC1) (code-emit #xE9) (code-emit #x03) ; shr rcx, 3
                                (let ((cloop (code-pos)))
                                  (emit-rex-w) (code-emit #x8B) (code-emit #x10)  ; mov rdx, [rax]
                                  (code-emit #x49) (code-emit #x89) (code-emit #x13)  ; mov [r11], rdx
                                  (emit-rex-w) (code-emit #x83) (code-emit #xC0) (code-emit #x08) ; add rax, 8
                                  (code-emit #x49) (code-emit #x83) (code-emit #xC3) (code-emit #x08) ; add r11, 8
                                  (emit-rex-w) (code-emit #xFF) (code-emit #xC9)  ; dec rcx
                                  (code-emit #x75)  ; jnz cloop (rel8)
                                  (code-emit (logand (- cloop (code-pos) 1) #xFF)))
                                ;; Store new obj to-alloc
                                (code-emit #x4C) (code-emit #x89) (code-emit #x1C) (code-emit #x25)
                                (code-emit #x60) (code-emit #x00) (code-emit #xF0) (code-emit #x03)
                                ;; Dest start = r11 - r10
                                (code-emit #x4D) (code-emit #x29) (code-emit #xD3)  ; sub r11, r10
                                ;; Result: rsi = r11 | 3
                                (code-emit #x4C) (code-emit #x89) (code-emit #xDE)  ; mov rsi, r11
                                (emit-rex-w) (code-emit #x83) (code-emit #xCE) (code-emit #x03) ; or rsi, 3
                                ;; Restore rcx, rax
                                (code-emit #x59) (code-emit #x58)  ; pop rcx, pop rax
                                ;; Set forwarding: [rax] = r11 | 2
                                (code-emit #x4C) (code-emit #x89) (code-emit #xDA)  ; mov rdx, r11
                                (emit-rex-w) (code-emit #x83) (code-emit #xCA) (code-emit #x02) ; or rdx, 2
                                (emit-rex-w) (code-emit #x89) (code-emit #x10)  ; mov [rax], rdx
                                ;; end: patch all jumps
                                (let ((end (code-pos)))
                                  (patch-rel32 ej1 end)
                                  (patch-rel32 ej2 end)
                                  (patch-rel32 ej3 end)
                                  (patch-rel32 skip1 end)
                                  (patch-rel32 skip2 end)
                                  (patch-rel32 skip3 end)
                                  (patch-rel32 skip4 end)
                                  (patch-rel32 skip5 end))))))))))))))))))

    ;; Helper: print a character
    (defun emit-gc-print-char (ch)
      (code-emit #x66) (code-emit #xBA)  ; mov dx, 0x3F8
      (code-emit #xF8) (code-emit #x03)
      (code-emit #xB0) (code-emit ch)    ; mov al, ch
      (code-emit #xEE))                  ; out dx, al

    ;; Helper: emit 8-byte GC metadata address
    (defun emit-gc-addr (offset)
      (code-emit offset)
      (code-emit #x00)
      (code-emit #xF0)
      (code-emit #x03)
      (code-emit #x00)
      (code-emit #x00)
      (code-emit #x00)
      (code-emit #x00))

    ;; Helper: emit 4-byte GC metadata address for ModRM
    (defun emit-gc-addr32 (offset)
      (code-emit offset)
      (code-emit #x00)
      (code-emit #xF0)
      (code-emit #x03))

    ;; Compile (listp x) - true if nil or cons (tag 01)
    (defun rt-compile-listp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Check if nil (zero) or cons (tag 01)
      ;; Result = (rax == 0) || ((rax & 3) == 1)
      ;; test rax, rax
      (emit-rex-w)
      (code-emit #x85)
      (code-emit #xC0)
      ;; setz cl (cl = 1 if nil)
      (code-emit #x0F)
      (code-emit #x94)
      (code-emit #xC1)
      ;; Check tag == 01: and al, 3; cmp al, 1; sete al
      (code-emit #x24) (code-emit #x03)  ; and al, 3
      (code-emit #x3C) (code-emit #x01)  ; cmp al, 1
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al
      ;; or al, cl
      (code-emit #x08)
      (code-emit #xC8)
      ;; movzx rax, al
      (emit-rex-w)
      (code-emit #x0F)
      (code-emit #xB6)
      (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (numberp x) - true if fixnum (tag 00, nonzero) or bignum (tag 11)
    (defun rt-compile-numberp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Check fixnum: (rax & 1) == 0 AND rax != 0
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (save)
      (code-emit #xA8) (code-emit #x01)  ; test al, 1
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al (even = possible fixnum)
      (emit-rex-w) (code-emit #x85) (code-emit #xC9)  ; test rcx, rcx
      (code-emit #x0F) (code-emit #x95) (code-emit #xC2)  ; setnz dl
      (code-emit #x20) (code-emit #xD0)  ; and al, dl (fixnum = even AND nonzero)
      ;; Check bignum: (rcx & 3) == 3
      (emit-rex-w) (code-emit #x89) (code-emit #xCA)  ; mov rdx, rcx
      (code-emit #x80) (code-emit #xE2) (code-emit #x03)  ; and dl, 3
      (code-emit #x80) (code-emit #xFA) (code-emit #x03)  ; cmp dl, 3
      (code-emit #x0F) (code-emit #x94) (code-emit #xC2)  ; sete dl
      ;; Result = fixnum OR bignum
      (code-emit #x08) (code-emit #xD0)  ; or al, dl
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)  ; movzx rax, al
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (and ...) - short-circuit: return nil on first nil, else last value
    (defun rt-compile-and (args env depth)
      (if (null args)
          ;; (and) = t (return tagged 1)
          (emit-mov-rax-imm64 2)
          (if (null (cdr args))
              ;; (and x) = x
              (rt-compile-expr-env (car args) env depth)
              ;; (and x y ...) - short-circuit
              (progn
                ;; Compile first arg
                (rt-compile-expr-env (car args) env depth)
                ;; test rax, rax; jz end
                (emit-rex-w)
                (code-emit #x85)
                (code-emit #xC0)
                (code-emit #x74)  ; jz rel8
                (let ((jz-pos (code-pos)))
                  (code-emit #x00)  ; placeholder
                  ;; Recursively compile rest of and
                  (rt-compile-and (cdr args) env depth)
                  ;; Patch jump
                  (code-patch jz-pos (- (code-pos) jz-pos 1)))))))

    ;; Compile (or ...) - short-circuit: return first non-nil value
    (defun rt-compile-or (args env depth)
      (if (null args)
          ;; (or) = nil
          (progn
            (emit-rex-w)
            (code-emit #x31)  ; xor rax, rax
            (code-emit #xC0))
          (if (null (cdr args))
              ;; (or x) = x
              (rt-compile-expr-env (car args) env depth)
              ;; (or x y ...) - short-circuit
              (progn
                ;; Compile first arg
                (rt-compile-expr-env (car args) env depth)
                ;; test rax, rax; jnz end (return this value if non-nil)
                (emit-rex-w)
                (code-emit #x85)
                (code-emit #xC0)
                (code-emit #x75)  ; jnz rel8
                (let ((jnz-pos (code-pos)))
                  (code-emit #x00)  ; placeholder
                  ;; Recursively compile rest of or
                  (rt-compile-or (cdr args) env depth)
                  ;; Patch jump
                  (code-patch jnz-pos (- (code-pos) jnz-pos 1)))))))

    ;; Compile (cond (test1 body1) (test2 body2) ...)
    ;; Returns nil if no clause matches
    (defun rt-compile-cond (clauses env depth)
      (if (null clauses)
          ;; No more clauses - return nil
          (progn
            (emit-rex-w)
            (code-emit #x31)  ; xor rax, rax
            (code-emit #xC0))
          (let ((clause (car clauses)))
            ;; Compile test
            (rt-compile-expr-env (car clause) env depth)
            ;; test rax, rax
            (emit-rex-w)
            (code-emit #x85)
            (code-emit #xC0)
            ;; jz next-clause
            (code-emit #x74)
            (let ((jz-pos (code-pos)))
              (code-emit #x00)  ; placeholder
              ;; Test is true - compile body (or return test value if no body)
              (if (cdr clause)
                  ;; Has body - compile it (last expression's value)
                  (rt-compile-progn-list (cdr clause) env depth)
                  ())  ; No body, just keep test value in RAX
              ;; Jump to end (skip remaining clauses)
              (code-emit #xEB)  ; jmp rel8
              (let ((jmp-pos (code-pos)))
                (code-emit #x00)  ; placeholder
                ;; Patch jz to here
                (code-patch jz-pos (- (code-pos) jz-pos 1))
                ;; Compile remaining clauses
                (rt-compile-cond (cdr clauses) env depth)
                ;; Patch jmp to end
                (code-patch jmp-pos (- (code-pos) jmp-pos 1)))))))

    ;; Helper: compile a list of expressions, returning last value
    ;; Iterative version
    (defun rt-compile-progn-list (exprs env depth)
      (let ((rest exprs))
        (loop
          (if (null rest)
              (return ())
              (if (null (cdr rest))
                  (progn
                    (rt-compile-expr-env (car rest) env depth)
                    (return ()))
                  (progn
                    (rt-compile-expr-env (car rest) env depth)
                    (setq rest (cdr rest))))))))

    ;; ================================================================
    ;; when/unless/dotimes (Phase 5.9)
    ;; ================================================================

    ;; Compile (when test body...) — inline if logic, no cons allocation
    (defun rt-compile-when (args env depth)
      (let ((test-form (car args))
            (body-forms (cdr args)))
        ;; Compile test
        (rt-compile-expr-env test-form env depth)
        ;; Compare to NIL
        (emit-cmp-rax-nil)
        ;; Jump to end if nil (skip body)
        (let ((end-patch (emit-je-placeholder)))
          ;; Compile body forms
          (rt-compile-progn-list body-forms env depth)
          ;; Patch jump target to here
          (let ((end-pos (code-pos)))
            (patch-jump end-patch end-pos)))))

    ;; Compile (unless test body...) — inline if logic, no cons allocation
    (defun rt-compile-unless (args env depth)
      (let ((test-form (car args))
            (body-forms (cdr args)))
        ;; Compile test
        (rt-compile-expr-env test-form env depth)
        ;; Compare to NIL: test RAX, RAX (non-nil = nonzero = skip body)
        (emit-rex-w) (code-emit #x85) (code-emit #xC0)
        ;; JNZ rel32 = 0F 85 rel32 (skip body if test is non-nil)
        (code-emit #x0F)
        (code-emit #x85)
        (let ((rel32-pos (code-pos)))
          (code-emit-u32 0)
          ;; Compile body forms (only runs when test is nil/zero)
          (rt-compile-progn-list body-forms env depth)
          ;; Patch jump target to here
          (let ((end-pos (code-pos)))
            (patch-jump rel32-pos end-pos)))))

    ;; Compile (dotimes (var count) body...)
    ;; Implemented as a counted loop:
    ;;   compile count -> push (limit)
    ;;   push 0 (counter)
    ;;   loop: load counter, compare limit, jump if >=
    ;;   compile body with env extended
    ;;   increment counter, jump back
    ;;   end: pop counter and limit
    (defun rt-compile-dotimes (args env depth)
      (let ((spec (car args))
            (body-forms (cdr args)))
        (let ((var (car spec))
              (count-form (car (cdr spec))))
          ;; Compile count expression -> push as limit
          (rt-compile-expr-env count-form env depth)
          (emit-push-rax)
          ;; Push 0 as initial counter (tagged: 0)
          (emit-mov-rax-imm64 0)
          (emit-push-rax)
          ;; Now stack has: [counter] [limit] ...
          ;; counter at depth+2, limit at depth+1
          ;; Save outer loop context so (return) inside dotimes works correctly.
          ;; Set loop-depth = depth (BEFORE counter/limit) so return's stack
          ;; adjustment of (body-depth - depth) cleans up counter+limit too.
          ;; Return jumps are patched to after the normal exit cleanup code.
          (let ((outer-patches (get-return-patches)))
            (let ((outer-loop-depth (get-loop-depth)))
              (set-return-patches ())
              (set-loop-depth depth)
              (let ((new-env (cons (cons var (+ depth 2)) env))
                    (new-depth (+ depth 2)))
                ;; loop_start:
                (let ((loop-start (code-pos)))
                  ;; Load counter into RAX
                  (emit-load-stack 0)  ; [rsp+0] = counter
                  ;; Load limit into RCX
                  (emit-push-rax)  ; save counter
                  (emit-load-stack 16)  ; [rsp+16] = limit (counter was pushed + original limit slot)
                  (emit-pop-rax)  ; restore counter (was just pushed)
                  (emit-rex-w) (code-emit #x8B) (code-emit #x4C) (code-emit #x24) (code-emit #x08)  ; mov rcx, [rsp+8]
                  ;; Compare: cmp rax, rcx (counter >= limit?)
                  (emit-rex-w) (code-emit #x39) (code-emit #xC8)  ; cmp rax, rcx
                  ;; jge loop_end (jump if counter >= limit, signed comparison on tagged values)
                  (code-emit #x0F) (code-emit #x8D)  ; jge rel32
                  (let ((end-patch (code-pos)))
                    (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                    ;; Compile body forms
                    (rt-compile-progn-list body-forms new-env new-depth)
                    ;; Increment counter: load, add 2 (tagged 1), store
                    (emit-load-stack 0)  ; load counter
                    (emit-rex-w) (code-emit #x83) (code-emit #xC0) (code-emit #x02)  ; add rax, 2
                    (emit-store-stack 0)  ; store counter
                    ;; Jump back to loop_start
                    (code-emit #xE9)  ; jmp rel32
                    (let ((jmp-offset (- loop-start (+ (code-pos) 4))))
                      (code-emit-u32 jmp-offset))
                    ;; loop_end: patch the jge
                    (patch-jump end-patch (code-pos))))
                ;; Pop counter and limit (normal exit path only)
                (emit-add-rsp 16)
                ;; Return NIL (normal dotimes completion)
                (emit-mov-rax-imm64 0)
                ;; Patch (return) jumps to here — return already cleaned up the
                ;; stack (including counter/limit) via adjust = depth_at_return - depth
                (let ((patches (get-return-patches)))
                  (patch-return-jumps patches (code-pos)))
                ;; Restore outer loop context
                (set-return-patches outer-patches)
                (set-loop-depth outer-loop-depth)))))))
    ;; ================================================================
    ;; Byte Arrays (Phase 5.5) - subtag 0x32
    ;; ================================================================

    ;; Helper: allocate array object from object heap
    ;; RAX = length (tagged fixnum), returns tagged array pointer in RAX
    (defun emit-alloc-array ()
      ;; Untag length
      (emit-sar-rax-1)  ; rax = raw length
      ;; Save length in RCX
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax
      ;; Load object alloc ptr from GS:[0x28] -> RDX (per-CPU)
      (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x14) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Compute size: 8 (header) + length bytes, rounded UP to 16
      ;; lea rbx, [rcx + 23]  (8 header + 15 for round-up)
      (emit-rex-w) (code-emit #x8D) (code-emit #x59) (code-emit #x17)
      ;; Round up to 16: and rbx, -16
      (emit-rex-w) (code-emit #x83) (code-emit #xE3) (code-emit #xF0)  ; and rbx, -16
      ;; Check limit
      (emit-rex-w) (code-emit #x89) (code-emit #xD0)  ; mov rax, rdx (save alloc ptr)
      (emit-rex-w) (code-emit #x01) (code-emit #xDA)  ; add rdx, rbx (new alloc end)
      ;; cmp rdx, GS:[0x30] (per-CPU obj-limit)
      (code-emit #x65) (emit-rex-w) (code-emit #x3B) (code-emit #x14) (code-emit #x25)
      (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      (code-emit #x0F) (code-emit #x82)  ; jb ok (rel32 - GC code is >127 bytes)
      (let ((ok-jmp (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; OOM: save length, run GC, restore, retry once
        (code-emit #x51)  ; push rcx (save untagged length)
        (emit-per-actor-gc)
        (code-emit #x59)  ; pop rcx (restore length)
        ;; Retry: reload alloc ptr and recompute size
        ;; mov rdx, GS:[0x28] (per-CPU obj-alloc)
        (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x14) (code-emit #x25)
        (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; lea rbx, [rcx + 23]
        (emit-rex-w) (code-emit #x8D) (code-emit #x59) (code-emit #x17)
        ;; and rbx, -16
        (emit-rex-w) (code-emit #x83) (code-emit #xE3) (code-emit #xF0)
        ;; mov rax, rdx
        (emit-rex-w) (code-emit #x89) (code-emit #xD0)
        ;; add rdx, rbx
        (emit-rex-w) (code-emit #x01) (code-emit #xDA)
        ;; cmp rdx, GS:[0x30] (per-CPU obj-limit)
        (code-emit #x65) (emit-rex-w) (code-emit #x3B) (code-emit #x14) (code-emit #x25)
        (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        (code-emit #x72)  ; jb ok2 (rel8 - only skips OOM halt)
        (let ((ok2-pos (code-pos)))
          (code-emit #x00)
          ;; Real OOM after GC
          (emit-gc-print-char #x4F) (emit-gc-print-char #x4F) (emit-gc-print-char #x41)  ; "OOA"
          (code-emit #xF4)  ; hlt
          (patch-rel8 ok2-pos (code-pos)))
        (patch-rel32 ok-jmp (code-pos)))
      ;; rax = alloc ptr, rdx = new end
      ;; Store new alloc ptr to GS:[0x28] (per-CPU)
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x14) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Write header: [subtag=0x32][flags=0][length=rcx]
      ;; header = rcx << 16 | 0x32
      (code-emit #x53)  ; push rbx (save size)
      (emit-rex-w) (code-emit #x89) (code-emit #xCB)  ; mov rbx, rcx
      (emit-rex-w) (code-emit #xC1) (code-emit #xE3) (code-emit #x10)  ; shl rbx, 16
      (emit-rex-w) (code-emit #x83) (code-emit #xCB) (code-emit #x32)  ; or rbx, 0x32
      (emit-rex-w) (code-emit #x89) (code-emit #x18)  ; mov [rax], rbx (store header)
      (code-emit #x5B)  ; pop rbx
      ;; Tag pointer: rax | 3
      (emit-rex-w) (code-emit #x83) (code-emit #xC8) (code-emit #x03))  ; or rax, 3

    ;; Compile (make-array len) - create byte array
    (defun rt-compile-make-array (args env depth)
      ;; Compile length -> RAX (tagged fixnum)
      (rt-compile-expr-env (car args) env depth)
      ;; Allocate array
      (emit-alloc-array))

    ;; Compile (aref arr idx) - read byte from array
    (defun rt-compile-aref (args env depth)
      ;; Compile array -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile index -> RAX
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; Untag index
      (emit-sar-rax-1)
      ;; RDI = index
      (emit-rex-w) (code-emit #x89) (code-emit #xC7)  ; mov rdi, rax
      ;; Pop array -> RAX
      (emit-pop-rax)
      ;; Clear tag: and rax, -4
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
      ;; Load byte: movzx rax, byte [rax + rdi + 8]
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #x44) (code-emit #x38) (code-emit #x08)
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (aset arr idx val) - write byte to array
    (defun rt-compile-aset (args env depth)
      ;; Compile array -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile index -> push
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-push-rax)
      ;; Compile value -> RAX
      (rt-compile-expr-env (car (cdr (cdr args))) env (+ depth 2))
      ;; Untag value
      (emit-sar-rax-1)
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (value in CL)
      ;; Pop index -> RDI
      (code-emit #x5F)  ; pop rdi
      (emit-rex-w) (code-emit #xD1) (code-emit #xFF)  ; sar rdi, 1 (untag index)
      ;; Pop array -> RAX
      (emit-pop-rax)
      ;; Clear tag
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
      ;; Store byte: mov [rax + rdi + 8], cl
      (code-emit #x88) (code-emit #x4C) (code-emit #x38) (code-emit #x08)
      ;; Return value (re-tag)
      (emit-rex-w) (code-emit #x89) (code-emit #xC8)  ; mov rax, rcx
      (emit-shl-rax-1))

    ;; Compile (array-length arr) - get array length
    (defun rt-compile-array-length (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Clear tag
      (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit #xFC)  ; and rax, -4
      ;; Load header
      (emit-rex-w) (code-emit #x8B) (code-emit #x00)  ; mov rax, [rax]
      ;; Shift right 16 to get length
      (emit-rex-w) (code-emit #xC1) (code-emit #xE8) (code-emit #x10)  ; shr rax, 16
      ;; Tag result
      (emit-shl-rax-1))

    ;; Compile (arrayp x) - check if x is array (tag=11, subtag=0x32)
    (defun rt-compile-arrayp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Check low 2 bits = 0b11
      (emit-rex-w) (code-emit #x89) (code-emit #xC1)  ; mov rcx, rax (save)
      (code-emit #x24) (code-emit #x03)  ; and al, 3
      (code-emit #x3C) (code-emit #x03)  ; cmp al, 3
      (code-emit #x0F) (code-emit #x85)  ; jne not_array (rel32)
      (let ((not-arr (code-pos)))
        (code-emit #x00) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        ;; Tag matches, check subtag
        (emit-rex-w) (code-emit #x83) (code-emit #xE1) (code-emit #xFC)  ; and rcx, -4
        (emit-rex-w) (code-emit #x8B) (code-emit #x01)  ; mov rax, [rcx]
        ;; Check low byte of header = 0x32
        (code-emit #x3C) (code-emit #x32)  ; cmp al, 0x32
        (code-emit #x0F) (code-emit #x94) (code-emit #xC0)  ; sete al
        (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)  ; movzx rax, al
        (emit-shl-rax-1)
        (code-emit #xEB)  ; jmp done
        (let ((done-jmp (code-pos)))
          (code-emit #x00)
          ;; not_array:
          (patch-rel32 not-arr (code-pos))
          (emit-mov-rax-imm64 0)  ; return 0 (nil/false)
          ;; done:
          (patch-rel8 done-jmp (code-pos)))))

    ;; ================================================================
    ;; Higher-Order Functions (Phase 5.7) - function/funcall
    ;; ================================================================

    ;; Compile (function fname) - look up function address at compile time
    (defun rt-compile-function (args env depth)
      ;; Look up fname in nfn table at compile time (like rt-compile-call)
      ;; This avoids the sym-unknown collision problem with runtime lookup
      (let ((fname (car args)))
        (let ((fn-addr (nfn-lookup fname)))
          (if fn-addr
              ;; Found: emit the tagged address as a constant
              (emit-mov-rax-tagged fn-addr)
              ;; Not found: return nil
              (emit-mov-rax-imm64 0)))))

    ;; Compile (funcall f arg1 arg2 ...) - indirect function call
    (defun rt-compile-funcall (args env depth)
      ;; Compile function expression -> push
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      ;; Compile arguments (up to 4: RSI, RDI, R8, R9)
      (let ((fn-args (cdr args))
            (nargs 0))
        ;; Compile each arg and push
        (let ((arg-list fn-args)
              (arg-depth (+ depth 1)))
          (let ((n-fn-args (list-len fn-args)))
            ;; Compile args left to right, push each
            (if (> n-fn-args 0)
                (progn
                  (rt-compile-expr-env (car arg-list) env arg-depth)
                  (emit-push-rax)
                  (if (> n-fn-args 1)
                      (progn
                        (rt-compile-expr-env (car (cdr arg-list)) env (+ arg-depth 1))
                        (emit-push-rax)
                        (if (> n-fn-args 2)
                            (progn
                              (rt-compile-expr-env (car (cdr (cdr arg-list))) env (+ arg-depth 2))
                              (emit-push-rax)
                              (if (> n-fn-args 3)
                                  (progn
                                    (rt-compile-expr-env (car (cdr (cdr (cdr arg-list)))) env (+ arg-depth 3))
                                    (emit-push-rax))))))))))
        ;; Pop args into registers (reverse order)
        (let ((n-fn-args (list-len fn-args)))
          (if (> n-fn-args 3)
              ;; pop r9
              (progn (code-emit #x41) (code-emit #x59)))  ; pop r9
          (if (> n-fn-args 2)
              ;; pop r8
              (progn (code-emit #x41) (code-emit #x58)))  ; pop r8
          (if (> n-fn-args 1)
              ;; pop rdi
              (progn (code-emit #x5F)))  ; pop rdi
          (if (> n-fn-args 0)
              ;; pop rsi
              (progn (code-emit #x5E)))  ; pop rsi
          ;; Pop function address -> RAX
          (emit-pop-rax)
          ;; Untag function address: sar rax, 1
          (emit-sar-rax-1)
          ;; mov rbx, rax
          (emit-rex-w) (code-emit #x89) (code-emit #xC3)  ; mov rbx, rax
          ;; call rbx
          (code-emit #xFF) (code-emit #xD3)))))  ; call rbx

    ;; Compile (1+ x) - increment by 1
    ;; For tagged fixnums: add 2 (since N is stored as N*2)
    (defun rt-compile-1plus (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; add rax, 2  (48 83 C0 02)
      (emit-rex-w)
      (code-emit #x83)
      (code-emit #xC0)
      (code-emit #x02))

    ;; Compile (1- x) - decrement by 1
    ;; For tagged fixnums: sub 2 (since N is stored as N*2)
    (defun rt-compile-1minus (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; sub rax, 2  (48 83 E8 02)
      (emit-rex-w)
      (code-emit #x83)
      (code-emit #xE8)
      (code-emit #x02))

    ;; Compile (let ((var val) ...) body-forms...)
    ;; Pushes each binding onto stack, compiles body (implicit progn), cleans up stack
    (defun rt-compile-let (args env depth)
      (let ((bindings (car args))
            (body-forms (cdr args)))
        ;; Compile each binding and push
        (let ((new-env (rt-compile-bindings bindings env depth)))
          (let ((n-bindings (list-len bindings)))
            (let ((new-depth (+ depth n-bindings)))
              ;; Compile body forms with implicit progn
              (rt-compile-progn-list body-forms new-env new-depth)
              ;; Clean up stack - pop all bindings
              (if (> n-bindings 0)
                  (emit-add-rsp (* n-bindings 8))))))))

    ;; Compile bindings list, return extended environment
    (defun rt-compile-bindings (bindings env depth)
      (if (null bindings)
          env
          (let ((binding (car bindings)))
            (let ((var (car binding))
                  (val (car (cdr binding))))
              ;; Compile value expression
              (rt-compile-expr-env val env depth)
              ;; Push onto stack
              (emit-push-rax)
              ;; Extend environment: var is now at depth+1 (we just pushed)
              (let ((new-env (cons (cons var (+ depth 1)) env)))
                ;; Recursively process remaining bindings with incremented depth
                (rt-compile-bindings (cdr bindings) new-env (+ depth 1)))))))

    ;; Simple list length (iterative)
    (defun list-len (lst)
      (let ((n 0))
        (loop
          (if (null lst)
              (return n)
              (progn
                (setq n (+ n 1))
                (setq lst (cdr lst)))))))

    ;; Environment lookup: find var in env, return stack offset or nil
    ;; env is list of (var-sym . depth-when-pushed)
    (defun env-find (var env)
      (if (null env)
          ()
          (if (eq var (car (car env)))
              (cdr (car env))  ; return the depth
              (env-find var (cdr env)))))

    ;; Emit: mov rax, [rsp + offset]
    ;; offset must be a multiple of 8, in bytes
    (defun emit-load-stack (offset)
      (emit-rex-w)
      (if (eq offset 0)
          (progn
            (code-emit #x8B)    ; mov r64, r/m64
            (code-emit #x04)    ; ModRM: [rsp]
            (code-emit #x24))   ; SIB: rsp
          (if (< offset 128)
              (progn
                ;; Use disp8 form
                (code-emit #x8B)    ; mov r64, r/m64
                (code-emit #x44)    ; ModRM: [rsp+disp8]
                (code-emit #x24)    ; SIB: rsp
                (code-emit offset)) ; disp8
              ;; Use disp32 form (for larger offsets)
              (progn
                (code-emit #x8B)    ; mov r64, r/m64
                (code-emit #x84)    ; ModRM: [rsp+disp32]
                (code-emit #x24)    ; SIB: rsp
                (code-emit-u32 offset)))))

    ;; Add rsp, imm (clean up stack)
    ;; Uses imm8 for small values (0-127), imm32 for larger
    (defun emit-add-rsp (n)
      (emit-rex-w)
      (if (< n 128)
          (progn
            (code-emit #x83)  ; add r/m64, imm8
            (code-emit #xC4)  ; ModRM: rsp
            (code-emit n))    ; imm8
          (progn
            (code-emit #x81)  ; add r/m64, imm32
            (code-emit #xC4)  ; ModRM: rsp
            (code-emit-u32 n)))) ; imm32

    ;; ================================================================
    ;; Native Function Table (flat memory array, GC-immune)
    ;; ================================================================
    ;; Open-addressing hash table at 0x330000 (fixed address, not affected by GC):
    ;;   2048 slots, linear probing. Empty slot = name 0.
    ;;   0x330000 + slot*16:     name (tagged fixnum, hash-chars ID, 0 = empty)
    ;;   0x330000 + slot*16 + 8: addr (tagged fixnum, absolute address)
    ;; Total: 2048 × 16 = 32768 bytes (0x330000–0x338000)
    ;; Slot = (logand name 2047) with linear probing on collision.

    (defun nfn-count ()
      (let ((count 0) (i 0))
        (loop
          (if (>= i 2048)
              (return count)
              (progn
                (if (not (eq (mem-ref (+ #x330000 (* i 16)) :u64) 0))
                    (setq count (+ count 1))
                    ())
                (setq i (+ i 1)))))))

    (defun init-nfntable ()
      (let ((i 0))
        (loop
          (if (>= i 4096)
              (return 0)
              (progn
                (setf (mem-ref (+ #x330000 (* i 8)) :u64) 0)
                (setq i (+ i 1)))))))

    (defun nfn-define (name addr)
      (let ((tbl-base (if (not (zerop (mem-ref #x4FF080 :u64)))
                          #x0A000000
                          #x330000)))
        (let ((slot (logand name 2047))
              (tries 0))
          (loop
            (if (>= tries 2048)
                (return 0)
                (let ((base (+ tbl-base (* slot 16))))
                  (let ((entry-name (mem-ref base :u64)))
                    (if (eq entry-name 0)
                        (progn
                          (setf (mem-ref base :u64) name)
                          (setf (mem-ref (+ base 8) :u64) addr)
                          (return name))
                        (if (eq entry-name name)
                            (progn
                              (setf (mem-ref (+ base 8) :u64) addr)
                              (return name))
                            (progn
                              (setq slot (logand (+ slot 1) 2047))
                              (setq tries (+ tries 1))))))))))))

    (defun nfn-lookup (name)
      (let ((tbl-base (if (not (zerop (mem-ref #x4FF080 :u64)))
                          #x0A000000
                          #x330000)))
        (let ((slot (logand name 2047))
              (tries 0))
          (loop
            (if (>= tries 2048)
                (return ())
                (let ((base (+ tbl-base (* slot 16))))
                  (let ((entry-name (mem-ref base :u64)))
                    (if (eq entry-name 0)
                        (return ())
                        (if (eq entry-name name)
                            (return (mem-ref (+ base 8) :u64))
                            (progn
                              (setq slot (logand (+ slot 1) 2047))
                              (setq tries (+ tries 1))))))))))))

    ;; ================================================================
    ;; Function Compilation
    ;; ================================================================

    ;; Build parameter environment with stack depths
    ;; After pushing N params: first param at depth 1, second at depth 2, etc.
    ;; env = ((p1 . 1) (p2 . 2) ...) for stack-saved params
    (defun build-param-env-stack (params idx)
      (if (null params)
          ()
          (cons (cons (car params) (+ idx 1))
                (build-param-env-stack (cdr params) (+ idx 1)))))

    ;; Emit code to save parameters to stack at function entry
    ;; Returns the number of params saved
    (defun emit-save-params (nparams)
      (if (> nparams 0)
          (progn
            (code-emit #x56)  ;; push rsi (param 0)
            (if (> nparams 1)
                (progn
                  (code-emit #x57)  ;; push rdi (param 1)
                  (if (> nparams 2)
                      (progn
                        (code-emit #x41) (code-emit #x50)  ;; push r8 (param 2)
                        (if (> nparams 3)
                            (progn
                              (code-emit #x41) (code-emit #x51)  ;; push r9 (param 3)
                              ;; For 5+ params: copy extra args from above return address
                              ;; Caller pushed them left-to-right. After 4 reg pushes + k copies,
                              ;; the next extra is always at RSP + nparams*8 (constant offset).
                              (if (> nparams 4)
                                  (let ((offset (* nparams 8))
                                        (k 0))
                                    (loop
                                      (if (>= k (- nparams 4))
                                          (return ())
                                          (progn
                                            (emit-load-stack offset)
                                            (emit-push-rax)
                                            (setq k (+ k 1))))))
                                  ()))
                            ()))))))))

    ;; Compile (defun name (params) body)
    ;; Stores compiled function in native function table
    ;; Functions accumulate in the code buffer (don't reset here)
    ;; In image mode (0x4FF080 != 0): emits to image buffer, uses image NFN table,
    ;; and computes start-addr relative to image load address (0x100000).
    (defun rt-compile-defun (args)
      (let ((name (car args))
            (params (car (cdr args)))
            (rest2 (cdr (cdr args))))
        (let ((body (if rest2 (car rest2) ())))
          (let ((nparams (list-len params)))
            ;; Compute start addr BEFORE emitting any code
            (let ((start-addr (if (not (zerop (mem-ref #x4FF080 :u64)))
                                  (+ #x100000 (code-pos))
                                  (+ #x500008 (code-pos)))))
              ;; Register FIRST so recursive calls can find this function
              (nfn-define name start-addr)
              ;; Save params to stack at function entry
              (emit-save-params nparams)
              ;; Build stack-based environment
              (let ((env (build-param-env-stack params 0)))
                ;; Compile ALL body forms (not just first!) with depth = nparams
                (if rest2
                    (rt-compile-progn-list rest2 env nparams)
                    (emit-mov-rax-imm64 0))
                ;; Clean up saved params and return
                (if (> nparams 0)
                    (emit-add-rsp (* nparams 8)))
                (emit-ret))
              start-addr)))))

    ;; Untag a fixnum: extract bits 1-63 (shift right 1)
    ;; All Lisp values are tagged (shifted left 1), so untagging recovers the raw value
    (defun untag-fixnum (x)
      (ldb (byte 63 1) x))

    ;; Emit: indirect call via RAX
    ;; target-addr is tagged (fixnum). emit-mov-rax-imm64 uses code-emit-u64
    ;; which already untags the value when emitting bytes.
    ;; Args must already be in RSI/RDI/R8/R9 before this is called.
    (defun emit-call-rel32 (target-addr)
      ;; Load target address into RAX
      (emit-mov-rax-imm64 target-addr)
      ;; Call RAX: FF D0
      (code-emit #xFF)
      (code-emit #xD0))

    ;; Push extra args (5th onward) left-to-right for 5+ arg calls
    (defun rt-compile-push-extras (extra-args env depth)
      (if (null extra-args)
          0
          (progn
            (rt-compile-expr-env (car extra-args) env depth)
            (emit-push-rax)
            (+ 1 (rt-compile-push-extras (cdr extra-args) env (+ depth 1))))))

    ;; Compile first 4 args into registers RSI, RDI, R8, R9
    (defun rt-compile-4reg-args (args env depth nargs)
      (if (eq nargs 0)
          ()
          (if (eq nargs 1)
              (progn
                (rt-compile-expr-env (car args) env depth)
                (emit-mov-rax-to-rsi))
              (if (eq nargs 2)
                  (progn
                    (rt-compile-expr-env (car args) env depth)
                    (emit-push-rax)
                    (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
                    (emit-mov-reg-rax-to-rdi)
                    (emit-pop-rsi))
                  (if (eq nargs 3)
                      (progn
                        (rt-compile-expr-env (car args) env depth)
                        (emit-push-rax)
                        (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
                        (emit-push-rax)
                        (rt-compile-expr-env (car (cdr (cdr args))) env (+ depth 2))
                        (emit-mov-rax-to-r8)
                        (emit-pop-rax)
                        (emit-mov-reg-rax-to-rdi)
                        (emit-pop-rsi))
                      (progn
                        (rt-compile-expr-env (car args) env depth)
                        (emit-push-rax)
                        (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
                        (emit-push-rax)
                        (rt-compile-expr-env (car (cdr (cdr args))) env (+ depth 2))
                        (emit-push-rax)
                        (rt-compile-expr-env (car (cdr (cdr (cdr args)))) env (+ depth 3))
                        (emit-mov-rax-to-r9)
                        (emit-pop-rax)
                        (emit-mov-rax-to-r8)
                        (emit-pop-rax)
                        (emit-mov-reg-rax-to-rdi)
                        (emit-pop-rsi)))))))

    ;; Get tail of list starting at index N
    (defun list-drop (lst n)
      (if (eq n 0) lst
          (if (null lst) ()
              (list-drop (cdr lst) (- n 1)))))

    ;; Compile function call arguments into registers RSI, RDI, R8, R9
    ;; For 5+ args, pushes extras onto stack first, then loads first 4 into regs
    ;; Returns the number of extra args pushed (0 for <= 4 args)
    (defun rt-compile-args (args env depth)
      (let ((nargs (list-len args)))
        (if (<= nargs 4)
            (progn
              (rt-compile-4reg-args args env depth nargs)
              0)
            ;; 5+ args: push extras left-to-right, then first 4 into regs
            (let ((n-extra (- nargs 4)))
              (rt-compile-push-extras (list-drop args 4) env depth)
              (rt-compile-4reg-args args env (+ depth n-extra) 4)
              n-extra))))

    ;; Compile a function call (fname arg1 arg2 ...)
    ;; Supports any number of arguments. First 4 in RSI/RDI/R8/R9, rest on stack.
    ;; In image mode, unresolved calls are recorded as forward references
    ;; and patched after all functions are compiled.
    (defun rt-compile-call (fname args env depth)
      (let ((fn-addr (nfn-lookup fname)))
        (if fn-addr
            (let ((n-extra (rt-compile-args args env depth)))
              (emit-call-rel32 fn-addr)
              (if (> n-extra 0)
                  (emit-add-rsp (* n-extra 8))
                  ()))
            ;; Function not found
            (if (not (zerop (mem-ref #x4FF080 :u64)))
                ;; Image mode: forward reference
                (let ((n-extra (rt-compile-args args env depth)))
                  (let ((patch-pos (+ (code-pos) 2)))
                    (img-fwd-record patch-pos fname)
                    (emit-mov-rax-imm64 0)
                    (code-emit #xFF)
                    (code-emit #xD0))
                  (if (> n-extra 0)
                      (emit-add-rsp (* n-extra 8))
                      ()))
                ;; Normal mode: return nil
                (emit-mov-rax-imm64 0)))))

    ;; Emit: mov rsi, rax
    (defun emit-mov-rax-to-rsi ()
      (emit-rex-w)
      (code-emit #x89)
      (code-emit #xC6))  ; ModRM: rax -> rsi

    ;; Emit: pop rsi
    (defun emit-pop-rsi ()
      (code-emit #x5E))

    ;; Emit: mov r8, rax
    (defun emit-mov-rax-to-r8 ()
      (code-emit #x49)  ; REX.WB
      (code-emit #x89)
      (code-emit #xC0))  ; ModRM: rax -> r8

    ;; Emit: mov r9, rax
    (defun emit-mov-rax-to-r9 ()
      (code-emit #x49)  ; REX.WB
      (code-emit #x89)
      (code-emit #xC1))  ; ModRM: rax -> r9

    ;; Emit: pop r8
    (defun emit-pop-r8 ()
      (code-emit #x41)  ; REX.B
      (code-emit #x58)) ; pop r8

    ;; Emit: pop r9
    (defun emit-pop-r9 ()
      (code-emit #x41)  ; REX.B
      (code-emit #x59)) ; pop r9

    ;; Emit: mov rax, r8
    (defun emit-mov-r8-rax ()
      (code-emit #x4C)  ; REX.WR
      (code-emit #x89)
      (code-emit #xC0))  ; ModRM: r8 -> rax

    ;; Emit: mov rax, r9
    (defun emit-mov-r9-rax ()
      (code-emit #x4C)  ; REX.WR
      (code-emit #x89)
      (code-emit #xC8))  ; ModRM: r9 -> rax

    ;; ================================================================
    ;; Self-Hosting: Missing Native Compiler Forms
    ;; ================================================================
    ;; These mirror the cross-compiler implementations from cross-compile.lisp
    ;; Organized by tier: trivial -> simple -> two-operand -> complex

    ;; --- Tier 1: Trivial (fixed byte sequences, no operands) ---

    (defun rt-compile-pause (args env depth)
      ;; F3 90 = PAUSE (spin-wait hint)
      (code-emit #xF3) (code-emit #x90)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-mfence (args env depth)
      ;; 0F AE F0 = MFENCE
      (code-emit #x0F) (code-emit #xAE) (code-emit #xF0)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-hlt-op (args env depth)
      ;; F4 = HLT
      (code-emit #xF4)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-sti-op (args env depth)
      ;; FB = STI
      (code-emit #xFB)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-cli-op (args env depth)
      ;; FA = CLI
      (code-emit #xFA)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-sti-hlt (args env depth)
      ;; FB F4 = STI; HLT (atomic: x86 guarantees interrupt after STI deferred 1 insn)
      (code-emit #xFB) (code-emit #xF4)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-get-alloc-ptr (args env depth)
      ;; mov rax, r12 (4C 89 E0) then shl rax,1 to tag
      (code-emit #x4C) (code-emit #x89) (code-emit #xE0)
      (emit-shl-rax-1))

    (defun rt-compile-get-alloc-limit (args env depth)
      ;; mov rax, r14 (4C 89 F0) then shl rax,1 to tag
      (code-emit #x4C) (code-emit #x89) (code-emit #xF0)
      (emit-shl-rax-1))

    ;; --- Tier 2: Simple (one operand) ---

    (defun rt-compile-untag (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; sar rax, 1 (48 D1 F8)
      (emit-sar-rax-1))

    (defun rt-compile-set-alloc-ptr (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Untag: sar rax, 1
      (emit-sar-rax-1)
      ;; mov r12, rax (49 89 C4)
      (code-emit #x49) (code-emit #x89) (code-emit #xC4))

    (defun rt-compile-set-alloc-limit (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Untag: sar rax, 1
      (emit-sar-rax-1)
      ;; mov r14, rax (49 89 C6)
      (code-emit #x49) (code-emit #x89) (code-emit #xC6))

    (defun rt-compile-fixnump (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; test al, 1 — check if low bit is 0 (fixnum tag)
      (code-emit #xA8) (code-emit #x01)
      ;; sete al (0F 94 C0)
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)
      ;; movzx rax, al (48 0F B6 C0)
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    (defun rt-compile-characterp (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; and al, 0xFF then cmp al, 0x05
      ;; Actually: test low byte = 0x05
      ;; cmp al, 5
      (code-emit #x3C) (code-emit #x05)
      ;; sete al
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)
      ;; Tag result
      (emit-shl-rax-1))

    (defun rt-compile-char-code (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Character: code in bits 8+, shift right by 8 then tag (shl 1)
      ;; Net: sar rax, 7
      ;; sar rax, 7 = 48 C1 F8 07
      (emit-rex-w) (code-emit #xC1) (code-emit #xF8) (code-emit #x07))

    (defun rt-compile-code-char (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Input is fixnum (code << 1), output is character (code << 8) | 0x05
      ;; shl rax, 7 = 48 C1 E0 07
      (emit-rex-w) (code-emit #xC1) (code-emit #xE0) (code-emit #x07)
      ;; or rax, 5 = 48 83 C8 05
      (emit-rex-w) (code-emit #x83) (code-emit #xC8) (code-emit #x05))

    (defun rt-compile-caar (args env depth)
      ;; args = (X), compile X -> RAX, then car of car
      (rt-compile-expr-env (car args) env depth)
      ;; car: lea rax, [rax-1]; mov rax, [rax]
      (emit-rex-w) (code-emit #x8D) (code-emit #x40) (code-emit #xFF)
      (emit-rex-w) (code-emit #x8B) (code-emit #x00)
      ;; car again
      (emit-rex-w) (code-emit #x8D) (code-emit #x40) (code-emit #xFF)
      (emit-rex-w) (code-emit #x8B) (code-emit #x00))

    (defun rt-compile-cdar (args env depth)
      ;; args = (X), compile X -> RAX, then car, then cdr
      (rt-compile-expr-env (car args) env depth)
      ;; car: lea rax, [rax-1]; mov rax, [rax]
      (emit-rex-w) (code-emit #x8D) (code-emit #x40) (code-emit #xFF)
      (emit-rex-w) (code-emit #x8B) (code-emit #x00)
      ;; cdr: mov rax, [rax+7]
      (emit-rex-w) (code-emit #x8B) (code-emit #x40) (code-emit #x07))

    (defun rt-compile-lidt-op (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; Untag: sar rax, 1
      (emit-sar-rax-1)
      ;; LIDT [RAX] = 0F 01 18
      (code-emit #x0F) (code-emit #x01) (code-emit #x18)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    ;; --- Tier 3: Two operands ---

    ;; (= a b) — numeric equality (same pattern as eq but uses CMP)
    (defun rt-compile-equals (args env depth)
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-mov-reg-rax-to-rdi)
      (emit-pop-rax)
      ;; cmp rax, rdi
      (emit-rex-w) (code-emit #x39) (code-emit #xF8)
      ;; sete al
      (code-emit #x0F) (code-emit #x94) (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)
      (emit-shl-rax-1))

    ;; (<= a b) — less-than-or-equal
    (defun rt-compile-le (args env depth)
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-mov-reg-rax-to-rdi)
      (emit-pop-rax)
      ;; cmp rax, rdi
      (emit-rex-w) (code-emit #x39) (code-emit #xF8)
      ;; setle al (0F 9E C0)
      (code-emit #x0F) (code-emit #x9E) (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)
      (emit-shl-rax-1))

    ;; (>= a b) — greater-than-or-equal
    (defun rt-compile-ge (args env depth)
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-mov-reg-rax-to-rdi)
      (emit-pop-rax)
      ;; cmp rax, rdi
      (emit-rex-w) (code-emit #x39) (code-emit #xF8)
      ;; setge al (0F 9D C0)
      (code-emit #x0F) (code-emit #x9D) (code-emit #xC0)
      ;; movzx rax, al
      (emit-rex-w) (code-emit #x0F) (code-emit #xB6) (code-emit #xC0)
      (emit-shl-rax-1))

    ;; (set-car cons val) — mutate car
    (defun rt-compile-set-car (args env depth)
      ;; Compile val first, push
      (rt-compile-expr-env (car (cdr args)) env depth)
      (emit-push-rax)
      ;; Compile cons -> RAX
      (rt-compile-expr-env (car args) env (+ depth 1))
      ;; Pop val -> RDI
      (emit-pop-rdi)
      ;; Store val at [rax-1] (car slot, removing cons tag)
      ;; mov [rax-1], rdi = 48 89 78 FF
      (emit-rex-w) (code-emit #x89) (code-emit #x78) (code-emit #xFF))

    ;; (set-cdr cons val) — mutate cdr
    (defun rt-compile-set-cdr (args env depth)
      ;; Compile val first, push
      (rt-compile-expr-env (car (cdr args)) env depth)
      (emit-push-rax)
      ;; Compile cons -> RAX
      (rt-compile-expr-env (car args) env (+ depth 1))
      ;; Pop val -> RDI
      (emit-pop-rdi)
      ;; Store val at [rax+7] (cdr slot = -1 + 8)
      ;; mov [rax+7], rdi = 48 89 78 07
      (emit-rex-w) (code-emit #x89) (code-emit #x78) (code-emit #x07))

    ;; (ldb (byte size pos) value) — extract bit field
    ;; In the runtime, ldb is called with size and pos as separate args:
    ;; The reader sees (ldb (byte S P) V) but the native compiler sees
    ;; the inner (byte S P) form. We handle the common case where
    ;; byte/size/pos are compile-time constants.
    (defun rt-compile-ldb-op (args env depth)
      ;; args = ((byte size pos) value)
      ;; For the native compiler, byte-spec is a list form
      ;; We need to extract size and pos from it
      ;; The form (byte S P) is parsed as a list: (byte-sym S P)
      ;; We'll compile value, then shift right by pos, then mask to size
      ;; For now, handle the common case with constant size/pos
      (let ((bytespec (car args))
            (value (car (cdr args))))
        (rt-compile-expr-env value env depth)
        ;; bytespec is (byte-id size pos) as parsed by reader
        ;; size and pos are fixnum literals in the source
        (let ((size (car (cdr bytespec)))
              (pos (car (cdr (cdr bytespec)))))
          ;; Shift right by pos (value is untagged for bit extraction)
          ;; Actually: value is tagged. For bit extraction we untag first,
          ;; shift right by pos, mask to size bits, then re-tag.
          ;; But the cross-compiler doesn't untag — it uses the raw value
          ;; and extracts bits directly. Let's match that behavior:
          ;; shr rax, pos
          (if (> pos 0)
              (progn
                ;; shr rax, imm8 = 48 C1 E8 pos
                (emit-rex-w) (code-emit #xC1) (code-emit #xE8) (code-emit pos)))
          ;; Mask to size bits: and rax, (1<<size)-1
          ;; For size <= 31, this fits in imm32
          ;; and rax, imm32 = 48 25 imm32 (for size < 32)
          (let ((mask (- (ash 1 size) 1)))
            (if (< mask 128)
                (progn
                  ;; and rax, imm8 (sign-extended) = 48 83 E0 mask
                  (emit-rex-w) (code-emit #x83) (code-emit #xE0) (code-emit mask))
                (progn
                  ;; and eax, imm32 = 25 imm32 (rax upper cleared)
                  (code-emit #x48) (code-emit #x25)
                  (code-emit-u32 mask)))))))

    ;; (xchg-mem addr val) — atomic exchange
    (defun rt-compile-xchg-mem (args env depth)
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; RAX = val (tagged), stack = addr (tagged)
      ;; Untag val
      (emit-sar-rax-1)
      ;; Pop addr -> RDI, untag
      (emit-pop-rdi)
      (emit-sar-rdi-1)
      ;; XCHG [RDI], RAX — atomic exchange (implicit LOCK)
      ;; 48 87 07 = xchg [rdi], rax
      (emit-rex-w) (code-emit #x87) (code-emit #x07)
      ;; Re-tag result
      (emit-shl-rax-1))

    ;; (percpu-ref offset) — read tagged value from gs:[offset]
    (defun rt-compile-percpu-ref (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; RAX = tagged offset, untag
      (emit-sar-rax-1)
      ;; MOV RAX, GS:[RAX] — 65 48 8B 00
      (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x00))

    ;; (percpu-set offset val) — write tagged value to gs:[offset]
    (defun rt-compile-percpu-set (args env depth)
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      ;; RAX = value (tagged, stored as-is)
      ;; Pop offset -> RDI, untag
      (emit-pop-rdi)
      (emit-sar-rdi-1)
      ;; MOV GS:[RDI], RAX — 65 48 89 07
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x07))

    ;; (wrmsr ecx-val eax-val edx-val) — write to MSR
    (defun rt-compile-wrmsr-op (args env depth)
      ;; Compile all three args
      (rt-compile-expr-env (car args) env depth)
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr args)) env (+ depth 1))
      (emit-push-rax)
      (rt-compile-expr-env (car (cdr (cdr args))) env (+ depth 2))
      ;; RAX = edx-val (tagged), untag -> RDX
      (emit-sar-rax-1)
      ;; mov rdx, rax (48 89 C2)
      (emit-rex-w) (code-emit #x89) (code-emit #xC2)
      ;; Pop eax-val, untag -> RAX
      (emit-pop-rax)
      (emit-sar-rax-1)
      ;; Pop ecx-val -> RCX, untag
      ;; pop rcx = 59
      (code-emit #x59)
      ;; sar rcx, 1 (48 D1 F9)
      (emit-rex-w) (code-emit #xD1) (code-emit #xF9)
      ;; WRMSR: 0F 30
      (code-emit #x0F) (code-emit #x30)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    ;; --- Tier 4: Complex forms ---

    ;; (save-context addr) — save actor registers to save area
    ;; Returns 0 on save, 1 (tagged: 2) when resumed
    (defun rt-compile-save-context (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; RAX = tagged address, untag -> RDX
      (emit-sar-rax-1)
      ;; mov rdx, rax (48 89 C2)
      (emit-rex-w) (code-emit #x89) (code-emit #xC2)
      ;; LEA RAX, [RIP+disp32] — compute continuation address
      ;; 48 8D 05 disp32
      (emit-rex-w) (code-emit #x8D) (code-emit #x05)
      ;; Record position of disp32 for patching
      (let ((lea-disp-pos (code-pos)))
        (code-emit-u32 0)  ; placeholder
        ;; Store continuation at [rdx+40]
        ;; mov [rdx+40], rax = 48 89 42 28
        (emit-rex-w) (code-emit #x89) (code-emit #x42) (code-emit #x28)
        ;; Save registers to actor struct
        ;; mov [rdx+0], rsp = 48 89 22
        (emit-rex-w) (code-emit #x89) (code-emit #x22)
        ;; mov [rdx+8], r12 = 4C 89 62 08
        (code-emit #x4C) (code-emit #x89) (code-emit #x62) (code-emit #x08)
        ;; mov [rdx+16], r14 = 4C 89 72 10
        (code-emit #x4C) (code-emit #x89) (code-emit #x72) (code-emit #x10)
        ;; mov [rdx+24], rbx = 48 89 5A 18
        (emit-rex-w) (code-emit #x89) (code-emit #x5A) (code-emit #x18)
        ;; mov [rdx+32], rbp = 48 89 6A 20
        (emit-rex-w) (code-emit #x89) (code-emit #x6A) (code-emit #x20)
        ;; Save GS:[0x28] (obj-alloc) to [rdx+0x68]
        (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
        (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        (emit-rex-w) (code-emit #x89) (code-emit #x42) (code-emit #x68)
        ;; Save GS:[0x30] (obj-limit) to [rdx+0x70]
        (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x04) (code-emit #x25)
        (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
        (emit-rex-w) (code-emit #x89) (code-emit #x42) (code-emit #x70)
        ;; Return 0 (initial save path)
        (code-emit #x31) (code-emit #xC0)
        ;; jmp +5 (skip continuation code)
        (code-emit #xEB) (code-emit #x05)
        ;; -- continuation: restore-context JMPs here --
        (let ((cont-pos (code-pos)))
          ;; Return 2 (tagged 1: resumed)
          (code-emit #xB8) (code-emit #x02) (code-emit #x00) (code-emit #x00) (code-emit #x00)
          ;; Patch LEA displacement: cont_pos - (lea_disp_pos + 4)
          (let ((disp (- cont-pos (+ lea-disp-pos 4))))
            (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                            #x08000000
                            #x500008)))
              (setf (mem-ref (+ base lea-disp-pos) :u8) (logand disp #xFF))
              (setf (mem-ref (+ base lea-disp-pos 1) :u8) (logand (ash disp -8) #xFF))
              (setf (mem-ref (+ base lea-disp-pos 2) :u8) (logand (ash disp -16) #xFF))
              (setf (mem-ref (+ base lea-disp-pos 3) :u8) (logand (ash disp -24) #xFF)))))))

    ;; (restore-context addr) — restore actor registers and jump
    ;; Never returns to caller
    (defun rt-compile-restore-context (args env depth)
      (rt-compile-expr-env (car args) env depth)
      ;; RAX = tagged address, untag
      (emit-sar-rax-1)
      ;; Restore callee-saved + R12/R14
      ;; mov rbp, [rax+32] = 48 8B 68 20
      (emit-rex-w) (code-emit #x8B) (code-emit #x68) (code-emit #x20)
      ;; mov rbx, [rax+24] = 48 8B 58 18
      (emit-rex-w) (code-emit #x8B) (code-emit #x58) (code-emit #x18)
      ;; mov r12, [rax+8] = 4C 8B 60 08
      (code-emit #x4C) (code-emit #x8B) (code-emit #x60) (code-emit #x08)
      ;; mov r14, [rax+16] = 4C 8B 70 10
      (code-emit #x4C) (code-emit #x8B) (code-emit #x70) (code-emit #x10)
      ;; Restore GS:[0x28] from [rax+0x68]
      (emit-rex-w) (code-emit #x8B) (code-emit #x50) (code-emit #x68)
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x14) (code-emit #x25)
      (code-emit #x28) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Restore GS:[0x30] from [rax+0x70]
      (emit-rex-w) (code-emit #x8B) (code-emit #x50) (code-emit #x70)
      (code-emit #x65) (emit-rex-w) (code-emit #x89) (code-emit #x14) (code-emit #x25)
      (code-emit #x30) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Load continuation -> RCX before switching RSP
      ;; mov rcx, [rax+40] = 48 8B 48 28
      (emit-rex-w) (code-emit #x8B) (code-emit #x48) (code-emit #x28)
      ;; Restore RSP
      ;; mov rsp, [rax] = 48 8B 20
      (emit-rex-w) (code-emit #x8B) (code-emit #x20)
      ;; Release scheduler lock (0x360400) = 0
      ;; mov qword [0x360400], 0 = 48 C7 04 25 <addr32> <imm32>
      (emit-rex-w) (code-emit #xC7) (code-emit #x04) (code-emit #x25)
      (code-emit-u32 #x360400)
      (code-emit-u32 0)
      ;; STI
      (code-emit #xFB)
      ;; JMP RCX
      (code-emit #xFF) (code-emit #xE1))

    ;; (call-native addr [args...]) — call native code at address
    (defun rt-compile-call-native (args env depth)
      (let ((addr-form (car args))
            (arg-list (cdr args)))
        ;; Save R12, R15 (might be clobbered)
        ;; push r12 = 41 54
        (code-emit #x41) (code-emit #x54)
        ;; push r15 = 41 57
        (code-emit #x41) (code-emit #x57)
        ;; Compile address -> RAX (tagged fixnum)
        (rt-compile-expr-env addr-form env (+ depth 2))
        ;; Untag and save to RBX
        (emit-sar-rax-1)
        ;; mov rbx, rax (48 89 C3)
        (emit-rex-w) (code-emit #x89) (code-emit #xC3)
        ;; Compile args -> registers (if any)
        (if (not (null arg-list))
            (progn
              ;; First arg -> RSI
              (rt-compile-expr-env (car arg-list) env (+ depth 2))
              (emit-mov-rax-to-rsi)
              ;; Second arg -> RDI (if any)
              (if (not (null (cdr arg-list)))
                  (progn
                    (rt-compile-expr-env (car (cdr arg-list)) env (+ depth 2))
                    (emit-mov-reg-rax-to-rdi)))))
        ;; Call RBX: FF D3
        (code-emit #xFF) (code-emit #xD3)
        ;; Restore R15, R12
        ;; pop r15 = 41 5F
        (code-emit #x41) (code-emit #x5F)
        ;; pop r12 = 41 5C
        (code-emit #x41) (code-emit #x5C)))

    ;; (switch-idle-stack) — switch RSP to per-CPU idle stack
    (defun rt-compile-switch-idle-stack (args env depth)
      ;; mov rsp, gs:[0x38]
      ;; 65 48 8B 24 25 38 00 00 00
      (code-emit #x65) (emit-rex-w) (code-emit #x8B) (code-emit #x24) (code-emit #x25)
      (code-emit #x38) (code-emit #x00) (code-emit #x00) (code-emit #x00)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    ;; (set-rsp addr) — set RSP to given address
    ;; Used to switch boot context to actor 1's stack so GC scans correctly.
    (defun rt-compile-set-rsp (args env depth)
      ;; Compile addr -> RAX (tagged fixnum)
      (rt-compile-expr-env (car args) env depth)
      ;; Untag: sar rax, 1
      (emit-rex-w) (code-emit #xD1) (code-emit #xF8)
      ;; mov rsp, rax
      (emit-rex-w) (code-emit #x89) (code-emit #xC4)
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    ;; (block name body...) — labeled block for non-local exit
    ;; Uses loop mechanism: records exit label, compiles body
    (defun rt-compile-block-op (args env depth)
      ;; args = (name body-form1 body-form2 ...)
      ;; For the native compiler, block works like progn but with an exit label
      ;; that (return) can jump to. We reuse the loop exit mechanism.
      (let ((body (cdr args)))
        ;; Save current return-label (at 0x4FF030) and set new one
        ;; Actually, for simplicity in the native compiler, treat block
        ;; like a simple progn. The cross-compiler's block/tagbody/go are
        ;; used within runtime functions compiled at build time.
        ;; We compile body forms sequentially.
        (if (null body)
            (progn (code-emit #x31) (code-emit #xC0))  ; return 0
            (let ((remaining body))
              (loop
                (if (null remaining)
                    (return ())
                    (progn
                      (rt-compile-expr-env (car remaining) env depth)
                      (setq remaining (cdr remaining)))))))))

    ;; (tagbody {tag | form}*) and (go tag) — for the native compiler,
    ;; these need runtime label tracking. Since these are used in cross-compiled
    ;; runtime functions (not typically at the REPL), we provide stubs that
    ;; compile the non-tag forms as progn.
    (defun rt-compile-tagbody-op (args env depth)
      ;; Compile non-symbol forms, skip tags
      (let ((forms args))
        (loop
          (if (null forms)
              (return ())
              (progn
                ;; Only compile if not a bare symbol (tag)
                ;; In the native compiler, tags are just symbol IDs
                ;; We skip them (they're labels, not executable)
                (if (consp (car forms))
                    (rt-compile-expr-env (car forms) env depth))
                (setq forms (cdr forms))))))
      ;; Return 0
      (code-emit #x31) (code-emit #xC0))

    (defun rt-compile-go-op (args env depth)
      ;; (go tag) — jump to tagbody label
      ;; In the native compiler, this is a no-op stub since tagbody
      ;; labels aren't tracked at runtime compile time
      (code-emit #x31) (code-emit #xC0))

    ;; (lambda (params) body) — compile as anonymous function
    (defun rt-compile-lambda-op (args env depth)
      ;; args = ((params...) body)
      ;; Jump over the function body, compile it, return its address
      ;; For the native compiler: compile body at current position,
      ;; return the entry address as a tagged fixnum

      ;; Save the body start address
      ;; JMP over function body (we'll patch the offset)
      (code-emit #xE9)  ; jmp rel32
      (let ((jmp-disp-pos (code-pos)))
        (code-emit-u32 0)  ; placeholder

        ;; Function entry: build param env
        (let ((params (car args))
              (body (car (cdr args)))
              (fn-start (code-pos)))

          ;; Save params to stack and build stack-based env
          (let ((nparams (list-len params)))
            (emit-save-params nparams)
            (let ((param-env (build-param-env-stack params 0)))
              (rt-compile-expr-env body param-env nparams)
              (if (> nparams 0)
                  (emit-add-rsp (* nparams 8)))
              (emit-ret)))

          ;; Patch JMP displacement
          (let ((fn-end (code-pos)))
            (let ((disp (- fn-end (+ jmp-disp-pos 4))))
              (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                              #x08000000
                              #x500008)))
                (setf (mem-ref (+ base jmp-disp-pos) :u8) (logand disp #xFF))
                (setf (mem-ref (+ base jmp-disp-pos 1) :u8) (logand (ash disp -8) #xFF))
                (setf (mem-ref (+ base jmp-disp-pos 2) :u8) (logand (ash disp -16) #xFF))
                (setf (mem-ref (+ base jmp-disp-pos 3) :u8) (logand (ash disp -24) #xFF))))

            ;; Return function address as tagged fixnum
            (let ((fn-addr (if (not (zerop (mem-ref #x4FF080 :u64)))
                               (+ #x100000 fn-start)
                               (+ #x500008 fn-start))))
              (emit-mov-rax-imm64 fn-addr))
            ;; Tag as fixnum: already raw address, need to SHL 1
            (emit-shl-rax-1)))))

    ;; Main expression compiler with environment
    ;; env: list of (var . depth), depth: current stack depth (in slots)
    ;; Negative depths indicate register params: -1=RSI, -2=RDI, -3=R8, -4=R9
    (defun rt-compile-expr-env (form env depth)
      (if (consp form)
          (let ((op (car form)))
            (if (eq op (sym-plus))
                (rt-compile-binop-env (sym-plus) (cdr form) env depth)
                (if (eq op (sym-minus))
                    (rt-compile-binop-env (sym-minus) (cdr form) env depth)
                    (if (eq op (sym-times))
                        (rt-compile-binop-env (sym-times) (cdr form) env depth)
                        (if (eq op (sym-1plus))
                            (rt-compile-1plus (cdr form) env depth)
                            (if (eq op (sym-1minus))
                                (rt-compile-1minus (cdr form) env depth)
                                (if (eq op (sym-if))
                                    (rt-compile-if-env (cdr form) env depth)
                            (if (eq op (sym-eq))
                                (rt-compile-eq-env (cdr form) env depth)
                                (if (eq op (sym-quote))
                                    (rt-compile-quote (cdr form) env depth)
                                    (if (eq op (sym-let))
                                    (rt-compile-let (cdr form) env depth)
                                    (if (eq op (sym-defun))
                                        (rt-compile-defun (cdr form))
                                        ;; List primitives
                                        (if (eq op (sym-car))
                                            (rt-compile-car (cdr form) env depth)
                                            (if (eq op (sym-cdr))
                                                (rt-compile-cdr (cdr form) env depth)
                                                (if (eq op (sym-cons))
                                                    (rt-compile-cons (cdr form) env depth)
                                                    (if (eq op (sym-null))
                                                        (rt-compile-null (cdr form) env depth)
                                                        (if (eq op (sym-cadr))
                                                            (rt-compile-cadr (cdr form) env depth)
                                                            (if (eq op (sym-cddr))
                                                                (rt-compile-cddr (cdr form) env depth)
                                                                (if (eq op (sym-caddr))
                                                                    (rt-compile-caddr (cdr form) env depth)
                                                                    (if (eq op (sym-consp))
                                                                        (rt-compile-consp (cdr form) env depth)
                                                                        (if (eq op (sym-atom))
                                                                            (rt-compile-atom (cdr form) env depth)
                                                                            (if (eq op (sym-length))
                                                                                (rt-compile-length (cdr form) env depth)
                                                                                (if (eq op (sym-nth))
                                                                                    (rt-compile-nth (cdr form) env depth)
                                                                                    (if (eq op (sym-list))
                                                                            (rt-compile-list (cdr form) env depth)
                                                        ;; Comparisons
                                                        (if (eq op (sym-lt))
                                                            (rt-compile-lt (cdr form) env depth)
                                                            (if (eq op (sym-gt))
                                                                (rt-compile-gt (cdr form) env depth)
                                                                ;; Control flow
                                                                (if (eq op (sym-loop))
                                                                    (rt-compile-loop (cdr form) env depth)
                                                                    (if (eq op (sym-return))
                                                                        (rt-compile-return (cdr form) env depth)
                                                                        (if (eq op (sym-progn))
                                                                            (rt-compile-progn (cdr form) env depth)
                                                                            (if (eq op (sym-setq))
                                                                                (rt-compile-setq (cdr form) env depth)
                                                                                ;; Predicates
                                                                                (if (eq op (sym-zerop))
                                                                                    (rt-compile-zerop (cdr form) env depth)
                                                                                    (if (eq op (sym-not))
                                                                                        (rt-compile-not (cdr form) env depth)
                                                                                        (if (eq op (sym-logand))
                                                                                            (rt-compile-logand (cdr form) env depth)
                                                                                            (if (eq op (sym-logior))
                                                                                                (rt-compile-logior (cdr form) env depth)
                                                                                                (if (eq op (sym-logxor))
                                                                                                    (rt-compile-logxor (cdr form) env depth)
                                                                                                    (if (eq op (sym-ash))
                                                                                                        (rt-compile-ash (cdr form) env depth)
                                                                                                        ;; More predicates
                                                                                                        (if (eq op (sym-listp))
                                                                                                (rt-compile-listp (cdr form) env depth)
                                                                                                (if (eq op (sym-numberp))
                                                                                                    (rt-compile-numberp (cdr form) env depth)
                                                                                                    ;; Control flow: and, or, cond
                                                                                                    (if (eq op (sym-and))
                                                                                                        (rt-compile-and (cdr form) env depth)
                                                                                                        (if (eq op (sym-or))
                                                                                                            (rt-compile-or (cdr form) env depth)
                                                                                                            (if (eq op (sym-cond))
                                                                                                                (rt-compile-cond (cdr form) env depth)
                                                                                                                ;; More list ops
                                                                                                                (if (eq op (sym-reverse))
                                                                                                                    (rt-compile-reverse (cdr form) env depth)
                                                                                                                    (if (eq op (sym-append))
                                                                                                                        (rt-compile-append (cdr form) env depth)
                                                                                                                        (if (eq op (sym-member))
                                                                                                                            (rt-compile-member (cdr form) env depth)
                                                                                                                            (if (eq op (sym-assoc))
                                                                                                                                (rt-compile-assoc (cdr form) env depth)
                                                                                                                                ;; I/O operations
                                                                                                                                (if (eq op (sym-io-in-byte))
                                                                                                                                    (rt-compile-io-in-byte (cdr form) env depth)
                                                                                                                                    (if (eq op (sym-io-out-byte))
                                                                                                                                        (rt-compile-io-out-byte (cdr form) env depth)
                                                                                                                                        ;; Memory operations
                                                                                                                                        (if (eq op (sym-mem-ref))
                                                                                                                                            (rt-compile-mem-ref (cdr form) env depth)
                                                                                                                                            (if (eq op (sym-setf))
                                                                                                                                                (rt-compile-setf (cdr form) env depth)
                                                                                                                                                ;; GC
                                                                                                                                                (if (eq op (sym-gc))
                                                                                                                                                    (rt-compile-gc (cdr form) env depth)
                                                                                                                                                    ;; Mutation with write barrier
                                                                                                                                                    (if (eq op (sym-rplaca))
                                                                                                                                                        (rt-compile-rplaca (cdr form) env depth)
                                                                                                                                                        (if (eq op (sym-rplacd))
                                                                                                                                                            (rt-compile-rplacd (cdr form) env depth)
                                                                                                                                                            ;; Bignum operations
                                                                                                                                                            (if (eq op (sym-bignump))
                                                                                                                                                                (rt-compile-bignump (cdr form) env depth)
                                                                                                                                                                (if (eq op (sym-integerp))
                                                                                                                                                                    (rt-compile-integerp (cdr form) env depth)
                                                                                                                                                                    (if (eq op (sym-make-bignum))
                                                                                                                                                                        (rt-compile-make-bignum (cdr form) env depth)
                                                                                                                                                                        (if (eq op (sym-bignum-ref))
                                                                                                                                                                            (rt-compile-bignum-ref (cdr form) env depth)
                                                                                                                                                                            (if (eq op (sym-bignum-set))
                                                                                                                                                                                (rt-compile-bignum-set (cdr form) env depth)
                                                                                                                                                                                (if (eq op (sym-bignum-add))
                                                                                                                                                                                    (rt-compile-bignum-add (cdr form) env depth)
                                                                                                                                                                                    (if (eq op (sym-bignum-sub))
                                                                                                                                                                                        (rt-compile-bignum-sub (cdr form) env depth)
                                                                                                                                                                                        (if (eq op (sym-bignum-mul))
                                                                                                                                                                                            (rt-compile-bignum-mul (cdr form) env depth)
                                                                                                                                                                                            (if (eq op (sym-print-bignum))
                                                                                                                                                                                                (rt-compile-print-bignum (cdr form) env depth)
                                                                                                                                                                                                ;; Division operations
                                                                                                                                                                                                (if (eq op (sym-truncate))
                                                                                                                                                                                                    (rt-compile-truncate (cdr form) env depth)
                                                                                                                                                                                                    (if (eq op (sym-mod))
                                                                                                                                                                                                        (rt-compile-mod (cdr form) env depth)
                                                                                                                                                                                                        ;; String operations
                                                                                                                                                                                                        (if (eq op (sym-stringp))
                                                                                                                                                                                                            (rt-compile-stringp (cdr form) env depth)
                                                                                                                                                                                                            ;; let* (alias for let)
                                                                                                                                                                                                            (if (eq op (sym-let-star))
                                                                                                                                                                                                                (rt-compile-let (cdr form) env depth)
                                                                                                                                                                                                                ;; when/unless/dotimes
                                                                                                                                                                                                                (if (eq op (sym-when))
                                                                                                                                                                                                                    (rt-compile-when (cdr form) env depth)
                                                                                                                                                                                                                    (if (eq op (sym-unless))
                                                                                                                                                                                                                        (rt-compile-unless (cdr form) env depth)
                                                                                                                                                                                                                        (if (eq op (sym-dotimes))
                                                                                                                                                                                                                            (rt-compile-dotimes (cdr form) env depth)
                                                                                                                                                                                                                            ;; Array operations - aref/aset/make-array use cross-compiled versions
                                                                                                                                                                                                                            ;; for consistent object pointer format
                                                                                                                                                                                                                            (if (eq op (sym-make-array))
                                                                                                                                                                                                                                (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                (if (eq op (sym-aref))
                                                                                                                                                                                                                                    (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                    (if (eq op (sym-aset))
                                                                                                                                                                                                                                        (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                        (if (eq op (sym-array-length))
                                                                                                                                                                                                                                            (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                            ;; String operations - use cross-compiled versions
                                                                                                                                                                                                                                            (if (eq op (sym-make-string))
                                                                                                                                                                                                                                                (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                                (if (eq op (sym-string-ref))
                                                                                                                                                                                                                                                    (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                                    (if (eq op (sym-string-set))
                                                                                                                                                                                                                                                        (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                                        (if (eq op (sym-string-length))
                                                                                                                                                                                                                                                            (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                                            (if (eq op (sym-print-string))
                                                                                                                                                                                                                                                                (rt-compile-call op (cdr form) env depth)
                                                                                                                                                                                                                                            (if (eq op (sym-arrayp))
                                                                                                                                                                                                                                                (rt-compile-arrayp (cdr form) env depth)
                                                                                                                                                                                                                                                ;; Higher-order functions
                                                                                                                                                                                                                                                (if (eq op (sym-function))
                                                                                                                                                                                                                                                    (rt-compile-function (cdr form) env depth)
                                                                                                                                                                                                                                                    (if (eq op (sym-funcall))
                                                                                                                                                                                                                                                        (rt-compile-funcall (cdr form) env depth)
                                                                                                                                                                                                                                                        ;; I/O
                                                                                                                                                                                                                                                        (if (eq op (sym-write-byte))
                                                                                                                                                                                                                                                            (rt-compile-write-byte (cdr form) env depth)
                                                                                                                                                                                                                                                            ;; 32-bit I/O
                                                                                                                                                                                                                                                            (if (eq op (sym-io-in-dword))
                                                                                                                                                                                                                                                                (rt-compile-io-in-dword (cdr form) env depth)
                                                                                                                                                                                                                                                                (if (eq op (sym-io-out-dword))
                                                                                                                                                                                                                                                                    (rt-compile-io-out-dword (cdr form) env depth)
                                                                                                                                                                                                                                                                    ;; Self-hosting: additional forms
                                                                                                                                                                                                                                                                    (if (eq op (sym-equals)) (rt-compile-equals (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-le)) (rt-compile-le (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-ge)) (rt-compile-ge (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-caar)) (rt-compile-caar (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-cdar)) (rt-compile-cdar (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-set-car)) (rt-compile-set-car (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-set-cdr)) (rt-compile-set-cdr (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-ldb)) (rt-compile-ldb-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-fixnump)) (rt-compile-fixnump (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-characterp)) (rt-compile-characterp (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-char-code)) (rt-compile-char-code (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-code-char)) (rt-compile-code-char (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-untag)) (rt-compile-untag (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-get-alloc-ptr)) (rt-compile-get-alloc-ptr (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-set-alloc-ptr)) (rt-compile-set-alloc-ptr (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-get-alloc-limit)) (rt-compile-get-alloc-limit (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-set-alloc-limit)) (rt-compile-set-alloc-limit (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-save-context)) (rt-compile-save-context (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-restore-context)) (rt-compile-restore-context (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-call-native)) (rt-compile-call-native (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-xchg-mem)) (rt-compile-xchg-mem (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-pause)) (rt-compile-pause (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-mfence)) (rt-compile-mfence (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-hlt)) (rt-compile-hlt-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-sti)) (rt-compile-sti-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-cli)) (rt-compile-cli-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-sti-hlt)) (rt-compile-sti-hlt (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-wrmsr)) (rt-compile-wrmsr-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-percpu-ref)) (rt-compile-percpu-ref (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-percpu-set)) (rt-compile-percpu-set (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-switch-idle-stack)) (rt-compile-switch-idle-stack (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-set-rsp)) (rt-compile-set-rsp (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-lidt)) (rt-compile-lidt-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-block)) (rt-compile-block-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-tagbody)) (rt-compile-tagbody-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-go)) (rt-compile-go-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    (if (eq op (sym-lambda)) (rt-compile-lambda-op (cdr form) env depth)
                                                                                                                                                                                                                                                                    ;; Not a special form - try function call
                                                                                                                                                                                                                                                                    (rt-compile-call op (cdr form) env depth))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))
          ;; ELSE: Atom - check environment first, then constant
          (let ((binding-depth (env-find form env)))
            (if binding-depth
                ;; Variable from binding - check if register or stack
                (if (< binding-depth 0)
                    ;; Register param: -1=RSI, -2=RDI, -3=R8, -4=R9
                    (if (eq binding-depth (- 0 1))
                        (emit-mov-rax-rsi)
                        (if (eq binding-depth (- 0 2))
                            (emit-mov-rax-rdi)
                            (if (eq binding-depth (- 0 3))
                                (emit-mov-r8-rax)
                                (if (eq binding-depth (- 0 4))
                                    (emit-mov-r9-rax)
                                    ()))))
                    ;; Stack variable - compute offset
                    (let ((offset (* (- depth binding-depth) 8)))
                      (emit-load-stack offset)))
                ;; Constant - emit with tagging (* 2)
                (emit-mov-rax-tagged form)))))  ; form already tagged

    ;; Wrapper for backward compatibility
    (defun rt-compile-expr (form)
      (rt-compile-expr-env form () 0))

    ;; Test: compile (+ x y)
    (defun test-rt-compile ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    (cons (sym-x) (cons (sym-y) ()))
                    (cons (sym-plus) (cons (sym-x) (cons (sym-y) ()))))))
        (write-byte 64)
        (print-hex32 addr)
        (write-byte 10)
        addr))

    ;; Test calling native code: compile (+ x y) then call with values
    ;; Test: simple function that writes a byte at code buffer pos
    (defun test-write-fn (pos val)
      (setf (mem-ref (+ #x500008 pos) :u8) val))

    ;; Test: function that computes (- target (+ pos 4)) and writes it
    (defun test-patch-fn (pos target)
      (let ((rel (- target (+ pos 4))))
        (setf (mem-ref (+ #x500008 pos) :u8) rel)))

    ;; Test: function that takes pos, computes base, writes val
    (defun test-base-fn (pos val)
      (let ((base (if (not (zerop (mem-ref #x4FF080 :u64)))
                      #x08000000
                      #x500008)))
        (setf (mem-ref (+ base pos) :u8) val)))

    (defun test-native-add (a b)
      (code-init)
      (let ((addr (rt-compile-lambda
                    (cons (sym-x) (cons (sym-y) ()))
                    (cons (sym-plus) (cons (sym-x) (cons (sym-y) ()))))))
        (call-native addr a b)))

    ;; Test (- x y)
    (defun test-native-sub (a b)
      (code-init)
      (let ((addr (rt-compile-lambda
                    (cons (sym-x) (cons (sym-y) ()))
                    (cons (sym-minus) (cons (sym-x) (cons (sym-y) ()))))))
        (call-native addr a b)))

    ;; Test (* x y)
    (defun test-native-mul (a b)
      (code-init)
      (let ((addr (rt-compile-lambda
                    (cons (sym-x) (cons (sym-y) ()))
                    (cons (sym-times) (cons (sym-x) (cons (sym-y) ()))))))
        (call-native addr a b)))

    ;; Test nested: (+ (+ x y) x) = 2x + y
    (defun test-native-nested (a b)
      (code-init)
      (let ((addr (rt-compile-lambda
                    (cons (sym-x) (cons (sym-y) ()))
                    ;; (+ (+ x y) x)
                    (cons (sym-plus)
                          (cons (cons (sym-plus) (cons (sym-x) (cons (sym-y) ())))
                                (cons (sym-x) ()))))))
        (call-native addr a b)))

    ;; Compile constant return - just compiles, returns address
    (defun test-native-const-compile ()
      (code-init)
      (rt-compile-lambda () 100))

    ;; Test constant return - just returns 100
    (defun test-native-const ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()  ; no params
                    100)))  ; just return 100
        (call-native addr 0 0)))

    ;; Simple if test - (if t 100 200) should always return 100
    (defun test-native-if-simple ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (if t 100 200) - t is truthy, should return 100
                    (cons (sym-if)
                          (cons (sym-t) (cons 100 (cons 200 ())))))))
        (call-native addr 0 0)))

    ;; Test (if (eq x y) 100 200) - returns 100 if equal, 200 otherwise
    (defun test-native-if (a b)
      (code-init)
      (let ((addr (rt-compile-lambda
                    (cons (sym-x) (cons (sym-y) ()))
                    ;; (if (eq x y) 100 200)
                    (cons (sym-if)
                          (cons (cons (sym-eq) (cons (sym-x) (cons (sym-y) ())))
                                (cons 100 (cons 200 ())))))))
        (call-native addr a b)))

    ;; Test (let ((a 5)) a) - simple binding, returns 5
    (defun test-native-let-simple ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (let ((a 5)) a)
                    (cons (sym-let)
                          (cons (cons (cons (sym-a) (cons 5 ())) ())  ; ((a 5))
                                (cons (sym-a) ()))))))               ; a
        (call-native addr 0 0)))

    ;; Test (let ((a 3) (b 7)) (+ a b)) - two bindings, returns 10
    (defun test-native-let-add ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (let ((a 3) (b 7)) (+ a b))
                    (cons (sym-let)
                          (cons (cons (cons (sym-a) (cons 3 ()))      ; (a 3)
                                      (cons (cons (sym-b) (cons 7 ())) ())) ; (b 7)
                                (cons (cons (sym-plus) (cons (sym-a) (cons (sym-b) ()))) ()))))))
        (call-native addr 0 0)))

    ;; Test (let ((a 10)) (let ((b 3)) (- a b))) - nested let, returns 7
    (defun test-native-let-nested ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (let ((a 10)) (let ((b 3)) (- a b)))
                    (cons (sym-let)
                          (cons (cons (cons (sym-a) (cons 10 ())) ())  ; ((a 10))
                                (cons (cons (sym-let)
                                            (cons (cons (cons (sym-b) (cons 3 ())) ())  ; ((b 3))
                                                  (cons (cons (sym-minus) (cons (sym-a) (cons (sym-b) ()))) ())))
                                      ()))))))
        (call-native addr 0 0)))

    ;; ================================================================
    ;; List Primitive Tests
    ;; ================================================================

    ;; Test (car (cons 3 7)) = 3
    (defun test-native-car ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (car (cons 3 7))
                    (cons (sym-car)
                          (cons (cons (sym-cons) (cons 3 (cons 7 ()))) ())))))
        (call-native addr 0 0)))

    ;; Test (cdr (cons 3 7)) = 7
    (defun test-native-cdr ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (cdr (cons 3 7))
                    (cons (sym-cdr)
                          (cons (cons (sym-cons) (cons 3 (cons 7 ()))) ())))))
        (call-native addr 0 0)))

    ;; Test (null ()) = t (non-zero)
    (defun test-native-null-t ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (null ()) - but we can't easily express nil, use (- 5 5) = 0
                    (cons (sym-null)
                          (cons (cons (sym-minus) (cons 5 (cons 5 ()))) ())))))
        (call-native addr 0 0)))

    ;; Test (null 5) = nil (0)
    (defun test-native-null-f ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (null 5)
                    (cons (sym-null) (cons 5 ())))))
        (call-native addr 0 0)))

    ;; Test (< 3 7) = t (non-zero)
    (defun test-native-lt-t ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-lt) (cons 3 (cons 7 ()))))))
        (call-native addr 0 0)))

    ;; Test (< 7 3) = nil (0)
    (defun test-native-lt-f ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-lt) (cons 7 (cons 3 ()))))))
        (call-native addr 0 0)))

    ;; Test (> 7 3) = t (non-zero)
    (defun test-native-gt-t ()
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-gt) (cons 7 (cons 3 ()))))))
        (call-native addr 0 0)))

    ;; ================================================================
    ;; Function Definition and Call Tests
    ;; ================================================================

    ;; Debug: test function registration and lookup
    (defun test-nfn-debug ()
      (init-nfntable)
      ;; Register a dummy function
      (nfn-define (sym-f) 12345)
      ;; Look it up
      (let ((addr (nfn-lookup (sym-f))))
        (if addr
            addr
            0)))  ; return 0 if not found

    ;; Test defun: define (double x) = (+ x x), call via compiled code
    ;; Expected: (double 7) = 14
    (defun test-native-defun ()
      (code-init)
      (init-nfntable)
      ;; First compile and register (defun double (x) (+ x x))
      (rt-compile-expr-env
        (cons (sym-defun)
              (cons (sym-f)  ; use 'f' as function name
                    (cons (cons (sym-x) ())  ; (x)
                          (cons (cons (sym-plus) (cons (sym-x) (cons (sym-x) ()))) ()))))  ; (+ x x)
        () 0)
      ;; Call function directly (this worked before: returns 14)
      (let ((fn-addr (nfn-lookup (sym-f))))
        (call-native fn-addr 7 0)))

    ;; Test defun with 2 params: (defun add (a b) (+ a b))
    ;; Expected: (add 5 8) = 13
    (defun test-native-defun2 ()
      (code-init)
      (init-nfntable)
      ;; Define (defun g (a b) (+ a b))
      (rt-compile-expr-env
        (cons (sym-defun)
              (cons (sym-g)  ; function name
                    (cons (cons (sym-a) (cons (sym-b) ()))  ; (a b)
                          (cons (cons (sym-plus) (cons (sym-a) (cons (sym-b) ()))) ()))))  ; (+ a b)
        () 0)
      ;; Call function directly with call-native
      (let ((fn-addr (nfn-lookup (sym-g))))
        (call-native fn-addr 5 8)))

    ;; Test calling function with expression args: (f (+ 3 4)) = (double 7) = 14
    (defun test-native-call-expr ()
      (code-init)
      (init-nfntable)
      ;; Define (defun f (x) (+ x x))
      (rt-compile-expr-env
        (cons (sym-defun)
              (cons (sym-f)
                    (cons (cons (sym-x) ())
                          (cons (cons (sym-plus) (cons (sym-x) (cons (sym-x) ()))) ()))))
        () 0)
      ;; Call (f (+ 3 4))
      (let ((call-addr (+ #x500008 (code-pos))))
        (rt-compile-expr-env
          (cons (sym-f) (cons (cons (sym-plus) (cons 3 (cons 4 ()))) ()))  ; (f (+ 3 4))
          () 0)
        (emit-ret)
        (call-native call-addr 0 0)))

    ;; Helper to print 4 hex digits
    (defun print-hex4 (v)
      (let ((c3 (logand (ash v -12) 15))
            (c2 (logand (ash v -8) 15))
            (c1 (logand (ash v -4) 15))
            (c0 (logand v 15)))
        (write-byte (if (< c3 10) (+ 48 c3) (+ 55 c3)))
        (write-byte (if (< c2 10) (+ 48 c2) (+ 55 c2)))
        (write-byte (if (< c1 10) (+ 48 c1) (+ 55 c1)))
        (write-byte (if (< c0 10) (+ 48 c0) (+ 55 c0)))))

    ;; Test native code generation
    (defun test-native ()
      (write-byte 78)  ; 'N'
      (write-byte 65)  ; 'A'
      (write-byte 84)  ; 'T'
      (write-byte 58)  ; ':'

      ;; Test 1: constant return
      (let ((r (test-native-const)))
        (if (eq r 100) (write-byte 49) (write-byte 33)))  ; '1' or '!'

      ;; Test 2: manual cons+car (should work) - car is 3, returns logical 3
      (write-byte 77)  ; 'M'
      (let ((r (test-native-cons-car-manual)))
        (write-byte 91)
        (print-hex4 r)
        (write-byte 93)
        (if (eq r 3) (write-byte 33) (write-byte 63)))  ; '!' if 3, '?' if wrong

      ;; Test 3: rt-compiled (car (cons 3 7)) = 3
      (write-byte 51)  ; '3'
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-car)
                          (cons (cons (sym-cons) (cons 3 (cons 7 ()))) ())))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 3) (write-byte 33) (write-byte 63))))  ; '!' if 3, '?' if wrong

      ;; Test 4: (and) = t (simplest case)
      (write-byte 65)  ; 'A' for and
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-and) ()))))  ; just (and) = t = 2
        (let ((r (call-native addr 0 0)))
          (if (eq r 1) (write-byte 33) (write-byte 63))))

      ;; Test 5: (and 1 2) = 2 (two args)
      (write-byte 97)  ; 'a' for and-two
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-and) (cons 1 (cons 2 ()))))))  ; (and 1 2) = 2
        (let ((r (call-native addr 0 0)))
          (if (eq r 2) (write-byte 33) (write-byte 63))))

      ;; Test 6: (or) = nil
      (write-byte 79)  ; 'O' for or
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-or) ()))))  ; (or) = nil
        (let ((r (call-native addr 0 0)))
          (if (eq r 0) (write-byte 33) (write-byte 63))))

      ;; Test 7: (or 5) = 5
      (write-byte 111)  ; 'o' for or-one
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-or) (cons 5 ())))))  ; (or 5) = 5
        (let ((r (call-native addr 0 0)))
          (if (eq r 5) (write-byte 33) (write-byte 63))))

      ;; Test 8: (listp nil) = t
      (write-byte 76)  ; 'L' for listp
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-listp) (cons 0 ())))))  ; 0 = nil
        (let ((r (call-native addr 0 0)))
          (if (> r 0) (write-byte 33) (write-byte 63))))

      ;; Test 9: (numberp 42) = t
      (write-byte 78)  ; 'N' for numberp
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-numberp) (cons 42 ())))))
        (let ((r (call-native addr 0 0)))
          (if (> r 0) (write-byte 33) (write-byte 63))))

      ;; Test 10: (and 1 2 3) = 3 (three args, last value)
      (write-byte 65)  ; 'A' for and-three
      (write-byte 51)  ; '3'
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-and) (cons 1 (cons 2 (cons 3 ())))))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 3) (write-byte 33) (write-byte 63))))

      ;; Test 11: (and 1 0 3) = 0 (short-circuit on false)
      (write-byte 65)  ; 'A' for and-short
      (write-byte 48)  ; '0'
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-and) (cons 1 (cons 0 (cons 3 ())))))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 0) (write-byte 33) (write-byte 63))))

      ;; Test 12: (or 0 0 5) = 5 (skip nils)
      (write-byte 79)  ; 'O' for or-skip
      (write-byte 53)  ; '5'
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-or) (cons 0 (cons 0 (cons 5 ())))))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 5) (write-byte 33) (write-byte 63))))

      ;; Test 13: (or 7 0) = 7 (short-circuit first non-nil)
      (write-byte 79)  ; 'O' for or-short
      (write-byte 55)  ; '7'
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-or) (cons 7 (cons 0 ()))))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 7) (write-byte 33) (write-byte 63))))

      ;; Test 14: (cond ((eq 1 2) 10) ((eq 1 1) 20)) = 20
      (write-byte 67)  ; 'C' for cond
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    ;; (cond ((eq 1 2) 10) ((eq 1 1) 20))
                    (cons (sym-cond)
                          (cons (cons (cons (sym-eq) (cons 1 (cons 2 ())))
                                      (cons 10 ()))
                                (cons (cons (cons (sym-eq) (cons 1 (cons 1 ())))
                                            (cons 20 ()))
                                      ()))))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 20) (write-byte 33) (write-byte 63))))

      ;; Test 15: (reverse (list 1 2)) = (2 1), check car = 2
      (write-byte 82)  ; 'R' for reverse
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-car)
                          (cons (cons (sym-reverse)
                                      (cons (cons (sym-list) (cons 1 (cons 2 ()))) ()))
                                ())))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 2) (write-byte 33) (write-byte 63))))

      ;; Test 16: (car (append (list 1) (list 2 3))) = 1
      (write-byte 80)  ; 'P' for aPPend
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-car)
                          (cons (cons (sym-append)
                                      (cons (cons (sym-list) (cons 1 ()))
                                            (cons (cons (sym-list) (cons 2 (cons 3 ()))) ())))
                                ())))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 1) (write-byte 33) (write-byte 63))))

      ;; Test 17: (cadr (append (list 1) (list 2 3))) = 2
      (write-byte 112)  ; 'p' for append second elem
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-cadr)
                          (cons (cons (sym-append)
                                      (cons (cons (sym-list) (cons 1 ()))
                                            (cons (cons (sym-list) (cons 2 (cons 3 ()))) ())))
                                ())))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 2) (write-byte 33) (write-byte 63))))

      ;; Test 18: (car (member 2 (list 1 2 3))) = 2
      (write-byte 77)  ; 'M' for member
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-car)
                          (cons (cons (sym-member)
                                      (cons 2 (cons (cons (sym-list) (cons 1 (cons 2 (cons 3 ())))) ())))
                                ())))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 2) (write-byte 33) (write-byte 63))))

      ;; Test 19: (member 5 (list 1 2 3)) = nil
      (write-byte 109)  ; 'm' for member-nil
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-member)
                          (cons 5 (cons (cons (sym-list) (cons 1 (cons 2 (cons 3 ())))) ()))))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 0) (write-byte 33) (write-byte 63))))

      ;; Test 20: (cdr (assoc 2 (list (cons 1 10) (cons 2 20)))) = 20
      (write-byte 83)  ; 'S' for aSSoc
      (code-init)
      (let ((addr (rt-compile-lambda
                    ()
                    (cons (sym-cdr)
                          (cons (cons (sym-assoc)
                                      (cons 2
                                            (cons (cons (sym-list)
                                                        (cons (cons (sym-cons) (cons 1 (cons 10 ())))
                                                              (cons (cons (sym-cons) (cons 2 (cons 20 ()))) ())))
                                                  ())))
                                ())))))
        (let ((r (call-native addr 0 0)))
          (if (eq r 20) (write-byte 33) (write-byte 63))))

      ;; Test 21: NESTED FUNCTION CALL (direct call-native)
      ;; Define k that returns 42, define j that calls k
      ;; (j) should return 42
      (write-byte 10)
      (write-byte 78)  ; 'N' for Nested
      (write-byte 69)  ; 'E'
      (write-byte 83)  ; 'S'
      (write-byte 84)  ; 'T'
      (write-byte 58)  ; ':'
      (code-init)
      (init-nfntable)
      ;; Define k: (defun k () 42)
      (rt-compile-defun (cons (sym-k)
                              (cons ()  ; no params
                                    (cons 42 ()))))  ; body = 42
      ;; Define j: (defun j () (k))
      (rt-compile-defun (cons (sym-j)
                              (cons ()  ; no params
                                    (cons (cons (sym-k) ()) ()))))  ; body = (k)
      ;; Now call j via call-native (DIRECT)
      (let ((j-addr (nfn-lookup (sym-j))))
        (write-byte 64)  ; '@'
        (print-hex16 j-addr)
        (let ((r (call-native j-addr 0 0)))
          (write-byte 61)  ; '='
          (print-hex16 r)
          (if (eq r 42)
              (write-byte 33)    ; '!' = success
              (write-byte 63)))) ; '?' = fail

      ;; Test 22: NESTED FUNCTION CALL (via native-eval, like REPL)
      ;; Same as test 21 but use native-eval to call (j)
      (write-byte 10)
      (write-byte 78)  ; 'N' for Nested
      (write-byte 50)  ; '2'
      (write-byte 58)  ; ':'
      (code-init)
      (init-nfntable)
      ;; Define k: (defun k () 77)
      (native-eval (cons (sym-defun) (cons (sym-k)
                              (cons ()  ; no params
                                    (cons 77 ())))))  ; body = 77
      ;; Define j: (defun j () (k))
      (native-eval (cons (sym-defun) (cons (sym-j)
                              (cons ()  ; no params
                                    (cons (cons (sym-k) ()) ())))))  ; body = (k)
      ;; Now call (j) via native-eval (like REPL would)
      (let ((r (native-eval (cons (sym-j) ()))))  ; (j)
        (write-byte 61)  ; '='
        (print-hex16 r)
        (if (eq r 77)
            (write-byte 33)    ; '!' = success
            (write-byte 63)))  ; '?' = fail

      (write-byte 10)
      (write-byte 79)  ; 'O'
      (write-byte 75)) ; 'K'

    ;; Manual cons + car sequence that works
    (defun test-native-cons-car-manual ()
      (code-init)
      ;; mov rax, 6 (car = 3 tagged)
      (emit-mov-rax-imm64 6)
      (emit-push-rax)
      ;; mov rax, 14 (cdr = 7 tagged)
      (emit-mov-rax-imm64 14)
      (emit-push-rax)
      ;; mov rax, r12
      (code-emit #x4C) (code-emit #x89) (code-emit #xE0)
      ;; add r12, 16
      (code-emit #x49) (code-emit #x83) (code-emit #xC4) (code-emit #x10)
      ;; pop rcx (cdr)
      (code-emit #x59)
      ;; pop rdx (car)
      (code-emit #x5A)
      ;; mov [rax], rdx
      (emit-rex-w) (code-emit #x89) (code-emit #x10)
      ;; mov [rax+8], rcx
      (emit-rex-w) (code-emit #x89) (code-emit #x48) (code-emit #x08)
      ;; or rax, 1
      (emit-rex-w) (code-emit #x83) (code-emit #xC8) (code-emit #x01)
      ;; lea rax, [rax-1]
      (emit-rex-w) (code-emit #x8D) (code-emit #x40) (code-emit #xFF)
      ;; mov rax, [rax]
      (emit-rex-w) (code-emit #x8B) (code-emit #x00)
      ;; ret
      (emit-ret)
      (call-native #x500008 0 0))

    ;; ================================================================
    ;; Networking / Crypto / SSH: loaded from net/ files
    ;; (see build-kernel-mvm for shared source loading)
    ;; ================================================================

    ;; ================================================================
    ;; Phase 9: SMP (Symmetric Multi-Processing)
    ;; ================================================================
    ;;
    ;; Per-CPU data at 0x360000 (64 bytes per CPU, max 8 CPUs):
    ;;   +0x00  current-actor   u64
    ;;   +0x08  reduction-ctr   u64
    ;;   +0x10  cpu-index       u64  (0=BSP, 1..7=APs)
    ;;   +0x18  apic-id         u64
    ;;   +0x20  idle-flag       u64  (1=idle)
    ;;   +0x28  reserved
    ;;   +0x30  reserved
    ;;   +0x38  reserved
    ;;
    ;; AP kernel stacks (16KB each):
    ;;   CPU 1: 0x362000-0x366000 (top at 0x366000)
    ;;   CPU 2: 0x366000-0x36A000 (top at 0x36A000)
    ;;   ...
    ;;
    ;; LAPIC MMIO at 0xFEE00000 (identity-mapped by page tables)
    ;; Trampoline at 0x8000 (copied at runtime from kernel image)

    ;; Read LAPIC register (32-bit MMIO)
    (defun lapic-read (offset)
      (logand (mem-ref (+ #xFEE00000 offset) :u32) #xFFFFFFFF))

    ;; Write LAPIC register (32-bit MMIO)
    (defun lapic-write (offset value)
      (setf (mem-ref (+ #xFEE00000 offset) :u32) value))

    ;; Get this CPU's APIC ID (from LAPIC register 0x20, bits 24-31)
    (defun lapic-id ()
      (ash (lapic-read #x20) -24))

    ;; Enable local APIC via Spurious Interrupt Vector Register
    ;; Set bit 8 (APIC enable) and vector 0xFF
    (defun lapic-enable ()
      (lapic-write #xF0 (logior (lapic-read #xF0) #x1FF)))

    ;; Configure LAPIC periodic timer for preemptive multitasking.
    ;; Timer fires at ~50-100 Hz, zeroing the per-CPU reduction counter.
    ;; This forces the next loop iteration to call yield, preempting the actor.
    ;; Must be called on each CPU after lapic-enable.
    (defun lapic-timer-init ()
      ;; Divide configuration: divide by 128 (value 0x0A)
      (lapic-write #x3E0 #x0A)
      ;; LVT Timer: periodic mode (bit 17) + vector 0x30
      (lapic-write #x320 (logior #x20000 #x30))
      ;; Initial count: ~10M cycles → roughly 50-100 Hz at QEMU's bus freq
      (lapic-write #x380 10000000))

    ;; I/O delay: ~10ms (10000 reads of port 0x80, each ~1µs)
    (defun smp-delay-10ms ()
      (let ((i 0))
        (loop
          (if (>= i 10000)
              (return 0)
              (progn (io-in-byte #x80) (setq i (+ i 1)))))))

    ;; I/O delay: ~200µs (200 reads of port 0x80)
    (defun smp-delay-200us ()
      (let ((i 0))
        (loop
          (if (>= i 200)
              (return 0)
              (progn (io-in-byte #x80) (setq i (+ i 1)))))))

    ;; ---- Real-Time Clock (CMOS RTC) ----
    ;; Standard PC CMOS RTC at I/O ports 0x70 (index) and 0x71 (data).
    ;; Registers: 0=sec, 2=min, 4=hr, 7=day, 8=month, 9=year, 0x32=century.
    ;; Values are BCD; convert via truncate/16 for high digit, logand/15 for low.
    ;; Each function inlines the port I/O with constant register numbers to
    ;; avoid MVM compiler limitations with variable io-out-byte arguments.

    (defun rtc-seconds ()
      (io-out-byte #x70 0)
      (let ((b (io-in-byte #x71)))
        (+ (* (truncate b 16) 10) (logand b 15))))

    (defun rtc-minutes ()
      (io-out-byte #x70 2)
      (let ((b (io-in-byte #x71)))
        (+ (* (truncate b 16) 10) (logand b 15))))

    (defun rtc-hours ()
      (io-out-byte #x70 4)
      (let ((b (io-in-byte #x71)))
        (+ (* (truncate b 16) 10) (logand b 15))))

    (defun rtc-day ()
      (io-out-byte #x70 7)
      (let ((b (io-in-byte #x71)))
        (+ (* (truncate b 16) 10) (logand b 15))))

    (defun rtc-month ()
      (io-out-byte #x70 8)
      (let ((b (io-in-byte #x71)))
        (+ (* (truncate b 16) 10) (logand b 15))))

    (defun rtc-year ()
      (io-out-byte #x70 #x32)
      (let ((century (io-in-byte #x71)))
        (io-out-byte #x70 9)
        (let ((yr (io-in-byte #x71)))
          (+ (* (+ (* (truncate century 16) 10) (logand century 15)) 100)
             (+ (* (truncate yr 16) 10) (logand yr 15))))))

    ;; Print 2-digit number with leading zero
    (defun print-2digit (n)
      (write-byte (+ (truncate n 10) 48))
      (write-byte (+ (mod n 10) 48)))

    ;; Print "YYYY-MM-DD HH:MM:SS"
    (defun print-time ()
      (print-dec (rtc-year))
      (write-byte 45)
      (print-2digit (rtc-month))
      (write-byte 45)
      (print-2digit (rtc-day))
      (write-byte 32)
      (print-2digit (rtc-hours))
      (write-byte 58)
      (print-2digit (rtc-minutes))
      (write-byte 58)
      (print-2digit (rtc-seconds)))

    ;; Leap year check (works for 1970-2099; 2000 is leap)
    (defun is-leap-year (y)
      (zerop (logand y 3)))

    ;; Days in month (1-12)
    (defun days-in-month (m y)
      (if (eq m 2) (if (is-leap-year y) 29 28)
      (if (eq m 4) 30
      (if (eq m 6) 30
      (if (eq m 9) 30
      (if (eq m 11) 30
      31))))))

    ;; Unix timestamp: seconds since 1970-01-01 00:00:00 UTC
    (defun unix-time ()
      (let ((sec (rtc-seconds))
            (min (rtc-minutes))
            (hr  (rtc-hours))
            (day (rtc-day))
            (mon (rtc-month))
            (yr  (rtc-year)))
        ;; Accumulate days from epoch
        (let ((days 0)
              (y 1970))
          (loop
            (if (>= y yr) (return 0)
                (progn
                  (setq days (+ days (if (is-leap-year y) 366 365)))
                  (setq y (+ y 1)))))
          ;; Add days for completed months this year
          (let ((m 1))
            (loop
              (if (>= m mon) (return 0)
                  (progn
                    (setq days (+ days (days-in-month m yr)))
                    (setq m (+ m 1))))))
          ;; Total seconds
          (let ((total (* (+ days (- day 1)) 86400)))
            (setq total (+ total (* hr 3600)))
            (setq total (+ total (* min 60)))
            (+ total sec)))))

    ;; Copy AP trampoline from kernel image to 0x8000
    ;; The trampoline is embedded at a fixed offset in the kernel image.
    ;; Kernel is loaded at 0x100000, trampoline offset stored at 0x300010.
    (defun smp-copy-trampoline ()
      (let ((src (mem-ref #x300010 :u64))
            (i 0))
        (if (zerop src)
            0  ;; No trampoline source — skip copy
            (loop
              (if (>= i 256)
                  (return 0)
                  (progn
                    (setf (mem-ref (+ #x8000 i) :u8)
                          (mem-ref (+ src i) :u8))
                    (setq i (+ i 1))))))))

    ;; Fill trampoline parameters at 0x8000
    ;; Values are stored RAW (not tagged) because the trampoline reads them
    ;; as hardware addresses. Use :u32 (which auto-untags) for CR3,
    ;; and (untag x) wrapper for 64-bit values.
    ;; Fill trampoline parameters at 0x8000
    ;; Entry address (0x80F0) is pre-patched at build time into trampoline data,
    ;; so it's already correct after smp-copy-trampoline. Only fill CR3, stack, flag.
    (defun smp-fill-params (stack-top)
      (setf (mem-ref #x80E0 :u32) #x380000)       ; CR3 low (u32 auto-untags)
      (setf (mem-ref #x80E4 :u32) 0)              ; CR3 high
      (setf (mem-ref #x80E8 :u64) (untag stack-top))   ; per-AP stack (raw)
      (setf (mem-ref #x80F8 :u32) 0)              ; alive flag = 0
      (setf (mem-ref #x80FC :u32) 0))             ; alive flag high

    ;; Send targeted INIT-SIPI-SIPI to a specific AP by APIC ID.
    ;; ICR high (0x310) bits 24-31 = destination APIC ID.
    ;; ICR low (0x300): shorthand=00 (use destination field).
    ;; 0x00004500 = INIT, 0x00004608 = SIPI vector=0x08 (addr 0x8000).
    (defun smp-send-sipi-targeted (apic-id)
      (lapic-write #x310 (ash apic-id 24))
      (lapic-write #x300 #x00004500)       ; INIT to specific AP
      (smp-delay-10ms)
      (lapic-write #x310 (ash apic-id 24))
      (lapic-write #x300 #x00004608)       ; SIPI, vector=0x08
      (smp-delay-200us)
      (lapic-write #x310 (ash apic-id 24))
      (lapic-write #x300 #x00004608))      ; Second SIPI

    ;; Wait for AP alive flag at 0x80F8. Returns 1 if alive, 0 if timeout.
    (defun smp-wait-alive ()
      (let ((j 0))
        (loop
          (if (not (zerop (mem-ref #x80F8 :u64)))
              (return 1)
              (if (< j 20000)
                  (progn (pause) (setq j (+ j 1)))
                  (return 0))))))

    ;; Boot a single AP: fill trampoline params, send INIT-SIPI-SIPI, wait.
    ;; Returns 1 if AP responded, 0 if timeout.
    (defun smp-boot-ap (apic-id stack-top)
      (smp-fill-params stack-top)
      (smp-send-sipi-targeted apic-id)
      (smp-wait-alive))

    ;; AP entry point (64-bit, called by trampoline)
    ;; This runs on the AP with its own stack.
    ;; It prints a message to serial and loops forever (Phase 9.3 adds scheduler).
    (defun ap-entry ()
      (lapic-enable)
      ;; Set up GS base for per-CPU data FIRST (before any percpu operations)
      (let ((apic (lapic-id)))
        (let ((percpu-base (+ #x360000 (* apic 64))))
          ;; Set GS base so percpu-ref/percpu-set work on this CPU
          (set-gs-base percpu-base)
          ;; Print "AP" + CPU number + newline
          (write-byte 65)  ; 'A'
          (write-byte 80)  ; 'P'
          (write-byte (+ 48 apic))  ; '0' + APIC ID
          (write-byte 10)  ; newline
          ;; Store our CPU info via direct mem-ref (GS is also set now)
          (setf (mem-ref (+ percpu-base 16) :u64) apic)   ; cpu-index
          (setf (mem-ref (+ percpu-base 24) :u64) apic)   ; apic-id
          (setf (mem-ref (+ percpu-base 32) :u64) 1)      ; idle=true
          ;; Per-CPU idle stack top: 0x352000 + (apic_id + 1) * 0x1000
          (setf (mem-ref (+ percpu-base 56) :u64) (+ #x352000 (ash (+ apic 1) 12)))
          ;; Initialize per-CPU reduction counter
          (percpu-set 8 4000)))
      ;; Load IDT (shared with BSP, descriptor at 0x391000)
      (lidt #x391000)
      (lapic-timer-init)
      ;; Enable interrupts so IPI can wake us from HLT
      (sti)
      ;; Enter scheduler loop (never returns)
      (ap-scheduler))

    ;; Validate an actor's save area before restore-context.
    ;; Checks that the continuation address (actor struct +0x30) is within
    ;; the kernel code range (>= 0x100000). If invalid, prints '!' and halts.
    ;; The continuation is stored as a raw code address (not tagged).
    (defun validate-actor (id)
      (let ((cont (actor-get id #x30)))
        (let ((min-addr (untag #x100000)))
          (if (< cont min-addr)
              (progn
                (write-byte 33)   ; '!'
                (write-byte 10)   ; newline
                (cli) (hlt))
              0))))

    ;; AP scheduler: dequeue actors from run queue and run them.
    ;; When no work available, HLT and wait for IPI wakeup.
    ;; Called from ap-entry and from actor-exit when no next actor.
    ;; This is an infinite loop — the caller's stack doesn't matter since
    ;; restore-context will load the actor's own stack.
    (defun ap-scheduler ()
      ;; CRITICAL: Switch to per-CPU idle stack BEFORE doing anything else.
      ;; Without this, ap-scheduler runs on whatever stack the caller used
      ;; (e.g., a dead actor's stack or the BSP kernel stack). If that actor's
      ;; context is later restored on a DIFFERENT CPU, two CPUs share the same
      ;; stack, causing corruption (e.g., IPI handler's IRETQ frame overwritten).
      (switch-idle-stack)
      ;; No actor running on this CPU
      (percpu-set 0 0)
      (loop
        ;; CLI first: disable interrupts so IPI stays pending.
        ;; THEN set idle flag. This ordering is critical: if idle is set
        ;; before CLI, an IPI can be consumed in the window, and the
        ;; subsequent STI-HLT will sleep forever.
        (cli)
        (percpu-set 32 1)
        (spin-lock #x360400)
        (let ((next-id (actor-dequeue)))
          (if (zerop next-id)
              ;; Nothing to do: unlock, then atomic STI+HLT.
              ;; x86 guarantees STI enables interrupts only after the next
              ;; instruction, so STI;HLT is atomic: a pending IPI causes
              ;; HLT to return immediately instead of sleeping forever.
              (progn
                (spin-unlock #x360400)
                (sti-hlt))
              ;; Got work! Set up and switch to the actor.
              ;; Lock is held through restore-context which releases it
              ;; AFTER switching RSP. This prevents the race where another
              ;; CPU dequeues an actor while we're still on its stack.
              (progn
                (percpu-set 32 0)             ; not idle
                (percpu-set 0 next-id)        ; current actor
                (actor-set next-id #x00 1)    ; mark running
                ;; Load actor's object heap state
                (percpu-set 40 (actor-get next-id #x70))
                (percpu-set 48 (actor-get next-id #x78))
                ;; restore-context switches RSP, unlocks, STI, then JMPs
                (let ((next-addr (actor-struct-addr next-id)))
                  (restore-context (+ next-addr #x08))))))))

    ;; Master SMP initialization (called by BSP at boot)
    ;; Boots APs sequentially (1 through 7), stops at first non-responding AP.
    ;; Stores total CPU count at 0x360420.
    (defun smp-init ()
      ;; Set GS base for BSP's per-CPU data FIRST
      ;; This must happen before any percpu-ref/percpu-set operations
      (write-byte 97)  ;; 'a' - before set-gs-base
      (set-gs-base #x360000)
      ;; Enable BSP's local APIC
      (write-byte 98)  ;; 'b' - before lapic-enable
      (lapic-enable)
      (write-byte 99)  ;; 'c' - before lapic-timer-init
      (lapic-timer-init)
      (write-byte 100) ;; 'd' - before per-CPU stores
      ;; Initialize per-CPU data for BSP (CPU 0) via direct mem-ref
      (setf (mem-ref #x360000 :u64) 0)              ; current-actor = 0 (set later by actor-init)
      (setf (mem-ref #x360008 :u64) 0)              ; reduction-ctr (set later by actor-init)
      (setf (mem-ref #x360010 :u64) 0)              ; cpu-index = 0
      (setf (mem-ref #x360018 :u64) (lapic-id))     ; apic-id
      (setf (mem-ref #x360020 :u64) 0)              ; idle = false (BSP is active)
      ;; Per-CPU idle stack top: each CPU gets its own 4KB stack for ap-scheduler
      ;; to prevent two CPUs from sharing an actor stack when one blocks.
      ;; Layout: CPU N idle stack top = 0x352000 + (N+1) * 0x1000
      (setf (mem-ref #x360038 :u64) #x353000)      ; CPU 0 (BSP) idle stack top
      (write-byte 101) ;; 'e' - before percpu-set
      ;; Initialize per-CPU obj-alloc/obj-limit with boot-time values
      ;; (will be overwritten by actor-init with per-actor values)
      (percpu-set 40 (untag #x04800000))            ; obj-alloc (boot value)
      (percpu-set 48 (untag #x04C00000))            ; obj-limit (boot value)
      (write-byte 102) ;; 'f' - before smp-copy-trampoline
      ;; Copy trampoline to 0x8000 (once, reused for each AP)
      (smp-copy-trampoline)
      (write-byte 103) ;; 'g' - after trampoline copy
      ;; Clear 0x300010 after use — this address is shared with the reader's
      ;; lookahead buffer. Leaving the trampoline address here causes the reader
      ;; to see a stale lookahead byte on the first REPL call.
      (setf (mem-ref #x300010 :u64) 0)
      (write-byte 104) ;; 'h' - before AP boot
      ;; Skip AP boot for now - just set CPU count to 1
      (setf (mem-ref #x360420 :u64) 1)
      (write-byte 105) ;; 'i' - after skip
      ;; Print "SMP1"
      (write-byte 83)  ; 'S'
      (write-byte 77)  ; 'M'
      (write-byte 80)  ; 'P'
      (write-byte 49)  ; '1'
      (write-byte 10)
      1)

    ;; Shutdown: try QEMU ISA debug exit (port 0xf4), then ACPI, then spin
    (defun halt ()
      (write-byte 66) (write-byte 121) (write-byte 101) (write-byte 10) ; "Bye\n"
      (io-out-dword #xf4 #x00)         ; ISA debug exit (QEMU exits immediately)
      (io-out-dword #x604 #x2000)      ; ACPI PIIX4 S5 shutdown fallback
      (io-out-dword #xB004 #x2000)     ; Older QEMU ACPI shutdown
      (loop))

    (defun quit ()
      (halt))

    ;; ================================================================
    ;; Phase 9.2: Per-CPU data, Spinlocks
    ;; ================================================================
    ;;
    ;; Per-CPU data accessed via GS segment (IA32_GS_BASE MSR).
    ;; BSP: GS base = 0x360000, AP1: 0x360040, AP2: 0x360080, etc.
    ;; Per-CPU struct (64 bytes):
    ;;   +0x00  current-actor   (tagged, actor ID running on this CPU)
    ;;   +0x08  reduction-ctr   (tagged, preemption counter)
    ;;   +0x10  cpu-index       (tagged)
    ;;   +0x18  apic-id         (tagged)
    ;;   +0x20  idle-flag       (tagged, 1=idle)
    ;;
    ;; Lock addresses (global, not per-CPU):
    ;;   0x360400  run-queue lock
    ;;   0x360408  mailbox-pool lock
    ;;   0x360410  actor-table lock

    ;; Set GS base MSR to addr (for per-CPU data access)
    ;; IA32_GS_BASE = MSR 0xC0000101
    ;; addr is a tagged fixnum representing a physical address
    (defun set-gs-base (addr)
      (wrmsr #xC0000101 (logand addr #xFFFFFFFF) (ash addr -32)))

    ;; Get current CPU index from per-CPU data
    (defun cpu-id ()
      (percpu-ref 16))

    ;; Spinlock: acquire lock at addr using atomic exchange.
    ;; Lock holds 0 (free) or 2 (held, tagged 1).
    ;; Spins with PAUSE hint until lock is acquired.
    (defun spin-lock (addr)
      (loop
        (if (zerop (xchg-mem addr 1))
            ;; Got the lock (old value was 0)
            (return 0)
            ;; Lock was held, spin-read until it looks free
            (loop
              (if (zerop (mem-ref addr :u64))
                  ;; Looks free, break inner loop to retry xchg
                  (return 0)
                  (pause))))))

    ;; Release spinlock at addr
    (defun spin-unlock (addr)
      (mfence)
      (setf (mem-ref addr :u64) 0))

    ;; ================================================================
    ;; Phase 9.4: IPI Wakeup
    ;; ================================================================

    ;; Send IPI (Inter-Processor Interrupt) to target CPU.
    ;; Vector 0x40 = wake from HLT (IDT handler is just IRETQ).
    ;; LAPIC ICR: write destination APIC ID to high register first,
    ;; then write command to low register (triggers the send).
    (defun send-ipi (target-apic-id)
      ;; ICR high [0xFEE00310]: destination APIC ID in bits 31:24
      (lapic-write #x310 (ash target-apic-id 24))
      ;; ICR low [0xFEE00300]: vector=0x40, delivery=fixed(000),
      ;; level=assert(1), trigger=edge(0), shorthand=none(00)
      ;; = 0x00004040
      (lapic-write #x300 #x4040))

    ;; Scan APs 1..ncpu-1 for an idle one. Returns APIC ID if found, 0 if none.
    ;; Idle flag for CPU i is at 0x360020 + i*64 (per-CPU base + 0x20).
    (defun wake-idle-ap-check (ncpu)
      (let ((i 1))
        (loop
          (if (>= i ncpu)
              (return 0)
              (if (not (zerop (mem-ref (+ #x360020 (* i 64)) :u64)))
                  (return i)
                  (setq i (+ i 1)))))))

    ;; Wake an idle CPU if one exists. Called after enqueuing work.
    ;; Scans all APs first (prefer waking APs over BSP), then checks BSP.
    ;; CPU count stored at 0x360420 by smp-init.
    (defun wake-idle-ap ()
      (let ((ncpu (mem-ref #x360420 :u64)))
        (let ((idle-ap (wake-idle-ap-check ncpu)))
          (if (not (zerop idle-ap))
              (send-ipi idle-ap)
              ;; No idle AP — check BSP
              (if (not (zerop (mem-ref #x360020 :u64)))
                  (send-ipi 0)
                  0)))))

    ;; ================================================================
    ;; Phase 8: Actor Model
    ;; ================================================================
    ;;
    ;; Actor table at 0x05100000 (128 bytes per actor, max 64 actors)
    ;; Scheduler state at 0x05102000
    ;; Per-actor stacks at 0x05200000 (64KB each)
    ;; Actor IDs are 1-based (0 = "no actor" sentinel for run queue)
    ;; Actor 1 = primordial (REPL/SSH), uses existing heap + stack
    ;; New actors (2+) get their own stacks; heap is shared for now (Phase 8.4 splits it)
    ;;
    ;; Actor struct layout (128 bytes):
    ;;   +0x00  status       u64  (0=free, 1=running, 2=ready, 3=dead)
    ;;   +0x08  saved RSP    u64
    ;;   +0x10  saved R12    u64  (cons alloc pointer)
    ;;   +0x18  saved R14    u64  (cons alloc limit)
    ;;   +0x20  saved RBX    u64
    ;;   +0x28  saved RBP    u64
    ;;   +0x30  entry-fn     u64  (function address / continuation RIP)
    ;;   +0x38  actor-id     u64
    ;;   +0x40  name         u64  (for debugging)
    ;;   +0x48  next-in-queue u64  (next actor ID in run queue, 0=none)
    ;;   +0x50  mailbox-head  u64  (tagged cons ptr, 0=empty)
    ;;   +0x58  mailbox-tail  u64  (tagged cons ptr, 0=empty)
    ;;   +0x60  linked-actor  u64  (ID of linked actor, 0=none)
    ;;   +0x68  (reserved)
    ;;   +0x70  obj-alloc     u64  (saved GS:[0x28] per-actor object alloc ptr)
    ;;   +0x78  obj-limit     u64  (saved GS:[0x30] per-actor object alloc limit)
    ;;
    ;; Scheduler state at 0x05102000:
    ;;   +0x00  current-actor   u64  (ID of running actor)
    ;;   +0x08  actor-count     u64  (total allocated actors)
    ;;   +0x10  run-head        u64  (first ready actor ID, 0=none)
    ;;   +0x18  initialized     u64  (1 if actor system is active)
    ;;
    ;; Run queue: simple linked list via actor struct +0x48 (next-in-queue)

    ;; Address of actor struct for actor N
    (defun actor-struct-addr (id)
      (+ #x05100000 (* id 128)))

    ;; Read a field from actor struct
    (defun actor-get (id offset)
      (mem-ref (+ (actor-struct-addr id) offset) :u64))

    ;; Write a field to actor struct
    (defun actor-set (id offset val)
      (setf (mem-ref (+ (actor-struct-addr id) offset) :u64) val))

    ;; Stack top for actor N (each gets 64KB, stack grows down)
    (defun actor-stack-top (id)
      (+ #x05200000 (* (+ id 1) #x10000)))

    ;; Initialize the actor system
    ;; Actor IDs are 1-based (0 = "no actor" sentinel for run queue)
    ;; Primordial actor (REPL) gets ID 1
    (defun actor-init ()
      ;; Zero actor table (64 * 128 = 8192 bytes)
      (let ((i 0))
        (loop
          (when (>= i 8192) (return 0))
          (setf (mem-ref (+ #x05100000 i) :u64) 0)
          (setq i (+ i 8))))
      ;; Zero scheduler state (shared globals)
      (setf (mem-ref #x05102008 :u64) 2)  ; actor-count = 2 (next available)
      (setf (mem-ref #x05102010 :u64) 0)  ; run-head = none
      (setf (mem-ref #x05102018 :u64) 0)  ; initialized = 0 (set AFTER per-CPU setup)
      ;; Per-CPU: current-actor = 1 (primordial), reduction counter
      (percpu-set 0 1)              ; current-actor = actor 1
      (percpu-set 8 4000)           ; reduction counter: tagged 2000 = 4000
      ;; Zero lock variables
      (setf (mem-ref #x360400 :u64) 0)   ; scheduler/run-queue lock
      (setf (mem-ref #x360408 :u64) 0)   ; reserved
      (setf (mem-ref #x360410 :u64) 0)   ; reserved
      ;; NOW set initialized flag (after per-CPU setup is done)
      (setf (mem-ref #x05102018 :u64) 1)  ; initialized = 1
      ;; Initialize mailbox shared pool
      (pool-init)
      ;; Set up actor 1 (primordial)
      ;; Status = 1 (running), registers will be saved on first yield
      (actor-set 1 #x00 1)   ; status = running
      (actor-set 1 #x38 1)   ; actor-id = 1
      ;; Initialize per-actor heap for actor 1
      ;; heap_base = 0x06000000 + (id-1) * 0x100000 = 0x06000000
      ;; Cons space A: 0x06000000 - 0x06040000 (256KB)
      ;; Cons space B: 0x06040000 - 0x06080000 (256KB)
      ;; Object space: 0x06080000 - 0x060C0000 (256KB)
      ;; Store obj-alloc and obj-limit in actor struct (+0x70/+0x78)
      ;; These are used as initial values AND updated by save-context
      (actor-set 1 #x70 (untag #x06080000))  ; obj-alloc (raw addr)
      (actor-set 1 #x78 (untag #x060C0000))  ; obj-limit (raw addr)
      ;; Switch R12/R14 to actor 1's per-actor heap
      (set-alloc-ptr #x06000000)
      (set-alloc-limit #x06040000)
      ;; Update per-CPU obj alloc metadata for actor 1
      (percpu-set 40 (untag #x06080000))  ; obj alloc ptr
      (percpu-set 48 (untag #x060C0000))  ; obj limit
      ;; Print "ACT" to confirm initialization
      (write-byte 65) (write-byte 67) (write-byte 84) (write-byte 10))

    ;; Spawn a new actor that will run function fn
    ;; fn is a tagged function address (from nfn-lookup or similar)
    ;; Returns the new actor's ID
    ;; SMP: Scheduler lock protects actor count + struct setup + enqueue.
    (defun actor-spawn (fn)
      (spin-lock #x360400)
      (let ((count (mem-ref #x05102008 :u64)))
        (if (>= count 64)
            (progn
              (spin-unlock #x360400)
              (write-byte 33)  ; '!' - too many actors
              0)
            (let ((id count))
              ;; Bump actor count
              (setf (mem-ref #x05102008 :u64) (+ count 1))
              ;; Initialize actor struct
              (actor-set id #x00 2)    ; status = ready
              (actor-set id #x38 id)   ; actor-id
              ;; Set up stack: only actor-exit on the stack.
              ;; restore-context uses JMP to the entry fn (stored in save area),
              ;; not RET. When the entry fn returns, its RET pops actor-exit.
              ;; Stack layout (grows down):
              ;;   [stack-top - 8]:  actor-exit addr  (fn's RET pops this)
              (let ((stack-top (actor-stack-top id)))
                (let ((exit-addr (nfn-lookup (hash-of "actor-exit"))))
                  (let ((rsp (- stack-top 8)))
                    (setf (mem-ref (- stack-top 8) :u64) (untag exit-addr))
                    ;; Save initial register state (must be RAW, not tagged)
                    (actor-set id #x08 (untag rsp))             ; RSP
                    ;; Per-actor heap: compute heap_base = 0x06000000 + (id-1)*0x100000
                    ;; Using ash since 0x100000 = 2^20
                    (let ((heap-base (+ #x06000000 (ash (- id 1) 20))))
                      ;; R12 = cons from-space start (raw)
                      (actor-set id #x10 (untag heap-base))
                      ;; R14 = cons from-space limit (raw)
                      (actor-set id #x18 (untag (+ heap-base #x40000)))
                      ;; obj-alloc and obj-limit (raw) at +0x70/+0x78
                      ;; These serve as initial values AND are updated by save-context
                      ;; restore-context reads them back into GS:[0x28]/GS:[0x30]
                      (actor-set id #x70 (untag (+ heap-base #x80000)))
                      (actor-set id #x78 (untag (+ heap-base #xC0000))))
                    (actor-set id #x20 0)     ; RBX = 0
                    (actor-set id #x28 0)     ; RBP = 0
                    ;; Store entry function in continuation field (save_area+40 = struct+0x30)
                    ;; restore-context JMPs to this address
                    (actor-set id #x30 (untag fn)))))
              ;; Add to run queue (no internal lock - we hold it)
              (actor-enqueue id)
              (spin-unlock #x360400)
              ;; Wake idle AP to pick up the new actor
              (wake-idle-ap)
              id))))

    ;; Add actor to run queue tail
    (defun actor-enqueue (id)
      (actor-set id #x48 0)  ; next = none
      (let ((head (mem-ref #x05102010 :u64)))
        (if (zerop head)
            ;; Empty queue, this becomes the head
            (setf (mem-ref #x05102010 :u64) id)
            ;; Walk to end and append
            (let ((cur head))
              (loop
                (let ((next (actor-get cur #x48)))
                  (when (zerop next)
                    (actor-set cur #x48 id)
                    (return 0))
                  (setq cur next)))))))

    ;; Remove and return first actor from run queue (0 if empty)
    (defun actor-dequeue ()
      (let ((head (mem-ref #x05102010 :u64)))
        (if (zerop head)
            0
            ;; Remove head, set next as new head
            (let ((next (actor-get head #x48)))
              (setf (mem-ref #x05102010 :u64) next)
              (actor-set head #x48 0)
              head))))

    ;; Yield: save current actor, switch to next ready actor
    ;; This is the core cooperative context switch.
    ;; Uses save-context as setjmp: returns 0 on save, nonzero on resume.
    ;; When called, saves current state and switches to the next actor.
    ;; When this actor is resumed, yield returns to its caller.
    ;; SMP: Uses scheduler lock (0x360400) to protect run queue.
    ;;       Lock is RELEASED before restore-context (context switch).
    ;;       On resume path, lock is NOT held.
    (defun yield ()
      (if (zerop (mem-ref #x05102018 :u64))
          ;; Actor system not initialized, no-op
          0
          (progn
            (spin-lock #x360400)
            (let ((next-id (actor-dequeue)))
              (if (zerop next-id)
                  ;; No other actors ready, unlock and return
                  (progn (spin-unlock #x360400) 0)
                  (let ((cur-id (percpu-ref 0)))
                    (if (zerop cur-id)
                        ;; No current actor (idle scheduler loop) — can't save context.
                        ;; Just run the dequeued actor directly.
                        ;; restore-context releases lock + STI after RSP switch.
                        (progn
                          (percpu-set 32 0)              ; not idle
                          (percpu-set 0 next-id)
                          (actor-set next-id #x00 1)     ; running
                          (percpu-set 40 (actor-get next-id #x70))
                          (percpu-set 48 (actor-get next-id #x78))
                          (let ((next-addr (actor-struct-addr next-id)))
                            (restore-context (+ next-addr #x08))))
                    (let ((cur-addr (actor-struct-addr cur-id)))
                      ;; save-context returns 0 on initial save, nonzero on resume
                      (if (zerop (save-context (+ cur-addr #x08)))
                          ;; Initial save: do the switch.
                          ;; Lock is held through restore-context to prevent the
                          ;; race where another CPU dequeues the enqueued actor
                          ;; while we're still on its stack.
                          (progn
                            (actor-set cur-id #x00 2)   ; mark as ready
                            ;; Save outgoing actor's object space state
                            (actor-set cur-id #x70 (percpu-ref 40))
                            (actor-set cur-id #x78 (percpu-ref 48))
                            (actor-enqueue cur-id)
                            ;; Switch to next actor (per-CPU)
                            (percpu-set 0 next-id)
                            (actor-set next-id #x00 1)  ; mark as running
                            ;; Load incoming actor's object space state
                            (percpu-set 40 (actor-get next-id #x70))
                            (percpu-set 48 (actor-get next-id #x78))
                            ;; restore-context: switch RSP, unlock, STI, JMP
                            (let ((next-addr (actor-struct-addr next-id)))
                              (restore-context (+ next-addr #x08))))
                          ;; Resumed: lock is NOT held (restore-context released it)
                          0)))))))))

    ;; Get current actor ID (per-CPU)
    (defun actor-self ()
      (percpu-ref 0))

    ;; Get number of active actors
    (defun actor-count ()
      (mem-ref #x05102008 :u64))

    ;; Actor exit handler - called when a spawned actor's function returns
    ;; This is pushed onto the actor's stack below the entry function,
    ;; so the function's RET jumps here.
    ;; SMP: send() acquires its own lock. Scheduler lock for dequeue+switch.
    (defun actor-exit ()
      (let ((cur (percpu-ref 0)))
        ;; Notify linked actor if any (send our ID as exit signal)
        ;; send acquires its own lock internally
        (let ((linked (actor-get cur #x60)))
          (if (not (zerop linked))
              (send linked cur)
              0))
        ;; Mark current actor as dead
        (actor-set cur #x00 3))
      ;; Switch to next ready actor (under scheduler lock)
      (spin-lock #x360400)
      (let ((next-id (actor-dequeue)))
        (if (zerop next-id)
            ;; No other actors: enter scheduler idle loop
            ;; (ap-scheduler never returns, so stack state doesn't matter)
            (progn (spin-unlock #x360400) (ap-scheduler))
            (progn
              (percpu-set 0 next-id)
              (actor-set next-id #x00 1)  ; mark as running
              ;; Load incoming actor's object space state
              (percpu-set 40 (actor-get next-id #x70))
              (percpu-set 48 (actor-get next-id #x78))
              ;; restore-context: switch RSP, unlock, STI, JMP
              (let ((next-addr (actor-struct-addr next-id)))
                (restore-context (+ next-addr #x08)))))))

    ;;; ============================================================
    ;;; Phase 8.2: Mailboxes - send/receive
    ;;; ============================================================
    ;;;
    ;;; Actor struct mailbox fields (added to existing struct):
    ;;;   +0x50  mailbox-head  u64  (tagged cons ptr to first msg cell, 0=empty)
    ;;;   +0x58  mailbox-tail  u64  (tagged cons ptr to last msg cell, 0=empty)
    ;;;
    ;;; Messages are stored as cons cells: (message . next-cell)
    ;;; Enqueue appends to tail, dequeue removes from head.
    ;;; Status 4 = blocked (waiting for message).

    ;;; ============================================================
    ;;; Phase 8.4: Mailbox Shared Pool
    ;;; ============================================================
    ;;;
    ;;; Mailbox cons cells live in a shared pool (not per-actor heaps).
    ;;; This prevents sender's GC from moving cells in receiver's mailbox.
    ;;; Pool at 0x05300000 (128KB = 8192 cells of 16 bytes).
    ;;; State at 0x05102030: pool-next(+0), pool-limit(+8), free-head(+16).

    ;; Initialize mailbox pool
    (defun pool-init ()
      (setf (mem-ref #x05102030 :u64) #x05300000)    ; pool-next
      (setf (mem-ref #x05102038 :u64) #x05320000)    ; pool-limit (128KB)
      (setf (mem-ref #x05102040 :u64) 0))             ; free-head = none

    ;; Allocate 16-byte cell from pool. Returns cons-tagged pointer or 0.
    (defun pool-alloc ()
      ;; Try free list first
      (let ((free (mem-ref #x05102040 :u64)))
        (if (not (zerop free))
            ;; Pop from free list: update head to cdr of free cell
            (progn
              (setf (mem-ref #x05102040 :u64) (cdr free))
              free)
            ;; Bump allocate
            (let ((ptr (mem-ref #x05102030 :u64)))
              (if (>= ptr (mem-ref #x05102038 :u64))
                  0  ; pool exhausted
                  (progn
                    (setf (mem-ref #x05102030 :u64) (+ ptr 16))
                    ;; Return cons-tagged pointer: raw_addr | 1
                    (logior (untag ptr) (untag 1))))))))

    ;; Return cell to free list
    (defun pool-free (cell)
      ;; Push onto free list: set cdr to current free-head
      (set-cdr cell (mem-ref #x05102040 :u64))
      (setf (mem-ref #x05102040 :u64) cell)
      0)

    ;; Dequeue a message from actor's mailbox. Returns 0 if empty.
    ;; Frees the dequeued cell back to the shared pool.
    ;; If car has machine bit 0 set, it's a staging pointer — decode into receiver's heap.
    (defun mailbox-dequeue (id)
      (let ((head (actor-get id #x50)))
        (if (zerop head)
            0
            (let ((raw-msg (car head)))
              (let ((next (cdr head)))
                (actor-set id #x50 next)
                (if (zerop next) (actor-set id #x58 0) ())
                (pool-free head)
                ;; Check machine bit 0: 0=fixnum/nil, 1=staging pointer
                (if (not (zerop (staging-ptr-p raw-msg)))
                    ;; Staging pointer — decode into receiver's heap
                    (let ((buf-addr (staging-untag raw-msg)))
                      (setf (mem-ref #x05102058 :u64) buf-addr)
                      (let ((result (term-decode-step)))
                        ;; Advance staging read-offset for this actor
                        (let ((staging-base (+ #x05700000 (ash id 14))))
                          (setf (mem-ref (+ staging-base 8) :u64)
                                (- (mem-ref #x05102058 :u64) staging-base 16)))
                        result))
                    ;; Fixnum/nil — return as-is
                    raw-msg))))))

    ;; ================================================================
    ;; Term Serialization for Actor Messages (Deep Copy)
    ;; ================================================================
    ;; Per-actor staging buffers at 0x05700000 (16KB each, max 64 actors).
    ;; Layout: [0:8] write-offset, [8:16] read-offset, [16:16384] ring data.
    ;;
    ;; Staging pointer discrimination in pool cell car:
    ;;   Machine bit 0 = 0 → fixnum/nil (fast path, return as-is)
    ;;   Machine bit 0 = 1 → staging pointer (decode from staging buffer)
    ;; Tagged fixnums always have machine bit 0 = 0 (value << 1 = even).
    ;; Scratch word at 0x05102050 used for machine-level bit manipulation.

    ;; Zero the staging region (1MB = 0x05700000-0x05800000)
    (defun staging-init ()
      (let ((i 0))
        (loop
          (when (>= i 131072) (return 0))
          (setf (mem-ref (+ #x05700000 (ash i 3)) :u64) 0)
          (setq i (+ i 1)))))

    ;; Check if val needs serialization: machine bit 0 = 1 means cons/object.
    ;; Uses scratch at 0x05102050 to inspect raw machine bits.
    (defun needs-staging (val)
      (setf (mem-ref #x05102050 :u64) val)
      (logand (mem-ref #x05102050 :u8) 1))

    ;; Tag a buffer address for staging (set machine bit 0 via scratch).
    ;; buf-addr is a tagged Lisp address (even at machine level).
    ;; Returns value with machine bit 0 set, for storing in pool cell car.
    (defun staging-tag (buf-addr)
      (setf (mem-ref #x05102050 :u64) buf-addr)
      (let ((b0 (mem-ref #x05102050 :u8)))
        (setf (mem-ref #x05102050 :u8) (logior b0 1)))
      (mem-ref #x05102050 :u64))

    ;; Check if pool cell car is a staging pointer (machine bit 0 = 1).
    ;; Returns non-zero if staging.
    (defun staging-ptr-p (raw-msg)
      (setf (mem-ref #x05102050 :u64) raw-msg)
      (logand (mem-ref #x05102050 :u8) 1))

    ;; Remove staging tag: clear machine bit 0 to recover original address.
    (defun staging-untag (raw-msg)
      (setf (mem-ref #x05102050 :u64) raw-msg)
      (let ((b0 (mem-ref #x05102050 :u8)))
        (setf (mem-ref #x05102050 :u8) (logand b0 (- 0 2))))
      (mem-ref #x05102050 :u64))

    ;; Compute serialized byte count for a term
    (defun term-size (val)
      (if (zerop val) 1
          (if (consp val)
              (+ 1 (term-size (car val)) (term-size (cdr val)))
              (if (stringp val) (+ 5 (string-length val))
                  (if (arrayp val) (+ 5 (array-length val))
                      (if (bignump val)
                          (let ((addr (ash (logand val (- 0 4)) 1)))
                            (+ 5 (ash (ash (mem-ref addr :u64) -15) 3)))
                          9))))))

    ;; Serialize term to buffer at raw address buf. Returns bytes written.
    (defun term-encode (val buf)
      (if (zerop val)
          (progn (setf (mem-ref buf :u8) 0) 1)
          (if (consp val)
              (progn
                (setf (mem-ref buf :u8) 2)
                (let ((n1 (term-encode (car val) (+ buf 1))))
                  (let ((n2 (term-encode (cdr val) (+ (+ buf 1) n1))))
                    (+ (+ 1 n1) n2))))
              (if (stringp val)
                  (let ((slen (string-length val)))
                    (setf (mem-ref buf :u8) 3)
                    (setf (mem-ref (+ buf 1) :u32) slen)
                    (let ((i 0))
                      (loop
                        (when (>= i slen) (return 0))
                        (setf (mem-ref (+ buf 5 i) :u8) (string-ref val i))
                        (setq i (+ i 1))))
                    (+ 5 slen))
                  (if (arrayp val)
                      (let ((alen (array-length val)))
                        (setf (mem-ref buf :u8) 4)
                        (setf (mem-ref (+ buf 1) :u32) alen)
                        (let ((i 0))
                          (loop
                            (when (>= i alen) (return 0))
                            (setf (mem-ref (+ buf 5 i) :u8) (aref val i))
                            (setq i (+ i 1))))
                        (+ 5 alen))
                      (if (bignump val)
                          (let ((addr (ash (logand val (- 0 4)) 1)))
                            (let ((nlimbs (ash (mem-ref addr :u64) -15)))
                              (setf (mem-ref buf :u8) 5)
                              (setf (mem-ref (+ buf 1) :u32) nlimbs)
                              (let ((i 0))
                                (loop
                                  (when (>= i nlimbs) (return 0))
                                  (setf (mem-ref (+ buf 5 (ash i 3)) :u64)
                                        (mem-ref (+ addr 8 (ash i 3)) :u64))
                                  (setq i (+ i 1))))
                              (+ 5 (ash nlimbs 3))))
                          ;; Fixnum (non-zero)
                          (progn
                            (setf (mem-ref buf :u8) 1)
                            (setf (mem-ref (+ buf 1) :u64) val)
                            9)))))))

    ;; Deserialize one term from staging buffer.
    ;; Uses global read pointer at 0x05102058 to track position.
    ;; Allocates in current actor's heap (cons, make-string, etc).
    (defun term-decode-step ()
      (let ((buf (mem-ref #x05102058 :u64)))
        (let ((tag (mem-ref buf :u8)))
          (if (zerop tag)
              ;; NIL
              (progn (setf (mem-ref #x05102058 :u64) (+ buf 1)) 0)
              (if (= tag 1)
                  ;; Fixnum
                  (let ((v (mem-ref (+ buf 1) :u64)))
                    (setf (mem-ref #x05102058 :u64) (+ buf 9))
                    v)
                  (if (= tag 2)
                      ;; Cons — decode car, decode cdr, cons them
                      (progn
                        (setf (mem-ref #x05102058 :u64) (+ buf 1))
                        (let ((car-val (term-decode-step)))
                          (let ((cdr-val (term-decode-step)))
                            (cons car-val cdr-val))))
                      (if (= tag 3)
                          ;; String
                          (let ((slen (mem-ref (+ buf 1) :u32)))
                            (let ((s (make-string slen)))
                              (let ((i 0))
                                (loop
                                  (when (>= i slen) (return 0))
                                  (string-set s i (mem-ref (+ buf 5 i) :u8))
                                  (setq i (+ i 1))))
                              (setf (mem-ref #x05102058 :u64) (+ buf 5 slen))
                              s))
                          (if (= tag 4)
                              ;; Array
                              (let ((alen (mem-ref (+ buf 1) :u32)))
                                (let ((a (make-array alen)))
                                  (let ((i 0))
                                    (loop
                                      (when (>= i alen) (return 0))
                                      (aset a i (mem-ref (+ buf 5 i) :u8))
                                      (setq i (+ i 1))))
                                  (setf (mem-ref #x05102058 :u64) (+ buf 5 alen))
                                  a))
                              ;; Bignum (tag 5)
                              (let ((nlimbs (mem-ref (+ buf 1) :u32)))
                                (let ((b (make-bignum-n nlimbs)))
                                  (let ((baddr (ash (logand b (- 0 4)) 1)))
                                    (let ((i 0))
                                      (loop
                                        (when (>= i nlimbs) (return 0))
                                        (setf (mem-ref (+ baddr 8 (ash i 3)) :u64)
                                              (mem-ref (+ buf 5 (ash i 3)) :u64))
                                        (setq i (+ i 1)))))
                                  (setf (mem-ref #x05102058 :u64)
                                        (+ buf 5 (ash nlimbs 3)))
                                  b))))))))))

    ;; Allocate a bignum with nlimbs limbs (for deserialization).
    ;; try-alloc-obj stores byte-count in header; we fix it to limb-count.
    ;; Header format: limb_count << 16 | 0x30
    (defun make-bignum-n (nlimbs)
      (let ((byte-size (ash nlimbs 3)))
        (let ((result (try-alloc-obj byte-size #x30)))
          (if (zerop result) 0
              (let ((raw (ash (logand result (- 0 4)) 1)))
                (setf (mem-ref raw :u64) (logior (ash nlimbs 15) (untag #x30)))
                result)))))

    ;; Cross-compiled make-bignum (the native compiler has an inline version,
    ;; but the cross-compiler doesn't know about it, so we need this).
    ;; Creates a bignum with nlimbs limbs, stores value in limb 0.
    (defun make-bignum (nlimbs value)
      (let ((b (make-bignum-n nlimbs)))
        (if (zerop b) 0
            (let ((addr (ash (logand b (- 0 4)) 1)))
              (setf (mem-ref (+ addr 8) :u64) (untag value))
              b))))

    ;; Compact staging buffer: move unread data to start, reset offsets.
    ;; Called when write-offset reaches limit but read-offset > 0.
    (defun staging-compact (staging-base)
      (let ((roff (mem-ref (+ staging-base 8) :u64)))
        (if (zerop roff)
            0
            (let ((woff (mem-ref staging-base :u64)))
              (let ((remaining (- woff roff)))
                (let ((i 0))
                  (loop
                    (when (>= i remaining) (return 0))
                    (setf (mem-ref (+ staging-base 16 i) :u8)
                          (mem-ref (+ staging-base 16 roff i) :u8))
                    (setq i (+ i 1))))
                (setf (mem-ref staging-base :u64) remaining)
                (setf (mem-ref (+ staging-base 8) :u64) 0)
                remaining)))))

    ;; Send a message to an actor
    ;; Allocates from shared pool (not per-actor heap) to avoid GC issues.
    ;; If target is blocked (status=4), wakes it up.
    ;; SMP: Scheduler lock protects pool-alloc, mailbox, and wake.
    ;; Enqueue cell into target's mailbox and wake if blocked.
    ;; Extracted so both fixnum and staging paths can share it.
    (defun mailbox-enqueue-and-wake (target-id cell)
      (let ((tail (actor-get target-id #x58)))
        (if (zerop tail)
            (progn
              (actor-set target-id #x50 cell)
              (actor-set target-id #x58 cell))
            (progn
              (set-cdr tail cell)
              (actor-set target-id #x58 cell))))
      ;; If target was blocked (status=4), wake it up
      (if (= (actor-get target-id #x00) 4)
          (progn
            (actor-set target-id #x00 2)
            (actor-enqueue target-id)
            (spin-unlock #x360400)
            (wake-idle-ap)
            0)
          (progn
            (spin-unlock #x360400)
            0)))

    (defun send (target-id message)
      (spin-lock #x360400)
      (let ((cell (pool-alloc)))
        (if (zerop cell)
            (progn (spin-unlock #x360400) 0)  ; pool exhausted
            (if (zerop (needs-staging message))
                ;; Fast path: fixnum/nil — store directly
                (progn
                  (set-car cell message)
                  (set-cdr cell 0)
                  (mailbox-enqueue-and-wake target-id cell))
                ;; Slow path: serialize to target's staging buffer
                (let ((size (term-size message)))
                  (let ((staging-base (+ #x05700000 (ash target-id 14))))
                    (let ((woff (mem-ref staging-base :u64)))
                      (if (> (+ woff size) 16368)
                          ;; Try compacting first
                          (progn
                            (staging-compact staging-base)
                            (let ((woff2 (mem-ref staging-base :u64)))
                              (if (> (+ woff2 size) 16368)
                                  ;; Still full — fail
                                  (progn (pool-free cell) (spin-unlock #x360400) 0)
                                  ;; Compact succeeded, encode now
                                  (let ((buf-addr (+ staging-base 16 woff2)))
                                    (let ((written (term-encode message buf-addr)))
                                      (setf (mem-ref staging-base :u64) (+ woff2 written))
                                      (set-car cell (staging-tag buf-addr))
                                      (set-cdr cell 0)
                                      (mailbox-enqueue-and-wake target-id cell))))))
                          ;; Enough space — encode directly
                          (let ((buf-addr (+ staging-base 16 woff)))
                            (let ((written (term-encode message buf-addr)))
                              (setf (mem-ref staging-base :u64) (+ woff written))
                              (set-car cell (staging-tag buf-addr))
                              (set-cdr cell 0)
                              (mailbox-enqueue-and-wake target-id cell)))))))))))

    ;; Receive a message, blocking if mailbox is empty.
    ;; If mailbox has a message, returns it immediately.
    ;; If empty, blocks (saves context, status=4) until someone sends us a message.
    ;; SMP: Scheduler lock protects mailbox check, block, and switch.
    (defun receive ()
      (spin-lock #x360400)
      (let ((cur-id (percpu-ref 0)))
        (let ((msg (mailbox-dequeue cur-id)))
          (if (not (zerop msg))
              ;; Have a message, unlock and return it
              (progn (spin-unlock #x360400) msg)
              ;; No message: block until one arrives
              (let ((cur-addr (actor-struct-addr cur-id)))
                (if (zerop (save-context (+ cur-addr #x08)))
                    ;; Save path: mark as blocked and switch
                    (progn
                      (actor-set cur-id #x00 4)
                      ;; Save outgoing actor's object space state
                      (actor-set cur-id #x70 (percpu-ref 40))
                      (actor-set cur-id #x78 (percpu-ref 48))
                      (let ((next-id (actor-dequeue)))
                        (if (zerop next-id)
                            ;; No ready actors — enter scheduler idle loop.
                            ;; ap-scheduler sets idle flag and HLTs. When woken by IPI,
                            ;; it dequeues and runs the next actor. yield is safe with
                            ;; percpu 0 = 0 (just runs dequeued actor directly).
                            (progn (spin-unlock #x360400) (ap-scheduler))
                            (progn
                              (percpu-set 0 next-id)
                              (actor-set next-id #x00 1)
                              ;; Load incoming actor's object space state
                              (percpu-set 40 (actor-get next-id #x70))
                              (percpu-set 48 (actor-get next-id #x78))
                              ;; restore-context: switch RSP, unlock, STI, JMP
                              (let ((next-addr (actor-struct-addr next-id)))
                                (restore-context (+ next-addr #x08)))))))
                    ;; Resumed: lock is NOT held (restore-context released it)
                    ;; Dequeue the message that woke us
                    (progn
                      (spin-lock #x360400)
                      (let ((m (mailbox-dequeue cur-id)))
                        (spin-unlock #x360400)
                        m))))))))

    ;; Receive with timeout: yield up to max-yields times, checking
    ;; mailbox each iteration. Returns message if one arrives, 0 on timeout.
    ;; Unlike receive, this never blocks -- it busy-polls via yield.
    ;; SMP: Lock around mailbox-dequeue calls; yield handles its own locking.
    (defun receive-timeout (max-yields)
      (let ((cur-id (percpu-ref 0)))
        (spin-lock #x360400)
        (let ((msg (mailbox-dequeue cur-id)))
          (spin-unlock #x360400)
          (if (not (zerop msg))
              msg
              (let ((count 0))
                (loop
                  (yield)
                  (spin-lock #x360400)
                  (let ((m (mailbox-dequeue (percpu-ref 0))))
                    (spin-unlock #x360400)
                    (if (not (zerop m))
                        (return m)
                        (progn
                          (setf count (+ count 1))
                          (if (= count max-yields)
                              (return 0)
                              0))))))))))

    ;;; ============================================================
    ;;; Phase 8.5: Link and lifecycle
    ;;; ============================================================
    ;;;
    ;;; Actor struct link field:
    ;;;   +0x60  linked-actor  u64  (ID of linked actor, 0=none)
    ;;;
    ;;; When a linked actor dies (actor-exit), it sends its ID to
    ;;; the linked partner as an exit notification.

    ;; Establish bidirectional link between current actor and other
    (defun link (other-id)
      (let ((self-id (actor-self)))
        (actor-set self-id #x60 other-id)
        (actor-set other-id #x60 self-id)
        0))

    ;; Spawn + link in one operation
    (defun spawn-link (fn)
      (let ((wid (actor-spawn fn)))
        (link wid)
        wid))

    ;;; ============================================================
    ;;; Tests
    ;;; ============================================================

    ;; Test worker actor - minimal round-trip test
    (defun actor-test-worker ()
      (write-byte 87)    ; 'W' - worker started
      (yield)            ; yield back to main
      (write-byte 88)    ; 'X' - worker resumed (2nd round)
      0)

    ;; Test the actor system - minimal context switch round-trip
    (defun actor-test ()
      (let ((worker-addr (nfn-lookup (hash-of "actor-test-worker"))))
        (actor-spawn worker-addr)
        (write-byte 65)   ; 'A' - main before 1st yield
        (yield)            ; -> worker: W, yield back
        (write-byte 66)   ; 'B' - main resumed
        (yield)            ; -> worker: X, returns, actor-exit
        (write-byte 67)   ; 'C' - main after worker died
        (write-byte 10)
        0))

    ;;; ---- Send/Receive Tests ----

    ;; Worker that receives a message and prints it as a digit
    (defun actor-msg-worker ()
      (let ((msg (receive)))
        (write-byte (+ 48 msg))    ; print digit '0'-'9'
        0))

    ;; Test basic send/receive
    ;; Expected output: S7D\n
    (defun actor-msg-test ()
      (let ((worker-addr (nfn-lookup (hash-of "actor-msg-worker"))))
        (let ((wid (actor-spawn worker-addr)))
          (write-byte 83)          ; 'S' - sending
          (send wid 7)             ; send 7 to worker
          (yield)                  ; let worker run and receive
          (write-byte 68)          ; 'D' - done
          (write-byte 10)
          0)))

    ;; Worker that receives sender ID, sends back a reply
    (defun actor-ping-worker ()
      (let ((sender (receive)))
        (write-byte 80)            ; 'P' - pong
        (send sender 1)            ; reply with 1
        0))

    ;; Test ping-pong: send our ID, wait for reply
    ;; Expected output: IPR\n
    (defun actor-ping-test ()
      (let ((worker-addr (nfn-lookup (hash-of "actor-ping-worker"))))
        (let ((wid (actor-spawn worker-addr)))
          (write-byte 73)          ; 'I' - ping
          (send wid (actor-self))  ; send our actor ID
          (let ((reply (receive))) ; block until worker replies
            (write-byte 82)        ; 'R' - received
            (write-byte 10)
            0))))

    ;; Test multiple actors (3 workers) with send/receive
    ;; Reuses actor-msg-worker (hash 39947) which receives and prints a digit.
    ;; Expected output: 123D\n
    (defun actor-multi-test ()
      (let ((fn (nfn-lookup (hash-of "actor-msg-worker"))))
        (let ((w1 (actor-spawn fn)))
          (let ((w2 (actor-spawn fn)))
            (let ((w3 (actor-spawn fn)))
              (send w1 1)
              (send w2 2)
              (send w3 3)
              (yield)
              (write-byte 68)    ; 'D'
              (write-byte 10)
              0)))))

    ;; Worker that exits after receiving any message (for link test)
    (defun actor-link-worker ()
      (receive)    ; wait for start signal
      (write-byte 87)  ; 'W' - worker ran
      0)               ; exit normally -> actor-exit notifies linked actor

    ;; Test link: spawn linked worker, when it exits we get notified
    ;; Expected output: WL2\n  (worker prints W, main gets link notification with ID 2)
    (defun actor-link-test ()
      (let ((fn (nfn-lookup (hash-of "actor-link-worker"))))
        (let ((wid (spawn-link fn)))
          (send wid 1)            ; start the worker
          (let ((exit-msg (receive)))  ; block until worker exits
            (write-byte 76)       ; 'L' - link notification received
            (write-byte (+ 48 exit-msg))  ; print dead actor's ID as digit
            (write-byte 10)
            0))))

    ;;; ============================================================
    ;;; Phase 8.5b: Supervisor
    ;;; ============================================================
    ;;;
    ;;; A supervisor is an actor that spawns children, links to them,
    ;;; and restarts them when they die. This implements the core of
    ;;; Erlang-style supervision trees.

    ;; Supervised worker: prints 'W' and exits (death triggers restart)
    (defun sup-worker ()
      (write-byte 87)  ; 'W' - worker ran
      0)               ; return -> actor-exit -> notify linked supervisor

    ;; Supervisor actor: spawns worker, restarts on death, up to 3 cycles.
    ;; Receives parent-id as first message so it can signal completion.
    ;; Restart sequence: spawn-link, receive exit notification, repeat.
    ;; After 3 worker cycles (2 restarts), sends done signal to parent.
    ;; Expected to produce: WRWRW (W from each worker, R from each restart)
    (defun supervisor ()
      (let ((parent-id (receive)))    ; first message: parent's actor ID
      (let ((fn (nfn-lookup (hash-of "sup-worker"))))
        ;; Spawn first worker (linked)
        (spawn-link fn)
        ;; Worker 1 exits -> receive notification
        (receive)
        (write-byte 82)  ; 'R' - restart
        ;; Spawn second worker
        (spawn-link fn)
        ;; Worker 2 exits -> receive notification
        (receive)
        (write-byte 82)  ; 'R' - restart
        ;; Spawn third worker
        (spawn-link fn)
        ;; Worker 3 exits -> done
        (receive)
        (write-byte 68)  ; 'D' - done, max restarts reached
        ;; Notify parent
        (send parent-id 1)
        0)))

    ;; Test: spawn supervisor, wait for completion
    ;; Expected output: WRWRWD\n
    ;; W=worker ran, R=restart, D=done (3 workers, 2 restarts)
    (defun sup-test ()
      (let ((fn (nfn-lookup (hash-of "supervisor"))))
        (let ((sup-id (actor-spawn fn)))
          (send sup-id (actor-self))  ; tell supervisor our ID
          (receive)                   ; wait for done signal
          (write-byte 10)
          0)))

    ;;; ============================================================
    ;;; Parallel Map-Reduce Demo
    ;;; ============================================================

    ;; Map worker: receives parent-id then value, sends back value^2
    (defun map-worker ()
      (let ((parent (receive)))
        (let ((val (receive)))
          (send parent (* val val))
          0)))

    ;; Parallel map-reduce: 4 workers compute sum of squares
    ;; 3^2 + 5^2 + 7^2 + 11^2 = 9 + 25 + 49 + 121 = 204
    ;; Expected output: 204\n
    (defun map-reduce-test ()
      (let ((fn (nfn-lookup (hash-of "map-worker"))))
        (let ((self (actor-self)))
          (let ((w1 (actor-spawn fn)))
            (let ((w2 (actor-spawn fn)))
              (let ((w3 (actor-spawn fn)))
                (let ((w4 (actor-spawn fn)))
                  ;; Dispatch work to all 4 workers in parallel
                  (send w1 self) (send w1 3)
                  (send w2 self) (send w2 5)
                  (send w3 self) (send w3 7)
                  (send w4 self) (send w4 11)
                  ;; Collect results and print sum
                  (let ((r1 (receive)))
                    (let ((r2 (receive)))
                      (let ((r3 (receive)))
                        (let ((r4 (receive)))
                          (print-dec (+ r1 (+ r2 (+ r3 r4))))
                          (write-byte 10)
                          0)))))))))))

    ;;; ============================================================
    ;;; Ring Benchmark
    ;;; ============================================================
    ;;;
    ;;; Classic Erlang-style ring benchmark:
    ;;; N actors in a ring, token passed around M times.
    ;;; Tests message passing throughput and context switching.

    ;; Ring node: receives next-id, then forwards tokens until 0
    (defun ring-node ()
      (let ((next (receive)))
        (loop
          (let ((token (receive)))
            (if (zerop token)
                (progn (send next 0) (return 0))
                (send next (- token 1)))))))

    ;; Ring benchmark: 5 nodes, 10000 hops = 2000 laps
    ;; Token starts at 10000, decrements each hop, stops at 0
    ;; Expected output: 10000\n (total messages passed)
    ;; Tests: 10000 context switches + 10000 message sends + mailbox ops
    (defun ring-test ()
      (let ((fn (nfn-lookup (hash-of "ring-node"))))
        (let ((n1 (actor-spawn fn)))
          (let ((n2 (actor-spawn fn)))
            (let ((n3 (actor-spawn fn)))
              (let ((n4 (actor-spawn fn)))
                (let ((n5 (actor-spawn fn)))
                  ;; Wire ring: n1->n2->n3->n4->n5->n1
                  (send n1 n2) (send n2 n3) (send n3 n4)
                  (send n4 n5) (send n5 n1)
                  ;; Link to n1 to detect completion
                  (link n1)
                  ;; Start token at 10000
                  (send n1 10000)
                  ;; Wait for n1 to die (token reached 0)
                  (receive)
                  (print-dec 10000)
                  (write-byte 10)
                  0)))))))

    ;;; ============================================================
    ;;; Timeout Test
    ;;; ============================================================

    ;; Test receive-timeout:
    ;; 1. receive-timeout with no messages -> should timeout
    ;; 2. Spawn ping-worker, send it our ID, receive-timeout -> should get reply
    ;; Expected output: TP1\n (T=timeout, P=ping-worker ran, 1=reply received)
    (defun timeout-test ()
      ;; Test 1: timeout when no message
      (let ((r1 (receive-timeout 5)))
        (if (zerop r1)
            (write-byte 84)    ; 'T' - timeout (correct)
            (write-byte 69)))  ; 'E' - error
      ;; Test 2: spawn worker that replies, should receive
      (let ((fn (nfn-lookup (hash-of "actor-ping-worker"))))
        (let ((wid (actor-spawn fn)))
          (send wid (actor-self))
          (let ((r2 (receive-timeout 100)))
            (if (zerop r2)
                (write-byte 69)      ; 'E' - timeout error
                (print-dec r2)))     ; should print 1
          (write-byte 10)
          0)))

    ;; Phase 8.3: Reduction counting preemption test
    ;; Busy-worker spins in a tight loop forever (no yield/receive)
    ;; Without reduction counting, this would starve all other actors
    (defun busy-worker ()
      (let ((x 0))
        (loop
          (setq x (+ x 1)))))

    ;; Reply-worker: receives sender id, sends back 1
    (defun reply-worker ()
      (let ((sender (receive)))
        (send sender 1) 0))

    ;; preempt-test: verifies that busy-worker gets preempted
    ;; so that reply-worker can still run and reply to us
    (defun preempt-test ()
      ;; Spawn a busy-looping actor (would starve without preemption)
      (let ((bfn (nfn-lookup (hash-of "busy-worker"))))
        (actor-spawn bfn))
      ;; Spawn a reply worker
      (let ((rfn (nfn-lookup (hash-of "reply-worker"))))
        (let ((wid (actor-spawn rfn)))
          (send wid (actor-self))
          ;; Wait for reply (with timeout in case preemption fails)
          (let ((reply (receive-timeout 500)))
            (if (zerop reply)
                (write-byte 70)     ; 'F' - failed (no preemption)
                (write-byte 80))))) ; 'P' - passed (preemption works!)
      (write-byte 10) 0)

    ;;; ============================================================
    ;;; GC Stress Tests
    ;;; ============================================================

    ;; Allocate n cons cells to exercise the allocator under pressure.
    ;; Note: Cross-compiled cons doesn't trigger GC. For actor 0 the cons
    ;; semispace is 4MB (0x04000000-0x043FFFFF), fitting 262144 cons cells.
    (defun gc-test (n)
      (let ((i 0))
        (loop
          (if (< i n)
              (progn
                (cons i i)
                (setq i (+ i 1)))
              (return i)))))

    ;; Allocate n arrays, recycling the object semispace when full.
    ;; Cross-compiled make-array doesn't have inline GC, so on OOM (returns 0)
    ;; we reset the alloc pointer to the saved base. This exercises the alloc
    ;; mechanism under pressure and verifies OOM recovery.
    ;; 256-byte array = ~272 bytes with header. 256KB semispace / 272 ~ 960 before OOM.
    (defun obj-gc-test (n)
      (let ((base (percpu-ref 40)))
        (let ((i 0))
          (loop
            (if (< i n)
                (progn
                  (if (zerop (make-array 256))
                      ;; OOM: reset object alloc pointer to saved base
                      (percpu-set 40 base)
                      ())
                  (setq i (+ i 1)))
                (return i))))))

    ;;; ============================================================
    ;;; Phase 9.4: SMP Test
    ;;; ============================================================

    ;; Worker that reports which CPU it runs on via shared memory.
    ;; Writes cpu-index+1 to 0x360500 (0 = not yet written).
    (defun smp-worker ()
      (let ((cpu (percpu-ref 16)))
        ;; Print CPU number to serial
        (write-byte (+ 48 cpu))
        ;; Write result to shared memory (cpu+1 so 0 means "not done")
        (setf (mem-ref #x360500 :u64) (+ cpu 1))))

    ;; SMP test: spawn a worker, verify it runs on a different CPU.
    ;; BSP busy-waits (no yield!) so it doesn't steal the work.
    ;; The AP should pick up the worker via IPI wakeup.
    ;; Prints: main-cpu + worker-cpu + result-char
    ;; Expected on -smp 2: "01Y" (BSP=0, worker on AP=1, different=Y)
    ;; Expected on -smp 1: "00N" (both on CPU 0, BSP runs it after timeout)
    (defun smp-test ()
      ;; Clear result
      (setf (mem-ref #x360500 :u64) 0)
      (let ((my-cpu (percpu-ref 16)))
        ;; Print our CPU
        (write-byte (+ 48 my-cpu))
        ;; Spawn worker (triggers IPI to wake idle AP)
        (let ((fn (nfn-lookup (hash-of "smp-worker"))))
          (actor-spawn fn))
        ;; Busy-wait for worker to write result (don't yield!)
        ;; On SMP 2: AP runs the worker, writes to 0x360500
        ;; On SMP 1: no AP, so we time out and then yield to let it run
        (let ((i 0))
          (loop
            (if (not (zerop (mem-ref #x360500 :u64)))
                (return 0)
                (if (< i 100000)
                    (progn (pause) (setq i (+ i 1)))
                    (return 0)))))
        ;; If still zero on SMP 1, yield to let worker run on same CPU
        (if (zerop (mem-ref #x360500 :u64))
            (progn (yield) (yield) (yield))
            0)
        ;; Read result
        (let ((result (mem-ref #x360500 :u64)))
          (if (zerop result)
              (write-byte 84)          ; 'T' - timeout (shouldn't happen)
              (let ((worker-cpu (- result 1)))
                (if (= worker-cpu my-cpu)
                    (write-byte 78)    ; 'N' - same CPU
                    (write-byte 89)))));; 'Y' - different CPU!
        (write-byte 10) 0))

    ;;; ============================================================
    ;;; Parallel Benchmarks
    ;;; ============================================================

    ;; Worker: receives parent ID and iteration count, computes sum(0..n-1),
    ;; sends result back. The tight loop exercises the reduction counter
    ;; and cooperative scheduling.
    (defun bench-worker ()
      (let ((parent (receive)))
        (let ((n (receive)))
          (let ((sum 0)
                (i 0))
            (loop
              (if (< i n)
                  (progn
                    (setq sum (+ sum i))
                    (setq i (+ i 1)))
                  (progn
                    (send parent sum)
                    (return 0))))))))

    ;; Parallel benchmark: spawn nworkers actors, each computing sum(0..iters-1),
    ;; collect results and print total. Use with any worker count:
    ;;   (par-bench 1 10000000)  - baseline
    ;;   (par-bench 8 10000000)  - 8 parallel workers
    (defun par-bench (nworkers iters)
      (let ((fn (nfn-lookup (hash-of "bench-worker"))))
        (let ((self (actor-self)))
          ;; Spawn workers and send them work
          (let ((i 0))
            (loop
              (if (>= i nworkers)
                  (return 0)
                  (let ((w (actor-spawn fn)))
                    (send w self)
                    (send w iters)
                    (setq i (+ i 1))))))
          ;; Collect results
          (let ((total 0)
                (j 0))
            (loop
              (if (>= j nworkers)
                  (return 0)
                  (progn
                    (setq total (+ total (receive)))
                    (setq j (+ j 1)))))
            (print-dec total)
            (write-byte 10)
            0))))

    ;;; ============================================================
    ;;; Deep-Copy Send Demo
    ;;; ============================================================

    ;; Print a value of any type: fixnum, nil, cons list, string, array, bignum.
    ;; Prints type tag then content for visual confirmation.
    (defun print-val (v)
      (if (zerop v)
          (progn (write-byte 78) (write-byte 73) (write-byte 76))  ; "NIL"
          (if (consp v)
              ;; Print cons as (a b c ...)
              (progn
                (write-byte 40)  ; '('
                (let ((cur v))
                  (loop
                    (if (consp cur)
                        (progn
                          (print-val (car cur))
                          (if (not (zerop (cdr cur)))
                              (write-byte 32)  ; ' '
                              ())
                          (setq cur (cdr cur)))
                        (progn
                          (if (not (zerop cur))
                              (progn
                                (write-byte 46) (write-byte 32)  ; ". "
                                (print-val cur))
                              ())
                          (return 0)))))
                (write-byte 41))  ; ')'
              (if (stringp v)
                  ;; Print string in quotes
                  (progn (write-byte 34) (print-string v) (write-byte 34))  ; "..."
                  (if (arrayp v)
                      ;; Print array as #(b0 b1 ...)
                      (progn
                        (write-byte 35) (write-byte 40)  ; "#("
                        (let ((len (array-length v))
                              (i 0))
                          (loop
                            (when (>= i len) (return 0))
                            (if (> i 0) (write-byte 32) ())
                            (print-dec (aref v i))
                            (setq i (+ i 1))))
                        (write-byte 41))  ; ")"
                      (if (bignump v)
                          ;; Print bignum hex: B[limb0,limb1,...]
                          (progn
                            (write-byte 66)  ; 'B'
                            (write-byte 91)  ; '['
                            (let ((addr (ash (logand v (- 0 4)) 1)))
                              (let ((nlimbs (ash (mem-ref addr :u64) -15))
                                    (i 0))
                                (loop
                                  (when (>= i nlimbs) (return 0))
                                  (if (> i 0)
                                      (write-byte 44)  ; ','
                                      ())
                                  (print-dec (ash (mem-ref (+ addr 8 (ash i 3)) :u64) 1))
                                  (setq i (+ i 1)))))
                            (write-byte 93))  ; ']'
                          ;; Fixnum
                          (print-dec v)))))))

    ;; Worker: receive one message, print it, and exit.
    (defun send-demo-worker ()
      (let ((msg (receive)))
        (print-val msg)
        (write-byte 10)
        0))

    ;; Comprehensive demo of deep-copy send with all types.
    ;; Spawns a worker for each test, sends it a complex term, worker prints what it got.
    (defun send-demo ()
      (let ((fn (nfn-lookup (hash-of "send-demo-worker"))))
        ;; Test 1: Fixnum (fast path)
        (write-byte 49) (write-byte 58) (write-byte 32)  ; "1: "
        (let ((w1 (actor-spawn fn)))
          (send w1 42)
          (yield) (yield))

        ;; Test 2: Cons list (1 2 3)
        (write-byte 50) (write-byte 58) (write-byte 32)  ; "2: "
        (let ((w2 (actor-spawn fn)))
          (send w2 (cons 1 (cons 2 (cons 3 0))))
          (yield) (yield))

        ;; Test 3: String "Hello"
        (write-byte 51) (write-byte 58) (write-byte 32)  ; "3: "
        (let ((w3 (actor-spawn fn)))
          (let ((s (make-string 5)))
            (string-set s 0 72) (string-set s 1 101) (string-set s 2 108)
            (string-set s 3 108) (string-set s 4 111)
            (send w3 s)
            (yield) (yield)))

        ;; Test 4: Byte array #(10 20 30)
        (write-byte 52) (write-byte 58) (write-byte 32)  ; "4: "
        (let ((w4 (actor-spawn fn)))
          (let ((a (make-array 3)))
            (aset a 0 10) (aset a 1 20) (aset a 2 30)
            (send w4 a)
            (yield) (yield)))

        ;; Test 5: Nested cons ((1 2) (3 4))
        (write-byte 53) (write-byte 58) (write-byte 32)  ; "5: "
        (let ((w5 (actor-spawn fn)))
          (send w5 (cons (cons 1 (cons 2 0)) (cons (cons 3 (cons 4 0)) 0)))
          (yield) (yield))

        ;; Test 6: NIL
        ;; NIL = 0 takes fixnum fast path, prints "NIL" via print-val
        ;; But wait - send returns 0 for fixnum 0 too, need to verify

        ;; Test 6: Bignum
        (write-byte 54) (write-byte 58) (write-byte 32)  ; "6: "
        (let ((w6 (actor-spawn fn)))
          (send w6 (make-bignum 1 12345))
          (yield) (yield))

        ;; Test 7: String inside cons — (42 "Hi")
        (write-byte 55) (write-byte 58) (write-byte 32)  ; "7: "
        (let ((w7 (actor-spawn fn)))
          (let ((s2 (make-string 2)))
            (string-set s2 0 72) (string-set s2 1 105)  ; "Hi"
            (send w7 (cons 42 (cons s2 0)))
            (yield) (yield)))

        (write-byte 68) (write-byte 79) (write-byte 78)  ; "DON"
        (write-byte 69) (write-byte 10)                   ; "E\n"
        0))

    ;; ============================================================
    ;; REPL Ergonomics: Line Editing, History, Tab Completion
    ;; ============================================================
    ;;
    ;; Memory layout:
    ;;   0x310000  Symbol name table (build-time, ~8KB)
    ;;   0x312000  History ring (8 entries x 256 bytes)
    ;;     +0: write-idx (u64), +8: browse-idx (u64)
    ;;     +16: entry 0..7 (256 bytes each)
    ;;   0x312800  Edit state
    ;;     +0: line-len (u64), +8: cursor-pos (u64), +16: esc-state (u64)

    ;; --- VT100 output helpers ---

    ;; Emit ESC [ (start of CSI sequence)
    (defun emit-csi ()
      (write-byte 27)   ; ESC
      (write-byte 91))  ; '['

    ;; Move cursor right N positions
    (defun cursor-right (n)
      (when (> n 0)
        (emit-csi)
        (if (eq n 1)
            (write-byte 67)  ; 'C'
            (progn
              ;; Emit decimal number then 'C'
              (print-dec-raw n)
              (write-byte 67)))))

    ;; Move cursor left N positions
    (defun cursor-left (n)
      (when (> n 0)
        (emit-csi)
        (if (eq n 1)
            (write-byte 68)  ; 'D'
            (progn
              (print-dec-raw n)
              (write-byte 68)))))

    ;; Print small decimal number (for CSI params, no newline)
    (defun print-dec-raw (n)
      (if (< n 10)
          (write-byte (+ n 48))
          (if (< n 100)
              (progn
                (write-byte (+ (truncate-div n 10) 48))
                (write-byte (+ (mod-10 n) 48)))
              (progn
                (write-byte (+ (truncate-div n 100) 48))
                (write-byte (+ (mod-10 (truncate-div n 10)) 48))
                (write-byte (+ (mod-10 n) 48))))))

    ;; Integer division by 10 (no bignum)
    (defun truncate-div (n d)
      (let ((q 0))
        (loop
          (if (< n d)
              (return q)
              (progn
                (setq n (- n d))
                (setq q (+ q 1)))))))

    ;; Mod 10
    (defun mod-10 (n)
      (let ((x n))
        (loop
          (if (< x 10)
              (return x)
              (setq x (- x 10))))))

    ;; Erase from cursor to end of line
    (defun erase-to-eol ()
      (emit-csi)
      (write-byte 75))  ; 'K'

    ;; --- Line buffer helpers ---
    ;; Line buffer: 0x300028+ (up to 200 bytes)
    ;; Edit state: 0x312800 = line-len, 0x312808 = cursor-pos, 0x312810 = esc-state

    (defun edit-line-len ()
      (mem-ref #x312800 :u64))

    (defun edit-cursor-pos ()
      (mem-ref #x312808 :u64))

    (defun edit-set-line-len (v)
      (setf (mem-ref #x312800 :u64) v))

    (defun edit-set-cursor-pos (v)
      (setf (mem-ref #x312808 :u64) v))

    ;; Redraw line from cursor position to end, then reposition cursor
    (defun line-redraw-from-cursor ()
      (let ((pos (edit-cursor-pos))
            (len (edit-line-len)))
        ;; Write chars from cursor to end
        (let ((i pos))
          (loop
            (if (< i len)
                (progn
                  (write-byte (mem-ref (+ #x300028 i) :u8))
                  (setq i (+ i 1)))
                (return 0))))
        ;; Erase any leftover chars (for delete operations)
        (erase-to-eol)
        ;; Move cursor back to cursor-pos
        (let ((dist (- len pos)))
          (cursor-left dist))))

    ;; Redraw entire line and position cursor
    (defun line-redraw-full ()
      ;; Move to start of line (after prompt)
      (write-byte 13)  ; CR
      (emit-prompt)
      ;; Write all chars
      (let ((len (edit-line-len))
            (i 0))
        (loop
          (if (< i len)
              (progn
                (write-byte (mem-ref (+ #x300028 i) :u8))
                (setq i (+ i 1)))
              (return 0))))
      (erase-to-eol)
      ;; Position cursor
      (let ((trail (- (edit-line-len) (edit-cursor-pos))))
        (cursor-left trail)))

    ;; Insert byte at cursor position with shift and redraw
    (defun line-insert-byte (b)
      (let ((pos (mem-ref #x312808 :u64))
            (len (mem-ref #x312800 :u64)))
        (when (< len 199)
          (if (eq pos len)
              ;; Appending at end — no shift needed
              (progn
                (setf (mem-ref (+ #x300028 pos) :u8) b)
                (setf (mem-ref #x312800 :u64) (+ len 1))
                (setf (mem-ref #x312808 :u64) (+ pos 1))
                (write-byte b))
              ;; Mid-line: shift right, insert, redraw
              (progn
                (let ((i len))
                  (loop
                    (if (> i pos)
                        (progn
                          (setf (mem-ref (+ #x300028 i) :u8)
                                (mem-ref (+ #x300027 i) :u8))
                          (setq i (- i 1)))
                        (return 0))))
                (setf (mem-ref (+ #x300028 pos) :u8) b)
                (setf (mem-ref #x312800 :u64) (+ len 1))
                ;; Redraw from current cursor-pos (not yet incremented)
                (line-redraw-from-cursor)
                ;; Now advance cursor
                (setf (mem-ref #x312808 :u64) (+ pos 1))
                (cursor-right 1))))))

    ;; Delete byte at cursor-1 (backspace), shift rest left
    (defun line-delete-back ()
      (let ((len (edit-line-len))
            (pos (edit-cursor-pos)))
        (when (> pos 0)
          (let ((new-pos (- pos 1)))
            ;; Remember deleted char (tab needs full redraw)
            (let ((deleted (mem-ref (+ #x300028 new-pos) :u8)))
              ;; Shift chars left from pos to end
              (let ((i new-pos))
                (loop
                  (if (< i (- len 1))
                      (progn
                        (setf (mem-ref (+ #x300028 i) :u8)
                              (mem-ref (+ #x300029 i) :u8))
                        (setq i (+ i 1)))
                      (return 0))))
              (edit-set-line-len (- len 1))
              (edit-set-cursor-pos new-pos)
              ;; Tab occupies multiple columns — full redraw needed
              (if (eq deleted 9)
                  (line-redraw-full)
                  (progn
                    (write-byte 8)
                    (line-redraw-from-cursor))))))))

    ;; --- Word movement (Alt+arrows, Alt+F/B) ---

    ;; Is byte a word character? Returns non-zero for word, 0 for separator.
    ;; Word chars: anything printable except space and parens
    (defun word-char-p (c)
      (if (< c 33) 0
          (if (eq c 40) 0
              (if (eq c 41) 0
                  1))))

    ;; Move cursor to beginning of line (Ctrl-A)
    (defun cursor-to-start ()
      (let ((pos (edit-cursor-pos)))
        (when (> pos 0)
          (cursor-left pos)
          (edit-set-cursor-pos 0))))

    ;; Move cursor left to start of previous word
    ;; Skip non-word chars backward, then skip word chars backward
    (defun word-left ()
      (let ((pos (edit-cursor-pos))
            (state 0))
        (loop
          (when (zerop pos) (return 0))
          (let ((c (mem-ref (+ #x300027 pos) :u8)))
            (if (zerop state)
                ;; State 0: skipping non-word chars
                (if (zerop (word-char-p c))
                    (setq pos (- pos 1))
                    (progn (setq state 1)
                           (setq pos (- pos 1))))
                ;; State 1: skipping word chars
                (if (not (zerop (word-char-p c)))
                    (setq pos (- pos 1))
                    (return 0)))))
        (let ((dist (- (edit-cursor-pos) pos)))
          (when (> dist 0)
            (cursor-left dist)
            (edit-set-cursor-pos pos)))))

    ;; Move cursor right to end of next word
    ;; Skip non-word chars forward, then skip word chars forward
    (defun word-right ()
      (let ((pos (edit-cursor-pos))
            (len (edit-line-len))
            (state 0))
        (loop
          (when (>= pos len) (return 0))
          (let ((c (mem-ref (+ #x300028 pos) :u8)))
            (if (zerop state)
                ;; State 0: skipping non-word chars
                (if (zerop (word-char-p c))
                    (setq pos (+ pos 1))
                    (setq state 1))
                ;; State 1: skipping word chars
                (if (not (zerop (word-char-p c)))
                    (setq pos (+ pos 1))
                    (return 0)))))
        (let ((dist (- pos (edit-cursor-pos))))
          (when (> dist 0)
            (cursor-right dist)
            (edit-set-cursor-pos pos)))))

    ;; --- History ring buffer ---
    ;; 0x312000: write-idx (u64)
    ;; 0x312008: browse-idx (u64)
    ;; 0x312010 + i*256: entry i (null-terminated)

    (defun history-write-idx ()
      (mem-ref #x312000 :u64))

    (defun history-browse-idx ()
      (mem-ref #x312008 :u64))

    ;; Save current line to history
    (defun history-save ()
      (let ((len (edit-line-len)))
        (when (> len 0)
          (let ((idx (logand (history-write-idx) 7)))
            (let ((base (+ #x312010 (* idx 256))))
              (let ((i 0))
                ;; Copy line to history entry
                (loop
                  (if (< i len)
                      (progn
                        (setf (mem-ref (+ base i) :u8)
                              (mem-ref (+ #x300028 i) :u8))
                        (setq i (+ i 1)))
                      (return 0)))
                ;; Null terminate
                (setf (mem-ref (+ base len) :u8) 0)
                ;; Advance write index
                (let ((new-idx (+ (history-write-idx) 1)))
                  (setf (mem-ref #x312000 :u64) new-idx)
                  ;; Reset browse index to write position
                  (setf (mem-ref #x312008 :u64) new-idx))))))))

    ;; Load history entry into line buffer (for up/down arrow)
    ;; Returns 1 if loaded, 0 if nothing
    (defun history-load (idx)
      (let ((ridx (logand idx 7)))
        (let ((base (+ #x312010 (* ridx 256))))
          (let ((len 0))
            ;; Measure entry length
            (loop
              (if (zerop (mem-ref (+ base len) :u8))
                  (return 0)
                  (setq len (+ len 1)))
              (when (> len 254)
                (return 0)))
            (if (zerop len)
                0
                (progn
                  ;; Copy to line buffer
                  (let ((i 0))
                    (loop
                      (if (< i len)
                          (progn
                            (setf (mem-ref (+ #x300028 i) :u8)
                                  (mem-ref (+ base i) :u8))
                            (setq i (+ i 1)))
                          (return 0))))
                  (edit-set-line-len len)
                  (edit-set-cursor-pos len)
                  1))))))

    ;; Navigate history up (older)
    (defun history-up ()
      (let ((bi (history-browse-idx))
            (wi (history-write-idx)))
        ;; Don't go back more than 8 entries or past write idx
        (when (> bi 0)
          (when (> bi (if (> wi 8) (- wi 8) 0))
            (let ((new-bi (- bi 1)))
              (setf (mem-ref #x312008 :u64) new-bi)
              (history-load new-bi)
              (line-redraw-full))))))

    ;; Navigate history down (newer)
    (defun history-down ()
      (let ((bi (history-browse-idx))
            (wi (history-write-idx)))
        (if (< bi (- wi 1))
            ;; Load next entry
            (let ((new-bi (+ bi 1)))
              (setf (mem-ref #x312008 :u64) new-bi)
              (history-load new-bi)
              (line-redraw-full))
            ;; At end: clear line
            (progn
              (setf (mem-ref #x312008 :u64) wi)
              (edit-set-line-len 0)
              (edit-set-cursor-pos 0)
              (line-redraw-full)))))

    ;; --- Tab completion ---
    ;; Symbol name table at 0x310000:
    ;;   [+0]: entry count (u64)
    ;;   [+8]: packed entries [len:u8][chars...]

    ;; Find word start from cursor position (scan back for space or SOL)
    (defun find-word-start ()
      (let ((pos (edit-cursor-pos))
            (i (- (edit-cursor-pos) 1)))
        (if (< pos 1)
            0
            (progn
              (loop
                (if (< i 0)
                    (return 0)
                    (let ((ch (mem-ref (+ #x300028 i) :u8)))
                      (if (eq ch 32)  ; space
                          (return (+ i 1))
                          (if (eq ch 40)  ; '('
                              (return (+ i 1))
                              (if (eq ch 41)  ; ')'
                                  (return (+ i 1))
                                  (setq i (- i 1))))))))))))

    ;; Match prefix against symbol name table
    ;; Stores matches at 0x312900 (temp buffer, up to 16 match indices)
    ;; Returns match count
    (defun sym-table-match (prefix-start prefix-len)
      (let ((count (mem-ref #x310000 :u64))
            (offset 8)
            (matches 0)
            (idx 0))
        (loop
          (if (< idx count)
              (let ((entry-len (mem-ref (+ #x310000 offset) :u8)))
                ;; Check if prefix matches
                (if (< entry-len prefix-len)
                    nil  ; entry shorter than prefix, skip
                    (let ((match 1)
                          (j 0))
                      (loop
                        (if (< j prefix-len)
                            (if (eq (mem-ref (+ #x300028 (+ prefix-start j)) :u8)
                                    (mem-ref (+ #x310001 (+ offset j)) :u8))
                                (setq j (+ j 1))
                                (progn
                                  (setq match 0)
                                  (setq j prefix-len)))  ; break
                            (return 0)))
                      (when (not (zerop match))
                        ;; Store match: save offset in temp buffer
                        (when (< matches 16)
                          (setf (mem-ref (+ #x312900 (* matches 8)) :u64) offset))
                        (setq matches (+ matches 1)))))
                ;; Advance to next entry
                (setq offset (+ offset 1 entry-len))
                (setq idx (+ idx 1)))
              (return matches)))))

    ;; Perform tab completion
    (defun tab-complete ()
      (let ((ws (find-word-start))
            (pos (edit-cursor-pos)))
        (let ((plen (- pos ws)))
          (when (> plen 0)
            (let ((nmatches (sym-table-match ws plen)))
              (if (eq nmatches 1)
                  ;; Single match: complete it
                  (let ((moff (mem-ref #x312900 :u64)))
                    (let ((entry-len (mem-ref (+ #x310000 moff) :u8)))
                      ;; Insert remaining chars
                      (let ((i plen))
                        (loop
                          (if (< i entry-len)
                              (progn
                                (line-insert-byte (mem-ref (+ #x310001 (+ moff i)) :u8))
                                (setq i (+ i 1)))
                              (return 0))))))
                  (when (> nmatches 1)
                    ;; Multiple matches: print them
                    (write-byte 10)
                    (let ((mi 0)
                          (show-count (if (> nmatches 16) 16 nmatches)))
                      (loop
                        (if (< mi show-count)
                            (let ((moff (mem-ref (+ #x312900 (* mi 8)) :u64)))
                              (let ((entry-len (mem-ref (+ #x310000 moff) :u8)))
                                (let ((k 0))
                                  (loop
                                    (if (< k entry-len)
                                        (progn
                                          (write-byte (mem-ref (+ #x310001 (+ moff k)) :u8))
                                          (setq k (+ k 1)))
                                        (return 0))))
                                (write-byte 32))  ; space between matches
                              (setq mi (+ mi 1)))
                            (return 0))))
                    (write-byte 10)
                    ;; Reprint prompt + current line
                    (line-redraw-full))))))))

    ;; --- Line-based eval and number parsing ---

    ;; Evaluate expression from line buffer (called when line starts with '(')
    ;; FIFO must be set up by caller: pos=1 (skip '('), len=line-len
    (defun eval-line-expr ()
      ;; Suppress serial echo during reader parse (already echoed)
      (setf (mem-ref #x300014 :u32) 2)
      (let ((lst (read-list)))
        (setf (mem-ref #x300014 :u32) 0)
        (write-byte 10)
        (write-byte 61) (write-byte 32)  ; "= "
        (print-obj (native-eval lst))
        (write-byte 10)))

    ;; Parse decimal number from line buffer and print
    (defun parse-print-line-number ()
      (let ((len (edit-line-len))
            (i 0)
            (num 0)
            (hex-mode 0))
        ;; Check for 0x prefix
        (if (> len 1)
            (if (eq (mem-ref #x300028 :u8) 48)  ; '0'
                (if (eq (mem-ref #x300029 :u8) 120)  ; 'x'
                    (progn
                      (setq hex-mode 1)
                      (setq i 2))
                    nil)
                nil)
            nil)
        (if (not (zerop hex-mode))
            ;; Parse hex
            (progn
              (loop
                (if (< i len)
                    (let ((b (mem-ref (+ #x300028 i) :u8)))
                      (if (raw-hex-digitp b)
                          (progn
                            (setq num (+ (* num 16) (raw-hex-digit-value b)))
                            (setq i (+ i 1)))
                          (return 0)))
                    (return 0)))
              (write-byte 10)
              (write-byte 61) (write-byte 32)  ; "= "
              (print-dec num)
              (write-byte 10))
            ;; Parse decimal
            (progn
              (loop
                (if (< i len)
                    (let ((b (mem-ref (+ #x300028 i) :u8)))
                      (if (raw-digitp b)
                          (progn
                            (setq num (+ (* num 10) (raw-digit-value b)))
                            (setq i (+ i 1)))
                          (return 0)))
                    (return 0)))
              (write-byte 10)
              (write-byte 61) (write-byte 32)  ; "= "
              (print-obj num)
              (write-byte 10)))))

    ;; ================================================================
    ;; Phase 2: Image Buffer for Self-Hosting
    ;; ================================================================
    ;; Image buffer at 0x08000000 (128MB mark, above all other regions)
    ;; Position counter at 0x4FF040
    ;; Build metadata at 0x4FF050-0x4FF078

    ;; Initialize image buffer — zero position counter
    (defun img-init ()
      (setf (mem-ref #x4FF040 :u64) 0)
      ;; Zero first 64 bytes as header area
      (let ((i 0))
        (loop
          (if (>= i 64)
              (return 0)
              (progn
                (setf (mem-ref (+ #x08000000 i) :u8) 0)
                (setq i (+ i 1)))))))

    ;; Get current image buffer position
    (defun img-pos ()
      (mem-ref #x4FF040 :u64))

    ;; Emit one byte to image buffer
    (defun img-emit (b)
      (let ((pos (mem-ref #x4FF040 :u64)))
        (setf (mem-ref (+ #x08000000 pos) :u8) b)
        (setf (mem-ref #x4FF040 :u64) (+ pos 1))))

    ;; Emit 32-bit little-endian value
    (defun img-emit-u32 (v)
      (img-emit (logand v 255))
      (img-emit (logand (ash v -8) 255))
      (img-emit (logand (ash v -16) 255))
      (img-emit (logand (ash v -24) 255)))

    ;; Emit 64-bit little-endian value
    (defun img-emit-u64 (v)
      (img-emit (logand v 255))
      (img-emit (logand (ash v -8) 255))
      (img-emit (logand (ash v -16) 255))
      (img-emit (logand (ash v -24) 255))
      (img-emit (logand (ash v -32) 255))
      (img-emit (logand (ash v -40) 255))
      (img-emit (logand (ash v -48) 255))
      (img-emit (logand (ash v -56) 255)))

    ;; Patch 4 bytes at arbitrary offset in image buffer
    (defun img-patch-u32 (offset v)
      (setf (mem-ref (+ #x08000000 offset) :u8) (logand v 255))
      (setf (mem-ref (+ #x08000001 offset) :u8) (logand (ash v -8) 255))
      (setf (mem-ref (+ #x08000002 offset) :u8) (logand (ash v -16) 255))
      (setf (mem-ref (+ #x08000003 offset) :u8) (logand (ash v -24) 255)))

    ;; Copy a block from source address into image buffer
    ;; src-addr and size are tagged fixnums
    (defun img-copy-from (src-addr size)
      (let ((i 0))
        (loop
          (if (>= i size)
              (return i)
              (progn
                (img-emit (mem-ref (+ src-addr i) :u8))
                (setq i (+ i 1)))))))

    ;; Copy boot preamble from our own kernel image
    ;; Boot code starts at 0x100000, size stored at 0x4FF050
    (defun img-emit-boot-preamble ()
      (let ((size (mem-ref #x4FF050 :u64)))
        (img-copy-from #x100000 size)))

    ;; Read a byte from image buffer at offset
    (defun img-ref (offset)
      (mem-ref (+ #x08000000 offset) :u8))

    ;; Send image buffer contents over TCP
    ;; Assumes TCP connection already established
    (defun img-send-tcp (size)
      (let ((i 0)
            (chunk-size 1024))
        (loop
          (if (>= i size)
              (return i)
              (let ((remaining (- size i)))
                (let ((send-size (if (< remaining chunk-size) remaining chunk-size)))
                  ;; Send chunk: copy to temp buffer, then tcp-send
                  ;; For now, send byte-by-byte (slow but correct)
                  (let ((j 0))
                    (loop
                      (if (>= j send-size)
                          (return 0)
                          (progn
                            (setf (mem-ref (+ #x300100 j) :u8) (img-ref (+ i j)))
                            (setq j (+ j 1))))))
                  (tcp-send #x300100 send-size)
                  (setq i (+ i send-size))))))))

    ;; ================================================================
    ;; Self-Hosting: Build Modus64 Kernel From Within
    ;; ================================================================
    ;; This section implements the self-hosting build system. The running
    ;; kernel can compile itself into a new bootable image without SBCL.
    ;;
    ;; Memory layout for self-hosting:
    ;;   0x4FF040: img-pos (image buffer write position)
    ;;   0x4FF050: preamble size (set by SBCL build)
    ;;   0x4FF058: total image size (set by SBCL build)
    ;;   0x4FF080: img-compile-mode (0=normal, 1=image buffer)
    ;;   0x4FF088: img-code-base (image load address, usually 0x100000)
    ;;   0x4FF090: source blob address (set by SBCL build)
    ;;   0x4FF098: source blob length (set by SBCL build)
    ;;   0x4FF0A0: source read position (runtime cursor)
    ;;   0x08000000: image buffer (up to ~32MB)
    ;;   0x0A000000: image NFN table (2048 × 16 bytes)
    ;;   0x0A100000: forward reference patch list

    ;; ---- Step 1: Dual-mode code emission ----
    ;; When img-compile-mode is 1, code-emit/code-pos/code-patch redirect
    ;; to the image buffer instead of the normal code buffer at 0x500008.

    (defun img-compile-mode ()
      (mem-ref #x4FF080 :u64))

    (defun img-compile-enter ()
      (setf (mem-ref #x4FF080 :u64) 1)
      (setf (mem-ref #x4FF088 :u64) #x100000))

    (defun img-compile-exit ()
      (setf (mem-ref #x4FF080 :u64) 0))

    ;; ---- Step 2: Image NFN table ----
    ;; Separate NFN table at 0x08800000 for the image being built.
    ;; Same structure as runtime NFN: 2048 slots × 16 bytes, open-addressing.

    (defun img-nfn-init ()
      (let ((i 0))
        (loop
          (if (>= i 4096)
              (return 0)
              (progn
                (setf (mem-ref (+ #x0A000000 (* i 8)) :u64) 0)
                (setq i (+ i 1)))))))

    (defun img-nfn-define (name addr)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 2048)
              (return 0)
              (let ((base (+ #x0A000000 (* slot 16))))
                (let ((entry-name (mem-ref base :u64)))
                  (if (eq entry-name 0)
                      (progn
                        (setf (mem-ref base :u64) name)
                        (setf (mem-ref (+ base 8) :u64) addr)
                        (return name))
                      (if (eq entry-name name)
                          (progn
                            (setf (mem-ref (+ base 8) :u64) addr)
                            (return name))
                          (progn
                            (setq slot (logand (+ slot 1) 2047))
                            (setq tries (+ tries 1)))))))))))

    (defun img-nfn-lookup (name)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 2048)
              (return ())
              (let ((base (+ #x0A000000 (* slot 16))))
                (let ((entry-name (mem-ref base :u64)))
                  (if (eq entry-name 0)
                      (return ())
                      (if (eq entry-name name)
                          (return (mem-ref (+ base 8) :u64))
                          (progn
                            (setq slot (logand (+ slot 1) 2047))
                            (setq tries (+ tries 1)))))))))))

    ;; Count entries in image NFN table
    (defun img-nfn-count ()
      (let ((count 0) (i 0))
        (loop
          (if (>= i 2048)
              (return count)
              (progn
                (if (not (eq (mem-ref (+ #x0A000000 (* i 16)) :u64) 0))
                    (setq count (+ count 1))
                    ())
                (setq i (+ i 1)))))))

    ;; ---- Forward reference patch list ----
    ;; During image compilation, function calls to not-yet-compiled functions
    ;; are recorded here. After all functions are compiled, the list is
    ;; iterated to patch the placeholder addresses with actual addresses.
    ;; Layout at 0x08900000:
    ;;   [0]: count (u64)
    ;;   [8 + i*16]: patch offset in image buffer (u64)
    ;;   [16 + i*16]: function name hash (u64)

    (defun img-fwd-init ()
      (setf (mem-ref #x0A100000 :u64) 0))

    (defun img-fwd-record (patch-offset name-hash)
      (let ((count (mem-ref #x0A100000 :u64)))
        (let ((base (+ #x0A100008 (* count 16))))
          (setf (mem-ref base :u64) patch-offset)
          (setf (mem-ref (+ base 8) :u64) name-hash)
          (setf (mem-ref #x0A100000 :u64) (+ count 1)))))

    ;; Patch all forward references by looking up each recorded hash
    ;; in the image NFN table and writing the address into the image.
    ;; Returns the number of successfully patched references.
    (defun img-patch-forward-refs ()
      (let ((count (mem-ref #x0A100000 :u64))
            (patched 0)
            (i 0))
        (loop
          (if (>= i count)
              (return patched)
              (let ((base (+ #x0A100008 (* i 16))))
                (let ((patch-offset (mem-ref base :u64))
                      (name-hash (mem-ref (+ base 8) :u64)))
                  (let ((addr (img-nfn-lookup name-hash)))
                    (if addr
                        (progn
                          (img-patch-u64 patch-offset addr)
                          (setq patched (+ patched 1)))
                        ()))
                  (setq i (+ i 1))))))))

    ;; ---- Dual-mode dispatch for code-emit, code-pos, etc. ----
    ;; These replace the originals during image compilation.
    ;; The original code-emit/code-pos/nfn-define/nfn-lookup above
    ;; always use the normal code buffer. These wrapper versions
    ;; check the mode flag and dispatch accordingly.
    ;;
    ;; We can't modify the originals (they're already compiled), but
    ;; the native compiler resolves function calls via nfn-lookup,
    ;; so we can override by redefining at the REPL before calling
    ;; build-image. Instead, build-image saves/restores code-emit etc.
    ;; via a different approach: we modify rt-compile-defun-img to
    ;; directly use the image buffer functions.

    ;; Compile a (defun ...) form into the image buffer.
    ;; Delegates to rt-compile-defun which already handles image mode:
    ;; code-emit writes to image buffer, code-pos returns img-pos,
    ;; nfn-define writes to image NFN table, start-addr uses 0x100000 base.
    (defun img-compile-defun (args)
      (rt-compile-defun args))

    ;; ---- Step 3: Source blob reader ----
    ;; At build time, SBCL serializes the source of *runtime-functions*
    ;; as ASCII text at a known address. At runtime, we read from this blob
    ;; using a cursor at 0x4FF0A0.
    ;;
    ;; Source blob address: (mem-ref #x4FF090 :u64)
    ;; Source blob length:  (mem-ref #x4FF098 :u64)
    ;; Current read pos:    (mem-ref #x4FF0A0 :u64)

    (defun src-pos ()
      (mem-ref #x4FF0A0 :u64))

    (defun src-set-pos (p)
      (setf (mem-ref #x4FF0A0 :u64) p))

    (defun src-len ()
      (mem-ref #x4FF098 :u64))

    (defun src-base ()
      (mem-ref #x4FF090 :u64))

    (defun src-eof-p ()
      (>= (src-pos) (src-len)))

    ;; Read one byte from source blob, advance cursor
    (defun src-read-byte ()
      (if (src-eof-p)
          0
          (let ((b (mem-ref (+ (src-base) (src-pos)) :u8)))
            (src-set-pos (+ (src-pos) 1))
            b)))

    ;; Peek at next byte without consuming
    (defun src-peek-byte ()
      (if (src-eof-p)
          0
          (mem-ref (+ (src-base) (src-pos)) :u8)))

    ;; Skip whitespace in source blob, return first non-ws byte
    (defun src-skip-ws ()
      (let ((done ())
            (ch 0))
        (loop
          (if done
              (return ch)
              (if (src-eof-p)
                  (return 0)
                  (progn
                    (setq ch (src-read-byte))
                    (if (eq ch 32)     ; space
                        ()
                        (if (eq ch 9)  ; tab
                            ()
                            (if (eq ch 10)  ; newline
                                ()
                                (if (eq ch 13)  ; CR
                                    ()
                                    (if (eq ch 59)  ; ';' - line comment
                                        (progn
                                          ;; Skip to end of line
                                          (loop
                                            (if (src-eof-p)
                                                (return 0)
                                                (let ((c (src-read-byte)))
                                                  (if (eq c 10)
                                                      (return 0)
                                                      ())))))
                                        (setq done t))))))))))))

    ;; Read a number from source blob (decimal)
    ;; Source blob uses integer IDs for symbols, so numbers are common.
    (defun src-read-num (first-char)
      ;; Accumulate decimal number from source blob.
      ;; Uses shifts instead of (* num 10) to avoid overflow in the
      ;; cross-compiler's multiply (which does tagged*tagged before SAR,
      ;; overflowing 63-bit signed range for 18-digit hash-chars IDs).
      ;; num*10 = num*8 + num*2 = (ash num 3) + (ash num 1)
      (let ((num (- first-char 48))
            (done ()))
        (loop
          (if done
              (return num)
              (if (src-eof-p)
                  (return num)
                  (let ((ch (src-read-byte)))
                    (if (raw-digitp ch)
                        (setq num (+ (+ (ash num 3) (ash num 1)) (- ch 48)))
                        (progn
                          (src-set-pos (- (src-pos) 1))
                          (setq done t)))))))))

    ;; Read a string literal from source blob (after opening " consumed)
    ;; Returns a Lisp string object
    (defun src-read-string ()
      (let ((buf (make-array 256))
            (len 0)
            (done ()))
        (loop
          (if done
              (let ((str (make-string len)))
                (let ((i 0))
                  (loop
                    (if (>= i len)
                        (return str)
                        (progn
                          (string-set str i (code-char (aref buf i)))
                          (setq i (+ i 1)))))))
              (if (src-eof-p)
                  (setq done t)
                  (let ((ch (src-read-byte)))
                    (if (eq ch 34)  ; closing "
                        (setq done t)
                        (if (eq ch 92)  ; backslash escape
                            (let ((esc (src-read-byte)))
                              (aset buf len (if (eq esc 110) 10  ; \n
                                                (if (eq esc 116) 9   ; \t
                                                    esc)))
                              (setq len (+ len 1)))
                            (progn
                              (aset buf len ch)
                              (setq len (+ len 1)))))))))))

    ;; Read a list from source blob (after ( consumed)
    (defun src-read-list ()
      (let ((result ())
            (done ()))
        (loop
          (if done
              (return (reverse-list result))
              (let ((ch (src-skip-ws)))
                (if (eq ch 41)  ; ')'
                    (setq done t)
                    (if (eq ch 0)  ; EOF
                        (setq done t)
                        (let ((elem (src-read-obj ch)))
                          (setq result (cons elem result))))))))))

    ;; Read a complete Lisp object from source blob.
    ;; The source blob has symbols pre-resolved to integer IDs by SBCL,
    ;; so we only need to handle: integers, negative integers, strings,
    ;; lists, and dotted pairs (. in lists).
    (defun src-read-obj (ch)
      (if (eq ch 40)  ; '('
          (src-read-list)
          (if (eq ch 34)  ; '"' string literal
              (src-read-string)
              (if (eq ch 45)  ; '-' negative number
                  (let ((next (src-peek-byte)))
                    (if (raw-digitp next)
                        (progn
                          (src-read-byte)
                          (- 0 (src-read-num next)))
                        0))
                  (if (raw-digitp ch)
                      (src-read-num ch)
                      ;; Dot for dotted pairs: skip, read next element
                      ;; (SBCL prin1 may output "NIL" for empty list... handle that)
                      0)))))

    ;; Read next top-level form from source blob
    ;; Returns the form, or () if EOF
    (defun src-read-next-form ()
      (let ((ch (src-skip-ws)))
        (if (eq ch 0)
            ()
            (src-read-obj ch))))

    ;; ---- Step 4: build-image orchestration ----

    ;; Compile all runtime functions from embedded source blob
    (defun img-compile-all-functions ()
      (src-set-pos 0)
      (let ((count 0))
        (loop
          (if (src-eof-p)
              (return count)
              (let ((form (src-read-next-form)))
                (if (null form)
                    (return count)
                    (progn
                      (write-byte 35)
                      (print-dec count)
                      (write-byte 32)
                      ;; Store each func START addr at 0x4FF0A8; last = kernel-main
                      ;; Compute start-addr BEFORE compilation (same as rt-compile-defun does)
                      (let ((start-addr (+ #x100000 (code-pos))))
                        (rt-compile-defun (cdr form))
                        (setf (mem-ref #x4FF0A8 :u64) start-addr))
                      (write-byte 46)
                      (setq count (+ count 1)))))))))


    ;; Generate and compile register-builtins for the new image.
    ;; Iterates the image NFN table and emits nfn-define calls for each entry.
    ;; This makes all cross-compiled functions available to the native compiler
    ;; when the new image boots.
    (defun img-compile-register-builtins ()
      (let ((i 0)
            (count 0))
        ;; First, build a list of (nfn-define name addr) calls
        ;; by scanning the image NFN table
        (let ((body ()))
          (loop
            (if (>= i 2048)
                ;; Now compile the register-builtins function
                ;; Wrap body list in progn since rt-compile-defun only takes one body form
                (let ((progn-body (cons (sym-progn) body)))
                  (let ((defun-form (cons (hash-of "register-builtins")
                                          (cons () (cons progn-body ())))))
                    (img-compile-defun defun-form)
                    (return count)))
                (let ((base (+ #x0A000000 (* i 16))))
                  (let ((name (mem-ref base :u64)))
                    (if (not (eq name 0))
                        (let ((addr (mem-ref (+ base 8) :u64)))
                          (setq body (cons (cons (hash-of "nfn-define")
                                                 (cons name (cons addr ())))
                                           body))
                          (setq count (+ count 1)))
                        ()))
                  (setq i (+ i 1))))))))

    ;; Generate and compile init-symbol-table for the new image.
    ;; Reads the existing symbol table at 0x310000 and replicates it.
    ;; Strategy: embed raw data in image, then emit a machine-code memcpy function.
    ;; This avoids generating thousands of setf calls (which would overflow the stack
    ;; during compilation due to recursive progn processing).
    (defun img-compile-init-symbol-table ()
      (let ((src-count (mem-ref #x310000 :u64)))
        ;; Compute total size of packed symbol table data by scanning entries
        (let ((scan-off 8)
              (scan-count 0))
          (loop
            (if (>= scan-count src-count)
                (return ())
                (let ((name-len (mem-ref (+ #x310000 scan-off) :u8)))
                  (setq scan-off (+ scan-off 1 name-len))
                  (setq scan-count (+ scan-count 1)))))
          ;; scan-off now = total bytes of packed data
          (let ((total-bytes scan-off))
            ;; Step 1: Emit raw symbol table data into image buffer
            (let ((data-start (img-pos)))
              (let ((copy-i 0))
                (loop
                  (if (>= copy-i total-bytes)
                      (return ())
                      (progn
                        (img-emit (mem-ref (+ #x310000 copy-i) :u8))
                        (setq copy-i (+ copy-i 1))))))
              ;; Step 2: Emit init-symbol-table as raw x86-64 memcpy code
              ;; Function copies total-bytes from data-addr to 0x310000
              (let ((data-addr (+ #x100000 data-start)))
                (let ((func-start (+ #x100000 (img-pos))))
                  ;; Register in image NFN table (via mode-checked nfn-define)
                  (nfn-define (hash-of "init-symbol-table") func-start)
                  ;; Emit: XOR ECX, ECX (counter = 0)
                  (code-emit #x31) (code-emit #xC9)
                  ;; Emit: CMP RCX, total-bytes (48 81 F9 imm32)
                  (code-emit #x48) (code-emit #x81) (code-emit #xF9)
                  (code-emit (logand total-bytes #xFF))
                  (code-emit (logand (ash total-bytes -8) #xFF))
                  (code-emit (logand (ash total-bytes -16) #xFF))
                  (code-emit (logand (ash total-bytes -24) #xFF))
                  ;; Emit: JGE +35 to .done (0F 8D rel32)
                  (code-emit #x0F) (code-emit #x8D)
                  (code-emit #x23) (code-emit #x00) (code-emit #x00) (code-emit #x00)
                  ;; Emit: MOV RAX, data-addr (48 B8 imm64)
                  (code-emit #x48) (code-emit #xB8)
                  (code-emit-u64 data-addr)
                  ;; Emit: MOVZX EDX, byte [RAX+RCX] (0F B6 14 08)
                  (code-emit #x0F) (code-emit #xB6) (code-emit #x14) (code-emit #x08)
                  ;; Emit: MOV RAX, 0x310000 (48 B8 imm64)
                  (code-emit #x48) (code-emit #xB8)
                  (code-emit-u64 #x310000)
                  ;; Emit: MOV [RAX+RCX], DL (88 14 08)
                  (code-emit #x88) (code-emit #x14) (code-emit #x08)
                  ;; Emit: INC RCX (48 FF C1)
                  (code-emit #x48) (code-emit #xFF) (code-emit #xC1)
                  ;; Emit: JMP .-48 back to CMP (E9 rel32)
                  (code-emit #xE9)
                  (code-emit #xD0) (code-emit #xFF) (code-emit #xFF) (code-emit #xFF)
                  ;; .done: XOR EAX, EAX (return nil=0)
                  (code-emit #x31) (code-emit #xC0)
                  ;; RET
                  (code-emit #xC3)
                  src-count)))))))

    ;; Compile kernel-main for the new image
    ;; MUST wrap body in progn since rt-compile-defun only takes one body form
    ;; kernel-main is now compiled from the source blob by img-compile-all-functions.
    ;; This no-op remains so build-image's call doesn't need changing.
    (defun img-compile-kernel-main ()
      ())

    ;; Patch metadata in the image buffer
    ;; Stores preamble size and total size at fixed offsets
    (defun img-patch-metadata ()
      (let ((preamble-size (mem-ref #x4FF050 :u64))
            (total-size (img-pos)))
        ;; Patch self-hosting metadata at 0x4FF050/0x4FF058
        ;; 0x4FF050 in image = offset 0x3FF050 from base 0x100000
        (let ((off-preamble (- #x4FF050 #x100000))
              (off-total (- #x4FF058 #x100000)))
          ;; Store tagged fixnums (shifted left 1)
          (let ((tagged-pre (ash preamble-size 1))
                (tagged-tot (ash total-size 1)))
            (img-patch-u64 off-preamble tagged-pre)
            (img-patch-u64 off-total tagged-tot)))
        ;; Patch multiboot header: load_end_addr (offset 20) and bss_end_addr (offset 24)
        ;; These must reflect the actual image size so bootloaders load everything
        (let ((load-end (+ #x100000 total-size)))
          (img-patch-u32 20 load-end)
          (img-patch-u32 24 load-end))))

    ;; Patch 8 bytes at arbitrary offset in image buffer
    (defun img-patch-u64 (offset v)
      (setf (mem-ref (+ #x08000000 offset) :u8) (logand v 255))
      (setf (mem-ref (+ #x08000001 offset) :u8) (logand (ash v -8) 255))
      (setf (mem-ref (+ #x08000002 offset) :u8) (logand (ash v -16) 255))
      (setf (mem-ref (+ #x08000003 offset) :u8) (logand (ash v -24) 255))
      (setf (mem-ref (+ #x08000004 offset) :u8) (logand (ash v -32) 255))
      (setf (mem-ref (+ #x08000005 offset) :u8) (logand (ash v -40) 255))
      (setf (mem-ref (+ #x08000006 offset) :u8) (logand (ash v -48) 255))
      (setf (mem-ref (+ #x08000007 offset) :u8) (logand (ash v -56) 255)))

    ;; Copy source blob from running kernel to image buffer for round-trip
    ;; self-hosting. Returns the image-relative position where the blob starts.
    (defun img-copy-source-blob ()
      (let ((base (src-base))
            (len (src-len))
            (blob-start (img-pos)))
        (let ((i 0))
          (loop
            (if (>= i len)
                (return blob-start)
                (progn
                  (img-emit (mem-ref (+ base i) :u8))
                  (setq i (+ i 1))))))))

    ;; Emit the call site into the image: stores metadata, calls kernel-main, halts
    ;; Also stores source blob address/length for round-trip self-hosting.
    ;; blob-vaddr/blob-len: 0 means skip source blob stores (first-gen only).
    (defun img-emit-call-site (blob-vaddr blob-len)
      (let ((preamble-size (mem-ref #x4FF050 :u64)))
        ;; Store trampoline physical address at 0x300010 (tagged fixnum)
        ;; The AP trampoline location is in the preamble, at the same relative
        ;; offset as in our running kernel. Read it from the running kernel's
        ;; stored value.
        (let ((tramp-addr (mem-ref #x300010 :u64)))
          ;; mov rax, tramp-addr (already tagged)
          (img-emit #x48) (img-emit #xB8)
          (img-emit-u64-raw tramp-addr)
          ;; mov [0x300010], rax
          (img-emit #x48) (img-emit #xA3)
          (img-emit-u64 #x300010))
        ;; Store preamble size at 0x4FF050 (tagged fixnum)
        ;; mov rax, preamble-size-tagged
        (img-emit #x48) (img-emit #xB8)
        (img-emit-u64 (ash preamble-size 1))
        ;; mov [0x4FF050], rax
        (img-emit #x48) (img-emit #xA3)
        (img-emit-u64 #x4FF050)
        ;; Store source blob address at 0x4FF090 (tagged fixnum)
        ;; This enables round-trip: the new image can run (build-image) too.
        (if (not (zerop blob-vaddr))
            (progn
              ;; mov rax, tagged-blob-addr
              (img-emit #x48) (img-emit #xB8)
              (img-emit-u64 (ash blob-vaddr 1))
              ;; mov [0x4FF090], rax
              (img-emit #x48) (img-emit #xA3)
              (img-emit-u64 #x4FF090)
              ;; mov rax, tagged-blob-len
              (img-emit #x48) (img-emit #xB8)
              (img-emit-u64 (ash blob-len 1))
              ;; mov [0x4FF098], rax
              (img-emit #x48) (img-emit #xA3)
              (img-emit-u64 #x4FF098))
            ())
        ;; Store register-builtins address at 0x4FF0B0 (tagged fixnum).
        ;; repl() calls (call-native (mem-ref #x4FF0B0 :u64)) to register
        ;; cross-compiled functions in the runtime NFN table.
        ;; Address was saved at 0x4FF0B0 by step 8b during image compilation.
        (let ((rb-addr (mem-ref #x4FF0B0 :u64)))
          (if rb-addr
              (progn
                ;; mov rax, rb-addr (tagged fixnum, preserved raw)
                (img-emit #x48) (img-emit #xB8)
                (img-emit-u64-raw rb-addr)
                ;; mov [0x4FF0B0], rax
                (img-emit #x48) (img-emit #xA3)
                (img-emit-u64 #x4FF0B0))
              ()))
        ;; Call kernel-main — addr stored at 0x4FF0A8 by img-compile-all-functions
        ;; (kernel-main is the last function in *runtime-functions*)
        (let ((km-addr (mem-ref #x4FF0A8 :u64)))
          (if km-addr
              (progn
                ;; mov rax, kernel-main-addr (tagged)
                (img-emit #x48) (img-emit #xB8)
                (img-emit-u64 km-addr)
                ;; call rax
                (img-emit #xFF) (img-emit #xD0))
              ()))
        ;; Infinite HLT loop
        (let ((halt-pos (img-pos)))
          (img-emit #xF4)       ; HLT
          ;; JMP back to HLT: EB FE (short jump -2)
          (img-emit #xEB) (img-emit #xFE))))

    ;; Emit raw bytes of a tagged value (for image buffer)
    ;; Like code-emit-u64-raw but writes to image buffer
    (defun img-emit-u64-raw (v)
      (setf (mem-ref #x4FF030 :u64) v)
      (img-emit (mem-ref #x4FF030 :u8))
      (img-emit (mem-ref #x4FF031 :u8))
      (img-emit (mem-ref #x4FF032 :u8))
      (img-emit (mem-ref #x4FF033 :u8))
      (img-emit (mem-ref #x4FF034 :u8))
      (img-emit (mem-ref #x4FF035 :u8))
      (img-emit (mem-ref #x4FF036 :u8))
      (img-emit (mem-ref #x4FF037 :u8)))

    ;; ---- Main entry point ----

    ;; Helper: print a short status marker (avoids string literal limitation)
    ;; B=Build P=Preamble C=Compiled R=Registered S=Symbol K=Kernel D=Done
    (defun img-status (ch)
      (write-byte ch)
      (write-byte 58)   ; ':'
      (write-byte 32))  ; ' '

    (defun build-image ()
      ;; 1. Initialize image buffer
      (img-init)
      ;; "B: " = Build starting
      (img-status 66)
      (write-byte 10)

      ;; 2. Copy boot preamble from running kernel
      (img-emit-boot-preamble)
      ;; "P: <n>"
      (img-status 80)
      (print-dec (img-pos))
      (write-byte 10)

      ;; 3. Emit jump-over: JMP rel32 right after preamble
      ;; MUST be immediately after preamble since preamble falls through here.
      ;; We'll patch the displacement after compiling everything.
      (let ((jmp-patch-pos (img-pos)))
        ;; E9 xx xx xx xx (JMP rel32)
        (img-emit #xE9)
        (img-emit 0) (img-emit 0) (img-emit 0) (img-emit 0)

        ;; 4. Zero the data structure region in the image buffer.
        ;; Runtime data (NFN table at 0x330000, metadata at 0x300000, etc.)
        ;; lives in the gap between preamble and code. Must be zeroed or
        ;; the self-built image boots with garbage in these areas.
        ;; Zero from img-pos to 0x500000 (about 5MB) using :u64 (8 bytes/iter).
        (let ((zpos (img-pos)))
          (loop
            (if (>= zpos #x500000)
                (return 0)
                (progn
                  (setf (mem-ref (+ #x08000000 zpos) :u64) 0)
                  (setq zpos (+ zpos 8))))))

        ;; 5. Skip img-pos past data structure region to avoid memory overlap
        ;; Functions at img-pos >= 0x500000 start at virtual addr >= 0x600000,
        ;; safely above all runtime data structures (0x300000-0x510000).
        (if (< (img-pos) #x500000)
            (setf (mem-ref #x4FF040 :u64) #x500000)
            ())

        ;; 6. Enter image-compile mode
        (img-compile-enter)
        (img-nfn-init)
        (img-fwd-init)

        ;; 7. Compile all runtime functions from embedded source
        ;; Use large scratch cons region to avoid GC during compilation.
        ;; Region at 0x10000000 (256MB), well above image buffer at 0x08000000.
        (set-alloc-ptr #x10000000)
        (set-alloc-limit #x1E000000)
        (let ((count (img-compile-all-functions)))
          ;; "C: <n> @<pos>"
          (img-status 67)
          (print-dec count)
          (write-byte 64)  ;; '@'
          (print-dec (img-pos))
          (write-byte 10))

        ;; 8. Generate and compile register-builtins
        (let ((nbuiltins (img-compile-register-builtins)))
          ;; "R: <n> @<pos>"
          (img-status 82)
          (print-dec nbuiltins)
          (write-byte 64)  ;; '@'
          (print-dec (img-pos))
          (write-byte 10))

        ;; 8b. Save register-builtins address at 0x4FF0B0 for call-site emission.
        ;; Must be done while still in image-compile mode so nfn-lookup uses
        ;; the image table (0x0A000000).
        (let ((rb-addr (nfn-lookup (hash-of "register-builtins"))))
          (if rb-addr
              (setf (mem-ref #x4FF0B0 :u64) rb-addr)
              ()))

        ;; 9. Generate and compile init-symbol-table
        (img-compile-init-symbol-table)
        ;; "S: @<pos>"
        (img-status 83)
        (write-byte 64)  ;; '@'
        (print-dec (img-pos))
        (write-byte 10)

        ;; 10. Compile kernel-main
        (img-compile-kernel-main)
        ;; "K: @<pos>"
        (img-status 75)
        (write-byte 64)  ;; '@'
        (print-dec (img-pos))
        (write-byte 10)

        ;; 11. Patch forward references (must be after ALL functions compiled)
        (let ((fwd-count (img-patch-forward-refs)))
          ;; "F: <n>"
          (img-status 70)
          (print-dec fwd-count)
          (write-byte 10))

        ;; 12. Exit image-compile mode
        (img-compile-exit)

        ;; 13. Copy source blob into image for round-trip self-hosting
        ;; The source blob text is appended to the image. On boot, the
        ;; call-site code stores its address/length at 0x4FF090/0x4FF098.
        (let ((blob-vaddr 0)
              (blob-len 0))
          (if (not (zerop (src-len)))
              (let ((blob-start-pos (img-copy-source-blob)))
                (setq blob-vaddr (+ #x100000 blob-start-pos))
                (setq blob-len (src-len))
                ;; Also patch statically in image buffer (belt and suspenders)
                (img-patch-u64 (- #x4FF090 #x100000) (ash blob-vaddr 1))
                (img-patch-u64 (- #x4FF098 #x100000) (ash blob-len 1))
                ;; "X: <len>"
                (img-status 88)
                (print-dec blob-len)
                (write-byte 10))
              ())

          ;; 14. Patch the JMP to land here (at the call site)
          (let ((call-site-pos (img-pos)))
            (let ((rel (- call-site-pos (+ jmp-patch-pos 5))))
              (img-patch-u32 (+ jmp-patch-pos 1) rel)))

          ;; 15. Emit call site (metadata stores + call kernel-main + HLT)
          (img-emit-call-site blob-vaddr blob-len)

          ;; 16. Patch metadata: preamble size, total size, and multiboot header
          (img-patch-metadata)

          ;; 17. Report: "D: <n>"
          (img-status 68)
          (print-dec (img-pos))
          (write-byte 10))))

    ;; ---- Step 5: Network transfer ----

    (defun send-image (host port)
      (tcp-connect host port)
      (img-send-tcp (img-pos))
      (tcp-close))

    ;; kernel-main: the entry point for the self-built image.
    ;; Compiled from the source blob so hash values match runtime computation.
    ;; register-builtins and init-symbol-table are forward references
    ;; that get patched by img-patch-forward-refs.
    ;; Test A: one nested let in loop (no memref)
    (defun test-1let-loop (name)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 3)
              (return tries)
              (let ((base (+ #x330000 (* slot 16))))
                (setq slot (logand (+ slot 1) 2047))
                (setq tries (+ tries 1)))))))

    ;; Test B: two nested lets in loop (no memref)
    (defun test-2let-loop (name)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 3)
              (return tries)
              (let ((base (+ #x330000 (* slot 16))))
                (let ((entry (+ base 8)))
                  (setq slot (logand (+ slot 1) 2047))
                  (setq tries (+ tries 1))))))))

    ;; Test C: one nested let with memref in loop
    (defun test-1let-memref-loop (name)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 3)
              (return tries)
              (let ((base (+ #x330000 (* slot 16))))
                (mem-ref base :u64)
                (setq slot (logand (+ slot 1) 2047))
                (setq tries (+ tries 1)))))))

    ;; Test D: two nested lets with memref in loop
    (defun test-2let-memref-loop (name)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 3)
              (return tries)
              (let ((base (+ #x330000 (* slot 16))))
                (let ((entry (mem-ref base :u64)))
                  (setq slot (logand (+ slot 1) 2047))
                  (setq tries (+ tries 1))))))))

    ;; Test E: 2 nested lets with if+return inside inner let
    (defun test-if-return-loop (name)
      (let ((slot (logand name 2047))
            (tries 0))
        (loop
          (if (>= tries 3)
              (return 0)
              (let ((base (+ #x330000 (* slot 16))))
                (let ((entry (mem-ref base :u64)))
                  (if (eq entry 0)
                      (return name)
                      (progn
                        (setq slot (logand (+ slot 1) 2047))
                        (setq tries (+ tries 1))))))))))

    ;;; ==========================================================
    ;;; Phase 0c: Hash Table Operations
    ;;; ==========================================================
    ;;;
    ;;; Hash tables stored as object with subtag #x41:
    ;;; Layout: [header:8 | capacity:8 | count:8 | entries...]
    ;;; Each entry is 2 words: [key:8 | value:8]
    ;;; Uses open addressing with linear probing.
    ;;; Keys are compared by eq. Hash on tagged pointer value.
    ;;; Empty slots have key = 0 (different from NIL which is a valid key).
    ;;; Deleted slots have key = 1 (sentinel, not a valid tagged pointer).

    (defun ht-hash-key (key capacity)
      ;; Hash a tagged key to a slot index
      ;; Use the key value itself as hash (fixnums are already shifted)
      ;; Multiply by a prime and mask to capacity
      (logand (ash (* key 2654435761) -8) (- capacity 1)))

    (defun make-hash-table ()
      ;; Create a new hash table with initial capacity 64
      (let ((capacity 64)
            (obj-size (+ 24 (* 128 8))))  ; header + cap + count + 64 pairs * 2 words
        ;; Allocate from general object space (GS:[0x28] = obj-alloc)
        (let ((base (percpu-ref 40)))  ; GS:[0x28]
          ;; Write header: subtag=#x41, element-count=(capacity * 2 + 2)
          (setf (mem-ref base :u64)
                (+ #x41 (ash (+ (* capacity 2) 2) 16)))
          ;; Write capacity
          (setf (mem-ref (+ base 8) :u64) (ash capacity 1))  ; tagged
          ;; Write count = 0
          (setf (mem-ref (+ base 16) :u64) 0)
          ;; Zero all entries (key=0 means empty)
          (let ((i 0))
            (loop
              (if (>= i (* capacity 2))
                  (return nil)
                  (progn
                    (setf (mem-ref (+ base 24 (* i 8)) :u64) 0)
                    (setq i (+ i 1))))))
          ;; Advance obj-alloc
          (percpu-set 40 (+ base obj-size))
          ;; Return tagged object pointer
          (+ base 9))))

    (defun gethash (key table)
      ;; Look up KEY in hash TABLE. Returns value or NIL.
      (let ((base (- table 9))  ; untag object
            (capacity (ash (mem-ref (+ (- table 9) 8) :u64) -1))  ; untagged
            (slot (ht-hash-key key 64))  ; initial slot
            (tries 0))
        (loop
          (if (>= tries capacity)
              (return nil)  ; table full, key not found
              (let ((entry-base (+ base 24 (* slot 16))))
                (let ((entry-key (mem-ref entry-base :u64)))
                  (if (eq entry-key 0)
                      (return nil)  ; empty slot, key not found
                      (if (eq entry-key key)
                          (return (mem-ref (+ entry-base 8) :u64))  ; found!
                          (progn
                            (setq slot (logand (+ slot 1) (- capacity 1)))
                            (setq tries (+ tries 1)))))))))))

    (defun sethash (key table value)
      ;; Set KEY to VALUE in hash TABLE. Returns VALUE.
      (let ((base (- table 9))  ; untag
            (capacity (ash (mem-ref (+ (- table 9) 8) :u64) -1))
            (slot (ht-hash-key key 64))
            (tries 0))
        (loop
          (if (>= tries capacity)
              (return value)  ; table full (should grow, but punt for now)
              (let ((entry-base (+ base 24 (* slot 16))))
                (let ((entry-key (mem-ref entry-base :u64)))
                  (if (eq entry-key 0)
                      ;; Empty slot: insert here
                      (progn
                        (setf (mem-ref entry-base :u64) key)
                        (setf (mem-ref (+ entry-base 8) :u64) value)
                        ;; Increment count
                        (setf (mem-ref (+ base 16) :u64)
                              (+ (mem-ref (+ base 16) :u64) 2))
                        (return value))
                      (if (eq entry-key key)
                          ;; Key exists: update value
                          (progn
                            (setf (mem-ref (+ entry-base 8) :u64) value)
                            (return value))
                          (progn
                            (setq slot (logand (+ slot 1) (- capacity 1)))
                            (setq tries (+ tries 1)))))))))))

    (defun remhash (key table)
      ;; Remove KEY from hash TABLE. Returns T if found, NIL otherwise.
      (let ((base (- table 9))
            (capacity (ash (mem-ref (+ (- table 9) 8) :u64) -1))
            (slot (ht-hash-key key 64))
            (tries 0))
        (loop
          (if (>= tries capacity)
              (return nil)
              (let ((entry-base (+ base 24 (* slot 16))))
                (let ((entry-key (mem-ref entry-base :u64)))
                  (if (eq entry-key 0)
                      (return nil)  ; empty slot, not found
                      (if (eq entry-key key)
                          ;; Found: mark as deleted (sentinel = 1)
                          (progn
                            (setf (mem-ref entry-base :u64) 1)  ; deleted sentinel
                            (setf (mem-ref (+ entry-base 8) :u64) 0)
                            ;; Decrement count
                            (setf (mem-ref (+ base 16) :u64)
                                  (- (mem-ref (+ base 16) :u64) 2))
                            (return t))
                          (progn
                            (setq slot (logand (+ slot 1) (- capacity 1)))
                            (setq tries (+ tries 1)))))))))))

    ;;; ==========================================================
    ;;; Phase 0e: Global Variable Table
    ;;; ==========================================================
    ;;;
    ;;; Global variables stored in a hash table at address 0x380000.
    ;;; Maps symbol hash (tagged fixnum) → tagged value.
    ;;; 0x380000-0x380008: pointer to global var hash table

    (defun init-global-vars ()
      ;; Initialize the global variable table
      (let ((ht (make-hash-table)))
        (setf (mem-ref #x380000 :u64) ht)))

    (defun symbol-value (name-hash)
      ;; Look up a global variable by its name hash
      (let ((ht (mem-ref #x380000 :u64)))
        (gethash name-hash ht)))

    (defun set-symbol-value (name-hash value)
      ;; Set a global variable by its name hash
      (let ((ht (mem-ref #x380000 :u64)))
        (sethash name-hash ht value)))

    ;;; ==========================================================
    ;;; Phase 0f: Error Handling
    ;;; ==========================================================

    (defun modus-error (code)
      ;; Signal an error. CODE is a tagged fixnum error code.
      ;; Prints error prefix and code, then halts.
      (write-byte 69)  ; 'E'
      (write-byte 82)  ; 'R'
      (write-byte 82)  ; 'R'
      (write-byte 58)  ; ':'
      (print-hex32 code)
      (write-byte 10)  ; newline
      (hlt))

    ;;; ==========================================================
    ;;; Phase 1d: Writer (print Lisp objects as text)
    ;;; ==========================================================

    (defun write-fixnum (n)
      ;; Print a fixnum as decimal text
      (if (< n 0)
          (progn
            (write-byte 45)  ; '-'
            (write-fixnum (- 0 n)))
          (if (< n 10)
              (write-byte (+ n 48))  ; '0' + n
              (progn
                (write-fixnum (truncate n 10))
                (write-byte (+ (mod n 10) 48))))))

    (defun write-string-contents (str)
      ;; Print the characters of a string object
      (let ((base (- str 9))   ; untag object
            (len (ash (logand (ash (mem-ref (- str 9) :u64) -16) #xFFFFFFFF) 0))
            (i 0))
        (loop
          (if (>= i len)
              (return nil)
              (progn
                (write-byte (mem-ref (+ base 8 i) :u8))
                (setq i (+ i 1)))))))

    (defun write-char-literal (c)
      ;; Print a character literal (#\x)
      (write-byte 35)   ; '#'
      (write-byte 92)   ; '\\'
      (write-byte (ash c -8)))  ; extract char code from immediate

    (defun kernel-main ()
      (write-byte 49)  ;; '1'
      (init-raw-constants)
      (write-byte 50)  ;; '2'
      (smp-init)
      (write-byte 51)  ;; '3'
      (actor-init)
      (write-byte 52)  ;; '4'
      (staging-init)
      (write-byte 53)  ;; '5'
      ;; Switch to actor 1's stack before entering REPL.
      ;; Boot RSP is at 0x300000 but actor 1's stack is 0x05210000-0x05220000.
      ;; GC computes stack bounds from actor ID, so RSP must be in actor 1's range.
      ;; Without this, GC scans 35MB of non-stack memory, corrupting code.
      (set-rsp #x05220000)
      (repl))

    )  ; end of *runtime-functions* list
  )  ; end of expand-hash-of
  "Runtime functions to compile")

;;; ============================================================
;;; Build Helpers
;;; ============================================================

;; compute-hash-chars is defined above *runtime-functions* (needed by expand-hash-of)

(defparameter *builtin-functions-to-register*
  '(pci-config-read pci-config-write pci-find-e1000
    e1000-write-reg e1000-read-reg e1000-read-eeprom
    e1000-init e1000-send e1000-receive e1000-rx-buf e1000-probe
    e1000-init-rx e1000-init-tx
    ;; Phase 6.4: ARP/IP/UDP
    htons htonl buf-write-u16 buf-write-u32
    buf-read-u16 buf-read-u32 buf-copy-mac
    eth-set-header arp-request arp-resolve arp-reply
    ip-checksum ip-send udp-send net-receive
    buf-read-u16-mem
    ;; Phase 6.5: TCP
    tcp-checksum tcp-send-segment tcp-connect
    buf-read-u32-mem tcp-send tcp-receive tcp-close
    ;; Phase 6.6: High-level
    net-init net-state tcp-test-send http-test tcp-echo-test
    ;; Phase 7.1: ICMP
    icmp-checksum icmp-handle ping
    ;; Phase 7.2: UDP Receive
    udp-handle udp-receive udp-rx-data-ref
    ;; Phase 7.3: DHCP
    ip-send-broadcast udp-send-broadcast
    dhcp-discover dhcp-request dhcp-parse-offer dhcp-client net-init-dhcp
    ;; Phase 7.4: DNS
    dns-encode-name dns-build-query dns-parse-response dns-resolve
    dns-test ping-test
    ;; Phase 7.5: SHA-256
    sha256-init sha256-ch sha256-maj sha256-bsig0 sha256-bsig1
    sha256-lsig0 sha256-lsig1 sha256-block sha256 sha256-test
    ;; Phase 7.5: ChaCha20
    chacha-rotl16 chacha-rotl12 chacha-rotl8 chacha-rotl7
    chacha-qr chacha-inner chacha-setup chacha-block
    chacha20-crypt chacha20-test
    ;; Phase 7.5: Poly1305
    buf-read-u32-le poly-from-17 poly-to-16 poly-add-limbs poly-reduce
    poly-mul-carry poly-mul poly-clamp poly1305 poly1305-test
    ;; Core array operations (cross-compiled for consistent object format)
    try-alloc-obj make-array aref aset array-length
    ;; String operations (cross-compiled for consistent object format)
    make-string string-ref string-set string-length print-string
    ;; GC helper for cross-compiled allocators
    init-gc-helper
    ;; Phase 7.5: X25519
    fe-from-bytes fe-from-int fe-copy fe-add fe-sub fe-carry fe-reduce
    fe-mul fe-sq fe-sq-iter fe-invert fe-to-bytes
    x25519 x25519-public-key x25519-test
    ;; Phase 7.6: SHA-512
    u64-add u64-xor u64-and u64-not
    sha512-ch sha512-maj sha512-sigma0 sha512-sigma1 sha512-lsig0 sha512-lsig1
    sha512-set-k sha512-init sha512-block sha512 sha512-test
    ;; Phase 7.7: Ed25519
    fe-store-fixed fe-load-fixed fe-equal fe-pow-sqrt
    ed-l-byte ed-c-byte ed25519-init ed-recover-x
    ed-double ed-add ed-scalar-mult ed-base-mult
    ed-to-affine ed-encode-point ed-decode-point
    ed25519-public-key ed-reduce-scalar ed-reduce-if-needed
    ed-scalar-add ed-scalar-mult-mod-l
    concat-bytes concat3-bytes
    ed25519-sign ed25519-verify ed25519-test
    ;; Phase 7.8: TCP Server
    tcp-listen tcp-accept
    ;; Phase 10: Multi-Connection SSH
    conn-base conn-ssh conn-alloc conn-free conn-init
    tcp-checksum-conn tcp-send-segment-conn tcp-send-conn tcp-ack-conn tcp-close-conn
    net-find-connection net-deliver-data net-wait-ack
    ssh-copy-host-key net-accept-connection
    conn-handler-fn ssh-connection-handler
    ssh-handler-0 ssh-handler-1 ssh-handler-2 ssh-handler-3
    net-handle-tcp net-actor-main
    ;; Phase 7.9: SSH Server
    ssh-random ssh-seed-random ssh-put-u32 ssh-get-u32
    ssh-make-str ssh-make-str-mem ssh-make-mpint
    ssh-concat2 ssh-mem-store ssh-mem-load ssh-make-nonce
    ssh-init-strings ssh-build-kexinit
    ssh-make-packet ssh-parse-packet
    ssh-encrypt-packet ssh-decrypt-packet ssh-send-payload
    ssh-buf-consume ssh-buf-to-array ssh-receive-packet
    ssh-send-version ssh-receive-version
    ssh-compute-exchange-hash ssh-encode-host-key
    ssh-derive-key ssh-derive-keys ssh-handle-kex
    ssh-send-newkeys ssh-send-service-accept
    ssh-send-auth-success ssh-send-auth-pk-ok
    ssh-send-channel-confirm ssh-send-channel-success
    ssh-send-channel-data ssh-send-string ssh-send-prompt
    ssh-set-host-key ssh-use-default-key
    ssh-handle-connection ssh-handle-userauth
    ssh-handle-ctrl-d ssh-handle-channel-data ssh-eval-line ssh-eval-expr ssh-server
    ;; Unified REPL: shared byte handler + SSH edit state
    ssh-load-edit-state ssh-save-edit-state ssh-flush-output
    ssh-do-eval ssh-do-eval-expr emit-prompt handle-edit-byte
    ;; Inter-session communication
    sessions whoami msg inbox
    ;; Auto-boot
    eval-cmdline
    ;; Phase 8: Actors
    actor-struct-addr actor-get actor-set actor-stack-top
    actor-init actor-spawn actor-enqueue actor-dequeue
    yield actor-self actor-count
    actor-exit actor-test-worker actor-test
    ;; Phase 8.2: Mailboxes
    mailbox-dequeue mailbox-enqueue-and-wake send receive receive-timeout
    actor-msg-worker actor-msg-test
    actor-ping-worker actor-ping-test
    actor-multi-test
    ;; Term serialization for actor messages (deep copy)
    staging-init needs-staging staging-tag staging-ptr-p staging-untag
    term-size term-encode term-decode-step
    make-bignum make-bignum-n staging-compact
    ;; Demo: deep-copy send demonstration
    print-val send-demo-worker send-demo
    ;; Phase 8.5: Link/Lifecycle
    link spawn-link
    actor-link-worker actor-link-test
    ;; Phase 8.5b: Supervisor
    sup-worker supervisor sup-test
    ;; Map-Reduce
    map-worker map-reduce-test
    ;; Ring Benchmark
    ring-node ring-test
    ;; Timeout
    timeout-test
    ;; Phase 8.3: Reduction counting / preemption
    busy-worker reply-worker preempt-test
    ;; GC stress tests
    gc-test obj-gc-test
    ;; Phase 9: SMP
    lapic-read lapic-write lapic-id lapic-enable lapic-timer-init
    smp-delay-10ms smp-delay-200us smp-copy-trampoline
    smp-fill-params smp-send-sipi-targeted smp-wait-alive smp-boot-ap
    validate-actor ap-entry ap-scheduler smp-init
    ;; Phase 9.2: Per-CPU + Spinlocks
    set-gs-base cpu-id spin-lock spin-unlock
    ;; Phase 9.4: IPI Wakeup
    send-ipi wake-idle-ap-check wake-idle-ap smp-worker smp-test
    ;; Parallel Benchmarks
    bench-worker par-bench
    ;; System
    halt quit
    ;; REPL Ergonomics: line editing, history, tab completion
    emit-csi cursor-right cursor-left print-dec-raw truncate-div mod-10
    erase-to-eol edit-line-len edit-cursor-pos edit-set-line-len edit-set-cursor-pos
    line-redraw-from-cursor line-redraw-full line-insert-byte line-delete-back
    history-write-idx history-browse-idx history-save history-load history-up history-down
    find-word-start sym-table-match tab-complete
    eval-line-expr parse-print-line-number
    ;; Self-hosting: image building
    img-init img-pos img-emit img-emit-u32 img-emit-u64 img-patch-u32
    img-copy-from img-emit-boot-preamble img-ref img-send-tcp
    img-compile-mode img-compile-enter img-compile-exit
    img-nfn-init img-nfn-define img-nfn-lookup img-nfn-count
    img-compile-defun
    src-pos src-set-pos src-len src-base src-eof-p
    src-read-byte src-peek-byte src-skip-ws
    src-read-num src-read-hex src-read-symbol src-read-string
    src-read-list src-read-obj src-read-next-form
    img-compile-all-functions img-compile-register-builtins
    img-compile-init-symbol-table img-compile-kernel-main
    img-patch-metadata img-patch-u64 img-copy-source-blob img-emit-call-site
    img-emit-u64-raw
    build-image send-image
    ;; Real-time clock
    rtc-seconds rtc-minutes rtc-hours rtc-day rtc-month rtc-year
    print-2digit print-time is-leap-year days-in-month unix-time)
  "List of cross-compiled functions to register in the native function table")

(defun generate-register-builtins ()
  "Generate (defun register-builtins () ...) form with nfn-define calls.
   Must be called AFTER all runtime functions are compiled so *functions*
   has the correct buffer positions. Adds base-addr (0x100000) to get
   absolute addresses since the kernel is loaded at that address."
  (let ((body nil)
        (base-addr #x100000)
        (count 0))
    (dolist (fn-name *builtin-functions-to-register*)
      (let* ((name-str (string-downcase (symbol-name fn-name)))
             (hash-id (compute-hash-chars name-str))
             (buf-pos (gethash fn-name *functions*)))
        (when buf-pos
          (let ((abs-addr (+ buf-pos base-addr)))
            (push `(nfn-define ,hash-id ,abs-addr) body)
            (incf count)))))
    `(defun register-builtins ()
       ,@(nreverse body))))

;; Inline builtin names that the native compiler handles directly.
;; These are NOT in *builtin-functions-to-register* but ARE callable from the REPL.
(defparameter *inline-builtin-names*
  '("+" "-" "*" "1+" "1-" "truncate" "mod"
    "eq" "<" ">" "zerop" "not"
    "logand" "logior" "logxor" "ash"
    "cons" "car" "cdr" "cadr" "cddr" "caddr" "consp" "atom"
    "length" "nth" "list" "listp" "null" "reverse" "append"
    "member" "assoc" "rplaca" "rplacd"
    "numberp" "integerp" "bignump" "stringp" "arrayp"
    "if" "loop" "return" "progn" "and" "or" "cond"
    "when" "unless" "dotimes" "let" "let*" "setq" "defun" "quote"
    "write-byte" "io-in-byte" "io-out-byte" "io-in-dword" "io-out-dword"
    "mem-ref" "setf"
    "make-bignum" "bignum-ref" "bignum-set"
    "bignum-add" "bignum-sub" "bignum-mul" "print-bignum"
    "function" "funcall" "gc"))

(defun generate-init-symbol-table ()
  "Generate (defun init-symbol-table () ...) that writes packed symbol names
   to 0x310000 at boot time. Format: [count:u64][len:u8][chars...]..."
  (let ((body nil)
        (offset 8)  ; skip count field
        (count 0)
        (seen (make-hash-table :test 'equal)))
    ;; Helper to add a name (dedup via hash table)
    (flet ((add-name (name-str)
             (when (and (not (gethash name-str seen))
                        (< (+ offset 1 (length name-str)) 8000))
               (setf (gethash name-str seen) t)
               (incf count)
               (push `(setf (mem-ref ,(+ #x310000 offset) :u8) ,(length name-str)) body)
               (incf offset)
               (loop for ch across name-str
                     for i from 0
                     do (push `(setf (mem-ref ,(+ #x310000 offset) :u8) ,(char-code ch)) body)
                        (incf offset)))))
      ;; Add inline builtin names (write-byte, cons, car, etc.)
      (dolist (name *inline-builtin-names*)
        (add-name name))
      ;; Add NFN-registered function names
      (dolist (fn-name *builtin-functions-to-register*)
        (add-name (string-downcase (symbol-name fn-name)))))
    ;; Emit count at start
    (push `(setf (mem-ref #x310000 :u64) ,count) body)
    (format t "Symbol table: ~D names, ~D bytes~%" count offset)
    `(defun init-symbol-table ()
       ,@(nreverse body))))

;;; ============================================================
;;; Self-Hosting: Source Serialization (SBCL side)
;;; ============================================================
;;; Convert Lisp forms to use runtime integer IDs for symbols,
;;; so the source blob can be parsed by a simple reader that
;;; only handles integers, strings, and lists.

(defparameter *known-symbol-ids*
  ;; Map from lowercase symbol name to fixed runtime ID.
  ;; Must match the sym-xxx functions in the runtime.
  (let ((ht (make-hash-table :test 'equal)))
    (flet ((add (name id) (setf (gethash name ht) id)))
      (add "+" 1) (add "-" 2) (add "*" 3)
      (add "car" 10) (add "cdr" 11) (add "cons" 12) (add "list" 13)
      (add "if" 20) (add "eq" 21) (add "null" 22) (add "quote" 23)
      (add "t" (compute-hash-chars "t")) (add "let" 25) (add "defun" 26) (add "<" 27) (add ">" 28)
      (add "loop" 29) (add "return" 30) (add "setq" 31) (add "progn" 32)
      (add "zerop" 33) (add "not" 34) (add "logand" 35)
      (add "cadr" 36) (add "cddr" 37) (add "caddr" 38)
      (add "1+" 39) (add "1-" 40) (add "consp" 41) (add "atom" 42)
      (add "length" 43) (add "nth" 44) (add "and" 45) (add "or" 46)
      (add "cond" 47) (add "listp" 48) (add "numberp" 49)
      (add "append" 50) (add "reverse" 51) (add "member" 52) (add "assoc" 53)
      (add "io-in-byte" 60) (add "io-out-byte" 61)
      (add "mem-ref" 62) (add "setf" 63) (add "ash" 64) (add "logior" 65)
      (add "logxor" 66) (add "gc" 67) (add "rplaca" 68) (add "rplacd" 69)
      (add "bignump" 70) (add "integerp" 71)
      (add "make-bignum" 72) (add "bignum-ref" 73) (add "bignum-set" 74)
      (add "bignum-add" 75) (add "bignum-sub" 76) (add "bignum-mul" 77)
      (add "print-bignum" 78) (add "truncate" 79) (add "mod" 80)
      (add "stringp" 85) (add "print-dec" 87) (add "let*" 88)
      (add "when" 89) (add "unless" 90) (add "dotimes" 91) (add "arrayp" 96)
      (add "function" 97) (add "funcall" 98) (add "write-byte" 99)
      ;; Single-letter variables a-z — use compute-hash-chars to avoid
      ;; collision with ASCII code literals in serialized source blob
      (loop for ch from (char-code #\a) to (char-code #\z)
            do (add (string (code-char ch)) (compute-hash-chars (string (code-char ch)))))
      ;; I/O dword
      (add "io-in-dword" 130) (add "io-out-dword" 131)
      ;; Networking symbols with fixed IDs
      (add "pci-config-read" 132) (add "pci-find-e1000" 133)
      (add "e1000-write-reg" 134) (add "e1000-read-reg" 135)
      (add "e1000-read-eeprom" 136) (add "e1000-init" 137)
      (add "e1000-send" 138) (add "e1000-receive" 139) (add "e1000-probe" 140)
      (add "arp-request" 141) (add "arp-resolve" 142) (add "ip-checksum" 143)
      (add "ip-send" 144) (add "udp-send" 145) (add "net-receive" 146)
      (add "htons" 147) (add "htonl" 148) (add "tcp-connect" 149)
      (add "tcp-send" 150) (add "tcp-receive" 151) (add "tcp-close" 152)
      (add "tcp-checksum" 153) (add "net-init" 154) (add "net-state" 155)
      (add "e1000-init-rx" 156) (add "e1000-init-tx" 157)
      (add "pci-config-write" 158))
    ht))

(defun symbol-to-runtime-id (sym)
  "Convert a CL symbol to its Modus64 runtime integer ID.
   Checks *known-symbol-ids* first for symbols with fixed sequential IDs
   (special forms, single-letter vars, etc.). Falls back to compute-hash-chars
   for all other symbols. NIL maps to 0."
  (cond
    ((null sym) 0)  ; NIL = 0
    ((keywordp sym)
     ;; Map mem-ref type keywords to small integers matching rt-compile-mem-ref
     (let ((kname (string-downcase (symbol-name sym))))
       (cond
         ((string= kname "u8") 1)
         ((string= kname "u16") 2)
         ((string= kname "u32") 4)
         ((string= kname "u64") 8)
         ;; Other keywords: use hash-chars with ":" prefix
         (t (compute-hash-chars (concatenate 'string ":" kname))))))
    (t
     (let* ((name (string-downcase (symbol-name sym)))
            (known-id (gethash name *known-symbol-ids*)))
       (or known-id (compute-hash-chars name))))))

(defun form-to-ids (form)
  "Recursively replace all symbols in FORM with their runtime integer IDs.
   Numbers and strings pass through unchanged.
   NIL as list terminator stays as NIL to preserve proper list structure.
   NIL as a value (car position or standalone) becomes 0."
  (cond
    ((null form) nil)     ; NIL as list terminator -> stays NIL (empty list)
    ((integerp form) form)
    ((symbolp form)
     (if (eq form 'nil)
         0               ; NIL as value -> 0
         (symbol-to-runtime-id form)))
    ((stringp form) form)
    ((consp form)
     (cons (form-to-ids-value (car form))
           (form-to-ids (cdr form))))
    (t form)))

(defun form-to-ids-value (form)
  "Convert FORM when it appears in a value position (car of a cons).
   NIL here means the value nil/false, not end-of-list."
  (cond
    ((null form) 0)       ; NIL as value -> 0
    ((integerp form) form)
    ((symbolp form) (symbol-to-runtime-id form))
    ((stringp form) form)
    ((consp form)
     (cons (form-to-ids-value (car form))
           (form-to-ids (cdr form))))
    (t form)))

(defun normalize-defun-body (form)
  "If FORM is (defun name (params) body1 body2 ...) with multiple body forms,
   wrap them in (progn body1 body2 ...) so the native compiler can handle it.
   Also ensures empty-body defuns get an explicit nil body."
  (if (and (consp form) (eq (car form) 'defun))
      (destructuring-bind (defun-sym name params &body body) form
        (cond
          ((null body) `(,defun-sym ,name ,params nil))
          ((> (length body) 1) `(,defun-sym ,name ,params (progn ,@body)))
          (t form)))
      form))

(defun all-runtime-forms ()
  "Return the full list of runtime forms: *runtime-functions* + shared net/ forms."
  (append *runtime-functions* (load-net-forms)))

(defun serialize-runtime-source ()
  "Serialize all runtime forms as text with symbols replaced by integer IDs.
   Returns a string containing all forms, one per line."
  (with-output-to-string (s)
    (dolist (form (all-runtime-forms))
      (let* ((normalized (normalize-defun-body form))
             (id-form (form-to-ids normalized)))
        (let ((*print-pretty* nil)
              (*print-base* 10)
              (*print-radix* nil))
          (prin1 id-form s))
        (write-char #\Newline s)))))

;;; ============================================================
;;; Phase 1: Plain Source Serialization (MVM path)
;;; ============================================================
;;; Instead of tokenizing symbols to integer IDs, serialize the
;;; source as plain readable Lisp text. This enables the self-hosting
;;; kernel to read, modify, and re-serialize its own source.

(defun serialize-runtime-source-plain ()
  "Serialize all runtime forms as plain readable Lisp source text.
   Phase 1c: the source blob becomes ASCII Lisp source rather than
   pre-tokenized data. Used for MVM-based cross-compilation."
  (with-output-to-string (s)
    (dolist (form (all-runtime-forms))
      (let* ((normalized (normalize-defun-body form))
             (*print-pretty* nil)
             (*print-case* :downcase)
             (*print-base* 10)
             (*print-radix* nil)
             (*print-escape* t)
             (*print-readably* t))
        (prin1 normalized s))
      (write-char #\Newline s))))

(defun verify-source-roundtrip ()
  "Phase 1 verification: read source → write source → read again → identical.
   Returns T if round-trip preserves all forms."
  (let* ((source-text (serialize-runtime-source-plain))
         (re-read (with-input-from-string (s source-text)
                    (loop for form = (read s nil :eof)
                          until (eq form :eof)
                          collect form))))
    ;; Compare each form
    (let ((original *runtime-functions*)
          (roundtrip re-read)
          (mismatches 0))
      (loop for o in original
            for r in roundtrip
            for i from 0
            do (let ((norm-o (normalize-defun-body o))
                     (norm-r (normalize-defun-body r)))
                 (unless (equal norm-o norm-r)
                   (format t "Mismatch at form ~D:~%  Original: ~S~%  Roundtrip: ~S~%"
                           i norm-o norm-r)
                   (incf mismatches))))
      (format t "Round-trip check: ~D forms, ~D mismatches~%"
              (length original) mismatches)
      (zerop mismatches))))

;;; ============================================================
;;; Build Process
;;; ============================================================

(defun build-kernel (output-path)
  "Build complete kernel image"
  (format t "Building Modus64 kernel...~%")

  (let ((*code-buffer* (make-code-buffer))
        (*functions* (make-hash-table :test 'eq))
        (*constants* nil))

    ;; Layout:
    ;; 0x100000: Multiboot header + 32-bit boot code
    ;; 0x100XXX: 64-bit entry
    ;; 0x100XXX: Compiled Lisp functions
    ;; 0x100XXX: Kernel init code

    (let* ((base-addr #x100000)
           (header-size 48))

      ;; Reserve space for multiboot header
      (dotimes (i header-size)
        (emit-byte *code-buffer* 0))

      ;; Emit 32-bit boot code (GDT + long mode switch)
      ;; emit-boot32-code returns the entry point offset within the buffer
      (let ((entry32-offset (emit-boot32-code *code-buffer* base-addr)))

        ;; Align to 16 bytes
        (loop while (not (zerop (mod (code-buffer-position *code-buffer*) 16)))
              do (emit-byte *code-buffer* #x90))

        ;; Mark 64-bit entry point
        (let ((entry64-offset (code-buffer-position *code-buffer*))
              (entry64-addr (+ base-addr (code-buffer-position *code-buffer*))))

          ;; Patch boot32 to jump here (second param unused)
          (patch-boot32-target *code-buffer* 0 entry64-addr)

          ;; Emit 64-bit initialization
          (emit-64bit-init *code-buffer*)

          ;; Emit AP trampoline data (Phase 9: SMP)
          ;; The trampoline is raw 16/32-bit code that would crash if executed
          ;; in 64-bit mode, so we jump over it.
          (let ((past-trampoline (make-label)))
            (emit-jmp *code-buffer* past-trampoline)
            (let ((trampoline-info (emit-ap-trampoline *code-buffer*)))
              (emit-label *code-buffer* past-trampoline)
              (let ((trampoline-phys-addr (+ base-addr (car trampoline-info))))
                (setf (gethash :trampoline-offset *functions*) (car trampoline-info))
                (format t "AP trampoline at physical 0x~X (kernel offset 0x~X, ~D bytes)~%"
                        trampoline-phys-addr (car trampoline-info) (cdr trampoline-info))
                ;; Store trampoline physical address at 0x300010 (read by smp-copy-trampoline)
                ;; Pre-tag as fixnum (shift left 1) so Lisp arithmetic works correctly
                ;; when smp-copy-trampoline reads it with mem-ref :u64
                ;; mov rax, (trampoline-phys-addr << 1)
                (emit-bytes *code-buffer* #x48 #xB8)
                (emit-u64 *code-buffer* (ash trampoline-phys-addr 1))
                ;; mov [0x300010], rax
                (emit-bytes *code-buffer* #x48 #xA3)
                (emit-u64 *code-buffer* #x300010))))

          ;; Record boot preamble size (offset where compiled functions start)
          (let ((preamble-size (code-buffer-position *code-buffer*)))
            (format t "Boot preamble size: ~D bytes (0x~X)~%" preamble-size preamble-size)

          ;; Jump over the compiled functions to the call site
          (let ((call-site-label (make-label)))
            (emit-jmp *code-buffer* call-site-label)

            ;; Compile runtime functions
            (format t "Compiling runtime functions...~%")
            (dolist (form *runtime-functions*)
              (compile-toplevel form))
            ;; Generate and compile register-builtins function
            ;; (must be compiled AFTER all runtime functions are compiled)
            (let ((reg-form (generate-register-builtins)))
              (format t "Registering ~D builtin functions~%"
                      (length *builtin-functions-to-register*))
              (compile-toplevel reg-form))
            ;; Generate and compile init-symbol-table for tab completion
            (let ((sym-form (generate-init-symbol-table)))
              (compile-toplevel sym-form))
            ;; Patch forward function references
            (dolist (fixup *constants*)
              (when (and (listp fixup) (= (length fixup) 2))
                (let ((call-offset (first fixup))
                      (fn-name (second fixup)))
                  (when (symbolp fn-name)
                    (let ((fn-addr (gethash fn-name *functions*)))
                      (when fn-addr
                        ;; Patch the relative call offset
                        ;; call instruction is 5 bytes: E8 xx xx xx xx
                        ;; The offset is relative to the instruction AFTER the call
                        (let* ((patch-pos (1+ call-offset))  ; Skip the E8 opcode
                               (next-ip (+ call-offset 5))   ; IP after call instruction
                               (rel-offset (- fn-addr next-ip)))
                          (setf (aref (code-buffer-bytes *code-buffer*) patch-pos)
                                (logand rel-offset #xFF))
                          (setf (aref (code-buffer-bytes *code-buffer*) (+ patch-pos 1))
                                (logand (ash rel-offset -8) #xFF))
                          (setf (aref (code-buffer-bytes *code-buffer*) (+ patch-pos 2))
                                (logand (ash rel-offset -16) #xFF))
                          (setf (aref (code-buffer-bytes *code-buffer*) (+ patch-pos 3))
                                (logand (ash rel-offset -24) #xFF)))))))))
            ;; Print function addresses
            (maphash (lambda (name addr)
                       (format t "  ~A: ~X~%" name addr))
                     *functions*)

            ;; Patch AP trampoline entry address at build time
            ;; The trampoline has param space at offset 0xF0 (entry function addr)
            ;; We write the raw absolute address of ap-entry directly into the
            ;; kernel image, so it gets copied to 0x80F0 by smp-copy-trampoline.
            ;; This bypasses the runtime nfn-lookup path entirely.
            (let ((trampoline-buf-offset (gethash :trampoline-offset *functions*))
                  (ap-entry-buf-offset (gethash 'ap-entry *functions*)))
              (when (and trampoline-buf-offset ap-entry-buf-offset)
                (let ((ap-entry-abs (+ ap-entry-buf-offset base-addr))
                      (param-offset (+ trampoline-buf-offset #xF0)))
                  (format t "Patching AP trampoline entry addr: 0x~X at buf offset 0x~X~%"
                          ap-entry-abs param-offset)
                  ;; Write 8-byte little-endian absolute address
                  (dotimes (i 8)
                    (setf (aref (code-buffer-bytes *code-buffer*) (+ param-offset i))
                          (logand (ash ap-entry-abs (* i -8)) #xFF))))))

            ;; Compile kernel init - run all tests
            (format t "Compiling kernel init...~%")
            (compile-toplevel '(defun kernel-main ()
                                ;; Initialize raw constants FIRST (needed for emit-call-rel32)
                                (init-raw-constants)
                                (test-mul)
                                (test-cons)
                                (test-types)
                                (test-list-ops)
                                (test-chars)
                                (test-native)
                                ;; Boot SMP first: sets GS base for BSP (needed by actor-init)
                                (smp-init)
                                ;; Initialize actor system (uses percpu-set for current-actor)
                                (actor-init)
                                ;; Initialize per-actor staging buffers for deep-copy send
                                (staging-init)
                                ;; Switch to actor 1's stack (GC needs RSP in actor's stack range)
                                (set-rsp #x05220000)
                                (repl)
                                ))

            ;; Call site - jump lands here
            (emit-label *code-buffer* call-site-label)

            ;; Store self-hosting metadata at fixed addresses (0x4FF050+)
            ;; These values let the running kernel reconstruct its own boot image
            ;; 0x4FF050: boot preamble size
            ;; mov rax, preamble-size (tagged as fixnum)
            (emit-bytes *code-buffer* #x48 #xB8)
            (emit-u64 *code-buffer* (ash preamble-size 1))
            ;; mov [0x4FF050], rax
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF050)

            ;; 0x4FF058: total image size (placeholder, patched below)
            ;; Each "mov rax, imm64; mov [addr], rax" is: 48 B8 [8 bytes] 48 A3 [8 bytes] = 20 bytes
            ;; The imm64 starts at offset +2 from the mov rax instruction
            (emit-bytes *code-buffer* #x48 #xB8)
            (setf (gethash :total-size-imm-pos *functions*) (code-buffer-position *code-buffer*))
            (emit-u64 *code-buffer* 0)  ; placeholder
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF058)

            ;; 0x4FF090: source blob address (placeholder, patched below)
            (emit-bytes *code-buffer* #x48 #xB8)
            (setf (gethash :src-addr-imm-pos *functions*) (code-buffer-position *code-buffer*))
            (emit-u64 *code-buffer* 0)  ; placeholder
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF090)

            ;; 0x4FF098: source blob length (placeholder, patched below)
            (emit-bytes *code-buffer* #x48 #xB8)
            (setf (gethash :src-len-imm-pos *functions*) (code-buffer-position *code-buffer*))
            (emit-u64 *code-buffer* 0)  ; placeholder
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF098)

            ;; Call kernel-main
            (emit-call *code-buffer* (gethash 'kernel-main *functions*)))

          ;; Infinite halt (shouldn't reach)
          (let ((halt-loop (make-label)))
            (emit-label *code-buffer* halt-loop)
            (emit-byte *code-buffer* #xF4)
            (emit-jmp *code-buffer* halt-loop))

          ;; Fix up labels
          (fixup-labels *code-buffer*)

          ;; Patch multiboot header
          (let ((entry32-addr (+ base-addr entry32-offset)))
            (patch-multiboot-header *code-buffer* base-addr entry32-addr))

          ;; ---- Self-hosting: embed runtime function source ----
          ;; Serialize *runtime-functions* with symbols replaced by integer IDs.
          ;; The running kernel uses this blob to recompile itself.
          (let ((src-start-offset (code-buffer-position *code-buffer*))
                (src-start-addr (+ base-addr (code-buffer-position *code-buffer*))))
            (let ((source-text (serialize-runtime-source)))
              (format t "Serialized source: ~D bytes~%" (length source-text))
              (loop for ch across source-text
                    do (emit-byte *code-buffer* (char-code ch))))
            (let ((src-len (- (code-buffer-position *code-buffer*) src-start-offset)))
              (format t "Source blob: ~D bytes at 0x~X (offset 0x~X)~%"
                      src-len src-start-addr src-start-offset)

              ;; Patch the call-site placeholder immediates with actual values
              ;; Source blob address -> 0x4FF090 placeholder
              (let ((src-addr-pos (gethash :src-addr-imm-pos *functions*))
                    (src-len-pos (gethash :src-len-imm-pos *functions*)))
                (let ((tagged-addr (ash src-start-addr 1))
                      (tagged-len (ash src-len 1)))
                  (dotimes (i 8)
                    (setf (aref (code-buffer-bytes *code-buffer*) (+ src-addr-pos i))
                          (logand (ash tagged-addr (* i -8)) #xFF)))
                  (dotimes (i 8)
                    (setf (aref (code-buffer-bytes *code-buffer*) (+ src-len-pos i))
                          (logand (ash tagged-len (* i -8)) #xFF)))))))

          ;; Patch total image size into call-site placeholder
          (let ((total-size (code-buffer-position *code-buffer*))
                (total-size-pos (gethash :total-size-imm-pos *functions*)))
            (let ((tagged-size (ash total-size 1)))
              (dotimes (i 8)
                (setf (aref (code-buffer-bytes *code-buffer*) (+ total-size-pos i))
                      (logand (ash tagged-size (* i -8)) #xFF))))
            (format t "Self-hosting metadata: preamble=~D, total=~D bytes~%"
                    preamble-size total-size)))))

    ;; Write output
    (with-open-file (out output-path
                         :direction :output
                         :element-type '(unsigned-byte 8)
                         :if-exists :supersede)
      (write-sequence (subseq (code-buffer-bytes *code-buffer*) 0
                             (code-buffer-position *code-buffer*))
                      out))

    (format t "Kernel written to ~A (~D bytes)~%"
            output-path (code-buffer-position *code-buffer*))
    (format t "~%To run: qemu-system-x86_64 -kernel ~A -nographic~%"
            output-path))))

;;; ============================================================
;;; MVM Build Pipeline
;;; ============================================================

(defun read-source-forms (path)
  "Read all Lisp forms from a source file. Returns list of forms."
  (with-open-file (s path :direction :input)
    (let ((forms nil))
      (loop
        (let ((form (read s nil :eof)))
          (when (eq form :eof)
            (return (nreverse forms)))
          (push form forms))))))

(defun load-net-forms ()
  "Load shared networking/crypto/SSH forms from net/.
   Returns a single list of all forms, with (hash-of ...) expanded."
  (let* ((base (asdf:system-source-directory :modus64))
         (net-dir (merge-pathnames "net/" base)))
    (format t "Loading shared network source from ~A~%" net-dir)
    (let ((all-forms
           (append (read-source-forms (merge-pathnames "arch-x86.lisp" net-dir))
                   (read-source-forms (merge-pathnames "e1000.lisp" net-dir))
                   (read-source-forms (merge-pathnames "ip.lisp" net-dir))
                   (read-source-forms (merge-pathnames "crypto.lisp" net-dir))
                   (read-source-forms (merge-pathnames "ssh.lisp" net-dir))
                   ;; Single-threaded SSH overrides (MVM x64 YIELD is NOP)
                   (read-source-forms (merge-pathnames "x86-ssh-overrides.lisp" net-dir)))))
      (format t "Loaded ~D network/crypto/SSH forms~%" (length all-forms))
      (expand-hash-of all-forms))))

(defun build-kernel-mvm (output-path)
  "Build kernel image using MVM compilation pipeline.
   Identical to build-kernel except runtime functions are compiled through
   MVM (compiler.lisp → translate-x64.lisp) instead of cross-compile.lisp."
  (format t "Building Modus64 kernel (MVM pipeline)...~%")

  (let ((*code-buffer* (make-code-buffer))
        (*functions* (make-hash-table :test 'eq))
        (*constants* nil))

    (let* ((base-addr #x100000)
           (header-size 48))

      ;; === BOOT PREAMBLE (identical to build-kernel) ===

      ;; Reserve space for multiboot header
      (dotimes (i header-size)
        (emit-byte *code-buffer* 0))

      ;; Emit 32-bit boot code
      (let ((entry32-offset (emit-boot32-code *code-buffer* base-addr)))

        ;; Align to 16 bytes
        (loop while (not (zerop (mod (code-buffer-position *code-buffer*) 16)))
              do (emit-byte *code-buffer* #x90))

        ;; Mark 64-bit entry point
        (let ((entry64-offset (code-buffer-position *code-buffer*))
              (entry64-addr (+ base-addr (code-buffer-position *code-buffer*))))

          ;; Patch boot32 to jump here
          (patch-boot32-target *code-buffer* 0 entry64-addr)

          ;; Emit 64-bit initialization
          (emit-64bit-init *code-buffer*)

          ;; Emit AP trampoline data
          (let ((past-trampoline (make-label)))
            (emit-jmp *code-buffer* past-trampoline)
            (let ((trampoline-info (emit-ap-trampoline *code-buffer*)))
              (emit-label *code-buffer* past-trampoline)
              (let ((trampoline-phys-addr (+ base-addr (car trampoline-info))))
                (setf (gethash :trampoline-offset *functions*) (car trampoline-info))
                (format t "AP trampoline at physical 0x~X (kernel offset 0x~X, ~D bytes)~%"
                        trampoline-phys-addr (car trampoline-info) (cdr trampoline-info))
                ;; Store trampoline physical address at 0x300010
                (emit-bytes *code-buffer* #x48 #xB8)
                (emit-u64 *code-buffer* (ash trampoline-phys-addr 1))
                (emit-bytes *code-buffer* #x48 #xA3)
                (emit-u64 *code-buffer* #x300010))))

          ;; Record boot preamble size
          (let ((preamble-size (code-buffer-position *code-buffer*)))
            (format t "Boot preamble size: ~D bytes (0x~X)~%" preamble-size preamble-size)

            ;; Jump over compiled functions to call site
            (let ((call-site-label (make-label)))
            (emit-jmp *code-buffer* call-site-label)

            ;; === MVM COMPILATION ===
            (format t "Compiling runtime functions (MVM pipeline)...~%")

            ;; 1. Register bootstrap macros (cond, and, or)
            (modus64.mvm:register-mvm-bootstrap-macros)

            ;; 2. Build form list: *runtime-functions* + shared net files + generated forms
            (let* ((net-forms (load-net-forms))
                   (sym-form (generate-init-symbol-table))
                   (main-form '(defun kernel-main ()
                                 (init-raw-constants)
                                 (smp-init)
                                 (actor-init)
                                 (staging-init)
                                 (set-rsp #x05220000)
                                 (repl)))
                   (all-forms (append *runtime-functions*
                                      net-forms
                                      (list sym-form main-form))))

              (format t "Compiling ~D forms via MVM...~%" (length all-forms))

              ;; 3. Compile to MVM bytecode
              (let ((module (modus64.mvm:mvm-compile-all all-forms)))
                (format t "MVM bytecode: ~D bytes, ~D functions~%"
                        (length (modus64.mvm:compiled-module-bytecode module))
                        (length (modus64.mvm:compiled-module-function-table module)))

                ;; 4. Extract function table for translator
                (let ((fn-table
                       (mapcar (lambda (fi)
                                 (list (modus64.mvm:function-info-name fi)
                                       (modus64.mvm:function-info-bytecode-offset fi)
                                       (modus64.mvm:function-info-bytecode-length fi)))
                               (modus64.mvm:compiled-module-function-table module))))

                  ;; 5. Translate MVM bytecode → x86-64 native code
                  (format t "Translating to x86-64 native code...~%")
                  (multiple-value-bind (native-buf fn-map)
                      (modus64.mvm.x64:translate-mvm-to-x64
                       (modus64.mvm:compiled-module-bytecode module) fn-table)

                    (format t "Native code: ~D bytes~%"
                            (code-buffer-position native-buf))

                    ;; 6. Copy native code into *code-buffer*
                    (let ((code-start (code-buffer-position *code-buffer*)))
                      (dotimes (i (code-buffer-position native-buf))
                        (emit-byte *code-buffer*
                                   (aref (code-buffer-bytes native-buf) i)))

                      ;; 7. Build *functions* hash from fn-map
                      ;; fn-map: string-name → label; label-position → byte offset in native-buf
                      (maphash (lambda (name label)
                                 (setf (gethash (intern (string-upcase name)
                                                        (find-package :modus64.build))
                                                *functions*)
                                       (+ code-start (label-position label))))
                               fn-map)
                      (format t "Registered ~D MVM-compiled functions~%"
                              (hash-table-count fn-map)))))))

            ;; === REGISTER-BUILTINS (old cross-compiler, one function) ===
            ;; generate-register-builtins reads *functions* → absolute addrs
            (let ((reg-form (generate-register-builtins)))
              (format t "Registering ~D builtin functions~%"
                      (length *builtin-functions-to-register*))
              (compile-toplevel reg-form))

            ;; === FORWARD REFERENCE PATCHING ===
            ;; Only needed for register-builtins (compiled with old cross-compiler).
            ;; MVM functions have all calls resolved internally.
            (dolist (fixup *constants*)
              (when (and (listp fixup) (= (length fixup) 2))
                (let ((call-offset (first fixup))
                      (fn-name (second fixup)))
                  (when (symbolp fn-name)
                    (let ((fn-addr (gethash fn-name *functions*)))
                      (when fn-addr
                        (let* ((patch-pos (1+ call-offset))
                               (next-ip (+ call-offset 5))
                               (rel-offset (- fn-addr next-ip)))
                          (setf (aref (code-buffer-bytes *code-buffer*) patch-pos)
                                (logand rel-offset #xFF))
                          (setf (aref (code-buffer-bytes *code-buffer*) (+ patch-pos 1))
                                (logand (ash rel-offset -8) #xFF))
                          (setf (aref (code-buffer-bytes *code-buffer*) (+ patch-pos 2))
                                (logand (ash rel-offset -16) #xFF))
                          (setf (aref (code-buffer-bytes *code-buffer*) (+ patch-pos 3))
                                (logand (ash rel-offset -24) #xFF)))))))))

            ;; Print function addresses
            (maphash (lambda (name addr)
                       (format t "  ~A: ~X~%" name addr))
                     *functions*)

            ;; Patch AP trampoline entry address at build time
            (let ((trampoline-buf-offset (gethash :trampoline-offset *functions*))
                  (ap-entry-buf-offset (gethash 'ap-entry *functions*)))
              (when (and trampoline-buf-offset ap-entry-buf-offset)
                (let ((ap-entry-abs (+ ap-entry-buf-offset base-addr))
                      (param-offset (+ trampoline-buf-offset #xF0)))
                  (format t "Patching AP trampoline entry addr: 0x~X at buf offset 0x~X~%"
                          ap-entry-abs param-offset)
                  (dotimes (i 8)
                    (setf (aref (code-buffer-bytes *code-buffer*) (+ param-offset i))
                          (logand (ash ap-entry-abs (* i -8)) #xFF))))))

            ;; Compile kernel init
            (format t "Compiling kernel-main call site...~%")

            ;; Call site - jump lands here
            (emit-label *code-buffer* call-site-label)

            ;; Store self-hosting metadata at fixed addresses (0x4FF050+)
            ;; 0x4FF050: boot preamble size
            (emit-bytes *code-buffer* #x48 #xB8)
            (emit-u64 *code-buffer* (ash preamble-size 1))
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF050)

            ;; 0x4FF058: total image size (placeholder, patched below)
            (emit-bytes *code-buffer* #x48 #xB8)
            (setf (gethash :total-size-imm-pos *functions*) (code-buffer-position *code-buffer*))
            (emit-u64 *code-buffer* 0)
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF058)

            ;; 0x4FF090: source blob address (placeholder, patched below)
            (emit-bytes *code-buffer* #x48 #xB8)
            (setf (gethash :src-addr-imm-pos *functions*) (code-buffer-position *code-buffer*))
            (emit-u64 *code-buffer* 0)
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF090)

            ;; 0x4FF098: source blob length (placeholder, patched below)
            (emit-bytes *code-buffer* #x48 #xB8)
            (setf (gethash :src-len-imm-pos *functions*) (code-buffer-position *code-buffer*))
            (emit-u64 *code-buffer* 0)
            (emit-bytes *code-buffer* #x48 #xA3)
            (emit-u64 *code-buffer* #x4FF098)

            ;; 0x4FF0B0: register-builtins address (tagged fixnum).
            ;; register-builtins is compiled by the old cross-compiler, not MVM,
            ;; so MVM-compiled repl() calls it indirectly via call-native.
            (let ((reg-builtins-addr (+ base-addr (gethash 'register-builtins *functions*))))
              (emit-bytes *code-buffer* #x48 #xB8)          ; mov rax, imm64
              (emit-u64 *code-buffer* (ash reg-builtins-addr 1))  ; tagged
              (emit-bytes *code-buffer* #x48 #xA3)          ; mov [imm64], rax
              (emit-u64 *code-buffer* #x4FF0B0))

            ;; Call kernel-main
            (emit-call *code-buffer* (gethash 'kernel-main *functions*)))

          ;; Infinite halt (shouldn't reach)
          (let ((halt-loop (make-label)))
            (emit-label *code-buffer* halt-loop)
            (emit-byte *code-buffer* #xF4)
            (emit-jmp *code-buffer* halt-loop))

          ;; Fix up labels
          (fixup-labels *code-buffer*)

          ;; Patch multiboot header
          (let ((entry32-addr (+ base-addr entry32-offset)))
            (patch-multiboot-header *code-buffer* base-addr entry32-addr))

          ;; Embed runtime function source (integer IDs, matches runtime reader)
          (let ((src-start-offset (code-buffer-position *code-buffer*))
                (src-start-addr (+ base-addr (code-buffer-position *code-buffer*))))
            (let ((source-text (serialize-runtime-source)))
              (format t "Serialized source: ~D bytes~%" (length source-text))
              (loop for ch across source-text
                    do (emit-byte *code-buffer* (char-code ch))))
            (let ((src-len (- (code-buffer-position *code-buffer*) src-start-offset)))
              (format t "Source blob: ~D bytes at 0x~X (offset 0x~X)~%"
                      src-len src-start-addr src-start-offset)

              ;; Patch source blob address/length placeholders
              (let ((src-addr-pos (gethash :src-addr-imm-pos *functions*))
                    (src-len-pos (gethash :src-len-imm-pos *functions*)))
                (let ((tagged-addr (ash src-start-addr 1))
                      (tagged-len (ash src-len 1)))
                  (dotimes (i 8)
                    (setf (aref (code-buffer-bytes *code-buffer*) (+ src-addr-pos i))
                          (logand (ash tagged-addr (* i -8)) #xFF)))
                  (dotimes (i 8)
                    (setf (aref (code-buffer-bytes *code-buffer*) (+ src-len-pos i))
                          (logand (ash tagged-len (* i -8)) #xFF)))))))

          ;; Patch total image size
          (let ((total-size (code-buffer-position *code-buffer*))
                (total-size-pos (gethash :total-size-imm-pos *functions*)))
            (let ((tagged-size (ash total-size 1)))
              (dotimes (i 8)
                (setf (aref (code-buffer-bytes *code-buffer*) (+ total-size-pos i))
                      (logand (ash tagged-size (* i -8)) #xFF))))
            (format t "Self-hosting metadata: preamble=~D, total=~D bytes~%"
                    preamble-size total-size)))))

    ;; Write output
    (with-open-file (out output-path
                         :direction :output
                         :element-type '(unsigned-byte 8)
                         :if-exists :supersede)
      (write-sequence (subseq (code-buffer-bytes *code-buffer*) 0
                             (code-buffer-position *code-buffer*))
                      out))

    (format t "Kernel written to ~A (~D bytes)~%"
            output-path (code-buffer-position *code-buffer*))
    (format t "~%To run: qemu-system-x86_64 -kernel ~A -nographic~%"
            output-path))))

;;; ============================================================
;;; Boot Code Emission
;;; ============================================================

(defun emit-boot32-code (buf base-addr)
  "Emit 32-bit boot code with GDT and long mode switch.
   Returns the offset of the entry point within the buffer."
  ;; GDT
  (let ((gdt-offset (code-buffer-position buf)))
    (emit-u64 buf 0)                    ; Null
    (emit-u64 buf #x00CF9A000000FFFF)   ; 32-bit code
    (emit-u64 buf #x00CF92000000FFFF)   ; 32-bit data
    (emit-u64 buf #x00AF9A000000FFFF)   ; 64-bit code
    (emit-u64 buf #x00AF92000000FFFF)   ; 64-bit data

    ;; GDTR
    (let ((gdtr-offset (code-buffer-position buf))
          (gdt-addr (+ base-addr gdt-offset)))
      (emit-u16 buf 39)
      (emit-u32 buf gdt-addr)

      ;; Entry point (CLI, LGDT, reload segs) - THIS is where execution starts
      (let ((entry-offset (code-buffer-position buf)))
          (emit-byte buf #xFA)            ; cli

          ;; lgdt
          (emit-bytes buf #x0F #x01 #x15)
          (emit-u32 buf (+ base-addr gdtr-offset))

          ;; Reload data segments
          (emit-bytes buf #x66 #xB8 #x10 #x00)
          (emit-bytes buf #x8E #xD8 #x8E #xC0 #x8E #xE0 #x8E #xE8 #x8E #xD0)

          ;; Far jump to reload CS
          (emit-byte buf #xEA)
          (emit-u32 buf (+ base-addr (code-buffer-position buf) 6))
          (emit-u16 buf #x08)

          ;; Save multiboot info
          (emit-bytes buf #x89 #x1D)
          (emit-u32 buf #x500)

          ;; Stack (at 0x300000 - well above kernel which can grow to ~512KB)
          (emit-byte buf #xBC)
          (emit-u32 buf #x300000)

          ;; Copy multiboot cmdline to 0x300200 (32-bit, before paging trashes memory)
          ;; Must match (ssh-ipc-base) + #x200 in arch-x86.lisp (= 0x300000 + 0x200)
          ;; Zero 256 bytes at 0x300200
          (emit-bytes buf #xBF)              ; mov edi, 0x300200
          (emit-u32 buf #x300200)
          (emit-bytes buf #x31 #xC0)         ; xor eax, eax
          (emit-bytes buf #xB9)              ; mov ecx, 64 (256/4 dwords)
          (emit-u32 buf 64)
          (emit-bytes buf #xF3 #xAB)         ; rep stosd
          ;; Check flags bit 2 (cmdline valid)
          (emit-bytes buf #x8B #x03)         ; mov eax, [ebx] (flags)
          (emit-bytes buf #xA8 #x04)         ; test al, 4
          (let ((skip32 (code-buffer-position buf)))
            (emit-bytes buf #x74 #x00)       ; jz skip (patched)
            ;; Load cmdline pointer
            (emit-bytes buf #x8B #x73 #x10)  ; mov esi, [ebx+16]
            ;; Copy to 0x300200, max 255 bytes
            (emit-bytes buf #xBF)            ; mov edi, 0x300200
            (emit-u32 buf #x300200)
            (emit-bytes buf #x31 #xC9)       ; xor ecx, ecx
            (let ((copy32 (code-buffer-position buf)))
              (emit-bytes buf #x8A #x04 #x0E) ; mov al, [esi+ecx]
              (emit-bytes buf #x84 #xC0)      ; test al, al
              (let ((done32 (code-buffer-position buf)))
                (emit-bytes buf #x74 #x00)    ; jz done (patched)
                (emit-bytes buf #x88 #x04 #x0F) ; mov [edi+ecx], al
                (emit-bytes buf #x41)         ; inc ecx
                (emit-bytes buf #x81 #xF9)    ; cmp ecx, 255
                (emit-u32 buf 255)
                (emit-bytes buf #x72)         ; jb copy32
                (emit-byte buf (- copy32 (+ (code-buffer-position buf) 1)))
                ;; done: null terminate
                (emit-bytes buf #xC6 #x04 #x0F #x00) ; mov [edi+ecx], 0
                ;; Patch jz done
                (setf (aref (code-buffer-bytes buf) (+ done32 1))
                      (- (code-buffer-position buf) (+ done32 2)))))
            ;; Patch jz skip
            (setf (aref (code-buffer-bytes buf) (+ skip32 1))
                  (- (code-buffer-position buf) (+ skip32 2))))

          ;; Page tables at 0x380000 (well above kernel and 32-bit stack)
          (emit-boot32-paging buf #x380000)

          ;; Enable long mode
          (emit-boot32-long-mode buf #x380000)

          ;; Far jump to 64-bit (target patched later)
          ;; Remember offset for patching
          (let ((jmp-offset (code-buffer-position buf)))
            (setf (gethash :jmp64-offset *functions*) jmp-offset))
          (emit-byte buf #xEA)
          (emit-u32 buf 0)  ; Placeholder
          (emit-u16 buf #x18)

          ;; Halt (shouldn't reach)
          (emit-byte buf #xF4)

          ;; Return the entry point offset (where CLI is)
          entry-offset))))

(defun emit-boot32-paging (buf pml4-addr)
  "Emit 32-bit code to set up 4GB identity-mapped page tables.
   Layout: PML4 -> PDPT -> 4 x PD (each 512 x 2MB pages = 1GB)
   PML4 at pml4-addr, PDPT at +0x1000, PD0-PD3 at +0x2000..+0x5000"
  ;; Clear page tables (6 pages: PML4, PDPT, PD0, PD1, PD2, PD3)
  ;; mov edi, pml4-addr
  (emit-bytes buf #xBF)
  (emit-u32 buf pml4-addr)
  ;; mov ecx, 6144 (6 * 4096 / 4 = 6144 dwords)
  (emit-bytes buf #xB9)
  (emit-u32 buf 6144)
  ;; xor eax, eax; rep stosd
  (emit-bytes buf #x31 #xC0 #xF3 #xAB)

  ;; PML4[0] -> PDPT
  ;; mov dword [pml4-addr], pdpt_addr | 3
  (emit-bytes buf #xC7 #x05)
  (emit-u32 buf pml4-addr)
  (emit-u32 buf (logior (+ pml4-addr #x1000) 3))

  ;; PDPT[0] -> PD0 (0-1GB)
  (emit-bytes buf #xC7 #x05)
  (emit-u32 buf (+ pml4-addr #x1000))
  (emit-u32 buf (logior (+ pml4-addr #x2000) 3))

  ;; PDPT[1] -> PD1 (1-2GB)
  (emit-bytes buf #xC7 #x05)
  (emit-u32 buf (+ pml4-addr #x1008))
  (emit-u32 buf (logior (+ pml4-addr #x3000) 3))

  ;; PDPT[2] -> PD2 (2-3GB)
  (emit-bytes buf #xC7 #x05)
  (emit-u32 buf (+ pml4-addr #x1010))
  (emit-u32 buf (logior (+ pml4-addr #x4000) 3))

  ;; PDPT[3] -> PD3 (3-4GB)
  (emit-bytes buf #xC7 #x05)
  (emit-u32 buf (+ pml4-addr #x1018))
  (emit-u32 buf (logior (+ pml4-addr #x5000) 3))

  ;; Fill all 4 PDs (2048 entries total, each 2MB page)
  ;; mov edi, pd0_addr
  (emit-bytes buf #xBF)
  (emit-u32 buf (+ pml4-addr #x2000))
  ;; mov eax, 0x83 (Present + RW + PS=2MB)
  (emit-bytes buf #xB8)
  (emit-u32 buf #x83)
  ;; mov ecx, 2048 (512 entries * 4 PDs)
  (emit-bytes buf #xB9)
  (emit-u32 buf 2048)

  ;; Loop: stosd (write low dword), add eax,0x200000, mov [edi],0 (high dword), add edi,4
  (let ((loop-start (code-buffer-position buf)))
    (emit-byte buf #xAB)             ; stosd (write eax to [edi], edi+=4)
    (emit-bytes buf #x05)            ; add eax, 0x200000
    (emit-u32 buf #x200000)
    (emit-bytes buf #xC7 #x07)      ; mov dword [edi], 0 (high 32 bits)
    (emit-u32 buf 0)
    (emit-bytes buf #x83 #xC7 #x04) ; add edi, 4
    (emit-bytes buf #xE2)            ; loop rel8
    (emit-byte buf (- loop-start (code-buffer-position buf) 1))))

(defun emit-boot32-long-mode (buf pml4-addr)
  "Emit code to enable long mode"
  ;; CR3 = PML4
  (emit-bytes buf #xB8)
  (emit-u32 buf pml4-addr)
  (emit-bytes buf #x0F #x22 #xD8)

  ;; Enable PAE
  (emit-bytes buf #x0F #x20 #xE0)
  (emit-bytes buf #x83 #xC8 #x20)
  (emit-bytes buf #x0F #x22 #xE0)

  ;; EFER.LME
  (emit-bytes buf #xB9)
  (emit-u32 buf #xC0000080)
  (emit-bytes buf #x0F #x32)
  (emit-bytes buf #x0D)
  (emit-u32 buf #x100)
  (emit-bytes buf #x0F #x30)

  ;; Enable paging
  (emit-bytes buf #x0F #x20 #xC0)
  (emit-bytes buf #x0D)
  (emit-u32 buf #x80000000)
  (emit-bytes buf #x0F #x22 #xC0))

(defun patch-boot32-target (buf boot-start target-addr)
  "Patch the 64-bit jump target in boot32 code"
  (let ((jmp-offset (gethash :jmp64-offset *functions*)))
    (when jmp-offset
      (let ((bytes (code-buffer-bytes buf)))
        (setf (aref bytes (+ jmp-offset 1)) (ldb (byte 8 0) target-addr))
        (setf (aref bytes (+ jmp-offset 2)) (ldb (byte 8 8) target-addr))
        (setf (aref bytes (+ jmp-offset 3)) (ldb (byte 8 16) target-addr))
        (setf (aref bytes (+ jmp-offset 4)) (ldb (byte 8 24) target-addr))))))

(defun patch-multiboot-header (buf base-addr entry-addr)
  "Patch multiboot1 header at start of buffer"
  (let ((bytes (code-buffer-bytes buf))
        (magic #x1BADB002)
        (flags (logior #x00000001 #x00000002 #x00010000)))
    ;; Magic
    (setf (aref bytes 0) (ldb (byte 8 0) magic))
    (setf (aref bytes 1) (ldb (byte 8 8) magic))
    (setf (aref bytes 2) (ldb (byte 8 16) magic))
    (setf (aref bytes 3) (ldb (byte 8 24) magic))
    ;; Flags
    (setf (aref bytes 4) (ldb (byte 8 0) flags))
    (setf (aref bytes 5) (ldb (byte 8 8) flags))
    (setf (aref bytes 6) (ldb (byte 8 16) flags))
    (setf (aref bytes 7) (ldb (byte 8 24) flags))
    ;; Checksum
    (let ((checksum (logand #xFFFFFFFF (- (+ magic flags)))))
      (setf (aref bytes 8) (ldb (byte 8 0) checksum))
      (setf (aref bytes 9) (ldb (byte 8 8) checksum))
      (setf (aref bytes 10) (ldb (byte 8 16) checksum))
      (setf (aref bytes 11) (ldb (byte 8 24) checksum)))
    ;; Address fields
    (setf (aref bytes 12) (ldb (byte 8 0) base-addr))
    (setf (aref bytes 13) (ldb (byte 8 8) base-addr))
    (setf (aref bytes 14) (ldb (byte 8 16) base-addr))
    (setf (aref bytes 15) (ldb (byte 8 24) base-addr))
    ;; load_addr
    (setf (aref bytes 16) (ldb (byte 8 0) base-addr))
    (setf (aref bytes 17) (ldb (byte 8 8) base-addr))
    (setf (aref bytes 18) (ldb (byte 8 16) base-addr))
    (setf (aref bytes 19) (ldb (byte 8 24) base-addr))
    ;; load_end (0 = whole file)
    (dotimes (i 4) (setf (aref bytes (+ 20 i)) 0))
    ;; bss_end (0)
    (dotimes (i 4) (setf (aref bytes (+ 24 i)) 0))
    ;; entry
    (setf (aref bytes 28) (ldb (byte 8 0) entry-addr))
    (setf (aref bytes 29) (ldb (byte 8 8) entry-addr))
    (setf (aref bytes 30) (ldb (byte 8 16) entry-addr))
    (setf (aref bytes 31) (ldb (byte 8 24) entry-addr))))

;;; ============================================================
;;; AP Trampoline (Phase 9: SMP)
;;; ============================================================
;;;
;;; The AP trampoline is raw machine code that gets embedded in the kernel
;;; image at build time. At runtime, smp-init copies it to physical 0x8000.
;;; The trampoline transitions AP cores: 16-bit real → 32-bit protected →
;;; 64-bit long mode, then jumps to the AP entry function.
;;;
;;; Layout at 0x8000 after copy:
;;;   +0x00: 16-bit real mode entry (SIPI lands here)
;;;   +0x20: 32-bit protected mode code
;;;   +0x60: 64-bit long mode code
;;;   +0xA0: GDT (null + 32-bit code/data + 64-bit code/data)
;;;   +0xD0: GDTR (limit=39, base=0x80A0)
;;;   +0xD6: (padding)
;;;   +0xE0: PARAM_CR3   (filled by BSP)
;;;   +0xE8: PARAM_STACK (filled by BSP)
;;;   +0xF0: PARAM_ENTRY (filled by BSP)
;;;   +0xF8: PARAM_FLAG  (AP sets to 1 when alive)

(defun emit-ap-trampoline (buf)
  "Emit AP trampoline code into the kernel image buffer.
   Returns (start-offset . size) so the runtime can locate and copy it."
  (let ((start-offset (code-buffer-position buf))
        (trampoline (make-array 256 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Helper to write bytes into the trampoline
    (let ((pos 0))
      (flet ((tb (&rest bytes)
               (dolist (b bytes)
                 (setf (aref trampoline pos) (logand b #xFF))
                 (incf pos)))
             (tb-at (offset &rest bytes)
               (let ((p offset))
                 (dolist (b bytes)
                   (setf (aref trampoline p) (logand b #xFF))
                   (incf p))))
             (t-u16 (offset val)
               (setf (aref trampoline offset) (ldb (byte 8 0) val))
               (setf (aref trampoline (1+ offset)) (ldb (byte 8 8) val)))
             (t-u32 (offset val)
               (setf (aref trampoline offset) (ldb (byte 8 0) val))
               (setf (aref trampoline (+ offset 1)) (ldb (byte 8 8) val))
               (setf (aref trampoline (+ offset 2)) (ldb (byte 8 16) val))
               (setf (aref trampoline (+ offset 3)) (ldb (byte 8 24) val)))
             (t-u64 (offset val)
               (setf (aref trampoline offset) (ldb (byte 8 0) val))
               (setf (aref trampoline (+ offset 1)) (ldb (byte 8 8) val))
               (setf (aref trampoline (+ offset 2)) (ldb (byte 8 16) val))
               (setf (aref trampoline (+ offset 3)) (ldb (byte 8 24) val))
               (setf (aref trampoline (+ offset 4)) (ldb (byte 8 32) val))
               (setf (aref trampoline (+ offset 5)) (ldb (byte 8 40) val))
               (setf (aref trampoline (+ offset 6)) (ldb (byte 8 48) val))
               (setf (aref trampoline (+ offset 7)) (ldb (byte 8 56) val))))

        ;; ---- +0x00: 16-bit real mode entry ----
        ;; SIPI sends AP to 0x8000 (vector 0x08, addr = vector * 0x1000)
        ;; AP starts in 16-bit real mode with CS=0x800, IP=0
        (setf pos 0)
        (tb #xFA)                ; cli
        (tb #x31 #xC0)          ; xor ax, ax
        (tb #x8E #xD8)          ; mov ds, ax
        (tb #x8E #xC0)          ; mov es, ax
        (tb #x8E #xD0)          ; mov ss, ax

        ;; lgdt [0x80D0]  (linear addr, DS=0)
        ;; In 16-bit mode with DS=0, we use address-size override (0x67) +
        ;; operand-size override (0x66) to access 32-bit linear address
        (tb #x66 #x67 #x0F #x01 #x15) ; lgdt [disp32]
        (t-u32 pos #x000080D0)
        (incf pos 4)

        ;; Enable protected mode (set CR0.PE)
        (tb #x0F #x20 #xC0)     ; mov eax, cr0
        (tb #x66 #x83 #xC8 #x01) ; or eax, 1
        (tb #x0F #x22 #xC0)     ; mov cr0, eax

        ;; Far jump to 32-bit code (selector 0x08, target 0x8028)
        ;; Use 66 EA (operand-size override + far JMP with 32-bit offset)
        (tb #x66 #xEA)
        (t-u32 pos #x00008028)  ; 32-bit offset
        (incf pos 4)
        (t-u16 pos #x0008)      ; 32-bit code selector
        (incf pos 2)

        ;; ---- +0x28: 32-bit protected mode ----
        (setf pos #x28)
        ;; Load data segments with 32-bit data selector (0x10)
        (tb #x66 #xB8 #x10 #x00) ; mov ax, 0x10
        (tb #x8E #xD8)            ; mov ds, ax
        (tb #x8E #xC0)            ; mov es, ax
        (tb #x8E #xD0)            ; mov ss, ax

        ;; Enable PAE (CR4.PAE, bit 5)
        (tb #x0F #x20 #xE0)       ; mov eax, cr4
        (tb #x83 #xC8 #x20)       ; or eax, 0x20
        (tb #x0F #x22 #xE0)       ; mov cr4, eax

        ;; Load CR3 from parameter at 0x80E0
        (tb #x8B #x05)            ; mov eax, [disp32]
        (t-u32 pos #x000080E0)
        (incf pos 4)
        (tb #x0F #x22 #xD8)       ; mov cr3, eax

        ;; Enable long mode (EFER.LME, bit 8)
        (tb #xB9)                  ; mov ecx, 0xC0000080 (EFER MSR)
        (t-u32 pos #xC0000080)
        (incf pos 4)
        (tb #x0F #x32)            ; rdmsr
        (tb #x0D)                 ; or eax, 0x100
        (t-u32 pos #x00000100)
        (incf pos 4)
        (tb #x0F #x30)            ; wrmsr

        ;; Enable paging (CR0.PG, bit 31)
        (tb #x0F #x20 #xC0)       ; mov eax, cr0
        (tb #x0D)                 ; or eax, 0x80000000
        (t-u32 pos #x80000000)
        (incf pos 4)
        (tb #x0F #x22 #xC0)       ; mov cr0, eax

        ;; Far jump to 64-bit code (selector 0x18, target 0x8068)
        (tb #xEA)
        (t-u32 pos #x00008068)
        (incf pos 4)
        (t-u16 pos #x0018)        ; 64-bit code selector
        (incf pos 2)

        ;; ---- +0x68: 64-bit long mode ----
        (setf pos #x68)
        ;; Reload data segments with 64-bit data selector (0x20)
        (tb #x66 #xB8 #x20 #x00) ; mov ax, 0x20
        (tb #x8E #xD8)            ; mov ds, ax
        (tb #x8E #xC0)            ; mov es, ax
        (tb #x8E #xD0)            ; mov ss, ax

        ;; Load RSP from parameter at 0x80E8
        ;; mov rsp, [disp32]  — 48 8B 24 25 E8 80 00 00
        (tb #x48 #x8B #x24 #x25)
        (t-u32 pos #x000080E8)
        (incf pos 4)

        ;; Set R15 = 0 (NIL)
        (tb #x4D #x31 #xFF)       ; xor r15, r15

        ;; Set PARAM_FLAG to 1 (signal BSP that AP is alive)
        ;; mov dword [0x80F8], 1
        (tb #xC7 #x04 #x25)
        (t-u32 pos #x000080F8)
        (incf pos 4)
        (t-u32 pos #x00000001)
        (incf pos 4)

        ;; Load entry function from parameter at 0x80F0
        ;; mov rax, [0x80F0] using disp32 encoding (same as RSP load above)
        (tb #x48 #x8B #x04 #x25)   ; mov rax, [disp32]
        (t-u32 pos #x000080F0)
        (incf pos 4)
        ;; jmp rax
        (tb #xFF #xE0)

        ;; ---- +0xA0: GDT ----
        ;; Same descriptors as BSP's GDT
        (t-u64 #xA0 #x0000000000000000) ; Null descriptor
        (t-u64 #xA8 #x00CF9A000000FFFF) ; 32-bit code (selector 0x08)
        (t-u64 #xB0 #x00CF92000000FFFF) ; 32-bit data (selector 0x10)
        (t-u64 #xB8 #x00AF9A000000FFFF) ; 64-bit code (selector 0x18)
        (t-u64 #xC0 #x00AF92000000FFFF) ; 64-bit data (selector 0x20)

        ;; ---- +0xD0: GDTR (6 bytes: limit u16 + base u32) ----
        (t-u16 #xD0 39)           ; GDT limit (5 entries * 8 - 1)
        (t-u32 #xD2 #x000080A0)  ; GDT base (linear address of GDT at 0x80A0)

        ;; ---- +0xE0-0xFF: Parameters (filled by BSP at runtime) ----
        ;; 0xE0: CR3 (page table root)
        ;; 0xE8: Stack pointer
        ;; 0xF0: Entry function address
        ;; 0xF8: Alive flag
        ;; (all initialized to 0)
        ))

    ;; Write the trampoline bytes into the kernel image buffer
    (dotimes (i 256)
      (emit-byte buf (aref trampoline i)))

    ;; Return start offset and size
    (cons start-offset 256)))

;;; ============================================================
;;; 64-bit Initialization
;;; ============================================================

(defun emit-serial-char (buf ch)
  "Emit asm to send one char to serial (no THRE wait - QEMU FIFO handles it)"
  ;; No THRE polling - QEMU's virtual UART FIFO buffers bytes internally.
  ;; Polling 'in al,dx' causes KVM VM exits that starve QEMU's event loop.
  (emit-bytes buf #x66 #xBA #xF8 #x03)  ; mov dx, 0x3F8
  (emit-bytes buf #xB0 ch)               ; mov al, char
  (emit-byte buf #xEE))                  ; out dx, al

(defun emit-64bit-init (buf)
  "Emit 64-bit initialization code"
  ;; Reload segments
  (emit-bytes buf #x66 #xB8 #x20 #x00)
  (emit-bytes buf #x8E #xD8 #x8E #xC0 #x8E #xE0 #x8E #xE8 #x8E #xD0)

  ;; Set up 64-bit stack (at 0x300000 - same as 32-bit, well above kernel)
  (emit-byte buf #x48)
  (emit-byte buf #xBC)
  (emit-u64 buf #x300000)

  ;; Mask all PIC interrupts to prevent spurious hardware interrupt delivery
  (emit-bytes buf #xB0 #xFF)            ; mov al, 0xFF
  (emit-bytes buf #xE6 #x21)            ; out 0x21, al  (PIC1 mask all)
  (emit-bytes buf #xE6 #xA1)            ; out 0xA1, al  (PIC2 mask all)

  ;; Initialize serial port (COM1 = 0x3F8) BEFORE anything else
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

  ;; Set up IDT with 256 entries to handle exceptions and IPI wakeup.
  ;; IDT at 0x390000, handlers at 0x390200+.
  ;; Page tables at 0x380000-0x386000, IDT uses 0x390000-0x391000.
  ;;
  ;; Step 1a: Write exception handler at 0x391010 (10 bytes)
  ;; Handler prints 'X' to serial and halts CPU (CLI+HLT instead of IRETQ).
  ;; IRETQ can't handle error-code exceptions (#8,#10-14,#17) because the
  ;; error code on the stack shifts the return frame, causing cascading faults.
  ;; CLI+HLT cleanly stops the faulting CPU so we get exactly one 'X'.
  (emit-bytes buf #x48 #xBF)             ; movabs rdi, 0x391010
  (emit-u64 buf #x391010)
  ;; Handler code: mov al,'X'; mov edx,0x3F8; out dx,al; cli; hlt
  (emit-bytes buf #xC6 #x07 #xB0)       ; mov byte [rdi], 0xB0  (mov al, imm8)
  (emit-bytes buf #xC6 #x47 #x01 #x58)  ; mov byte [rdi+1], 0x58  ('X')
  (emit-bytes buf #xC6 #x47 #x02 #xBA)  ; mov byte [rdi+2], 0xBA  (mov edx, imm32)
  (emit-bytes buf #xC6 #x47 #x03 #xF8)  ; mov byte [rdi+3], 0xF8
  (emit-bytes buf #xC6 #x47 #x04 #x03)  ; mov byte [rdi+4], 0x03
  (emit-bytes buf #xC6 #x47 #x05 #x00)  ; mov byte [rdi+5], 0x00
  (emit-bytes buf #xC6 #x47 #x06 #x00)  ; mov byte [rdi+6], 0x00
  (emit-bytes buf #xC6 #x47 #x07 #xEE)  ; mov byte [rdi+7], 0xEE  (out dx, al)
  (emit-bytes buf #xC6 #x47 #x08 #xFA)  ; mov byte [rdi+8], 0xFA  (cli)
  (emit-bytes buf #xC6 #x47 #x09 #xF4)  ; mov byte [rdi+9], 0xF4  (hlt)
  ;;
  ;; Step 1b: Write IPI handler at 0x391020 (20 bytes)
  ;; Must write EOI to LAPIC before IRETQ, otherwise the ISR bit stays set
  ;; and subsequent IPIs at the same vector are blocked.
  ;; Handler: push rdi; movabs rdi,0xFEE000B0; mov [rdi],0; pop rdi; iretq
  ;; Also used as catch-all for unexpected interrupts (vectors 32-255).
  (emit-bytes buf #xC6 #x47 #x10 #x57)  ; [rdi+16] = 0x57 (push rdi)
  (emit-bytes buf #xC6 #x47 #x11 #x48)  ; [rdi+17] = 0x48 (REX.W prefix for movabs)
  (emit-bytes buf #xC6 #x47 #x12 #xBF)  ; [rdi+18] = 0xBF (movabs rdi, imm64)
  (emit-bytes buf #xC6 #x47 #x13 #xB0)  ; [rdi+19] = 0xB0 (low byte of 0xFEE000B0)
  (emit-bytes buf #xC6 #x47 #x14 #x00)  ; [rdi+20] = 0x00
  (emit-bytes buf #xC6 #x47 #x15 #xE0)  ; [rdi+21] = 0xE0
  (emit-bytes buf #xC6 #x47 #x16 #xFE)  ; [rdi+22] = 0xFE
  (emit-bytes buf #xC6 #x47 #x17 #x00)  ; [rdi+23] = 0x00
  (emit-bytes buf #xC6 #x47 #x18 #x00)  ; [rdi+24] = 0x00
  (emit-bytes buf #xC6 #x47 #x19 #x00)  ; [rdi+25] = 0x00
  (emit-bytes buf #xC6 #x47 #x1A #x00)  ; [rdi+26] = 0x00
  ;; mov dword [rdi], 0  (C7 07 00 00 00 00)
  (emit-bytes buf #xC6 #x47 #x1B #xC7)  ; [rdi+27] = 0xC7
  (emit-bytes buf #xC6 #x47 #x1C #x07)  ; [rdi+28] = 0x07
  (emit-bytes buf #xC6 #x47 #x1D #x00)  ; [rdi+29] = 0x00
  (emit-bytes buf #xC6 #x47 #x1E #x00)  ; [rdi+30] = 0x00
  (emit-bytes buf #xC6 #x47 #x1F #x00)  ; [rdi+31] = 0x00
  (emit-bytes buf #xC6 #x47 #x20 #x00)  ; [rdi+32] = 0x00
  ;; pop rdi (5F)
  (emit-bytes buf #xC6 #x47 #x21 #x5F)  ; [rdi+33] = 0x5F (pop rdi)
  ;; iretq (48 CF)
  (emit-bytes buf #xC6 #x47 #x22 #x48)  ; [rdi+34] = 0x48 (REX.W)
  (emit-bytes buf #xC6 #x47 #x23 #xCF)  ; [rdi+35] = 0xCF (iretq)
  ;;
  ;; Step 1b2: Write LAPIC timer ISR at 0x391040 (28 bytes)
  ;; Timer fires periodically, zeroes the per-CPU reduction counter at GS:[8].
  ;; This forces the next loop iteration to call yield, achieving preemption.
  ;; RDI is still 0x391010, so offset 0x30 = 0x391040.
  ;; MOV QWORD GS:[8], 0 — zero reduction counter (13 bytes)
  (emit-bytes buf #xC6 #x47 #x30 #x65)  ; [rdi+48] = 0x65 (GS prefix)
  (emit-bytes buf #xC6 #x47 #x31 #x48)  ; [rdi+49] = 0x48 (REX.W)
  (emit-bytes buf #xC6 #x47 #x32 #xC7)  ; [rdi+50] = 0xC7 (MOV r/m64, imm32)
  (emit-bytes buf #xC6 #x47 #x33 #x04)  ; [rdi+51] = 0x04 (SIB)
  (emit-bytes buf #xC6 #x47 #x34 #x25)  ; [rdi+52] = 0x25 (disp32)
  (emit-bytes buf #xC6 #x47 #x35 #x08)  ; [rdi+53] = 0x08 (offset low)
  (emit-bytes buf #xC6 #x47 #x36 #x00)  ; [rdi+54] = 0x00
  (emit-bytes buf #xC6 #x47 #x37 #x00)  ; [rdi+55] = 0x00
  (emit-bytes buf #xC6 #x47 #x38 #x00)  ; [rdi+56] = 0x00
  (emit-bytes buf #xC6 #x47 #x39 #x00)  ; [rdi+57] = 0x00 (imm32 low = 0)
  (emit-bytes buf #xC6 #x47 #x3A #x00)  ; [rdi+58] = 0x00
  (emit-bytes buf #xC6 #x47 #x3B #x00)  ; [rdi+59] = 0x00
  (emit-bytes buf #xC6 #x47 #x3C #x00)  ; [rdi+60] = 0x00
  ;; PUSH RDI (1 byte)
  (emit-bytes buf #xC6 #x47 #x3D #x57)  ; [rdi+61] = 0x57 (push rdi)
  ;; MOV EDI, 0xFEE000B0 (5 bytes) — LAPIC EOI register
  (emit-bytes buf #xC6 #x47 #x3E #xBF)  ; [rdi+62] = 0xBF (mov edi, imm32)
  (emit-bytes buf #xC6 #x47 #x3F #xB0)  ; [rdi+63] = 0xB0
  (emit-bytes buf #xC6 #x47 #x40 #x00)  ; [rdi+64] = 0x00
  (emit-bytes buf #xC6 #x47 #x41 #xE0)  ; [rdi+65] = 0xE0
  (emit-bytes buf #xC6 #x47 #x42 #xFE)  ; [rdi+66] = 0xFE
  ;; MOV DWORD [RDI], 0 (6 bytes) — write EOI
  (emit-bytes buf #xC6 #x47 #x43 #xC7)  ; [rdi+67] = 0xC7
  (emit-bytes buf #xC6 #x47 #x44 #x07)  ; [rdi+68] = 0x07
  (emit-bytes buf #xC6 #x47 #x45 #x00)  ; [rdi+69] = 0x00
  (emit-bytes buf #xC6 #x47 #x46 #x00)  ; [rdi+70] = 0x00
  (emit-bytes buf #xC6 #x47 #x47 #x00)  ; [rdi+71] = 0x00
  (emit-bytes buf #xC6 #x47 #x48 #x00)  ; [rdi+72] = 0x00
  ;; POP RDI (1 byte)
  (emit-bytes buf #xC6 #x47 #x49 #x5F)  ; [rdi+73] = 0x5F (pop rdi)
  ;; IRETQ (2 bytes)
  (emit-bytes buf #xC6 #x47 #x4A #x48)  ; [rdi+74] = 0x48 (REX.W)
  (emit-bytes buf #xC6 #x47 #x4B #xCF)  ; [rdi+75] = 0xCF (iretq)
  ;;
  ;; Step 1c: Write enhanced exception handler at 0x391100 (102 bytes)
  ;; Prints 'X', then [RSP]:[RSP+8]:[RSP+16] as 8-digit hex values
  ;; For exceptions without error code: RIP:CS:RFLAGS
  ;; For exceptions with error code: errcode:RIP:CS
  (emit-bytes buf #x48 #xBF)             ; movabs rdi, 0x391100
  (emit-u64 buf #x391100)
  ;; Handler bytes at 0x391100:
  ;; mov edx, 0x3F8  (BA F8 03 00 00)
  (emit-bytes buf #xC6 #x07 #xBA)        ; [rdi+0] = BA
  (emit-bytes buf #xC6 #x47 #x01 #xF8)   ; [rdi+1] = F8
  (emit-bytes buf #xC6 #x47 #x02 #x03)   ; [rdi+2] = 03
  (emit-bytes buf #xC6 #x47 #x03 #x00)   ; [rdi+3] = 00
  (emit-bytes buf #xC6 #x47 #x04 #x00)   ; [rdi+4] = 00
  ;; mov al, 'X'  (B0 58)
  (emit-bytes buf #xC6 #x47 #x05 #xB0)   ; [rdi+5] = B0
  (emit-bytes buf #xC6 #x47 #x06 #x58)   ; [rdi+6] = 58
  ;; out dx, al  (EE)
  (emit-bytes buf #xC6 #x47 #x07 #xEE)   ; [rdi+7] = EE
  ;; --- Block 1: print [RSP] as 8 hex digits ---
  ;; mov ebx, [rsp]  (8B 1C 24)
  (emit-bytes buf #xC6 #x47 #x08 #x8B)   ; [rdi+8]
  (emit-bytes buf #xC6 #x47 #x09 #x1C)
  (emit-bytes buf #xC6 #x47 #x0A #x24)
  ;; mov ecx, 8  (B9 08 00 00 00)
  (emit-bytes buf #xC6 #x47 #x0B #xB9)
  (emit-bytes buf #xC6 #x47 #x0C #x08)
  (emit-bytes buf #xC6 #x47 #x0D #x00)
  (emit-bytes buf #xC6 #x47 #x0E #x00)
  (emit-bytes buf #xC6 #x47 #x0F #x00)
  ;; loop1: rol ebx, 4  (C1 C3 04)
  (emit-bytes buf #xC6 #x47 #x10 #xC1)   ; [rdi+16]
  (emit-bytes buf #xC6 #x47 #x11 #xC3)
  (emit-bytes buf #xC6 #x47 #x12 #x04)
  ;; mov al, bl  (8A C3)
  (emit-bytes buf #xC6 #x47 #x13 #x8A)
  (emit-bytes buf #xC6 #x47 #x14 #xC3)
  ;; and al, 0x0F  (24 0F)
  (emit-bytes buf #xC6 #x47 #x15 #x24)
  (emit-bytes buf #xC6 #x47 #x16 #x0F)
  ;; add al, 0x30  (04 30)
  (emit-bytes buf #xC6 #x47 #x17 #x04)
  (emit-bytes buf #xC6 #x47 #x18 #x30)
  ;; cmp al, 0x39  (3C 39)
  (emit-bytes buf #xC6 #x47 #x19 #x3C)
  (emit-bytes buf #xC6 #x47 #x1A #x39)
  ;; jbe +2  (76 02)
  (emit-bytes buf #xC6 #x47 #x1B #x76)
  (emit-bytes buf #xC6 #x47 #x1C #x02)
  ;; add al, 7  (04 07)
  (emit-bytes buf #xC6 #x47 #x1D #x04)
  (emit-bytes buf #xC6 #x47 #x1E #x07)
  ;; out dx, al  (EE)
  (emit-bytes buf #xC6 #x47 #x1F #xEE)
  ;; dec ecx  (FF C9)
  (emit-bytes buf #xC6 #x47 #x20 #xFF)
  (emit-bytes buf #xC6 #x47 #x21 #xC9)
  ;; jnz loop1  (75 EC = -20)
  (emit-bytes buf #xC6 #x47 #x22 #x75)
  (emit-bytes buf #xC6 #x47 #x23 #xEC)
  ;; --- Print ':' ---
  ;; mov al, ':'  (B0 3A)
  (emit-bytes buf #xC6 #x47 #x24 #xB0)   ; [rdi+36]
  (emit-bytes buf #xC6 #x47 #x25 #x3A)
  ;; out dx, al  (EE)
  (emit-bytes buf #xC6 #x47 #x26 #xEE)
  ;; --- Block 2: print [RSP+8] as 8 hex digits ---
  ;; mov ebx, [rsp+8]  (8B 5C 24 08)
  (emit-bytes buf #xC6 #x47 #x27 #x8B)   ; [rdi+39]
  (emit-bytes buf #xC6 #x47 #x28 #x5C)
  (emit-bytes buf #xC6 #x47 #x29 #x24)
  (emit-bytes buf #xC6 #x47 #x2A #x08)
  ;; mov ecx, 8  (B9 08 00 00 00)
  (emit-bytes buf #xC6 #x47 #x2B #xB9)
  (emit-bytes buf #xC6 #x47 #x2C #x08)
  (emit-bytes buf #xC6 #x47 #x2D #x00)
  (emit-bytes buf #xC6 #x47 #x2E #x00)
  (emit-bytes buf #xC6 #x47 #x2F #x00)
  ;; loop2: same 20-byte hex loop
  (emit-bytes buf #xC6 #x47 #x30 #xC1)   ; [rdi+48] rol ebx, 4
  (emit-bytes buf #xC6 #x47 #x31 #xC3)
  (emit-bytes buf #xC6 #x47 #x32 #x04)
  (emit-bytes buf #xC6 #x47 #x33 #x8A)   ; mov al, bl
  (emit-bytes buf #xC6 #x47 #x34 #xC3)
  (emit-bytes buf #xC6 #x47 #x35 #x24)   ; and al, 0x0F
  (emit-bytes buf #xC6 #x47 #x36 #x0F)
  (emit-bytes buf #xC6 #x47 #x37 #x04)   ; add al, 0x30
  (emit-bytes buf #xC6 #x47 #x38 #x30)
  (emit-bytes buf #xC6 #x47 #x39 #x3C)   ; cmp al, 0x39
  (emit-bytes buf #xC6 #x47 #x3A #x39)
  (emit-bytes buf #xC6 #x47 #x3B #x76)   ; jbe +2
  (emit-bytes buf #xC6 #x47 #x3C #x02)
  (emit-bytes buf #xC6 #x47 #x3D #x04)   ; add al, 7
  (emit-bytes buf #xC6 #x47 #x3E #x07)
  (emit-bytes buf #xC6 #x47 #x3F #xEE)   ; out dx, al
  (emit-bytes buf #xC6 #x47 #x40 #xFF)   ; dec ecx
  (emit-bytes buf #xC6 #x47 #x41 #xC9)
  (emit-bytes buf #xC6 #x47 #x42 #x75)   ; jnz loop2
  (emit-bytes buf #xC6 #x47 #x43 #xEC)
  ;; --- Print ':' ---
  (emit-bytes buf #xC6 #x47 #x44 #xB0)   ; [rdi+68] mov al, ':'
  (emit-bytes buf #xC6 #x47 #x45 #x3A)
  (emit-bytes buf #xC6 #x47 #x46 #xEE)   ; out dx, al
  ;; --- Block 3: print CR2 (page fault address) as 8 hex digits ---
  ;; mov rbx, cr2  (0F 20 D3 = REX.W not needed, mov r64, cr2)
  ;; Actually: 0F 20 D3 = mov rbx, cr2 (needs no REX.W for CR access)
  (emit-bytes buf #xC6 #x47 #x47 #x0F)   ; [rdi+71]
  (emit-bytes buf #xC6 #x47 #x48 #x20)
  (emit-bytes buf #xC6 #x47 #x49 #xD3)
  ;; Pad with NOP for alignment (was 4 bytes, now 3)
  (emit-bytes buf #xC6 #x47 #x4A #x90)   ; nop
  ;; mov ecx, 8
  (emit-bytes buf #xC6 #x47 #x4B #xB9)
  (emit-bytes buf #xC6 #x47 #x4C #x08)
  (emit-bytes buf #xC6 #x47 #x4D #x00)
  (emit-bytes buf #xC6 #x47 #x4E #x00)
  (emit-bytes buf #xC6 #x47 #x4F #x00)
  ;; loop3: same 20-byte hex loop
  (emit-bytes buf #xC6 #x47 #x50 #xC1)   ; [rdi+80] rol ebx, 4
  (emit-bytes buf #xC6 #x47 #x51 #xC3)
  (emit-bytes buf #xC6 #x47 #x52 #x04)
  (emit-bytes buf #xC6 #x47 #x53 #x8A)   ; mov al, bl
  (emit-bytes buf #xC6 #x47 #x54 #xC3)
  (emit-bytes buf #xC6 #x47 #x55 #x24)   ; and al, 0x0F
  (emit-bytes buf #xC6 #x47 #x56 #x0F)
  (emit-bytes buf #xC6 #x47 #x57 #x04)   ; add al, 0x30
  (emit-bytes buf #xC6 #x47 #x58 #x30)
  (emit-bytes buf #xC6 #x47 #x59 #x3C)   ; cmp al, 0x39
  (emit-bytes buf #xC6 #x47 #x5A #x39)
  (emit-bytes buf #xC6 #x47 #x5B #x76)   ; jbe +2
  (emit-bytes buf #xC6 #x47 #x5C #x02)
  (emit-bytes buf #xC6 #x47 #x5D #x04)   ; add al, 7
  (emit-bytes buf #xC6 #x47 #x5E #x07)
  (emit-bytes buf #xC6 #x47 #x5F #xEE)   ; out dx, al
  (emit-bytes buf #xC6 #x47 #x60 #xFF)   ; dec ecx
  (emit-bytes buf #xC6 #x47 #x61 #xC9)
  (emit-bytes buf #xC6 #x47 #x62 #x75)   ; jnz loop3
  (emit-bytes buf #xC6 #x47 #x63 #xEC)
  ;; cli; hlt
  (emit-bytes buf #xC6 #x47 #x64 #xFA)   ; [rdi+100] cli
  (emit-bytes buf #xC6 #x47 #x65 #xF4)   ; [rdi+101] hlt
  ;;
  ;; Step 2a: Fill IDT entries 0-31 at 0x390000 (exception handler at 0x391100)
  ;; IDT entry format (long mode):
  ;;   [0:1]   offset[15:0]   = 0x1100
  ;;   [2:3]   selector       = 0x0018  (64-bit code segment)
  ;;   [4]     IST            = 0x00
  ;;   [5]     type/attr      = 0x8E  (present, DPL=0, interrupt gate)
  ;;   [6:7]   offset[31:16]  = 0x0039
  ;;   [8:11]  offset[63:32]  = 0x00000000
  ;;   [12:15] reserved       = 0x00000000
  (emit-bytes buf #x48 #xBF)             ; movabs rdi, 0x390000
  (emit-u64 buf #x390000)
  (emit-bytes buf #x48 #xB9)             ; movabs rcx, 32
  (emit-u64 buf 32)
  ;; Loop: write 16-byte IDT entry (exception handler at 0x391100)
  (let ((loop-pos (code-buffer-position buf)))
    ;; mov dword [rdi], 0x00181100  (offset[15:0]=0x1100, selector=0x0018)
    (emit-bytes buf #xC7 #x07)
    (emit-u32 buf #x00181100)
    ;; mov dword [rdi+4], 0x00398E00  (IST=0, type=0x8E, offset[31:16]=0x0039)
    (emit-bytes buf #xC7 #x47 #x04)
    (emit-u32 buf #x00398E00)
    ;; mov dword [rdi+8], 0  (offset[63:32])
    (emit-bytes buf #xC7 #x47 #x08)
    (emit-u32 buf 0)
    ;; mov dword [rdi+12], 0  (reserved)
    (emit-bytes buf #xC7 #x47 #x0C)
    (emit-u32 buf 0)
    ;; add rdi, 16
    (emit-bytes buf #x48 #x83 #xC7 #x10)
    ;; dec rcx
    (emit-bytes buf #x48 #xFF #xC9)
    ;; jnz loop
    (emit-bytes buf #x75)
    (emit-byte buf (logand (- loop-pos (code-buffer-position buf) 1) #xFF)))
  ;;
  ;; Step 2b: Fill IDT entries 32-255 (IPI/catch-all handler at 0x391020)
  ;; RDI already points to entry 32 (0x390000 + 32*16 = 0x390200)
  (emit-bytes buf #x48 #xB9)             ; movabs rcx, 224  (256-32)
  (emit-u64 buf 224)
  (let ((loop-pos (code-buffer-position buf)))
    ;; mov dword [rdi], 0x00181020  (offset[15:0]=0x1020, selector=0x0018)
    (emit-bytes buf #xC7 #x07)
    (emit-u32 buf #x00181020)
    ;; mov dword [rdi+4], 0x00398E00  (IST=0, type=0x8E, offset[31:16]=0x0039)
    (emit-bytes buf #xC7 #x47 #x04)
    (emit-u32 buf #x00398E00)
    ;; mov dword [rdi+8], 0  (offset[63:32])
    (emit-bytes buf #xC7 #x47 #x08)
    (emit-u32 buf 0)
    ;; mov dword [rdi+12], 0  (reserved)
    (emit-bytes buf #xC7 #x47 #x0C)
    (emit-u32 buf 0)
    ;; add rdi, 16
    (emit-bytes buf #x48 #x83 #xC7 #x10)
    ;; dec rcx
    (emit-bytes buf #x48 #xFF #xC9)
    ;; jnz loop
    (emit-bytes buf #x75)
    (emit-byte buf (logand (- loop-pos (code-buffer-position buf) 1) #xFF)))
  ;;
  ;; Step 2c: Override IDT entry for LAPIC timer vector 0x30 → handler at 0x391040
  ;; The fill loop set all entries 32-255 to the IPI handler (0x391020).
  ;; Override vector 0x30 (48) to point to the timer ISR instead.
  ;; IDT entry at 0x390000 + 0x30 * 16 = 0x390300
  (emit-bytes buf #x48 #xBF)             ; movabs rdi, 0x390300
  (emit-u64 buf #x390300)
  ;; mov dword [rdi], 0x00181040  (offset[15:0]=0x1040, selector=0x0018)
  (emit-bytes buf #xC7 #x07)
  (emit-u32 buf #x00181040)
  ;; mov dword [rdi+4], 0x00398E00  (IST=0, type=0x8E, offset[31:16]=0x0039)
  (emit-bytes buf #xC7 #x47 #x04)
  (emit-u32 buf #x00398E00)
  ;; [rdi+8] and [rdi+12] already 0 from fill loop (offset[63:32]=0, reserved=0)
  ;;
  ;; Step 3: Load IDT with LIDT
  ;; Store IDT descriptor at 0x391000: limit (u16) + base (u64)
  ;; (256 entries * 16 bytes = 4096 bytes, IDT spans 0x390000-0x391000)
  (emit-bytes buf #x48 #xBF)             ; movabs rdi, 0x391000
  (emit-u64 buf #x391000)
  ;; limit = 256*16 - 1 = 4095 = 0x0FFF
  (emit-bytes buf #x66 #xC7 #x07)       ; mov word [rdi], 0x0FFF
  (emit-u16 buf #x0FFF)
  ;; base = 0x390000
  (emit-bytes buf #x48 #xC7 #x47 #x02)  ; mov qword [rdi+2], 0x390000
  (emit-u32 buf #x390000)
  (emit-bytes buf #xC7 #x47 #x06)       ; mov dword [rdi+6], 0
  (emit-u32 buf 0)
  ;; lidt [rdi]
  (emit-bytes buf #x0F #x01 #x1F)       ; lidt [rdi]

  ;; Print a marker to show we reached 64-bit mode
  ;; This will help debug if we crash before Lisp runs
  (loop for char across "64>" do
    (emit-serial-char buf (char-code char)))

  ;; Cmdline already copied to 0x300200 by 32-bit boot code

  ;; Set up allocation registers for two-space GC
  ;; Memory layout:
  ;;   0x03F00000 - GC metadata (to-space ptr, etc.)
  ;;   0x04000000 - 0x04400000: Cons from-space (4MB)
  ;;   0x04400000 - 0x04800000: Cons to-space (4MB)
  ;;   0x04800000 - 0x04C00000: Object from-space (4MB)
  ;;   0x04C00000 - 0x05000000: Object to-space (4MB)

  ;; R12 = cons alloc pointer (from-space start)
  (emit-bytes buf #x49 #xBC)  ; mov r12, imm64
  (emit-u64 buf #x04000000)

  ;; R14 = cons from-space limit
  (emit-bytes buf #x49 #xBE)  ; mov r14, imm64
  (emit-u64 buf #x04400000)  ; 4MB cons from-space

  ;; R15 = NIL (0)
  (emit-bytes buf #x49 #xBF)  ; mov r15, imm64
  (emit-u64 buf 0)

  ;; Initialize GC metadata at 0x03F00000
  ;; Cons space:
  ;; [0x03F00000] = cons to-space start = 0x04400000
  ;; [0x03F00008] = cons to-space alloc ptr (used during GC)
  ;; [0x03F00010] = cons to-space limit = 0x04800000
  ;; [0x03F00018] = cons from-space start = 0x04000000
  ;; [0x03F00028] = scan ptr (used during GC)
  ;; [0x03F00030] = card table base = 0x03F01000
  ;; Object space:
  ;; [0x03F00038] = object from-space start = 0x04800000
  ;; [0x03F00040] = object alloc ptr = 0x04800000
  ;; [0x03F00048] = object from-space limit = 0x04C00000
  ;; [0x03F00050] = object to-space start = 0x04C00000
  ;; [0x03F00058] = object to-space limit = 0x05000000
  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x04400000)   ; cons to-space start
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax (absolute)
  (emit-u64 buf #x03F00000)

  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x04800000)   ; cons to-space limit
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00010)

  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x04000000)   ; cons from-space start
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00018)

  ;; Store card table base address
  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x03F01000)   ; card table at 0x03F01000
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00030)

  ;; Initialize object space metadata
  ;; Set from-start to impossibly high value so GC never finds objects
  ;; in "from-space". This disables object GC (objects are never copied
  ;; or forwarded). Native code has hardcoded object pointers that GC
  ;; can't update, so moving objects would corrupt them.
  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #xFFFFFFFFFFFFFFFF) ; impossible from-start (disables GC for objects)
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00038)

  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x04800000)   ; object alloc ptr (starts at from-space start)
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00040)

  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x04C00000)   ; object from-space limit (used for OOM checks)
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00048)

  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x04C00000)   ; object to-space start
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00050)

  (emit-bytes buf #x48 #xB8)  ; mov rax, imm64
  (emit-u64 buf #x05000000)   ; object to-space limit
  (emit-bytes buf #x48 #xA3)  ; mov [addr], rax
  (emit-u64 buf #x03F00058)

  ;; Zero the card table (64KB at 0x03F01000)
  ;; rep stosb: RDI=dest, RCX=count, AL=value
  (emit-bytes buf #x48 #xBF)  ; mov rdi, imm64
  (emit-u64 buf #x03F01000)
  (emit-bytes buf #x48 #xB9)  ; mov rcx, imm64
  (emit-u64 buf #x10000)      ; 64KB = 0x10000
  (emit-bytes buf #x30 #xC0)  ; xor al, al
  (emit-bytes buf #xF3 #xAA)  ; rep stosb

  ;; Restore RDI (rep stosb clobbers it, but we don't use it yet)
  ;; Diagnostic: print markers to identify stall location
  ;; Boot sequence will show: 64>Z...M19MN  (Z=init done, then Lisp tests)
  ;; If stall is between > and Z: GC/card table init is slow
  ;; If stall is between Z and M: first Lisp function call is slow
  (emit-serial-char buf (char-code #\Z)))

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-build ()
  "Build and test kernel"
  (build-kernel "/tmp/modus64-full.elf")
  (format t "~%Running QEMU...~%")
  (uiop:run-program
   '("timeout" "3" "qemu-system-x86_64"
     "-kernel" "/tmp/modus64-full.elf"
     "-nographic")
   :output t
   :error-output t))
