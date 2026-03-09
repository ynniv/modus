;;;; build-fixpoint.lisp - Build the Fixpoint of Theseus
;;;;
;;;; The fixpoint proves the MVM compiler is a fixed point across
;;;; architectures: SBCL→Gen0(x64)→Gen2(aarch64)→Gen3(x64),
;;;; where SHA256(Gen3)==SHA256(Gen0).
;;;;
;;;; Architecture:
;;;;   - All source is compiled to MVM bytecode (architecture-independent)
;;;;   - The MVM bytecode is the "fixed point" — same source always produces
;;;;     the same bytecode regardless of which architecture does the compilation
;;;;   - Each generation translates the bytecode to native code for the target
;;;;     architecture using the embedded translator
;;;;
;;;; This build script:
;;;;   1. Loads the MVM system (compiler, translators, boot descriptors)
;;;;   2. Collects all fixpoint source (REPL + MVM system + translators +
;;;;      boot descriptors + cross pipeline + build-image-cross)
;;;;   3. Compiles all source through MVM → MVM bytecode
;;;;   4. Translates bytecode → x64 native code for Gen0
;;;;   5. Assembles Gen0 image with embedded bytecode + function table
;;;;   6. Writes Gen0 ELF to /tmp/fixpoint-gen0.elf
;;;;
;;;; Usage: sbcl --script mvm/build-fixpoint.lisp
;;;;   With SSH: sbcl --script mvm/build-fixpoint.lisp -- --ssh
;;;;
;;;; Boot:
;;;;   qemu-system-x86_64 -kernel /tmp/fixpoint-gen0.elf -m 512 -nographic -no-reboot

;;; ============================================================
;;; Load MVM system
;;; ============================================================

(defvar *modus-base*
  (let* ((mvm-dir (directory-namestring (truename *load-truename*)))
         (modus-dir (namestring (truename (merge-pathnames "../" mvm-dir)))))
    (pathname modus-dir)))

(defun mvm-load (relative-path)
  (let ((path (merge-pathnames relative-path *modus-base*)))
    (load path :verbose nil :print nil)))

(format t "=== Fixpoint of Theseus ===~%")
(format t "Loading MVM system...~%")

(mvm-load "cross/packages.lisp")
(mvm-load "cross/x64-asm.lisp")
(mvm-load "mvm/mvm.lisp")
(mvm-load "mvm/target.lisp")
(mvm-load "mvm/compiler.lisp")
(mvm-load "mvm/interp.lisp")
(mvm-load "boot/boot-x64.lisp")
(mvm-load "boot/boot-riscv.lisp")
(mvm-load "boot/boot-aarch64.lisp")
(mvm-load "boot/boot-rpi.lisp")
(mvm-load "boot/boot-ppc64.lisp")
(mvm-load "boot/boot-ppc32.lisp")
(mvm-load "boot/boot-i386.lisp")
(mvm-load "boot/boot-68k.lisp")
(mvm-load "boot/boot-arm32.lisp")
(mvm-load "mvm/translate-x64.lisp")
(mvm-load "mvm/translate-riscv.lisp")
(mvm-load "mvm/translate-aarch64.lisp")
(mvm-load "mvm/translate-ppc.lisp")
(mvm-load "mvm/translate-i386.lisp")
(mvm-load "mvm/translate-68k.lisp")
(mvm-load "mvm/translate-arm32.lisp")
(mvm-load "mvm/cross.lisp")
(mvm-load "mvm/repl-source.lisp")

;;; ============================================================
;;; Read all fixpoint source files
;;; ============================================================

(defun read-file-text (path)
  "Read entire file as a string."
  (with-open-file (s path :direction :input)
    (let ((text (make-string (file-length s))))
      (let ((n (read-sequence text s)))
        (subseq text 0 n)))))

(format t "Collecting fixpoint source...~%")

;;; The fixpoint source includes:
;;; 1. REPL (basic I/O, eval, print)
;;; 2. MVM prelude (library functions)
;;; 3. MVM ISA definitions (opcodes, structs)
;;; 4. Target descriptors
;;; 5. x64 assembler (code-buffer, labels, instruction emission)
;;; 6. x64 translator (MVM bytecode → x86-64 native)
;;; 7. AArch64 translator (MVM bytecode → AArch64 native)
;;; 8. Cross-compilation pipeline (translation, image assembly)
;;; 9. Boot descriptors (x64, AArch64)
;;; 10. build-image-cross (bare-metal cross-compilation entry point)
;;; 11. kernel-main

(defvar *mvm-source-files*
  '("mvm/prelude.lisp"
    "mvm/mvm.lisp"
    "mvm/target.lisp"
    "cross/x64-asm.lisp"
    "mvm/translate-x64.lisp"
    "mvm/translate-aarch64.lisp"
    "mvm/translate-i386.lisp"
    "mvm/cross.lisp"
    "boot/boot-x64.lisp"
    "boot/boot-aarch64.lisp"
    "boot/boot-i386.lisp"))

(defvar *mvm-source-text*
  (with-output-to-string (s)
    (dolist (file *mvm-source-files*)
      (let ((path (merge-pathnames file *modus-base*)))
        (format t "  ~A~%" file)
        (write-string (read-file-text path) s)
        (terpri s)))))

;;; Preprocess source text: fix &key calls for bare-metal MVM compilation.
;;; The MVM compiler doesn't handle keyword arguments at call sites — it
;;; treats :hw, :shift etc. as positional args. Transform to positional calls.

;; Preprocess: manual string replacement for &key patterns
(flet ((replace-all (old new string)
         (with-output-to-string (s)
           (let ((old-len (length old))
                 (pos 0))
             (loop
               (let ((found (search old string :start2 pos)))
                 (if found
                     (progn
                       (write-string string s :start pos :end found)
                       (write-string new s)
                       (setf pos (+ found old-len)))
                     (progn
                       (write-string string s :start pos)
                       (return)))))))))
  ;; &key in defun params → positional
  (setf *mvm-source-text* (replace-all "&key (hw 0)" "hw" *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "&key (shift 0)" "shift" *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "&key (shift :lsl) (amount 0)"
                                        "shift amount" *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "&key (option #xB)" "option" *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "&key (start 0) (end nil)"
                                        "start end" *mvm-source-text*))
  ;; Call sites: strip keyword indicators
  (setf *mvm-source-text* (replace-all " :hw " " " *mvm-source-text*))
  (setf *mvm-source-text* (replace-all " :shift :lsl :amount " " 0 " *mvm-source-text*))
  (setf *mvm-source-text* (replace-all " :shift :lsr :amount " " 1 " *mvm-source-text*))
  (setf *mvm-source-text* (replace-all " :shift :asr :amount " " 2 " *mvm-source-text*))
  (setf *mvm-source-text* (replace-all " :option " " " *mvm-source-text*))
  ;; ecase shift → shift directly (already numeric after keyword stripping)
  (setf *mvm-source-text* (replace-all "(ecase shift (:lsl 0) (:lsr 1) (:asr 2))"
                                        "shift" *mvm-source-text*))
  ;; i386 translator preprocessing:
  ;; 1. Expand macrolet in i386-translate-insn (MVM compiler can't handle macrolet)
  (setf *mvm-source-text*
        (replace-all "(macrolet ((op= (sym) `(= opcode ,sym)))"
                     "(progn" *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "(op= " "(= opcode " *mvm-source-text*))
  ;; 2. Replace first/second/third (not in prelude) with car/cadr/caddr
  (setf *mvm-source-text* (replace-all "(first " "(car " *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "(second " "(cadr " *mvm-source-text*))
  (setf *mvm-source-text* (replace-all "(third " "(caddr " *mvm-source-text*))
  ;; 3. Replace /= with (not (= ...)) — single occurrence in i386-emit-modrm-mem
  (setf *mvm-source-text*
        (replace-all "(/= base-reg +i386-ebp+)" "(not (= base-reg +i386-ebp+))" *mvm-source-text*))
  ;; 4. Replace loop-for in TRAP handler (overflow args copy)
  (setf *mvm-source-text*
        (replace-all
         "(loop for param-idx from 4 below code
                      for k from 0  ;; k-th overflow arg
                      do (let ((src-off (+ 16 (* k 4)))
                               (dst-off (+ +frame-slot-base+ (* param-idx -4))))
                           (i386-emit-mov-reg-mem buf +scratch0+ +i386-ebp+ src-off)
                           (i386-emit-mov-mem-reg buf +i386-ebp+ dst-off +scratch0+)))"
         "(let ((param-idx 4))
                  (loop
                    (when (>= param-idx code) (return nil))
                    (let ((k (- param-idx 4)))
                      (let ((src-off (+ 16 (* k 4))))
                        (let ((dst-off (+ +frame-slot-base+ (* param-idx -4))))
                          (i386-emit-mov-reg-mem buf +scratch0+ +i386-ebp+ src-off)
                          (i386-emit-mov-mem-reg buf +i386-ebp+ dst-off +scratch0+))))
                    (setq param-idx (+ param-idx 1))))"
         *mvm-source-text*))
  ;; 5. Replace (vector ...) in *i386-vreg-map* with nil (init via explicit function)
  (setf *mvm-source-text*
        (replace-all
         "(defparameter *i386-vreg-map*
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
          nil))"
         "(defvar *i386-vreg-map* nil)"
         *mvm-source-text*))
  (format t "Preprocessed source (~D chars)~%" (length *mvm-source-text*)))

(format t "MVM system source: ~D chars across ~D files~%"
        (length *mvm-source-text*) (length *mvm-source-files*))

;;; ============================================================
;;; SSH mode: include networking source when --ssh flag is passed
;;; ============================================================

(defvar *fixpoint-ssh-mode*
  (member "--ssh" sb-ext:*posix-argv* :test #'string=))

(defvar *net-source-text*
  (when *fixpoint-ssh-mode*
    (format t "~%SSH mode: loading networking source...~%")
    (let ((net-dir (merge-pathnames "net/" *modus-base*)))
      ;; Load order:
      ;;   1. Arch adapters: i386 first, then x86, then aarch64 last
      ;;      (last-defun-wins: AArch64 addresses win for x64/aarch64 hosts)
      ;;   2. Drivers: ne2000 first, then e1000 last
      ;;      (e1000 wrappers win by default; dispatch layer overrides for dual-driver)
      ;;   3. Shared net core: ip, crypto (64-bit), ssh, aarch64-overrides
      ;; NOTE: crypto-32/crypto-i386/i386-overrides NOT loaded here.
      ;; Those override 64-bit crypto with 32-bit pair arithmetic (last-defun-wins),
      ;; which would make the x64/AArch64 host unusably slow.
      ;; The i386 SSH target needs proper runtime dispatch (future work).
      (let ((text (with-output-to-string (s)
                    ;; Arch adapters
                    (write-string (read-file-text (merge-pathnames "arch-i386.lisp" net-dir)) s)
                    (terpri s)
                    (write-string (read-file-text (merge-pathnames "arch-x86.lisp" net-dir)) s)
                    (terpri s)
                    (write-string (read-file-text (merge-pathnames "arch-aarch64.lisp" net-dir)) s)
                    (terpri s)
                    ;; NIC drivers (ne2000 first, e1000 last — e1000 wrappers win)
                    (write-string (read-file-text (merge-pathnames "ne2000.lisp" net-dir)) s)
                    (terpri s)
                    (write-string (read-file-text (merge-pathnames "e1000.lisp" net-dir)) s)
                    (terpri s)
                    ;; 64-bit net core
                    (write-string (read-file-text (merge-pathnames "ip.lisp" net-dir)) s)
                    (terpri s)
                    (write-string (read-file-text (merge-pathnames "crypto.lisp" net-dir)) s)
                    (terpri s)
                    (write-string (read-file-text (merge-pathnames "ssh.lisp" net-dir)) s)
                    (terpri s)
                    (write-string (read-file-text (merge-pathnames "aarch64-overrides.lisp" net-dir)) s)
                    (terpri s))))
        (format t "  Networking source: ~D chars~%" (length text))
        text))))

;;; Build-image-cross: the bare-metal cross-compilation entry point.
;;; This function reads the embedded MVM bytecode and function table,
;;; then calls the appropriate translator to produce native code for
;;; the target architecture.
;;;
;;; On bare metal, the fixpoint data is stored at:
;;;   0x380000: MVM bytecode address (tagged fixnum)
;;;   0x380008: MVM bytecode length (tagged fixnum)
;;;   0x380010: function table address (tagged fixnum)
;;;   0x380018: function table entry count (tagged fixnum)
;;;
;;; Function table format: packed array of 24-byte entries
;;;   [name-hash:u64] [bytecode-offset:u64] [bytecode-length:u64]

(defvar *fixpoint-extra-source*
"
;;; Override write-string-serial to be nil-safe
;;; (MVM compiles string literals as NIL — no heap strings on bare metal)
(defun write-string-serial (str)
  (if (null str)
      nil
      (let ((len (array-length str))
            (i 0))
        (loop
          (when (= i len) (return nil))
          (write-char-serial (aref str i))
          (setq i (+ i 1))))))

;;; Architecture-neutral metadata helpers: read/write u32 LE via :u8
;;; Works on any architecture (64/32-bit, LE/BE)
(defun td-read-u32 (addr)
  (let ((b0 (mem-ref addr :u8)))
    (let ((b1 (mem-ref (+ addr 1) :u8)))
      (let ((b2 (mem-ref (+ addr 2) :u8)))
        (let ((b3 (mem-ref (+ addr 3) :u8)))
          (+ b0 (+ (ash b1 8) (+ (ash b2 16) (ash b3 24)))))))))

(defun td-write-u32 (addr val)
  (setf (mem-ref addr :u8) (logand val 255))
  (setf (mem-ref (+ addr 1) :u8) (logand (ash val -8) 255))
  (setf (mem-ref (+ addr 2) :u8) (logand (ash val -16) 255))
  (setf (mem-ref (+ addr 3) :u8) (logand (ash val -24) 255)))

;;; Override error to use direct char output + print diagnostics + actually halt
;;; Diagnostics at 0x380040+ use u32 LE format
(defun error (msg)
  ;; Print ERR: using direct char codes (not string literals)
  (write-char-serial 69) (write-char-serial 82)
  (write-char-serial 82) (write-char-serial 58)
  ;; Print current function index from diagnostic address
  (write-char-serial 102) ;; f
  (print-dec (td-read-u32 #x380040))
  ;; Print step checkpoint
  (write-char-serial 115) ;; s
  (print-dec (td-read-u32 #x380044))
  ;; Print current bytecode position
  (write-char-serial 64) ;; @
  (print-dec (td-read-u32 #x380048))
  ;; Print opcode
  (write-char-serial 111) ;; o
  (print-dec (td-read-u32 #x38004C))
  ;; Print new-pos
  (write-char-serial 110) ;; n
  (print-dec (td-read-u32 #x380050))
  ;; Print MOV operands
  (write-char-serial 32) (write-char-serial 100) ;; d
  (print-dec (td-read-u32 #x380054))
  (write-char-serial 47) ;; /
  (print-dec (td-read-u32 #x380058))
  ;; Print completion marker
  (write-char-serial 32) (write-char-serial 99) ;; c
  (print-dec (td-read-u32 #x38005C))
  ;; Print msg value (if fixnum, print as number; helps identify which error)
  (write-char-serial 32) (write-char-serial 109) ;; m
  (print-dec msg)
  (write-char-serial 10)
  ;; Actually halt: (hlt) is the compiler built-in, (halt) is undefined
  (loop (hlt)))

;;; Override warn to use direct char output
(defun warn (msg)
  (write-char-serial 87) (write-char-serial 65)
  (write-char-serial 82) (write-char-serial 78)
  (write-char-serial 58) (write-char-serial 10))

;;; Fixpoint metadata layout (all u32 LE at VA 0x380000):
;;;   +0x00: magic 0x544D564D (MVMT)
;;;   +0x04: version (1)
;;;   +0x08: my-architecture (0=x64, 1=aarch64)
;;;   +0x0C: bytecode-offset (image offset)
;;;   +0x10: bytecode-length
;;;   +0x14: fn-table-offset (image offset)
;;;   +0x18: fn-table-count
;;;   +0x1C: native-code-offset (image offset)
;;;   +0x20: native-code-length
;;;   +0x24: preamble-size
;;;   +0x28: kernel-main-hash-lo (lower 32 bits)
;;;   +0x2C: kernel-main-native-offset
;;;   +0x30: image-load-addr
;;;   +0x34: (reserved)
;;;   +0x38: (reserved)
;;;   +0x3C: (reserved)
;;; Diagnostics at +0x40:
;;;   +0x40: current fn index (u32)
;;;   +0x44: step checkpoint (u32)
;;;   +0x48: bytecode position (u32)
;;;   +0x4C: opcode (u32)

;;; Fixpoint: read embedded MVM bytecode into an array
(defun td-read-bytecode ()
  (let ((img-base (td-read-u32 #x380030)))
    (let ((bc-off (td-read-u32 #x38000C)))
      (let ((bc-len (td-read-u32 #x380010)))
        (if (zerop bc-len)
            nil
            (let ((addr (+ img-base bc-off)))
              (let ((bc (make-array bc-len))
                    (i 0))
                (loop
                  (when (>= i bc-len) (return bc))
                  (aset bc i (mem-ref (+ addr i) :u8))
                  (setq i (+ i 1))))))))))

;;; Fixpoint: read embedded function table as a list of (name offset length)
;;; Function table entries are 12 bytes each (3 x u32 LE)
(defun td-read-fn-table-list ()
  (let ((img-base (td-read-u32 #x380030)))
    (let ((ft-off (td-read-u32 #x380014)))
      (let ((ft-count (td-read-u32 #x380018)))
        (if (zerop ft-count)
            nil
            (let ((addr (+ img-base ft-off)))
              (let ((result nil)
                    (i 0))
                (loop
                  (when (>= i ft-count) (return (nreverse result)))
                  (let ((base (+ addr (* i 12))))
                    (let ((name (td-read-u32 base)))
                      (let ((offset (td-read-u32 (+ base 4))))
                        (let ((length (td-read-u32 (+ base 8))))
                          (setq result (cons (cons name (cons offset (cons length nil)))
                                             result))
                          (setq i (+ i 1))))))))))))))

;;; Direct register lookup functions — bypass *registers* alist
;;; The 48-entry *registers* alist in x64-asm.lisp is too large for
;;; compile-quote (causes triple fault from deep recursive cons nesting).
;;; These overrides compute register info directly via cond, no consing.

(defun reg-code-lookup (reg)
  (cond
    ((eql reg 'rax) 0) ((eql reg 'eax) 0) ((eql reg 'al) 0)
    ((eql reg 'rcx) 1) ((eql reg 'ecx) 1) ((eql reg 'cl) 1)
    ((eql reg 'rdx) 2) ((eql reg 'edx) 2) ((eql reg 'dl) 2)
    ((eql reg 'rbx) 3) ((eql reg 'ebx) 3) ((eql reg 'bl) 3)
    ((eql reg 'rsp) 4) ((eql reg 'esp) 4) ((eql reg 'spl) 4)
    ((eql reg 'rbp) 5) ((eql reg 'ebp) 5) ((eql reg 'bpl) 5)
    ((eql reg 'rsi) 6) ((eql reg 'esi) 6) ((eql reg 'sil) 6)
    ((eql reg 'rdi) 7) ((eql reg 'edi) 7) ((eql reg 'dil) 7)
    ((eql reg 'r8) 8) ((eql reg 'r8d) 8) ((eql reg 'r8b) 8)
    ((eql reg 'r9) 9) ((eql reg 'r9d) 9) ((eql reg 'r9b) 9)
    ((eql reg 'r10) 10) ((eql reg 'r10d) 10) ((eql reg 'r10b) 10)
    ((eql reg 'r11) 11) ((eql reg 'r11d) 11) ((eql reg 'r11b) 11)
    ((eql reg 'r12) 12) ((eql reg 'r12d) 12) ((eql reg 'r12b) 12)
    ((eql reg 'r13) 13) ((eql reg 'r13d) 13) ((eql reg 'r13b) 13)
    ((eql reg 'r14) 14) ((eql reg 'r14d) 14) ((eql reg 'r14b) 14)
    ((eql reg 'r15) 15) ((eql reg 'r15d) 15) ((eql reg 'r15b) 15)
    (t 0)))

(defun reg-size-lookup (reg)
  (cond
    ((eql reg 'rax) 64) ((eql reg 'rcx) 64) ((eql reg 'rdx) 64) ((eql reg 'rbx) 64)
    ((eql reg 'rsp) 64) ((eql reg 'rbp) 64) ((eql reg 'rsi) 64) ((eql reg 'rdi) 64)
    ((eql reg 'r8) 64) ((eql reg 'r9) 64) ((eql reg 'r10) 64) ((eql reg 'r11) 64)
    ((eql reg 'r12) 64) ((eql reg 'r13) 64) ((eql reg 'r14) 64) ((eql reg 'r15) 64)
    ((eql reg 'eax) 32) ((eql reg 'ecx) 32) ((eql reg 'edx) 32) ((eql reg 'ebx) 32)
    ((eql reg 'esp) 32) ((eql reg 'ebp) 32) ((eql reg 'esi) 32) ((eql reg 'edi) 32)
    ((eql reg 'r8d) 32) ((eql reg 'r9d) 32) ((eql reg 'r10d) 32) ((eql reg 'r11d) 32)
    ((eql reg 'r12d) 32) ((eql reg 'r13d) 32) ((eql reg 'r14d) 32) ((eql reg 'r15d) 32)
    ((eql reg 'al) 8) ((eql reg 'cl) 8) ((eql reg 'dl) 8) ((eql reg 'bl) 8)
    ((eql reg 'spl) 8) ((eql reg 'bpl) 8) ((eql reg 'sil) 8) ((eql reg 'dil) 8)
    ((eql reg 'r8b) 8) ((eql reg 'r9b) 8) ((eql reg 'r10b) 8) ((eql reg 'r11b) 8)
    ((eql reg 'r12b) 8) ((eql reg 'r13b) 8) ((eql reg 'r14b) 8) ((eql reg 'r15b) 8)
    (t 64)))

(defun reg-rex-flag (reg)
  (cond
    ((eql reg 'r8) t) ((eql reg 'r9) t) ((eql reg 'r10) t) ((eql reg 'r11) t)
    ((eql reg 'r12) t) ((eql reg 'r13) t) ((eql reg 'r14) t) ((eql reg 'r15) t)
    ((eql reg 'r8d) t) ((eql reg 'r9d) t) ((eql reg 'r10d) t) ((eql reg 'r11d) t)
    ((eql reg 'r12d) t) ((eql reg 'r13d) t) ((eql reg 'r14d) t) ((eql reg 'r15d) t)
    ((eql reg 'spl) t) ((eql reg 'bpl) t) ((eql reg 'sil) t) ((eql reg 'dil) t)
    ((eql reg 'r8b) t) ((eql reg 'r9b) t) ((eql reg 'r10b) t) ((eql reg 'r11b) t)
    ((eql reg 'r12b) t) ((eql reg 'r13b) t) ((eql reg 'r14b) t) ((eql reg 'r15b) t)
    (t nil)))

;;; Override reg-info to build result from direct lookups (last-defun-wins)
(defun reg-info (reg)
  (let ((code (reg-code-lookup reg)))
    (let ((size (reg-size-lookup reg)))
      (let ((rex (reg-rex-flag reg)))
        (let ((t1 (cons rex nil)))
          (let ((t2 (cons size t1)))
            (let ((t3 (cons code t2)))
              (cons reg t3))))))))

;;; Array-based position labels: bypass hash table for branch target labels.
;;; Hash table gethash/puthash inconsistently fails on AArch64 bare metal,
;;; causing 140 labels with target=0 (position never set). Array indexing
;;; is simple and reliable.
(defvar *td-label-array* nil)
(defvar *td-label-base* 0)
;;; Global fn-offset-to-label array: indexed by bytecode offset.
;;; CALL opcode looks up function labels by bytecode offset.
;;; Hash table gethash is unreliable on AArch64 bare metal.
(defvar *td-fn-label-array* nil)

;;; Override ensure-label-at: use array instead of position-labels hash table
(defun ensure-label-at (state mvm-pos)
  (let ((idx (- mvm-pos *td-label-base*)))
    (let ((existing (aref *td-label-array* idx)))
      (if (zerop existing)
          (let ((label (make-label)))
            (let ((dummy (aset *td-label-array* idx label)))
              label))
          existing))))

;;; Override emit-label: simpler version that just sets position (no hash table)
(defun emit-label (buf label)
  (let ((pos (code-buffer-position buf)))
    (aset label 1 pos)))

;;; Override scan-branch-targets: use numeric opcode checks instead of
;;; (member :off16 op-specs) which fails on bare metal (equal broken for cons cells).
;;; Branch opcodes: BR(64)-BGT(70) have offset in operand 0,
;;;                 BNULL(71)/BNNULL(72) have offset in operand 1.
(defun scan-branch-targets (state)
  (let ((bytes (translate-state-mvm-bytes state))
        (offset (translate-state-mvm-offset state))
        (length (translate-state-mvm-length state)))
    (let ((pos offset)
          (limit (+ offset length)))
      (loop
        (when (>= pos limit) (return nil))
        (let ((decoded (decode-instruction bytes pos)))
          (let ((opcode (car decoded))
                (operands (car (cdr decoded)))
                (new-pos (cdr (cdr decoded))))
            ;; Check if branch opcode (0x40-0x48 = 64-72)
            (when (and (>= opcode 64) (<= opcode 72))
              (let ((off (if (<= opcode 70)
                             (car operands)         ;; BR-BGT: offset is operand 0
                             (car (cdr operands))))) ;; BNULL/BNNULL: offset is operand 1
                (let ((target-pos (+ new-pos off)))
                  (ensure-label-at state target-pos))))
            (setq pos new-pos)))))))

(defun reg-code (reg)
  (logand 7 (reg-code-lookup reg)))

(defun reg-size (reg)
  (reg-size-lookup reg))

(defun reg-needs-rex-p (reg)
  (let ((code (reg-code-lookup reg)))
    (if (>= code 8) t (reg-rex-flag reg))))

(defun reg-extended-p (reg)
  (>= (reg-code-lookup reg) 8))

;;; Override emit-load-vreg/emit-store-vreg with diagnostic (last-defun-wins)
(defun emit-load-vreg (buf vreg phys-dest)
  (let ((phys (vreg-phys vreg)))
    (cond
      (phys
       (if (eql phys phys-dest)
           nil
           (emit-mov-reg-reg buf phys-dest phys)))
      ((vreg-spills-p vreg)
       (emit-mov-reg-mem buf phys-dest 'rbp (spill-offset vreg)))
      (t
       ;; Diagnostic: print vreg value
       (write-char-serial 76) ;; L
       (write-char-serial 86) ;; V
       (print-dec vreg) (write-char-serial 10)
       (error 1)))))

(defun emit-store-vreg (buf vreg phys-src)
  (let ((phys (vreg-phys vreg)))
    (cond
      (phys
       (if (eql phys phys-src)
           nil
           (emit-mov-reg-reg buf phys phys-src)))
      ((vreg-spills-p vreg)
       (emit-mov-mem-reg buf 'rbp phys-src (spill-offset vreg)))
      (t
       ;; Diagnostic: print vreg value
       (write-char-serial 83) ;; S
       (write-char-serial 86) ;; V
       (print-dec vreg) (write-char-serial 10)
       (error 2)))))

;;; Direct ALU rrr helpers — no funcall/#'function (avoids FN-ADDR on AArch64)
;;; Each function inlines the specific emit-xxx-reg-reg call.
(defun td-alu-core (buf vd va vb op-tag)
  ;; op-tag: 0=add, 1=sub, 2=and, 3=or, 4=xor
  (let ((d (dest-phys-or-scratch vd)))
    (let ((pa (vreg-phys va)))
      (let ((pb (vreg-phys vb)))
        ;; Step 1: load Va into d
        (cond
          (pa (if (eql pa d) nil (emit-mov-reg-reg buf d pa)))
          (t (emit-load-vreg buf va d)))
        ;; Step 2: apply op (dispatch by tag, no funcall)
        (let ((src (if pb pb nil)))
          (if src
              (cond
                ((= op-tag 0) (emit-add-reg-reg buf d src))
                ((= op-tag 1) (emit-sub-reg-reg buf d src))
                ((= op-tag 2) (emit-and-reg-reg buf d src))
                ((= op-tag 3) (emit-or-reg-reg buf d src))
                ((= op-tag 4) (emit-xor-reg-reg buf d src)))
              (let ((tmp (if (eql d 'rax) 'r13 'rax)))
                (emit-push buf tmp)
                (emit-load-vreg buf vb tmp)
                (cond
                  ((= op-tag 0) (emit-add-reg-reg buf d tmp))
                  ((= op-tag 1) (emit-sub-reg-reg buf d tmp))
                  ((= op-tag 2) (emit-and-reg-reg buf d tmp))
                  ((= op-tag 3) (emit-or-reg-reg buf d tmp))
                  ((= op-tag 4) (emit-xor-reg-reg buf d tmp)))
                (emit-pop buf tmp))))
        ;; Step 3: store if spilled
        (maybe-store-scratch buf vd)))))

(defun td-emit-add (buf operands)
  (let ((vd (car operands)))
    (let ((va (car (cdr operands))))
      (let ((vb (car (cdr (cdr operands)))))
        (td-alu-core buf vd va vb 0)))))

(defun td-emit-sub (buf operands)
  (let ((vd (car operands)))
    (let ((va (car (cdr operands))))
      (let ((vb (car (cdr (cdr operands)))))
        (td-alu-core buf vd va vb 1)))))

(defun td-emit-and (buf operands)
  (let ((vd (car operands)))
    (let ((va (car (cdr operands))))
      (let ((vb (car (cdr (cdr operands)))))
        (td-alu-core buf vd va vb 2)))))

(defun td-emit-or (buf operands)
  (let ((vd (car operands)))
    (let ((va (car (cdr operands))))
      (let ((vb (car (cdr (cdr operands)))))
        (td-alu-core buf vd va vb 3)))))

(defun td-emit-xor (buf operands)
  (let ((vd (car operands)))
    (let ((va (car (cdr operands))))
      (let ((vb (car (cdr (cdr operands)))))
        (td-alu-core buf vd va vb 4)))))

(defun td-translate-fn-body (state)
  (let ((bytes (translate-state-mvm-bytes state))
        (offset (translate-state-mvm-offset state))
        (len (translate-state-mvm-length state)))
    (let ((pos offset)
          (limit (+ offset len)))
      (loop
        (when (>= pos limit) (return nil))
        ;; Use array-based label lookup (bypasses hash table)
        (let ((lbl-idx (- pos *td-label-base*)))
          (let ((label (aref *td-label-array* lbl-idx)))
            (when (not (zerop label))
              (emit-label (translate-state-buf state) label))))
        (let ((decoded (decode-instruction bytes pos)))
          (let ((opcode (car decoded))
                (operands (car (cdr decoded)))
                (new-pos (cdr (cdr decoded))))
            ;; Intercept opcodes that need bare-metal fixes
            (cond
              ;; ALU rrr: direct call, no funcall/#'function
              ((= opcode 32)  ;; ADD
               (td-emit-add (translate-state-buf state) operands))
              ((= opcode 33)  ;; SUB
               (td-emit-sub (translate-state-buf state) operands))
              ((= opcode 40)  ;; AND
               (td-emit-and (translate-state-buf state) operands))
              ((= opcode 41)  ;; OR
               (td-emit-or (translate-state-buf state) operands))
              ((= opcode 42)  ;; XOR
               (td-emit-xor (translate-state-buf state) operands))
              ;; CONSP: handle internal labels explicitly (bypass translate-instruction)
              ((= opcode 85)  ;; CONSP (#x55)
               (let ((vd (car operands))
                     (vs (car (cdr operands))))
                 (let ((buf2 (translate-state-buf state)))
                   (let ((d (dest-phys-or-scratch vd))
                         (true-label (make-label))
                         (end-label (make-label)))
                     (emit-load-vreg buf2 vs d)
                     (emit-and-reg-imm buf2 d 15)
                     (emit-cmp-reg-imm buf2 d 1)
                     (emit-jcc buf2 :e true-label)
                     (emit-mov-reg-reg buf2 d (quote r15))
                     (emit-jmp buf2 end-label)
                     (let ((p1 (code-buffer-position buf2)))
                       (aset true-label 1 p1))
                     (emit-mov-reg-imm buf2 d 3735883785)
                     (let ((p2 (code-buffer-position buf2)))
                       (aset end-label 1 p2))
                     (maybe-store-scratch buf2 vd)))))
              ;; ATOM: handle internal labels explicitly
              ((= opcode 86)  ;; ATOM (#x56)
               (let ((vd (car operands))
                     (vs (car (cdr operands))))
                 (let ((buf2 (translate-state-buf state)))
                   (let ((d (dest-phys-or-scratch vd))
                         (true-label (make-label))
                         (end-label (make-label)))
                     (emit-load-vreg buf2 vs d)
                     (emit-and-reg-imm buf2 d 15)
                     (emit-cmp-reg-imm buf2 d 1)
                     (emit-jcc buf2 :ne true-label)
                     (emit-mov-reg-reg buf2 d (quote r15))
                     (emit-jmp buf2 end-label)
                     (let ((p1 (code-buffer-position buf2)))
                       (aset true-label 1 p1))
                     (emit-mov-reg-imm buf2 d 3735883785)
                     (let ((p2 (code-buffer-position buf2)))
                       (aset end-label 1 p2))
                     (maybe-store-scratch buf2 vd)))))
              ;; GC-CHECK: handle skip-label explicitly
              ((= opcode 137) ;; GC-CHECK (#x89)
               (let ((buf2 (translate-state-buf state)))
                 (let ((skip-label (make-label)))
                   (emit-cmp-reg-reg buf2 (quote r12) (quote r14))
                   (emit-jcc buf2 :l skip-label)
                   (let ((gc-lbl (translate-state-gc-label state)))
                     (if gc-lbl
                         (emit-call buf2 gc-lbl)
                         (emit-int buf2 49)))
                   (let ((p1 (code-buffer-position buf2)))
                     (aset skip-label 1 p1)))))
              ;; TAILCALL: use fn-label-array (like CALL)
              ((= opcode 131) ;; TAILCALL (#x83)
               (let ((target-offset (car operands)))
                 (let ((buf2 (translate-state-buf state))
                       (label (aref *td-fn-label-array* target-offset)))
                   (emit-mov-reg-mem buf2 (quote rbx) (quote rbp) -8)
                   (emit-mov-reg-reg buf2 (quote rsp) (quote rbp))
                   (emit-pop buf2 (quote rbp))
                   (if (zerop label)
                       (emit-jmp buf2 (make-label))
                       (emit-jmp buf2 label)))))
              ;; CALL: use array-based fn label lookup (bypass hash table)
              ((= opcode 128) ;; CALL
               (let ((target-offset (car operands)))
                 (let ((label (aref *td-fn-label-array* target-offset)))
                   (if (zerop label)
                       (emit-call (translate-state-buf state) (make-label))
                       (emit-call (translate-state-buf state) label)))))
              ;; FN-ADDR: same array lookup
              ((= opcode 167) ;; FN-ADDR
               (let ((vd (car operands))
                     (target-offset (car (cdr operands))))
                 (let ((label (aref *td-fn-label-array* target-offset)))
                   (let ((d (dest-phys-or-scratch vd)))
                     (if (zerop label)
                         ;; Unknown target — load 0 (matches original)
                         (emit-mov-reg-imm (translate-state-buf state) d 0)
                         (emit-lea-label (translate-state-buf state) d label))
                     (maybe-store-scratch (translate-state-buf state) vd)))))
              (t
               (translate-instruction state opcode operands new-pos)))
            (setq pos new-pos)))))))

(defun td-translate-one-fn (ctx fn-label offset len)
  ;; ctx = (cons buf (cons bytecode fn-offset-to-label))
  ;; 4 args → all in registers, no overflow stack args
  (let ((buf (car ctx))
        (bytecode (car (cdr ctx)))
        (fn-offset-to-label (cdr (cdr ctx))))
    (let ((state (make-translate-state)))
      (set-translate-state-buf state buf)
      (set-translate-state-mvm-bytes state bytecode)
      (set-translate-state-mvm-length state len)
      (set-translate-state-mvm-offset state offset)
      (set-translate-state-function-table state fn-offset-to-label)
      ;; Emit function label
      (let ((lpos (code-buffer-position buf)))
        (aset fn-label 1 lpos)
        (let ((labels-ht (code-buffer-labels buf)))
          (puthash fn-label labels-ht lpos)))
      ;; Emit prologue
      (emit-function-prologue buf)
      ;; Set up array-based position labels (bypass hash table)
      (setq *td-label-array* (make-array len))
      (setq *td-label-base* offset)
      ;; Pre-scan branch targets
      (scan-branch-targets state)
      ;; Translate instructions
      (td-translate-fn-body state))))

;;; Override translate-mvm-to-x64 (last-defun-wins)
(defun translate-mvm-to-x64 (bytecode function-table)
  (let ((buf (make-code-buffer)))
    (let ((n-functions (length function-table)))
      (print-dec n-functions) (write-char-serial 10)
      (let ((fn-labels (make-array n-functions)))
        (let ((fn-map (make-hash-table))
              (fn-offset-to-label (make-hash-table)))
          ;; Create global array for fn-offset-to-label (bypass hash table)
          (setq *td-fn-label-array* (make-array (array-length bytecode)))
          (let ((rest-ft function-table)
                (i 0))
            (loop
              (when (>= i n-functions) (return nil))
              (let ((entry (car rest-ft)))
                (let ((name (car entry))
                      (offset (car (cdr entry))))
                  (let ((label (make-label)))
                    (aset fn-labels i label)
                    (puthash name fn-map label)
                    (puthash offset fn-offset-to-label label)
                    (let ((dummy (aset *td-fn-label-array* offset label)))
                      dummy))))
              (setq rest-ft (cdr rest-ft))
              (setq i (+ i 1))))
          ;; Translate each function
          (write-char-serial 84) (write-char-serial 10) ;; T
          (let ((ctx (cons buf (cons bytecode fn-offset-to-label))))
            (let ((rest-ft function-table)
                  (i 0))
              (loop
                (when (>= i n-functions) (return nil))
                (let ((entry (car rest-ft)))
                  (let ((offset (car (cdr entry)))
                        (len (car (cdr (cdr entry)))))
                    (let ((fn-label (aref fn-labels i)))
                      (td-translate-one-fn ctx fn-label offset len))))
                (setq rest-ft (cdr rest-ft))
                (setq i (+ i 1))
                (when (zerop (mod i 50))
                  (write-char-serial 35) ;; #
                  (print-dec i)
                  (write-char-serial 10)))))
          ;; Apply fixups
          (fixup-labels buf)
          ;; Post-fixup checksum (uses td-fnv-native — i386-safe)
          (let ((pos (code-buffer-position buf))
                (bytes (code-buffer-bytes buf)))
            (print-dec pos) (write-char-serial 10)
            (let ((fnv (td-fnv-native bytes pos)))
              (write-char-serial 70) (write-char-serial 78) ;; FN
              (write-char-serial 86) (write-char-serial 58) ;; V:
              (print-dec fnv) (write-char-serial 10)))
          (cons buf fn-map))))))

;;; Override emit-label-ref-rel32: bare-metal compatible version
(defun emit-label-ref-rel32 (buf label)
  (let ((pos (code-buffer-position buf)))
    (let ((inner (cons 4 nil)))
      (let ((mid (cons label inner)))
        (let ((entry (cons pos mid)))
          (let ((old-fixups (code-buffer-fixups buf)))
            (let ((new-fixups (cons entry old-fixups)))
              (set-code-buffer-fixups buf new-fixups)))))))
  (emit-u32 buf 0))

;;; Override emit-call: skip label-p check (broken on AArch64 due to tag mismatch:
;;; MVM compiler bakes tag=9 into bytecodes, AArch64 translator uses tag=2)
;;; In fixpoint, target is ALWAYS a label from translate-instruction.
(defun emit-call (buf target)
  (emit-byte buf #xE8)
  (emit-label-ref-rel32 buf target))

;;; Override emit-jmp: skip label-p check
(defun emit-jmp (buf target)
  (emit-byte buf #xE9)
  (emit-label-ref-rel32 buf target))

;;; Override emit-jcc: skip label-p check, use assoc for condition code lookup
(defun emit-jcc (buf cc target)
  (let ((code (cdr (assoc cc *condition-codes*))))
    (emit-bytes buf #x0F (+ #x80 code))
    (emit-label-ref-rel32 buf target)))

;;; Helper: patch 4 LE bytes at pos in bytes array
;;; Separate function avoids variable-index ASET dest=nil bug
;;; (when ASET is non-last form with dest=nil, value register doesn't load
;;; on AArch64 due to different register allocation vs x64)
(defun fixup-patch-one (bytes pos rel)
  (let ((v0 (logand rel 255)))
    (let ((d0 (aset bytes pos v0)))
      (let ((v1 (logand (ash rel -8) 255)))
        (let ((d1 (aset bytes (+ pos 1) v1)))
          (let ((v2 (logand (ash rel -16) 255)))
            (let ((d2 (aset bytes (+ pos 2) v2)))
              (let ((v3 (logand (ash rel -24) 255)))
                (let ((d3 (aset bytes (+ pos 3) v3)))
                  d3)))))))))

;;; Override fixup-labels: MVM-compatible version (no destructuring-bind/ecase/setf)
(defun fixup-labels (buf)
  (let ((bytes (code-buffer-bytes buf))
        (fixups (code-buffer-fixups buf)))
    (let ((rest-fixups fixups))
      (loop
        (when (null rest-fixups) (return nil))
        (let ((fixup (car rest-fixups)))
          (let ((pos (car fixup))
                (label (car (cdr fixup)))
                (size (car (cdr (cdr fixup)))))
            (let ((target (aref label 1)))
              (when (eql size 4)
                (let ((sum (+ pos size)))
                  (let ((rel (- target sum)))
                    (fixup-patch-one bytes pos rel)))))))
        (setq rest-fixups (cdr rest-fixups)))))
  buf)

;;; ============================================================
;;; Image buffer functions (for assembling Gen1 on bare metal)
;;; ============================================================
;;; Image buffer at 0x08000000, position counter at 0x4FF040

(defun img-init ()
  (setf (mem-ref #x4FF040 :u64) 0))

(defun img-pos ()
  (mem-ref #x4FF040 :u64))

(defun img-emit (b)
  (let ((pos (mem-ref #x4FF040 :u64)))
    (setf (mem-ref (+ #x08000000 pos) :u8) b)
    (setf (mem-ref #x4FF040 :u64) (+ pos 1))))

(defun img-emit-u32 (v)
  (img-emit (logand v 255))
  (img-emit (logand (ash v -8) 255))
  (img-emit (logand (ash v -16) 255))
  (img-emit (logand (ash v -24) 255)))

(defun img-emit-u64-raw (v)
  ;; Write tagged fixnum v as 8 LE bytes via mem-ref :u64 (raw bits)
  ;; This preserves the tagged representation for next-generation reads
  (let ((pos (mem-ref #x4FF040 :u64)))
    (setf (mem-ref (+ #x08000000 pos) :u64) v)
    (setf (mem-ref #x4FF040 :u64) (+ pos 8))))

(defun img-patch-u32 (offset v)
  (let ((base #x08000000))
    (setf (mem-ref (+ base offset) :u8) (logand v 255))
    (let ((p1 (+ offset 1)))
      (setf (mem-ref (+ base p1) :u8) (logand (ash v -8) 255)))
    (let ((p2 (+ offset 2)))
      (setf (mem-ref (+ base p2) :u8) (logand (ash v -16) 255)))
    (let ((p3 (+ offset 3)))
      (setf (mem-ref (+ base p3) :u8) (logand (ash v -24) 255)))))

(defun img-emit-boot-preamble ()
  ;; Preamble size stored at metadata +0x24 = address 0x300024
  (let ((size (td-read-u32 #x380024))
        (i 0))
    (let ((load-addr (td-read-u32 #x380030)))
      (loop
        (when (>= i size) (return i))
        (img-emit (mem-ref (+ load-addr i) :u8))
        (setq i (+ i 1))))))

;;; Fixpoint: compute FNV-1a of native code
(defun td-fnv-native (bytes size)
  (let ((hash 2166136261)
        (j 0))
    (loop
      (when (>= j size) (return hash))
      (let ((b (aref bytes j)))
        (setq hash (logand #xFFFFFFFF
                           (* (logxor hash b) 16777619))))
      (setq j (+ j 1)))))

;;; Fixpoint: assemble Gen1 x64 image from translated native code
;;; Writes a bootable multiboot1 image to 0x08000000
(defun td-assemble-gen1 (result bc ft)
  ;; result = (cons code-buffer fn-map)
  ;; bc = bytecode array, ft = function table list
  (let ((buf (car result))
        (fn-map (cdr result)))
    (let ((native-bytes (code-buffer-bytes buf))
          (native-size (code-buffer-position buf)))
      ;; 1. Init image buffer
      (img-init)
      (write-char-serial 71) (write-char-serial 49) ;; G1
      (write-char-serial 58) (write-char-serial 10) ;; :NL
      ;; 2. Copy boot preamble from running kernel
      (img-emit-boot-preamble)
      (write-char-serial 80) ;; P
      (print-dec (img-pos))
      (write-char-serial 10)
      ;; 3. Emit JMP rel32 to kernel-main
      ;; Kernel-main native offset from metadata +0x2C
      (let ((km-offset (td-read-u32 #x38002C)))
        (let ((jmp-pos (img-pos)))
          (img-emit #xE9)
          (img-emit-u32 km-offset)
          ;; 4. Copy native code from code-buffer
          (write-char-serial 78) ;; N
          ;; Save code-start position in diagnostic slot for metadata
          (td-write-u32 #x380050 (img-pos))
          (let ((i 0))
            (loop
              (when (>= i native-size) (return nil))
              (img-emit (aref native-bytes i))
              (setq i (+ i 1))
              (when (zerop (mod i 50000))
                (write-char-serial 46))))
          (write-char-serial 10)
          (print-dec (img-pos))
          (write-char-serial 10)
          ;; 5. Append fixpoint data: MVM bytecode
          (write-char-serial 84) ;; T
          (let ((bc-len (array-length bc))
                (bc-img-offset (img-pos)))
            (let ((bi 0))
              (loop
                (when (>= bi bc-len) (return nil))
                (img-emit (aref bc bi))
                (setq bi (+ bi 1))))
            ;; 6. Append function table entries (12 bytes each, 3 x u32 LE)
            (let ((ft-img-offset (img-pos))
                  (rest-ft ft)
                  (ft-count 0))
              (loop
                (when (null rest-ft) (return nil))
                (let ((entry (car rest-ft)))
                  (let ((name (car entry))
                        (offset (car (cdr entry)))
                        (len (car (cdr (cdr entry)))))
                    (img-emit-u32 name)
                    (img-emit-u32 offset)
                    (img-emit-u32 len)))
                (setq rest-ft (cdr rest-ft))
                (setq ft-count (+ ft-count 1)))
              (write-char-serial 10)
              (print-dec ft-count)
              (write-char-serial 10)
              ;; 7. Write fixpoint metadata at offset 0x280000 (= VA 0x380000 for x64)
              ;; All values as u32 LE
              (let ((md-img-off #x280000))
                ;; magic MVMT = 0x544D564D
                (img-patch-u32 md-img-off #x544D564D)
                ;; version = 1
                (img-patch-u32 (+ md-img-off 4) 1)
                ;; my-architecture = 0 (x64)
                (img-patch-u32 (+ md-img-off 8) 0)
                ;; bytecode-offset
                (img-patch-u32 (+ md-img-off 12) bc-img-offset)
                ;; bytecode-length
                (img-patch-u32 (+ md-img-off 16) bc-len)
                ;; fn-table-offset
                (img-patch-u32 (+ md-img-off 20) ft-img-offset)
                ;; fn-table-count
                (img-patch-u32 (+ md-img-off 24) ft-count)
                ;; native-code-offset (saved in diagnostic slot)
                (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x380050))
                ;; native-code-length
                (img-patch-u32 (+ md-img-off 32) native-size)
                ;; preamble-size (same as running kernel)
                (let ((preamble (td-read-u32 #x380024)))
                  (img-patch-u32 (+ md-img-off 36) preamble))
                ;; kernel-main-hash-lo (copy from running kernel)
                (let ((km-hash (td-read-u32 #x380028)))
                  (img-patch-u32 (+ md-img-off 40) km-hash))
                ;; kernel-main-native-offset
                (img-patch-u32 (+ md-img-off 44) km-offset)
                ;; image-load-addr = 0x100000 (x64)
                (img-patch-u32 (+ md-img-off 48) #x100000)
                ;; target-architecture (default: 1=aarch64, overridden by host script)
                (img-patch-u32 (+ md-img-off 52) 1)
                ;; mode (default: 0=cross-compile, overridden by host script)
                (img-patch-u32 (+ md-img-off 56) 0))
              ;; 8. Patch multiboot header: load_end_addr, bss_end_addr
              (let ((total-size (+ #x280000 64)))
                (let ((load-end (+ #x100000 total-size)))
                  (img-patch-u32 20 load-end)
                  (img-patch-u32 24 load-end))
                ;; Print Gen1 info
                (write-char-serial 71) (write-char-serial 49) ;; G1
                (write-char-serial 61) ;; =
                (print-dec total-size)
                (write-char-serial 10)
                total-size))))))))

;;; Fixpoint: build-image-cross entry point
;;; Build x64 target from x64 host (same-arch, existing path)
(defun td-print-bytes-at (bytes pos offset count)
  ;; Print COUNT bytes at OFFSET for comparison
  (write-char-serial 66) (write-char-serial 64) ;; B@
  (print-dec offset) (write-char-serial 58) ;; :
  (let ((i 0))
    (loop
      (when (>= i count) (return nil))
      (let ((idx (+ offset i)))
        (when (< idx pos)
          (write-char-serial 32)
          (print-dec (aref bytes idx))))
      (setq i (+ i 1))))
  (write-char-serial 10))

(defun build-x64-from-x64 (bc ft)
  (let ((result (translate-mvm-to-x64 bc ft)))
    ;; result is (cons code-buffer fn-map)
    (let ((buf (car result)))
      (let ((pos (code-buffer-position buf)))
        (print-dec pos) (write-char-serial 10)
        ;; FNV-1a of native code
        (let ((native-bytes (code-buffer-bytes buf)))
          (let ((hash (td-fnv-native native-bytes pos)))
            (write-char-serial 70) (write-char-serial 78) ;; FN
            (write-char-serial 86) (write-char-serial 58) ;; V:
            (print-dec hash) (write-char-serial 10))
          ;; Print bytes at key positions for comparison with SBCL reference
          (td-print-bytes-at native-bytes pos 0 16)
          (td-print-bytes-at native-bytes pos 1000 16)
          (td-print-bytes-at native-bytes pos 100000 16)
          (td-print-bytes-at native-bytes pos 200000 16)
          ;; XOR checksum
          (let ((xsum 0) (xi 0))
            (loop
              (when (>= xi pos) (return nil))
              (setq xsum (logxor xsum (aref native-bytes xi)))
              (setq xi (+ xi 1)))
            (write-char-serial 88) (write-char-serial 79) ;; XO
            (write-char-serial 82) (write-char-serial 58) ;; R:
            (print-dec xsum) (write-char-serial 10))
          ;; Assemble Gen1 x64 image
          (td-assemble-gen1 result bc ft))
        pos))))

;;; Build AArch64 target from x64 host (cross-arch)
(defun build-aarch64-from-x64 (bc ft)
  ;; Set AArch64 serial config for fixpoint (UART at VA 0x20000000, PL011 byte-width)
  (setq *aarch64-serial-base* #x20000000)
  (setq *aarch64-serial-width* 0)
  (setq *aarch64-serial-tx-poll* nil)
  (setq *aarch64-sched-lock-addr* nil)
  (let ((result (translate-mvm-to-aarch64 bc ft)))
    ;; result is (cons native-bytes (cons native-size fn-map))
    (let ((native-bytes (car result))
          (native-size (car (cdr result))))
      (print-dec native-size) (write-char-serial 10)
      ;; FNV-1a of AArch64 native code
      (let ((hash (td-fnv-native native-bytes native-size)))
        (write-char-serial 70) (write-char-serial 78) ;; FN
        (write-char-serial 86) (write-char-serial 58) ;; V:
        (print-dec hash) (write-char-serial 10))
      ;; Assemble Gen1 AArch64 image
      (td-assemble-gen1-aarch64 result bc ft)
      native-size)))

;;; Build x64 target from AArch64 host (cross-arch return trip)
(defun build-x64-from-aarch64 (bc ft)
  (let ((result (translate-mvm-to-x64 bc ft)))
    (let ((buf (car result)))
      (let ((pos (code-buffer-position buf)))
        (print-dec pos) (write-char-serial 10)
        (let ((native-bytes (code-buffer-bytes buf)))
          (let ((hash (td-fnv-native native-bytes pos)))
            (write-char-serial 70) (write-char-serial 78)
            (write-char-serial 86) (write-char-serial 58)
            (print-dec hash) (write-char-serial 10))
          ;; Print bytes at key positions for comparison
          (td-print-bytes-at native-bytes pos 0 16)
          (td-print-bytes-at native-bytes pos 5000 16)
          (td-print-bytes-at native-bytes pos 50000 16)
          (td-print-bytes-at native-bytes pos 100000 16)
          (td-print-bytes-at native-bytes pos 200000 16)
          (td-print-bytes-at native-bytes pos 250000 16)
          (td-print-bytes-at native-bytes pos 270000 16)
          (td-print-bytes-at native-bytes pos 280000 16)
          (td-print-bytes-at native-bytes pos 285000 16)
          (td-print-bytes-at native-bytes pos 290000 16)
          ;; Segment XOR: print XOR of each 10000-byte segment
          (let ((seg 0) (seg-size 10000))
            (loop
              (let ((seg-start (* seg seg-size)))
                (when (>= seg-start pos) (return nil))
                (let ((seg-end (+ seg-start seg-size))
                      (sxor 0) (si seg-start))
                  (when (> seg-end pos) (setq seg-end pos))
                  (loop
                    (when (>= si seg-end) (return nil))
                    (setq sxor (logxor sxor (aref native-bytes si)))
                    (setq si (+ si 1)))
                  (write-char-serial 83) ;; S
                  (print-dec seg) (write-char-serial 61) ;; =
                  (print-dec sxor) (write-char-serial 32)))
              (setq seg (+ seg 1))))
          (write-char-serial 10)
          ;; Assemble using the cross-arch x64 assembler
          (td-assemble-gen1-x64 result bc ft))
        pos))))

(defun build-image-cross (target)
  ;; target: 0=x64, 1=aarch64
  ;; Step 1: Read embedded bytecode
  (write-char-serial 83) (write-char-serial 49) (write-char-serial 58)
  (let ((bc (td-read-bytecode)))
    (print-dec (array-length bc))
    (write-char-serial 10)
    ;; XOR checksum of bytecode
    (write-char-serial 88) ;; X
    (let ((xsum 0) (xi 0))
      (loop
        (when (>= xi (array-length bc)) (return nil))
        (setq xsum (logxor xsum (aref bc xi)))
        (setq xi (+ xi 1)))
      (print-dec xsum))
    (write-char-serial 10)
    ;; Step 2: Read function table
    (write-char-serial 83) (write-char-serial 50) (write-char-serial 58)
    (let ((ft (td-read-fn-table-list)))
      (print-dec (length ft))
      (write-char-serial 10)
      ;; Step 3: Translate and assemble based on target
      (write-char-serial 83) (write-char-serial 51) (write-char-serial 58)
      (write-char-serial 10)
      (let ((my-arch (td-read-u32 #x380008)))
        ;; Dispatch: target 0=x64, 1=aarch64, 2=i386
        (cond
          ((= my-arch 2)
           ;; Running on i386
           (cond
             ((= target 2) (build-i386-from-i386 bc ft))
             ((zerop target) (build-x64-from-i386 bc ft))
             (t (build-aarch64-from-i386 bc ft))))
          ((= target 2)
           ;; i386 target (from x64 or aarch64 host)
           (if (zerop my-arch)
               (build-i386-from-x64 bc ft)
               (build-i386-from-aarch64 bc ft)))
          ((zerop my-arch)
           ;; Running on x64
           (if (zerop target)
               (build-x64-from-x64 bc ft)
               (build-aarch64-from-x64 bc ft)))
          (t
           ;; Running on AArch64
           (if (zerop target)
               (build-x64-from-aarch64 bc ft)
               (build-x64-from-x64 bc ft)))))
      ;; Print DONE marker for host script
      (write-char-serial 68) (write-char-serial 79) ;; DO
      (write-char-serial 78) (write-char-serial 69) ;; NE
      (write-char-serial 10))))

;;; ============================================================
;;; AArch64 translator overrides (bare-metal compatible)
;;; ============================================================

;;; Override a64-resolve-fixups: no destructuring-bind or ecase
(defun a64-resolve-fixups (buf)
  (let ((code (a64-buffer-code buf))
        (rest-fixups (a64-buffer-fixups buf))
        (fix-b 0) (fix-bl 0) (fix-bcond 0) (fix-adr 0) (fix-skip 0) (fix-miss 0))
    (loop
      (when (null rest-fixups) (return nil))
      (let ((fixup (car rest-fixups)))
        (let ((index (car fixup))
              (label-id (car (cdr fixup)))
              (type (car (cdr (cdr fixup)))))
          (let ((target (gethash label-id (a64-buffer-labels buf))))
            (if target
              (let ((offset (- target index)))
                (let ((word (aref code index)))
                  (cond
                    ;; :b (name-hash 126943983357610533) and :bl (592037923804208769)
                    ;; Both use imm26 encoding
                    ((eql type 126943983357610533)
                     (setq fix-b (+ fix-b 1))
                     (aset code index
                           (logior (logand word #xFC000000)
                                   (logand offset #x3FFFFFF))))
                    ((eql type 592037923804208769)
                     (setq fix-bl (+ fix-bl 1))
                     (aset code index
                           (logior (logand word #xFC000000)
                                   (logand offset #x3FFFFFF))))
                    ;; :bcond (name-hash 248172622495451147)
                    ;; Reconstruct from scratch to avoid bit4 tagging issue
                    ((eql type 248172622495451147)
                     (setq fix-bcond (+ fix-bcond 1))
                     (let ((cond-bits (logand word #xF)))
                       (let ((new-word (logior (ash #b01010100 24)
                                              (logior (ash (logand offset #x7FFFF) 5)
                                                      cond-bits))))
                         ;; Check for bad bit4: write to scratch and check
                         (setf (mem-ref #x380078 :u64) new-word)
                         (let ((check-b0 (mem-ref #x380078 :u8)))
                           (when (not (zerop (logand check-b0 #x20)))
                             (when (<= fix-bcond 5)
                               (write-char-serial 33) ;; !
                               (write-char-serial 105) ;; i
                               (print-dec index) (write-char-serial 32)
                               (write-char-serial 111) ;; o
                               (print-dec offset) (write-char-serial 32)
                               (write-char-serial 99) ;; c
                               (print-dec cond-bits) (write-char-serial 32)
                               (write-char-serial 119) ;; w
                               (print-dec new-word) (write-char-serial 10))))
                         (aset code index new-word))))
                    ;; :adr (name-hash 782868907041998776)
                    ((eql type 782868907041998776)
                     (setq fix-adr (+ fix-adr 1))
                     (let ((byte-off (* offset 4)))
                       (let ((immlo (logand byte-off 3)))
                         (let ((immhi (logand (ash byte-off -2) #x7FFFF)))
                           (let ((rd (logand word 31)))
                             ;; Use nested 2-arg logior (bare-metal 4-arg logior is broken)
                             (let ((hi (logior (ash immlo 29) (ash 16 24))))
                               (let ((lo (logior (ash immhi 5) rd)))
                                 (aset code index
                                       (logior hi lo)))))))))
                    (t (setq fix-miss (+ fix-miss 1))))))
              (setq fix-skip (+ fix-skip 1))))))
      (setq rest-fixups (cdr rest-fixups)))
    ;; Print fixup stats
    (write-char-serial 102) ;; f
    (write-char-serial 98)  ;; b
    (print-dec fix-b) (write-char-serial 10)
    (write-char-serial 102) ;; f
    (write-char-serial 108) ;; l
    (print-dec fix-bl) (write-char-serial 10)
    (write-char-serial 102) ;; f
    (write-char-serial 99)  ;; c
    (print-dec fix-bcond) (write-char-serial 10)
    (write-char-serial 102) ;; f
    (write-char-serial 97)  ;; a
    (print-dec fix-adr) (write-char-serial 10)
    (write-char-serial 102) ;; f
    (write-char-serial 115) ;; s (skip - no label)
    (print-dec fix-skip) (write-char-serial 10)
    (write-char-serial 102) ;; f
    (write-char-serial 109) ;; m (miss - no type match)
    (print-dec fix-miss) (write-char-serial 10))
  buf)

;;; ============================================================
;;; Bare-metal overrides for AArch64 encoder functions
;;; These handle callers that pass fewer args (missing keyword values
;;; that were stripped by preprocessing — use null defaults)
;;; ============================================================

;;; --- RET: override to hardcode x30 (avoids &optional call-site bug) ---
;;; The original a64-ret has &optional rn which becomes a 2-param function
;;; but call sites pass only buf. This 1-param override avoids the mismatch.
(defun a64-ret (buf)
  (a64-emit buf (logior #xD65F0000 (ash 30 5))))

;;; --- MOV instructions (null-safe hw) ---
(defun a64-movz (buf rd imm16 hw)
  (when (null hw) (setq hw 0))
  (a64-emit buf (logior (ash 1 31) (ash #b10 29) (ash #b100101 23)
                        (ash (logand hw 3) 21) (ash (logand imm16 65535) 5) rd)))

(defun a64-movk (buf rd imm16 hw)
  (when (null hw) (setq hw 0))
  (a64-emit buf (logior (ash 1 31) (ash #b11 29) (ash #b100101 23)
                        (ash (logand hw 3) 21) (ash (logand imm16 65535) 5) rd)))

(defun a64-movn (buf rd imm16 hw)
  (when (null hw) (setq hw 0))
  (a64-emit buf (logior (ash 1 31) (ash #b00 29) (ash #b100101 23)
                        (ash (logand hw 3) 21) (ash (logand imm16 65535) 5) rd)))

;;; --- ADD/SUB immediate (null-safe shift) ---
(defun a64-add-imm (buf rd rn imm12 shift)
  (when (null shift) (setq shift 0))
  (let ((sh (if (= shift 12) 1 0)))
    (a64-emit buf (logior (ash 1 31) (ash #b100010 23) (ash sh 22)
                          (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64-adds-imm (buf rd rn imm12 shift)
  (when (null shift) (setq shift 0))
  (let ((sh (if (= shift 12) 1 0)))
    (a64-emit buf (logior (ash 1 31) (ash 1 29) (ash #b100010 23) (ash sh 22)
                          (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64-sub-imm (buf rd rn imm12 shift)
  (when (null shift) (setq shift 0))
  (let ((sh (if (= shift 12) 1 0)))
    (a64-emit buf (logior (ash 1 31) (ash 1 30) (ash #b100010 23) (ash sh 22)
                          (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64-subs-imm (buf rd rn imm12 shift)
  (when (null shift) (setq shift 0))
  (let ((sh (if (= shift 12) 1 0)))
    (a64-emit buf (logior (ash 1 31) (ash 1 30) (ash 1 29) (ash #b100010 23)
                          (ash sh 22) (ash (logand imm12 4095) 10) (ash rn 5) rd))))

;;; --- ADD/SUB register (null-safe shift/amount) ---
(defun a64-add-reg (buf rd rn rm shift amount)
  (when (null shift) (setq shift 0))
  (when (null amount) (setq amount 0))
  (a64-emit buf (logior (ash 1 31) (ash #b01011 24)
                        (ash (logand shift 3) 22) (ash rm 16)
                        (ash amount 10) (ash rn 5) rd)))

(defun a64-adds-reg (buf rd rn rm shift amount)
  (when (null shift) (setq shift 0))
  (when (null amount) (setq amount 0))
  (a64-emit buf (logior (ash 1 31) (ash 1 29) (ash #b01011 24)
                        (ash (logand shift 3) 22) (ash rm 16)
                        (ash amount 10) (ash rn 5) rd)))

(defun a64-sub-reg (buf rd rn rm shift amount)
  (when (null shift) (setq shift 0))
  (when (null amount) (setq amount 0))
  (a64-emit buf (logior (ash 1 31) (ash 1 30) (ash #b01011 24)
                        (ash (logand shift 3) 22) (ash rm 16)
                        (ash amount 10) (ash rn 5) rd)))

(defun a64-subs-reg (buf rd rn rm shift amount)
  (when (null shift) (setq shift 0))
  (when (null amount) (setq amount 0))
  (a64-emit buf (logior (ash 1 31) (ash 1 30) (ash 1 29) (ash #b01011 24)
                        (ash (logand shift 3) 22) (ash rm 16)
                        (ash amount 10) (ash rn 5) rd)))

(defun a64-cmp-reg (buf rn rm)
  (a64-subs-reg buf 31 rn rm 0 0))

;;; --- DMB/DSB (null-safe option) ---
(defun a64-dmb (buf option)
  (when (null option) (setq option 11))
  (a64-emit buf (logior #xD5033000 (ash (logand option 15) 8) #xBF)))

(defun a64-dsb (buf option)
  (when (null option) (setq option 11))
  (a64-emit buf (logior #xD5033000 (ash (logand option 15) 8) #x9F)))

;;; --- a64-load-imm64: bare-metal compatible (no list/remove-if/lambda) ---
(defun a64-load-imm64 (buf rd imm64)
  (let ((hw0 (logand imm64 65535))
        (hw1 (logand (ash imm64 -16) 65535))
        (hw2 (logand (ash imm64 -32) 65535))
        (hw3 (logand (ash imm64 -48) 65535)))
    (let ((nz 0) (first-nz-idx 0))
      (when (> hw0 0) (setq nz (+ nz 1)) (setq first-nz-idx 0))
      (when (> hw1 0) (setq nz (+ nz 1)) (when (= nz 1) (setq first-nz-idx 1)))
      (when (> hw2 0) (setq nz (+ nz 1)) (when (= nz 1) (setq first-nz-idx 2)))
      (when (> hw3 0) (setq nz (+ nz 1)) (when (= nz 1) (setq first-nz-idx 3)))
      (cond
        ((= nz 0) (a64-movz buf rd 0 0))
        ((= nz 1)
         (let ((val 0))
           (cond ((> hw0 0) (setq val hw0) (setq first-nz-idx 0))
                 ((> hw1 0) (setq val hw1) (setq first-nz-idx 1))
                 ((> hw2 0) (setq val hw2) (setq first-nz-idx 2))
                 ((> hw3 0) (setq val hw3) (setq first-nz-idx 3)))
           (a64-movz buf rd val first-nz-idx)))
        (t
         (let ((did-first nil))
           (when (> hw0 0)
             (if did-first (a64-movk buf rd hw0 0)
                 (progn (a64-movz buf rd hw0 0) (setq did-first t))))
           (when (> hw1 0)
             (if did-first (a64-movk buf rd hw1 1)
                 (progn (a64-movz buf rd hw1 1) (setq did-first t))))
           (when (> hw2 0)
             (if did-first (a64-movk buf rd hw2 2)
                 (progn (a64-movz buf rd hw2 2) (setq did-first t))))
           (when (> hw3 0)
             (if did-first (a64-movk buf rd hw3 3)
                 (progn (a64-movz buf rd hw3 3) (setq did-first t))))))))))

;;; Override a64-emit-prologue for bare metal - direct instruction encoding
(defun a64-emit-prologue (buf)
  ;; STP x29, x30, [sp, #-80]!
  (a64-stp-pre buf 29 30 31 -80)
  ;; ADD x29, sp, #0 (no shift arg - avoid &key issue)
  (a64-emit buf (logior (ash 1 31) (ash #b100010 23) (ash 31 5) 29))
  ;; STP x19, x20, [sp, #16]
  (a64-stp-offset buf 19 20 31 16)
  ;; STP x21, x22, [sp, #32]
  (a64-stp-offset buf 21 22 31 32)
  ;; STP x23, xzr, [sp, #48]
  (a64-stp-offset buf 23 31 31 48)
  ;; SUB sp, sp, #1024 (no shift arg)
  (a64-emit buf (logior (ash 1 31) (ash 1 30) (ash #b100010 23) (ash 1024 10) (ash 31 5) 31)))

;;; Override a64-emit-epilogue for bare metal
(defun a64-emit-epilogue (buf)
  ;; ADD sp, sp, #1024 (no shift arg)
  (a64-emit buf (logior (ash 1 31) (ash #b100010 23) (ash 1024 10) (ash 31 5) 31))
  ;; LDP x23, xzr, [sp, #48]
  (a64-ldp-offset buf 23 31 31 48)
  ;; LDP x21, x22, [sp, #32]
  (a64-ldp-offset buf 21 22 31 32)
  ;; LDP x19, x20, [sp, #16]
  (a64-ldp-offset buf 19 20 31 16)
  ;; LDP x29, x30, [sp], #80
  (a64-ldp-post buf 29 30 31 80)
  ;; RET
  (a64-ret buf))

;;; Override a64-buffer-to-bytes: dotimes on bare metal returns nil (ignores
;;; result form), so the original function returns nil instead of the byte array.
;;; Use explicit loop with return.
(defun a64-buffer-to-bytes (buf)
  (let ((code (a64-buffer-code buf)))
    (let ((n (a64-buffer-position buf)))
      (let ((bytes (make-array (* n 4))))
        (let ((i 0))
          (loop
            (when (>= i n) (return bytes))
            (let ((w (aref code i)))
              (let ((base (* i 4)))
                (aset bytes base (logand w 255))
                (aset bytes (+ base 1) (logand (ash w -8) 255))
                (aset bytes (+ base 2) (logand (ash w -16) 255))
                (aset bytes (+ base 3) (logand (ash w -24) 255))))
            (setq i (+ i 1))))))))

;;; Closure fix: flet functions ensure-src and store-dst in translate-mvm-insn
;;; capture 'buf' from parent scope, but MVM compiler compiles them as separate
;;; global functions. The parent's V1 (buf) maps to their own V1 (scratch/vreg),
;;; so they read wrong values. Fix: store buf at memory address 0x300058.

(defun set-current-a64-buf (buf)
  (setf (mem-ref #x380058 :u64) buf))

(defun get-current-a64-buf ()
  (mem-ref #x380058 :u64))

;;; Override ensure-src: reads buf from fixed memory instead of broken closure
(defun ensure-src (vreg scratch)
  (let ((p (a64-phys-reg vreg)))
    (if p p
        (let ((buf (get-current-a64-buf)))
          (a64-emit-load-vreg buf scratch vreg)
          scratch))))

;;; Override store-dst: reads buf from fixed memory instead of broken closure
(defun store-dst (phys-src vreg)
  (let ((buf (get-current-a64-buf)))
    (a64-emit-store-vreg buf phys-src vreg)))

;;; AArch64 per-function translation helper
(defun td-a64-translate-fn-body (bytecode offset len buf mvm-to-native-label)
  ;; Store buf in fixed memory for ensure-src/store-dst closure fix
  (set-current-a64-buf buf)
  (let ((pos offset)
        (limit (+ offset len)))
    (loop
      (when (>= pos limit) (return nil))
      ;; Write diagnostic
      (td-write-u32 #x380048 pos)
      ;; Set label if this offset has one
      (let ((label (gethash pos mvm-to-native-label)))
        (when label
          (a64-set-label buf label)))
      ;; Decode instruction
      (let ((decoded (decode-instruction bytecode pos)))
        (let ((opcode (car decoded))
              (operands (car (cdr decoded)))
              (new-pos (cdr (cdr decoded))))
          (td-write-u32 #x38004C opcode)
          ;; Build a decoded-mvm-insn struct
          (let ((insn (make-decoded-mvm-insn)))
            (set-decoded-mvm-insn-offset insn pos)
            (set-decoded-mvm-insn-opcode insn opcode)
            (set-decoded-mvm-insn-operands insn operands)
            (set-decoded-mvm-insn-size insn (- new-pos pos))
            (translate-mvm-insn insn buf mvm-to-native-label))
          (setq pos new-pos))))))

;;; AArch64 branch target pre-scan
(defun td-a64-scan-branches (bytecode offset len mvm-to-native-label)
  (let ((pos offset)
        (limit (+ offset len)))
    (loop
      (when (>= pos limit) (return nil))
      (let ((decoded (decode-instruction bytecode pos)))
        (let ((opcode (car decoded))
              (operands (car (cdr decoded)))
              (new-pos (cdr (cdr decoded))))
          ;; Branch opcodes: #x40-#x48
          (when (>= opcode #x40)
            (when (<= opcode #x48)
              ;; BNULL(#x47)/BNNULL(#x48) have Vs first, offset second
              (let ((off-idx 0))
                (when (>= opcode #x47)
                  (setq off-idx 1))
                (let ((mvm-offset (nth off-idx operands)))
                  (let ((target-byte (+ pos (- new-pos pos) mvm-offset)))
                    (let ((existing (gethash target-byte mvm-to-native-label)))
                      (when (null existing)
                        (let ((lbl (gensym-label)))
                          (puthash target-byte mvm-to-native-label lbl)))))))))
          (setq pos new-pos))))))

;;; Helper: generate unique label ID using *mvm-label-counter*
(defun gensym-label ()
  (let ((v *mvm-label-counter*))
    (setq *mvm-label-counter* (+ v 1))
    v))

;;; Override translate-mvm-to-aarch64 for bare metal
;;; Same pattern as translate-mvm-to-x64 override: works with function-table list
;;; Returns (cons a64-buffer fn-map) where fn-map maps name-hash to native-byte-offset
(defun translate-mvm-to-aarch64 (bytecode function-table)
  (write-char-serial 97) (write-char-serial 54) (write-char-serial 52) ;; a64
  (write-char-serial 10)
  (let ((buf (make-a64-buffer)))
    (let ((n-functions (length function-table)))
      (print-dec n-functions) (write-char-serial 10)
      (let ((mvm-to-native-label (make-hash-table)))
        ;; First pass: register labels for all function entry points
        (let ((rest-ft function-table)
              (i 0))
          (loop
            (when (>= i n-functions) (return nil))
            (let ((entry (car rest-ft)))
              (let ((offset (car (cdr entry))))
                (let ((lbl (gensym-label)))
                  (puthash offset mvm-to-native-label lbl))))
            (setq rest-ft (cdr rest-ft))
            (setq i (+ i 1))))
        ;; Pre-scan ALL function bodies for branch targets
        (let ((rest-ft function-table)
              (i 0))
          (loop
            (when (>= i n-functions) (return nil))
            (let ((entry (car rest-ft)))
              (let ((offset (car (cdr entry)))
                    (len (car (cdr (cdr entry)))))
                (td-a64-scan-branches bytecode offset len mvm-to-native-label)))
            (setq rest-ft (cdr rest-ft))
            (setq i (+ i 1))))
        ;; Second pass: translate each function
        (write-char-serial 84) (write-char-serial 10) ;; T
        (let ((fn-map (make-hash-table)))
          (let ((rest-ft function-table)
                (i 0))
            (loop
              (when (>= i n-functions) (return nil))
              (td-write-u32 #x380040 i)
              (let ((entry (car rest-ft)))
                (let ((name (car entry))
                      (offset (car (cdr entry)))
                      (len (car (cdr (cdr entry)))))
                  ;; Set label at function entry
                  (let ((fn-label (gethash offset mvm-to-native-label)))
                    (when fn-label
                      (a64-set-label buf fn-label)))
                  ;; Record native byte offset for this function
                  (let ((native-off (* (a64-current-index buf) 4)))
                    (puthash name fn-map native-off))
                  ;; NOTE: No explicit prologue here — the TRAP instruction
                  ;; at function start triggers prologue via translate-mvm-insn
                  ;; Translate body
                  (td-a64-translate-fn-body bytecode offset len buf mvm-to-native-label)))
              (setq rest-ft (cdr rest-ft))
              (setq i (+ i 1))
              (when (zerop (mod i 50))
                (write-char-serial 35)
                (print-dec i)
                (write-char-serial 10))))
          ;; End-of-stream label
          (let ((end-label (gethash (array-length bytecode) mvm-to-native-label)))
            (when end-label
              (a64-set-label buf end-label)))
          ;; Resolve fixups
          (write-char-serial 82) (write-char-serial 10) ;; R
          (a64-resolve-fixups buf)
          (write-char-serial 68) (write-char-serial 10) ;; D
          ;; Return (cons buf fn-map)
          ;; Convert buffer to bytes for consistency
          (let ((native-bytes (a64-buffer-to-bytes buf)))
            ;; Diagnostic: scan byte array for B.cond (byte3=0x54)
            (let ((nb-len (array-length native-bytes))
                  (nb-good 0) (nb-bad 0) (nb-i 0))
              (loop
                (when (>= nb-i nb-len) (return nil))
                (let ((b3 (aref native-bytes (+ nb-i 3))))
                  (when (= b3 #x54)
                    (let ((b0 (aref native-bytes nb-i)))
                      (if (zerop (logand b0 #x10))
                          (setq nb-good (+ nb-good 1))
                          (let ((dummy (+ 0 0)))
                            (setq nb-bad (+ nb-bad 1))
                            (when (<= nb-bad 5)
                              (write-char-serial 88) ;; X
                              (print-dec nb-i) (write-char-serial 58)
                              (print-dec b0) (write-char-serial 44)
                              (print-dec b3) (write-char-serial 10)))))))
                (setq nb-i (+ nb-i 4)))
              (write-char-serial 71) ;; G
              (print-dec nb-good) (write-char-serial 10)
              (write-char-serial 66) ;; B
              (print-dec nb-bad) (write-char-serial 10))
            ;; Also check: scan code buffer (tagged words) for B.cond
            ;; Use a different approach: check if (aref code i) >> 25 (untagged) = 0x54
            ;; On tagged: ((tagged >> 1) >> 24) = hi byte. Check = 0x54.
            ;; We can compute: (ash (ash word -1) -24) but this is tricky with tagged values.
            ;; Instead, read the tagged word, write it to a scratch memory as u64,
            ;; then read byte 3 via u8.
            (let ((diag-code (a64-buffer-code buf))
                  (diag-n (a64-buffer-position buf))
                  (dg 0) (db 0) (di 0))
              (loop
                (when (>= di diag-n) (return nil))
                (let ((w (aref diag-code di)))
                  ;; Write tagged word to scratch address, read bytes
                  (setf (mem-ref #x380070 :u64) w)
                  ;; :u64 writes raw tagged bits. Now read byte 3 (bits [31:24] of tagged)
                  ;; Tagged = untagged << 1, so byte 3 of tagged is different from untagged.
                  ;; For untagged 0x54000001, tagged 0xA8000002:
                  ;; byte0=0x02, byte1=0x00, byte2=0x00, byte3=0xA8
                  ;; We want to check untagged byte3 = 0x54. That's tagged byte3 = 0xA8.
                  (let ((tb3 (mem-ref #x380073 :u8)))
                    (when (= tb3 #xA8)
                      ;; Check bit 4 of untagged byte0 = bit 5 of tagged byte0
                      (let ((tb0 (mem-ref #x380070 :u8)))
                        (if (zerop (logand tb0 #x20))
                            (setq dg (+ dg 1))
                            (let ((dummy2 (+ 0 0)))
                              (setq db (+ db 1))
                              (when (<= db 3)
                                (write-char-serial 67) ;; C (code buffer bad)
                                (print-dec di) (write-char-serial 58)
                                (print-dec tb0) (write-char-serial 10))))))))
                (setq di (+ di 1)))
              (write-char-serial 99) ;; g (code buffer good)
              (print-dec dg) (write-char-serial 10)
              (write-char-serial 98) ;; b (code buffer bad)
              (print-dec db) (write-char-serial 10))
            (let ((native-size (* (a64-current-index buf) 4)))
              (cons native-bytes (cons native-size fn-map)))))))))

;;; ============================================================
;;; AArch64 image assembly
;;; ============================================================

;;; Generate AArch64 boot preamble into image buffer
;;; Uses emit-aarch64-fixpoint-entry which writes into an mvm-buffer,
;;; then copies the bytes into the image.
(defun td-generate-aarch64-boot ()
  (let ((boot-buf (make-mvm-buffer)))
    (emit-aarch64-fixpoint-entry boot-buf)
    ;; Copy boot bytes into image
    (let ((boot-size (mvm-buffer-position boot-buf))
          (i 0))
      (loop
        (when (>= i boot-size) (return boot-size))
        (img-emit (aref (mvm-buffer-bytes boot-buf) i))
        (setq i (+ i 1))))))

;;; Assemble Gen1 AArch64 image from translated native code
;;; Image layout: [boot preamble 4096B] [native code at offset 0x1000] [bytecodes] [fn-table] [pad] [metadata at 0x380000]
(defun td-assemble-gen1-aarch64 (result bc ft)
  ;; result = (cons native-bytes (cons native-size fn-map))
  (let ((native-bytes (car result))
        (native-size (car (cdr result)))
        (fn-map (cdr (cdr result))))
    ;; 1. Init image buffer
    (img-init)
    (write-char-serial 65) (write-char-serial 49) ;; A1
    (write-char-serial 58) (write-char-serial 10)
    ;; 2. Generate AArch64 boot preamble (fills up to offset 0x1000)
    (let ((boot-size (td-generate-aarch64-boot)))
      (write-char-serial 80) ;; P
      (print-dec boot-size) (write-char-serial 10)
      ;; Pad to 0x1000 if needed (native code must start at instruction 1024 = offset 0x1000)
      (let ((pad-target #x1000))
        (loop
          (when (>= (img-pos) pad-target) (return nil))
          (img-emit 0)))
      ;; 3. Emit B instruction at 0x1000 to jump to kernel-main
      ;; The boot preamble branches to offset 0x1000 (instruction 1024).
      ;; We emit a B instruction here that jumps forward to kernel-main.
      (write-char-serial 75) ;; K
      (let ((km-hash (td-read-u32 #x380028)))
        (print-dec km-hash) (write-char-serial 10)
        (let ((km-native-off (gethash km-hash fn-map)))
          (write-char-serial 79) ;; O
          (if km-native-off
              (let ((dummy1 (print-dec km-native-off)))
                (write-char-serial 10)
                (let ((km-insn-offset (ash km-native-off -2)))
                  ;; B forward: offset = km_insn_offset + 1 (skip this B instruction)
                  (let ((b-offset (+ km-insn-offset 1)))
                    (write-char-serial 66) ;; B
                    (print-dec b-offset) (write-char-serial 10)
                    (let ((b-word (logior (ash #b000101 26)
                                          (logand b-offset #x3FFFFFF))))
                      (write-char-serial 87) ;; W
                      (print-dec b-word) (write-char-serial 10)
                      (write-char-serial 73) ;; I  img-pos before emit
                      (print-dec (img-pos)) (write-char-serial 10)
                      (img-emit-u32 b-word)
                      (write-char-serial 74) ;; J  img-pos after emit
                      (print-dec (img-pos)) (write-char-serial 10)))))
              ;; No kernel-main found — emit NOP (shouldn't happen)
              (let ((dummy2 0))
                (write-char-serial 33) (write-char-serial 10) ;; !
                (img-emit-u32 #xD503201F)))))
      ;; 4. Copy native code (starts at 0x1004)
      (write-char-serial 78) ;; N
      (td-write-u32 #x380050 (img-pos))
      (let ((i 0))
        (loop
          (when (>= i native-size) (return nil))
          (img-emit (aref native-bytes i))
          (setq i (+ i 1))
          (when (zerop (mod i 50000))
            (write-char-serial 46))))
      (write-char-serial 10)
      ;; 4. Append MVM bytecode
      (write-char-serial 84) ;; T
      (let ((bc-len (array-length bc))
            (bc-img-offset (img-pos)))
        (let ((bi 0))
          (loop
            (when (>= bi bc-len) (return nil))
            (img-emit (aref bc bi))
            (setq bi (+ bi 1))))
        ;; 5. Append function table (12-byte u32 LE entries)
        (let ((ft-img-offset (img-pos))
              (rest-ft ft)
              (ft-count 0))
          (loop
            (when (null rest-ft) (return nil))
            (let ((entry (car rest-ft)))
              (let ((name (car entry))
                    (offset (car (cdr entry)))
                    (len (car (cdr (cdr entry)))))
                (img-emit-u32 name)
                (img-emit-u32 offset)
                (img-emit-u32 len)))
            (setq rest-ft (cdr rest-ft))
            (setq ft-count (+ ft-count 1)))
          (write-char-serial 10)
          (print-dec ft-count) (write-char-serial 10)
          ;; 6. Write metadata at offset 0x300000
          ;; QEMU virt loads raw binary at PA 0x40080000 (not 0x40000000).
          ;; MMU maps VA = PA - 0x40000000, so image start VA = 0x80000.
          ;; Metadata VA must be 0x380000, so image offset = 0x380000 - 0x80000 = 0x300000.
          (let ((md-img-off #x300000))
            ;; magic MVMT
            (img-patch-u32 md-img-off #x544D564D)
            ;; version = 1
            (img-patch-u32 (+ md-img-off 4) 1)
            ;; my-architecture = 1 (aarch64)
            (img-patch-u32 (+ md-img-off 8) 1)
            ;; bytecode-offset
            (img-patch-u32 (+ md-img-off 12) bc-img-offset)
            ;; bytecode-length
            (img-patch-u32 (+ md-img-off 16) bc-len)
            ;; fn-table-offset
            (img-patch-u32 (+ md-img-off 20) ft-img-offset)
            ;; fn-table-count
            (img-patch-u32 (+ md-img-off 24) ft-count)
            ;; native-code-offset
            (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x380050))
            ;; native-code-length
            (img-patch-u32 (+ md-img-off 32) native-size)
            ;; preamble-size = 0x1000 (4096, AArch64 boot preamble)
            (img-patch-u32 (+ md-img-off 36) #x1000)
            ;; kernel-main-hash-lo (copy from running kernel)
            (let ((km-hash (td-read-u32 #x380028)))
              (img-patch-u32 (+ md-img-off 40) km-hash))
            ;; kernel-main native offset (look up in fn-map)
            (let ((km-native-off (gethash (td-read-u32 #x380028) fn-map)))
              (if km-native-off
                  (img-patch-u32 (+ md-img-off 44) km-native-off)
                  (img-patch-u32 (+ md-img-off 44) 0)))
            ;; image-load-addr: QEMU loads at PA 0x40080000.
            ;; MMU maps VA = PA - 0x40000000, so VA load-addr = 0x80000.
            (img-patch-u32 (+ md-img-off 48) #x80000)
            ;; target-architecture (default: 0=x64, overridden by host script)
            (img-patch-u32 (+ md-img-off 52) 0)
            ;; mode (default: 0=cross-compile, overridden by host script)
            (img-patch-u32 (+ md-img-off 56) 0))
          ;; Total size must cover metadata at 0x300000
          (let ((total-size (+ #x300000 64)))
            (write-char-serial 65) (write-char-serial 49) ;; A1
            (write-char-serial 61) ;; =
            (print-dec total-size) (write-char-serial 10)
            total-size))))))

;;; ============================================================
;;; x64 image assembly (from AArch64 Gen1 going back to x64)
;;; ============================================================

;;; Generate x64 boot preamble into image buffer
(defun td-generate-x64-boot ()
  (let ((boot-buf (make-mvm-buffer)))
    (emit-x64-multiboot-header boot-buf)
    (emit-x64-boot32 boot-buf)
    (emit-x64-kernel64-entry boot-buf)
    ;; Copy boot bytes into image
    (let ((boot-size (mvm-buffer-position boot-buf))
          (i 0))
      (loop
        (when (>= i boot-size) (return boot-size))
        (img-emit (aref (mvm-buffer-bytes boot-buf) i))
        (setq i (+ i 1))))))

;;; Assemble Gen1 x64 image (when running on AArch64)
(defun td-assemble-gen1-x64 (result bc ft)
  ;; result = (cons code-buffer fn-map) from translate-mvm-to-x64
  (let ((buf (car result))
        (fn-map (cdr result)))
    (let ((native-bytes (code-buffer-bytes buf))
          (native-size (code-buffer-position buf)))
      ;; 1. Init image buffer
      (img-init)
      (write-char-serial 88) (write-char-serial 49) ;; X1
      (write-char-serial 58) (write-char-serial 10)
      ;; 2. Generate x64 boot preamble
      (let ((boot-size (td-generate-x64-boot)))
        (write-char-serial 80) ;; P
        (print-dec boot-size) (write-char-serial 10)
        ;; 3. Emit JMP rel32 to kernel-main
        ;; Look up kernel-main native offset from fn-map
        (let ((km-hash (td-read-u32 #x380028)))
          (let ((km-label (gethash km-hash fn-map)))
            (let ((km-offset 0))
              (when km-label
                (setq km-offset (aref km-label 1)))
              ;; JMP rel32
              (img-emit #xE9)
              (img-emit-u32 km-offset))))
        ;; 4. Copy native code
        (write-char-serial 78) ;; N
        (td-write-u32 #x380050 (img-pos))
        (let ((i 0))
          (loop
            (when (>= i native-size) (return nil))
            (img-emit (aref native-bytes i))
            (setq i (+ i 1))
            (when (zerop (mod i 50000))
              (write-char-serial 46))))
        (write-char-serial 10)
        ;; 5. Append bytecodes
        (write-char-serial 84) ;; T
        (let ((bc-len (array-length bc))
              (bc-img-offset (img-pos)))
          (let ((bi 0))
            (loop
              (when (>= bi bc-len) (return nil))
              (img-emit (aref bc bi))
              (setq bi (+ bi 1))))
          ;; 6. Append function table (12-byte u32 LE entries)
          (let ((ft-img-offset (img-pos))
                (rest-ft ft)
                (ft-count 0))
            (loop
              (when (null rest-ft) (return nil))
              (let ((entry (car rest-ft)))
                (let ((name (car entry))
                      (offset (car (cdr entry)))
                      (len (car (cdr (cdr entry)))))
                  (img-emit-u32 name)
                  (img-emit-u32 offset)
                  (img-emit-u32 len)))
              (setq rest-ft (cdr rest-ft))
              (setq ft-count (+ ft-count 1)))
            (write-char-serial 10)
            (print-dec ft-count) (write-char-serial 10)
            ;; 7. Write metadata at offset 0x280000 (= VA 0x380000 for x64)
            (let ((md-img-off #x280000))
              ;; magic
              (img-patch-u32 md-img-off #x544D564D)
              (img-patch-u32 (+ md-img-off 4) 1)
              ;; my-architecture = 0 (x64)
              (img-patch-u32 (+ md-img-off 8) 0)
              (img-patch-u32 (+ md-img-off 12) bc-img-offset)
              (img-patch-u32 (+ md-img-off 16) bc-len)
              (img-patch-u32 (+ md-img-off 20) ft-img-offset)
              (img-patch-u32 (+ md-img-off 24) ft-count)
              (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x380050))
              (img-patch-u32 (+ md-img-off 32) native-size)
              (img-patch-u32 (+ md-img-off 36) boot-size)
              ;; kernel-main-hash-lo
              (let ((km-hash (td-read-u32 #x380028)))
                (img-patch-u32 (+ md-img-off 40) km-hash)
                ;; kernel-main-native-offset
                (let ((km-label (gethash km-hash fn-map)))
                  (if km-label
                      (img-patch-u32 (+ md-img-off 44) (aref km-label 1))
                      (img-patch-u32 (+ md-img-off 44) 0))))
              ;; image-load-addr = 0x100000 (x64)
              (img-patch-u32 (+ md-img-off 48) #x100000)
              ;; target-architecture (default: 1=aarch64, overridden by host script)
              (img-patch-u32 (+ md-img-off 52) 1)
              ;; mode (default: 0=cross-compile, overridden by host script)
              (img-patch-u32 (+ md-img-off 56) 0))
            ;; 8. Patch multiboot header
            (let ((total-size (+ #x280000 64)))
              (let ((load-end (+ #x100000 total-size)))
                (img-patch-u32 20 load-end)
                (img-patch-u32 24 load-end))
              (write-char-serial 88) (write-char-serial 49) ;; X1
              (write-char-serial 61) ;; =
              (print-dec total-size) (write-char-serial 10)
              total-size)))))))

;;; ============================================================
;;; i386 translator bare-metal overrides
;;; ============================================================

;;; Initialize *i386-vreg-map* (vector isn't available on bare metal)
(defun init-*i386-vreg-map* ()
  (setq *i386-vreg-map* (make-array 23))
  ;; V0=ESI(6), V1=EDI(7), V2=nil, V3=nil, V4=EBX(3)
  (aset *i386-vreg-map* 0 6)
  (aset *i386-vreg-map* 1 7)
  ;; V2-V3 = nil (default 0 = spill, checked via i386-vreg-phys)
  (aset *i386-vreg-map* 4 3)
  ;; V5-V15 = nil (spill) — default 0
  ;; VR=EAX(0) — index 16
  (aset *i386-vreg-map* 16 255)
  ;; VA(17), VL(18), VN(19) = nil (spill)
  ;; VSP=ESP(4) — index 20
  (aset *i386-vreg-map* 20 4)
  ;; VFP=EBP(5) — index 21
  (aset *i386-vreg-map* 21 5)
  ;; VPC(22) = nil
  *i386-vreg-map*)

;;; Fix: i386-vreg-phys needs to return nil for spilled regs, not 0.
;;; On bare metal, make-array initializes to 0, but 0=EAX is a valid phys reg.
;;; Override to explicitly check known mappings.
(defun i386-vreg-phys (vreg)
  (cond
    ((= vreg 0) 6)     ;; V0 = ESI
    ((= vreg 1) 7)     ;; V1 = EDI
    ((= vreg 4) 3)     ;; V4 = EBX
    ((= vreg 16) 0)    ;; VR = EAX
    ((= vreg 20) 4)    ;; VSP = ESP
    ((= vreg 21) 5)    ;; VFP = EBP
    (t nil)))

;;; Override i386-emit-jcc — assoc on *i386-cc-codes* doesn't work because
;;; keyword constants from defparameter are different objects than caller keywords.
;;; Use = on tagged name hashes instead.
(defun i386-emit-jcc (buf cc &optional label-id)
  (let ((code (cond
                ((= cc :e)  4)
                ((= cc :ne) 5)
                ((= cc :l)  12)
                ((= cc :ge) 13)
                ((= cc :le) 14)
                ((= cc :g)  15)
                ((= cc :b)  2)
                ((= cc :ae) 3)
                ((= cc :be) 6)
                ((= cc :a)  7)
                ((= cc :z)  4)
                ((= cc :nz) 5)
                ((= cc :s)  8)
                ((= cc :ns) 9)
                (t nil))))
    (when (null code)
      (write-char-serial 74) (write-char-serial 67) ;; JC
      (write-char-serial 67) (write-char-serial 33) ;; C!
      (print-dec cc) (write-char-serial 10)
      (error 99))
    (i386-emit-byte buf 15)
    (i386-emit-byte buf (+ 128 code))
    (if label-id
        (i386-emit-fixup-rel32 buf label-id)
        (i386-emit-u32 buf 0))))

;;; Helper: translate one instruction, reducing nesting depth in main loop
;;; Helper: translate one instruction.
;;; Saves new-pos to 0x300060 for caller (avoids AArch64 return-value clobber).
;;; Handles common opcodes inline to avoid deep cond dispatch in i386-translate-insn.
;;; Emit a LI immediate by reading 4 raw bytes from bytecodes directly.
;;; This avoids decode-u32 which loses bit 31 on i386 (fixnum-shift=1).
(defun i386-emit-raw-imm32 (buf bytecode imm-pos)
  (i386-emit-byte buf (aref bytecode imm-pos))
  (i386-emit-byte buf (aref bytecode (+ imm-pos 1)))
  (i386-emit-byte buf (aref bytecode (+ imm-pos 2)))
  (i386-emit-byte buf (aref bytecode (+ imm-pos 3))))

;;; Handle LI opcode with raw byte emission (i386 fixnum-safe).
;;; LI bytecode format: [opcode:1][reg:1][imm64:8] = 10 bytes total.
(defun i386-translate-li-raw (buf state bytecode pos)
  (let ((new-pos (+ pos 10)))
    (td-write-u32 #x380060 new-pos)
    (let ((label (gethash pos (i386-translate-state-label-map state))))
      (when label
        (i386-emit-label buf label)))
    (td-write-u32 #x38004C 17)
    (td-write-u32 #x380048 pos)
    (let ((vd (logand (aref bytecode (+ pos 1)) 31)))
      (let ((imm-pos (+ pos 2)))
        (cond
          ((i386-has-phys vd)
           ;; MOV physical-reg, imm32: opcode B8+reg, then 4 LE bytes
           (i386-emit-byte buf (+ 184 (i386-vreg-phys vd)))
           (i386-emit-raw-imm32 buf bytecode imm-pos))
          ((i386-vreg-abs-addr vd)
           ;; MOV scratch0(ECX), imm32; then MOV [abs-addr], ECX
           (let ((abs-addr (i386-vreg-abs-addr vd)))
             (i386-emit-byte buf (+ 184 1))  ;; B8+ECX
             (i386-emit-raw-imm32 buf bytecode imm-pos)
             (i386-emit-mov-abs-reg buf abs-addr 1)))
          (t
           ;; MOV DWORD [EBP + spill-offset], imm32
           (i386-emit-byte buf 199)  ;; C7 opcode
           (i386-emit-modrm-mem buf 0 5 (i386-spill-offset vd))
           (i386-emit-raw-imm32 buf bytecode imm-pos)))))
    new-pos))

(defun i386-translate-one-insn (buf state bytecode pos)
  ;; Check for LI opcode (0x11 = 17): handle with raw byte emission
  ;; to avoid decode-u32 overflow on i386 (fixnum-shift=1 loses bit 31)
  (if (= (aref bytecode pos) 17)
      (i386-translate-li-raw buf state bytecode pos)
      ;; All other opcodes: normal decode path
      (let ((decoded (decode-instruction bytecode pos)))
        (let ((new-pos (cdr (cdr decoded))))
          (td-write-u32 #x380060 new-pos)
          (let ((label (gethash pos (i386-translate-state-label-map state))))
            (when label
              (i386-emit-label buf label)))
          (let ((opcode (car decoded)))
            (let ((operands (car (cdr decoded))))
              (td-write-u32 #x38004C opcode)
              (td-write-u32 #x380048 pos)
              (i386-translate-insn state opcode operands new-pos)))
          new-pos))))

;;; Progressive i386-translate-insn override for AArch64 bisection
;;; Group A: NOP/BREAK/TRAP + data movement + arithmetic + bitwise + comparison
;;; Group B: branches
;;; Group C: list ops + object ops + memory + call/ret + alloc + IO
;;; Unknown opcodes → NOP (safe fallback)
(defun i386-translate-insn (state opcode operands mvm-next-pos)
  (let ((buf (i386-translate-state-buf state)))
    (cond
      ;; === NOP/BREAK ===
      ((= opcode 0) (i386-emit-nop buf))
      ((= opcode 1) (i386-emit-int3 buf))

      ;; === TRAP (#x02) ===
      ((= opcode 2)
       (let ((code (first operands)))
         (cond
           ((< code 256)
            ;; Frame-enter: code = nparams.
            ;; If nparams > 4, copy overflow args from caller's stack to local frame slots.
            ;; Overflow args at [EBP+16+k*4], frame slot N at [EBP + (-68) + N*(-4)].
            (when (> code 4)
              (let ((param-idx 4))
                (loop
                  (when (>= param-idx code) (return nil))
                  (let ((k (- param-idx 4)))
                    (let ((src-off (+ 16 (* k 4))))
                      (let ((dst-off (+ -68 (* param-idx -4))))
                        (i386-emit-mov-reg-mem buf 1 5 src-off)
                        (i386-emit-mov-mem-reg buf 5 dst-off 1))))
                  (setq param-idx (+ param-idx 1))))))
           ((< code 768) nil)
           ((= code 768)
            (let ((poll-label (i386-make-label)))
              (i386-emit-byte buf 102) (i386-emit-byte buf 186)
              (i386-emit-byte buf 253) (i386-emit-byte buf 3)
              (i386-emit-label buf poll-label)
              (i386-emit-byte buf 236)
              (i386-emit-byte buf 168) (i386-emit-byte buf 32)
              (i386-emit-jcc buf :z poll-label))
            (i386-emit-byte buf 137) (i386-emit-byte buf 240)
            (i386-emit-byte buf 209) (i386-emit-byte buf 248)
            (i386-emit-byte buf 102) (i386-emit-byte buf 186)
            (i386-emit-byte buf 248) (i386-emit-byte buf 3)
            (i386-emit-byte buf 238))
           ((= code 769)
            (let ((poll-label (i386-make-label)))
              (i386-emit-byte buf 102) (i386-emit-byte buf 186)
              (i386-emit-byte buf 253) (i386-emit-byte buf 3)
              (i386-emit-label buf poll-label)
              (i386-emit-byte buf 236)
              (i386-emit-byte buf 168) (i386-emit-byte buf 1)
              (i386-emit-jcc buf :z poll-label))
            (i386-emit-byte buf 102) (i386-emit-byte buf 186)
            (i386-emit-byte buf 248) (i386-emit-byte buf 3)
            (i386-emit-byte buf 236)
            (i386-emit-byte buf 15) (i386-emit-byte buf 182) (i386-emit-byte buf 192)
            (i386-emit-byte buf 209) (i386-emit-byte buf 224)
            (i386-emit-byte buf 137) (i386-emit-byte buf 198))
           (t nil))))

      ;; === MOV (#x10) ===
      ((= opcode 16)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 1 vs)
         (i386-store-vreg buf vd 1)))

      ;; === LI (#x11) ===
      ((= opcode 17)
       (let ((vd (first operands))
             (imm (logand (second operands) 4294967295)))
         (cond
           ((i386-has-phys vd)
            (i386-emit-mov-reg-imm buf (i386-vreg-phys vd) imm))
           ((i386-vreg-abs-addr vd)
            (let ((abs (i386-vreg-abs-addr vd)))
              (i386-emit-mov-reg-imm buf 1 imm)
              (i386-emit-mov-abs-reg buf abs 1)))
           (t (i386-emit-mov-mem-imm buf 5 (i386-spill-offset vd) imm)))))

      ;; === PUSH (#x12) ===
      ((= opcode 18)
       (let ((vs (first operands)))
         (cond
           ((i386-has-phys vs) (i386-emit-push-reg buf (i386-vreg-phys vs)))
           ((i386-vreg-abs-addr vs) (i386-emit-push-abs buf (i386-vreg-abs-addr vs)))
           (t (i386-emit-push-mem buf 5 (i386-spill-offset vs))))))

      ;; === POP (#x13) ===
      ((= opcode 19)
       (let ((vd (first operands)))
         (if (i386-has-phys vd)
             (i386-emit-pop-reg buf (i386-vreg-phys vd))
             (progn
               (i386-emit-pop-reg buf 1)
               (i386-store-vreg buf vd 1)))))

      ;; === ADD (#x20) ===
      ((= opcode 32)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-add-reg-reg buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === SUB (#x21) ===
      ((= opcode 33)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-sub-reg-reg buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === MUL (#x22) ===
      ((= opcode 34)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-sar-reg-imm buf 0 1)
         (i386-emit-imul-reg-reg buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === DIV (#x23) ===
      ((= opcode 35)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-emit-sar-reg-imm buf 1 1)
         (i386-load-vreg buf 0 va)
         (i386-emit-sar-reg-imm buf 0 1)
         (i386-emit-cdq buf)
         (i386-emit-idiv-reg buf 1)
         (i386-emit-shl-reg-imm buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === MOD (#x24) ===
      ((= opcode 36)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-emit-sar-reg-imm buf 1 1)
         (i386-load-vreg buf 0 va)
         (i386-emit-sar-reg-imm buf 0 1)
         (i386-emit-cdq buf)
         (i386-emit-idiv-reg buf 1)
         (i386-emit-shl-reg-imm buf 2 1)
         (i386-store-vreg buf vd 2)))

      ;; === NEG (#x25) ===
      ((= opcode 37)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-neg-reg buf 0)
         (i386-store-vreg buf vd 0)))

      ;; === INC (#x26) ===
      ((= opcode 38)
       (let ((vd (first operands)))
         (if (i386-has-phys vd)
             (i386-emit-add-reg-imm buf (i386-vreg-phys vd) 2)
             (progn
               (i386-load-vreg buf 0 vd)
               (i386-emit-add-reg-imm buf 0 2)
               (i386-store-vreg buf vd 0)))))

      ;; === DEC (#x27) ===
      ((= opcode 39)
       (let ((vd (first operands)))
         (if (i386-has-phys vd)
             (i386-emit-sub-reg-imm buf (i386-vreg-phys vd) 2)
             (progn
               (i386-load-vreg buf 0 vd)
               (i386-emit-sub-reg-imm buf 0 2)
               (i386-store-vreg buf vd 0)))))

      ;; === AND (#x28) ===
      ((= opcode 40)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-and-reg-reg buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === OR (#x29) ===
      ((= opcode 41)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-or-reg-reg buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === XOR (#x2A) ===
      ((= opcode 42)
       (let ((vd (first operands)) (va (second operands)) (vb (third operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-xor-reg-reg buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === SHL (#x2B) ===
      ((= opcode 43)
       (let ((vd (first operands)) (vs (second operands)) (amt (third operands)))
         (i386-load-vreg buf 1 vs)
         (i386-emit-shl-reg-imm buf 1 amt)
         (i386-store-vreg buf vd 1)))

      ;; === SHR (#x2C) ===
      ((= opcode 44)
       (let ((vd (first operands)) (vs (second operands)) (amt (third operands)))
         (i386-load-vreg buf 1 vs)
         (i386-emit-shr-reg-imm buf 1 amt)
         (i386-store-vreg buf vd 1)))

      ;; === SAR (#x2D) ===
      ((= opcode 45)
       (let ((vd (first operands)) (vs (second operands)) (amt (third operands)))
         (i386-load-vreg buf 1 vs)
         (i386-emit-sar-reg-imm buf 1 amt)
         (i386-store-vreg buf vd 1)))

      ;; === LDB (#x2E) ===
      ((= opcode 46)
       (let ((vd (first operands)) (vs (second operands))
             (pos (third operands)) (size (fourth operands)))
         (i386-load-vreg buf 0 vs)
         (when (> pos 0)
           (i386-emit-shr-reg-imm buf 0 pos))
         (i386-emit-and-reg-imm buf 0 (logand (- (ash 1 size) 1) 4294967295))
         (i386-store-vreg buf vd 0)))

      ;; === SHLV (#x2F) ===
      ((= opcode 47)
       (let ((vd (first operands)) (vs (second operands)) (vc (third operands)))
         (i386-load-vreg buf 1 vc)
         (i386-load-vreg buf 0 vs)
         (i386-emit-shl-reg-cl buf 0)
         (i386-store-vreg buf vd 0)))

      ;; === CMP (#x30) ===
      ((= opcode 48)
       (let ((va (first operands)) (vb (second operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-cmp-reg-reg buf 0 1)))

      ;; === TEST (#x31) ===
      ((= opcode 49)
       (let ((va (first operands)) (vb (second operands)))
         (i386-load-vreg buf 1 vb)
         (i386-load-vreg buf 0 va)
         (i386-emit-test-reg-reg buf 0 1)))

      ;; === SARV (#x32) ===
      ((= opcode 50)
       (let ((vd (first operands)) (vs (second operands)) (vc (third operands)))
         (i386-load-vreg buf 1 vc)
         (i386-load-vreg buf 0 vs)
         (i386-emit-sar-reg-cl buf 0)
         (i386-store-vreg buf vd 0)))

      ;; === BRANCHES (#x40-#x48) ===
      ((= opcode 64)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jmp-rel32 buf label)))))
      ((= opcode 65)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jcc buf :e label)))))
      ((= opcode 66)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jcc buf :ne label)))))
      ((= opcode 67)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jcc buf :l label)))))
      ((= opcode 68)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jcc buf :ge label)))))
      ((= opcode 69)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jcc buf :le label)))))
      ((= opcode 70)
       (let ((off (first operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-emit-jcc buf :g label)))))

      ;; === BNULL (#x47) ===
      ((= opcode 71)
       (let ((vs (first operands)) (off (second operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-load-vreg buf 0 vs)
             (i386-emit-cmp-reg-abs buf 0 1544)
             (i386-emit-jcc buf :e label)))))

      ;; === BNNULL (#x48) ===
      ((= opcode 72)
       (let ((vs (first operands)) (off (second operands)))
         (let ((target-pos (+ mvm-next-pos off)))
           (let ((label (i386-ensure-label-at state target-pos)))
             (i386-load-vreg buf 0 vs)
             (i386-emit-cmp-reg-abs buf 0 1544)
             (i386-emit-jcc buf :ne label)))))

      ;; === CAR (#x50) ===
      ((= opcode 80)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-sub-reg-imm buf 0 1)
         (i386-emit-mov-reg-mem buf 0 0 0)
         (i386-store-vreg buf vd 0)))

      ;; === CDR (#x51) ===
      ((= opcode 81)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-sub-reg-imm buf 0 1)
         (i386-emit-mov-reg-mem buf 0 0 4)
         (i386-store-vreg buf vd 0)))

      ;; === CONS (#x52) ===
      ((= opcode 82)
       (let ((vd (first operands)) (va-arg (second operands)) (vb-arg (third operands)))
         (i386-load-vreg buf 1 vb-arg)
         (i386-emit-mov-reg-abs buf 2 1536)
         (i386-load-vreg buf 0 va-arg)
         (i386-emit-mov-mem-reg buf 2 0 0)
         (i386-emit-mov-mem-reg buf 2 4 1)
         (i386-emit-mov-reg-reg buf 0 2)
         (i386-emit-or-reg-imm buf 0 1)
         (i386-emit-add-reg-imm buf 2 16)
         (i386-emit-mov-abs-reg buf 1536 2)
         (i386-store-vreg buf vd 0)))

      ;; === SETCAR (#x53) ===
      ((= opcode 83)
       (let ((vd-reg (first operands)) (vs (second operands)))
         (i386-load-vreg buf 1 vs)
         (i386-load-vreg buf 0 vd-reg)
         (i386-emit-sub-reg-imm buf 0 1)
         (i386-emit-mov-mem-reg buf 0 0 1)))

      ;; === SETCDR (#x54) ===
      ((= opcode 84)
       (let ((vd-reg (first operands)) (vs (second operands)))
         (i386-load-vreg buf 1 vs)
         (i386-load-vreg buf 0 vd-reg)
         (i386-emit-sub-reg-imm buf 0 1)
         (i386-emit-mov-mem-reg buf 0 4 1)))

      ;; === CONSP (#x55) ===
      ((= opcode 85)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-and-reg-imm buf 0 15)
         (i386-emit-cmp-reg-imm buf 0 1)
         (let ((true-label (i386-make-label))
               (done-label (i386-make-label)))
           (i386-emit-jcc buf :e true-label)
           (i386-emit-mov-reg-abs buf 0 1544)
           (i386-emit-jmp-rel32 buf done-label)
           (i386-emit-label buf true-label)
           (i386-emit-mov-reg-imm buf 0 262)
           (i386-emit-label buf done-label))
         (i386-store-vreg buf vd 0)))

      ;; === ATOM (#x56) ===
      ((= opcode 86)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-and-reg-imm buf 0 15)
         (i386-emit-cmp-reg-imm buf 0 1)
         (let ((true-label (i386-make-label))
               (done-label (i386-make-label)))
           (i386-emit-jcc buf :ne true-label)
           (i386-emit-mov-reg-abs buf 0 1544)
           (i386-emit-jmp-rel32 buf done-label)
           (i386-emit-label buf true-label)
           (i386-emit-mov-reg-imm buf 0 262)
           (i386-emit-label buf done-label))
         (i386-store-vreg buf vd 0)))

      ;; === ALLOC-OBJ (#x60) ===
      ((= opcode 96)
       (let ((vd (first operands)) (count (second operands)) (subtag (third operands)))
         (i386-emit-mov-reg-abs buf 2 1536)
         (i386-emit-mov-mem-imm buf 2 0 (logior (ash count 8) subtag))
         (i386-emit-mov-reg-reg buf 0 2)
         (i386-emit-or-reg-imm buf 0 9)
         (let ((total (logand (+ (* (+ count 1) 4) 15) (lognot 15))))
           (i386-emit-add-reg-imm buf 2 total))
         (i386-emit-mov-abs-reg buf 1536 2)
         (i386-store-vreg buf vd 0)))

      ;; === OBJ-REF (#x61) ===
      ((= opcode 97)
       (let ((vd (first operands)) (vobj (second operands)) (idx (third operands)))
         (if (= vobj 21)
             (progn
               (i386-emit-mov-reg-mem buf 0 5 (+ -68 (* idx -4)))
               (i386-store-vreg buf vd 0))
             (progn
               (i386-load-vreg buf 0 vobj)
               (i386-emit-sub-reg-imm buf 0 9)
               (i386-emit-mov-reg-mem buf 0 0 (* (+ idx 1) 4))
               (i386-store-vreg buf vd 0)))))

      ;; === OBJ-SET (#x62) ===
      ((= opcode 98)
       (let ((vobj (first operands)) (idx (second operands)) (vs (third operands)))
         (if (= vobj 21)
             (progn
               (i386-load-vreg buf 1 vs)
               (i386-emit-mov-mem-reg buf 5 (+ -68 (* idx -4)) 1))
             (progn
               (i386-load-vreg buf 1 vs)
               (i386-load-vreg buf 0 vobj)
               (i386-emit-sub-reg-imm buf 0 9)
               (i386-emit-mov-mem-reg buf 0 (* (+ idx 1) 4) 1)))))

      ;; === OBJ-TAG (#x63) ===
      ((= opcode 99)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-and-reg-imm buf 0 15)
         (i386-emit-shl-reg-imm buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === OBJ-SUBTAG (#x64) ===
      ((= opcode 100)
       (let ((vd (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-sub-reg-imm buf 0 9)
         (i386-emit-mov-reg-mem buf 0 0 0)
         (i386-emit-and-reg-imm buf 0 255)
         (i386-emit-shl-reg-imm buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === AREF (#x65) ===
      ((= opcode 101)
       (let ((vd (first operands)) (vobj (second operands)) (vidx (third operands)))
         (i386-load-vreg buf 1 vidx)
         (i386-emit-shl-reg-imm buf 1 1)
         (i386-load-vreg buf 0 vobj)
         (i386-emit-add-reg-reg buf 0 1)
         (i386-emit-mov-reg-mem buf 0 0 -5)
         (i386-store-vreg buf vd 0)))

      ;; === ASET (#x66) ===
      ((= opcode 102)
       (let ((vobj (first operands)) (vidx (second operands)) (vs (third operands)))
         (i386-load-vreg buf 1 vs)
         (i386-load-vreg buf 0 vidx)
         (i386-emit-shl-reg-imm buf 0 1)
         (i386-emit-push-reg buf 1)
         (i386-load-vreg buf 2 vobj)
         (i386-emit-add-reg-reg buf 0 2)
         (i386-emit-pop-reg buf 1)
         (i386-emit-mov-mem-reg buf 0 -5 1)))

      ;; === ARRAY-LEN (#x67) ===
      ((= opcode 103)
       (let ((vd (first operands)) (vobj (second operands)))
         (i386-load-vreg buf 0 vobj)
         (i386-emit-sub-reg-imm buf 0 9)
         (i386-emit-mov-reg-mem buf 0 0 0)
         (i386-emit-shr-reg-imm buf 0 8)
         (i386-emit-and-reg-imm buf 0 16777215)
         (i386-emit-shl-reg-imm buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === ALLOC-ARRAY (#x68) ===
      ((= opcode 104)
       (let ((vd (first operands)) (vcount (second operands)))
         (i386-load-vreg buf 1 vcount)
         (i386-emit-push-reg buf 1)
         (i386-emit-shl-reg-imm buf 1 8)
         (i386-emit-or-reg-imm buf 1 50)
         (i386-emit-mov-reg-abs buf 2 1536)
         (i386-emit-mov-mem-reg buf 2 0 1)
         (i386-emit-mov-reg-reg buf 0 2)
         (i386-emit-or-reg-imm buf 0 9)
         (i386-emit-pop-reg buf 1)
         (i386-emit-add-reg-imm buf 1 1)
         (i386-emit-shl-reg-imm buf 1 2)
         (i386-emit-add-reg-imm buf 1 15)
         (i386-emit-and-reg-imm buf 1 -16)
         (i386-emit-add-reg-reg buf 2 1)
         (i386-emit-mov-abs-reg buf 1536 2)
         (i386-store-vreg buf vd 0)))

      ;; === LOAD (#x70) ===
      ((= opcode 112)
       (let ((vd (first operands)) (vaddr (second operands)) (width (third operands)))
         (i386-load-vreg buf 0 vaddr)
         (cond
           ((= width 0) (i386-emit-movzx-byte buf 0 0 0))
           ((= width 1) (i386-emit-movzx-word buf 0 0 0))
           (t (i386-emit-mov-reg-mem buf 0 0 0)))
         (i386-store-vreg buf vd 0)))

      ;; === STORE (#x71) ===
      ((= opcode 113)
       (let ((vaddr (first operands)) (vs (second operands)) (width (third operands)))
         (i386-load-vreg buf 1 vs)
         (i386-load-vreg buf 0 vaddr)
         (cond
           ((= width 0) (i386-emit-mov-mem8-reg buf 0 0 1))
           ((= width 1) (i386-emit-mov-mem16-reg buf 0 0 1))
           (t (i386-emit-mov-mem-reg buf 0 0 1)))))

      ;; === FENCE (#x72) ===
      ((= opcode 114) (i386-emit-mfence buf))

      ;; === CALL (#x80) ===
      ((= opcode 128)
       (let ((target-offset (first operands)))
         (let ((fn-table (i386-translate-state-function-table state)))
           (let ((label (when fn-table (gethash target-offset fn-table))))
             (i386-emit-push-mem buf 5 -20)
             (i386-emit-push-mem buf 5 -16)
             (if label
                 (i386-emit-call-rel32 buf label)
                 (i386-emit-call-rel32 buf nil))
             (i386-emit-add-reg-imm buf 4 8)))))

      ;; === CALL-IND (#x81) ===
      ((= opcode 129)
       (let ((vs (first operands)))
         (i386-emit-push-mem buf 5 -20)
         (i386-emit-push-mem buf 5 -16)
         (i386-load-vreg buf 0 vs)
         (i386-emit-call-reg buf 0)
         (i386-emit-add-reg-imm buf 4 8)))

      ;; === RET (#x82) ===
      ((= opcode 130)
       (i386-emit-epilogue buf))

      ;; === TAILCALL (#x83) ===
      ((= opcode 131)
       (let ((target-offset (first operands)))
         (let ((fn-table (i386-translate-state-function-table state)))
           (let ((label (when fn-table (gethash target-offset fn-table))))
             ;; Save V2/V3 before frame teardown
             (i386-emit-mov-reg-mem buf 1 5 -16)    ;; ECX = V2
             (i386-emit-mov-reg-mem buf 2 5 -20)    ;; EDX = V3
             ;; Restore callee-saved
             (i386-emit-mov-reg-mem buf 3 5 -4)     ;; EBX = [EBP-4]
             (i386-emit-mov-reg-mem buf 6 5 -8)     ;; ESI = [EBP-8]
             (i386-emit-mov-reg-mem buf 7 5 -12)    ;; EDI = [EBP-12]
             ;; Tear down frame
             (i386-emit-mov-reg-reg buf 4 5)         ;; ESP = EBP
             (i386-emit-pop-reg buf 5)               ;; POP EBP
             ;; Pop return addr, push V3, V2, return addr back
             (i386-emit-pop-reg buf 0)               ;; EAX = return addr
             (i386-emit-push-reg buf 2)              ;; push V3
             (i386-emit-push-reg buf 1)              ;; push V2
             (i386-emit-push-reg buf 0)              ;; push return addr
             (if label
                 (i386-emit-jmp-rel32 buf label)
                 (i386-emit-jmp-rel32 buf nil))))))

      ;; === ALLOC-CONS (#x88) ===
      ((= opcode 136)
       (let ((vd (first operands)))
         (i386-emit-mov-reg-abs buf 0 1536)
         (i386-emit-mov-reg-reg buf 1 0)
         (i386-emit-or-reg-imm buf 1 1)
         (i386-emit-add-reg-imm buf 0 16)
         (i386-emit-mov-abs-reg buf 1536 0)
         (i386-store-vreg buf vd 1)))

      ;; === GC-CHECK (#x89) ===
      ((= opcode 137)
       (i386-emit-mov-reg-abs buf 1 1536)
       (i386-emit-cmp-reg-abs buf 1 1540)
       (let ((ok-label (i386-make-label)))
         (i386-emit-jcc buf :b ok-label)
         (let ((gc-lbl (i386-translate-state-gc-label state)))
           (if gc-lbl
               (i386-emit-call-rel32 buf gc-lbl)
               (i386-emit-int buf 49)))
         (i386-emit-label buf ok-label)))

      ;; === WRITE-BARRIER (#x8A) ===
      ((= opcode 138) (i386-emit-nop buf))

      ;; === SAVE-CTX (#x90) ===
      ((= opcode 144)
       (i386-emit-push-reg buf 6)
       (i386-emit-push-reg buf 7)
       (i386-emit-push-reg buf 3)
       (i386-emit-push-abs buf 1536)
       (i386-emit-push-abs buf 1540)
       (i386-emit-push-abs buf 1544))

      ;; === RESTORE-CTX (#x91) ===
      ((= opcode 145)
       (i386-emit-pop-abs buf 1544)
       (i386-emit-pop-abs buf 1540)
       (i386-emit-pop-abs buf 1536)
       (i386-emit-pop-reg buf 3)
       (i386-emit-pop-reg buf 7)
       (i386-emit-pop-reg buf 6))

      ;; === YIELD (#x92) ===
      ((= opcode 146) (i386-emit-nop buf))

      ;; === ATOMIC-XCHG (#x93) ===
      ((= opcode 147)
       (let ((vd (first operands)) (vaddr (second operands)) (vs (third operands)))
         (i386-load-vreg buf 0 vs)
         (i386-load-vreg buf 1 vaddr)
         (i386-emit-xchg-mem-reg buf 1 0 0)
         (i386-store-vreg buf vd 0)))

      ;; === IO-READ (#xA0) ===
      ((= opcode 160)
       (let ((vd (first operands)) (port (second operands)) (width (third operands)))
         (cond
           ((<= port 255)
            (cond
              ((= width 0) (i386-emit-in-al-imm8 buf port)
                           (i386-emit-and-reg-imm buf 0 255))
              ((= width 1) (i386-emit-in-ax-imm8 buf port)
                           (i386-emit-and-reg-imm buf 0 65535))
              (t (i386-emit-in-eax-imm8 buf port))))
           (t
            (i386-emit-mov-reg-imm buf 2 port)
            (cond
              ((= width 0) (i386-emit-in-al-dx buf)
                           (i386-emit-and-reg-imm buf 0 255))
              ((= width 1) (i386-emit-in-ax-dx buf)
                           (i386-emit-and-reg-imm buf 0 65535))
              (t (i386-emit-in-eax-dx buf)))))
         (i386-emit-shl-reg-imm buf 0 1)
         (i386-store-vreg buf vd 0)))

      ;; === IO-WRITE (#xA1) ===
      ((= opcode 161)
       (let ((port (first operands)) (vs (second operands)) (width (third operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-shr-reg-imm buf 0 1)
         (cond
           ((<= port 255)
            (cond
              ((= width 0) (i386-emit-out-imm8-al buf port))
              ((= width 1) (i386-emit-byte buf 102) (i386-emit-out-imm8-eax buf port))
              (t (i386-emit-out-imm8-eax buf port))))
           (t
            (i386-emit-mov-reg-imm buf 2 port)
            (cond
              ((= width 0) (i386-emit-out-dx-al buf))
              ((= width 1) (i386-emit-out-dx-ax buf))
              (t (i386-emit-out-dx-eax buf)))))))

      ;; === HALT (#xA2) ===
      ((= opcode 162)
       (let ((halt-label (i386-make-label)))
         (i386-emit-label buf halt-label)
         (i386-emit-cli buf)
         (i386-emit-hlt buf)
         (i386-emit-jmp-rel32 buf halt-label)))

      ;; === CLI (#xA3) ===
      ((= opcode 163) (i386-emit-cli buf))

      ;; === STI (#xA4) ===
      ((= opcode 164) (i386-emit-sti buf))

      ;; === PERCPU-REF (#xA5) ===
      ((= opcode 165)
       (let ((vd (first operands)) (offset (second operands)))
         (i386-emit-byte buf 100)
         (i386-emit-byte buf 139)
         (i386-emit-byte buf (i386-modrm 0 0 5))
         (i386-emit-u32 buf offset)
         (i386-store-vreg buf vd 0)))

      ;; === PERCPU-SET (#xA6) ===
      ((= opcode 166)
       (let ((offset (first operands)) (vs (second operands)))
         (i386-load-vreg buf 0 vs)
         (i386-emit-byte buf 100)
         (i386-emit-byte buf 137)
         (i386-emit-byte buf (i386-modrm 0 0 5))
         (i386-emit-u32 buf offset)))

      ;; === Unknown → NOP ===
      (t (i386-emit-nop buf)))))

;;; Override i386-vreg-phys to avoid *i386-vreg-map* global lookup
;;; Returns physical register number or nil. WARNING: returns 0 for VR=EAX,
;;; which is indistinguishable from NIL on AArch64 (NIL=0).
;;; Use i386-has-phys to check if a vreg has a physical register.
(defun i386-vreg-phys (vreg)
  (cond
    ((= vreg 0) 6)   ;; V0 = ESI
    ((= vreg 1) 7)   ;; V1 = EDI
    ((= vreg 4) 3)   ;; V4 = EBX
    ((= vreg 16) 0)  ;; VR = EAX
    ((= vreg 20) 4)  ;; VSP = ESP
    ((= vreg 21) 5)  ;; VFP = EBP
    (t nil)))

;;; Predicate: does vreg have a physical register? Safe on AArch64 (NIL=0).
(defun i386-has-phys (vreg)
  (cond
    ((= vreg 0) 1) ((= vreg 1) 1) ((= vreg 4) 1)
    ((= vreg 16) 1) ((= vreg 20) 1) ((= vreg 21) 1)
    (t nil)))

;;; Override i386-store-vreg — fully inlined to avoid NIL=0 truthiness bug
;;; On AArch64, fixnum 0 == NIL, so i386-vreg-phys returning 0 (EAX)
;;; is treated as false. Fix: match vreg values directly, no truthiness check.
(defun i386-store-vreg (buf vreg scratch)
  (cond
    ((= vreg 0)  (unless (= 6 scratch) (i386-emit-mov-reg-reg buf 6 scratch)))
    ((= vreg 1)  (unless (= 7 scratch) (i386-emit-mov-reg-reg buf 7 scratch)))
    ((= vreg 4)  (unless (= 3 scratch) (i386-emit-mov-reg-reg buf 3 scratch)))
    ((= vreg 16) (unless (= 0 scratch) (i386-emit-mov-reg-reg buf 0 scratch)))
    ((= vreg 20) (unless (= 4 scratch) (i386-emit-mov-reg-reg buf 4 scratch)))
    ((= vreg 21) (unless (= 5 scratch) (i386-emit-mov-reg-reg buf 5 scratch)))
    ((= vreg 17) (i386-emit-mov-abs-reg buf 1536 scratch))
    ((= vreg 18) (i386-emit-mov-abs-reg buf 1540 scratch))
    ((= vreg 19) (i386-emit-mov-abs-reg buf 1544 scratch))
    (t (i386-emit-mov-mem-reg buf 5 (i386-spill-offset vreg) scratch))))

;;; Override i386-load-vreg — same NIL=0 fix
(defun i386-load-vreg (buf scratch vreg)
  (cond
    ((= vreg 0)  (unless (= scratch 6) (i386-emit-mov-reg-reg buf scratch 6)))
    ((= vreg 1)  (unless (= scratch 7) (i386-emit-mov-reg-reg buf scratch 7)))
    ((= vreg 4)  (unless (= scratch 3) (i386-emit-mov-reg-reg buf scratch 3)))
    ((= vreg 16) (unless (= scratch 0) (i386-emit-mov-reg-reg buf scratch 0)))
    ((= vreg 20) (unless (= scratch 4) (i386-emit-mov-reg-reg buf scratch 4)))
    ((= vreg 21) (unless (= scratch 5) (i386-emit-mov-reg-reg buf scratch 5)))
    ((= vreg 17) (i386-emit-mov-reg-abs buf scratch 1536))
    ((= vreg 18) (i386-emit-mov-reg-abs buf scratch 1540))
    ((= vreg 19) (i386-emit-mov-reg-abs buf scratch 1544))
    (t (i386-emit-mov-reg-mem buf scratch 5 (i386-spill-offset vreg)))))

;;; Override i386-vreg-abs-addr
(defun i386-vreg-abs-addr (vreg)
  (cond
    ((= vreg 17) 1536)  ;; VA = 0x600
    ((= vreg 18) 1540)  ;; VL = 0x604
    ((= vreg 19) 1544)  ;; VN = 0x608
    (t nil)))

;;; Override i386-emit-modrm-mem — the original uses 3-arg <= and /= which
;;; may have issues on AArch64 bare metal. Simplify to always use disp8 or disp32.
(defun i386-emit-modrm-mem (buf reg-field base-reg offset)
  (let ((needs-sib (= base-reg 4)))  ;; ESP=4
    (cond
      ;; 8-bit displacement: offset fits in [-128, 127]
      ((and (>= offset -128) (<= offset 127))
       (if needs-sib
           (progn
             (i386-emit-byte buf (i386-modrm 1 reg-field 4))
             (i386-emit-byte buf (i386-sib 0 4 4)))
           (i386-emit-byte buf (i386-modrm 1 reg-field base-reg)))
       (i386-emit-s8 buf offset))
      ;; 32-bit displacement
      (t
       (if needs-sib
           (progn
             (i386-emit-byte buf (i386-modrm 2 reg-field 4))
             (i386-emit-byte buf (i386-sib 0 4 4)))
           (i386-emit-byte buf (i386-modrm 2 reg-field base-reg)))
       (i386-emit-s32 buf offset)))))

;;; Override i386-emit-s32 — original may use logand with negative numbers
(defun i386-emit-s32 (buf val)
  (let ((v (if (< val 0) (+ val 4294967296) val)))
    (i386-emit-byte buf (logand v 255))
    (i386-emit-byte buf (logand (ash v -8) 255))
    (i386-emit-byte buf (logand (ash v -16) 255))
    (i386-emit-byte buf (logand (ash v -24) 255))))

;;; Override i386-emit-init-serial — the original uses labels (local functions) which
;;; the bare-metal compiler handles as global functions, but may have issues with
;;; function resolution after 968+ functions are compiled. Inline instead.
(defun i386-serial-out (buf port val)
  (mvm-emit-byte buf 102)   ;; 66 prefix
  (mvm-emit-byte buf 186)   ;; BA = mov dx, imm16
  (mvm-emit-u16 buf port)
  (mvm-emit-byte buf 176)   ;; B0 = mov al, imm8
  (mvm-emit-byte buf val)
  (mvm-emit-byte buf 238))  ;; EE = out dx, al

(defun i386-init-serial (buf)
  (i386-serial-out buf 1017 0)     ;; 0x3F9: disable interrupts
  (i386-serial-out buf 1019 128)   ;; 0x3FB: DLAB
  (i386-serial-out buf 1016 1)     ;; 0x3F8: divisor lo
  (i386-serial-out buf 1017 0)     ;; 0x3F9: divisor hi
  (i386-serial-out buf 1019 3)     ;; 0x3FB: 8N1
  (i386-serial-out buf 1018 193))  ;; 0x3FA: FIFO

;;; Override emit-i386-entry — avoid labels construct, use simpler code
(defun emit-i386-entry (buf)
  ;; CLI
  (mvm-emit-byte buf 250)
  ;; mov [0x500], ebx
  (mvm-emit-byte buf 137) (mvm-emit-byte buf 29) (mvm-emit-u32 buf 1280)
  ;; mov esp, 0x400000
  (mvm-emit-byte buf 188) (mvm-emit-u32 buf 4194304)
  ;; push ebp; mov ebp, esp
  (mvm-emit-byte buf 85)
  (mvm-emit-byte buf 137) (mvm-emit-byte buf 229)
  ;; sub esp, 80
  (mvm-emit-byte buf 131) (mvm-emit-byte buf 236) (mvm-emit-byte buf 80)
  ;; mov [0x600], 0x800000
  (mvm-emit-byte buf 199) (mvm-emit-byte buf 5) (mvm-emit-u32 buf 1536) (mvm-emit-u32 buf 8388608)
  ;; mov [0x604], 0x4000000
  (mvm-emit-byte buf 199) (mvm-emit-byte buf 5) (mvm-emit-u32 buf 1540) (mvm-emit-u32 buf 67108864)
  ;; mov [0x608], 0x00
  (mvm-emit-byte buf 199) (mvm-emit-byte buf 5) (mvm-emit-u32 buf 1544) (mvm-emit-u32 buf 0)
  ;; Serial init
  (i386-init-serial buf))

;;; Override i386 ALU emitters (macro-generated versions may not work on bare metal
;;; due to 3-arg <= with negative numbers or constant resolution issues)
(defun i386-emit-alu-reg-reg (buf opcode dst src)
  (i386-emit-byte buf opcode)
  (i386-emit-byte buf (i386-modrm 3 src dst)))

(defun i386-emit-alu-reg-imm (buf opcode-ri8 opcode-ri32 modrm-ext reg imm)
  (cond
    ((and (>= imm -128) (<= imm 127))
     (i386-emit-byte buf opcode-ri8)
     (i386-emit-byte buf (i386-modrm 3 modrm-ext reg))
     (i386-emit-s8 buf imm))
    ((= reg 0) ;; EAX short form
     (i386-emit-byte buf opcode-ri32)
     (i386-emit-s32 buf imm))
    (t
     (i386-emit-byte buf 129) ;; #x81
     (i386-emit-byte buf (i386-modrm 3 modrm-ext reg))
     (i386-emit-s32 buf imm))))

(defun i386-emit-alu-reg-mem (buf opcode reg base offset)
  (i386-emit-byte buf opcode)
  (i386-emit-modrm-mem buf reg base offset))

(defun i386-emit-alu-mem-reg (buf opcode base offset reg)
  (i386-emit-byte buf opcode)
  (i386-emit-modrm-mem buf reg base offset))

;; ADD: rr=#x01, ri8=#x83, ri32=#x05, ext=0, rm=#x03, mr=#x01
(defun i386-emit-add-reg-reg (buf dst src) (i386-emit-alu-reg-reg buf 1 dst src))
(defun i386-emit-add-reg-imm (buf reg imm) (i386-emit-alu-reg-imm buf 131 5 0 reg imm))
(defun i386-emit-add-reg-mem (buf reg base offset) (i386-emit-alu-reg-mem buf 3 reg base offset))
(defun i386-emit-add-mem-reg (buf base offset reg) (i386-emit-alu-mem-reg buf 1 base offset reg))

;; SUB: rr=#x29, ri8=#x83, ri32=#x2D, ext=5, rm=#x2B, mr=#x29
(defun i386-emit-sub-reg-reg (buf dst src) (i386-emit-alu-reg-reg buf 41 dst src))
(defun i386-emit-sub-reg-imm (buf reg imm) (i386-emit-alu-reg-imm buf 131 45 5 reg imm))
(defun i386-emit-sub-reg-mem (buf reg base offset) (i386-emit-alu-reg-mem buf 43 reg base offset))
(defun i386-emit-sub-mem-reg (buf base offset reg) (i386-emit-alu-mem-reg buf 41 base offset reg))

;; CMP: rr=#x39, ri8=#x83, ri32=#x3D, ext=7, rm=#x3B, mr=#x39
(defun i386-emit-cmp-reg-reg (buf dst src) (i386-emit-alu-reg-reg buf 57 dst src))
(defun i386-emit-cmp-reg-imm (buf reg imm) (i386-emit-alu-reg-imm buf 131 61 7 reg imm))
(defun i386-emit-cmp-reg-mem (buf reg base offset) (i386-emit-alu-reg-mem buf 59 reg base offset))
(defun i386-emit-cmp-mem-reg (buf base offset reg) (i386-emit-alu-mem-reg buf 57 base offset reg))

;; AND: rr=#x21, ri8=#x83, ri32=#x25, ext=4, rm=#x23, mr=#x21
(defun i386-emit-and-reg-reg (buf dst src) (i386-emit-alu-reg-reg buf 33 dst src))
(defun i386-emit-and-reg-imm (buf reg imm) (i386-emit-alu-reg-imm buf 131 37 4 reg imm))
(defun i386-emit-and-reg-mem (buf reg base offset) (i386-emit-alu-reg-mem buf 35 reg base offset))
(defun i386-emit-and-mem-reg (buf base offset reg) (i386-emit-alu-mem-reg buf 33 base offset reg))

;; OR: rr=#x09, ri8=#x83, ri32=#x0D, ext=1, rm=#x0B, mr=#x09
(defun i386-emit-or-reg-reg (buf dst src) (i386-emit-alu-reg-reg buf 9 dst src))
(defun i386-emit-or-reg-imm (buf reg imm) (i386-emit-alu-reg-imm buf 131 13 1 reg imm))
(defun i386-emit-or-reg-mem (buf reg base offset) (i386-emit-alu-reg-mem buf 11 reg base offset))
(defun i386-emit-or-mem-reg (buf base offset reg) (i386-emit-alu-mem-reg buf 9 base offset reg))

;; XOR: rr=#x31, ri8=#x83, ri32=#x35, ext=6, rm=#x33, mr=#x31
(defun i386-emit-xor-reg-reg (buf dst src) (i386-emit-alu-reg-reg buf 49 dst src))
(defun i386-emit-xor-reg-imm (buf reg imm) (i386-emit-alu-reg-imm buf 131 53 6 reg imm))
(defun i386-emit-xor-reg-mem (buf reg base offset) (i386-emit-alu-reg-mem buf 51 reg base offset))
(defun i386-emit-xor-mem-reg (buf base offset reg) (i386-emit-alu-mem-reg buf 49 base offset reg))

;;; Override i386-emit-byte: verify writes + diagnostic for first bytes
(defun i386-emit-byte (buf byte)
  (let ((pos (i386-buffer-position buf)))
    (let ((masked (logand byte 255)))
      (let ((dummy (aset (i386-buffer-bytes buf) pos masked)))
        (set-i386-buffer-position buf (+ pos 1))
        dummy))))

;;; Override i386-emit-u32: avoid calling through original chain
(defun i386-emit-u32 (buf val)
  (i386-emit-byte buf (logand val 255))
  (i386-emit-byte buf (logand (ash val -8) 255))
  (i386-emit-byte buf (logand (ash val -16) 255))
  (i386-emit-byte buf (logand (ash val -24) 255)))

;;; Override i386-emit-s8: bare metal compatible
(defun i386-emit-s8 (buf val)
  (i386-emit-byte buf (if (< val 0) (logand val 255) val)))

;;; Override i386-emit-fixup-rel32: no push/list on bare metal
(defun i386-emit-fixup-rel32 (buf label-id)
  (let ((pos (i386-buffer-position buf)))
    (let ((entry (cons pos (cons label-id (cons 0 nil)))))
      (let ((old (i386-buffer-fixups buf)))
        (set-i386-buffer-fixups buf (cons entry old)))))
  (i386-emit-u32 buf 0))

;;; Override i386-emit-label: store (pos + 1) to avoid NIL=0 on AArch64.
;;; Position 0 becomes 1 (truthy), lookup miss returns 0/nil.
(defun i386-emit-label (buf label-id)
  (puthash label-id (i386-buffer-labels buf) (+ (i386-buffer-position buf) 1)))

;;; Helper: write byte 0 of a 32-bit LE value
(defun fixup-write-b0 (bytes pos val)
  (aset bytes pos (logand val 255)))

;;; Helper: write byte 1 of a 32-bit LE value
(defun fixup-write-b1 (bytes pos val)
  (aset bytes (+ pos 1) (logand (ash val -8) 255)))

;;; Helper: write byte 2 of a 32-bit LE value
(defun fixup-write-b2 (bytes pos val)
  (aset bytes (+ pos 2) (logand (ash val -16) 255)))

;;; Helper: write byte 3 of a 32-bit LE value
(defun fixup-write-b3 (bytes pos val)
  (aset bytes (+ pos 3) (logand (ash val -24) 255)))

;;; Helper: write a 32-bit little-endian value into byte array at pos.
;;; Split into 4 separate function calls to minimize vreg pressure.
(defun fixup-write-u32-le (bytes pos val)
  (fixup-write-b0 bytes pos val)
  (fixup-write-b1 bytes pos val)
  (fixup-write-b2 bytes pos val)
  (fixup-write-b3 bytes pos val))

;;; Helper: apply one fixup entry. Returns 1 if applied, 0 if label not found.
;;; Separate function to keep vreg count within V9-V15 spill limit.
(defun fixup-apply-one (buf bytes fixup)
  (let ((pos (car fixup))
        (label-id (car (cdr fixup))))
    (let ((raw-target (gethash label-id (i386-buffer-labels buf))))
      (if raw-target
          (let ((target (- raw-target 1)))
            (let ((rel (- target (+ pos 4))))
              (let ((urel (if (< rel 0) (logand rel 4294967295) rel)))
                (fixup-write-u32-le bytes pos urel)
                1)))
          0))))

;;; Override i386-fixup-labels: no destructuring-bind/ecase
;;; Label positions stored as (pos + 1) in hash table to avoid NIL=0 on AArch64.
;;; Kept shallow: outer loop has V0=buf + V9-V13 (5 vars).
(defun i386-fixup-labels (buf)
  (let ((bytes (i386-buffer-bytes buf))
        (rest-fixups (i386-buffer-fixups buf))
        (fix-count 0)
        (skip-count 0))
    (loop
      (when (null rest-fixups) (return nil))
      (let ((applied (fixup-apply-one buf bytes (car rest-fixups))))
        (if (= applied 1)
            (setq fix-count (+ fix-count 1))
            (setq skip-count (+ skip-count 1))))
      (setq rest-fixups (cdr rest-fixups)))
    (write-char-serial 70) (write-char-serial 88) ;; FX
    (print-dec fix-count)
    (write-char-serial 47) ;; /
    (print-dec skip-count)
    (write-char-serial 10)))

;;; Override i386-buffer-to-bytes: no dotimes-with-result
(defun i386-buffer-to-bytes (buf)
  (let ((len (i386-buffer-position buf)))
    (let ((result (make-array len))
          (i 0))
      (loop
        (when (>= i len) (return result))
        (aset result i (aref (i386-buffer-bytes buf) i))
        (setq i (+ i 1))))))

;;; Override i386-scan-branch-targets: no loop-while/member/position
(defun i386-scan-branch-targets (state)
  (let ((bytes (i386-translate-state-mvm-bytes state))
        (offset (i386-translate-state-mvm-offset state))
        (length (i386-translate-state-mvm-length state)))
    (let ((pos offset)
          (limit (+ offset length)))
      (loop
        (when (>= pos limit) (return nil))
        (let ((decoded (decode-instruction bytes pos)))
          (let ((opcode (car decoded))
                (operands (car (cdr decoded)))
                (new-pos (cdr (cdr decoded))))
            ;; Branch opcodes: 64-72 (BR through BNNULL)
            (when (and (>= opcode 64) (<= opcode 72))
              (let ((off (if (<= opcode 70)
                             (car operands)
                             (car (cdr operands)))))
                (let ((target-pos (+ new-pos off)))
                  (i386-ensure-label-at state target-pos))))
            (setq pos new-pos)))))))

;;; Override translate-mvm-to-i386: no loop-for/maphash/lambda/values
(defun translate-mvm-to-i386 (bytecode function-table)
  (write-char-serial 105) (write-char-serial 51) ;; i3
  (write-char-serial 56) (write-char-serial 54) ;; 86
  (write-char-serial 10)
  (let ((buf (make-i386-buffer)))
    (let ((n-functions (length function-table)))
      (print-dec n-functions) (write-char-serial 10)
      (let ((fn-labels (make-array n-functions))
            (fn-map (make-hash-table))
            (fn-offset-to-label (make-hash-table)))
        ;; Create labels for each function
        (let ((rest-ft function-table)
              (i 0))
          (loop
            (when (>= i n-functions) (return nil))
            (let ((entry (car rest-ft)))
              (let ((name (car entry))
                    (offset (car (cdr entry))))
                (let ((label (i386-make-label)))
                  (aset fn-labels i label)
                  (puthash name fn-map label)
                  (puthash offset fn-offset-to-label label))))
            (setq rest-ft (cdr rest-ft))
            (setq i (+ i 1))))
        ;; Translate each function — use single reusable state
        (write-char-serial 84) (write-char-serial 10) ;; T
        ;; Reset all diagnostic addresses
        (td-write-u32 #x380040 0)
        (td-write-u32 #x380044 0)
        (td-write-u32 #x380048 0)
        (td-write-u32 #x38004C 0)
        (td-write-u32 #x380050 0)
        (td-write-u32 #x380054 0)
        (td-write-u32 #x380058 0)
        (td-write-u32 #x38005C 0)
        (td-write-u32 #x380060 0)
        ;; Print alloc pointer before translation
        (write-char-serial 65) ;; A
        (write-char-serial 80) ;; P
        (write-char-serial 61) ;; =
        (print-dec (get-alloc-ptr))
        (write-char-serial 47) ;; /
        (print-dec (get-alloc-limit))
        (write-char-serial 10) ;; newline
        (let ((state (make-i386-translate-state)))
          (set-i386-translate-state-buf state buf)
          (set-i386-translate-state-mvm-bytes state bytecode)
          (set-i386-translate-state-function-table state fn-offset-to-label)
          (let ((rest-ft function-table)
                (i 0))
            (loop
              (when (>= i n-functions) (return nil))
              (let ((entry (car rest-ft)))
                (let ((fn-offset (car (cdr entry)))
                      (fn-length (car (cdr (cdr entry)))))
                  (let ((fn-label (aref fn-labels i)))
                    (set-i386-translate-state-mvm-length state fn-length)
                    (set-i386-translate-state-mvm-offset state fn-offset)
                    (set-i386-translate-state-label-map state (make-hash-table))
                    (i386-emit-label buf fn-label)
                    (i386-emit-prologue buf)
                    (i386-scan-branch-targets state)
                    (let ((pos fn-offset)
                          (limit (+ fn-offset fn-length)))
                      (loop
                        (when (>= pos limit) (return nil))
                        (i386-translate-one-insn buf state bytecode pos)
                        (setq pos (td-read-u32 #x380060)))))))
            (when (zerop (mod i 50))
              (write-char-serial 46)) ;; progress dot every 50 functions
            (setq rest-ft (cdr rest-ft))
            (setq i (+ i 1)))))
        ;; Fixup labels
        (i386-fixup-labels buf)
        ;; Resolve fn-map: replace label IDs with native byte positions
        (let ((resolved-map (make-hash-table)))
          (let ((rest-ft function-table)
                (i 0))
            (loop
              (when (>= i n-functions) (return nil))
              (let ((entry (car rest-ft)))
                (let ((name (car entry)))
                  (let ((label (gethash name fn-map)))
                    (when label
                      (let ((raw-pos (gethash label (i386-buffer-labels buf))))
                        (when raw-pos
                          (puthash name resolved-map (- raw-pos 1))))))))
              (setq rest-ft (cdr rest-ft))
              (setq i (+ i 1))))
          (cons buf resolved-map))))))

;;; Generate i386 boot preamble into image buffer
(defun td-generate-i386-boot ()
  (let ((boot-buf (make-mvm-buffer)))
    (emit-i386-multiboot-header boot-buf)
    (emit-i386-entry boot-buf)
    (let ((boot-size (mvm-buffer-position boot-buf))
          (i 0))
      (loop
        (when (>= i boot-size) (return boot-size))
        (img-emit (aref (mvm-buffer-bytes boot-buf) i))
        (setq i (+ i 1))))))

;;; Assemble Gen1 i386 image from translated native code
;;; Layout: [boot preamble][JMP to kernel-main][native code][bytecodes][fn-table]...[metadata at 0x280000]
(defun td-assemble-gen1-i386 (result bc ft)
  ;; result = (cons i386-buffer fn-map)
  (let ((buf (car result))
        (fn-map (cdr result)))
    (let ((native-bytes (i386-buffer-bytes buf))
          (native-size (i386-buffer-position buf)))
      ;; 1. Init image buffer
      (img-init)
      (write-char-serial 73) (write-char-serial 49) ;; I1
      (write-char-serial 58) (write-char-serial 10)
      ;; 2. Generate i386 boot preamble
      (let ((boot-size (td-generate-i386-boot)))
        (write-char-serial 80) ;; P
        (print-dec boot-size) (write-char-serial 10)
        ;; 3. Emit JMP rel32 to kernel-main
        (let ((km-hash (td-read-u32 #x380028)))
          (let ((km-native-off (gethash km-hash fn-map)))
            (let ((km-offset (if km-native-off km-native-off 0)))
              (img-emit 233)  ;; 0xE9 = JMP rel32
              (img-emit-u32 km-offset))))
        ;; 4. Copy native code
        (write-char-serial 78) ;; N
        (td-write-u32 #x380050 (img-pos))
        (let ((i 0))
          (loop
            (when (>= i native-size) (return nil))
            (img-emit (aref native-bytes i))
            (setq i (+ i 1))
            (when (zerop (mod i 50000))
              (write-char-serial 46))))
        (write-char-serial 10)
        (print-dec (img-pos)) (write-char-serial 10)
        ;; 5. Append MVM bytecode
        (write-char-serial 84) ;; T
        (let ((bc-len (array-length bc))
              (bc-img-offset (img-pos)))
          (let ((bi 0))
            (loop
              (when (>= bi bc-len) (return nil))
              (img-emit (aref bc bi))
              (setq bi (+ bi 1))))
          ;; 6. Append function table — raw byte copy from source image
          ;; (avoids u32 overflow for name hashes with byte 3 >= 0x80 on i386)
          (let ((ft-img-offset (img-pos))
                (src-ft-addr (+ (td-read-u32 #x380030) (td-read-u32 #x380014)))
                (ft-count (td-read-u32 #x380018)))
            (let ((total-ft-bytes (* ft-count 12))
                  (bi 0))
              (loop
                (when (>= bi total-ft-bytes) (return nil))
                (img-emit (mem-ref (+ src-ft-addr bi) :u8))
                (setq bi (+ bi 1))))
            (write-char-serial 10)
            (print-dec ft-count) (write-char-serial 10)
            ;; 7. Write metadata at offset 0x280000 (VA = 0x100000 + 0x280000 = 0x380000)
            (let ((md-img-off #x280000))
              ;; magic MVMT = 0x544D564D — write as individual bytes
              ;; (0x544D564D > 2^30, overflows i386 30-bit fixnum)
              (let ((base (+ #x08000000 md-img-off)))
                (setf (mem-ref base :u8) #x4D)
                (setf (mem-ref (+ base 1) :u8) #x56)
                (setf (mem-ref (+ base 2) :u8) #x4D)
                (setf (mem-ref (+ base 3) :u8) #x54))
              (img-patch-u32 (+ md-img-off 4) 1)
              ;; my-architecture = 2 (i386)
              (img-patch-u32 (+ md-img-off 8) 2)
              (img-patch-u32 (+ md-img-off 12) bc-img-offset)
              (img-patch-u32 (+ md-img-off 16) bc-len)
              (img-patch-u32 (+ md-img-off 20) ft-img-offset)
              (img-patch-u32 (+ md-img-off 24) ft-count)
              (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x380050))
              (img-patch-u32 (+ md-img-off 32) native-size)
              (img-patch-u32 (+ md-img-off 36) boot-size)
              ;; kernel-main-hash-lo — raw byte copy (avoids u32 overflow on i386)
              (let ((dst-base (+ #x08000000 md-img-off 40)))
                (setf (mem-ref dst-base :u8) (mem-ref #x380028 :u8))
                (setf (mem-ref (+ dst-base 1) :u8) (mem-ref #x380029 :u8))
                (setf (mem-ref (+ dst-base 2) :u8) (mem-ref #x38002A :u8))
                (setf (mem-ref (+ dst-base 3) :u8) (mem-ref #x38002B :u8)))
              ;; kernel-main native offset
              (let ((km-native-off (gethash (td-read-u32 #x380028) fn-map)))
                (if km-native-off
                    (img-patch-u32 (+ md-img-off 44) km-native-off)
                    (img-patch-u32 (+ md-img-off 44) 0)))
              ;; image-load-addr = 0x100000 (i386 Multiboot, same as x64)
              (img-patch-u32 (+ md-img-off 48) #x100000)
              ;; target-architecture (not used — i386 is target-only)
              (img-patch-u32 (+ md-img-off 52) 0)
              (img-patch-u32 (+ md-img-off 56) 0))
            ;; 8. Patch multiboot header: load_end_addr, bss_end_addr
            (let ((total-size (+ #x280000 64)))
              (let ((load-end (+ #x100000 total-size)))
                (img-patch-u32 20 load-end)
                (img-patch-u32 24 load-end))
              (write-char-serial 73) (write-char-serial 49) ;; I1
              (write-char-serial 61) ;; =
              (print-dec total-size) (write-char-serial 10)
              total-size)))))))

;;; Build i386 target from x64 host (cross-arch)
(defun build-i386-from-x64 (bc ft)
  (let ((result (translate-mvm-to-i386 bc ft)))
    (let ((buf (car result)))
      (let ((native-size (i386-buffer-position buf)))
        (print-dec native-size) (write-char-serial 10)
        (let ((native-bytes (i386-buffer-bytes buf)))
          (let ((hash (td-fnv-native native-bytes native-size)))
            (write-char-serial 70) (write-char-serial 78)
            (write-char-serial 86) (write-char-serial 58)
            (print-dec hash) (write-char-serial 10)))
        (td-assemble-gen1-i386 result bc ft)
        native-size))))

;;; Build i386 target from AArch64 host (cross-arch)
(defun build-i386-from-aarch64 (bc ft)
  (let ((result (translate-mvm-to-i386 bc ft)))
    (let ((buf (car result)))
      (let ((native-size (i386-buffer-position buf)))
        (print-dec native-size) (write-char-serial 10)
        (let ((native-bytes (i386-buffer-bytes buf)))
          (let ((hash (td-fnv-native native-bytes native-size)))
            (write-char-serial 70) (write-char-serial 78)
            (write-char-serial 86) (write-char-serial 58)
            (print-dec hash) (write-char-serial 10)))
        (td-assemble-gen1-i386 result bc ft)
        native-size))))

;;; ============================================================
;;; i386 HOST overrides — safe for 30-bit fixnum (max ~1073741823)
;;; These override earlier defuns via last-defun-wins when running
;;; on i386, where #xFFFFFFFF and 4294967296 overflow fixnums.
;;; ============================================================

;;; Override i386-emit-mov-reg-imm: drop logand #xFFFFFFFF
;;; On i386 all values are already 32-bit; logand mask overflows.
(defun i386-emit-mov-reg-imm (buf reg imm)
  (i386-emit-byte buf (+ 184 reg))
  (i386-emit-u32 buf imm))

;;; Override i386-emit-s32: drop (+ val 4294967296) for negatives.
;;; On i386, negative fixnums already have correct bit pattern when
;;; extracted byte-by-byte with logand 255 / ash -8.
(defun i386-emit-s32 (buf val)
  (i386-emit-u32 buf val))

;;; Override td-fnv-native for i386 host: FNV init 2166136261 overflows
;;; 30-bit fixnum. Return XOR checksum instead (diagnostic only, not
;;; used for fixpoint comparison — SHA256 of full image is the proof).
(defun td-fnv-native (bytes size)
  (let ((my-arch (td-read-u32 #x380008)))
    (if (= my-arch 2)
        ;; i386 host: XOR checksum (FNV constants overflow)
        (let ((xsum 0) (j 0))
          (loop
            (when (>= j size) (return xsum))
            (setq xsum (logxor xsum (aref bytes j)))
            (setq j (+ j 1))))
        ;; x64/AArch64 host: real FNV-1a
        (let ((hash 2166136261) (j 0))
          (loop
            (when (>= j size) (return hash))
            (let ((b (aref bytes j)))
              (setq hash (logand #xFFFFFFFF
                                 (* (logxor hash b) 16777619))))
            (setq j (+ j 1)))))))

;;; Build i386 target from i386 host (same-arch fixpoint)
(defun build-i386-from-i386 (bc ft)
  (let ((result (translate-mvm-to-i386 bc ft)))
    (let ((buf (car result)))
      (let ((native-size (i386-buffer-position buf)))
        (print-dec native-size) (write-char-serial 10)
        (let ((native-bytes (i386-buffer-bytes buf)))
          (let ((hash (td-fnv-native native-bytes native-size)))
            (write-char-serial 70) (write-char-serial 78)
            (write-char-serial 86) (write-char-serial 58)
            (print-dec hash) (write-char-serial 10)))
        (td-assemble-gen1-i386 result bc ft)
        native-size))))

;;; ============================================================
;;; i386→x64 cross-compilation overrides
;;; These override x64 translator functions for i386-host safety.
;;; Key issues: decode-u64 overflow, emit-u64 shift-by-32 no-op,
;;; img-patch-u32 byte-3 overflow for values with bit30!=bit31.
;;; ============================================================

;;; Raw LI handler for x64 output — safe on i386 host.
;;; LI bytecode: [17][vd:1][imm64:8] = 10 bytes.
;;; Emits x64 MOV reg, imm64 (REX.W + B8+r + 8 raw bytes).
(defun td-x64-emit-li-raw (buf bytes pos)
  (let ((vd (logand (aref bytes (+ pos 1)) 31)))
    (let ((d (dest-phys-or-scratch vd)))
      (emit-byte buf (if (reg-extended-p d) 73 72))
      (emit-byte buf (+ 184 (reg-code d)))
      (let ((b0 (+ pos 2)))
        (emit-byte buf (aref bytes b0))
        (emit-byte buf (aref bytes (+ b0 1)))
        (emit-byte buf (aref bytes (+ b0 2)))
        (emit-byte buf (aref bytes (+ b0 3)))
        (emit-byte buf (aref bytes (+ b0 4)))
        (emit-byte buf (aref bytes (+ b0 5)))
        (emit-byte buf (aref bytes (+ b0 6)))
        (emit-byte buf (aref bytes (+ b0 7))))
      (maybe-store-scratch buf vd))))

;;; Override emit-u64: architecture-aware.
;;; On i386, (ash v -32) is a no-op due to x86 shift masking, and
;;; #xFFFFFFFF overflows 30-bit fixnum. With LI and CONSP/ATOM intercepted,
;;; all remaining emit-u64 calls on i386 have values that fit in 32 bits.
;;; On x64/AArch64, use standard ldb decomposition (safe for 63-bit fixnums).
(defun emit-u64 (buf value)
  (if (= (td-read-u32 #x380008) 2)
      ;; i386 host: high32 always 0
      (progn (emit-u32 buf value)
             (emit-byte buf 0) (emit-byte buf 0)
             (emit-byte buf 0) (emit-byte buf 0))
      ;; x64/AArch64 host
      (let ((lo (logand value 4294967295)))
        (let ((hi (logand (ash value -32) 4294967295)))
          (emit-u32 buf lo)
          (emit-u32 buf hi)))))

;;; i386-safe version of td-translate-fn-body: intercepts LI (opcode 17)
;;; before decode-instruction to avoid decode-u64 overflow.
(defun td-translate-fn-body-li-safe (state)
  (let ((bytes (translate-state-mvm-bytes state))
        (offset (translate-state-mvm-offset state))
        (len (translate-state-mvm-length state)))
    (let ((pos offset)
          (limit (+ offset len)))
      (loop
        (when (>= pos limit) (return nil))
        (let ((lbl-idx (- pos *td-label-base*)))
          (let ((label (aref *td-label-array* lbl-idx)))
            (when (not (zerop label))
              (emit-label (translate-state-buf state) label))))
        (if (= (aref bytes pos) 17)
            (progn
              (td-x64-emit-li-raw (translate-state-buf state) bytes pos)
              (setq pos (+ pos 10)))
            (let ((decoded (decode-instruction bytes pos)))
              (let ((opcode (car decoded))
                    (operands (car (cdr decoded)))
                    (new-pos (cdr (cdr decoded))))
                (cond
                  ((= opcode 32)
                   (td-emit-add (translate-state-buf state) operands))
                  ((= opcode 33)
                   (td-emit-sub (translate-state-buf state) operands))
                  ((= opcode 40)
                   (td-emit-and (translate-state-buf state) operands))
                  ((= opcode 41)
                   (td-emit-or (translate-state-buf state) operands))
                  ((= opcode 42)
                   (td-emit-xor (translate-state-buf state) operands))
                  ((= opcode 85)
                   (let ((vd (car operands))
                         (vs (car (cdr operands))))
                     (let ((buf2 (translate-state-buf state)))
                       (let ((d (dest-phys-or-scratch vd))
                             (true-label (make-label))
                             (end-label (make-label)))
                         (emit-load-vreg buf2 vs d)
                         (emit-and-reg-imm buf2 d 15)
                         (emit-cmp-reg-imm buf2 d 1)
                         (emit-jcc buf2 :e true-label)
                         (emit-mov-reg-reg buf2 d (quote r15))
                         (emit-jmp buf2 end-label)
                         (let ((p1 (code-buffer-position buf2)))
                           (aset true-label 1 p1))
                         (emit-mov-reg-imm buf2 d 3735883785)
                         (let ((p2 (code-buffer-position buf2)))
                           (aset end-label 1 p2))
                         (maybe-store-scratch buf2 vd)))))
                  ((= opcode 86)
                   (let ((vd (car operands))
                         (vs (car (cdr operands))))
                     (let ((buf2 (translate-state-buf state)))
                       (let ((d (dest-phys-or-scratch vd))
                             (true-label (make-label))
                             (end-label (make-label)))
                         (emit-load-vreg buf2 vs d)
                         (emit-and-reg-imm buf2 d 15)
                         (emit-cmp-reg-imm buf2 d 1)
                         (emit-jcc buf2 :ne true-label)
                         (emit-mov-reg-reg buf2 d (quote r15))
                         (emit-jmp buf2 end-label)
                         (let ((p1 (code-buffer-position buf2)))
                           (aset true-label 1 p1))
                         (emit-mov-reg-imm buf2 d 3735883785)
                         (let ((p2 (code-buffer-position buf2)))
                           (aset end-label 1 p2))
                         (maybe-store-scratch buf2 vd)))))
                  ((= opcode 137)
                   (let ((buf2 (translate-state-buf state)))
                     (let ((skip-label (make-label)))
                       (emit-cmp-reg-reg buf2 (quote r12) (quote r14))
                       (emit-jcc buf2 :l skip-label)
                       (let ((gc-lbl (translate-state-gc-label state)))
                         (if gc-lbl
                             (emit-call buf2 gc-lbl)
                             (emit-int buf2 49)))
                       (let ((p1 (code-buffer-position buf2)))
                         (aset skip-label 1 p1)))))
                  ((= opcode 131)
                   (let ((target-offset (car operands)))
                     (let ((buf2 (translate-state-buf state))
                           (label (aref *td-fn-label-array* target-offset)))
                       (emit-mov-reg-mem buf2 (quote rbx) (quote rbp) -8)
                       (emit-mov-reg-reg buf2 (quote rsp) (quote rbp))
                       (emit-pop buf2 (quote rbp))
                       (if (zerop label)
                           (emit-jmp buf2 (make-label))
                           (emit-jmp buf2 label)))))
                  ((= opcode 128)
                   (let ((target-offset (car operands)))
                     (let ((label (aref *td-fn-label-array* target-offset)))
                       (if (zerop label)
                           (emit-call (translate-state-buf state) (make-label))
                           (emit-call (translate-state-buf state) label)))))
                  ((= opcode 167)
                   (let ((vd (car operands))
                         (target-offset (car (cdr operands))))
                     (let ((label (aref *td-fn-label-array* target-offset)))
                       (let ((d (dest-phys-or-scratch vd)))
                         (if (zerop label)
                             (emit-mov-reg-imm (translate-state-buf state) d 0)
                             (emit-lea-label (translate-state-buf state) d label))
                         (maybe-store-scratch (translate-state-buf state) vd)))))
                  (t
                   (translate-instruction state opcode operands new-pos)))
                (setq pos new-pos))))))))

;;; i386-safe td-translate-one-fn: uses td-translate-fn-body-li-safe
;;; instead of td-translate-fn-body (avoids last-defun-wins override).
(defun td-translate-one-fn-i386 (ctx fn-label offset len)
  (let ((buf (car ctx))
        (bytecode (car (cdr ctx)))
        (fn-offset-to-label (cdr (cdr ctx))))
    (let ((state (make-translate-state)))
      (set-translate-state-buf state buf)
      (set-translate-state-mvm-bytes state bytecode)
      (set-translate-state-mvm-length state len)
      (set-translate-state-mvm-offset state offset)
      (set-translate-state-function-table state fn-offset-to-label)
      (let ((lpos (code-buffer-position buf)))
        (aset fn-label 1 lpos)
        (let ((labels-ht (code-buffer-labels buf)))
          (puthash fn-label labels-ht lpos)))
      (emit-function-prologue buf)
      (setq *td-label-array* (make-array len))
      (setq *td-label-base* offset)
      (scan-branch-targets state)
      (td-translate-fn-body-li-safe state))))

;;; i386-safe translate-mvm-to-x64: uses td-translate-one-fn-i386.
;;; Does NOT override translate-mvm-to-x64 (avoids breaking x64/AArch64 hosts).
(defun translate-mvm-to-x64-from-i386 (bytecode function-table)
  (let ((buf (make-code-buffer)))
    (let ((n-functions (length function-table)))
      (print-dec n-functions) (write-char-serial 10)
      (let ((fn-labels (make-array n-functions)))
        (let ((fn-map (make-hash-table))
              (fn-offset-to-label (make-hash-table)))
          (setq *td-fn-label-array* (make-array (array-length bytecode)))
          (let ((rest-ft function-table)
                (i 0))
            (loop
              (when (>= i n-functions) (return nil))
              (let ((entry (car rest-ft)))
                (let ((name (car entry))
                      (offset (car (cdr entry))))
                  (let ((label (make-label)))
                    (aset fn-labels i label)
                    (puthash name fn-map label)
                    (puthash offset fn-offset-to-label label)
                    (let ((dummy (aset *td-fn-label-array* offset label)))
                      dummy))))
              (setq rest-ft (cdr rest-ft))
              (setq i (+ i 1))))
          (write-char-serial 84) (write-char-serial 10)
          (let ((ctx (cons buf (cons bytecode fn-offset-to-label))))
            (let ((rest-ft function-table)
                  (i 0))
              (loop
                (when (>= i n-functions) (return nil))
                (let ((entry (car rest-ft)))
                  (let ((offset (car (cdr entry)))
                        (len (car (cdr (cdr entry)))))
                    (let ((fn-label (aref fn-labels i)))
                      (td-translate-one-fn-i386 ctx fn-label offset len))))
                (setq rest-ft (cdr rest-ft))
                (setq i (+ i 1))
                (when (zerop (mod i 50))
                  (write-char-serial 35)
                  (print-dec i)
                  (write-char-serial 10)))))
          (fixup-labels buf)
          (let ((pos (code-buffer-position buf))
                (bytes (code-buffer-bytes buf)))
            (print-dec pos) (write-char-serial 10)
            (let ((fnv (td-fnv-native bytes pos)))
              (write-char-serial 70) (write-char-serial 78)
              (write-char-serial 86) (write-char-serial 58)
              (print-dec fnv) (write-char-serial 10)))
          (cons buf fn-map))))))

;;; i386-safe td-assemble-gen1-x64-i386: raw byte copies avoid u32 overflow.
;;; Separate name avoids clobbering td-assemble-gen1-x64 used by AArch64→x64.
(defun td-assemble-gen1-x64-i386 (result bc ft)
  (let ((buf (car result))
        (fn-map (cdr result)))
    (let ((native-bytes (code-buffer-bytes buf))
          (native-size (code-buffer-position buf)))
      (img-init)
      (write-char-serial 88) (write-char-serial 49)
      (write-char-serial 58) (write-char-serial 10)
      (let ((boot-size (td-generate-x64-boot)))
        (write-char-serial 80)
        (print-dec boot-size) (write-char-serial 10)
        ;; JMP rel32 to kernel-main
        (let ((km-hash (td-read-u32 #x380028)))
          (let ((km-label (gethash km-hash fn-map)))
            (let ((km-offset 0))
              (when km-label
                (setq km-offset (aref km-label 1)))
              (img-emit 233)
              (img-emit-u32 km-offset))))
        ;; Copy native code
        (write-char-serial 78)
        (td-write-u32 #x380050 (img-pos))
        (let ((i 0))
          (loop
            (when (>= i native-size) (return nil))
            (img-emit (aref native-bytes i))
            (setq i (+ i 1))
            (when (zerop (mod i 50000))
              (write-char-serial 46))))
        (write-char-serial 10)
        ;; Append bytecodes
        (write-char-serial 84)
        (let ((bc-len (array-length bc))
              (bc-img-offset (img-pos)))
          (let ((bi 0))
            (loop
              (when (>= bi bc-len) (return nil))
              (img-emit (aref bc bi))
              (setq bi (+ bi 1))))
          ;; Append function table — raw byte copy from source image
          ;; (avoids u32 overflow for name hashes with byte 3 >= 0x80 on i386)
          (let ((ft-img-offset (img-pos))
                (src-ft-addr (+ (td-read-u32 #x380030) (td-read-u32 #x380014)))
                (ft-count (td-read-u32 #x380018)))
            (let ((total-ft-bytes (* ft-count 12))
                  (bi 0))
              (loop
                (when (>= bi total-ft-bytes) (return nil))
                (img-emit (mem-ref (+ src-ft-addr bi) :u8))
                (setq bi (+ bi 1))))
            (write-char-serial 10)
            (print-dec ft-count) (write-char-serial 10)
            ;; Metadata at 0x280000
            (let ((md-img-off #x280000))
              ;; magic MVMT = 0x544D564D — write as individual bytes
              ;; (0x544D564D > 2^30, overflows i386 30-bit fixnum)
              (let ((base (+ #x08000000 md-img-off)))
                (setf (mem-ref base :u8) #x4D)
                (setf (mem-ref (+ base 1) :u8) #x56)
                (setf (mem-ref (+ base 2) :u8) #x4D)
                (setf (mem-ref (+ base 3) :u8) #x54))
              (img-patch-u32 (+ md-img-off 4) 1)
              ;; my-architecture = 0 (x64)
              (img-patch-u32 (+ md-img-off 8) 0)
              (img-patch-u32 (+ md-img-off 12) bc-img-offset)
              (img-patch-u32 (+ md-img-off 16) bc-len)
              (img-patch-u32 (+ md-img-off 20) ft-img-offset)
              (img-patch-u32 (+ md-img-off 24) ft-count)
              (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x380050))
              (img-patch-u32 (+ md-img-off 32) native-size)
              (img-patch-u32 (+ md-img-off 36) boot-size)
              ;; kernel-main-hash-lo — raw byte copy (avoids u32 overflow on i386)
              (let ((dst-base (+ #x08000000 md-img-off 40)))
                (setf (mem-ref dst-base :u8) (mem-ref #x380028 :u8))
                (setf (mem-ref (+ dst-base 1) :u8) (mem-ref #x380029 :u8))
                (setf (mem-ref (+ dst-base 2) :u8) (mem-ref #x38002A :u8))
                (setf (mem-ref (+ dst-base 3) :u8) (mem-ref #x38002B :u8)))
              ;; kernel-main-native-offset
              (let ((km-label (gethash (td-read-u32 #x380028) fn-map)))
                (if km-label
                    (img-patch-u32 (+ md-img-off 44) (aref km-label 1))
                    (img-patch-u32 (+ md-img-off 44) 0)))
              ;; image-load-addr = 0x100000 (x64)
              (img-patch-u32 (+ md-img-off 48) #x100000)
              ;; target-architecture (default: 1=aarch64)
              (img-patch-u32 (+ md-img-off 52) 1)
              ;; mode (default: 0=cross-compile)
              (img-patch-u32 (+ md-img-off 56) 0))
            ;; Patch multiboot header
            (let ((total-size (+ #x280000 64)))
              (let ((load-end (+ #x100000 total-size)))
                (img-patch-u32 20 load-end)
                (img-patch-u32 24 load-end))
              (write-char-serial 88) (write-char-serial 49)
              (write-char-serial 61)
              (print-dec total-size) (write-char-serial 10)
              total-size)))))))

;;; Build x64 target from i386 host
(defun build-x64-from-i386 (bc ft)
  (let ((result (translate-mvm-to-x64-from-i386 bc ft)))
    (let ((buf (car result)))
      (let ((native-size (code-buffer-position buf)))
        (print-dec native-size) (write-char-serial 10)
        (let ((native-bytes (code-buffer-bytes buf)))
          (let ((hash (td-fnv-native native-bytes native-size)))
            (write-char-serial 70) (write-char-serial 78)
            (write-char-serial 86) (write-char-serial 58)
            (print-dec hash) (write-char-serial 10)))
        (td-assemble-gen1-x64-i386 result bc ft)
        native-size))))


;;; ================================================================
;;; i386-safe AArch64 translator (byte-level emission)
;;; All instruction encodings use byte3/lo24 split to avoid
;;; 30-bit fixnum overflow on i386 (where ash 1 31 = 0).
;;; ================================================================

;;; Pre-generated AArch64 boot preamble (4096 bytes)
;;; Generated at SBCL build time from emit-aarch64-fixpoint-entry
(defvar *a64-boot-preamble-size* 4096)
(defvar *a64-boot-preamble-packed* nil)
(defun a64i-init-boot-preamble ()
  (let ((p (make-array 1366)))
    ;; Indices 0-255: constant-index aset (OBJ-SET imm8 safe)
    (aset p 0 11012112)
    (aset p 1 139218)
    (aset p 2 37120)
    (aset p 3 13795328)
    (aset p 4 11010080)
    (aset p 5 498)
    (aset p 6 184960)
    (aset p 7 13795392)
    (aset p 8 33823)
    (aset p 9 279288)
    (aset p 10 12767488)
    (aset p 11 11927551)
    (aset p 12 8519680)
    (aset p 13 8402)
    (aset p 14 193192)
    (aset p 15 13795392)
    (aset p 16 33823)
    (aset p 17 279288)
    (aset p 18 12767488)
    (aset p 19 11927551)
    (aset p 20 8388608)
    (aset p 21 8402)
    (aset p 22 6419112)
    (aset p 23 13795840)
    (aset p 24 11010081)
    (aset p 25 498)
    (aset p 26 2226432)
    (aset p 27 13795552)
    (aset p 28 11010049)
    (aset p 29 262642)
    (aset p 30 63744)
    (aset p 31 13795584)
    (aset p 32 11010080)
    (aset p 33 14721522)
    (aset p 34 119424)
    (aset p 35 15908872)
    (aset p 36 1)
    (aset p 37 249)
    (aset p 38 2151040)
    (aset p 39 15902720)
    (aset p 40 8519680)
    (aset p 41 8402)
    (aset p 42 2224808)
    (aset p 43 13795552)
    (aset p 44 11010049)
    (aset p 45 2097906)
    (aset p 46 250496)
    (aset p 47 13795328)
    (aset p 48 10486787)
    (aset p 49 8651250)
    (aset p 50 2226176)
    (aset p 51 9110272)
    (aset p 52 1090)
    (aset p 53 16753361)
    (aset p 54 46591)
    (aset p 55 13796096)
    (aset p 56 11010080)
    (aset p 57 14721522)
    (aset p 58 119424)
    (aset p 59 15900960)
    (aset p 60 1)
    (aset p 61 8388857)
    (aset p 62 2151042)
    (aset p 63 15902720)
    (aset p 64 8446113)
    (aset p 65 466)
    (aset p 66 127650)
    (aset p 67 16318464)
    (aset p 68 8396768)
    (aset p 69 10617042)
    (aset p 70 2151704)
    (aset p 71 13797027)
    (aset p 72 12582976)
    (aset p 73 2113778)
    (aset p 74 54552)
    (aset p 75 13795328)
    (aset p 76 11010080)
    (aset p 77 2097394)
    (aset p 78 10474776)
    (aset p 79 13959995)
    (aset p 80 212959)
    (aset p 81 1048789)
    (aset p 82 10605880)
    (aset p 83 13795840)
    (aset p 84 65536)
    (aset p 85 1048746)
    (aset p 86 14669080)
    (aset p 87 13959999)
    (aset p 88 8388624)
    (aset p 89 266450)
    (aset p 90 2093728)
    (aset p 91 9502722)
    (aset p 92 8388625)
    (aset p 93 4562)
    (aset p 94 2159268)
    (aset p 95 13795424)
    (aset p 96 12832)
    (aset p 97 917689)
    (aset p 98 2151040)
    (aset p 99 12124206)
    (aset p 100 8389024)
    (aset p 101 2498770)
    (aset p 102 2144512)
    (aset p 103 13795328)
    (aset p 104 10784)
    (aset p 105 6299833)
    (aset p 106 2151040)
    (aset p 107 12124210)
    (aset p 108 8388632)
    (aset p 109 8394962)
    (aset p 110 1700512)
    (aset p 111 13795328)
    (aset p 112 10550809)
    (aset p 113 6898)
    (aset p 114 1102464)
    (aset p 115 13795328)
    (aset p 116 10487504)
    (aset p 117 13668594)
    (aset p 118 1103128)
    (aset p 119 13795584)
    (aset p 120 1622032)
    (aset p 121 4186069)
    (aset p 122 10802435)
    (aset p 123 1310723)
    (aset p 124 204831)
    (aset p 125 2105301)
    (aset p 126 2086147)
    (aset p 127 13959968)
    (aset p 128 204831)
    (aset p 129 2105301)
    (aset p 130 2086147)
    (aset p 131 13959968)
    (aset p 132 204831)
    (aset p 133 2105301)
    (aset p 134 2086147)
    (aset p 135 13959968)
    (aset p 136 204831)
    (aset p 137 2105301)
    (aset p 138 2086147)
    (aset p 139 13959968)
    (aset p 140 204831)
    (aset p 141 2105301)
    (aset p 142 2086147)
    (aset p 143 13959968)
    (aset p 144 204831)
    (aset p 145 2105301)
    (aset p 146 2086147)
    (aset p 147 13959968)
    (aset p 148 204831)
    (aset p 149 2105301)
    (aset p 150 2086147)
    (aset p 151 13959968)
    (aset p 152 204831)
    (aset p 153 2105301)
    (aset p 154 2086147)
    (aset p 155 13959968)
    (aset p 156 204831)
    (aset p 157 2105301)
    (aset p 158 2086147)
    (aset p 159 13959968)
    (aset p 160 204831)
    (aset p 161 2105301)
    (aset p 162 2086147)
    (aset p 163 13959968)
    (aset p 164 204831)
    (aset p 165 2105301)
    (aset p 166 2086147)
    (aset p 167 13959968)
    (aset p 168 204831)
    (aset p 169 2105301)
    (aset p 170 2086147)
    (aset p 171 13959968)
    (aset p 172 204831)
    (aset p 173 2105301)
    (aset p 174 2086147)
    (aset p 175 13959968)
    (aset p 176 204831)
    (aset p 177 2105301)
    (aset p 178 2086147)
    (aset p 179 13959968)
    (aset p 180 204831)
    (aset p 181 2105301)
    (aset p 182 2086147)
    (aset p 183 13959968)
    (aset p 184 204831)
    (aset p 185 2105301)
    (aset p 186 2086147)
    (aset p 187 13959968)
    (aset p 188 204831)
    (aset p 189 2105301)
    (aset p 190 2086147)
    (aset p 191 13959968)
    (aset p 192 204831)
    (aset p 193 2105301)
    (aset p 194 2086147)
    (aset p 195 13959968)
    (aset p 196 204831)
    (aset p 197 2105301)
    (aset p 198 2086147)
    (aset p 199 13959968)
    (aset p 200 204831)
    (aset p 201 2105301)
    (aset p 202 2086147)
    (aset p 203 13959968)
    (aset p 204 204831)
    (aset p 205 2105301)
    (aset p 206 2086147)
    (aset p 207 13959968)
    (aset p 208 204831)
    (aset p 209 2105301)
    (aset p 210 2086147)
    (aset p 211 13959968)
    (aset p 212 204831)
    (aset p 213 2105301)
    (aset p 214 2086147)
    (aset p 215 13959968)
    (aset p 216 204831)
    (aset p 217 2105301)
    (aset p 218 2086147)
    (aset p 219 13959968)
    (aset p 220 204831)
    (aset p 221 2105301)
    (aset p 222 2086147)
    (aset p 223 13959968)
    (aset p 224 204831)
    (aset p 225 2105301)
    (aset p 226 2086147)
    (aset p 227 13959968)
    (aset p 228 204831)
    (aset p 229 2105301)
    (aset p 230 2086147)
    (aset p 231 13959968)
    (aset p 232 204831)
    (aset p 233 2105301)
    (aset p 234 2086147)
    (aset p 235 13959968)
    (aset p 236 204831)
    (aset p 237 2105301)
    (aset p 238 2086147)
    (aset p 239 13959968)
    (aset p 240 204831)
    (aset p 241 2105301)
    (aset p 242 2086147)
    (aset p 243 13959968)
    (aset p 244 204831)
    (aset p 245 2105301)
    (aset p 246 2086147)
    (aset p 247 13959968)
    (aset p 248 204831)
    (aset p 249 2105301)
    (aset p 250 2086147)
    (aset p 251 13959968)
    (aset p 252 204831)
    (aset p 253 2105301)
    (aset p 254 2086147)
    (aset p 255 13959968)
    ;; Indices 256+: variable-index aset (avoids OBJ-SET imm8 overflow)
    (let ((i 256))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 54531) (setq i (+ i 1))
      (aset p i 1310720) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 213) (setq i (+ i 1))
      (aset p i 2036736) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 0) (setq i (+ i 1))
      (aset p i 2105108) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 54531) (setq i (+ i 1))
      (aset p i 1310720) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 213) (setq i (+ i 1))
      (aset p i 2036736) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 12519392) (setq i (+ i 1))
      (aset p i 8361) (setq i (+ i 1))
      (aset p i 119457) (setq i (+ i 1))
      (aset p i 12140556) (setq i (+ i 1))
      (aset p i 4097) (setq i (+ i 1))
      (aset p i 516281) (setq i (+ i 1))
      (aset p i 14723265) (setq i (+ i 1))
      (aset p i 14065411) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 54531) (setq i (+ i 1))
      (aset p i 1310720) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 213) (setq i (+ i 1))
      (aset p i 2036736) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 0) (setq i (+ i 1))
      (aset p i 2105108) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 54531) (setq i (+ i 1))
      (aset p i 1310720) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 213) (setq i (+ i 1))
      (aset p i 2036736) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 0) (setq i (+ i 1))
      (aset p i 2105108) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 54531) (setq i (+ i 1))
      (aset p i 1310720) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 213) (setq i (+ i 1))
      (aset p i 2036736) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 0) (setq i (+ i 1))
      (aset p i 2105108) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 54531) (setq i (+ i 1))
      (aset p i 1310720) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 2105301) (setq i (+ i 1))
      (aset p i 2086147) (setq i (+ i 1))
      (aset p i 13959968) (setq i (+ i 1))
      (aset p i 204831) (setq i (+ i 1))
      (aset p i 213) (setq i (+ i 1))
    )
    (setq *a64-boot-preamble-packed* p)
    (setq *a64-boot-preamble-size* 4096)))


;;; i386-safe AArch64 code buffer (byte-based)
;;; buf = (bytes . (pos . (labels . fixups)))
(defun make-a64i-buffer ()
  (let ((bytes (make-array 2097152)))
    (cons bytes (cons 0 (cons (make-hash-table) nil)))))

(defun a64i-buf-bytes (buf) (car buf))
(defun a64i-buf-pos (buf) (car (cdr buf)))
(defun a64i-buf-labels (buf) (car (cdr (cdr buf))))
(defun a64i-buf-fixups (buf) (cdr (cdr (cdr buf))))
(defun a64i-set-pos (buf p) (set-car (cdr buf) p))
(defun a64i-set-fixups (buf f) (set-cdr (cdr (cdr buf)) f))

(defun a64i-emit (buf b3 lo24)
  (let ((bytes (a64i-buf-bytes buf))
        (pos (a64i-buf-pos buf)))
    (aset bytes pos (logand lo24 255))
    (aset bytes (+ pos 1) (logand (ash lo24 -8) 255))
    (aset bytes (+ pos 2) (logand (ash lo24 -16) 255))
    (aset bytes (+ pos 3) b3)
    (a64i-set-pos buf (+ pos 4))))

(defun a64i-emit-raw (buf b0 b1 b2 b3)
  (let ((bytes (a64i-buf-bytes buf))
        (pos (a64i-buf-pos buf)))
    (aset bytes pos b0)
    (aset bytes (+ pos 1) b1)
    (aset bytes (+ pos 2) b2)
    (aset bytes (+ pos 3) b3)
    (a64i-set-pos buf (+ pos 4))))

(defun a64i-current-index (buf) (ash (a64i-buf-pos buf) -2))

(defun a64i-set-label (buf label-id)
  (puthash label-id (a64i-buf-labels buf) (a64i-current-index buf)))

(defun a64i-add-fixup (buf index label-id type)
  (a64i-set-fixups buf (cons (cons index (cons label-id type)) (a64i-buf-fixups buf))))

;;; AArch64 encoder functions (i386-safe byte3/lo24 split)

(defun a64i-add-reg (buf rd rn rm shift amount)
  (a64i-emit buf #x8B (logior (ash shift 22) (ash rm 16) (ash amount 10) (ash rn 5) rd)))

(defun a64i-sub-reg (buf rd rn rm shift amount)
  (a64i-emit buf #xCB (logior (ash shift 22) (ash rm 16) (ash amount 10) (ash rn 5) rd)))

(defun a64i-subs-reg (buf rd rn rm shift amount)
  (a64i-emit buf #xEB (logior (ash shift 22) (ash rm 16) (ash amount 10) (ash rn 5) rd)))

(defun a64i-cmp-reg (buf rn rm)
  (a64i-subs-reg buf 31 rn rm 0 0))

(defun a64i-add-imm (buf rd rn imm12 shift)
  (let ((sh (if (= shift 12) 1 0)))
    (a64i-emit buf #x91 (logior (ash sh 22) (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64i-sub-imm (buf rd rn imm12 shift)
  (let ((sh (if (= shift 12) 1 0)))
    (a64i-emit buf #xD1 (logior (ash sh 22) (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64i-adds-imm (buf rd rn imm12 shift)
  (let ((sh (if (= shift 12) 1 0)))
    (a64i-emit buf #xB1 (logior (ash sh 22) (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64i-subs-imm (buf rd rn imm12 shift)
  (let ((sh (if (= shift 12) 1 0)))
    (a64i-emit buf #xF1 (logior (ash sh 22) (ash (logand imm12 4095) 10) (ash rn 5) rd))))

(defun a64i-cmp-imm (buf rn imm12)
  (a64i-subs-imm buf 31 rn imm12 0))

(defun a64i-and-reg (buf rd rn rm)
  (a64i-emit buf #x8A (logior (ash rm 16) (ash rn 5) rd)))

(defun a64i-orr-reg (buf rd rn rm)
  (a64i-emit buf #xAA (logior (ash rm 16) (ash rn 5) rd)))

(defun a64i-eor-reg (buf rd rn rm)
  (a64i-emit buf #xCA (logior (ash rm 16) (ash rn 5) rd)))

(defun a64i-ands-reg (buf rd rn rm)
  (a64i-emit buf #xEA (logior (ash rm 16) (ash rn 5) rd)))

(defun a64i-tst-reg (buf rn rm)
  (a64i-ands-reg buf 31 rn rm))

(defun a64i-mov-reg (buf rd rm)
  (a64i-emit buf #xAA (logior (ash rm 16) (ash 31 5) rd)))

(defun a64i-movz (buf rd imm16 hw)
  (a64i-emit buf #xD2 (logior (ash 1 23) (ash (logand hw 3) 21) (ash (logand imm16 65535) 5) rd)))

(defun a64i-movk (buf rd imm16 hw)
  (a64i-emit buf #xF2 (logior (ash 1 23) (ash (logand hw 3) 21) (ash (logand imm16 65535) 5) rd)))

(defun a64i-movn (buf rd imm16 hw)
  (a64i-emit buf #x92 (logior (ash 1 23) (ash (logand hw 3) 21) (ash (logand imm16 65535) 5) rd)))

(defun a64i-ubfm (buf rd rn immr imms)
  (a64i-emit buf #xD3 (logior (ash 1 22) (ash (logand immr 63) 16) (ash (logand imms 63) 10) (ash rn 5) rd)))

(defun a64i-sbfm (buf rd rn immr imms)
  (a64i-emit buf #x93 (logior (ash 1 22) (ash (logand immr 63) 16) (ash (logand imms 63) 10) (ash rn 5) rd)))

(defun a64i-lsr-imm (buf rd rn amount) (a64i-ubfm buf rd rn amount 63))
(defun a64i-lsl-imm (buf rd rn amount) (a64i-ubfm buf rd rn (logand (- 64 amount) 63) (- 63 amount)))
(defun a64i-asr-imm (buf rd rn amount) (a64i-sbfm buf rd rn amount 63))

(defun a64i-mul (buf rd rn rm)
  (a64i-emit buf #x9B (logior (ash rm 16) (ash 31 10) (ash rn 5) rd)))

(defun a64i-sdiv (buf rd rn rm)
  (a64i-emit buf #x9A (logior (ash 6 21) (ash rm 16) (ash 3 10) (ash rn 5) rd)))

(defun a64i-lslv (buf rd rn rm)
  (a64i-emit buf #x9A (logior (ash 6 21) (ash rm 16) (ash 8 10) (ash rn 5) rd)))

(defun a64i-asrv (buf rd rn rm)
  (a64i-emit buf #x9A (logior (ash 6 21) (ash rm 16) (ash 10 10) (ash rn 5) rd)))

(defun a64i-neg (buf rd rm) (a64i-sub-reg buf rd 31 rm 0 0))

(defun a64i-ldur (buf rt rn simm9)
  (a64i-emit buf #xF8 (logior (ash 1 22) (ash (logand simm9 511) 12) (ash rn 5) rt)))

(defun a64i-stur (buf rt rn simm9)
  (a64i-emit buf #xF8 (logior (ash (logand simm9 511) 12) (ash rn 5) rt)))

(defun a64i-ldr-width (buf rt rn offset width)
  (let ((b3 (cond ((= width 0) #x38) ((= width 1) #x78) ((= width 2) #xB8) (t #xF8))))
    (a64i-emit buf b3 (logior (ash 1 22) (ash (logand offset 511) 12) (ash rn 5) rt))))

(defun a64i-str-width (buf rt rn offset width)
  (let ((b3 (cond ((= width 0) #x38) ((= width 1) #x78) ((= width 2) #xB8) (t #xF8))))
    (a64i-emit buf b3 (logior (ash (logand offset 511) 12) (ash rn 5) rt))))

(defun a64i-ldr-unsigned (buf rt rn imm12)
  (let ((scaled (ash imm12 -3)))
    (a64i-emit buf #xF9 (logior (ash 1 22) (ash (logand scaled 4095) 10) (ash rn 5) rt))))

(defun a64i-str-unsigned (buf rt rn imm12)
  (let ((scaled (ash imm12 -3)))
    (a64i-emit buf #xF9 (logior (ash (logand scaled 4095) 10) (ash rn 5) rt))))

(defun a64i-stp-offset (buf rt1 rt2 rn simm7)
  (let ((scaled (ash simm7 -3)))
    (a64i-emit buf #xA9 (logior (ash (logand scaled 127) 15) (ash rt2 10) (ash rn 5) rt1))))

(defun a64i-ldp-offset (buf rt1 rt2 rn simm7)
  (let ((scaled (ash simm7 -3)))
    (a64i-emit buf #xA9 (logior (ash 1 22) (ash (logand scaled 127) 15) (ash rt2 10) (ash rn 5) rt1))))

(defun a64i-stp-pre (buf rt1 rt2 rn simm7)
  (let ((scaled (ash simm7 -3)))
    (a64i-emit buf #xA9 (logior (ash 1 23) (ash (logand scaled 127) 15) (ash rt2 10) (ash rn 5) rt1))))

(defun a64i-ldp-post (buf rt1 rt2 rn simm7)
  (let ((scaled (ash simm7 -3)))
    (a64i-emit buf #xA8 (logior (ash 3 22) (ash (logand scaled 127) 15) (ash rt2 10) (ash rn 5) rt1))))

(defun a64i-str-pre (buf rt rn simm9)
  (a64i-emit buf #xF8 (logior (ash (logand simm9 511) 12) (ash 3 10) (ash rn 5) rt)))

(defun a64i-ldr-post (buf rt rn simm9)
  (a64i-emit buf #xF8 (logior (ash 1 22) (ash (logand simm9 511) 12) (ash 1 10) (ash rn 5) rt)))

(defun a64i-b (buf imm26)
  (let ((masked (logand imm26 67108863)))
    (a64i-emit buf (logior 20 (logand (ash masked -24) 3))
                (logand masked 16777215))))

(defun a64i-bl (buf imm26)
  (let ((masked (logand imm26 67108863)))
    (a64i-emit buf (logior 148 (logand (ash masked -24) 3))
                (logand masked 16777215))))

(defun a64i-bcond (buf cond imm19)
  (a64i-emit buf #x54 (logior (ash (logand imm19 524287) 5) (logand cond 15))))

(defun a64i-ret (buf rn) (a64i-emit buf #xD6 (logior (ash 95 16) (ash rn 5))))
(defun a64i-br (buf rn) (a64i-emit buf #xD6 (logior (ash 31 16) (ash rn 5))))
(defun a64i-blr (buf rn) (a64i-emit buf #xD6 (logior (ash 63 16) (ash rn 5))))

(defun a64i-nop (buf) (a64i-emit buf #xD5 #x03201F))
(defun a64i-sev (buf) (a64i-emit buf #xD5 #x03209F))
(defun a64i-wfe (buf) (a64i-emit buf #xD5 #x03205F))
(defun a64i-wfi (buf) (a64i-emit buf #xD5 #x03207F))
(defun a64i-isb (buf) (a64i-emit buf #xD5 #x033FDF))

(defun a64i-brk (buf imm16) (a64i-emit buf #xD4 (logior (ash 1 21) (ash (logand imm16 65535) 5))))
(defun a64i-svc (buf imm16) (a64i-emit buf #xD4 (logior 1 (ash (logand imm16 65535) 5))))

(defun a64i-dmb (buf option)
  (a64i-emit buf #xD5 (logior (ash 3 16) (ash 3 12) (ash (logand option 15) 8) (ash 5 5) 31)))

(defun a64i-dsb (buf option)
  (a64i-emit buf #xD5 (logior (ash 3 16) (ash 3 12) (ash (logand option 15) 8) (ash 4 5) 31)))

(defun a64i-mrs (buf rt sysreg) (a64i-emit buf #xD5 (logior (ash 3 20) (ash sysreg 5) rt)))
(defun a64i-msr-sysreg (buf sysreg rt) (a64i-emit buf #xD5 (logior (ash 1 20) (ash sysreg 5) rt)))

(defun a64i-msr-daifset (buf imm4) (a64i-emit buf #xD5 (logior (ash 3 16) (ash 4 12) (ash (logand imm4 15) 8) (ash 6 5) 31)))
(defun a64i-msr-daifclr (buf imm4) (a64i-emit buf #xD5 (logior (ash 3 16) (ash 4 12) (ash (logand imm4 15) 8) (ash 7 5) 31)))

(defun a64i-ldxr (buf rt rn) (a64i-emit buf #xC8 (logior (ash 95 16) (ash 31 10) (ash rn 5) rt)))
(defun a64i-stxr (buf rs rt rn) (a64i-emit buf #xC8 (logior (ash rs 16) (ash 31 10) (ash rn 5) rt)))

(defun a64i-cset (buf rd cond)
  (let ((inv (logxor cond 1)))
    (a64i-emit buf #x9A (logior (ash 1 23) (ash 31 16) (ash inv 12) (ash 1 10) (ash 31 5) rd))))

(defun a64i-cbnz-w (buf rt offset19)
  (a64i-emit buf #x35 (logior (ash (logand offset19 524287) 5) rt)))

(defun a64i-tbnz (buf rt bit-num imm14)
  (a64i-emit buf #x37 (logior (ash (logand bit-num 31) 19) (ash (logand imm14 16383) 5) rt)))

(defun a64i-cbnz (buf rt offset19)
  (a64i-emit buf #xB5 (logior (ash (logand offset19 524287) 5) rt)))

;;; Load 64-bit immediate from bytecodes (reads raw 16-bit half-words)
;;; Must match a64-load-imm64 optimization exactly:
;;;   1. Zero -> MOVZ rd, 0
;;;   2. Single non-zero halfword -> MOVZ at that position
;;;   3. MOVN: if inverted value has single non-zero halfword
;;;   4. General: MOVZ first non-zero, MOVK rest
(defun a64i-load-imm64-raw (buf rd bytecode pos)
  (let ((hw0 (+ (aref bytecode pos) (ash (aref bytecode (+ pos 1)) 8))))
    (let ((hw1 (+ (aref bytecode (+ pos 2)) (ash (aref bytecode (+ pos 3)) 8))))
      (let ((hw2 (+ (aref bytecode (+ pos 4)) (ash (aref bytecode (+ pos 5)) 8))))
        (let ((hw3 (+ (aref bytecode (+ pos 6)) (ash (aref bytecode (+ pos 7)) 8))))
          ;; Count non-zero halfwords
          (let ((nz (+ (if (zerop hw0) 0 1)
                       (+ (if (zerop hw1) 0 1)
                          (+ (if (zerop hw2) 0 1)
                             (if (zerop hw3) 0 1))))))
            (cond
              ;; All zero
              ((= nz 0) (a64i-movz buf rd 0 0))
              ;; Single non-zero halfword
              ((= nz 1)
               (cond
                 ((not (zerop hw0)) (a64i-movz buf rd hw0 0))
                 ((not (zerop hw1)) (a64i-movz buf rd hw1 1))
                 ((not (zerop hw2)) (a64i-movz buf rd hw2 2))
                 (t (a64i-movz buf rd hw3 3))))
              ;; General: MOVZ first non-zero, MOVK rest (no MOVN - must match bare-metal a64-load-imm64)
              (t
               (cond
                 ((not (zerop hw0))
                  (a64i-movz buf rd hw0 0)
                  (when (not (zerop hw1)) (a64i-movk buf rd hw1 1))
                  (when (not (zerop hw2)) (a64i-movk buf rd hw2 2))
                  (when (not (zerop hw3)) (a64i-movk buf rd hw3 3)))
                 ((not (zerop hw1))
                  (a64i-movz buf rd hw1 1)
                  (when (not (zerop hw2)) (a64i-movk buf rd hw2 2))
                  (when (not (zerop hw3)) (a64i-movk buf rd hw3 3)))
                 ((not (zerop hw2))
                  (a64i-movz buf rd hw2 2)
                  (when (not (zerop hw3)) (a64i-movk buf rd hw3 3)))
                 (t
                  (a64i-movz buf rd hw3 3)))))))))))

(defun a64i-load-imm64 (buf rd value)
  ;; Optimized for 32-bit values (up to 2 halfwords on i386)
  (let ((hw0 (logand value 65535)))
    (let ((hw1 (logand (ash value -16) 65535)))
      (let ((nz (+ (if (zerop hw0) 0 1) (if (zerop hw1) 0 1))))
        (cond
          ((= nz 0) (a64i-movz buf rd 0 0))
          ((= nz 1)
           (if (not (zerop hw0)) (a64i-movz buf rd hw0 0) (a64i-movz buf rd hw1 1)))
          (t (a64i-movz buf rd hw0 0) (a64i-movk buf rd hw1 1)))))))

;;; Spill slot helpers
(defun a64i-spill-offset (vreg) (+ -8 (* (- vreg 9) -8)))

;;; On bare-metal x64/aarch64, *a64-vreg-to-phys* slots 9-15 contain fixnum 0
;;; (not nil) because make-array ignores :initial-element on bare metal.
;;; So a64-phys-reg(V9) returns 0 (X0, truthy) and the translator treats V9-V15
;;; as mapped to X0 without spilling. To match, never report any VR as spilled.
(defun a64i-vreg-spilled-p (vreg) nil)

(defun a64i-emit-load-vreg (buf phys-dest vreg)
  (if (a64i-vreg-spilled-p vreg)
      (a64i-ldur buf phys-dest 29 (a64i-spill-offset vreg))
      (let ((phys (aref *a64-vreg-to-phys* vreg)))
        (when (not (= phys phys-dest)) (a64i-mov-reg buf phys-dest phys)))))

(defun a64i-emit-store-vreg (buf phys-src vreg)
  (if (a64i-vreg-spilled-p vreg)
      (a64i-stur buf phys-src 29 (a64i-spill-offset vreg))
      (let ((phys (aref *a64-vreg-to-phys* vreg)))
        (when (not (= phys phys-src)) (a64i-mov-reg buf phys phys-src)))))

(defun a64i-emit-prologue (buf)
  (a64i-stp-pre buf 29 30 31 -80)
  (a64i-add-imm buf 29 31 0 0)
  (a64i-stp-offset buf 19 20 31 16)
  (a64i-stp-offset buf 21 22 31 32)
  (a64i-stp-offset buf 23 31 31 48)
  (a64i-sub-imm buf 31 31 1024 0))

(defun a64i-emit-epilogue (buf)
  (a64i-add-imm buf 31 31 1024 0)
  (a64i-ldp-offset buf 23 31 31 48)
  (a64i-ldp-offset buf 21 22 31 32)
  (a64i-ldp-offset buf 19 20 31 16)
  (a64i-ldp-post buf 29 30 31 80)
  (a64i-ret buf 30))

;;; Fixup resolution (byte-based buffer)
(defun a64i-read-u32-at (buf idx)
  (let ((bytes (a64i-buf-bytes buf))
        (off (* idx 4)))
    (+ (aref bytes off) (ash (aref bytes (+ off 1)) 8)
       (ash (aref bytes (+ off 2)) 16))))

(defun a64i-write-bytes-at (buf idx b0 b1 b2 b3)
  (let ((bytes (a64i-buf-bytes buf))
        (off (* idx 4)))
    (aset bytes off b0)
    (aset bytes (+ off 1) b1)
    (aset bytes (+ off 2) b2)
    (aset bytes (+ off 3) b3)))

(defun a64i-resolve-fixups (buf)
  (let ((rest-fixups (a64i-buf-fixups buf))
        (labels (a64i-buf-labels buf)))
    (loop
      (when (null rest-fixups) (return nil))
      (let ((fixup (car rest-fixups)))
        (let ((index (car fixup))
              (label-id (car (cdr fixup)))
              (type (cdr (cdr fixup))))
          (let ((target (gethash label-id labels)))
            (when target
              (let ((offset (- target index)))
                (let ((masked (logand offset 67108863)))
                  (cond
                    ((eql type 126943983357610533)
                     (a64i-write-bytes-at buf index
                       (logand masked 255) (logand (ash masked -8) 255)
                       (logand (ash masked -16) 255) (logior 20 (logand (ash masked -24) 3))))
                    ((eql type 592037923804208769)
                     (a64i-write-bytes-at buf index
                       (logand masked 255) (logand (ash masked -8) 255)
                       (logand (ash masked -16) 255) (logior 148 (logand (ash masked -24) 3))))
                    ((eql type 248172622495451147)
                     (let ((cond-bits (logand (aref (a64i-buf-bytes buf) (* index 4)) 15)))
                       (let ((lo24 (logior (ash (logand offset 524287) 5) cond-bits)))
                         (a64i-write-bytes-at buf index
                           (logand lo24 255) (logand (ash lo24 -8) 255)
                           (logand (ash lo24 -16) 255) #x54))))
                    ((eql type 782868907041998776)
                     (let ((byte-off (* offset 4)))
                       (let ((immlo (logand byte-off 3)))
                         (let ((immhi (logand (ash byte-off -2) 524287)))
                           (let ((rd (logand (aref (a64i-buf-bytes buf) (* index 4)) 31)))
                             (let ((b3 (logior (ash immlo 5) 16)))
                               (let ((lo24 (logior (ash immhi 5) rd)))
                                 (a64i-write-bytes-at buf index
                                   (logand lo24 255) (logand (ash lo24 -8) 255)
                                   (logand (ash lo24 -16) 255) b3)))))))))))))))
      (setq rest-fixups (cdr rest-fixups)))))

;;; End of i386-safe AArch64 encoder functions


;;; ================================================================
;;; i386-safe AArch64 translation loop + pipeline
;;; ================================================================

;;; Store buf pointer for ensure-src-i386a64 / store-dst-i386a64
(defvar *a64i-current-buf* nil)
(defun a64i-set-current-buf (buf) (setq *a64i-current-buf* buf))
(defun a64i-get-current-buf () *a64i-current-buf*)

;;; ensure-src for i386 AArch64 translation
;;; Note: cannot use (if (a64-phys-reg vreg) ...) because nil=0=x0 on i386
(defun ensure-src-i386a64 (vreg scratch)
  (if (a64i-vreg-spilled-p vreg)
      (let ((buf (a64i-get-current-buf)))
        (a64i-emit-load-vreg buf scratch vreg)
        scratch)
      (aref *a64-vreg-to-phys* vreg)))

;;; store-dst for i386 AArch64 translation
(defun store-dst-i386a64 (phys-src vreg)
  (let ((buf (a64i-get-current-buf)))
    (a64i-emit-store-vreg buf phys-src vreg)))

;;; Translate a single MVM instruction to AArch64 using i386-safe encoders.
;;; opcode/operands come from decode-instruction.
;;; buf is a64i-buffer (byte-based).
;;; mvm-to-native-label maps MVM byte offsets to label IDs.
;;; insn-offset is the MVM byte offset of this instruction.
;;; insn-size is the byte size of this MVM instruction.
(defun a64i-translate-insn (buf op operands mvm-to-native-label insn-offset insn-size)
  (a64i-set-current-buf buf)
  (cond
    ;; NOP
    ((= op 0) (a64i-nop buf))
    ;; BREAK
    ((= op 1) (a64i-brk buf 0))
    ;; TRAP
    ((= op 2)
     (let ((code (car operands)))
       (a64i-translate-trap buf code)))
    ;; MOV Vd Vs
    ((= op 16)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (store-dst-i386a64 ps vd))))
    ;; LI: handled separately in td-a64i-translate-fn-body (never reaches here)
    ;; PUSH Vs
    ((= op 18)
     (let ((ps (ensure-src-i386a64 (car operands) 16)))
       (a64i-str-pre buf ps 31 -8)))
    ;; POP Vd
    ((= op 19)
     (if (a64i-vreg-spilled-p (car operands))
         (progn
           (a64i-ldr-post buf 16 31 8)
           (store-dst-i386a64 16 (car operands)))
         (a64i-ldr-post buf (aref *a64-vreg-to-phys* (car operands)) 31 8)))
    ;; ADD Vd Va Vb
    ((= op 32)
     (a64i-translate-binop-reg buf operands 0)) ; 0=ADD
    ;; SUB Vd Va Vb
    ((= op 33)
     (a64i-translate-binop-reg buf operands 1)) ; 1=SUB
    ;; MUL Vd Va Vb
    ((= op 34)
     (let ((vd (car operands))
           (va (car (cdr operands)))
           (vb (car (cdr (cdr operands)))))
       (let ((pa (ensure-src-i386a64 va 16))
             (pb (ensure-src-i386a64 vb 17)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-asr-imm buf 16 pa 1)
           (a64i-mul buf pd 16 pb)
           (a64i-maybe-store pd vd)))))
    ;; DIV Vd Va Vb
    ((= op 35)
     (let ((vd (car operands))
           (va (car (cdr operands)))
           (vb (car (cdr (cdr operands)))))
       (let ((pa (ensure-src-i386a64 va 16))
             (pb (ensure-src-i386a64 vb 17)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-sdiv buf 16 pa pb)
           (a64i-lsl-imm buf pd 16 1)
           (a64i-maybe-store pd vd)))))
    ;; MOD Vd Va Vb
    ((= op 36)
     (let ((vd (car operands))
           (va (car (cdr operands)))
           (vb (car (cdr (cdr operands)))))
       (let ((pa (ensure-src-i386a64 va 16))
             (pb (ensure-src-i386a64 vb 17)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-sdiv buf 16 pa pb)
           (a64i-mul buf 16 16 pb)
           (a64i-sub-reg buf pd pa 16 0 0)
           (a64i-maybe-store pd vd)))))
    ;; NEG Vd Vs
    ((= op 37)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-neg buf pd ps)
           (a64i-maybe-store pd vd)))))
    ;; INC Vd
    ((= op 38)
     (let ((vd (car operands)))
       (let ((pd (ensure-src-i386a64 vd 16)))
         (a64i-add-imm buf pd pd 2 0)
         (a64i-maybe-store pd vd))))
    ;; DEC Vd
    ((= op 39)
     (let ((vd (car operands)))
       (let ((pd (ensure-src-i386a64 vd 16)))
         (a64i-sub-imm buf pd pd 2 0)
         (a64i-maybe-store pd vd))))
    ;; AND Vd Va Vb
    ((= op 40)
     (a64i-translate-binop-reg buf operands 2)) ; 2=AND
    ;; OR Vd Va Vb
    ((= op 41)
     (a64i-translate-binop-reg buf operands 3)) ; 3=OR
    ;; XOR Vd Va Vb
    ((= op 42)
     (a64i-translate-binop-reg buf operands 4)) ; 4=XOR
    ;; SHL Vd Vs imm8
    ((= op 43)
     (let ((vd (car operands))
           (vs (car (cdr operands)))
           (amt (car (cdr (cdr operands)))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-lsl-imm buf pd ps amt)
           (a64i-maybe-store pd vd)))))
    ;; SHR Vd Vs imm8
    ((= op 44)
     (let ((vd (car operands))
           (vs (car (cdr operands)))
           (amt (car (cdr (cdr operands)))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-lsr-imm buf pd ps amt)
           (a64i-maybe-store pd vd)))))
    ;; SAR Vd Vs imm8
    ((= op 45)
     (let ((vd (car operands))
           (vs (car (cdr operands)))
           (amt (car (cdr (cdr operands)))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-asr-imm buf pd ps amt)
           (a64i-maybe-store pd vd)))))
    ;; LDB Vd Vs pos size
    ((= op 46)
     (let ((vd (car operands))
           (vs (car (cdr operands)))
           (pos (car (cdr (cdr operands))))
           (sz (car (cdr (cdr (cdr operands))))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-ubfm buf pd ps pos (+ pos (- sz 1)))
           (a64i-maybe-store pd vd)))))
    ;; SHLV Vd Vs Vc
    ((= op 47)
     (a64i-translate-shift-var buf operands 0)) ; 0=LSLV
    ;; CMP Va Vb
    ((= op 48)
     (let ((pa (ensure-src-i386a64 (car operands) 16))
           (pb (ensure-src-i386a64 (car (cdr operands)) 17)))
       (a64i-cmp-reg buf pa pb)))
    ;; TEST Va Vb
    ((= op 49)
     (let ((pa (ensure-src-i386a64 (car operands) 16))
           (pb (ensure-src-i386a64 (car (cdr operands)) 17)))
       (a64i-tst-reg buf pa pb)))
    ;; SARV Vd Vs Vc
    ((= op 50)
     (a64i-translate-shift-var buf operands 1)) ; 1=ASRV
    ;; BR off16 (#x40 = 64)
    ((= op 64)
     (a64i-translate-branch buf operands insn-offset insn-size mvm-to-native-label 0 0))
    ;; BEQ off16 (#x41 = 65)
    ((= op 65)
     (a64i-translate-bcond buf operands insn-offset insn-size mvm-to-native-label 0))
    ;; BNE off16 (#x42 = 66)
    ((= op 66)
     (a64i-translate-bcond buf operands insn-offset insn-size mvm-to-native-label 1))
    ;; BLT off16 (#x43 = 67)
    ((= op 67)
     (a64i-translate-bcond buf operands insn-offset insn-size mvm-to-native-label 11))
    ;; BGE off16 (#x44 = 68)
    ((= op 68)
     (a64i-translate-bcond buf operands insn-offset insn-size mvm-to-native-label 10))
    ;; BLE off16 (#x45 = 69)
    ((= op 69)
     (a64i-translate-bcond buf operands insn-offset insn-size mvm-to-native-label 13))
    ;; BGT off16 (#x46 = 70)
    ((= op 70)
     (a64i-translate-bcond buf operands insn-offset insn-size mvm-to-native-label 12))
    ;; BNULL Vs off16 (#x47 = 71)
    ((= op 71)
     (let ((ps (ensure-src-i386a64 (car operands) 16))
           (mvm-offset (car (cdr operands))))
       (a64i-cmp-reg buf ps 26) ; VN=x26
       (let ((target-byte (+ insn-offset insn-size mvm-offset)))
         (let ((label (a64i-get-or-make-label target-byte mvm-to-native-label)))
           (let ((idx (a64i-current-index buf)))
             (a64i-bcond buf 0 0) ; EQ
             (a64i-add-fixup buf idx label 248172622495451147)))))) ; :bcond hash
    ;; BNNULL Vs off16 (#x48 = 72)
    ((= op 72)
     (let ((ps (ensure-src-i386a64 (car operands) 16))
           (mvm-offset (car (cdr operands))))
       (a64i-cmp-reg buf ps 26)
       (let ((target-byte (+ insn-offset insn-size mvm-offset)))
         (let ((label (a64i-get-or-make-label target-byte mvm-to-native-label)))
           (let ((idx (a64i-current-index buf)))
             (a64i-bcond buf 1 0) ; NE
             (a64i-add-fixup buf idx label 248172622495451147))))))
    ;; CAR Vd Vs (#x50 = 80)
    ((= op 80)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-ldur buf pd ps (logand -1 511)) ; -1 = 0x1FF (9 bits)
           (a64i-maybe-store pd vd)))))
    ;; CDR Vd Vs (#x51 = 81)
    ((= op 81)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-ldur buf pd ps 7)
           (a64i-maybe-store pd vd)))))
    ;; CONS Vd Va Vb (#x52 = 82)
    ((= op 82)
     (let ((vd (car operands))
           (va (car (cdr operands)))
           (vb (car (cdr (cdr operands)))))
       (let ((pa (ensure-src-i386a64 va 16))
             (pb (ensure-src-i386a64 vb 17)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-stp-offset buf pa pb 24 0) ; x24=VA
           (a64i-add-imm buf pd 24 1 0)
           (a64i-add-imm buf 24 24 16 0)
           (a64i-maybe-store pd vd)))))
    ;; SETCAR Vd Vs (#x53 = 83)
    ((= op 83)
     (let ((pd (ensure-src-i386a64 (car operands) 16))
           (ps (ensure-src-i386a64 (car (cdr operands)) 17)))
       (a64i-stur buf ps pd (logand -1 511))))
    ;; SETCDR Vd Vs (#x54 = 84)
    ((= op 84)
     (let ((pd (ensure-src-i386a64 (car operands) 16))
           (ps (ensure-src-i386a64 (car (cdr operands)) 17)))
       (a64i-stur buf ps pd 7)))
    ;; CONSP Vd Vs (#x55 = 85)
    ((= op 85)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch2 vd)))
           (a64i-movz buf 17 15 0) ; mask=0xF
           (a64i-and-reg buf 16 ps 17)
           (a64i-cmp-imm buf 16 1)
           (a64i-cset buf pd 0) ; EQ
           (a64i-maybe-store pd vd)))))
    ;; ATOM Vd Vs (#x56 = 86)
    ((= op 86)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch2 vd)))
           (a64i-movz buf 17 15 0)
           (a64i-and-reg buf 16 ps 17)
           (a64i-cmp-imm buf 16 1)
           (a64i-cset buf pd 1) ; NE
           (a64i-maybe-store pd vd)))))
    ;; ALLOC-OBJ Vd count subtag (#x60 = 96)
    ((= op 96)
     (a64i-translate-alloc-obj buf operands))
    ;; OBJ-REF Vd Vobj idx (#x61 = 97)
    ((= op 97)
     (a64i-translate-obj-ref buf operands))
    ;; OBJ-SET Vobj idx Vs (#x62 = 98)
    ((= op 98)
     (a64i-translate-obj-set buf operands))
    ;; OBJ-TAG Vd Vs (#x63 = 99)
    ((= op 99)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-movz buf 17 15 0)
           (a64i-and-reg buf pd ps 17)
           (a64i-maybe-store pd vd)))))
    ;; OBJ-SUBTAG Vd Vs (#x64 = 100)
    ((= op 100)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-ldur buf 17 ps (logand -10 511))
           (a64i-movz buf 16 255 0)
           (a64i-and-reg buf pd 17 16)
           (a64i-maybe-store pd vd)))))
    ;; AREF Vd Vobj Vidx (#x65 = 101)
    ((= op 101)
     (a64i-translate-aref buf operands))
    ;; ASET Vobj Vidx Vs (#x66 = 102)
    ((= op 102)
     (a64i-translate-aset buf operands))
    ;; ARRAY-LEN Vd Vobj (#x67 = 103)
    ((= op 103)
     (let ((vd (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 16)))
         (let ((pd (a64i-dest-or-scratch vd)))
           (a64i-ldur buf 17 ps (logand -10 511))
           (a64i-lsr-imm buf 17 17 16)
           (a64i-lsl-imm buf pd 17 1)
           (a64i-maybe-store pd vd)))))
    ;; ALLOC-ARRAY Vd Vcount (#x68 = 104)
    ((= op 104)
     (a64i-translate-alloc-array buf operands))
    ;; LOAD Vd Vaddr width (#x70 = 112)
    ((= op 112)
     (let ((vd (car operands))
           (va (car (cdr operands)))
           (width (car (cdr (cdr operands)))))
       (let ((pa (ensure-src-i386a64 va 16)))
         (let ((pd (a64i-dest-or-scratch2 vd)))
           (a64i-ldr-width buf pd pa 0 width)
           (a64i-maybe-store pd vd)))))
    ;; STORE Vaddr Vs width (#x71 = 113)
    ((= op 113)
     (let ((va (car operands))
           (vs (car (cdr operands)))
           (width (car (cdr (cdr operands)))))
       (let ((pa (ensure-src-i386a64 va 16))
             (ps (ensure-src-i386a64 vs 17)))
         (a64i-str-width buf ps pa 0 width))))
    ;; FENCE (#x72 = 114)
    ((= op 114)
     (a64i-dmb buf 11)) ; ISH
    ;; CALL target (#x80 = 128)
    ((= op 128)
     (let ((target-offset (car operands)))
       (let ((label (gethash target-offset mvm-to-native-label)))
         (when label
           (let ((idx (a64i-current-index buf)))
             (a64i-bl buf 0)
             (a64i-add-fixup buf idx label 592037923804208769)))))) ; :bl hash
    ;; CALL-IND Vs (#x81 = 129)
    ((= op 129)
     (let ((ps (ensure-src-i386a64 (car operands) 16)))
       (a64i-blr buf ps)))
    ;; RET (#x82 = 130)
    ((= op 130)
     (a64i-emit-epilogue buf))
    ;; TAILCALL target (#x83 = 131)
    ((= op 131)
     (let ((target-offset (car operands)))
       (let ((label (gethash target-offset mvm-to-native-label)))
         (when label
           (a64i-add-imm buf 31 31 1024 0) ; ADD SP, SP, #1024
           (a64i-ldp-offset buf 23 31 31 48)
           (a64i-ldp-offset buf 21 22 31 32)
           (a64i-ldp-offset buf 19 20 31 16)
           (a64i-ldp-post buf 29 30 31 80)
           (let ((idx (a64i-current-index buf)))
             (a64i-b buf 0)
             (a64i-add-fixup buf idx label 126943983357610533)))))) ; :b hash
    ;; ALLOC-CONS Vd (#x88 = 136)
    ((= op 136)
     (let ((vd (car operands)))
       (let ((pd (a64i-dest-or-scratch vd)))
         (a64i-mov-reg buf pd 24) ; MOV pd, x24
         (a64i-add-imm buf 24 24 16 0)
         (a64i-maybe-store pd vd))))
    ;; GC-CHECK (#x89 = 137)
    ((= op 137)
     (a64i-cmp-reg buf 24 25)
     (a64i-bcond buf 11 2) ; B.LT +2 (skip BRK)
     (a64i-brk buf 1))
    ;; WRITE-BARRIER (#x8A = 138)
    ((= op 138)
     (a64i-dmb buf 11))
    ;; SAVE-CTX (#x90 = 144)
    ((= op 144)
     (a64i-translate-save-ctx buf operands))
    ;; RESTORE-CTX (#x91 = 145)
    ((= op 145)
     (a64i-translate-restore-ctx buf operands))
    ;; YIELD (#x92 = 146)
    ((= op 146)
     (a64i-sev buf)
     (a64i-wfe buf))
    ;; ATOMIC-XCHG Vd Vaddr Vs (#x93 = 147)
    ((= op 147)
     (a64i-translate-atomic-xchg buf operands))
    ;; IO-READ Vd port width (#xA0 = 160)
    ((= op 160)
     (let ((vd (car operands))
           (port (car (cdr operands)))
           (width (car (cdr (cdr operands)))))
       (let ((pd (a64i-dest-or-scratch vd)))
         (a64i-load-imm64 buf 17 port)
         (a64i-ldr-width buf pd 17 0 width)
         (a64i-maybe-store pd vd))))
    ;; IO-WRITE port Vs width (#xA1 = 161)
    ((= op 161)
     (let ((port (car operands))
           (vs (car (cdr operands)))
           (width (car (cdr (cdr operands)))))
       (let ((ps (ensure-src-i386a64 vs 17)))
         (a64i-load-imm64 buf 16 port)
         (a64i-str-width buf ps 16 0 width))))
    ;; HALT (#xA2 = 162)
    ((= op 162)
     (a64i-wfi buf))
    ;; CLI (#xA3 = 163)
    ((= op 163)
     (a64i-msr-daifset buf 3))
    ;; STI (#xA4 = 164)
    ((= op 164)
     (a64i-msr-daifclr buf 3))
    ;; PERCPU-REF Vd offset (#xA5 = 165)
    ((= op 165)
     (let ((vd (car operands))
           (offset (car (cdr operands))))
       (let ((pd (a64i-dest-or-scratch vd)))
         (a64i-mrs buf 17 50820) ; TPIDR_EL1 = 0xC684
         (if (zerop (mod offset 8))
             (a64i-ldr-unsigned buf pd 17 offset)
             (progn
               (a64i-load-imm64 buf 16 offset)
               (a64i-add-reg buf 17 17 16 0 0)
               (a64i-ldur buf pd 17 0)))
         (a64i-maybe-store pd vd))))
    ;; PERCPU-SET offset Vs (#xA6 = 166)
    ((= op 166)
     (let ((offset (car operands))
           (vs (car (cdr operands))))
       (let ((ps (ensure-src-i386a64 vs 17)))
         (a64i-mrs buf 16 50820)
         (if (zerop (mod offset 8))
             (a64i-str-unsigned buf ps 16 offset)
             (progn
               (a64i-load-imm64 buf 17 offset)
               (a64i-add-reg buf 16 16 17 0 0)
               (a64i-stur buf ps 16 0))))))
    ;; FN-ADDR Vd target (#xA7 = 167)
    ((= op 167)
     (let ((vd (car operands))
           (target-offset (car (cdr operands))))
       (let ((pd (a64i-dest-or-scratch vd)))
         (let ((label (gethash target-offset mvm-to-native-label)))
           (if label
               (let ((idx (a64i-current-index buf)))
                 ;; ADR pd: byte3=0x10, lo24=pd (placeholder)
                 (a64i-emit buf 16 pd) ; 16=0x10
                 (a64i-add-fixup buf idx label 782868907041998776)) ; :adr hash
               (a64i-movz buf pd 0 0)))
         (a64i-maybe-store pd vd))))
    ;; Unknown opcode: BRK with opcode number
    (t (a64i-brk buf op))))

;;; Helper: dest register or x16 scratch
(defun a64i-dest-or-scratch (vd)
  (if (a64i-vreg-spilled-p vd) 16 (aref *a64-vreg-to-phys* vd)))

;;; Helper: dest register or x17 scratch (for ops that use x16 internally)
(defun a64i-dest-or-scratch2 (vd)
  (if (a64i-vreg-spilled-p vd) 17 (aref *a64-vreg-to-phys* vd)))

;;; Helper: store scratch if needed
(defun a64i-maybe-store (pd vd)
  (when (a64i-vreg-spilled-p vd)
    (store-dst-i386a64 pd vd)))

;;; Helper: get or create label for target
(defun a64i-get-or-make-label (target-byte mvm-to-native-label)
  (let ((existing (gethash target-byte mvm-to-native-label)))
    (if existing existing
        (let ((lbl *mvm-label-counter*))
          (setq *mvm-label-counter* (+ lbl 1))
          (puthash target-byte mvm-to-native-label lbl)
          lbl))))

;;; Helper: translate 3-reg binary operation (ADD/SUB/AND/OR/XOR)
(defun a64i-translate-binop-reg (buf operands type)
  (let ((vd (car operands))
        (va (car (cdr operands)))
        (vb (car (cdr (cdr operands)))))
    (let ((pa (ensure-src-i386a64 va 16))
          (pb (ensure-src-i386a64 vb 17)))
      (let ((pd (a64i-dest-or-scratch vd)))
        (cond
          ((= type 0) (a64i-add-reg buf pd pa pb 0 0))
          ((= type 1) (a64i-sub-reg buf pd pa pb 0 0))
          ((= type 2) (a64i-and-reg buf pd pa pb))
          ((= type 3) (a64i-orr-reg buf pd pa pb))
          ((= type 4) (a64i-eor-reg buf pd pa pb)))
        (a64i-maybe-store pd vd)))))

;;; Helper: translate variable shift (SHLV/SARV)
(defun a64i-translate-shift-var (buf operands type)
  (let ((vd (car operands))
        (vs (car (cdr operands)))
        (vc (car (cdr (cdr operands)))))
    (let ((ps (ensure-src-i386a64 vs 16))
          (pc (ensure-src-i386a64 vc 17)))
      (let ((pd (a64i-dest-or-scratch vd)))
        (if (= type 0)
            (a64i-lslv buf pd ps pc)
            (a64i-asrv buf pd ps pc))
        (a64i-maybe-store pd vd)))))

;;; Helper: translate unconditional/conditional branch
(defun a64i-translate-branch (buf operands insn-offset insn-size mvm-to-native-label is-cond cond-code)
  (let ((mvm-offset (car operands)))
    (let ((target-byte (+ insn-offset insn-size mvm-offset)))
      (let ((label (a64i-get-or-make-label target-byte mvm-to-native-label)))
        (let ((idx (a64i-current-index buf)))
          (a64i-b buf 0)
          (a64i-add-fixup buf idx label 126943983357610533)))))) ; :b hash

(defun a64i-translate-bcond (buf operands insn-offset insn-size mvm-to-native-label cond-code)
  (let ((mvm-offset (car operands)))
    (let ((target-byte (+ insn-offset insn-size mvm-offset)))
      (let ((label (a64i-get-or-make-label target-byte mvm-to-native-label)))
        (let ((idx (a64i-current-index buf)))
          (a64i-bcond buf cond-code 0)
          (a64i-add-fixup buf idx label 248172622495451147)))))) ; :bcond hash

;;; TRAP handler
(defun a64i-translate-trap (buf code)
  (cond
    ;; Frame-enter (code < 256)
    ((< code 256)
     (a64i-emit-prologue buf)
     ;; Copy overflow args (>4 params) from caller's stack
     (when (> code 4)
       (a64i-translate-trap-overflow buf code 4)))
    ;; Frame-alloc/frame-free (code < 768)
    ((< code 768) nil)
    ;; Serial write (code = 768 = 0x0300)
    ((= code 768)
     (a64i-asr-imm buf 16 0 1) ; untag x0
     ;; UART base: 0x20000000 (VA mapping, matches standard translator)
     (a64i-load-imm64 buf 17 536870912) ; 0x20000000
     ;; STRB x16, [x17, #0]
     (a64i-str-width buf 16 17 0 0))
    ;; Serial read (code = 769 = 0x0301)
    ((= code 769)
     (a64i-load-imm64 buf 17 536870912) ; 0x20000000
     ;; LDRB w16, [x17, #0x18]
     (a64i-ldr-width buf 16 17 24 0) ; offset 0x18=24
     ;; TBNZ x16, #4, -1 (back to LDRB)
     (a64i-tbnz buf 16 4 (logand -1 16383)) ; imm14 = -1
     ;; LDRB w0, [x17, #0]
     (a64i-ldr-width buf 0 17 0 0)
     ;; LSL x0, x0, #1 (tag)
     (a64i-lsl-imm buf 0 0 1))
    ;; DSB SY (code = 770 = 0x0302)
    ((= code 770)
     (a64i-dsb buf 15)) ; SY=0xF
    ;; Jump to address (code = 771 = 0x0303)
    ((= code 771)
     (a64i-asr-imm buf 0 0 1)
     (a64i-br buf 0))
    ;; switch-idle-stack (code = 1024 = 0x0400)
    ((= code 1024)
     (a64i-mrs buf 16 50820) ; TPIDR_EL1
     (a64i-ldr-unsigned buf 16 16 56) ; [x16, #0x38]
     (a64i-add-imm buf 31 16 0 0)) ; MOV SP, x16
    ;; All other: SVC
    (t (a64i-svc buf code))))

;;; Copy overflow args from caller's stack to local frame slots
(defun a64i-translate-trap-overflow (buf code start)
  (let ((i start))
    (loop
      (when (>= i code) (return nil))
      (let ((src-offset (+ 80 (* (- i 4) 8)))
            (dst-offset (+ -64 (* i -8))))
        (a64i-ldur buf 16 29 src-offset) ; LDR x16, [FP, #src]
        (a64i-stur buf 16 29 (logand dst-offset 511))) ; STR x16, [FP, #dst]
      (setq i (+ i 1)))))

;;; ALLOC-OBJ Vd count subtag
(defun a64i-translate-alloc-obj (buf operands)
  (let ((vd (car operands))
        (count (car (cdr operands)))
        (subtag (car (cdr (cdr operands)))))
    (let ((data-bytes (* count 8))
          (pd (a64i-dest-or-scratch vd)))
      (let ((total-size (logand (+ 8 data-bytes 15) (lognot 15))))
        ;; Header: (count << 16) | subtag
        (a64i-movz buf 16 subtag 0)
        (a64i-movk buf 16 count 1)
        ;; Store header at alloc pointer
        (a64i-stur buf 16 24 0)
        ;; Result = alloc_ptr + 10
        (a64i-add-imm buf pd 24 10 0)
        ;; Bump alloc pointer
        (if (<= total-size 4095)
            (a64i-add-imm buf 24 24 total-size 0)
            (progn
              (a64i-load-imm64 buf 17 total-size)
              (a64i-add-reg buf 24 24 17 0 0)))
        (a64i-maybe-store pd vd)))))

;;; OBJ-REF Vd Vobj idx
(defun a64i-translate-obj-ref (buf operands)
  (let ((vd (car operands))
        (vobj (car (cdr operands)))
        (idx (car (cdr (cdr operands)))))
    (let ((pd (a64i-dest-or-scratch2 vd)))
      (if (= vobj 21) ; VFP = 21
          ;; Frame slot access
          (let ((offset (+ -64 (* idx -8))))
            (if (>= offset -256)
                (a64i-ldur buf pd 29 (logand offset 511))
                (progn
                  (a64i-sub-imm buf 16 29 (- offset) 0)
                  (a64i-ldur buf pd 16 0))))
          ;; Normal object slot access
          (let ((pobj (ensure-src-i386a64 vobj 16)))
            (let ((offset (- (* idx 8) 2)))
              (if (and (>= offset -256) (<= offset 255))
                  (a64i-ldur buf pd pobj (logand offset 511))
                  (progn
                    (a64i-load-imm64 buf 17 offset)
                    (a64i-add-reg buf 17 pobj 17 0 0)
                    (a64i-ldur buf pd 17 0))))))
      (a64i-maybe-store pd vd))))

;;; OBJ-SET Vobj idx Vs
(defun a64i-translate-obj-set (buf operands)
  (let ((vobj (car operands))
        (idx (car (cdr operands)))
        (vs (car (cdr (cdr operands)))))
    (let ((ps (ensure-src-i386a64 vs 17)))
      (if (= vobj 21) ; VFP
          (let ((offset (+ -64 (* idx -8))))
            (if (>= offset -256)
                (a64i-stur buf ps 29 (logand offset 511))
                (progn
                  (a64i-sub-imm buf 16 29 (- offset) 0)
                  (a64i-stur buf ps 16 0))))
          (let ((pobj (ensure-src-i386a64 vobj 16)))
            (let ((offset (- (* idx 8) 2)))
              (if (and (>= offset -256) (<= offset 255))
                  (a64i-stur buf ps pobj (logand offset 511))
                  (progn
                    (a64i-load-imm64 buf 16 offset)
                    (a64i-add-reg buf 16 pobj 16 0 0)
                    (a64i-stur buf ps 16 0)))))))))

;;; AREF Vd Vobj Vidx
(defun a64i-translate-aref (buf operands)
  (let ((vd (car operands))
        (vobj (car (cdr operands)))
        (vidx (car (cdr (cdr operands)))))
    (let ((pobj (ensure-src-i386a64 vobj 16))
          (pidx (ensure-src-i386a64 vidx 17)))
      (let ((pd (a64i-dest-or-scratch vd)))
        ;; x16 = (Vobj - 2) + Vidx * 4 (tagged idx: real*2, shift 2 gives real*8)
        (a64i-sub-imm buf 16 pobj 2 0)
        (a64i-add-reg buf 16 16 pidx 0 2) ; LSL #2
        (a64i-ldur buf pd 16 0)
        (a64i-maybe-store pd vd)))))

;;; ASET Vobj Vidx Vs
(defun a64i-translate-aset (buf operands)
  (let ((vobj (car operands))
        (vidx (car (cdr operands))))
    (let ((pobj (ensure-src-i386a64 vobj 16))
          (pidx (ensure-src-i386a64 vidx 17)))
      (a64i-sub-imm buf 16 pobj 2 0)
      (a64i-add-reg buf 16 16 pidx 0 2)
      (let ((ps (ensure-src-i386a64 (car (cdr (cdr operands))) 17)))
        (a64i-stur buf ps 16 0)))))

;;; ALLOC-ARRAY Vd Vcount
(defun a64i-translate-alloc-array (buf operands)
  (let ((vd (car operands))
        (vc (car (cdr operands))))
    (let ((pcount (ensure-src-i386a64 vc 17)))
      (let ((pd (a64i-dest-or-scratch vd)))
        ;; Header: (count << 16) | 0x32
        (a64i-lsl-imm buf 16 pcount 16)
        (a64i-movk buf 16 50 0) ; 0x32
        ;; Store header
        (a64i-stur buf 16 24 0)
        ;; Aligned alloc: (count+2)/2 * 16
        (a64i-add-imm buf 17 pcount 2 0)
        (a64i-lsr-imm buf 17 17 1)
        (a64i-lsl-imm buf 17 17 4)
        ;; Result = alloc_ptr + 10
        (a64i-add-imm buf pd 24 10 0)
        ;; Bump
        (a64i-add-reg buf 24 24 17 0 0)
        (a64i-maybe-store pd vd)))))

;;; ATOMIC-XCHG Vd Vaddr Vs
(defun a64i-translate-atomic-xchg (buf operands)
  (let ((vd (car operands))
        (vaddr (car (cdr operands)))
        (vs (car (cdr (cdr operands)))))
    (let ((pa (ensure-src-i386a64 vaddr 16))
          (ps (ensure-src-i386a64 vs 17)))
      (let ((pd (a64i-dest-or-scratch vd)))
        ;; Pick status reg that doesn't conflict
        (let ((status (cond ((not (= ps 17)) 17)
                            ((not (= pa 15)) 15)
                            (t 0))))
          ;; loop: LDXR pd, [pa]
          (let ((loop-idx (a64i-current-index buf)))
            (a64i-ldxr buf pd pa)
            ;; STXR status, ps, [pa]
            (a64i-stxr buf status ps pa)
            ;; CBNZ-W status, loop
            (let ((back-offset (- loop-idx (a64i-current-index buf))))
              (a64i-cbnz-w buf status (logand back-offset 524287)))))
        (a64i-maybe-store pd vd)))))

;;; SAVE-CTX Vd — simplified i386-safe version with byte-level patching
(defun a64i-translate-save-ctx (buf operands)
  (let ((vd (car operands)))
    (let ((pa (ensure-src-i386a64 vd 0)))
      ;; 1. Push callee-saved
      (a64i-stp-pre buf 20 21 31 -48)
      (a64i-stp-offset buf 22 23 31 16)
      (a64i-stp-offset buf 29 30 31 32)
      ;; 2. Save SP
      (a64i-add-imm buf 16 31 0 0) ; MOV x16, SP
      (a64i-str-unsigned buf 16 pa 0)
      ;; 3. Save regs
      (a64i-str-unsigned buf 24 pa 8)
      (a64i-str-unsigned buf 25 pa 16)
      (a64i-str-unsigned buf 19 pa 24)
      ;; 4. ADR x17, continuation — placeholder, record position
      (let ((adr-idx (a64i-current-index buf)))
        (a64i-emit buf 16 17) ; placeholder: byte3=0x10, lo24=17(x17)
        (a64i-str-unsigned buf 17 pa 40) ; [pa+0x28] = continuation
        ;; 5. Save per-CPU obj-alloc/obj-limit
        (a64i-mrs buf 16 50820) ; TPIDR_EL1
        (a64i-ldr-unsigned buf 17 16 40) ; [x16, #0x28]
        (a64i-str-unsigned buf 17 pa 104) ; [pa+0x68]
        (a64i-ldr-unsigned buf 17 16 48) ; [x16, #0x30]
        (a64i-str-unsigned buf 17 pa 112) ; [pa+0x70]
        ;; 6. Initial save: return 0
        (a64i-movz buf 0 0 0)
        ;; 7. B to pop (placeholder)
        (let ((b-idx (a64i-current-index buf)))
          (a64i-b buf 0)
          ;; 8. Continuation label
          (let ((cont-idx (a64i-current-index buf)))
            ;; Patch ADR x17 at adr-idx
            (let ((byte-off (* (- cont-idx adr-idx) 4)))
              (let ((immlo (logand byte-off 3))
                    (immhi (logand (ash byte-off -2) 524287)))
                (let ((b3 (logior (ash immlo 5) 16))
                      (lo24 (logior (ash immhi 5) 17)))
                  (a64i-write-bytes-at buf adr-idx
                    (logand lo24 255) (logand (ash lo24 -8) 255)
                    (logand (ash lo24 -16) 255) b3))))
            ;; Resume path: return 2
            (a64i-movz buf 0 2 0)
            ;; 9. Pop callee-saved (both paths)
            (let ((pop-idx (a64i-current-index buf)))
              ;; Patch B forward at b-idx
              (let ((b-offset (- pop-idx b-idx)))
                (let ((masked (logand b-offset 67108863)))
                  (a64i-write-bytes-at buf b-idx
                    (logand masked 255) (logand (ash masked -8) 255)
                    (logand (ash masked -16) 255)
                    (logior 20 (logand (ash masked -24) 3)))))
              (a64i-ldp-offset buf 29 30 31 32)
              (a64i-ldp-offset buf 22 23 31 16)
              (a64i-ldp-post buf 20 21 31 48)
              (store-dst-i386a64 0 vd))))))))

;;; RESTORE-CTX Vd
(defun a64i-translate-restore-ctx (buf operands)
  (let ((vd (car operands)))
    (let ((pa (ensure-src-i386a64 vd 0)))
      ;; Move addr to x16
      (a64i-mov-reg buf 16 pa)
      ;; Load continuation
      (a64i-ldr-unsigned buf 17 16 40) ; [x16+0x28]
      ;; Restore per-CPU
      (a64i-mrs buf 0 50820)
      (a64i-ldr-unsigned buf 1 16 104) ; [x16+0x68]
      (a64i-str-unsigned buf 1 0 40)
      (a64i-ldr-unsigned buf 1 16 112) ; [x16+0x70]
      (a64i-str-unsigned buf 1 0 48)
      ;; Restore callee-saved
      (a64i-ldr-unsigned buf 19 16 24)
      (a64i-ldr-unsigned buf 24 16 8)
      (a64i-ldr-unsigned buf 25 16 16)
      ;; Restore SP
      (a64i-ldr-unsigned buf 0 16 0)
      (a64i-add-imm buf 31 0 0 0) ; MOV SP, x0
      ;; (sched-lock-addr omitted for fixpoint — no actors)
      ;; BR to continuation
      (a64i-br buf 17))))

;;; ================================================================
;;; Translation pipeline
;;; ================================================================

;;; Branch target pre-scan (same as td-a64-scan-branches)
(defun a64i-scan-branches (bytecode offset len mvm-to-native-label)
  (let ((pos offset)
        (limit (+ offset len)))
    (loop
      (when (>= pos limit) (return nil))
      (let ((decoded (decode-instruction bytecode pos)))
        (let ((opcode (car decoded))
              (operands (car (cdr decoded)))
              (new-pos (cdr (cdr decoded))))
          (when (>= opcode 64) ; #x40
            (when (<= opcode 72) ; #x48
              (let ((off-idx 0))
                (when (>= opcode 71) ; #x47 BNULL/BNNULL
                  (setq off-idx 1))
                (let ((mvm-offset (nth off-idx operands)))
                  (let ((target-byte (+ pos (- new-pos pos) mvm-offset)))
                    (let ((existing (gethash target-byte mvm-to-native-label)))
                      (when (null existing)
                        (let ((lbl *mvm-label-counter*))
                          (setq *mvm-label-counter* (+ lbl 1))
                          (puthash target-byte mvm-to-native-label lbl)))))))))
          (setq pos new-pos))))))

;;; Per-function translation with LI interception
(defun a64i-translate-fn-body (bytecode offset len buf mvm-to-native-label)
  (a64i-set-current-buf buf)
  (let ((pos offset)
        (limit (+ offset len)))
    (loop
      (when (>= pos limit) (return nil))
      ;; Set label if exists
      (let ((label (gethash pos mvm-to-native-label)))
        (when label
          (a64i-set-label buf label)))
      ;; Check for LI (opcode 17): intercept before decode-instruction
      (if (= (aref bytecode pos) 17)
          ;; LI Vd, imm64: opcode(1) + vreg(1) + imm64(8) = 10 bytes
          (let ((vd (aref bytecode (+ pos 1))))
            (let ((pd (a64i-dest-or-scratch vd)))
              (a64i-load-imm64-raw buf pd bytecode (+ pos 2))
              (a64i-maybe-store pd vd))
            (setq pos (+ pos 10)))
          ;; Normal decode
          (let ((decoded (decode-instruction bytecode pos)))
            (let ((opcode (car decoded))
                  (operands (car (cdr decoded)))
                  (new-pos (cdr (cdr decoded))))
              (a64i-translate-insn buf opcode operands mvm-to-native-label
                                   pos (- new-pos pos))
              (setq pos new-pos)))))))

;;; Main translation entry point: i386→AArch64
(defun translate-mvm-to-aarch64-from-i386 (bytecode function-table)
  (write-char-serial 105) (write-char-serial 51) ;; i3
  (write-char-serial 56) (write-char-serial 54) ;; 86
  (write-char-serial 97) (write-char-serial 54) (write-char-serial 52) ;; a64
  (write-char-serial 10)
  (let ((buf (make-a64i-buffer)))
    (let ((n-functions (length function-table)))
      (print-dec n-functions) (write-char-serial 10)
      (let ((mvm-to-native-label (make-hash-table)))
        ;; Register labels for function entry points
        (let ((rest-ft function-table)
              (i 0))
          (loop
            (when (>= i n-functions) (return nil))
            (let ((entry (car rest-ft)))
              (let ((offset (car (cdr entry))))
                (let ((lbl *mvm-label-counter*))
                  (setq *mvm-label-counter* (+ lbl 1))
                  (puthash offset mvm-to-native-label lbl))))
            (setq rest-ft (cdr rest-ft))
            (setq i (+ i 1))))
        ;; Pre-scan branches
        (let ((rest-ft function-table)
              (i 0))
          (loop
            (when (>= i n-functions) (return nil))
            (let ((entry (car rest-ft)))
              (let ((offset (car (cdr entry)))
                    (len (car (cdr (cdr entry)))))
                (a64i-scan-branches bytecode offset len mvm-to-native-label)))
            (setq rest-ft (cdr rest-ft))
            (setq i (+ i 1))))
        ;; Translate
        (write-char-serial 84) (write-char-serial 10)
        (let ((fn-map (make-hash-table)))
          (let ((rest-ft function-table)
                (i 0))
            (loop
              (when (>= i n-functions) (return nil))
              (let ((entry (car rest-ft)))
                (let ((name (car entry))
                      (offset (car (cdr entry)))
                      (len (car (cdr (cdr entry)))))
                  ;; Set label
                  (let ((fn-label (gethash offset mvm-to-native-label)))
                    (when fn-label
                      (a64i-set-label buf fn-label)))
                  ;; Record native offset
                  (puthash name fn-map (a64i-buf-pos buf))
                  ;; Translate body
                  (a64i-translate-fn-body bytecode offset len buf mvm-to-native-label)))
              (setq rest-ft (cdr rest-ft))
              (setq i (+ i 1))
              (when (zerop (mod i 50))
                (write-char-serial 35)
                (print-dec i)
                (write-char-serial 10))))
          ;; End label
          (let ((end-label (gethash (array-length bytecode) mvm-to-native-label)))
            (when end-label
              (a64i-set-label buf end-label)))
          ;; Resolve fixups
          (write-char-serial 82) (write-char-serial 10)
          (a64i-resolve-fixups buf)
          ;; Return (bytes . (size . fn-map))
          (let ((native-size (a64i-buf-pos buf)))
            (write-char-serial 78) (write-char-serial 83) ;; NS
            (print-dec native-size) (write-char-serial 10)
            ;; Compute FNV of native code
            (let ((fnv (td-fnv-native (a64i-buf-bytes buf) native-size)))
              (write-char-serial 70) (write-char-serial 78) ;; FN
              (write-char-serial 86) (write-char-serial 58) ;; V:
              (print-dec fnv) (write-char-serial 10))
            (cons (a64i-buf-bytes buf) (cons native-size fn-map))))))))

;;; ================================================================
;;; Image assembly: i386→AArch64
;;; ================================================================

;;; Unpack boot preamble from packed array into image
(defun td-generate-aarch64-boot-i386 ()
  (when (null *a64-boot-preamble-packed*)
    (a64i-init-boot-preamble))
  ;; Diagnostic: check packed array contents
  (write-char-serial 91) ;; [
  (write-char-serial 76) ;; L
  (print-dec (array-length *a64-boot-preamble-packed*))
  (write-char-serial 44) ;; ,
  ;; Direct read of first 3 elements
  (write-char-serial 48) ;; 0
  (write-char-serial 61) ;; =
  (print-dec (aref *a64-boot-preamble-packed* 0))
  (write-char-serial 44)
  (write-char-serial 49) ;; 1
  (write-char-serial 61) ;; =
  (print-dec (aref *a64-boot-preamble-packed* 1))
  (write-char-serial 44)
  ;; Test: write then read
  (let ((test-arr (make-array 3)))
    (aset test-arr 0 42)
    (write-char-serial 84) ;; T
    (write-char-serial 61) ;; =
    (print-dec (aref test-arr 0)))
  (write-char-serial 93) ;; ]
  (write-char-serial 10)
  (let ((packed *a64-boot-preamble-packed*)
        (size *a64-boot-preamble-size*)
        (packed-count (array-length *a64-boot-preamble-packed*))
        (byte-idx 0)
        (pi 0))
    (loop
      (when (>= pi packed-count) (return size))
      (let ((val (aref packed pi)))
        (let ((b0 (logand val 255))
              (b1 (logand (ash val -8) 255))
              (b2 (logand (ash val -16) 255)))
          (when (< byte-idx size) (img-emit b0))
          (setq byte-idx (+ byte-idx 1))
          (when (< byte-idx size) (img-emit b1))
          (setq byte-idx (+ byte-idx 1))
          (when (< byte-idx size) (img-emit b2))
          (setq byte-idx (+ byte-idx 1))))
      (setq pi (+ pi 1)))))

;;; Assemble Gen1 AArch64 image from i386 host
(defun td-assemble-gen1-aarch64-i386 (result bc ft)
  ;; result = (bytes . (size . fn-map))
  (let ((native-bytes (car result))
        (native-size (car (cdr result)))
        (fn-map (cdr (cdr result))))
    ;; 1. Init
    (img-init)
    (write-char-serial 65) (write-char-serial 52) ;; A4
    (write-char-serial 58) (write-char-serial 10)
    ;; 2. Boot preamble from packed array
    (let ((boot-size (td-generate-aarch64-boot-i386)))
      (write-char-serial 80)
      (print-dec boot-size) (write-char-serial 10)
      ;; Pad to 0x1000
      (loop
        (when (>= (img-pos) 4096) (return nil))
        (img-emit 0))
      ;; 3. B instruction to kernel-main at 0x1000
      (write-char-serial 75)
      ;; Read kernel-main hash from running kernel's metadata at VA 0x380000
      (let ((km-hash (td-read-u32 #x380028)))
        (print-dec km-hash) (write-char-serial 10)
        (let ((km-native-off (gethash km-hash fn-map)))
          (write-char-serial 79)
          (if km-native-off
              (let ((dummy1 (print-dec km-native-off)))
                (write-char-serial 10)
                ;; km-native-off is in bytes (since a64i buffer is byte-based)
                (let ((km-insn-offset (ash km-native-off -2)))
                  ;; B forward: offset = km_insn_offset + 1
                  (let ((b-offset (+ km-insn-offset 1)))
                    (let ((masked (logand b-offset 67108863)))
                      ;; Emit B instruction as 4 raw bytes
                      (img-emit (logand masked 255))
                      (img-emit (logand (ash masked -8) 255))
                      (img-emit (logand (ash masked -16) 255))
                      (img-emit (logior 20 (logand (ash masked -24) 3)))))))
              ;; No kernel-main — emit NOP
              (progn
                (write-char-serial 33) (write-char-serial 10)
                (img-emit 31) (img-emit 32) (img-emit 3) (img-emit 213))))) ; NOP = D503201F
      ;; 4. Copy native code (starts at 0x1004)
      (write-char-serial 78)
      ;; Store native-code-offset in running kernel's scratch area
      (td-write-u32 #x380050 (img-pos)) ; 0x300050
      (let ((i 0))
        (loop
          (when (>= i native-size) (return nil))
          (img-emit (aref native-bytes i))
          (setq i (+ i 1))
          (when (zerop (mod i 50000))
            (write-char-serial 46))))
      (write-char-serial 10)
      ;; 5. Append bytecodes
      (write-char-serial 84)
      (let ((bc-len (array-length bc))
            (bc-img-offset (img-pos)))
        (let ((bi 0))
          (loop
            (when (>= bi bc-len) (return nil))
            (img-emit (aref bc bi))
            (setq bi (+ bi 1))))
        ;; 6. Append function table — raw byte copy from source image
        ;; (avoids u32 overflow for name hashes with byte 3 >= 0x80 on i386)
        (let ((ft-img-offset (img-pos))
              (src-ft-addr (+ (td-read-u32 #x380030) (td-read-u32 #x380014)))
              (ft-count (td-read-u32 #x380018)))
          (let ((total-ft-bytes (* ft-count 12))
                (bi 0))
            (loop
              (when (>= bi total-ft-bytes) (return nil))
              (img-emit (mem-ref (+ src-ft-addr bi) :u8))
              (setq bi (+ bi 1))))
          (write-char-serial 10)
          (print-dec ft-count) (write-char-serial 10)
          ;; 7. Write metadata at image offset 0x300000
          ;; AArch64: load at PA 0x40080000, VA = PA - 0x40000000 = 0x80000
          ;; Metadata VA = 0x380000, so image offset = 0x380000 - 0x80000 = 0x300000
          (let ((md-img-off #x300000))
            ;; magic MVMT = 0x544D564D — write as individual bytes
            ;; (0x544D564D > 2^30, overflows i386 30-bit fixnum)
            (let ((base (+ #x08000000 md-img-off)))
              (setf (mem-ref base :u8) #x4D)
              (setf (mem-ref (+ base 1) :u8) #x56)
              (setf (mem-ref (+ base 2) :u8) #x4D)
              (setf (mem-ref (+ base 3) :u8) #x54))
            ;; version = 1
            (img-patch-u32 (+ md-img-off 4) 1)
            ;; my-architecture = 1 (aarch64)
            (img-patch-u32 (+ md-img-off 8) 1)
            ;; bytecode-offset
            (img-patch-u32 (+ md-img-off 12) bc-img-offset)
            ;; bytecode-length
            (img-patch-u32 (+ md-img-off 16) bc-len)
            ;; fn-table-offset
            (img-patch-u32 (+ md-img-off 20) ft-img-offset)
            ;; fn-table-count
            (img-patch-u32 (+ md-img-off 24) ft-count)
            ;; native-code-offset
            (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x380050))
            ;; native-code-length
            (img-patch-u32 (+ md-img-off 32) native-size)
            ;; preamble-size = 0x1000
            (img-patch-u32 (+ md-img-off 36) 4096)
            ;; kernel-main-hash-lo — raw byte copy (avoids u32 overflow on i386)
            (let ((dst-base (+ #x08000000 md-img-off 40)))
              (setf (mem-ref dst-base :u8) (mem-ref #x380028 :u8))
              (setf (mem-ref (+ dst-base 1) :u8) (mem-ref #x380029 :u8))
              (setf (mem-ref (+ dst-base 2) :u8) (mem-ref #x38002A :u8))
              (setf (mem-ref (+ dst-base 3) :u8) (mem-ref #x38002B :u8)))
            ;; kernel-main native offset
            (let ((km-native-off (gethash (td-read-u32 #x380028) fn-map)))
              (if km-native-off
                  (img-patch-u32 (+ md-img-off 44) km-native-off)
                  (img-patch-u32 (+ md-img-off 44) 0)))
            ;; image-load-addr: 0x80000
            (img-patch-u32 (+ md-img-off 48) #x80000)
            ;; target-architecture (default 0=x64)
            (img-patch-u32 (+ md-img-off 52) 0)
            ;; mode (default 0=cross-compile)
            (img-patch-u32 (+ md-img-off 56) 0))
          ;; Total size must cover metadata at 0x300000
          (let ((total-size (+ #x300000 64)))
            (write-char-serial 65) (write-char-serial 52) ;; A4
            (write-char-serial 61)
            (print-dec total-size) (write-char-serial 10)
            total-size))))))

;;; Top-level: build AArch64 from i386
(defun build-aarch64-from-i386 (bc ft)
  (write-char-serial 105) (write-char-serial 51) ;; i3
  (write-char-serial 56) (write-char-serial 54) ;; 86
  (write-char-serial 62) (write-char-serial 97) ;; >a
  (write-char-serial 54) (write-char-serial 52) ;; 64
  (write-char-serial 10)
  (let ((result (translate-mvm-to-aarch64-from-i386 bc ft)))
    (let ((native-size (car (cdr result))))
      (write-char-serial 78) ;; N
      (print-dec native-size) (write-char-serial 10)
      ;; FNV hash for verification
      (let ((fnv (td-fnv-native (car result) native-size)))
        (let ((hash fnv))
          (write-char-serial 72) ;; H
          (print-dec hash) (write-char-serial 10)))
      (td-assemble-gen1-aarch64-i386 result bc ft)
      native-size)))

")

;;; SSH: driver dispatch and kernel-main (only included when --ssh)
(when *fixpoint-ssh-mode*
  (setf *fixpoint-extra-source*
        (concatenate 'string *fixpoint-extra-source*
                     "
;;; ================================================================
;;; Multi-architecture dispatch — loaded after all driver/adapter source.
;;; Overrides NIC API and address functions via last-defun-wins.
;;; Checks my-architecture from metadata at 0x300008:
;;;   0=x64, 1=aarch64 → E1000 PCI (e1000-hw-*), AArch64 addresses
;;;   2=i386           → NE2000 ISA (ne2k-*), i386 addresses
;;; ================================================================

;;; Address dispatch (i386 vs x64/aarch64 memory layout)
(defun e1000-state-base ()
  (if (= (td-read-u32 #x380008) 2) #x200000 #x41060000))
(defun ssh-conn-base ()
  (if (= (td-read-u32 #x380008) 2) #x280000 #x41080000))
(defun ssh-ipc-base ()
  (if (= (td-read-u32 #x380008) 2) #x300000 #x41100000))

;;; NIC driver dispatch
(defun e1000-send (buf len)
  (if (= (td-read-u32 #x380008) 2)
      (ne2k-send buf len)
      (e1000-hw-send buf len)))

(defun e1000-receive ()
  (if (= (td-read-u32 #x380008) 2)
      (ne2k-receive)
      (e1000-hw-receive)))

(defun e1000-rx-buf ()
  (if (= (td-read-u32 #x380008) 2)
      (ne2k-rx-host)
      (e1000-hw-rx-buf)))

(defun e1000-probe ()
  (if (= (td-read-u32 #x380008) 2)
      (progn (ne2k-reset) (ne2k-init))
      (e1000-hw-probe)))

;;; SSH server entry point — called when metadata mode=1
;;; Architecture-aware: uses E1000 PCI on x64/aarch64, NE2000 ISA on i386.
(defun ssh-kernel-main ()
  ;; NIC initialization (dispatch selects driver based on my-architecture)
  (write-char-serial 91) (write-char-serial 49) (write-char-serial 93) ;; [1]
  (let ((arch (td-read-u32 #x380008)))
    (if (= arch 2)
        nil  ;; i386: no PCI, NE2000 is ISA
        (pci-assign-bars)))
  (write-char-serial 91) (write-char-serial 50) (write-char-serial 93) ;; [2]
  (e1000-probe)
  ;; Crypto initialization
  (write-char-serial 91) (write-char-serial 51) (write-char-serial 93) ;; [3]
  (sha256-init)
  (write-char-serial 91) (write-char-serial 52) (write-char-serial 93) ;; [4]
  (sha512-init)
  (write-char-serial 91) (write-char-serial 53) (write-char-serial 93) ;; [5]
  (ed25519-init)
  (write-char-serial 91) (write-char-serial 54) (write-char-serial 93) ;; [6]
  (ssh-seed-random)
  (dhcp-discover)
  (write-char-serial 91) (write-char-serial 55) (write-char-serial 93) ;; [7]
  (ssh-seed-random)
  (ssh-init-strings)
  ;; Pre-computed Ed25519 host key (private=zeros, public=ed25519(zeros))
  (let ((state (e1000-state-base)))
    (setf (mem-ref (+ state #x710) :u64) 0)
    (setf (mem-ref (+ state #x718) :u64) 0)
    (setf (mem-ref (+ state #x720) :u64) 0)
    (setf (mem-ref (+ state #x728) :u64) 0)
    (setf (mem-ref (+ state #x730) :u32) #xBC276A3B)
    (setf (mem-ref (+ state #x734) :u32) #x2DA4B6CE)
    (setf (mem-ref (+ state #x738) :u32) #xD0A8A362)
    (setf (mem-ref (+ state #x73C) :u32) #x730D6F2A)
    (setf (mem-ref (+ state #x740) :u32) #x77153265)
    (setf (mem-ref (+ state #x744) :u32) #xA643E21D)
    (setf (mem-ref (+ state #x748) :u32) #xA148C03A)
    (setf (mem-ref (+ state #x74C) :u32) #x29DA598B)
    (setf (mem-ref (+ state #x624) :u32) 1))
  (pre-compute-host-sign)
  (write-char-serial 91) (write-char-serial 56) (write-char-serial 93) ;; [8]
  ;; SSH port (22)
  (setf (mem-ref (+ (ssh-ipc-base) #x60438) :u32) 22)
  ;; Initialize connections
  (let ((i 0))
    (loop
      (when (>= i 4) (return 0))
      (setf (mem-ref (conn-base i) :u32) 0)
      (setq i (+ i 1))))
  ;; Pre-compute server ephemeral X25519 key pair
  (pre-compute-server-eph (conn-ssh 0))
  (write-char-serial 83) (write-char-serial 83) (write-char-serial 72) ;; SSH
  (write-char-serial 10)
  (net-actor-main))
")))

;;; ============================================================
;;; Generate opcode table init source (in cl-user, before package switch)
;;; ============================================================

;; Generate init-opcode-entries from SBCL-side *opcode-table*
;; The defopcode calls in mvm.lisp are top-level side effects that compile
;; to TOPLEVEL-* thunks but are never called on bare metal. This function
;; explicitly registers all opcodes.
;; Must use cl:maphash here — the modus64.mvm package shadows maphash.
(defvar *opcode-init-source*
  (let ((ot modus64.mvm::*opcode-table*)
        (count 0))
    (with-output-to-string (s)
      (format s "(defun init-opcode-entries ()~%")
      (cl:maphash (lambda (code info)
                    (incf count)
                    ;; Progress marker every 10 entries
                    (when (zerop (mod count 10))
                      (format s "  (write-char-serial ~D)~%" (+ 48 (floor count 10))))
                    (let ((operands (modus64.mvm::opcode-info-operands info)))
                      (format s "  (puthash ~D *opcode-table* (%make-opcode-info ~D ~D "
                              code code (modus64.mvm::normalize-name (modus64.mvm::opcode-info-name info)))
                      (if (null operands)
                          (format s "nil")
                          (progn
                            (loop for op in operands
                                  for first = t then nil
                                  do (unless first (format s " "))
                                     (format s "(cons ~D" (modus64.mvm::normalize-name op)))
                            (format s " nil")
                            (dotimes (j (length operands))
                              (format s ")"))))
                      (format s " nil))~%")))
                  ot)
      ;; Final marker
      (format s "  (write-char-serial 33)~%")  ; '!'
      (format s ")~%"))))

(format t "Generated init-opcode-entries: ~D chars~%" (length *opcode-init-source*))
(format t "~A~%" (subseq *opcode-init-source* 0 (min 1500 (length *opcode-init-source*))))

;;; ============================================================
;;; Compile fixpoint source through MVM
;;; ============================================================

(in-package :modus64.mvm)

;; Forward x64-asm bindings so defmacro bodies can access them at expansion time
;; (x64-asm.lisp source is read in modus64.mvm package, so *registers* resolves here)
(defparameter *registers* modus64.asm::*registers*)

;; Install translators
(funcall (intern "INSTALL-X64-TRANSLATOR" "MODUS64.MVM.X64"))
(install-aarch64-translator)
(funcall (intern "INSTALL-I386-TRANSLATOR" "MODUS64.MVM.I386"))

;; init-opcode-entries source was generated above (before in-package switch)
;; to avoid maphash compiler-macro conflict in modus64.mvm package.
;; (See *opcode-init-source* defvar near top of this section)

;; (old maphash code removed — now generated in cl-user section above)

;; Combine all source: REPL first, then networking (if --ssh), then MVM system,
;; then fixpoint cross-compilation, then kernel-main LAST.
(defvar *fixpoint-source*
  (concatenate 'string
               ;; REPL source first (defines most runtime functions)
               *repl-source*
               (string #\Newline)
               ;; Networking source (only when --ssh)
               (or cl-user::*net-source-text* "")
               (string #\Newline)
               ;; MVM system source
               cl-user::*mvm-source-text*
               (string #\Newline)
               ;; Fixpoint cross-compilation functions
               cl-user::*fixpoint-extra-source*
               (string #\Newline)
               ;; Opcode table initialization
               cl-user::*opcode-init-source*
               (string #\Newline)
               ;; kernel-main LAST — "last-defun-wins" makes this the entry point.
               ;; The JMP in boot code targets the last kernel-main in the function table.
               ;; Must use write-char-serial (the MVM compiler builtin), not write-byte.
               "(defun kernel-main ()
  ;; Initialize MVM runtime tables
  (write-char-serial 73) (write-char-serial 49) (write-char-serial 10)
  (init-*gensym-counter*)
  (write-char-serial 73) (write-char-serial 50) (write-char-serial 10)
  (init-*vreg-names*)
  (write-char-serial 73) (write-char-serial 51) (write-char-serial 10)
  (init-*opcode-table*)
  (init-opcode-entries)
  (write-char-serial 73) (write-char-serial 52) (write-char-serial 10)
  (init-*mvm-label-counter*)
  (write-char-serial 73) (write-char-serial 53) (write-char-serial 10)
  (init-*target-x86-64*)
  (write-char-serial 73) (write-char-serial 54) (write-char-serial 10)
  (init-*condition-codes*)
  (write-char-serial 73) (write-char-serial 55) (write-char-serial 10)
  (init-*vreg-to-x64*)
  ;; Diagnostic: verify *vreg-to-x64* initialization
  (write-char-serial 73) (write-char-serial 56) (write-char-serial 10)
  (write-char-serial 88) ;; X
  (print-dec (length *vreg-to-x64*))
  (write-char-serial 32)
  ;; Print first 9 elements (V0-V8 = physical regs)
  (let ((vi 0))
    (loop
      (when (>= vi 9) (return nil))
      (let ((v (aref *vreg-to-x64* vi)))
        (if (null v)
            (write-char-serial 78) ;; N
            (progn (write-char-serial 89) ;; Y
                   (print-dec v)))
        (write-char-serial 44))
      (setq vi (+ vi 1))))
  (write-char-serial 10)
  ;; Initialize AArch64 translator tables
  (init-*a64-vreg-to-phys*)
  ;; Initialize i386 translator tables
  (init-*i386-vreg-map*)
  (write-char-serial 73) (write-char-serial 57) (write-char-serial 10)
  ;; Check mode: 0=cross-compile, 1=SSH server
  (let ((mode (td-read-u32 #x380038)))
    (if (= mode 1)
        ;; SSH server mode
        (ssh-kernel-main)
        ;; Cross-compile mode: read target from metadata
        (let ((target (td-read-u32 #x380034)))
          (build-image-cross target))))
  (write-char-serial 68) (write-char-serial 10)
  ;; Drop to REPL
  (let ((globals (cons nil nil)))
    (repl globals)))"))

(format t "~%Total fixpoint source: ~D chars~%" (length *fixpoint-source*))

;; Debug: check paren balance of each fixpoint source piece
(flet ((check-depth (src label)
         (let ((depth 0) (in-string nil) (in-comment nil) (escape nil))
           (dotimes (i (length src))
             (let ((ch (char src i)))
               (cond
                 (escape (setf escape nil))
                 ((char= ch #\Newline) (setf in-comment nil))
                 (in-comment nil)
                 (in-string (cond ((char= ch #\\) (setf escape t))
                                  ((char= ch #\") (setf in-string nil))))
                 ((char= ch #\;) (setf in-comment t))
                 ((char= ch #\") (setf in-string t))
                 ((char= ch #\() (incf depth))
                 ((char= ch #\)) (decf depth)))))
           (format t "  ~A: depth=~D (~D chars)~%" label depth (length src))
           depth)))
  (check-depth modus64.mvm::*repl-source* "repl-source")
  (check-depth cl-user::*mvm-source-text* "mvm-source-text")
  (check-depth cl-user::*fixpoint-extra-source* "fixpoint-extra")
  (check-depth cl-user::*opcode-init-source* "opcode-init")
  (check-depth *fixpoint-source* "TOTAL"))

;; Phase 1: Compile to MVM bytecode (THE FIXED POINT)
(format t "~%Phase 1: Compiling fixpoint source → MVM bytecode...~%")
(let* ((module (compile-source-to-module *fixpoint-source* :name :fixpoint))
       (bytecode (mvm-module-bytecode module))
       (fn-table (mvm-module-function-table module)))
  (format t "  MVM bytecode: ~D bytes~%" (length bytecode))
  (format t "  Functions: ~D~%" (length fn-table))
  ;; XOR checksum for bare-metal comparison
  (let ((xsum 0))
    (dotimes (i (length bytecode))
      (setf xsum (logxor xsum (aref bytecode i))))
    (format t "  Bytecode XOR checksum: ~D~%" xsum))
  ;; Print function 13 info
  (let ((fi13 (nth 13 fn-table)))
    (format t "  Fn 13: ~A offset=~D length=~D~%"
            (mvm-function-info-name fi13)
            (mvm-function-info-bytecode-offset fi13)
            (mvm-function-info-bytecode-length fi13)))
  ;; Check for emit-add-reg-reg and related functions
  (dolist (fi fn-table)
    (let ((name (string (mvm-function-info-name fi))))
      (when (or (search "ADD-REG" name)
                (search "SUB-REG" name)
                (search "AND-REG" name)
                (search "OR-REG" name)
                (search "XOR-REG" name))
        (format t "  FOUND: ~A offset=~D~%" name (mvm-function-info-bytecode-offset fi)))))

  ;; Count opcodes that create internal labels
  (format t "~%Opcode census:~%")
  (let ((n-consp 0) (n-atom 0) (n-gc 0) (n-tailcall 0) (n-call 0) (n-total 0)
        (n-call0 0) (n-fnaddr 0) (n-fnaddr0 0)
        (pos 0))
    (loop while (< pos (length bytecode))
          do (let ((decoded (modus64.mvm::decode-instruction bytecode pos)))
               (incf n-total)
               (let ((opcode (car decoded))
                     (operands (cadr decoded)))
                 (case opcode
                   (#x55 (incf n-consp))
                   (#x56 (incf n-atom))
                   (#x89 (incf n-gc))
                   (#x83 (incf n-tailcall))
                   (#x80 (incf n-call)
                         (when (zerop (first operands))
                           (incf n-call0)))
                   (#xA7 (incf n-fnaddr)
                         (when (zerop (second operands))
                           (incf n-fnaddr0)))))
               (setf pos (cddr decoded))))
    (format t "  CONSP(#x55): ~D -> ~D labels~%" n-consp (* 2 n-consp))
    (format t "  ATOM(#x56): ~D -> ~D labels~%" n-atom (* 2 n-atom))
    (format t "  GC-CHECK(#x89): ~D -> ~D labels~%" n-gc n-gc)
    (format t "  TAILCALL(#x83): ~D~%" n-tailcall)
    (format t "  CALL(#x80): ~D (target=0: ~D)~%" n-call n-call0)
    (format t "  FN-ADDR(#xA7): ~D (target=0: ~D)~%" n-fnaddr n-fnaddr0)
    (format t "  Total internal labels: ~D~%" (+ (* 2 n-consp) (* 2 n-atom) n-gc))
    (format t "  Total instructions: ~D~%~%" n-total))

  ;; Verify: translate bytecode on SBCL side (reference native code size)
  (format t "~%Reference translation (SBCL side)...~%")
  (let ((fn-table-for-translator
         (mapcar (lambda (fi)
                   (list (mvm-function-info-name-hash fi)
                         (mvm-function-info-bytecode-offset fi)
                         (mvm-function-info-bytecode-length fi)))
                 fn-table)))
    (multiple-value-bind (ref-buf ref-fn-map)
        (modus64.mvm.x64::translate-mvm-to-x64 bytecode fn-table-for-translator)
      (let ((ref-size (modus64.asm:code-buffer-position ref-buf))
            (ref-bytes (modus64.asm:code-buffer-bytes ref-buf)))
        (format t "  SBCL-side native code: ~D bytes~%" ref-size)
        ;; Pre-fixup FNV: zero fixup positions, compute FNV, restore
        (let ((fixups (modus64.asm::code-buffer-fixups ref-buf))
              (saved nil))
          ;; Save and zero fixup bytes
          (dolist (fixup fixups)
            (destructuring-bind (pos label size) fixup
              (declare (ignore label))
              (when (eql size 4)
                (push (list pos (aref ref-bytes pos) (aref ref-bytes (+ pos 1))
                            (aref ref-bytes (+ pos 2)) (aref ref-bytes (+ pos 3)))
                      saved)
                (setf (aref ref-bytes pos) 0
                      (aref ref-bytes (+ pos 1)) 0
                      (aref ref-bytes (+ pos 2)) 0
                      (aref ref-bytes (+ pos 3)) 0))))
          ;; Restore fixup bytes
          (dolist (entry saved)
            (destructuring-bind (pos b0 b1 b2 b3) entry
              (setf (aref ref-bytes pos) b0
                    (aref ref-bytes (+ pos 1)) b1
                    (aref ref-bytes (+ pos 2)) b2
                    (aref ref-bytes (+ pos 3)) b3))))
        ;; Post-fixup FNV-1a checksum of native code
        (let ((hash 2166136261))
          (dotimes (i ref-size)
            (setf hash (logand #xFFFFFFFF
                               (* (logxor hash (aref ref-bytes i)) 16777619))))
          (format t "  SBCL-side x64 FNV-1a: ~D~%" hash)))))

  ;; AArch64 reference translation (SBCL side)
  (format t "~%AArch64 reference translation (SBCL side)...~%")
  (let ((*aarch64-serial-base* #x20000000)
        (*aarch64-serial-width* 0)
        (*aarch64-serial-tx-poll* nil)
        (*aarch64-sched-lock-addr* nil))
    ;; Build hash table: func-idx → mvm-byte-offset (AArch64 translator format)
    (let ((a64-fn-ht (make-hash-table :test 'eql)))
      (loop for fi in fn-table
            for i from 0
            do (setf (gethash i a64-fn-ht)
                     (mvm-function-info-bytecode-offset fi)))
      (let ((a64-buf (translate-mvm-to-aarch64 bytecode a64-fn-ht)))
        (let* ((a64-bytes (a64-buffer-to-bytes a64-buf))
               (a64-size (length a64-bytes)))
          (format t "  SBCL-side AArch64 native: ~D bytes~%" a64-size)
          ;; FNV-1a checksum
          (let ((hash 2166136261))
            (dotimes (i a64-size)
              (setf hash (logand #xFFFFFFFF
                                 (* (logxor hash (aref a64-bytes i)) 16777619))))
            (format t "  SBCL-side AArch64 FNV-1a: ~D~%" hash))))))

  ;; i386 reference translation (SBCL side)
  (format t "~%i386 reference translation (SBCL side)...~%")
  (let ((i386-fn-table-for-translator
         (mapcar (lambda (fi)
                   (list (mvm-function-info-name-hash fi)
                         (mvm-function-info-bytecode-offset fi)
                         (mvm-function-info-bytecode-length fi)))
                 fn-table)))
    (multiple-value-bind (i386-buf i386-fn-map)
        (modus64.mvm.i386::translate-mvm-to-i386 bytecode i386-fn-table-for-translator)
      (let* ((i386-size (modus64.mvm.i386::i386-buffer-position i386-buf))
             (i386-bytes (modus64.mvm.i386::i386-buffer-bytes i386-buf)))
        (format t "  SBCL-side i386 native: ~D bytes~%" i386-size)
        (let ((hash 2166136261))
          (dotimes (i i386-size)
            (setf hash (logand #xFFFFFFFF
                               (* (logxor hash (aref i386-bytes i)) 16777619))))
          (format t "  SBCL-side i386 FNV-1a: ~D~%" hash)))))

  ;; Phase 2: Assemble fixpoint image
  (format t "~%Phase 2: Assembling fixpoint kernel image...~%")
  (let ((boot-desc (get-boot-descriptor :x86-64)))
    (let ((image (assemble-kernel-image module *target-x86-64*
                                        :boot-descriptor boot-desc)))
        (let* ((img-bytes (kernel-image-image-bytes image))
               (img-len (length img-bytes)))
          (format t "  Base image: ~D bytes~%" img-len)
          (format t "  Functions: ~D~%" (length fn-table))

          ;; Now append fixpoint data: MVM bytecode + function table
          ;; Metadata at offset 0x280000 (= VA 0x380000 for x64) uses
          ;; architecture-neutral u32 LE format.
          ;;
          ;; Layout:
          ;;   [Base image: boot + native + constants + NFN + source]
          ;;   [MVM bytecode bytes]
          ;;   [Function table: 12-byte entries (3 × u32 LE each)]
          ;;   [zero padding to offset 0x200000]
          ;;   [Metadata: 14 × u32 LE = 56 bytes]

          ;; Serialize function table
          (let* ((ft-entries
                  (mapcar (lambda (fi)
                            (list (mvm-function-info-name-hash fi)
                                  (mvm-function-info-bytecode-offset fi)
                                  (mvm-function-info-bytecode-length fi)))
                          fn-table))
                 ;; Calculate sizes and offsets
                 (bc-len (length bytecode))
                 (ft-count (length ft-entries))
                 (ft-entry-size (* ft-count 12))  ; 3 × u32 per entry
                 (bc-offset img-len)
                 (ft-offset (+ bc-offset bc-len))
                 ;; Metadata at fixed offset 0x280000 (address 0x380000)
                 (metadata-offset #x280000)
                 (metadata-size 64) ; 16 × u32
                 (final-size (+ metadata-offset metadata-size))
                 ;; Create final image (zero-initialized = implicit padding)
                 (extended (make-array final-size
                                       :element-type '(unsigned-byte 8)
                                       :initial-element 0)))

            ;; Verify content fits before metadata
            (let ((content-end (+ ft-offset ft-entry-size)))
              (when (> content-end metadata-offset)
                (error "Fixpoint content (~D bytes) exceeds metadata offset 0x~X"
                       content-end metadata-offset)))

            ;; Copy original image
            (dotimes (i img-len)
              (setf (aref extended i) (aref img-bytes i)))

            ;; Append MVM bytecode
            (dotimes (i bc-len)
              (setf (aref extended (+ bc-offset i)) (aref bytecode i)))

            ;; Write function table entries as u32 LE (12 bytes each)
            (loop for entry in ft-entries
                  for idx from 0
                  for base = (+ ft-offset (* idx 12))
                  do (let ((hash (logand (first entry) #xFFFFFFFF))
                           (off (second entry))
                           (len (third entry)))
                       (dotimes (b 4)
                         (setf (aref extended (+ base b))
                               (logand (ash hash (* b -8)) #xFF)))
                       (dotimes (b 4)
                         (setf (aref extended (+ base 4 b))
                               (logand (ash off (* b -8)) #xFF)))
                       (dotimes (b 4)
                         (setf (aref extended (+ base 8 b))
                               (logand (ash len (* b -8)) #xFF)))))

            ;; Write fixpoint metadata at offset 0x280000 (address 0x380000)
            ;; All values as u32 LE — architecture-neutral
            (let ((load-addr #x100000))
              (flet ((write-u32-le (offset value)
                       (dotimes (b 4)
                         (setf (aref extended (+ offset b))
                               (logand (ash value (* b -8)) #xFF)))))
                ;; +0x00: magic "MVMT" = 0x544D564D
                (write-u32-le metadata-offset #x544D564D)
                ;; +0x04: version = 1
                (write-u32-le (+ metadata-offset 4) 1)
                ;; +0x08: my-architecture = 0 (x64)
                (write-u32-le (+ metadata-offset 8) 0)
                ;; +0x0C: bytecode-offset (image offset)
                (write-u32-le (+ metadata-offset 12) bc-offset)
                ;; +0x10: bytecode-length
                (write-u32-le (+ metadata-offset 16) bc-len)
                ;; +0x14: fn-table-offset (image offset)
                (write-u32-le (+ metadata-offset 20) ft-offset)
                ;; +0x18: fn-table-count
                (write-u32-le (+ metadata-offset 24) ft-count)
                ;; +0x1C..+0x20: native-code-offset, native-code-length (filled by bare metal)
                ;; For Gen0, the base image already has native code at known positions
                ;; Preamble size, kernel-main hash, etc.
                (let* ((preamble-size (length (kernel-image-boot-code image)))
                       (jmp-offset preamble-size)
                       (d0 (aref img-bytes (+ jmp-offset 1)))
                       (d1 (aref img-bytes (+ jmp-offset 2)))
                       (d2 (aref img-bytes (+ jmp-offset 3)))
                       (d3 (aref img-bytes (+ jmp-offset 4)))
                       (actual-jmp-disp (logior d0 (ash d1 8) (ash d2 16) (ash d3 24)))
                       (last-fn (car (last fn-table)))
                       (last-fn-name (mvm-function-info-name last-fn))
                       (last-fn-offset (mvm-function-info-native-offset last-fn)))
                  ;; +0x1C: native-code-offset (after preamble + JMP)
                  (write-u32-le (+ metadata-offset 28) (+ preamble-size 5))
                  ;; +0x20: native-code-length
                  (write-u32-le (+ metadata-offset 32)
                                (- img-len (+ preamble-size 5)))
                  ;; +0x24: preamble-size
                  (write-u32-le (+ metadata-offset 36) preamble-size)
                  ;; +0x28: kernel-main-hash-lo (lower 32 bits of name hash)
                  (write-u32-le (+ metadata-offset 40)
                                (logand (compute-name-hash "KERNEL-MAIN") #xFFFFFFFF))
                  ;; +0x2C: kernel-main-native-offset
                  (write-u32-le (+ metadata-offset 44) actual-jmp-disp)
                  ;; +0x30: image-load-addr
                  (write-u32-le (+ metadata-offset 48) load-addr)
                  ;; +0x34: target-architecture (default: 1 = aarch64)
                  (write-u32-le (+ metadata-offset 52) 1)
                  ;; +0x38: mode (0 = cross-compile, 1 = SSH server)
                  (write-u32-le (+ metadata-offset 56) 0)
                  (format t "  Preamble size: ~D bytes~%" preamble-size)
                  (format t "  Last fn-table entry: ~A native-offset=~D~%"
                          last-fn-name last-fn-offset)
                  (format t "  Actual JMP displacement in image: ~D~%" actual-jmp-disp)
                  (format t "  JMP byte at ~D: ~D (should be ~D = E9)~%"
                          jmp-offset (aref img-bytes jmp-offset) #xE9)
                  (format t "  Kernel-main native offset (from JMP): ~D~%"
                          actual-jmp-disp))))

            (format t "  Fixpoint data: ~D bytes bytecode + ~D function entries~%"
                    bc-len ft-count)
            (format t "  Final image: ~D bytes (~DKB)~%" final-size
                    (ceiling final-size 1024))

            ;; Write to disk
            (let ((output-path "/tmp/fixpoint-gen0.elf"))
              (with-open-file (out output-path
                                   :direction :output
                                   :element-type '(unsigned-byte 8)
                                   :if-exists :supersede)
                (write-sequence extended out))
              (format t "~%Fixpoint Gen0 written to ~A~%" output-path)
              (format t "~%Boot with:~%")
              (format t "  qemu-system-x86_64 -kernel ~A -m 512 -nographic -no-reboot~%"
                      output-path)
              (format t "~%Fixpoint data:~%")
              (format t "  MVM bytecode: ~D bytes (the fixed point)~%" bc-len)
              (format t "  Functions: ~D~%" ft-count)
              (format t "  Bytecode at: 0x~X (offset 0x~X)~%"
                      (+ #x100000 bc-offset) bc-offset)
              (format t "  Fn table at: 0x~X (offset 0x~X, ~D entries)~%"
                      (+ #x100000 ft-offset) ft-offset ft-count)
              (format t "  Metadata at: 0x380000 (offset 0x280000)~%")))))))
