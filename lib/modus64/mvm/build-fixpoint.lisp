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
;;;; Usage: cd lib/modus64 && sbcl --script mvm/build-fixpoint.lisp
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
    "mvm/cross.lisp"
    "boot/boot-x64.lisp"
    "boot/boot-aarch64.lisp"))

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
      ;; Load order: arch-x86 FIRST, then arch-aarch64 LAST so AArch64
      ;; functions win via last-defun-wins (pci-config-read uses ECAM,
      ;; e1000-state-base returns AArch64 addresses, etc.)
      (let ((text (format nil "~A~%~A~%~A~%~A~%~A~%~A~%~A~%"
                          (read-file-text (merge-pathnames "arch-x86.lisp" net-dir))
                          (read-file-text (merge-pathnames "arch-aarch64.lisp" net-dir))
                          (read-file-text (merge-pathnames "e1000.lisp" net-dir))
                          (read-file-text (merge-pathnames "ip.lisp" net-dir))
                          (read-file-text (merge-pathnames "crypto.lisp" net-dir))
                          (read-file-text (merge-pathnames "ssh.lisp" net-dir))
                          (read-file-text (merge-pathnames "aarch64-overrides.lisp" net-dir)))))
        (format t "  Networking source: ~D chars~%" (length text))
        text))))

;;; Build-image-cross: the bare-metal cross-compilation entry point.
;;; This function reads the embedded MVM bytecode and function table,
;;; then calls the appropriate translator to produce native code for
;;; the target architecture.
;;;
;;; On bare metal, the fixpoint data is stored at:
;;;   0x300000: MVM bytecode address (tagged fixnum)
;;;   0x300008: MVM bytecode length (tagged fixnum)
;;;   0x300010: function table address (tagged fixnum)
;;;   0x300018: function table entry count (tagged fixnum)
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
;;; Diagnostics at 0x300040+ use u32 LE format
(defun error (msg)
  ;; Print ERR: using direct char codes (not string literals)
  (write-char-serial 69) (write-char-serial 82)
  (write-char-serial 82) (write-char-serial 58)
  ;; Print current function index from diagnostic address
  (write-char-serial 102) ;; f
  (print-dec (td-read-u32 #x300040))
  ;; Print step checkpoint
  (write-char-serial 115) ;; s
  (print-dec (td-read-u32 #x300044))
  ;; Print current bytecode position
  (write-char-serial 64) ;; @
  (print-dec (td-read-u32 #x300048))
  ;; Print opcode
  (write-char-serial 111) ;; o
  (print-dec (td-read-u32 #x30004C))
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

;;; Fixpoint metadata layout (all u32 LE at VA 0x300000):
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
  (let ((img-base (td-read-u32 #x300030)))
    (let ((bc-off (td-read-u32 #x30000C)))
      (let ((bc-len (td-read-u32 #x300010)))
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
  (let ((img-base (td-read-u32 #x300030)))
    (let ((ft-off (td-read-u32 #x300014)))
      (let ((ft-count (td-read-u32 #x300018)))
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
          ;; Post-fixup FNV
          (let ((pos (code-buffer-position buf))
                (bytes (code-buffer-bytes buf)))
            (print-dec pos) (write-char-serial 10)
            (let ((fnv 2166136261) (fi 0))
              (loop
                (when (>= fi pos) (return nil))
                (let ((xv (logxor fnv (aref bytes fi))))
                  (setq fnv (logand (* xv 16777619) 4294967295)))
                (setq fi (+ fi 1)))
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
  (let ((size (td-read-u32 #x300024))
        (i 0))
    (let ((load-addr (td-read-u32 #x300030)))
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
      (let ((km-offset (td-read-u32 #x30002C)))
        (let ((jmp-pos (img-pos)))
          (img-emit #xE9)
          (img-emit-u32 km-offset)
          ;; 4. Copy native code from code-buffer
          (write-char-serial 78) ;; N
          ;; Save code-start position in diagnostic slot for metadata
          (td-write-u32 #x300050 (img-pos))
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
              ;; 7. Write fixpoint metadata at offset 0x200000 (= VA 0x300000 for x64)
              ;; All values as u32 LE
              (let ((md-img-off #x200000))
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
                (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x300050))
                ;; native-code-length
                (img-patch-u32 (+ md-img-off 32) native-size)
                ;; preamble-size (same as running kernel)
                (let ((preamble (td-read-u32 #x300024)))
                  (img-patch-u32 (+ md-img-off 36) preamble))
                ;; kernel-main-hash-lo (copy from running kernel)
                (let ((km-hash (td-read-u32 #x300028)))
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
              (let ((total-size (+ #x200000 64)))
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
      (let ((my-arch (td-read-u32 #x300008)))
        ;; Dispatch: x64 host → aarch64 target (cross), or same-arch, or return trip
        (if (zerop my-arch)
            ;; Running on x64
            (if (zerop target)
                (build-x64-from-x64 bc ft)
                (build-aarch64-from-x64 bc ft))
            ;; Running on AArch64
            (if (zerop target)
                (build-x64-from-aarch64 bc ft)
                (build-x64-from-x64 bc ft))))  ;; fallback: same-arch via x64
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
                                              (ash (logand offset #x7FFFF) 5)
                                              cond-bits)))
                         ;; Check for bad bit4: write to scratch and check
                         (setf (mem-ref #x300078 :u64) new-word)
                         (let ((check-b0 (mem-ref #x300078 :u8)))
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
                             (aset code index
                                   (logior (ash immlo 29)
                                           (ash 16 24)
                                           (ash immhi 5)
                                           rd)))))))
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
  (setf (mem-ref #x300058 :u64) buf))

(defun get-current-a64-buf ()
  (mem-ref #x300058 :u64))

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
      (td-write-u32 #x300048 pos)
      ;; Set label if this offset has one
      (let ((label (gethash pos mvm-to-native-label)))
        (when label
          (a64-set-label buf label)))
      ;; Decode instruction
      (let ((decoded (decode-instruction bytecode pos)))
        (let ((opcode (car decoded))
              (operands (car (cdr decoded)))
              (new-pos (cdr (cdr decoded))))
          (td-write-u32 #x30004C opcode)
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
              (td-write-u32 #x300040 i)
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
                  (setf (mem-ref #x300070 :u64) w)
                  ;; :u64 writes raw tagged bits. Now read byte 3 (bits [31:24] of tagged)
                  ;; Tagged = untagged << 1, so byte 3 of tagged is different from untagged.
                  ;; For untagged 0x54000001, tagged 0xA8000002:
                  ;; byte0=0x02, byte1=0x00, byte2=0x00, byte3=0xA8
                  ;; We want to check untagged byte3 = 0x54. That's tagged byte3 = 0xA8.
                  (let ((tb3 (mem-ref #x300073 :u8)))
                    (when (= tb3 #xA8)
                      ;; Check bit 4 of untagged byte0 = bit 5 of tagged byte0
                      (let ((tb0 (mem-ref #x300070 :u8)))
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
;;; Image layout: [boot preamble 4096B] [native code at offset 0x1000] [bytecodes] [fn-table] [pad] [metadata at 0x300000]
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
      (let ((km-hash (td-read-u32 #x300028)))
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
      (td-write-u32 #x300050 (img-pos))
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
          ;; 6. Write metadata at offset 0x280000
          ;; QEMU virt loads raw binary at PA 0x40080000 (not 0x40000000).
          ;; MMU maps VA = PA - 0x40000000, so image start VA = 0x80000.
          ;; Metadata VA must be 0x300000, so image offset = 0x300000 - 0x80000 = 0x280000.
          (let ((md-img-off #x280000))
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
            (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x300050))
            ;; native-code-length
            (img-patch-u32 (+ md-img-off 32) native-size)
            ;; preamble-size = 0x1000 (4096, AArch64 boot preamble)
            (img-patch-u32 (+ md-img-off 36) #x1000)
            ;; kernel-main-hash-lo (copy from running kernel)
            (let ((km-hash (td-read-u32 #x300028)))
              (img-patch-u32 (+ md-img-off 40) km-hash))
            ;; kernel-main native offset (look up in fn-map)
            (let ((km-native-off (gethash (td-read-u32 #x300028) fn-map)))
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
          ;; Total size must cover metadata at 0x280000
          (let ((total-size (+ #x280000 64)))
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
        (let ((km-hash (td-read-u32 #x300028)))
          (let ((km-label (gethash km-hash fn-map)))
            (let ((km-offset 0))
              (when km-label
                (setq km-offset (aref km-label 1)))
              ;; JMP rel32
              (img-emit #xE9)
              (img-emit-u32 km-offset))))
        ;; 4. Copy native code
        (write-char-serial 78) ;; N
        (td-write-u32 #x300050 (img-pos))
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
            ;; 7. Write metadata at offset 0x200000 (= VA 0x300000 for x64)
            (let ((md-img-off #x200000))
              ;; magic
              (img-patch-u32 md-img-off #x544D564D)
              (img-patch-u32 (+ md-img-off 4) 1)
              ;; my-architecture = 0 (x64)
              (img-patch-u32 (+ md-img-off 8) 0)
              (img-patch-u32 (+ md-img-off 12) bc-img-offset)
              (img-patch-u32 (+ md-img-off 16) bc-len)
              (img-patch-u32 (+ md-img-off 20) ft-img-offset)
              (img-patch-u32 (+ md-img-off 24) ft-count)
              (img-patch-u32 (+ md-img-off 28) (td-read-u32 #x300050))
              (img-patch-u32 (+ md-img-off 32) native-size)
              (img-patch-u32 (+ md-img-off 36) boot-size)
              ;; kernel-main-hash-lo
              (let ((km-hash (td-read-u32 #x300028)))
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
            (let ((total-size (+ #x200000 64)))
              (let ((load-end (+ #x100000 total-size)))
                (img-patch-u32 20 load-end)
                (img-patch-u32 24 load-end))
              (write-char-serial 88) (write-char-serial 49) ;; X1
              (write-char-serial 61) ;; =
              (print-dec total-size) (write-char-serial 10)
              total-size)))))))
")

;;; SSH kernel-main function (only included when --ssh)
(when *fixpoint-ssh-mode*
  (setf *fixpoint-extra-source*
        (concatenate 'string *fixpoint-extra-source*
                     "
;;; SSH server entry point — called when metadata mode=1
(defun ssh-kernel-main ()
  ;; PCI + E1000 setup
  (write-char-serial 91) (write-char-serial 49) (write-char-serial 93) ;; [1]
  (pci-assign-bars)
  (write-char-serial 91) (write-char-serial 50) (write-char-serial 93) ;; [2]
  (e1000-probe)
  ;; Crypto initialization
  (write-char-serial 91) (write-char-serial 51) (write-char-serial 93) ;; [3]
  (sha256-init)
  (write-char-serial 91) (write-char-serial 52) (write-char-serial 93) ;; [4]
  (sha512-init)
  ;; --- Crypto diagnostics (diag9) ---
  ;; Test SHA-256(empty) — should be E3B0C44298FC1C14...
  (let ((empty (make-array 0)))
    (let ((he (sha256 empty)))
      (write-char-serial 83) (write-char-serial 50) (write-char-serial 58) ;; S2:
      (dotimes (ti 8) (print-hex-byte (aref he ti)))
      (write-char-serial 10)))
  ;; --- end diagnostics ---
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
  (write-char-serial 73) (write-char-serial 57) (write-char-serial 10)
  ;; Check mode: 0=cross-compile, 1=SSH server
  (let ((mode (td-read-u32 #x300038)))
    (if (= mode 1)
        ;; SSH server mode
        (ssh-kernel-main)
        ;; Cross-compile mode: read target from metadata
        (let ((target (td-read-u32 #x300034)))
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
          ;; Metadata at offset 0x200000 (= VA 0x300000 for x64) uses
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
                 ;; Metadata at fixed offset 0x200000 (address 0x300000)
                 (metadata-offset #x200000)
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

            ;; Write fixpoint metadata at offset 0x200000 (address 0x300000)
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
              (format t "  Metadata at: 0x300000 (offset 0x200000)~%")))))))
