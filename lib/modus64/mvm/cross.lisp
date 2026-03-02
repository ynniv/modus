;;;; cross.lisp - Universal Cross-Compilation for Modus64
;;;;
;;;; The endgame: a running Modus instance on any architecture can
;;;; build kernel images for any other architecture.
;;;;
;;;; Pipeline:
;;;;   1. Read embedded source (plain Lisp text)
;;;;   2. Compile through MVM compiler (target-independent)
;;;;   3. Select target descriptor for desired architecture
;;;;   4. Translate MVM bytecode to native code via target translator
;;;;   5. Emit bootable kernel image with target's boot code
;;;;   6. Embed same source text in new image (for self-replication)

(in-package :modus64.mvm)

;;; ============================================================
;;; Compilation Module
;;; ============================================================

(defstruct mvm-module
  name              ; module name (keyword)
  bytecode          ; byte vector of MVM bytecode
  function-table    ; list of function-info structs
  constant-table    ; list of constant values
  source-text       ; original source text (for embedding)
  metadata)         ; plist of additional info

(defstruct mvm-function-info
  name              ; function name (symbol or string)
  name-hash         ; hash of function name (for runtime lookup)
  param-count       ; number of parameters
  bytecode-offset   ; offset into module bytecode
  bytecode-length   ; length of this function's bytecode
  native-offset     ; offset in native code (filled by translator)
  native-length)    ; length of native code (filled by translator)

;;; ============================================================
;;; Image Builder
;;; ============================================================

(defstruct kernel-image
  target            ; target descriptor
  boot-code         ; byte vector of boot code (architecture-specific)
  native-code       ; byte vector of translated native code
  constant-data     ; byte vector of constant pool
  source-blob       ; embedded source text (for next-generation compilation)
  symbol-table      ; NFN table data
  gc-metadata       ; GC root information
  image-bytes       ; final assembled image (byte vector)
  entry-point       ; offset of kernel-main in native code
  metadata)         ; plist of image metadata

;;; ============================================================
;;; Cross-Compilation Pipeline
;;; ============================================================

(defun compile-source-to-module (source-text &key (name :kernel))
  "Phase 1: Compile Lisp source text to an MVM module.
   This is 100% target-independent.
   Delegates to the MVM compiler (compiler.lisp) for the actual
   compilation, then converts the result to an mvm-module for
   the image building pipeline."
  ;; Read source forms
  (let* ((forms (read-all-forms source-text))
         ;; Compile all forms through the MVM compiler
         ;; mvm-compile-all is defined in compiler.lisp and returns
         ;; a compiled-module struct
         (compiled-mod (mvm-compile-all forms))
         ;; Convert to mvm-module for the image pipeline
         (module (compiled-module-to-mvm-module compiled-mod source-text)))
    (setf (mvm-module-name module) name)
    module))

(defun translate-module-to-native (module target)
  "Phase 2: Translate MVM bytecode to native code for TARGET.
   Calls the target's bulk translator with (bytecode function-table),
   extracts native bytes from the architecture-specific buffer,
   and maps native offsets back to mvm-function-info structs."
  (let ((translator (target-translate-fn target)))
    (unless translator
      (error "No translator installed for target ~A" (target-name target)))
    (let* ((fn-list (mvm-module-function-table module))
           (bytecode (mvm-module-bytecode module))
           ;; Build function table in the format each translator expects
           (fn-table (build-translator-fn-table fn-list target)))
      ;; Call the bulk translator — returns an arch-specific buffer
      ;; (some return multiple values; we only need the first)
      (let* ((buf (funcall translator bytecode fn-table))
             (native-bytes (extract-native-bytes buf target)))
        ;; Map native offsets proportionally from bytecode positions
        (let ((total-bc (max 1 (length bytecode)))
              (total-native (length native-bytes)))
          (dolist (fn-info fn-list)
            (let* ((bc-off (mvm-function-info-bytecode-offset fn-info))
                   (bc-len (mvm-function-info-bytecode-length fn-info))
                   (native-off (truncate (* bc-off total-native) total-bc))
                   (native-len (truncate (* bc-len total-native) total-bc)))
              (setf (mvm-function-info-native-offset fn-info) native-off)
              (setf (mvm-function-info-native-length fn-info) native-len))))
        native-bytes))))

(defun build-translator-fn-table (fn-list target)
  "Build a function table in the format the target's translator expects.
   x86-64 and i386 want a list of (name offset length).
   Others want a hash-table of index → bytecode-offset."
  (let ((name (target-name target)))
    (if (member name '(:x86-64 :i386))
        ;; List of (name offset length)
        (mapcar (lambda (fi)
                  (list (string (mvm-function-info-name fi))
                        (mvm-function-info-bytecode-offset fi)
                        (mvm-function-info-bytecode-length fi)))
                fn-list)
        ;; Hash-table of index → bytecode-offset (riscv64, aarch64, ppc64, ppc32, 68k)
        (let ((ht (make-hash-table)))
          (loop for fi in fn-list
                for i from 0
                do (setf (gethash i ht)
                         (mvm-function-info-bytecode-offset fi)))
          ht))))

(defun extract-native-bytes (buf target)
  "Extract a byte vector from an architecture-specific native code buffer."
  (cond
    ;; If it's already a byte vector, return as-is
    ((and (typep buf 'vector)
          (or (zerop (length buf))
              (integerp (aref buf 0))))
     buf)
    ;; Try known buffer types by target name
    (t
     (let ((name (target-name target)))
       (handler-case
           (ecase name
             (:riscv64
              ;; rv-buffer has bytes slot with fill-pointer
              (let* ((raw (rv-buffer-bytes buf))
                     (len (fill-pointer raw))
                     (result (make-array len :element-type '(unsigned-byte 8))))
                (replace result raw)
                result))
             (:aarch64  (a64-buffer-to-bytes buf))
             ((:ppc64 :ppc32) (ppc-buffer-to-bytes buf))
             (:i386     (modus64.mvm.i386:i386-buffer-to-bytes buf))
             (:68k      (m68k-buffer-to-bytes buf))
             ((:arm32 :armv7) (arm32-buffer-to-bytes buf))
             (:x86-64
              ;; x64 translator uses code-buffer from modus64.asm
              (let* ((raw (modus64.asm:code-buffer-bytes buf))
                     (len (fill-pointer raw))
                     (result (make-array len :element-type '(unsigned-byte 8))))
                (replace result raw)
                result)))
         (error (e)
           (declare (ignore e))
           (make-array 0 :element-type '(unsigned-byte 8))))))))

(defun build-constant-pool (module target)
  "Build the constant pool for the image.
   Serializes constants according to target endianness and word size."
  (let ((buf (make-mvm-buffer))
        (word-size (target-word-size target)))
    (dolist (constant (mvm-module-constant-table module))
      (etypecase constant
        (integer
         (if (= word-size 8)
             (mvm-emit-u64 buf (ash constant 1))  ; tagged fixnum
             (mvm-emit-u32 buf (ash constant 1))))
        (string
         ;; String object: [header:word | chars...]
         (let ((header (logior #x10 (ash (length constant) 16))))
           (if (= word-size 8)
               (mvm-emit-u64 buf header)
               (mvm-emit-u32 buf header)))
         (loop for c across constant
               do (mvm-emit-byte buf (char-code c)))
         ;; Align to word boundary
         (loop while (/= 0 (mod (mvm-buffer-position buf) word-size))
               do (mvm-emit-byte buf 0)))
        (null
         ;; NIL placeholder
         (if (= word-size 8)
             (mvm-emit-u64 buf 0)
             (mvm-emit-u32 buf 0)))))
    (mvm-buffer-bytes buf)))

(defun build-nfn-table (module target)
  "Build the NFN (Name-to-Function-Number) table.
   Maps name hashes to native code offsets."
  (let ((buf (make-mvm-buffer))
        (word-size (target-word-size target)))
    ;; Table format: [count:word] [hash:word addr:word]*
    (let ((functions (mvm-module-function-table module)))
      (if (= word-size 8)
          (mvm-emit-u64 buf (length functions))
          (mvm-emit-u32 buf (length functions)))
      (dolist (fn-info functions)
        (if (= word-size 8)
            (progn
              (mvm-emit-u64 buf (mvm-function-info-name-hash fn-info))
              (mvm-emit-u64 buf (mvm-function-info-native-offset fn-info)))
            (progn
              (mvm-emit-u32 buf (mvm-function-info-name-hash fn-info))
              (mvm-emit-u32 buf (mvm-function-info-native-offset fn-info))))))
    (mvm-buffer-bytes buf)))

(defun embed-source-blob (source-text target)
  "Prepare the source text for embedding in the kernel image.
   The source is stored as plain ASCII text, readable by the
   self-contained reader (Phase 1a)."
  (let ((buf (make-mvm-buffer)))
    ;; Source blob header: [magic:4 | length:4 | text...]
    (mvm-emit-u32 buf #x4D564D53)  ; "MVMS" magic
    (mvm-emit-u32 buf (length source-text))
    (loop for c across source-text
          do (mvm-emit-byte buf (char-code c)))
    ;; Align to word boundary
    (loop while (/= 0 (mod (mvm-buffer-position buf) (target-word-size target)))
          do (mvm-emit-byte buf 0))
    (mvm-buffer-bytes buf)))

;;; ============================================================
;;; ELF Wrappers (for QEMU -kernel loading)
;;; ============================================================

(defun emit-elf-be16 (buf val)
  "Emit 16-bit value in big-endian order."
  (mvm-emit-byte buf (logand (ash val -8) #xFF))
  (mvm-emit-byte buf (logand val #xFF)))

(defun emit-elf-be32 (buf val)
  "Emit 32-bit value in big-endian order."
  (mvm-emit-byte buf (logand (ash val -24) #xFF))
  (mvm-emit-byte buf (logand (ash val -16) #xFF))
  (mvm-emit-byte buf (logand (ash val -8) #xFF))
  (mvm-emit-byte buf (logand val #xFF)))

(defun emit-elf-be64 (buf val)
  "Emit 64-bit value in big-endian order."
  (emit-elf-be32 buf (logand (ash val -32) #xFFFFFFFF))
  (emit-elf-be32 buf (logand val #xFFFFFFFF)))

(defun wrap-in-elf32-be (raw-bytes load-addr e-machine)
  "Wrap raw image bytes in a minimal big-endian ELF32 executable.
   The entire raw image is loaded at LOAD-ADDR. Entry point is LOAD-ADDR
   (first byte of raw image = boot code entry stub)."
  (let* ((buf (make-mvm-buffer))
         (ehdr-size 52)
         (phdr-size 32)
         (hdr-total (+ ehdr-size phdr-size))
         (total-size (+ hdr-total (length raw-bytes)))
         (entry-addr (+ load-addr hdr-total)))
    ;; ---- ELF header (52 bytes) ----
    ;; e_ident: magic
    (mvm-emit-byte buf #x7F)
    (mvm-emit-byte buf (char-code #\E))
    (mvm-emit-byte buf (char-code #\L))
    (mvm-emit-byte buf (char-code #\F))
    ;; EI_CLASS=1 (32-bit), EI_DATA=2 (big-endian), EI_VERSION=1
    (mvm-emit-byte buf 1) (mvm-emit-byte buf 2) (mvm-emit-byte buf 1)
    ;; EI_OSABI + padding (9 bytes)
    (dotimes (i 9) (mvm-emit-byte buf 0))
    ;; e_type = ET_EXEC (2)
    (emit-elf-be16 buf 2)
    ;; e_machine
    (emit-elf-be16 buf e-machine)
    ;; e_version = 1
    (emit-elf-be32 buf 1)
    ;; e_entry = entry point (after ELF headers)
    (emit-elf-be32 buf entry-addr)
    ;; e_phoff = 52
    (emit-elf-be32 buf ehdr-size)
    ;; e_shoff = 0
    (emit-elf-be32 buf 0)
    ;; e_flags = 0
    (emit-elf-be32 buf 0)
    ;; e_ehsize = 52
    (emit-elf-be16 buf ehdr-size)
    ;; e_phentsize = 32
    (emit-elf-be16 buf phdr-size)
    ;; e_phnum = 1
    (emit-elf-be16 buf 1)
    ;; e_shentsize=0, e_shnum=0, e_shstrndx=0
    (emit-elf-be16 buf 0)
    (emit-elf-be16 buf 0)
    (emit-elf-be16 buf 0)
    ;; ---- Program header (32 bytes) ----
    ;; p_type = PT_LOAD (1)
    (emit-elf-be32 buf 1)
    ;; p_offset = 0 (load from start of file, including headers)
    (emit-elf-be32 buf 0)
    ;; p_vaddr = load_addr
    (emit-elf-be32 buf load-addr)
    ;; p_paddr = load_addr
    (emit-elf-be32 buf load-addr)
    ;; p_filesz = total file size
    (emit-elf-be32 buf total-size)
    ;; p_memsz = file size + 1MB extra for BSS/stack
    (emit-elf-be32 buf (+ total-size #x100000))
    ;; p_flags = PF_R|PF_W|PF_X (7)
    (emit-elf-be32 buf 7)
    ;; p_align = 4096
    (emit-elf-be32 buf #x1000)
    ;; ---- Raw image data ----
    (loop for b across raw-bytes do (mvm-emit-byte buf b))
    (mvm-buffer-bytes buf)))

(defun wrap-in-elf64-be (raw-bytes load-addr e-machine &optional (e-flags 0))
  "Wrap raw image bytes in a minimal big-endian ELF64 executable."
  (let* ((buf (make-mvm-buffer))
         (ehdr-size 64)
         (phdr-size 56)
         (hdr-total (+ ehdr-size phdr-size))
         (total-size (+ hdr-total (length raw-bytes)))
         (entry-addr (+ load-addr hdr-total)))
    ;; ---- ELF header (64 bytes) ----
    (mvm-emit-byte buf #x7F)
    (mvm-emit-byte buf (char-code #\E))
    (mvm-emit-byte buf (char-code #\L))
    (mvm-emit-byte buf (char-code #\F))
    ;; EI_CLASS=2 (64-bit), EI_DATA=2 (big-endian), EI_VERSION=1
    (mvm-emit-byte buf 2) (mvm-emit-byte buf 2) (mvm-emit-byte buf 1)
    (dotimes (i 9) (mvm-emit-byte buf 0))
    ;; e_type = ET_EXEC (2)
    (emit-elf-be16 buf 2)
    ;; e_machine
    (emit-elf-be16 buf e-machine)
    ;; e_version = 1
    (emit-elf-be32 buf 1)
    ;; e_entry (64-bit)
    (emit-elf-be64 buf entry-addr)
    ;; e_phoff = 64
    (emit-elf-be64 buf ehdr-size)
    ;; e_shoff = 0
    (emit-elf-be64 buf 0)
    ;; e_flags (e.g. 2 for PPC64 ELFv2 ABI)
    (emit-elf-be32 buf e-flags)
    ;; e_ehsize = 64
    (emit-elf-be16 buf ehdr-size)
    ;; e_phentsize = 56
    (emit-elf-be16 buf phdr-size)
    ;; e_phnum = 1
    (emit-elf-be16 buf 1)
    ;; e_shentsize=0, e_shnum=0, e_shstrndx=0
    (emit-elf-be16 buf 0)
    (emit-elf-be16 buf 0)
    (emit-elf-be16 buf 0)
    ;; ---- Program header (56 bytes) ----
    ;; p_type = PT_LOAD (1)
    (emit-elf-be32 buf 1)
    ;; p_flags = PF_R|PF_W|PF_X (7) — note: flags at offset 4 in ELF64
    (emit-elf-be32 buf 7)
    ;; p_offset = 0
    (emit-elf-be64 buf 0)
    ;; p_vaddr = load_addr
    (emit-elf-be64 buf load-addr)
    ;; p_paddr = load_addr
    (emit-elf-be64 buf load-addr)
    ;; p_filesz
    (emit-elf-be64 buf total-size)
    ;; p_memsz
    (emit-elf-be64 buf (+ total-size #x100000))
    ;; p_align = 4096
    (emit-elf-be64 buf #x1000)
    ;; ---- Raw image data ----
    (loop for b across raw-bytes do (mvm-emit-byte buf b))
    (mvm-buffer-bytes buf)))

;;; ============================================================
;;; Image Assembly
;;; ============================================================

(defun assemble-kernel-image (module target &key boot-descriptor)
  "Assemble a complete bootable kernel image for TARGET."
  (let* ((native-code (translate-module-to-native module target))
         (constant-pool (build-constant-pool module target))
         (nfn-table (build-nfn-table module target))
         (source-blob (embed-source-blob
                       (mvm-module-source-text module) target))
         (image (make-kernel-image
                 :target target
                 :native-code native-code
                 :constant-data constant-pool
                 :source-blob source-blob
                 :symbol-table nfn-table)))
    ;; Emit boot code (architecture-specific)
    (when boot-descriptor
      (let ((boot-buf (make-mvm-buffer)))
        ;; x86-64 has a multi-stage boot: multiboot header → 32-bit stub → 64-bit entry
        (let ((mb-fn  (getf boot-descriptor :multiboot-header-fn))
              (b32-fn (getf boot-descriptor :boot32-fn))
              (k64-fn (getf boot-descriptor :kernel64-entry-fn))
              (entry-fn (getf boot-descriptor :entry-fn)))
          (when mb-fn  (funcall mb-fn boot-buf))
          (when b32-fn (funcall b32-fn boot-buf))
          (when k64-fn (funcall k64-fn boot-buf))
          ;; Generic entry-fn (RISC-V, AArch64)
          (when entry-fn (funcall entry-fn boot-buf)))
        (setf (kernel-image-boot-code image)
              (mvm-buffer-bytes boot-buf))))
    ;; Find kernel-main entry point
    (dolist (fn-info (mvm-module-function-table module))
      (when (string-equal (string (mvm-function-info-name fn-info)) "KERNEL-MAIN")
        (setf (kernel-image-entry-point image)
              (mvm-function-info-native-offset fn-info))))
    ;; Assemble final image
    (let ((final-buf (make-mvm-buffer)))
      ;; Boot code (architecture-specific preamble)
      (when (kernel-image-boot-code image)
        (loop for b across (kernel-image-boot-code image)
              do (mvm-emit-byte final-buf b)))
      ;; Native code (kernel-main must be the first function in source
      ;; so that boot code falls through to it)
      (let ((code-offset (mvm-buffer-position final-buf)))
        (loop for b across native-code
              do (mvm-emit-byte final-buf b))
        ;; Update entry point to absolute offset
        (when (kernel-image-entry-point image)
          (incf (kernel-image-entry-point image) code-offset)))
      ;; Constant pool
      (loop for b across constant-pool
            do (mvm-emit-byte final-buf b))
      ;; NFN table
      (loop for b across nfn-table
            do (mvm-emit-byte final-buf b))
      ;; Source blob (for next-generation self-hosting)
      (loop for b across source-blob
            do (mvm-emit-byte final-buf b))
      ;; Image metadata footer
      (let ((word-size (target-word-size target)))
        ;; Total image size
        (if (= word-size 8)
            (mvm-emit-u64 final-buf (mvm-buffer-position final-buf))
            (mvm-emit-u32 final-buf (mvm-buffer-position final-buf)))
        ;; Source blob offset (for self-hosting reader)
        (if (= word-size 8)
            (mvm-emit-u64 final-buf (- (mvm-buffer-position final-buf)
                                        (length source-blob) 8))
            (mvm-emit-u32 final-buf (- (mvm-buffer-position final-buf)
                                        (length source-blob) 4))))
      (let ((raw-bytes (mvm-buffer-bytes final-buf)))
        ;; Wrap in ELF if target requires it (for QEMU -kernel loading)
        (setf (kernel-image-image-bytes image)
              (if boot-descriptor
                  (let ((elf-machine (getf boot-descriptor :elf-machine))
                        (load-addr (or (getf boot-descriptor :load-addr) 0))
                        (elf-class (getf boot-descriptor :elf-class 32))
                        (elf-flags (getf boot-descriptor :elf-flags 0)))
                    (cond
                      ((and elf-machine (= elf-class 32))
                       (wrap-in-elf32-be raw-bytes load-addr elf-machine))
                      ((and elf-machine (= elf-class 64))
                       (wrap-in-elf64-be raw-bytes load-addr elf-machine elf-flags))
                      (t raw-bytes)))
                  raw-bytes))))
    image))

;;; ============================================================
;;; Top-Level API
;;; ============================================================

(defun resolve-target-arch (target)
  "Resolve a target keyword to its underlying architecture keyword.
   Board-specific targets (e.g. :rpi) map to their base architecture."
  (case target
    (:rpi :aarch64)
    (otherwise target)))

(defun build-image (&key (target :x86-64) (source nil) (source-text nil))
  "Build a bootable kernel image for TARGET.

   TARGET: keyword naming the target architecture or board
           (:x86-64, :riscv64, :aarch64, :ppc64, :ppc32, :i386, :68k,
            :arm32, :rpi)

   SOURCE: list of Lisp forms to compile (alternative to source-text)

   SOURCE-TEXT: raw Lisp source text string (alternative to source)

   Returns a KERNEL-IMAGE struct with the assembled image.

   Usage:
     (build-image :target :riscv64)     ; from any running Modus
     (build-image :target :x86-64)      ; cross-compile back
     (build-image :target :aarch64)     ; or to ARM
     (build-image :target :rpi)         ; Raspberry Pi (AArch64)"
  (let* ((arch (resolve-target-arch target))
         (target-desc (find-target arch)))
    (unless target-desc
      (error "Unknown target architecture: ~A~%Known targets: ~{~A~^, ~}"
             target (list-targets)))
    ;; Get source
    (let ((src-text (or source-text
                       (when source
                         (with-output-to-string (s)
                           (dolist (form source)
                             (prin1 form s)
                             (terpri s))))
                       ;; In a running Modus kernel, read embedded source
                       ;; (read-embedded-source)
                       (error "No source provided"))))
      ;; Compile
      (let ((module (compile-source-to-module src-text)))
        ;; Get boot descriptor for target
        (let* ((boot-desc (get-boot-descriptor target))
               (serial-base (getf boot-desc :serial-base)))
          ;; Serial base priority: explicit setf > boot descriptor > QEMU virt default
          (let ((*aarch64-serial-base* (or *aarch64-serial-base* serial-base #x09000000)))
            ;; Assemble image
            (assemble-kernel-image module target-desc
                                   :boot-descriptor boot-desc)))))))

(defun get-boot-descriptor (target-name)
  "Get the boot descriptor for the given target architecture.
   Returns a boot descriptor plist, or NIL for architectures
   whose boot code has not yet been implemented."
  (case target-name
    (:x86-64  (x64-boot-descriptor))
    (:riscv64 (riscv-boot-descriptor))
    (:aarch64 (aarch64-boot-descriptor))
    (:ppc64   (ppc64-boot-descriptor))
    (:ppc32   (ppc32-boot-descriptor))
    (:i386    (i386-boot-descriptor))
    (:68k     (m68k-boot-descriptor))
    (:arm32   (arm32-boot-descriptor))
    (:armv7   (armv7-boot-descriptor))
    (:rpi     (rpi-boot-descriptor))
    (otherwise nil)))

(defun write-kernel-image (image pathname)
  "Write a kernel image to disk as a flat binary."
  (let ((bytes (kernel-image-image-bytes image)))
    (with-open-file (out pathname :direction :output
                                  :element-type '(unsigned-byte 8)
                                  :if-exists :supersede)
      (write-sequence bytes out))
    (format t "Wrote ~D bytes to ~A~%" (length bytes) pathname)
    pathname))

;;; ============================================================
;;; Cross-Compilation Matrix Test
;;; ============================================================

(defun test-cross-compilation ()
  "Test that cross-compilation works for all target pairs.
   Each architecture should be able to produce images for every other."
  (let ((targets (list-targets))
        (test-source '((defun add1 (x) (+ x 1))
                       (defun kernel-main () (add1 41)))))
    (dolist (target targets)
      (format t "~%Building for ~A...~%" target)
      (handler-case
          (let ((image (build-image :target target :source test-source)))
            (format t "  Success: ~D bytes~%"
                    (length (kernel-image-image-bytes image))))
        (error (e)
          (format t "  FAILED: ~A~%" e))))))

;;; ============================================================
;;; Self-Hosting Support
;;; ============================================================

(defun read-all-forms (source-text)
  "Read all Lisp forms from SOURCE-TEXT string.
   Returns a list of forms."
  (with-input-from-string (stream source-text)
    (loop for form = (read stream nil :eof)
          until (eq form :eof)
          collect form)))

(defun compute-name-hash (name-string)
  "Compute dual-FNV-1a hash for a function name.
   Two independent FNV-1a-32 hashes combined into a 60-bit value.
   Same algorithm as compute-hash-chars in build.lisp."
  (let ((name (string-upcase (string name-string)))
        (h1 2166136261) (h2 3735928559))
    (loop for c across name
          do (setq h1 (logand (* (logxor h1 (char-code c)) 16777619) #xFFFFFFFF))
             (setq h2 (logand (* (logxor h2 (char-code c)) 805306457) #xFFFFFFFF)))
    (let ((combined (logior (ash (logand h1 #x3FFFFFFF) 30)
                            (logand h2 #x3FFFFFFF))))
      (if (zerop combined) 1 combined))))

(defun compiled-module-to-mvm-module (compiled-mod source-text)
  "Convert a compiled-module (from compiler.lisp) to an mvm-module
   (used by the cross-compilation pipeline).
   Bridges the compiler's function-info to mvm-function-info with
   name hashes for the NFN table."
  (make-mvm-module
   :bytecode (compiled-module-bytecode compiled-mod)
   :function-table
   (mapcar (lambda (fi)
             (make-mvm-function-info
              :name (function-info-name fi)
              :name-hash (compute-name-hash (function-info-name fi))
              :param-count (function-info-param-count fi)
              :bytecode-offset (function-info-bytecode-offset fi)
              :bytecode-length (function-info-bytecode-length fi)
              :native-offset nil
              :native-length nil))
           (compiled-module-function-table compiled-mod))
   :constant-table (compiled-module-constant-table compiled-mod)
   :source-text source-text))
