;;;; multiboot.lisp - Multiboot2 Header Generator
;;;;
;;;; Generates the Multiboot2 header that GRUB uses to load our kernel.
;;;; The header must be in the first 8KB of the kernel image.
;;;;
;;;; Reference: https://www.gnu.org/software/grub/manual/multiboot2/

(in-package :modus64.cross)

;;; ============================================================
;;; Multiboot2 Constants
;;; ============================================================

(defconstant +multiboot2-magic+ #xE85250D6)
(defconstant +multiboot2-arch-i386+ 0)  ; Also used for x86-64
(defconstant +multiboot2-header-length+ 24)

;; Tag types
(defconstant +multiboot2-tag-end+            0)
(defconstant +multiboot2-tag-info-request+   1)
(defconstant +multiboot2-tag-address+        2)
(defconstant +multiboot2-tag-entry+          3)
(defconstant +multiboot2-tag-console-flags+  4)
(defconstant +multiboot2-tag-framebuffer+    5)
(defconstant +multiboot2-tag-module-align+   6)
(defconstant +multiboot2-tag-efi-bs+         7)
(defconstant +multiboot2-tag-entry-efi32+    8)
(defconstant +multiboot2-tag-entry-efi64+    9)

;; Info request types (what we want from bootloader)
(defconstant +multiboot2-info-cmdline+      1)
(defconstant +multiboot2-info-bootloader+   2)
(defconstant +multiboot2-info-modules+      3)
(defconstant +multiboot2-info-mem-basic+    4)
(defconstant +multiboot2-info-bootdev+      5)
(defconstant +multiboot2-info-mmap+         6)
(defconstant +multiboot2-info-framebuffer+ 8)

;;; ============================================================
;;; Header Generation
;;; ============================================================

(defun emit-multiboot2-header (buf entry-address)
  "Emit Multiboot2 header into code buffer.
   ENTRY-ADDRESS is the 32-bit physical address of the entry point."
  (let ((header-start (code-buffer-position buf)))

    ;; Magic number
    (emit-u32 buf +multiboot2-magic+)

    ;; Architecture (0 = i386/x86-64)
    (emit-u32 buf +multiboot2-arch-i386+)

    ;; Header length (filled in at end)
    (let ((length-pos (code-buffer-position buf)))
      (emit-u32 buf 0)  ; placeholder

      ;; Checksum (filled in at end)
      (let ((checksum-pos (code-buffer-position buf)))
        (emit-u32 buf 0)  ; placeholder

        ;; === Tags ===

        ;; Information request tag
        (emit-multiboot2-tag buf +multiboot2-tag-info-request+ 0
                             (lambda ()
                               (emit-u32 buf +multiboot2-info-mmap+)
                               (emit-u32 buf +multiboot2-info-cmdline+)))

        ;; Entry address tag (32-bit entry point)
        (emit-multiboot2-tag buf +multiboot2-tag-entry+ 0
                             (lambda ()
                               (emit-u32 buf entry-address)))

        ;; End tag
        (emit-multiboot2-tag buf +multiboot2-tag-end+ 0 nil)

        ;; Pad to 8-byte alignment
        (loop while (not (zerop (mod (code-buffer-position buf) 8)))
              do (emit-byte buf 0))

        ;; Fill in header length
        (let ((header-length (- (code-buffer-position buf) header-start)))
          (setf (aref (code-buffer-bytes buf) (+ length-pos 0))
                (ldb (byte 8 0) header-length))
          (setf (aref (code-buffer-bytes buf) (+ length-pos 1))
                (ldb (byte 8 8) header-length))
          (setf (aref (code-buffer-bytes buf) (+ length-pos 2))
                (ldb (byte 8 16) header-length))
          (setf (aref (code-buffer-bytes buf) (+ length-pos 3))
                (ldb (byte 8 24) header-length))

          ;; Fill in checksum (must make all fields sum to 0)
          (let ((checksum (ldb (byte 32 0)
                               (- (+ +multiboot2-magic+
                                     +multiboot2-arch-i386+
                                     header-length)))))
            (setf (aref (code-buffer-bytes buf) (+ checksum-pos 0))
                  (ldb (byte 8 0) checksum))
            (setf (aref (code-buffer-bytes buf) (+ checksum-pos 1))
                  (ldb (byte 8 8) checksum))
            (setf (aref (code-buffer-bytes buf) (+ checksum-pos 2))
                  (ldb (byte 8 16) checksum))
            (setf (aref (code-buffer-bytes buf) (+ checksum-pos 3))
                  (ldb (byte 8 24) checksum))))))))

(defun emit-multiboot2-tag (buf type flags body-fn)
  "Emit a Multiboot2 tag"
  (let ((tag-start (code-buffer-position buf)))
    ;; Type (u16)
    (emit-u16 buf type)
    ;; Flags (u16)
    (emit-u16 buf flags)
    ;; Size (u32) - placeholder
    (let ((size-pos (code-buffer-position buf)))
      (emit-u32 buf 0)
      ;; Body
      (when body-fn
        (funcall body-fn))
      ;; Fill in size
      (let ((tag-size (- (code-buffer-position buf) tag-start)))
        (setf (aref (code-buffer-bytes buf) (+ size-pos 0))
              (ldb (byte 8 0) tag-size))
        (setf (aref (code-buffer-bytes buf) (+ size-pos 1))
              (ldb (byte 8 8) tag-size))
        (setf (aref (code-buffer-bytes buf) (+ size-pos 2))
              (ldb (byte 8 16) tag-size))
        (setf (aref (code-buffer-bytes buf) (+ size-pos 3))
              (ldb (byte 8 24) tag-size)))
      ;; Pad to 8-byte alignment
      (loop while (not (zerop (mod (code-buffer-position buf) 8)))
            do (emit-byte buf 0)))))

;;; ============================================================
;;; Testing
;;; ============================================================

(defun test-multiboot2-header ()
  "Test Multiboot2 header generation"
  (let ((buf (make-code-buffer)))
    (emit-multiboot2-header buf #x00100000)  ; Entry at 1MB
    (format t "Multiboot2 header: ~D bytes~%" (code-buffer-position buf))
    (format t "First 32 bytes: ~{~2,'0X ~}~%"
            (coerce (subseq (code-buffer-bytes buf) 0
                           (min 32 (code-buffer-position buf)))
                    'list))
    ;; Verify magic
    (let ((magic (logior (aref (code-buffer-bytes buf) 0)
                         (ash (aref (code-buffer-bytes buf) 1) 8)
                         (ash (aref (code-buffer-bytes buf) 2) 16)
                         (ash (aref (code-buffer-bytes buf) 3) 24))))
      (format t "Magic: ~8,'0X (expected ~8,'0X) ~A~%"
              magic +multiboot2-magic+
              (if (= magic +multiboot2-magic+) "OK" "FAIL")))
    buf))
