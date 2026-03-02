;;;; actors-aarch64.lisp - AArch64 hardware layer for actor system
;;;;
;;;; Provides address constants and hardware-specific hooks for the
;;;; shared actor system (actors.lisp). Loaded BEFORE actors.lisp.
;;;;
;;;; Memory layout (QEMU virt, RAM at 0x40000000):
;;;;   0x41200000  Per-CPU data (8 CPUs x 64 bytes = 512 bytes)
;;;;   0x41200200  Locks: +0x00 scheduler, +0x08 pool, +0x10 actor-table
;;;;   0x41201000  Idle stacks (8 x 4KB = 32KB)
;;;;   0x41210000  Actor table (64 x 128 bytes = 8KB)
;;;;   0x41212000  Scheduler state
;;;;   0x41220000  Actor stacks (64 x 64KB = 4MB)
;;;;   0x41620000  Mailbox pool (128KB = 8192 x 16-byte cells)
;;;;   0x41640000  Pool state
;;;;   0x41700000  Staging buffers (64 x 16KB = 1MB)
;;;;   0x46000000  Per-actor heaps (64 x 4MB = 256MB)

;;; ============================================================
;;; Address hooks (called by actors.lisp)
;;; ============================================================

(defun actor-table-base () #x41210000)
(defun sched-state-base () #x41212000)
(defun sched-lock-addr () #x41200200)
(defun mailbox-pool-base () #x41620000)
(defun mailbox-pool-limit () #x41640000)
(defun pool-state-base () #x41640000)
(defun staging-base-addr () #x41700000)
(defun actor-stack-base () #x41220000)
(defun actor-heap-base () #x46000000)
(defun percpu-data-base () #x41200000)

;; Scratch word for bit manipulation (staging pointer tagging)
(defun scratch-addr () #x41212050)

;; Staging decode read pointer
(defun decode-ptr-addr () #x41212058)

;;; ============================================================
;;; Per-CPU accessors
;;; ============================================================
;;;
;;; AArch64 per-CPU layout (via TPIDR_EL1):
;;;   +0x00 self-ptr       +0x08 reduction
;;;   +0x10 cpu-id         +0x18 current-actor
;;;   +0x20 idle-flag      +0x28 obj-alloc
;;;   +0x30 obj-limit      +0x38 idle-stack-top
;;;
;;; x86 has current-actor at +0x00; AArch64 at +0x18.
;;; All other shared offsets (idle, obj-alloc, obj-limit) match.

(defun get-current-actor () (percpu-ref 24))
(defun set-current-actor (val) (percpu-set 24 val))

(defun get-idle-flag () (percpu-ref 32))
(defun set-idle-flag (val) (percpu-set 32 val))

;;; ============================================================
;;; SMP initialization (single CPU for Phase 1)
;;; ============================================================

(defun smp-init ()
  ;; TPIDR_EL1 already set to 0x41200000 by boot code
  ;; Initialize per-CPU data for BSP (CPU 0)
  (let ((base (percpu-data-base)))
    (setf (mem-ref base :u64) base)            ; self-ptr
    (setf (mem-ref (+ base 8) :u64) 0)         ; reduction
    (setf (mem-ref (+ base 16) :u64) 0)        ; cpu-id = 0
    (setf (mem-ref (+ base 24) :u64) 0)        ; current-actor (set by actor-init)
    (setf (mem-ref (+ base 32) :u64) 0)        ; idle-flag = 0
    ;; obj-alloc and obj-limit already set by boot code via x24/x25
    ;; idle stack top for CPU 0: base of idle stack area + 4KB
    (setf (mem-ref (+ base 56) :u64) #x41202000))
  ;; Zero lock variables
  (setf (mem-ref (sched-lock-addr) :u64) 0)
  (let ((lk2 (+ (sched-lock-addr) 8)))
    (setf (mem-ref lk2 :u64) 0))
  (let ((lk3 (+ (sched-lock-addr) 16)))
    (setf (mem-ref lk3 :u64) 0))
  ;; CPU count = 1 (single CPU)
  (let ((cc (+ (sched-state-base) #x20)))
    (setf (mem-ref cc :u64) 1))
  ;; Print "SMP1"
  (write-byte 83) (write-byte 77) (write-byte 80)
  (write-byte 49) (write-byte 10)
  1)

;;; ============================================================
;;; IPI / Wake (stubs for single CPU)
;;; ============================================================

;; Send SGI 0 to target CPU via GICv2
;; GICD_SGIR (0x08000F00): write target CPU in bits [23:16], SGI ID in [3:0]
(defun send-ipi-to-idle (target-cpu)
  ;; Phase 1: single CPU, no APs to signal
  0)

;; Scan per-CPU idle flags and wake first idle CPU
(defun wake-idle-ap ()
  ;; Phase 1: single CPU, no APs to wake
  0)

;;; ============================================================
;;; Shutdown
;;; ============================================================

(defun shutdown ()
  ;; Print "Bye\n" then halt
  (write-byte 66) (write-byte 121) (write-byte 101) (write-byte 10)
  (loop (halt)))
