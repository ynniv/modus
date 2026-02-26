# 64-bit Lisp Allocator Design

**Note**: The bump allocator and Cheney copying GC described here are implemented. Per-actor heaps with independent GC were added later (see `actors.md`).

## Overview

The allocator is the foundation of the runtime. Every `cons`, `make-array`,
function call, and closure creation goes through it. Getting this right
determines performance, memory efficiency, and GC behavior.

## Memory Regions

Based on Mezzano's proven design, we use five allocation regions:

```
+-------------------+  0x0000_0000_0500_0000  (80MB)
| General Area      |  <- Most objects go here
| (semispace A+B)   |
+-------------------+  0x0000_0000_0400_0000  (64MB)
| Cons Area         |  <- Optimized for pairs
| (semispace A+B)   |
+-------------------+  0x0000_0000_0380_0000  (56MB)
| Function Area     |  <- Code + closures
+-------------------+  0x0000_0000_0300_0000  (48MB)
| Pinned Area       |  <- DMA buffers, etc.
+-------------------+  0x0000_0000_0200_0000  (32MB)
| Wired Area        |  <- Kernel, never moves
+-------------------+  0x0000_0000_0100_0000  (16MB)
| Kernel Code       |  <- Bootstrap code
+-------------------+  0x0000_0000_0010_0000  (1MB)
| Low Memory        |  <- BIOS, legacy
+-------------------+  0x0000_0000_0000_0000
```

## Allocation Fast Path

Goal: allocate an 8-byte aligned object in ~10 instructions.

```asm
; Inputs:
;   R13 = allocation-pointer (current position)
;   R14 = allocation-limit (end of current page)
;   RDX = size in bytes (already aligned to 16)
;
; Output:
;   RAX = new object pointer (tagged)

alloc_fast:
    mov rax, r13              ; Current position
    add r13, rdx              ; Bump pointer
    cmp r13, r14              ; Check limit
    ja  alloc_slow            ; Slow path if overflow
    ret                       ; Return untagged pointer in RAX

alloc_slow:
    ; Save registers, call into GC/region extension
    call gc_maybe_collect
    jmp alloc_fast            ; Retry after GC
```

## Cons Cell Allocation

Cons cells are 16 bytes (CAR + CDR), always allocated from Cons Area:

```asm
; Fast cons allocation
; Inputs: RSI = car value, RDI = cdr value
; Output: RAX = tagged cons pointer

cons_fast:
    mov rax, [cons_ptr]       ; Current cons pointer
    mov rdx, rax
    add rdx, 16               ; Size of cons
    cmp rdx, [cons_limit]     ; Check limit
    ja  cons_slow
    mov [rax], rsi            ; Store CAR
    mov [rax+8], rdi          ; Store CDR
    mov [cons_ptr], rdx       ; Update pointer
    or  rax, 1                ; Tag as cons (xxxx_0001)
    ret

cons_slow:
    push rsi
    push rdi
    call gc_collect_cons_area
    pop rdi
    pop rsi
    jmp cons_fast
```

## Object Headers

Every non-cons heap object has a header:

```
+0: [ subtag:8 | unused:8 | element-count:48 ]
+8: [ ... payload ... ]
```

Allocating a vector of N elements:

```lisp
(defun %alloc-uvector (subtag element-count)
  "Allocate a uvector with the given subtag and element count.
   Returns untagged pointer to header."
  (let* ((data-bytes (* element-count (element-size subtag)))
         (total-bytes (+ 8 data-bytes))  ; Header + data
         (aligned (logand (+ total-bytes 15) -16)))  ; 16-byte align
    (let ((ptr (%raw-alloc aligned)))
      ;; Write header
      (%memset-64 ptr (logior subtag (ash element-count 16)))
      ptr)))
```

## Subtag Encoding

8-bit subtag tells GC how to scan the object:

```
Subtag ranges:
  00-0F: Node vectors (all elements are tagged pointers)
  10-1F: Byte vectors (no pointers, just bytes)
  20-2F: Bit vectors
  30-3F: Specialized numeric vectors
  40-4F: Struct/instance objects
  50-5F: Special objects (symbols, functions, etc.)
```

Key subtags:
```
0x01 = Simple-vector (elements are pointers)
0x10 = Simple-string (UTF-8 bytes)
0x11 = (unsigned-byte 8) vector
0x12 = (unsigned-byte 16) vector
0x13 = (unsigned-byte 32) vector
0x14 = (unsigned-byte 64) vector  <- CRYPTO!
0x15 = (signed-byte 64) vector
0x20 = Bit-vector
0x40 = Struct-instance
0x50 = Symbol
0x51 = Function
0x52 = Closure
```

## Generational GC

Two generations with semispace copying:

### Nursery (Young Generation)

- Size: ~4MB
- Contains: Recently allocated objects
- Collection: Frequent (when full)
- Strategy: Copy survivors to old generation

### Old Generation

- Size: Remaining heap
- Contains: Objects that survived nursery collection
- Collection: Rare (when 70% full)
- Strategy: Full copying compaction

### Card Marking

For old→young pointers, use card table:

```
Card table: One byte per 512 bytes of old space
  0x00 = Card is clean (no young pointers)
  0xFF = Card is dirty (may contain young pointers)
```

Write barrier (inline):
```asm
; Storing VALUE into OBJECT[offset]
; If VALUE is young and OBJECT is old, mark card dirty

write_barrier:
    test value, 1             ; Is it immediate?
    jz .store                 ; Yes, skip barrier

    cmp value, [nursery_end]  ; Is VALUE in nursery?
    jae .store                ; No, skip barrier

    cmp object, [nursery_end] ; Is OBJECT old?
    jb .store                 ; No (it's young), skip

    ; Mark card dirty
    mov rcx, object
    shr rcx, 9                ; Divide by 512
    mov byte [card_table + rcx], 0xFF

.store:
    mov [object + offset], value
    ret
```

### Minor Collection

1. Scan roots (registers, stack, card-dirty old objects)
2. Copy reachable young objects to old generation
3. Update pointers
4. Clear nursery

### Major Collection

1. Swap old-space semispaces
2. Scan roots
3. Copy all reachable objects to new semispace
4. Update all pointers
5. Free old semispace

## Pinned Objects

For DMA buffers that cannot move:

```lisp
(defun alloc-pinned (size)
  "Allocate from pinned area. Object will never move."
  (%raw-alloc-pinned size))
```

Pinned area uses a simple free-list allocator instead of copying.

## Thread Safety

For SMP support (future):

```lisp
(defvar *allocation-lock* (make-spinlock))

(defun alloc-threadsafe (size)
  (with-spinlock (*allocation-lock*)
    (%raw-alloc size)))
```

Better: Per-thread allocation buffers (TLABs):
- Each thread has 64KB local buffer
- Allocate from TLAB without locking
- When TLAB exhausted, grab new buffer (locked)

## Constants

```lisp
(defconstant +nursery-size+ (* 4 1024 1024))      ; 4MB
(defconstant +card-size+ 512)
(defconstant +min-object-size+ 16)                ; 16-byte alignment
(defconstant +cons-size+ 16)
(defconstant +header-size+ 8)
```

## Initialization

At boot:
```lisp
(defun init-allocator ()
  ;; Set up regions
  (setf *wired-start*   #x02000000
        *pinned-start*  #x03000000
        *function-start* #x03800000
        *cons-start*    #x04000000
        *general-start* #x05000000)

  ;; Initialize allocation pointers
  (setf *cons-ptr* *cons-start*
        *cons-limit* (+ *cons-start* (/ +nursery-size+ 2))
        *general-ptr* *general-start*
        *general-limit* (+ *general-start* (/ +nursery-size+ 2)))

  ;; Clear card table
  (%memset *card-table* 0 (/ *old-gen-size* +card-size+))

  ;; Ready!
  t)
```

## Performance Targets

| Operation | Cycles | Notes |
|-----------|--------|-------|
| cons | <20 | Inline, no function call |
| make-array (small) | <50 | Header + bump allocate |
| car/cdr | <5 | Single memory load |
| Minor GC | <10ms | For 4MB nursery |
| Major GC | <100ms | For 100MB heap |

## What CCL Teaches Us

From CCL's `%alloc-misc`:
- Subtag determines element type and GC behavior
- Header encodes both type and length
- Special handling for different vector types

From CCL's bignum allocation:
- Bignums are variable-length
- Use `%normalize-bignum` after computation
- Reuse result buffers when possible (`%maybe-allocate-bignum`)

## What Mezzano Teaches Us

From Mezzano's GC:
- Separate young/old with card marking
- Multiple allocation regions for different object types
- Wired area for kernel objects that must never move
- Per-thread state for safe-point GC

From Mezzano's threading:
- Full-save vs partial-save state
- GS-base for current-thread access
- FXSAVE for floating-point state

## Next Steps

1. Implement `%raw-alloc` for general area
2. Implement `cons` fast path
3. Implement `%alloc-uvector` for vectors
4. Add write barrier
5. Implement minor GC
6. Test with simple programs
7. Add major GC
8. Performance tuning
