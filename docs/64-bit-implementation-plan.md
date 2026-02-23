# Modus 64-bit Implementation Plan

## Overview

This document breaks down the implementation into concrete tasks with
dependencies and verification steps.

---

## Phase 1: Boot to Serial (Week 1-2)

### 1.0 Cross-Compiler Foundation
**File**: `lib/modus64/cross/cross-compile.lisp`

This is a minimal, throwaway compiler that runs on SBCL and emits 64-bit code.
NOT the final compiler - just enough to bootstrap.

```
Tasks:
[1.0.1] x86-64 instruction encoder (MOV, ADD, SUB, CMP, JMP, CALL, RET)
[1.0.2] REX prefix generation
[1.0.3] ModR/M and SIB encoding
[1.0.4] Label resolution and fixups
[1.0.5] Basic Lisp->IR conversion (defun, let, if, progn)
[1.0.6] IR->x64 code generation
[1.0.7] Image builder (ELF or flat binary)

Dependencies: None (pure SBCL code)
Verification:
- (cross-compile '(lambda (x) (+ x 1))) produces valid x86-64 bytes
```

### 1.1 Multiboot Entry Point
**File**: `lib/modus64/boot/multiboot.s` (hand-written assembly)

```
Tasks:
[1.1.1] Create multiboot2 header
[1.1.2] 32-bit entry point (multiboot drops us in 32-bit protected mode)
[1.1.3] Check multiboot magic
[1.1.4] Save multiboot info pointer

Verification:
- QEMU boots, doesn't triple-fault
- Serial output: "MB" (multiboot entered)
```

### 1.2 Transition to Long Mode
**File**: `lib/modus64/boot/start64.s` (hand-written assembly)

```
Tasks:
[1.2.1] Set up identity-mapped page tables (PML4 -> PDPT -> PD)
[1.2.2] Enable PAE (CR4.PAE = 1)
[1.2.3] Load CR3 with PML4 address
[1.2.4] Enable EFER.LME
[1.2.5] Enable paging (CR0.PG = 1)
[1.2.6] Load 64-bit GDT
[1.2.7] Far jump to 64-bit code segment
[1.2.8] Jump to Lisp entry point

Dependencies: 1.1
Verification:
- Serial output: "64" (in 64-bit mode)
```

### 1.3 Basic GDT and IDT
**File**: `lib/modus64/boot/gdt.lisp` (cross-compiled)

```
Tasks:
[1.3.1] 64-bit code segment (selector 0x08)
[1.3.2] 64-bit data segment (selector 0x10)
[1.3.3] TSS for stack switching
[1.3.4] IDT with exception handlers
[1.3.5] Division by zero handler (prints message, halts)

Dependencies: 1.0, 1.2
Verification:
- Intentional div-by-zero prints error
```

### 1.4 Serial Driver (Minimal)
**File**: `lib/modus64/drivers/serial.lisp` (cross-compiled)

```
Tasks:
[1.4.1] Initialize COM1 (0x3F8)
[1.4.2] serial-write-byte function
[1.4.3] serial-write-string function
[1.4.4] serial-read-byte function (polling)

Dependencies: 1.0, 1.2
Verification:
- "Hello from 64-bit Modus!" appears on serial
```

### 1.5 Build System
**File**: `lib/modus64/cross/build.lisp`

```
Tasks:
[1.5.1] Load cross-compiler into SBCL
[1.5.2] Cross-compile boot/*.lisp
[1.5.3] Cross-compile drivers/serial.lisp
[1.5.4] Link into bootable image
[1.5.5] Write modus64-kernel.img

Dependencies: 1.0, 1.1, 1.2, 1.3, 1.4
Verification:
- (load "build.lisp") produces working kernel image
```

**MILESTONE 1**: Boot to serial "Hello from 64-bit Modus!"

---

## Phase 2: Memory and Basic Types (Week 3-4)

### 2.1 Physical Memory Manager
**File**: `lib/modus64/boot/memory.lisp`

```
Tasks:
[2.1.1] Parse multiboot memory map
[2.1.2] Mark reserved regions (kernel, DMA)
[2.1.3] Initialize region pointers (wired, pinned, cons, general)
[2.1.4] memset/memcpy primitives

Dependencies: 1.4
Verification:
- Print memory map to serial
- Print available memory size
```

### 2.2 Bump Allocator
**File**: `lib/modus64/runtime/alloc.lisp`

```
Tasks:
[2.2.1] alloc-cons (from cons area)
[2.2.2] alloc-object (from general area, given size)
[2.2.3] Allocation pointer + limit
[2.2.4] Out-of-memory handler (panic for now)

Dependencies: 2.1
Verification:
- Allocate 1000 cons cells, verify addresses are sequential
```

### 2.3 Tag Predicates
**File**: `lib/modus64/runtime/tags.lisp`

```
Tasks:
[2.3.1] Tag constants (+tag-fixnum+, +tag-cons+, etc.)
[2.3.2] fixnump, consp, symbolp, etc.
[2.3.3] tag-of function
[2.3.4] untag-pointer function

Dependencies: None
Verification:
- (fixnump 42) => T
- (consp (cons 1 2)) => T
```

### 2.4 Cons Cells
**File**: `lib/modus64/runtime/cons.lisp`

```
Tasks:
[2.4.1] cons function
[2.4.2] car, cdr functions
[2.4.3] rplaca, rplacd functions
[2.4.4] null, atom predicates
[2.4.5] list, list* functions

Dependencies: 2.2, 2.3
Verification:
- (car (cons 'a 'b)) => a
- (cdr (cons 'a 'b)) => b
```

### 2.5 Fixnum Arithmetic
**File**: `lib/modus64/runtime/number.lisp`

```
Tasks:
[2.5.1] fx+ (fixnum add, no overflow check)
[2.5.2] fx- (fixnum subtract)
[2.5.3] fx* (fixnum multiply)
[2.5.4] fx< fx> fx= comparisons
[2.5.5] + - * with overflow -> bignum (stub: error for now)

Dependencies: 2.3
Verification:
- (+ 1 2) => 3
- (< 5 10) => T
```

### 2.6 Simple Vectors
**File**: `lib/modus64/runtime/vector.lisp`

```
Tasks:
[2.6.1] make-array (simple-vector only)
[2.6.2] aref, (setf aref)
[2.6.3] length
[2.6.4] Bounds checking

Dependencies: 2.2, 2.3
Verification:
- (let ((v (make-array 3))) (setf (aref v 1) 42) (aref v 1)) => 42
```

**MILESTONE 2**: Can execute `(car (cons 1 2))` and `(+ 40 2)`

---

## Phase 3: Reader and REPL (Week 5-6)

### 3.1 Symbol Table
**File**: `lib/modus64/runtime/symbol.lisp`

```
Tasks:
[3.1.1] make-symbol function
[3.1.2] symbol-name, symbol-value, symbol-function
[3.1.3] Initial obarray (hash table or alist)
[3.1.4] intern function
[3.1.5] find-symbol function
[3.1.6] Bootstrap symbols: T, NIL, QUOTE, etc.

Dependencies: 2.4, 2.6
Verification:
- (symbol-name 'foo) => "FOO"
- (eq 'foo 'foo) => T
```

### 3.2 Character Input
**File**: `lib/modus64/drivers/serial.lisp` (extend)

```
Tasks:
[3.2.1] Input buffer (ring buffer)
[3.2.2] read-char function
[3.2.3] peek-char function
[3.2.4] unread-char function

Dependencies: 1.4
Verification:
- Type character, see it echoed
```

### 3.3 Lisp Reader
**File**: `lib/modus64/compiler/reader.lisp`

```
Tasks:
[3.3.1] Skip whitespace
[3.3.2] Read symbol
[3.3.3] Read integer
[3.3.4] Read list (recursive)
[3.3.5] Read string
[3.3.6] Read quote ('x -> (quote x))
[3.3.7] Read comment (;)

Dependencies: 3.1, 3.2
Verification:
- Type "(+ 1 2)", read returns (+ 1 2) as list
```

### 3.4 Lisp Printer
**File**: `lib/modus64/runtime/print.lisp`

```
Tasks:
[3.4.1] print-fixnum
[3.4.2] print-symbol
[3.4.3] print-cons (with circular detection)
[3.4.4] print-string
[3.4.5] print-vector
[3.4.6] Generic print dispatch

Dependencies: 2.3, 2.4, 3.1
Verification:
- (print '(a b c)) outputs "(A B C)"
```

### 3.5 Tree-Walking Evaluator
**File**: `lib/modus64/runtime/eval.lisp`

```
Tasks:
[3.5.1] eval-symbol (variable lookup)
[3.5.2] eval-self-evaluating (numbers, strings)
[3.5.3] eval-quote
[3.5.4] eval-if
[3.5.5] eval-progn
[3.5.6] eval-let, eval-let*
[3.5.7] eval-lambda (create closure)
[3.5.8] eval-funcall (apply function)
[3.5.9] Environment structure

Dependencies: 3.1, 3.3
Verification:
- (eval '(+ 1 2)) => 3
- (eval '(let ((x 5)) (+ x 3))) => 8
```

### 3.6 REPL
**File**: `lib/modus64/runtime/repl.lisp`

```
Tasks:
[3.6.1] Read-eval-print loop
[3.6.2] Error handling (catch errors, print, continue)
[3.6.3] Prompt

Dependencies: 3.3, 3.4, 3.5
Verification:
- Interactive REPL works via serial
```

**MILESTONE 3**: Interactive REPL - type `(+ 1 2)`, get `3`

---

## Phase 4: Native Compiler (Week 7-8)

### 4.1 IR Generation
**File**: `lib/modus64/compiler/ir.lisp`

```
Tasks:
[4.1.1] IR node types (const, var, if, call, etc.)
[4.1.2] Convert Lisp form to IR
[4.1.3] Lambda lifting
[4.1.4] Closure conversion

Dependencies: 3.5
Verification:
- IR for (lambda (x) (+ x 1)) is reasonable
```

### 4.2 Register Allocator
**File**: `lib/modus64/compiler/regalloc.lisp`

```
Tasks:
[4.2.1] Liveness analysis
[4.2.2] Linear scan allocation
[4.2.3] Spill handling
[4.2.4] Register move insertion

Dependencies: 4.1
Verification:
- Simple functions don't spill
```

### 4.3 x86-64 Code Generation
**File**: `lib/modus64/compiler/x64-gen.lisp`

```
Tasks:
[4.3.1] Function prologue/epilogue
[4.3.2] Argument handling
[4.3.3] Fixnum arithmetic (inline)
[4.3.4] Comparison and branching
[4.3.5] Function calls
[4.3.6] Constant loading
[4.3.7] Tag checking

Dependencies: 4.2
Verification:
- (compile nil '(lambda (x) (+ x 1))) produces working code
```

### 4.4 Assembler
**File**: `lib/modus64/compiler/assemble.lisp`

```
Tasks:
[4.4.1] Instruction encoding tables
[4.4.2] REX prefix logic
[4.4.3] ModR/M and SIB bytes
[4.4.4] Label resolution
[4.4.5] Emit to byte vector

Dependencies: None
Verification:
- Hand-written assembly encodes correctly
```

### 4.5 compile Function
**File**: `lib/modus64/compiler/compile.lisp`

```
Tasks:
[4.5.1] (compile name lambda) function
[4.5.2] Allocate function object
[4.5.3] Copy code into object
[4.5.4] Set function name, arglist

Dependencies: 4.3, 4.4, 2.6
Verification:
- Compiled functions are faster than interpreted
```

**MILESTONE 4**: `(compile nil '(lambda (x) (+ x x)))` works

---

## Phase 5: GC and Full Runtime (Week 9-10)

### 5.1 Copying GC
**File**: `lib/modus64/runtime/gc.lisp`

```
Tasks:
[5.1.1] Root scanning (registers, stack)
[5.1.2] Object copying
[5.1.3] Forwarding pointers
[5.1.4] Pointer updating
[5.1.5] Semispace flip

Dependencies: 2.2
Verification:
- Allocate until GC triggers, system continues working
```

### 5.2 Write Barrier
**File**: `lib/modus64/runtime/gc.lisp` (extend)

```
Tasks:
[5.2.1] Card table allocation
[5.2.2] Inline barrier code generation
[5.2.3] Dirty card scanning

Dependencies: 5.1
Verification:
- Old->young pointers are found correctly
```

### 5.3 Bignums
**File**: `lib/modus64/runtime/bignum.lisp`

```
Tasks:
[5.3.1] Bignum representation (vector of u64)
[5.3.2] bignum-add, bignum-sub
[5.3.3] bignum-mul (schoolbook first)
[5.3.4] bignum-div
[5.3.5] Fixnum overflow -> bignum promotion

Dependencies: 2.6, 5.1
Verification:
- (* 12345678901234567 98765432109876543) => correct
```

### 5.4 Strings
**File**: `lib/modus64/runtime/string.lisp`

```
Tasks:
[5.4.1] String representation (UTF-8 bytes)
[5.4.2] make-string
[5.4.3] char, schar
[5.4.4] string=, string<
[5.4.5] concatenate

Dependencies: 2.6
Verification:
- (concatenate 'string "Hello" " " "World") => "Hello World"
```

### 5.5 Hash Tables
**File**: `lib/modus64/runtime/hash.lisp`

```
Tasks:
[5.5.1] Hash table structure
[5.5.2] sxhash function
[5.5.3] gethash, (setf gethash)
[5.5.4] remhash
[5.5.5] Rehashing on growth

Dependencies: 2.6, 5.4
Verification:
- Hash table with 1000 entries works
```

**MILESTONE 5**: Full numeric tower, strings, hash tables work

---

## Phase 6: Network and SSH (Week 11-12)

### 6.1 E1000 Driver
**File**: `lib/modus64/drivers/e1000.lisp`

```
Tasks:
[6.1.1] Port from 32-bit Modus
[6.1.2] Adapt DMA to 64-bit addresses
[6.1.3] Pinned buffer allocation
[6.1.4] Interrupt handler

Dependencies: 2.1, 5.1
Verification:
- Ping from host works
```

### 6.2 TCP/IP Stack
**File**: `lib/modus64/net/tcp.lisp`

```
Tasks:
[6.2.1] Port IP layer
[6.2.2] Port TCP layer
[6.2.3] tcp-connect, tcp-send, tcp-receive
[6.2.4] tcp-listen, tcp-accept

Dependencies: 6.1
Verification:
- Fetch webpage via TCP
```

### 6.3 Crypto Library
**File**: `lib/modus64/crypto/*.lisp`

```
Tasks:
[6.3.1] SHA-256 (64-bit optimized)
[6.3.2] X25519 (64-bit limbs = 4x faster!)
[6.3.3] Ed25519
[6.3.4] ChaCha20-Poly1305

Dependencies: 5.3
Verification:
- Test vectors pass
- X25519 < 1 second!
```

### 6.4 SSH Server
**File**: `lib/modus64/net/ssh.lisp`

```
Tasks:
[6.4.1] Port from 32-bit Modus
[6.4.2] Key exchange with X25519
[6.4.3] Ed25519 host keys
[6.4.4] ChaCha20-Poly1305 encryption
[6.4.5] Shell channel -> REPL

Dependencies: 6.2, 6.3
Verification:
- ssh -p 2222 user@modus-host works!
```

**MILESTONE 6**: SSH into 64-bit Modus, run fast crypto

---

## Verification Checklist

### End of Week 2
- [ ] QEMU boots without triple fault
- [ ] "Hello from 64-bit Modus!" on serial
- [ ] Exception handler catches div-by-zero

### End of Week 4
- [ ] (cons 1 2) allocates and returns correctly
- [ ] (+ 123456789 987654321) works
- [ ] (make-array 10) allocates vector

### End of Week 6
- [ ] (read) from serial works
- [ ] (print '(a b c)) outputs correctly
- [ ] REPL is interactive

### End of Week 8
- [ ] (compile nil '(lambda (x) (+ x 1))) works
- [ ] Compiled code runs faster than interpreted
- [ ] No register allocator crashes

### End of Week 10
- [ ] GC runs without corrupting data
- [ ] (* 2^64 2^64) produces correct bignum
- [ ] Hash tables work under GC pressure

### End of Week 12
- [ ] Network ping works
- [ ] (x25519-public-key k) < 1 second
- [ ] SSH login works
- [ ] Remote REPL is usable

---

## Risk Mitigation

### Risk: Cross-compiler bugs
**Mitigation**: Heavy testing of generated code, compare with CCL output

### Risk: GC corrupts data
**Mitigation**: Extensive stress testing, conservative roots at first

### Risk: 64-bit mode switch issues
**Mitigation**: We already have working 32->64->32 in current Modus

### Risk: Register allocator complexity
**Mitigation**: Start with simple linear scan, optimize later

### Risk: Network driver porting
**Mitigation**: 32-bit version is known working, mostly address width changes

---

## Dependencies Graph

```
1.0 Cross-Compiler (SBCL)        ← Foundation, everything depends on this
 │
 ├─→ 1.1 Multiboot (hand-written asm)
 │    └─→ 1.2 Long Mode (hand-written asm)
 │
 ├─→ 1.3 GDT/IDT (cross-compiled)
 │
 ├─→ 1.4 Serial (cross-compiled)
 │
 └─→ 1.5 Build System
      │
      └─→ MILESTONE 1: "Hello from 64-bit Modus!"
           │
           └─→ 2.1 Memory Manager
                └─→ 2.2 Allocator
                     └─→ 2.4 Cons
                     └─→ 2.6 Vectors
                          └─→ 3.1 Symbols
                               └─→ 3.3 Reader ──────────────────┐
                               └─→ 3.5 Eval (tree-walking)      │
                                    │                           │
                                    └─→ 3.6 REPL ◄──────────────┘
                                         │
                                         │  MILESTONE 3: Interactive REPL
                                         │
                                         └─→ 4.* Native Compiler (loaded as source)
                                              │
                                              └─→ MILESTONE 4: Self-hosting
                                                   │
                                                   └─→ 5.* GC + Full Runtime
                                                        │
                                                        └─→ 6.* Network + SSH
                                                             │
                                                             └─→ MILESTONE 6: SSH + Fast Crypto
```

### Two Compilers

```
┌─────────────────────────────────────────────────────────────────────┐
│ CROSS-COMPILER (lib/modus64/cross/)                                 │
│ • Runs on SBCL                                                      │
│ • Minimal (~2000 lines)                                             │
│ • Produces: boot code, runtime, reader, simple eval                 │
│ • Throwaway - not used after self-hosting                           │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ produces
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ modus64-kernel.img                                                  │
│ • Boots to REPL                                                     │
│ • Has reader + tree-walking eval                                    │
│ • Can (load "file.lisp")                                            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ loads & compiles
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ NATIVE COMPILER (lib/modus64/compiler/)                             │
│ • Runs on Modus64                                                   │
│ • Full-featured                                                     │
│ • Self-hosting                                                      │
│ • This is the "real" compiler                                       │
└─────────────────────────────────────────────────────────────────────┘
```
