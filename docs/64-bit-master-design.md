# Modus 64-bit Lisp OS: Master Design Document

**Note**: This is the original design document. The core architecture (tagging, memory layout, GC, register convention) is implemented as described. The system now also includes the MVM portable virtual machine (9 architectures) and full SMP support not covered here. See `mvm.md` and `actors.md` for those additions.

## Vision

A native 64-bit Lisp operating system that runs on bare metal x86-64 hardware.
No underlying OS, no emulation, no compromises. Every line of code is Lisp,
every memory word is a tagged object, and the entire system is live and
modifiable at runtime.

**Target**: SSH into a bare-metal Lisp and evaluate `(x25519-public-key k)` in
under a second (currently 180+ seconds in 32-bit Movitz).

## Design Principles

### From Genera
1. **Everything is an object** - No raw bits anywhere
2. **Open system** - No kernel/user split, single address space
3. **Full tagging** - Every word self-describing
4. **Live development** - Modify anything at runtime
5. **Protocols over ad-hoc** - Well-defined contracts between components

### From Mezzano
1. **4-bit tags** - 63-bit fixnums, efficient dispatch
2. **Memory regions** - Wired, pinned, cons, general areas
3. **Generational GC** - Card marking for efficiency
4. **Language-based safety** - Trust the type system

### From CCL
1. **Register discipline** - Clear allocation for args, temps, specials
2. **Efficient funcall** - Tag dispatch in ~5 instructions
3. **Subtag encoding** - Type info in object headers

### From Movitz
1. **Bootstrap strategy** - Cross-compile from SBCL
2. **DMA handling** - Pinned memory for hardware buffers
3. **Working drivers** - E1000, serial as reference implementations

---

## Object Representation

### Tagging Scheme (4-bit)

```
Bit pattern     Type                Range/Notes
──────────────────────────────────────────────────
xxxx_xxxx_xxx0  Fixnum              63-bit signed integer
xxxx_xxxx_0001  Cons pointer        Points to car/cdr pair
xxxx_xxxx_1001  Object pointer      Points to header+data
xxxx_xxxx_0101  Immediate           Characters, single-floats
xxxx_xxxx_1111  GC forwarding       Used during collection
```

**Fixnum range**: -4,611,686,018,427,387,904 to +4,611,686,018,427,387,903

This is enough for:
- All 256-bit crypto without bignums (when split into limbs)
- Unix timestamps until year 146 billion
- Array indices for 8 exabytes of memory

### Immediate Encoding

```
Character:  [unicode:21][unused:35][0101] = 64 bits
Single-float: [IEEE-754:32][unused:24][0101] = 64 bits (later)
```

### Cons Cell (16 bytes)

```
+0: [car - tagged value]
+8: [cdr - tagged value]
```

No header. Type determined by tag in pointer (0001).

### Object Header (8 bytes + data)

```
+0: [subtag:8][flags:8][element-count:48]
+8: [... element data ...]
```

Subtags:
```
0x01  Symbol          0x20  Struct/instance
0x02  Function        0x21  Hash-table
0x03  Closure         0x22  Package
0x10  Simple-vector   0x30  Bignum
0x11  String (UTF-8)  0x31  Ratio
0x12  (u8 vector)     0x32  Complex
0x13  (u16 vector)
0x14  (u32 vector)
0x15  (u64 vector)    <- Critical for crypto!
0x16  (s64 vector)
0x17  Bit-vector
```

### Symbol Layout (48 bytes)

```
+0:  header
+8:  value (global value cell)
+16: function (function cell)
+24: plist (property list)
+32: name (string pointer)
+40: package (package pointer)
```

### Function Layout (variable)

```
+0:  header
+8:  code-size (bytes, fixnum)
+16: name (symbol or string)
+24: arglist (for documentation)
+32: [... native x86-64 code ...]
```

Entry point is at offset 32. Function pointer points to header,
call jumps to header+32.

---

## Memory Layout

### Physical Memory Map

```
Address              Size    Purpose
─────────────────────────────────────────────────────
0x0000_0000_0000     1MB     Low memory (BIOS, legacy)
0x0000_0000_0010     15MB    Kernel code + bootstrap
0x0000_0000_0100     16MB    Wired area (never moves)
0x0000_0000_0200     16MB    Pinned area (DMA buffers)
0x0000_0000_0300     8MB     Function area (code objects)
0x0000_0000_0380     8MB     Cons area (nursery)
0x0000_0000_0400     --      General area (grows upward)
```

### Allocation Regions

| Region | Purpose | GC Behavior |
|--------|---------|-------------|
| Wired | Kernel objects | Never collected |
| Pinned | DMA, FFI buffers | Never moves, free-list |
| Function | Code objects | Compacting |
| Cons | Pair allocation | Copying, nursery |
| General | Everything else | Generational copying |

---

## Register Convention

### Lisp Mode Registers

```
Register  Name    Purpose
────────────────────────────────────────
RAX       imm0    Return value, scratch
RCX       nargs   Argument count (fixnum)
RDX       imm1    Scratch

RSI       arg0    First argument
RDI       arg1    Second argument
R8        arg2    Third argument
R9        arg3    Fourth argument

RBX       temp0   Callee-saved temp, fname
R10       temp1   Caller-saved temp
R11       temp2   Caller-saved temp

R12       alloc   Allocation pointer
R13       fn      Current function pointer
R14       limit   Allocation limit
R15       nil     Constant NIL pointer

RBP       frame   Frame pointer (optional)
RSP       stack   Stack pointer

GS        tcr     Thread context segment
```

### Calling Convention

**Caller:**
1. Put args in arg0-arg3 (RSI, RDI, R8, R9)
2. Push extra args right-to-left
3. Set nargs (RCX) to arg count << 3
4. Put function in temp0 (RBX)
5. Call `funcall` or inline the dispatch

**Callee:**
1. Function pointer in fn (R13)
2. Args in registers or on stack
3. Return value in arg0 (RSI) - note: differs from C!
4. Single return: just RET
5. Multiple values: set tcr.mv-count, fill tcr.mv-area

### funcall Implementation

```asm
funcall:
    movb %bl, %al           ; Get low byte of temp0
    andb $0x0F, %al         ; Extract 4-bit tag
    cmpb $0x09, %al         ; Object pointer?
    jne .try_symbol
    movb -8(%rbx), %al      ; Get subtag from header
    cmpb $0x02, %al         ; Function?
    jne .error
    leaq 32(%rbx), %r13     ; Entry = header + 32
    jmp *%r13
.try_symbol:
    cmpb $0x09, %al         ; Actually check for symbol
    ; ... symbol dispatch
```

---

## Garbage Collector

### Generational Design

**Nursery (Young Generation)**
- Size: 4MB
- Strategy: Copying
- Collected: When full (~100ms of allocation)
- Survivors: Promoted to old generation

**Old Generation**
- Size: Rest of heap
- Strategy: Semispace copying
- Collected: When 70% full
- Write barrier: Card marking

### Card Marking

```
Card size: 512 bytes
Card table: 1 byte per card
  0x00 = Clean (no young pointers)
  0xFF = Dirty (may have young pointers)

Write barrier (inline):
  ; Storing NEWVAL into OBJECT[offset]
  testb $1, %newval_b      ; Immediate?
  jz .store                ; Yes, skip
  cmpq %newval, nursery_end
  jae .store               ; Not young, skip
  cmpq %object, nursery_end
  jb .store                ; Object is young, skip
  ; Mark card dirty
  movq %object, %scratch
  shrq $9, %scratch        ; Divide by 512
  movb $0xFF, card_table(%scratch)
.store:
  movq %newval, offset(%object)
```

### Collection Algorithm

**Minor GC:**
1. Scan roots (registers, stack, dirty cards)
2. Copy reachable young objects to old space
3. Update pointers
4. Clear nursery
5. Clear dirty bits

**Major GC:**
1. Swap semispace roles
2. Scan all roots
3. Copy all reachable objects
4. Update all pointers
5. Free old semispace

---

## Multiple Values

### TCR (Thread Context Record)

```
Offset  Field           Purpose
──────────────────────────────────────
+0      self            Pointer to self (for validation)
+8      mv-count        Number of multiple values (0 = single in RAX)
+16     mv-area[64]     Up to 64 multiple values (512 bytes)
+528    alloc-ptr       Current allocation pointer
+536    alloc-limit     End of current region
+544    stack-base      Bottom of Lisp stack
+552    stack-limit     Stack overflow guard
```

### Returning Multiple Values

```lisp
(values a b c)
```

Compiles to:
```asm
    movq %a, tcr.mv_area+0(%gs)
    movq %b, tcr.mv_area+8(%gs)
    movq %c, tcr.mv_area+16(%gs)
    movq $3, tcr.mv_count(%gs)
    movq %a, %rsi           ; Also in arg0 for single-value callers
    ret
```

### Receiving Multiple Values

```lisp
(multiple-value-bind (x y z) (foo) ...)
```

Compiles to:
```asm
    call foo
    movq tcr.mv_count(%gs), %rcx
    testq %rcx, %rcx
    jz .single
    movq tcr.mv_area+0(%gs), %x
    movq tcr.mv_area+8(%gs), %y
    movq tcr.mv_area+16(%gs), %z
    jmp .done
.single:
    movq %rsi, %x           ; Single value in arg0
    movq $nil, %y
    movq $nil, %z
.done:
```

---

## Code Organization

### Principle: Complete Separation

32-bit and 64-bit are fundamentally different systems. No hybrid compiler,
no shared runtime code. Use 32-bit as *reference*, not *dependency*.

```
lib/
├── movitz/                    # 32-bit (UNCHANGED, working system)
│   ├── losp/                  # 32-bit OS code
│   └── compiler.lisp          # 32-bit compiler
│
└── modus64/                   # 64-bit (FRESH START)
    ├── cross/                 # Bootstrap cross-compiler (runs on SBCL)
    │   └── cross-compile.lisp # Minimal, throwaway
    ├── boot/                  # Multiboot, long mode
    ├── runtime/               # 64-bit runtime
    ├── compiler/              # Native 64-bit compiler
    ├── drivers/               # Ported from 32-bit
    ├── crypto/                # Ported from 32-bit
    └── net/                   # Ported from 32-bit
```

### Why No Hybrid?

| Aspect | 32-bit Movitz | 64-bit Modus |
|--------|---------------|--------------|
| Tags | 3-bit | 4-bit |
| Fixnum shift | 2 | 1 |
| Word size | 4 bytes | 8 bytes |
| Arg registers | 0-1 | 4 |
| Object layout | Movitz-specific | New design |

Trying to parameterize all this would make the compiler incomprehensible.

---

## Bootstrap Strategy

### Phase 1: Cross-Compiler (runs on SBCL)

A minimal, throwaway cross-compiler. NOT the final compiler.

**Location**: `lib/modus64/cross/cross-compile.lisp`

**Supports**:
- `defun`, `let`, `let*`, `if`, `progn`, `lambda`
- Fixnum arithmetic (`+`, `-`, `*`, `<`, `>`, `=`)
- `cons`, `car`, `cdr`, `null`, `eq`
- `make-array`, `aref`, `setf`
- Basic macros

**Does NOT support**:
- Full Common Lisp
- CLOS
- Conditions/restarts
- Format
- Optimization passes

**Size**: ~2000 lines, purpose-built for bootstrap

**Output**: `modus64-kernel.img` - boots to reader + tree-walking eval

### Phase 2: Minimal Runtime

First functions to implement (in order):
1. `cons`, `car`, `cdr`, `rplaca`, `rplacd`
2. `eq`, `null`, `atom`, `consp`
3. `+`, `-`, `*` (fixnum only)
4. `<`, `>`, `=` (fixnum only)
5. `make-array`, `aref`, `aset`
6. `funcall`, `apply`
7. `if`, `progn`, `let`, `let*`

### Phase 3: Reader + Evaluator

1. Character input from serial
2. `read` - Lisp reader
3. `eval` - Tree-walking evaluator (temporary)
4. `print` - Lisp printer
5. REPL loop

**Milestone: Boot to `(+ 1 2)` => `3`**

### Phase 4: Compiler

1. IR generation
2. Register allocation
3. x86-64 emission
4. `compile` function
5. Self-compile the compiler

**Milestone: `(compile nil '(lambda (x) (+ x 1)))` works**

### Phase 5: Full Runtime

1. Bignums
2. Ratios, complex
3. Strings, characters
4. Hash tables
5. CLOS (minimal)
6. Conditions/restarts
7. Streams
8. Format

### Phase 6: OS Services

Port from 32-bit Modus:
1. Serial driver
2. E1000 network driver
3. TCP/IP stack
4. SSH server

**Milestone: SSH in, run `(x25519-public-key k)` in < 1 second**

---

## File Structure

```
lib/modus64/
├── cross/                    ; BOOTSTRAP CROSS-COMPILER (runs on SBCL)
│   ├── cross-compile.lisp    ; Main cross-compiler (~2000 lines)
│   ├── x64-asm.lisp          ; x86-64 instruction encoding
│   ├── image.lisp            ; Kernel image builder
│   └── build.lisp            ; (load "build.lisp") to build kernel
│
├── boot/                     ; BOOT CODE (cross-compiled)
│   ├── multiboot.s           ; Multiboot header (hand-written asm)
│   ├── start64.s             ; 64-bit entry, GDT, IDT
│   ├── paging.lisp           ; Page table setup
│   └── init.lisp             ; Lisp-level init
│
├── runtime/                  ; RUNTIME (cross-compiled initially)
│   ├── tags.lisp             ; Tag constants, predicates
│   ├── cons.lisp             ; Cons cells
│   ├── alloc.lisp            ; Allocator
│   ├── gc.lisp               ; Garbage collector
│   ├── symbol.lisp           ; Symbols, packages
│   ├── vector.lisp           ; Arrays, strings
│   ├── number.lisp           ; Fixnums, bignums
│   ├── function.lisp         ; Functions, closures
│   └── mv.lisp               ; Multiple values
│
├── compiler/                 ; NATIVE COMPILER (loaded as source, then compiled)
│   ├── reader.lisp           ; Lisp reader
│   ├── ir.lisp               ; Intermediate representation
│   ├── x64-gen.lisp          ; x86-64 code generation
│   └── assemble.lisp         ; Assembler
│
├── clos/                     ; CLOS (loaded after compiler works)
│   ├── boot.lisp             ; Minimal CLOS
│   └── mop.lisp              ; Meta-object protocol
│
├── conditions/               ; CONDITIONS (loaded after CLOS)
│   ├── conditions.lisp       ; Condition system
│   └── restarts.lisp         ; Restart handling
│
├── drivers/                  ; DRIVERS (ported from 32-bit)
│   ├── serial.lisp           ; Serial port
│   ├── e1000.lisp            ; Network card
│   └── keyboard.lisp         ; PS/2 keyboard
│
├── net/                      ; NETWORKING (ported from 32-bit)
│   ├── ethernet.lisp         ; Ethernet frames
│   ├── ip.lisp               ; IP layer
│   ├── tcp.lisp              ; TCP
│   └── ssh.lisp              ; SSH server
│
└── crypto/                   ; CRYPTO (ported from 32-bit, 64-bit optimized)
    ├── sha256.lisp           ; SHA-256
    ├── x25519.lisp           ; Curve25519 (64-bit limbs!)
    ├── ed25519.lisp          ; Signatures
    └── chacha20.lisp         ; Stream cipher
```

### Bootstrap Flow

```
SBCL (host)                         Modus64 (target)
───────────────────────────────────────────────────────
lib/modus64/cross/build.lisp
        │
        ▼
cross-compile.lisp compiles:
  • boot/*.lisp
  • runtime/*.lisp
  • compiler/reader.lisp
  • minimal eval
        │
        ▼
    modus64-kernel.img ──────────▶ Boots on QEMU
                                         │
                                         ▼
                                   REPL (interpreted)
                                         │
                                         ▼
                              (load "compiler/ir.lisp")
                              (load "compiler/x64-gen.lisp")
                                         │
                                         ▼
                              (compile-file "compiler.lisp")
                                         │
                                         ▼
                                   SELF-HOSTING!
```

---

## Implementation Timeline

### Week 1-2: Boot to Serial Output
- [ ] Multiboot header and entry point
- [ ] 64-bit GDT, IDT setup
- [ ] Paging (identity map first 4GB)
- [ ] Serial output (character at a time)
- [ ] Print "Hello from 64-bit Lisp"

### Week 3-4: Memory Allocator + Basic Types
- [ ] Physical memory map
- [ ] Bump allocator for nursery
- [ ] cons/car/cdr
- [ ] Fixnum arithmetic
- [ ] Simple vectors

### Week 5-6: Reader + REPL
- [ ] Serial input
- [ ] Lisp reader (symbols, lists, numbers)
- [ ] Tree-walking eval (subset)
- [ ] Print
- [ ] REPL loop

### Week 7-8: Native Compiler
- [ ] IR from Lisp forms
- [ ] Register allocator
- [ ] x86-64 code emission
- [ ] compile function
- [ ] Self-hosting test

### Week 9-10: GC + Full Runtime
- [ ] Copying GC
- [ ] Write barrier
- [ ] Bignums
- [ ] Strings
- [ ] Hash tables

### Week 11-12: Network + SSH
- [ ] Port E1000 driver
- [ ] Port TCP/IP
- [ ] Port SSH server
- [ ] Crypto at native speed!

---

## Success Criteria

1. **Boot**: Machine boots to 64-bit Lisp REPL via serial
2. **Compute**: `(* 12345678901234567 98765432109876543)` returns correct bignum
3. **Compile**: `(compile nil '(lambda (x) (+ x x)))` produces working function
4. **Network**: TCP connection to external host works
5. **Crypto**: `(x25519-public-key k)` completes in < 1 second
6. **SSH**: Remote login via SSH works

## References

- `docs/64-bit-lisp-design.md` - High-level architecture
- `docs/64-bit-allocator-design.md` - GC and allocation details
- `docs/calling-convention-design.md` - Registers, calling, MVs
- `ref/sel4/ccl/` - CCL source for reference
- `ref/genera-retrospective-1991.pdf` - Genera design lessons
- Mezzano source: github.com/froggey/Mezzano
