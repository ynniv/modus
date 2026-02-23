# The One True 64-bit Lisp OS: Design Document

## Executive Summary

This document outlines the design for a 64-bit native Lisp OS for Modus,
taking the best ideas from Genera, Movitz, CCL, SBCL, and Mezzano.

The core insight: **We already have a working 32-bit Lisp OS.** The path forward
is not to throw it away, but to bootstrap a 64-bit system from it.

## Design Goals

1. **Native 64-bit execution** - No emulation, no hybrid modes
2. **61+ bit fixnums** - Cryptography without bignums
3. **Live development** - Like Genera, modify any code while running
4. **Single world** - One OS, not two fighting for devices
5. **Practical bootstrapping** - Use existing Movitz compiler infrastructure
6. **Performance for crypto** - X25519, Ed25519, secp256k1 at native speed

## Object Representation

### Tagging Scheme (Mezzano-inspired, CCL-refined)

Use 4 low tag bits (like CCL), but simplified for our needs:

```
xxxx_xxx0 = Fixnum (63-bit integers, only lose 1 bit!)
xxxx_0001 = Cons cell pointer
xxxx_1001 = Object pointer (vectors, structs, symbols, etc.)
xxxx_0101 = Immediate (characters, single-floats)
xxxx_1111 = GC forwarding pointer
```

This gives us:
- **63-bit fixnums** (range: -4.6×10^18 to +4.6×10^18)
- **Cons cells** are 16 bytes (CAR + CDR, each 8 bytes)
- **Objects** point to uvector headers with type/length info
- **Immediates** encode chars (8-bit) and single-floats (32-bit) directly

### Object Headers (CCL-style)

Every heap object has an 8-byte header:
```
+0: [ subtag:8 | element-count:56 ]
+8: [ ... data ... ]
```

Subtags identify object type:
- 0x01: Symbol
- 0x02: Function
- 0x03: Closure
- 0x10: Simple-vector
- 0x11: String (UTF-8)
- 0x12: (unsigned-byte 8) vector
- 0x13: (unsigned-byte 64) vector  <- CRITICAL for crypto!
- 0x14: Bignum
- 0x20: Struct/instance
- 0x30: Hash-table

### Symbol Layout

```
+0:  header (subtag + 0)
+8:  value cell
+16: function cell
+24: plist
+32: name (string pointer)
+40: package
```

### Function Layout

```
+0:  header
+8:  code-size (bytes)
+16: entry-point offset
+24: constants vector
+32: name
+40: arglist
+48: [ native code ... ]
```

## Memory Layout

### Physical Memory Map

```
0x0000_0000_0000_0000 - 0x0000_0000_000F_FFFF : Low memory (legacy, BIOS)
0x0000_0000_0010_0000 - 0x0000_0000_00FF_FFFF : Kernel code (16MB)
0x0000_0000_0100_0000 - 0x0000_0000_03FF_FFFF : Initial heap (48MB)
0x0000_0000_0400_0000 - 0x0000_0000_040F_FFFF : Static DMA region (1MB)
0x0000_0000_0500_0000 - 0x0000_0000_7FFF_FFFF : Dynamic heap expansion
0x0000_0000_8000_0000 - upward                : Large objects/mmap
```

### Virtual Memory (when paging enabled)

Identity-map low 4GB initially. Later: proper virtual memory with:
- Copy-on-write pages
- Demand paging from disk
- Memory-mapped files

## Garbage Collector

### Primary: Generational Copying (Mezzano-style)

Two generations:
1. **Nursery** (young): 4MB, collected frequently
2. **Old space**: Remaining heap, collected rarely

Collection strategy:
- Nursery fills -> minor GC (copy live to old space)
- Old space 70% full -> major GC (copy compact everything)

### Key Optimizations

1. **Card marking** for old-to-young pointers
2. **Pinned objects** for DMA buffers (never move)
3. **Unboxed arrays** don't need scanning

### Write Barrier

Every store to a heap object must check if we're storing a young pointer
into an old object. Inline fast path:

```asm
; Storing NEW into OLD[offset]
test new, 1           ; Is it a fixnum?
jz .done              ; Yes, no barrier needed
cmp new, nursery_end  ; Is it in nursery?
jae .done             ; No, no barrier needed
cmp old, nursery_end  ; Is destination old?
jb .done              ; No (in nursery), skip
call gc_write_barrier ; Mark card dirty
.done:
mov [old+offset], new
```

## Native Code Compiler

### Compilation Strategy (SBCL-inspired)

1. **Parse** - Read Lisp forms
2. **IR1** - High-level IR with Lisp semantics
3. **IR2** - Low-level IR, explicit registers
4. **Assembly** - x86-64 machine code

### Key Optimizations

1. **Type inference** - Propagate known types
2. **Inline arithmetic** - Fixnum ops without boxing
3. **Inline allocation** - Bump-pointer allocation
4. **Unboxed locals** - Keep intermediates in registers
5. **Tail call optimization** - Jump instead of call/ret

### Register Allocation

Reserve certain registers (like CCL):
- **RAX**: Return value / temp
- **RBX**: Function pointer (current function)
- **RCX**: Argument count
- **RDX**: Scratch
- **RSI**: Arg 0
- **RDI**: Arg 1
- **R8-R11**: Args 2-5 / temps
- **R12**: Thread context pointer
- **R13**: Allocation pointer
- **R14**: Allocation limit
- **R15**: NIL (constant, always points to nil)
- **RSP**: Stack pointer
- **RBP**: Frame pointer (optional)

### Inline Fixnum Arithmetic

Addition with overflow check:
```asm
; RAX = x + y, both known fixnums
mov rax, x
add rax, y
jo .overflow
; Result in RAX, still tagged
ret
.overflow:
call bignum_add
ret
```

This compiles `(+ x y)` to ~5 instructions when types are known!

## Bootstrapping Strategy

### Phase 1: Cross-compile from Movitz (Week 1-2)

Use existing Movitz compiler (running on SBCL) to generate:
1. 64-bit bootloader
2. Initial memory allocator
3. Basic runtime (cons, car, cdr, etc.)
4. Minimal reader
5. Minimal evaluator

This creates a "kernel image" that boots to a REPL.

### Phase 2: Self-hosting compiler (Week 3-4)

On the running 64-bit Lisp:
1. Implement full reader
2. Implement full compiler
3. Compile the compiler to itself
4. Verify by comparing outputs

### Phase 3: Full runtime (Week 5-6)

Add:
1. Full numeric tower (bignums, ratios, complex)
2. CLOS (can start simple, expand later)
3. Conditions/restarts
4. Streams
5. Format

### Phase 4: OS services (Week 7-8)

Port from existing 32-bit Modus:
1. E1000 network driver
2. TCP/IP stack
3. SSH server (much faster with 64-bit crypto!)
4. Serial console

## Crypto Performance Targets

With native 64-bit code:

| Operation | 32-bit Movitz | Target 64-bit | Speedup |
|-----------|---------------|---------------|---------|
| X25519    | 180 sec       | < 1 sec       | 180x+   |
| Ed25519 sign | 300 sec    | < 2 sec       | 150x+   |
| SHA-256 (1KB) | 500 ms    | < 1 ms        | 500x+   |

Key insight: 64-bit limbs mean 4x fewer multiplications for 256-bit math,
and each multiplication is native MUL instead of emulated.

## File Structure

```
lib/modus64/
├── boot/
│   ├── start.S          ; 64-bit entry point
│   ├── gdt.lisp         ; GDT setup
│   └── memory.lisp      ; Physical memory manager
├── runtime/
│   ├── alloc.lisp       ; Allocation + GC
│   ├── cons.lisp        ; Cons cells
│   ├── symbol.lisp      ; Symbols + packages
│   ├── vector.lisp      ; Vectors + strings
│   ├── number.lisp      ; Fixnums + bignums
│   └── function.lisp    ; Functions + closures
├── compiler/
│   ├── reader.lisp      ; Lisp reader
│   ├── ir1.lisp         ; High-level IR
│   ├── ir2.lisp         ; Low-level IR
│   ├── x86-64.lisp      ; Code generation
│   └── assemble.lisp    ; Assembler
├── clos/
│   ├── boot.lisp        ; Minimal CLOS for bootstrap
│   └── full.lisp        ; Full MOP
├── drivers/
│   ├── serial.lisp      ; Serial console
│   └── e1000.lisp       ; Network
├── net/
│   ├── tcp.lisp         ; TCP/IP
│   └── ssh.lisp         ; SSH server
└── crypto/
    ├── x25519.lisp      ; Fast curve25519
    ├── ed25519.lisp     ; Fast signatures
    └── chacha20.lisp    ; Stream cipher
```

## What We Keep from Each System

### From Genera
- Live development philosophy
- Everything is modifiable at runtime
- Deep integration of debugger with system

### From Movitz
- Bootstrap from existing compiler
- Careful low-level memory access patterns
- DMA buffer management approach
- Working drivers as reference

### From CCL
- Register allocation strategy
- Tagged pointer layout
- Efficient calling convention
- Subtag organization for types

### From SBCL
- IR-based compilation
- Type inference approach
- Inline caching for generic functions
- Policy-based optimization

### From Mezzano
- 4-bit tag scheme (simplified)
- Language-based security model
- Single address space
- Generational GC design

## Why NOT Just Port Mezzano?

1. **Complexity** - Mezzano is 100K+ lines, deep dependencies
2. **Build system** - Requires full SBCL + Quicklisp toolchain
3. **GUI focus** - Much of Mezzano is McCLIM/GUI oriented
4. **Learning** - Building teaches us the system deeply
5. **Control** - Can make exactly the tradeoffs we want

## Why NOT Just Use SBCL?

1. **Hosted** - Requires Linux/OS underneath
2. **Different goals** - Optimized for desktop Lisp, not embedded/OS
3. **Size** - Full SBCL image is 50+ MB
4. **Device access** - No native hardware access model

## Next Steps

1. **Read Mezzano's supervisor/** - Understand its kernel structure
2. **Read CCL's level-0/** - Understand primitive operations
3. **Design allocator** - This is the foundation of everything
4. **Write 64-bit bootloader** - Start from our working long-mode code
5. **Implement cons/car/cdr** - Minimal Lisp operations
6. **Get to REPL** - First milestone: evaluate `(+ 1 2)`

## Open Questions

1. **Threading model?** - Single-threaded first, add SMP later?
2. **Virtual memory?** - Identity-mapped first, add paging later?
3. **Disk access?** - Network boot only? Add IDE/AHCI later?
4. **Graphics?** - Serial-only? VGA text? Full framebuffer?

## Timeline

| Week | Milestone |
|------|-----------|
| 1 | 64-bit boot to serial output |
| 2 | Memory allocator + basic types |
| 3 | Reader + evaluator |
| 4 | Self-hosting compiler |
| 5 | Full numeric tower |
| 6 | Network driver port |
| 7 | TCP/IP + SSH |
| 8 | Crypto at full speed! |

## Conclusion

The "One True 64-bit Lisp OS" takes the best ideas from five decades of Lisp
system design. By bootstrapping from our working Movitz system and carefully
choosing what to keep vs. reimagine, we can build something special:

A live, interactive, bare-metal Lisp where `(x25519-public-key k)` runs in
milliseconds instead of minutes, where every line of code is inspectable and
modifiable, and where the only limit is our imagination.

Let's build it.
