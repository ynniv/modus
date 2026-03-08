# MVM: The Modus Virtual Machine

## Overview

MVM is a portable register-based bytecode ISA (~50 opcodes) that decouples the Lisp compiler from target CPU architectures. Source code compiles to MVM bytecode through a 3-phase pipeline, then thin per-architecture translators convert MVM bytecode to native machine code.

9 architectures are supported: x86-64, i386, AArch64, RISC-V 64, PPC64, PPC32, ARM32 (ARMv5), ARMv7, and Motorola 68k. All produce correct serial output (factorial 3628800) in QEMU.

### Motivation

Modus64 originally had two x86-64-only compilers sharing zero code: `cross-compile.lisp` (SBCL-side, ~1845 lines) and `rt-compile-*` in `build.lisp` (self-hosting, ~2500 lines), both with hundreds of hardcoded hex bytes. MVM replaces the cross-compiler side with a target-independent pipeline. The self-hosting native compiler remains (it compiles Gen1+ from source at runtime).

Inspired by Genera's Ivory processor (256-opcode tagged ISA, architecture mixins) but designed for AOT register-machine translation rather than hardware interpretation.

---

## Architecture

### Compilation pipeline

```
Lisp source → [Phase 1: Frontend] → IR (virtual register ops)
           → [Phase 2: Codegen]  → MVM bytecode
           → [Phase 3: Translate] → Native machine code
```

Phases 1-2 are target-independent. Phase 3 selects a translator based on the target architecture.

### Virtual registers

```
V0-V3     : argument registers (e.g., RSI/RDI/R8/R9 on x64)
V4-V15    : general purpose (callee-save subset varies per arch)
VR        : return value (e.g., RAX on x64)
VA        : alloc pointer (e.g., R12 on x64)
VL        : alloc limit (e.g., R14 on x64)
VN        : NIL constant (e.g., R15 on x64)
VSP       : stack pointer
VFP       : frame pointer
```

16 virtual GPRs + 4 special registers. Each architecture maps these to physical registers; overflows spill to the stack.

### Instruction encoding

Each instruction is `[opcode:8][operands:variable]`. Operands encode register numbers (4 bits), immediates (8/16/32/64 bit), or branch offsets (16-bit signed).

### Instruction set (~50 opcodes)

**Data movement**: `mov`, `li` (load immediate), `push`, `pop`

**Arithmetic** (tagged fixnum): `add`, `sub`, `mul`, `div`, `mod`, `neg`, `inc`, `dec`

**Bitwise**: `and`, `or`, `xor`, `shl`, `shr`, `sar`, `not`

**Comparison**: `cmp` (sets condition), `test`

**Branch**: `br`, `beq`, `bne`, `blt`, `bge`, `ble`, `bgt`

**List operations**: `car`, `cdr`, `cons`, `setcar`, `setcdr`, `consp`, `atom`

**Object operations**: `alloc-obj`, `obj-ref`, `obj-set`, `obj-tag`, `obj-subtag`

**Memory** (raw, for drivers): `load` (u8/u16/u32/u64), `store`, `fence`

**Function calls**: `call`, `call-ind`, `ret`, `tailcall`

**GC and allocation**: `alloc-cons`, `gc-check`, `write-barrier`

**System**: `io-read`, `io-write`, `halt`, `cli`, `sti`, `serial-out`

**Actor/concurrency**: `save-ctx`, `restore-ctx`, `yield`, `atomic-xchg`

---

## Files

### Core

| File | Lines | Description |
|------|-------|-------------|
| `mvm/mvm.lisp` | 865 | ISA definition, opcode encoding/decoding, constants |
| `mvm/compiler.lisp` | 2533 | 3-phase compiler: Source → IR → MVM bytecode |
| `mvm/target.lisp` | 458 | Architecture descriptors for all 9 targets |
| `mvm/interp.lisp` | 802 | MVM bytecode interpreter (bootstrapping) |
| `mvm/cross.lisp` | 588 | Universal cross-compilation pipeline |

### Translators

| File | Lines | Architecture | Notes |
|------|-------|-------------|-------|
| `mvm/translate-x64.lisp` | 1660 | x86-64 | Primary target, uses `x64-asm.lisp` encoder |
| `mvm/translate-i386.lisp` | 1670 | i386 | Hardest: only 8 GPRs, V4+ always spill |
| `mvm/translate-aarch64.lisp` | 1935 | AArch64 | Bitmask immediate encoding |
| `mvm/translate-riscv.lisp` | 1382 | RISC-V 64 | Cleanest encoder |
| `mvm/translate-ppc.lisp` | 1739 | PowerPC 64 | r0 gotcha (reads as 0 in some contexts) |
| `mvm/translate-68k.lisp` | 1864 | Motorola 68k | Big-endian, split D/A register file |
| `mvm/translate-arm32.lisp` | 1574 | ARM32/ARMv7 | Barrel shifter immediates, conditional execution |

### Boot sequences

| File | Lines | Architecture |
|------|-------|-------------|
| `boot/boot-x64.lisp` | 393 | x86-64 (Multiboot, 32→64 transition) |
| `boot/boot-i386.lisp` | 207 | i386 (Multiboot, protected mode) |
| `boot/boot-aarch64.lisp` | 289 | AArch64 (DTB, MMU off, UART) |
| `boot/boot-riscv.lisp` | 243 | RISC-V 64 (OpenSBI, UART) |
| `boot/boot-ppc64.lisp` | 323 | PowerPC 64 (Open Firmware) |
| `boot/boot-ppc32.lisp` | 112 | PowerPC 32 |
| `boot/boot-68k.lisp` | 221 | 68k (big-endian) |
| `boot/boot-arm32.lisp` | 152 | ARM32/ARMv7 |

---

## Compiler details

### Phase 1: Frontend

- Reads Lisp source forms
- Expands macros (`when`, `unless`, `cond`, `and`, `or` are macros, not special forms)
- Recognizes ~40 special forms and builtins
- Allocates virtual registers for let bindings and temporaries
- This phase is 100% target-independent

### Phase 2: IR generation

- Walks forms, emits MVM IR (virtual register operations)
- Linear register allocation with spill/restore for deep expressions
- Handles `let`/`let*` → virtual register assignments
- Handles `if`/`loop`/`block`/`return` → branch instructions
- Handles `defun` → function prologue/epilogue with callee-save
- Built-in function recognition: `car` → `mvm-car`, `+` → `mvm-add`, etc.
- This phase is 100% target-independent

### Phase 3: Bytecode emission

- Encodes IR into compact bytecode
- Two-pass: measure branch offsets, then emit
- Produces a compiled module with function table and bytecode blob

### Built-in operation mapping

Common Lisp functions compile to single MVM instructions:

| Lisp | MVM op | Notes |
|------|--------|-------|
| `car`, `cdr` | `car`, `cdr` | Tagged, type-checking |
| `cons` | `cons` | Bump-allocates from VA/VL |
| `+`, `-`, `*` | `add`, `sub`, `mul` | Tagged fixnum fast path |
| `truncate`, `mod` | `div`, `mod` | |
| `logand`, `logior`, `logxor` | `and`, `or`, `xor` | |
| `ash` | `shl`, `shr` | Direction from sign of amount |
| `eq` | `cmp` + `beq` | Branch pattern |
| `<`, `>`, `<=`, `>=` | `cmp` + conditional branch | |
| `mem-ref`, `setf mem-ref` | `load`, `store` | Raw memory for drivers |
| `io-in-byte`, `io-out-byte` | `io-read`, `io-write` | Port I/O |

---

## Translation

Each translator converts MVM bytecode to native machine code. Translation is a linear scan: each MVM instruction becomes 1-5 native instructions.

### x86-64 register mapping

```
V0 → RSI    V1 → RDI    V2 → R8     V3 → R9     (args)
V4 → RBX    V5 → RCX    V6 → RDX    V7 → R10    (scratch/general)
V8 → R11    V9-V15 → stack spill
VR → RAX    VA → R12    VL → R14    VN → R15
```

### Translation example

`mvm-add V4, V0, V1` on x86-64:
```asm
mov rbx, rsi     ; V4 = V0
add rbx, rdi     ; V4 += V1
```

`mvm-cons VR, V0, V1` on x86-64:
```asm
mov [r12], rsi      ; car = V0
mov [r12+8], rdi    ; cdr = V1
lea rax, [r12+1]    ; tag cons pointer
add r12, 16         ; bump alloc
```

`mvm-call target` on x86-64:
```asm
call rel32           ; direct call
```

### Architecture-specific challenges

- **i386**: Only 8 GPRs. V4+ spill to stack frame. Every 3-operand MVM op needs load/compute/store.
- **68k**: Split register file (D0-D7 data, A0-A7 address). Big-endian byte ordering. Variable-length encoding.
- **AArch64**: Bitmask immediates are encoded as a rotation+mask pattern, not arbitrary constants.
- **PPC**: r0 reads as 0 in load/store base — must use r0 only for immediates, never as base register.
- **ARM32**: 8-bit rotated immediates; large constants require `movw`/`movt` pairs (ARMv7) or literal pools (ARMv5).

---

## Build integration

### SBCL-side kernel build

`build-kernel-mvm` in `build.lisp` uses the MVM pipeline to compile all ~940 runtime functions:

1. Register bootstrap macros (cond, and, or)
2. Compile all `*runtime-functions*` forms → MVM bytecode module
3. Translate MVM bytecode → x86-64 native code
4. Copy native code into kernel image buffer
5. Generate `register-builtins` (NFN table registration)
6. Emit boot preamble, source blob, metadata
7. Write bootable ELF image

### Self-hosting

The runtime's native compiler (`rt-compile-*` in `build.lisp`) compiles Gen1+ from embedded source. It does not use MVM — it generates x86-64 code directly. MVM is only used for the SBCL → Gen0 bootstrap path.

The self-hosting pipeline:
```
SBCL + MVM → Gen0 (x86-64 ELF)
Gen0 + (build-image) → Gen1 (native compiler)
Gen1 + (build-image) → Gen2 (identical to Gen1)
```

### Cross-architecture (partial)

The MVM pipeline can compile and translate for any of the 9 targets from SBCL. Each target boots in QEMU with its architecture-specific boot sequence and runs serial output programs. Full runtime support (networking, SSH, actors) is currently x86-64 only.

---

## Testing

### Per-architecture QEMU test

`mvm/test-arch.sh` builds and boots all 9 architectures, verifying serial output:

```bash
./mvm/test-arch.sh
```

Each target computes factorial(10) and prints `3628800` via serial port.

### Self-hosting verification

```bash
./scripts/run-x64-gen1-repl.sh --rebuild
```

Builds Gen0 via MVM, boots it, runs `(build-image)` to compile Gen1, extracts Gen1 via QMP, boots Gen1 to REPL. Verifies arithmetic, loops, factorial, and RTC functions.
