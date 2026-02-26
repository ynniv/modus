# Modus

A bare-metal Lisp operating system. Boots directly on x86 hardware (or QEMU) into an interactive Lisp REPL with networking, SSH, and cryptography — no underlying OS.

Modus has two runtime targets:

- **Modus32** — a 32-bit system built on [Movitz](https://github.com/dym/movitz), with SSH, TLS 1.3, TCP/IP, E1000, and a full crypto suite
- **Modus64** — a self-hosting 64-bit system with a portable virtual machine (MVM) targeting 9 CPU architectures, an Erlang-style actor model, SMP multicore support, and per-actor garbage collection

## What works

### Modus32 (Movitz-based)

- Boots to interactive REPL over serial console
- E1000 network driver with full TCP/IP stack
- SSH server with Ed25519 host keys (port 2222)
- TLS 1.3 client (ECDHE, AES-128-GCM, ChaCha20-Poly1305)
- WebSocket client
- Nostr protocol support (NIP-04, NIP-44, NIP-46)
- Crypto: SHA-256, SHA-384, SHA-512, HMAC, HKDF, X25519, Ed25519, secp256k1, AES, GCM, ChaCha20, Poly1305

### Modus64

**Compiler and self-hosting**
- MVM (Modus Virtual Machine): portable bytecode ISA with ~50 opcodes
- 9 architecture backends: x86-64, i386, AArch64, RISC-V 64, PPC64, PPC32, ARM32 (ARMv5), ARMv7, Motorola 68k
- Self-hosting: the kernel compiles itself from embedded source via `(build-image)`
- SBCL bootstraps Gen0; Gen0 compiles Gen1 natively; Gen1 can repeat the process
- Runtime native compiler (defun, let, lambda, if, closures, loops)
- Closures, hash tables, structs, global variables

**Runtime**
- Tagged object system (4-bit tags, 63-bit fixnums)
- Cons cells, symbols, strings, arrays, bignums
- Lisp reader, printer, tree-walking evaluator
- Cheney copying GC with per-actor heaps
- Serial REPL with line editing and tab completion
- Real-time clock: `(print-time)`, `(unix-time)`

**Networking and crypto**
- E1000 driver with TCP/IP, UDP, DHCP, DNS, ICMP
- SSH server (multi-connection, Ed25519, X25519, ChaCha20-Poly1305)
- Crypto: SHA-256, X25519, Ed25519, ChaCha20, Poly1305

**Concurrency**
- Erlang-style actors: `spawn`, `send`, `receive`, `link`
- Supervisors with automatic worker restart
- Reduction-counting preemption with LAPIC timer backup
- SMP: multi-core boot, per-CPU scheduling, IPI wakeup (tested on 8 CPUs)
- Per-actor heaps with independent garbage collection

## Building and running

Requires SBCL and QEMU.

### Modus32

```bash
./modus/scripts/build.sh           # build image
./modus/scripts/run.sh             # boot to serial REPL
./modus/scripts/run-ssh-server.sh  # boot with SSH on port 2222
```

### Modus64

```bash
./modus/scripts/run-modus64.sh       # boot to serial REPL
./modus/scripts/run-modus64-ssh.sh   # boot with SSH networking
```

### Self-hosted Modus64

```bash
./modus/scripts/run-modus64-self-hosted-ssh.sh        # Gen0 → Gen1, boot Gen1 with SSH
./modus/scripts/run-modus64-self-hosted-ssh.sh --repl  # Gen1 REPL only
```

SBCL cross-compiles Gen0 via the MVM pipeline (Source → MVM bytecode → x86-64 native). Gen0 boots in QEMU, runs `(build-image)` to natively compile Gen1 from its own embedded source (~558KB), and Gen1 is extracted via QMP. Gen1 can repeat the process indefinitely. Build artifacts are cached by content hash.

## Project structure

```
lib/modus64/
  cross/                 Cross-compiler, x64 assembler, runtime (build.lisp ~17K lines)
  mvm/                   Modus Virtual Machine
    mvm.lisp             ISA definition (~50 opcodes, encoding/decoding)
    compiler.lisp        3-phase compiler (Source → IR → MVM bytecode)
    translate-x64.lisp   x86-64 native translator
    translate-riscv.lisp RISC-V translator
    translate-aarch64.lisp AArch64 translator
    translate-ppc.lisp   PowerPC 64 translator
    translate-i386.lisp  i386 translator
    translate-68k.lisp   Motorola 68k translator
    translate-arm32.lisp ARM32/ARMv7 translator
    interp.lisp          MVM interpreter (bootstrapping)
    target.lisp          Architecture descriptors (9 targets)
  boot/                  Per-architecture boot sequences (9 targets)
  runtime/               Tags, subtags
lib/movitz/              Movitz bare-metal Lisp framework (Fjeld)
lib/binary-types/        Binary data type library (Fjeld)
modus/
  src/crypto/            Crypto suite (shared by both targets)
  src/drivers/           E1000 network driver
  src/net/               SSH, TLS 1.3, WebSocket, Nostr
  scripts/               Build, run, and test scripts
docs/                    Design documents
```

## Design

### MVM: the Modus Virtual Machine

MVM is a portable register-based bytecode ISA (~50 opcodes) that decouples the Lisp compiler from target architectures. The compiler is a 3-phase pipeline: Source → IR (virtual register operations) → MVM bytecode. Thin per-architecture translators (~1300-1900 lines each) convert MVM bytecode to native code.

All 9 architectures produce correct output (factorial 3628800) in QEMU. The x86-64 target is the primary platform with full runtime support (networking, SSH, actors, self-hosting). The other 8 targets boot and run serial output programs.

### Tagged objects

4-bit tag scheme with 63-bit fixnums. Large enough for native 64-bit multiply, which makes 256-bit elliptic curve cryptography practical without bignums (4 limbs instead of 32).

### Self-hosting

The kernel carries its own source (~558KB, plain s-expressions with symbol names replaced by integer hashes) and includes a native compiler that rebuilds the entire kernel from it. Each generation copies the source blob into the next, so SBCL is only needed for the initial bootstrap.

### Actors and SMP

Erlang-style actor model with per-actor heaps, so garbage collection never stops the world. Preemption uses reduction counting with LAPIC timer backup. SMP distributes actors across cores with per-CPU run queues and IPI wakeup.

See `docs/` for detailed design documents.

## License

MIT. Movitz and binary-types are BSD-licensed (Frode Vatvedt Fjeld).
