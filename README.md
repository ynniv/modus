# Modus

A bare-metal Lisp operating system. Boots directly on x86 hardware (or QEMU) into an interactive Common Lisp REPL with networking, SSH, and cryptography — no underlying OS.

Modus has two runtime targets:

- **Modus32** — a 32-bit system built on [Movitz](https://github.com/dym/movitz), with a working SSH server, TLS 1.3, TCP/IP stack, E1000 network driver, and a full crypto suite (X25519, Ed25519, ChaCha20, AES-GCM, secp256k1)
- **Modus64** — a self-hosting 64-bit system with an Erlang-style actor model, SMP multicore support, per-actor garbage collection, and preemptive multitasking

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

- Self-hosting: the kernel compiles itself from embedded source via `(build-image)`
- Cross-compiler bootstraps from SBCL; subsequent generations are self-compiled
- Multiboot boot, 64-bit long mode, identity-mapped paging
- Tagged object system (4-bit tags, 63-bit fixnums)
- Cons cells, symbols, strings, arrays, bignums
- Lisp reader, printer, tree-walking evaluator
- Runtime native compiler (defun, let, lambda, if, closures, loops)
- Cheney copying GC with write barrier
- Serial REPL with line editing
- E1000 networking with TCP/IP, DHCP, DNS, ICMP
- SSH server (multi-connection, inter-session messaging)
- Erlang-style actor model: `spawn`, `send`, `receive`, `link`
- Supervisors with automatic worker restart
- Reduction-counting preemption and LAPIC timer preemption
- SMP: multi-core boot, per-CPU scheduling, IPI wakeup (tested stable on 8 CPUs)
- Per-actor heaps with independent garbage collection
- Collision-free function dispatch via dual FNV-1a hashing

## Building and running

Requires SBCL and QEMU.

### Modus32

```bash
./modus/scripts/build.sh        # build image
./modus/scripts/run.sh           # boot to serial REPL
./modus/scripts/run-ssh-server.sh  # boot with SSH on port 2222
```

### Modus64

```bash
./modus/scripts/run-modus64.sh       # boot to serial REPL
./modus/scripts/run-modus64-ssh.sh   # boot with SSH networking
```

### Self-hosted Modus64

```bash
./modus/scripts/run-modus64-self-hosted-ssh.sh        # Gen0→Gen1 pipeline, boot Gen1 with SSH
./modus/scripts/run-modus64-self-hosted-ssh.sh --repl  # Gen1 REPL only
```

SBCL cross-compiles Gen0. Gen0 boots in QEMU, runs `(build-image)` to natively compile Gen1 from its own embedded source, and Gen1 is extracted via QMP. Gen1 can repeat the process. Build artifacts are cached by content hash.

## Project structure

```
lib/
  binary-types/          Binary data type library (Fjeld)
  movitz/                Movitz bare-metal Lisp framework (Fjeld)
  modus64/               64-bit cross-compiler, boot, and runtime
    boot/                Multiboot entry, 32→64 transition, kernel init
    cross/               Cross-compiler and x86-64 assembler
    runtime/             Tags, cons, alloc, print
  build-image.lisp       Movitz image builder
modus/
  build/                 ASDF system definition and build scripts
  src/
    crypto/              Crypto suite (shared by both targets)
    drivers/             E1000 network driver
    net/                 SSH, TLS 1.3, WebSocket, Nostr
    movitz/              Movitz patches and Modus32 boot code
    repl.lisp            REPL implementation
  scripts/               Build, run, and test scripts
  docs/                  Design documents (Modus32)
docs/                    Design documents (Modus64, actors, calling conventions)
```

## Design

Modus64 uses a 4-bit tag scheme with 63-bit fixnums — large enough for native 64-bit multiply, which makes 256-bit elliptic curve cryptography practical without bignums (4 limbs instead of 32). The actor model gives each actor its own heap, so garbage collection never stops the world. Preemption uses Erlang-style reduction counting with LAPIC timer backup, and SMP distributes actors across cores.

The kernel is self-hosting: SBCL is only needed to bootstrap Gen0. The runtime carries its own source (~550KB, serialized with symbol names replaced by integer hashes) and includes a native compiler that can rebuild the entire kernel from it. Each generation copies the source blob into the next, so SBCL is not involved after the initial bootstrap.

See `docs/` for detailed design documents.

## License

MIT. Movitz and binary-types are BSD-licensed (Frode Vatvedt Fjeld).
