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
- E1000 driver with TCP/IP, UDP, DHCP, DNS, ICMP (x86-64 and AArch64)
- SSH server (multi-connection, Ed25519, X25519, ChaCha20-Poly1305)
- Crypto: SHA-256, SHA-512, X25519, Ed25519, ChaCha20, Poly1305
- Shared networking code with thin arch adapters (x86 I/O ports vs AArch64 ECAM PCI)

**Concurrency**
- Erlang-style actors: `spawn`, `send`, `receive`, `link`
- Supervisors with automatic worker restart
- Reduction-counting preemption with LAPIC timer backup
- SMP: multi-core boot, per-CPU scheduling, IPI wakeup (tested on 8 CPUs)
- Per-actor heaps with independent garbage collection

**Raspberry Pi (bare-metal hardware)**
- Runs on Pi Zero 2 W (BCM2710A1, Cortex-A53) and QEMU raspi3b
- DWC2 USB host stack: enumeration, hub support, CDC Ethernet (QEMU)
- DWC2 USB device mode: CDC-ECM gadget for Pi Zero 2 W networking
- USB HID: keyboard, mouse, tablet via boot protocol
- BCM2835 peripherals: system timer, GPIO LED, GPU framebuffer (640x480 HDMI)
- UART serial bootloader: deploy new kernels over serial from Pi 5 — no SD card swapping
- Qubes-like actor isolation: net-domain owns hardware, SSH handlers use mailbox messages

## Building and running

Requires SBCL and QEMU.

### Modus32

```bash
./modus/scripts/build-movitz.sh       # build image
./modus/scripts/run-movitz-repl.sh    # boot to serial REPL
./modus/scripts/run-movitz-ssh.sh     # boot with SSH on port 2222
```

### Modus64

```bash
./modus/scripts/run-x64-repl.sh      # boot to serial REPL
./modus/scripts/run-x64-ssh.sh       # boot with SSH networking
```

### Self-hosted Modus64

```bash
./modus/scripts/run-x64-gen1-ssh.sh          # Gen0 → Gen1, boot Gen1 with SSH
./modus/scripts/run-x64-gen1-repl.sh         # Gen1 REPL only
./modus/scripts/run-x64-gen1-repl.sh --rebuild  # force full rebuild
```

### AArch64 (QEMU virt)

```bash
./modus/scripts/run-aarch64-repl.sh  # AArch64 REPL on QEMU virt
./modus/scripts/run-aarch64-ssh.sh   # AArch64 with SSH networking (E1000, port 2222)
```

Connect to AArch64 SSH: `ssh -p 2222 -o StrictHostKeyChecking=no test@localhost`

### Raspberry Pi (QEMU raspi3b)

```bash
./modus/scripts/run-rpi-repl.sh      # AArch64 REPL on emulated raspi3b
./modus/scripts/run-rpi-ssh.sh       # SSH over USB CDC Ethernet (port 2222)
./modus/scripts/run-rpi-hid.sh       # USB keyboard-driven REPL
```

### Raspberry Pi Zero 2 W (real hardware)

```bash
# One-time: build bootloader and flash SD card
cd lib/modus64 && bash scripts/make-sdcard-bootloader.sh
sudo dd if=/tmp/pizero2w-sdcard.img of=/dev/sdX bs=4M

# Deploy kernels over UART (no SD card swapping)
sbcl --script mvm/build-pizero2w-ssh.lisp          # or any build script
scp /tmp/piboot/kernel8.img pi5:~/kernel8.img
ssh pi5 'python3 deploy-kernel.py ~/kernel8.img'    # GPIO17 reset + UART upload
```

See [`docs/rpi-zero-2w.md`](docs/rpi-zero-2w.md) for wiring, memory map, and hardware details.

SBCL cross-compiles Gen0 via the MVM pipeline (Source → MVM bytecode → x86-64 native). Gen0 boots in QEMU, runs `(build-image)` to natively compile Gen1 from its own embedded source (~558KB), and Gen1 is extracted via QMP. Gen1 can repeat the process indefinitely. Build artifacts are cached by content hash.

## Project structure

```
lib/modus64/
  cross/                 Cross-compiler, x64 assembler, runtime (build.lisp ~13K lines)
  net/                   Shared networking/crypto/SSH (arch-independent, ~8000 lines)
    arch-x86.lisp        x86 PCI I/O, addresses
    arch-aarch64.lisp    AArch64 ECAM PCI, addresses
    arch-raspi3b.lisp    RPi 3B/Zero 2 W adapter (DWC2 addresses, PCI stubs)
    e1000.lisp           E1000 network driver
    dwc2.lisp            DWC2 USB host controller (QEMU raspi3b)
    dwc2-device.lisp     DWC2 USB gadget + CDC-ECM Ethernet (Pi Zero 2 W)
    usb.lisp             USB enumeration, hub support
    cdc-ether.lisp       CDC Ethernet NIC (USB host mode)
    hid.lisp             USB HID keyboard/mouse/tablet
    ip.lisp              ARP, IP, UDP, TCP, DHCP, DNS, ICMP
    crypto.lisp          SHA-256, ChaCha20, Poly1305, X25519, SHA-512, Ed25519
    ssh.lisp             SSH server (multi-connection)
    actors.lisp          Actor system (spawn, yield, send, receive, scheduler)
    bcm2835-periph.lisp  System timer, GPIO LED, GPU framebuffer
    uart-bootloader.lisp UART serial bootloader protocol
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

All 9 architectures produce correct output (factorial 3628800) in QEMU. The x86-64 target is the primary platform with full runtime support (networking, SSH, actors, self-hosting). AArch64 supports REPL and SSH via QEMU virt (PCI ECAM + E1000). The other 7 targets boot and run serial output programs.

### Tagged objects

4-bit tag scheme with 63-bit fixnums. Large enough for native 64-bit multiply, which makes 256-bit elliptic curve cryptography practical without bignums (4 limbs instead of 32).

### Self-hosting

The kernel carries its own source (~558KB, plain s-expressions with symbol names replaced by integer hashes) and includes a native compiler that rebuilds the entire kernel from it. Each generation copies the source blob into the next, so SBCL is only needed for the initial bootstrap.

### Actors and SMP

Erlang-style actor model with per-actor heaps, so garbage collection never stops the world. Preemption uses reduction counting with LAPIC timer backup. SMP distributes actors across cores with per-CPU run queues and IPI wakeup.

See `docs/` for detailed design documents.

## License

MIT. Movitz and binary-types are BSD-licensed (Frode Vatvedt Fjeld).
