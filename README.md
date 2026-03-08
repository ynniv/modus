# Modus

A bare-metal Lisp operating system. Boots directly on hardware (or QEMU) into an interactive Lisp REPL with networking, SSH, and cryptography — no underlying OS.

A self-hosting 64-bit system with a portable virtual machine (MVM) targeting 9 CPU architectures, an Erlang-style actor model, SMP multicore support, and per-actor garbage collection.

## Feature matrix

### Platforms

|                    | x86-64 QEMU | AArch64 QEMU virt | RPi 3B QEMU | Pi Zero 2 W |
|--------------------|:-----------:|:-----------------:|:-----------:|:-----------:|
| Serial REPL        | Y | Y | Y | Y |
| E1000 networking   | Y | Y | - | - |
| USB CDC networking | - | - | Y | Y |
| SSH server         | Y | Y | Y | Y |
| HTTP server/client | - | Y | - | Y |
| Actors             | Y | Y | - | Y |
| Actor isolation    | - | Y | - | - |
| SMP (multi-core)   | Y | - | - | - |
| Self-hosting       | Y | Y | - | - |
| USB HID            | - | - | Y | - |
| GPIO/SPI/I2C       | - | - | Y | - |
| GPU framebuffer    | - | - | Y | Y |
| UART bootloader    | - | - | - | Y |
| Real hardware      | - | - | - | Y |

NIC driver: x86-64 and AArch64 virt use Intel E1000 (PCI). RPi uses DWC2 USB — host mode (CDC Ethernet) on QEMU raspi3b, device/gadget mode (CDC-ECM) on Pi Zero 2 W.

### MVM architectures

All 9 architectures compile and produce correct output (factorial 3628800) in QEMU. x86-64 and AArch64 have full runtime support; i386 has REPL support.

| Architecture | Bits | Endian | Translator | Boot | QEMU target | Status |
|-------------|:----:|:------:|:----------:|:----:|-------------|--------|
| x86-64      | 64 | little | translate-x64.lisp    | boot-x64.lisp    | `qemu-system-x86_64`    | Full (REPL, SSH, actors, self-hosting) |
| AArch64     | 64 | little | translate-aarch64.lisp | boot-aarch64.lisp | `qemu-system-aarch64 -M virt` | Full (REPL, SSH, actors) |
| AArch64 RPi | 64 | little | translate-aarch64.lisp | boot-rpi.lisp    | `qemu-system-aarch64 -M raspi3b` | Full (REPL, SSH, USB HID, real hardware) |
| RISC-V 64   | 64 | little | translate-riscv.lisp  | boot-riscv.lisp  | `qemu-system-riscv64`   | Serial output |
| PPC64       | 64 | big    | translate-ppc.lisp    | boot-ppc64.lisp  | `qemu-system-ppc64`     | Serial output |
| PPC32       | 32 | big    | translate-ppc.lisp    | boot-ppc32.lisp  | `qemu-system-ppc`       | Serial output |
| i386        | 32 | little | translate-i386.lisp   | boot-i386.lisp   | `qemu-system-i386`      | REPL |
| ARM32 (v5)  | 32 | little | translate-arm32.lisp  | boot-arm32.lisp  | `qemu-system-arm -M versatilepb` | Serial output |
| ARMv7       | 32 | little | translate-arm32.lisp  | boot-arm32.lisp  | `qemu-system-arm -M virt` | Serial output |
| 68k         | 32 | big    | translate-68k.lisp    | boot-68k.lisp    | `qemu-system-m68k -M an5206` | Serial output |

### Run modes

| Mode | Description | Platforms |
|------|-------------|-----------|
| REPL | Interactive serial console with line editing | All 4 platforms |
| SSH | Single-threaded SSH server (one connection) | All 4 platforms |
| Actors | Cooperative multi-connection SSH via actor system | x86-64, AArch64 virt, Pi Zero 2 W |
| Isolated | Qubes-like actor isolation (net-domain owns hardware) | AArch64 virt |
| Self-host | Gen0 boots, compiles Gen1 from embedded source | x86-64, AArch64 virt |
| HID | USB keyboard-driven REPL | RPi 3B QEMU |

## Building and running

Requires SBCL and QEMU.

### x86-64

```bash
./scripts/run-x64-repl.sh      # boot to serial REPL
./scripts/run-x64-ssh.sh       # boot with SSH networking
```

### Self-hosted x86-64

```bash
./scripts/run-x64-gen1-ssh.sh          # Gen0 → Gen1, boot Gen1 with SSH
./scripts/run-x64-gen1-repl.sh         # Gen1 REPL only
./scripts/run-x64-gen1-repl.sh --rebuild  # force full rebuild
```

### AArch64 (QEMU virt)

```bash
./scripts/run-aarch64-repl.sh  # AArch64 REPL on QEMU virt
./scripts/run-aarch64-ssh.sh   # AArch64 with SSH networking (E1000, port 2222)
```

Connect to AArch64 SSH: `ssh -p 2222 -o StrictHostKeyChecking=no test@localhost`

### i386 (QEMU)

```bash
./scripts/run-i386-repl.sh     # 32-bit x86 REPL on QEMU
```

### Raspberry Pi (QEMU raspi3b)

```bash
./scripts/run-rpi-repl.sh      # AArch64 REPL on emulated raspi3b
./scripts/run-rpi-ssh.sh       # SSH over USB CDC Ethernet (port 2222)
./scripts/run-rpi-hid.sh       # USB keyboard-driven REPL
```

### Raspberry Pi Zero 2 W (real hardware)

The Pi Zero 2 W boots via USB (no SD card needed) using rpiboot, with SSH over USB CDC-ECM Ethernet.

```bash
# One-time: program USB boot OTP fuse (irreversible, requires SD card)
bash scripts/fuse-pizero2w.sh
sudo dd if=/tmp/pizero2w-fuse.img of=/dev/sdX bs=4M  # boot once to program fuse

# Build and deploy
sbcl --script mvm/build-pizero2w-actors.lisp   # actor-based SSH + HTTP
# or: sbcl --script mvm/build-pizero2w-ssh.lisp   # single-threaded SSH

# Full workflow (build, USB boot or UART redeploy, network setup, SSH)
bash scripts/boot-pizero2w.sh

# Manual deployment via UART bootloader (fast iteration)
scp /tmp/piboot/kernel8.img pi5:~/kernel8.img
ssh pi5 'sudo python3 ~/deploy-kernel.py ~/kernel8.img'
ssh pi5 'sudo ip addr add 10.0.0.1/24 dev usb0; sudo ip link set usb0 up'
ssh -o ConnectTimeout=30 test@10.0.0.2
```

SBCL cross-compiles Gen0 via the MVM pipeline (Source → MVM bytecode → x86-64 native). Gen0 boots in QEMU, runs `(build-image)` to natively compile Gen1 from its own embedded source (~558KB), and Gen1 is extracted via QMP. Gen1 can repeat the process indefinitely. Build artifacts are cached by content hash.

## Project structure

```
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
  http.lisp            HTTP/1.0 server
  http-client.lisp     HTTP client with URL parsing and DNS
  actors.lisp          Actor system (spawn, yield, send, receive, scheduler)
  isolated-net.lisp    Qubes-like isolation (net-domain owns all hardware)
  bcm2835-periph.lisp  System timer, GPIO LED, GPU framebuffer
  uart-bootloader.lisp UART serial bootloader protocol
crypto/                CL reference implementations (not yet MVM-adapted)
  aes.lisp             AES-128/256 block cipher
  gcm.lisp             GCM authenticated encryption
  secp256k1.lisp       secp256k1 elliptic curve
  hmac.lisp            HMAC
  hkdf.lisp            HKDF key derivation
  aead.lisp            AEAD construction
  sha384.lisp          SHA-384
  sha512.lisp          SHA-512 (4x16-bit limb variant)
  nip04.lisp           Nostr NIP-04 encryption
  nip44.lisp           Nostr NIP-44 encryption
proto/                 Protocol implementations (CL reference, not yet MVM-adapted)
  tls13.lisp           TLS 1.3 client (RFC 8446)
  websocket.lisp       WebSocket client (RFC 6455)
  nostr.lisp           Nostr protocol (NIP-01)
  nip46.lisp           Nostr NIP-46 nsecBunker
lib/                   Utility libraries (CL reference, not yet MVM-adapted)
  json.lisp            JSON parser and serializer
  trace.lisp           Timing/profiling macros
mvm/                   Modus Virtual Machine
  mvm.lisp             ISA definition (~50 opcodes, encoding/decoding)
  compiler.lisp        3-phase compiler (Source → IR → MVM bytecode)
  prelude.lisp         MVM-compilable CL library (hash tables, sort, mapcar)
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
scripts/               Build, run, and deployment scripts
docs/                  Design documents and presentations
```

## Design

### MVM: the Modus Virtual Machine

MVM is a portable register-based bytecode ISA (~50 opcodes) that decouples the Lisp compiler from target architectures. The compiler is a 3-phase pipeline: Source → IR (virtual register operations) → MVM bytecode. Thin per-architecture translators (~1300-1900 lines each) convert MVM bytecode to native code.

All 9 architectures produce correct output (factorial 3628800) in QEMU. The x86-64 target is the primary platform with full runtime support (networking, SSH, actors, self-hosting). AArch64 supports REPL and SSH via both QEMU virt (PCI ECAM + E1000) and real Pi hardware (DWC2 USB + CDC-ECM). i386 runs an interactive REPL with user-defined functions and global variables. The other 6 targets boot and run serial output programs.

### Tagged objects

4-bit tag scheme with 63-bit fixnums. Large enough for native 64-bit multiply, which makes 256-bit elliptic curve cryptography practical without bignums (4 limbs instead of 32).

### Self-hosting

The kernel carries its own source (~558KB, plain s-expressions with symbol names replaced by integer hashes) and includes a native compiler that rebuilds the entire kernel from it. Each generation copies the source blob into the next, so SBCL is only needed for the initial bootstrap. The MVM compiler can also compile its own source to architecture-independent bytecode, proving the compilation pipeline is a fixed point.

### Actors and SMP

Erlang-style actor model with per-actor heaps, so garbage collection never stops the world. Preemption uses reduction counting with LAPIC timer backup. SMP distributes actors across cores with per-CPU run queues and IPI wakeup.

See `docs/` for detailed design documents.

## License

MIT.
