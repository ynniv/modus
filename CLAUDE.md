# Modus64

Modus64 is a self-hosting bare-metal Lisp operating system. It compiles Lisp to native code via the MVM (Modus Virtual Machine) — a portable virtual ISA with translators for 7 CPU architectures. The system runs SSH servers, handles USB devices, and supports cooperative actor-based concurrency, all on bare metal with no OS underneath.

## Directory Structure

```
root=lib/modus64

cross/          SBCL-hosted cross-compiler and x64 assembler
  cross-compile.lisp   Phase 0 cross-compiler (1845L)
  build.lisp           Runtime + self-hosting kernel builder (~16500L)
  x64-asm.lisp         x86-64 assembler (484L)
  packages.lisp        Package definitions

boot/           Architecture boot sequences
  boot-aarch64.lisp    AArch64 QEMU virt boot
  boot-rpi.lisp        Raspberry Pi (BCM2835/2837) boot
  boot-x64.lisp        x86-64 boot
  boot-riscv.lisp      RISC-V boot
  boot-ppc64.lisp      PowerPC 64 boot
  boot-ppc32.lisp      PowerPC 32 boot
  boot-i386.lisp       i386 boot
  boot-68k.lisp        Motorola 68k boot
  boot-arm32.lisp      ARM32 boot

mvm/            MVM compiler, translators, and build scripts
  mvm.lisp             ISA definition (~50 opcodes)
  target.lisp          Target descriptors for all architectures
  compiler.lisp        3-phase compiler: Source → IR → MVM bytecode
  interp.lisp          MVM interpreter (bootstrapping)
  cross.lisp           Universal cross-compilation pipeline
  repl-source.lisp     Embedded REPL source for bare-metal builds
  translate-*.lisp     Native code translators (x64, riscv, aarch64, ppc, i386, 68k, arm32)
  build-*.lisp         Build scripts (see Build Commands below)

net/            Networking, crypto, USB, actor system
  arch-aarch64.lisp    QEMU virt PCI/E1000 adapter + actor addresses
  arch-raspi3b.lisp    RPi adapter (DMA addresses, actor addresses)
  arch-x86.lisp        x86 adapter
  actors.lisp          Cooperative actor system (spawn, yield, send/receive, scheduling)
  actors-net-overrides.lisp   Actor-aware SSH overrides
  isolated-net.lisp    Qubes-like isolation (net-domain owns all hardware)
  e1000.lisp           Intel E1000 NIC driver
  dwc2.lisp            DWC2 USB host controller (RPi 3B QEMU)
  dwc2-device.lisp     DWC2 USB gadget + CDC-ECM (Pi Zero 2 W)
  usb.lisp             USB enumeration + hub support
  cdc-ether.lisp       USB CDC Ethernet
  hid.lisp             USB HID (keyboard, mouse, tablet)
  ip.lisp              ARP/IP/TCP/UDP/DHCP/DNS
  crypto.lisp          SHA-256/512, ChaCha20, Poly1305, X25519, Ed25519
  ssh.lisp             SSH-2 server (key exchange, auth, channels)
  http.lisp            HTTP/1.0 server
  http-client.lisp     HTTP client (URL parsing, GET, fetch)
  aarch64-overrides.lisp   Line editor, buffer reader, SSH I/O overrides
  uart-bootloader.lisp     UART bootloader for rapid kernel redeploy
  bcm2835-periph.lisp      BCM2835 GPIO, SPI, I2C, PWM

scripts/        Deployment and boot scripts
  boot-pizero2w.sh     Build + boot + network + SSH (USB or SD card)
  build-pizero2w.sh    Build kernel + SD card image
  fuse-pizero2w.sh     Program USB boot OTP fuse on Pi Zero 2 W
  make-sdcard-bootloader.sh  Create SD card with UART bootloader
  run-rpi-periph.sh    Launch RPi peripheral test in QEMU

runtime/        Runtime type system
  tags.lisp            Tag/subtag definitions
  packages.lisp        Runtime package definitions
```

## Build Commands

All builds: `cd lib/modus64 && sbcl --script <build-script>`

### QEMU AArch64 (virt machine, E1000)
```bash
# SSH server (single-threaded)
sbcl --script mvm/build-aarch64-ssh.lisp
# Actors (cooperative multi-connection SSH)
sbcl --script mvm/build-aarch64-actors.lisp
# Isolated actors (Qubes-like, net-domain owns hardware)
sbcl --script mvm/build-aarch64-isolated.lisp
# REPL only (serial)
sbcl --script mvm/build-aarch64-repl.lisp
```

QEMU launch (actors example):
```bash
qemu-system-aarch64 -machine virt -cpu cortex-a57 -m 512 \
  -kernel /tmp/modus64-aarch64-actors.bin -nographic -semihosting \
  -device 'e1000,netdev=net0,romfile=,rombar=0' \
  -netdev 'user,id=net0,hostfwd=tcp::2222-:22'
```

### QEMU RPi 3B (DWC2 USB host, CDC Ethernet)
```bash
sbcl --script mvm/build-rpi-ssh.lisp      # SSH
sbcl --script mvm/build-rpi-hid.lisp      # USB keyboard REPL
sbcl --script mvm/build-rpi-repl.lisp     # Serial REPL
sbcl --script mvm/build-rpi-periph.lisp   # GPIO/SPI/I2C peripherals
```

### Pi Zero 2 W (real hardware, DWC2 USB gadget, CDC-ECM)
```bash
sbcl --script mvm/build-pizero2w-ssh.lisp      # Single-threaded SSH
sbcl --script mvm/build-pizero2w-actors.lisp   # Actor-based SSH
```
Output: `/tmp/piboot/kernel8.img`

Deploy via rpiboot (USB boot): `sudo rpiboot -d /tmp/piboot`
Deploy via UART bootloader: `sudo python3 ~/deploy-kernel.py ~/kernel8.img`
Full workflow: `./scripts/boot-pizero2w.sh`

## Tagged Value System

All values are tagged 64-bit words with fixnum-shift=1:
- **Fixnum** (tag xxx0): value << 1, 63-bit integers
- **Cons** (tag 0001): pointer to car/cdr pair, 16-byte aligned
- **Object** (tag 1001): pointer to header + data
- **Immediate** (tag 0101): characters, nil, booleans
- **Forward** (tag 1111): GC forwarding pointer

Object header: `[subtag:8][unused:7][element-count:49]`
Key subtags: string=#x10, symbol=#x50, closure=#x52, array=#x32, hash-table=#x41

### mem-ref Semantics (MVM)
- `:u8`, `:u32` loads → result is **tagged** (SHL 1); stores → value is **untagged** (SHR 1)
- `:u64` loads/stores → **raw** bits, no shift
- Address operand is always **untagged** (SHR 1)

### Array Access
Raw address from object pointer: `(ash (logand obj (- 0 4)) 1)` — strips tag bits, doubles to byte address. Data starts at +8 (past header).

## MVM Compiler Limitations

These are known compiler bugs/limitations — work around them, don't try to fix:

1. **3-arg `+` is broken**: Always use nested 2-arg `+`: `(+ a (+ b c))` not `(+ a b c)`
2. **set-car/set-cdr with function call args clobber registers**: Pre-compute to a let binding:
   ```lisp
   ;; BAD: (set-car cell (some-fn x))
   ;; GOOD:
   (let ((val (some-fn x)))
     (set-car cell val))
   ```
3. **Last-defun-wins**: All calls resolve to the LAST defun of a given name. You cannot alias a function before overriding it. Use different names.
4. **18+ nested lets**: May miscompile. Split into helper functions.
5. **YIELD opcode**: Emitted at end of every `loop` iteration. On AArch64 bare metal, must be SEV+WFE (not just WFE which would stall on Cortex-A53).
6. **cons cells in actor context**: May get corrupted across yield/context-switch boundaries. Inline data construction instead of relying on cons returns when the result crosses scheduling points.

## Actor System

Cooperative scheduling on single core (SMP stubs exist, multi-core not yet active).

- **Actor 1**: Primordial (kernel-main → idle yield loop)
- **Actor 2**: Net-domain (owns all hardware: NIC polling, TCP/IP, ARP)
- **Actor 3+**: SSH handler actors (one per connection)

Per-actor heaps: 4MB each (`actor-heap-base + (id-1) << 22`).
Communication: mailbox messages via `send`/`try-receive`. Messages serialized through staging buffers.

Key globals for translator:
- `*aarch64-sched-lock-addr*`: Set to lock address for RESTORE-CONTEXT unlock. nil = no actor support.
- `*aarch64-serial-base/width/tx-poll*`: UART configuration per board.

## Pi Zero 2 W Hardware Notes

- **BCM2710A1** (Cortex-A53, 512MB, same as BCM2837 in RPi 3B)
- **USB**: Single micro-USB OTG, DWC2 in device/gadget mode
- **UART**: Mini UART at 0x3F215040 (not PL011), 32-bit stores, ALT5 on GPIO14/15
- **CDC-ECM**: Static IP 10.0.0.2, host 10.0.0.1, MAC 02:00:00:00:00:01
- **GPIO17**: Connected to RST pad for reset. Reset: `pinctrl set 17 op dl; sleep 0.3; pinctrl set 17 ip pn` (MUST set back to input-no-pull or default pull-down holds Pi in reset)
- **USB boot**: Requires OTP fuse programmed once via `scripts/fuse-pizero2w.sh`
- **Crypto**: Pre-compute Ed25519 host key + X25519 ephemeral at boot (saves ~10s per connection). USB keep-alive polling during crypto prevents NETDEV WATCHDOG timeout.
- **Host NAT**: `boot-pizero2w.sh` sets up iptables MASQUERADE for Pi internet access

## Networking Architecture

Shared source files between QEMU virt (E1000) and RPi (DWC2 CDC-ECM):
- `ip.lisp`, `crypto.lisp`, `ssh.lisp`, `http.lisp`, `http-client.lisp`, `aarch64-overrides.lisp`

Per-platform adapters provide: `e1000-send`, `e1000-receive`, `e1000-state-base`, `ssh-ipc-base`, allocation primitives (`make-array`, `aref`, `aset`), and actor address hooks.

Source load order matters — later files override earlier defuns:
```
arch-* → [actors] → NIC driver → ip → crypto → ssh → http → http-client →
aarch64-overrides → [actors-net-overrides] → [isolated-net]
```

## Testing

```bash
# QEMU SSH test
echo '(+ 1 2)' | ssh -p 2222 test@localhost   # → 3

# Pi Zero 2 W SSH test
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 test@10.0.0.2
```

SSH credentials: username `test`, any password accepted (no real auth).
