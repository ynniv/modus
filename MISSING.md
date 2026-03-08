# What Modus64 Doesn't Have

## Language
- No macros at the REPL (defmacro works in cross-compiler and MVM, not in native compiler)
- No conditions / restarts (modus-error prints and halts)
- No multiple return values
- No floating point, no rationals
- No mapcar/reduce/filter (dolist/dotimes exist in MVM compiler, not at REPL)
- No format strings — print-dec, print-hex, print-string, write-byte only
- No packages
- 4-arg limit on native-compiled functions

## OS
- No filesystem — no disk I/O at all
- No display — serial and SSH only
- No virtual memory / memory protection
- No user/kernel separation — everything runs ring 0
- No process isolation — actors share address space

## Networking
- No TLS (SSH rolls its own crypto channel)
- No HTTP
- No WebSocket
- TCP is bare-bones (no retransmit, no congestion control)

## Tooling
- No debugger
- No disassembler

## What It Does Have (non-obvious)
- Closures / lambda with variable capture
- Hash tables (make-hash-table, gethash, sethash, remhash)
- Structs (defstruct in cross-compiler and MVM)
- Real-time clock (rtc-seconds/minutes/hours/day/month/year, print-time, unix-time)
- Self-hosting: (build-image) compiles a new kernel from within the running kernel
- 9-architecture MVM backend (x86-64, i386, AArch64, RISC-V, PPC64, PPC32, ARM32, ARMv7, 68k)
- SSH server with Ed25519, X25519, ChaCha20-Poly1305
- Actor-based SMP (multi-core support)
- Full TCP/IP + UDP networking with E1000 NIC driver
