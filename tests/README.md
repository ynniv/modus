# AArch64 Test Suite

SBCL-driven tests that build MVM images and run them on AArch64 QEMU. Each test compiles Lisp source to native AArch64 via the MVM pipeline, boots in QEMU, and checks serial output against expected values.

## Running

```bash
sbcl --script tests/test-aarch64-logior.lisp
sbcl --script tests/test-aarch64-exchange-hash.lisp
sbcl --script tests/test-aarch64-ssh-packet.lisp

# test-aarch64-handle-kex.lisp takes ~60s (Ed25519 scalar mult without crypto-fast)
sbcl --script tests/test-aarch64-handle-kex.lisp
```

## Test Files

### test-aarch64-logior.lisp (16 tests)

MVM compiler correctness on AArch64 — nested expressions and deep let nesting.

| Test | What | Result |
|------|------|--------|
| t1-const | `(logior 1 2 4 8)` | PASS |
| t2-ash-args | `(logior a (ash b 8) (ash c 16) (ash d 24))` from let-bound params | PASS |
| t3-aref | `(logior (aref buf off) (ash (aref ...) 8) ...)` — buf-read-u32-le pattern | PASS |
| t4-flat | Flat let-binding workaround version | PASS |
| t5-20-lets | 20 nested lets, each calling make-array | PASS |
| t6-deep-forms | 20 nested lets + write-char-serial before return | PASS |
| t7-24-lets | 24 nested lets (ssh-compute-exchange-hash depth) | PASS |
| t8-24-lets-4params | 24 lets + 4 function params | PASS |
| t9-trap-clobber | Deep nesting + TRAP before return expression | PASS |
| t10-no-trap | Same without trap (control) | PASS |
| t11-call-clobber | Deep nesting + function call before return | PASS |
| t-4p-all+{16..24}n | Bisect: 4 params + varying depth using all params | PASS |

### test-aarch64-exchange-hash.lisp (17 tests)

SSH concat chain + SHA-256 — tests the ssh-compute-exchange-hash pattern.

| Test | What | Result |
|------|------|--------|
| concat-{1..7}v | ssh-make-str + ssh-concat2 chain, 1-7 values | PASS |
| concat-4p-{1..7}v | Same with 4 function params | PASS |
| hash-{1,3,5,7}v | Concat chain → SHA-256, compare with Python | PASS |
| hash-4p-{3,5,7}v | 4 params + concat chain → SHA-256 | PASS |

Requires: arch-aarch64.lisp, ip.lisp (buf-read-u32), crypto.lisp (SHA-256), ssh.lisp (ssh-make-str, ssh-concat2).

### test-aarch64-handle-kex.lisp (4 tests, ~60s)

Full SSH key exchange chain with mock data.

| Test | What | Result |
|------|------|--------|
| sha256-abc | SHA-256("abc") = BA78... | PASS |
| ed25519-sign | Sign 0x42*32 with private=zeros → 9FD65CCE | PASS (~60s) |
| exchange-hash | ssh-compute-exchange-hash with fixed inputs → FD278F52 | PASS |
| exchange-hash-v2 | Same, verified against Python hashlib | PASS |

Uses full SSH source set: arch-aarch64 + e1000 + ip + crypto + crypto-fast + ssh + ssh-profile + aarch64-overrides.

### test-aarch64-ssh-packet.lisp (8 tests)

SSH packet framing, buffer management, and complete staged handshake.

| Test | What | Result |
|------|------|--------|
| make-parse-roundtrip | ssh-make-packet → ssh-parse-packet | PASS |
| buf-consume | ssh-buf-consume small buffer (6 bytes, consume 2) | PASS |
| buf-consume-large | ssh-buf-consume 100-byte buffer, verify byte[50] | PASS |
| receive-version | ssh-receive-version from mock recv buffer | PASS |
| packet-roundtrip | Make packet → copy to recv buffer → receive back | PASS |
| send-version | Capture tcp-send-conn from ssh-send-version | PASS |
| send-payload | Verify SSH packet framing (length, padding, type) | PASS |
| staged-handshake | **Full ssh-handle-connection** with mock receive() | PASS |

The staged handshake test feeds version string, KEXINIT, and KEX_ECDH_INIT through a mock `receive()` that copies from a staging buffer. The complete handshake succeeds: version exchange → kexinit → x25519 → exchange hash → Ed25519 sign → KEXDH_REPLY → NEWKEYS.

### ssh-kex-dump.py

Custom Python SSH client that performs the key exchange manually and dumps the raw KEXDH_REPLY bytes. Independently computes the exchange hash and verifies the Ed25519 signature. **This tool found the root cause** — the server ephemeral key was truncated (`...01000000` instead of `...09F8A209`).

```bash
# Boot the server, then:
python3 tests/ssh-kex-dump.py localhost 2222
```

## AArch64 SSH Bug — FIXED

**Symptom**: `ssh_dispatch_run_fatal: incorrect signature` — server ephemeral X25519 key truncated (last 4 bytes `01000000` instead of `09F8A209`).

**Root cause**: Memory address collision. `enable-gic-timer` in `net/arch-aarch64.lisp` wrote a timer-enabled flag to `(mem-ref #x41060700 :u32)`, which is `e1000-state-base + 0x700`. The ephemeral X25519 public key occupies `state+0x6E4..0x703` (32 bytes). Address `0x700` is bytes 28-31 of the key. Writing `1` there produced `01 00 00 00` in the last 4 bytes, overwriting the correct `09 F8 A2 09`.

**Fix**: Moved the timer flag from `state+0x700` to `state+0x704` (between ephemeral key end at 0x703 and host private key at 0x710).

**Found by**: `ssh-kex-dump.py` — independently computes exchange hash and verifies Ed25519 signature, showing exactly which bytes were wrong.

**Verified**: `echo '(+ 1 2)' | ssh -p 2222 test@localhost` returns `= 3`. `ssh-kex-dump.py` reports `SIGNATURE VALID`.
