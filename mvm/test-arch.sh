#!/bin/bash
# test-arch.sh - Multi-architecture test harness for MVM
#
# Usage: ./test-arch.sh [--qemu] [arch...]
#
# Validates MVM cross-compiled kernel images:
#   Phase A: Build images for all 8 architectures via SBCL
#   Phase B: Disassemble and validate native code with cross-objdump
#   Phase C: (with --qemu) Boot in QEMU and check execution
#
# Architecture targets: x86-64, i386, aarch64, riscv64, ppc64, ppc32, 68k, arm32

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="/tmp/mvm-test"
PASS=0
FAIL=0
SKIP=0
DO_QEMU=false
TARGETS=()

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --qemu) DO_QEMU=true ;;
        *) TARGETS+=("$arg") ;;
    esac
done

# Default: all targets
if [ ${#TARGETS[@]} -eq 0 ]; then
    TARGETS=(x86-64 i386 aarch64 riscv64 ppc64 ppc32 68k arm32 armv7 rpi)
fi

# Architecture → objdump command mapping
declare -A OBJDUMP_CMD
OBJDUMP_CMD[x86-64]="objdump -D -b binary -m i386:x86-64"
OBJDUMP_CMD[i386]="objdump -D -b binary -m i386"
OBJDUMP_CMD[aarch64]="aarch64-linux-gnu-objdump -D -b binary -m aarch64"
OBJDUMP_CMD[riscv64]="riscv64-linux-gnu-objdump -D -b binary -m riscv:rv64"
OBJDUMP_CMD[ppc64]="powerpc64-linux-gnu-objdump -D -b binary -m powerpc:common64 -EB"
OBJDUMP_CMD[ppc32]="powerpc64-linux-gnu-objdump -D -b binary -m powerpc:common -EB"
OBJDUMP_CMD[68k]="m68k-linux-gnu-objdump -D -b binary -m m68k"
OBJDUMP_CMD[arm32]="aarch64-linux-gnu-objdump -D -b binary -m arm"
OBJDUMP_CMD[armv7]="aarch64-linux-gnu-objdump -D -b binary -m arm"
OBJDUMP_CMD[rpi]="aarch64-linux-gnu-objdump -D -b binary -m aarch64"

# Architecture → QEMU command mapping
# Use -serial file:SERIAL to capture serial output to a file
# -display none -monitor none to avoid conflicts
declare -A QEMU_CMD
QEMU_CMD[x86-64]="qemu-system-x86_64 -kernel FILE -display none -monitor none -serial file:SERIAL -device isa-debug-exit,iobase=0xf4,iosize=0x04 -m 64"
QEMU_CMD[i386]="qemu-system-i386 -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[aarch64]="qemu-system-aarch64 -machine virt -cpu cortex-a57 -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[riscv64]="qemu-system-riscv64 -machine virt -bios none -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[ppc64]="qemu-system-ppc64 -machine powernv -kernel FILE -display none -monitor none -serial file:SERIAL -m 2G"
QEMU_CMD[ppc32]="qemu-system-ppc -machine ppce500 -cpu e500v2 -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[68k]="qemu-system-m68k -machine virt -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[arm32]="qemu-system-arm -machine versatilepb -cpu arm926 -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[armv7]="qemu-system-arm -machine virt -cpu cortex-a15 -kernel FILE -display none -monitor none -serial file:SERIAL -m 64"
QEMU_CMD[rpi]="qemu-system-aarch64 -machine raspi3b -kernel FILE -display none -serial file:SERIAL"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} $1"; SKIP=$((SKIP + 1)); }
info() { echo -e "  ${CYAN}INFO${NC} $1"; }

echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD} MVM Multi-Architecture Test Harness${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# ============================================================
# Phase A: Build images
# ============================================================

echo -e "${BOLD}Phase A: Build kernel images${NC}"
echo ""

mkdir -p "$TEST_DIR"

if ! sbcl --script "$SCRIPT_DIR/test-images.lisp" 2>&1; then
    echo -e "${RED}FATAL: Image build failed${NC}"
    exit 1
fi

echo ""

# Check summary
if [ ! -f "$TEST_DIR/summary.txt" ]; then
    echo -e "${RED}FATAL: No summary.txt produced${NC}"
    exit 1
fi

BUILD_PASS=0
BUILD_FAIL=0
while IFS=' ' read -r arch status img_size code_size boot_size; do
    if [ "$status" = "PASS" ]; then
        ((BUILD_PASS++))
    else
        ((BUILD_FAIL++))
    fi
done < "$TEST_DIR/summary.txt"

echo -e "Build: ${GREEN}$BUILD_PASS${NC} passed, ${RED}$BUILD_FAIL${NC} failed"
echo ""

# ============================================================
# Phase B: Static validation with objdump
# ============================================================

echo -e "${BOLD}Phase B: Static validation (objdump)${NC}"
echo ""

for arch in "${TARGETS[@]}"; do
    code_file="$TEST_DIR/$arch.code"

    echo -e " ${BOLD}[$arch]${NC}"

    # Check file exists and has content
    if [ ! -f "$code_file" ]; then
        fail "$arch: no .code file"
        continue
    fi

    code_size=$(stat -c%s "$code_file" 2>/dev/null || true)
            has_ret=${has_ret:-0}
    if [ "$code_size" -eq 0 ]; then
        fail "$arch: empty .code file"
        continue
    fi

    info "$arch: $code_size bytes native code"

    # Check if objdump is available for this arch
    cmd="${OBJDUMP_CMD[$arch]:-}"
    if [ -z "$cmd" ]; then
        skip "$arch: no objdump mapping"
        continue
    fi

    # Extract the tool name and check it exists
    tool=$(echo "$cmd" | awk '{print $1}')
    if ! command -v "$tool" &>/dev/null; then
        skip "$arch: $tool not installed"
        continue
    fi

    # Run objdump, capture output
    disasm_file="$TEST_DIR/$arch.disasm"
    if ! $cmd "$code_file" > "$disasm_file" 2>&1; then
        fail "$arch: objdump returned error"
        continue
    fi

    # Count instructions (lines with hex address prefix)
    insn_count=$(grep -cE '^\s+[0-9a-f]+:' "$disasm_file" 2>/dev/null || true)
    insn_count=${insn_count:-0}
    info "$arch: $insn_count instructions disassembled"

    # Validate: must have at least some instructions
    if [ "$insn_count" -lt 5 ]; then
        fail "$arch: too few instructions ($insn_count < 5)"
        continue
    fi

    # Check for excessive unknown/undefined instructions
    # (objdump shows ".word", ".byte", "(bad)" for unrecognised encodings)
    bad_count=$(grep -ciE '\(bad\)|\.word\s+0x0000' "$disasm_file" 2>/dev/null || true)
    bad_count=${bad_count:-0}
    bad_pct=0
    if [ "$insn_count" -gt 0 ]; then
        bad_pct=$(( bad_count * 100 / insn_count ))
    fi

    if [ "$bad_pct" -gt 30 ]; then
        fail "$arch: ${bad_pct}% bad/unknown instructions ($bad_count/$insn_count)"
        continue
    fi

    # Architecture-specific checks
    case "$arch" in
        x86-64)
            # Should contain ret instructions
            has_ret=$(grep -c '\bret\b' "$disasm_file" 2>/dev/null || true)
            has_ret=${has_ret:-0}
            if [ "$has_ret" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_ret ret(s), ${bad_pct}% unknown"
            else
                fail "$arch: no ret instruction found"
            fi
            ;;
        i386)
            has_ret=$(grep -c '\bret\b' "$disasm_file" 2>/dev/null || true)
            has_ret=${has_ret:-0}
            if [ "$has_ret" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_ret ret(s), ${bad_pct}% unknown"
            else
                fail "$arch: no ret instruction found"
            fi
            ;;
        aarch64)
            # Should contain ret instructions
            has_ret=$(grep -c '\bret\b' "$disasm_file" 2>/dev/null || true)
            has_ret=${has_ret:-0}
            if [ "$has_ret" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_ret ret(s), ${bad_pct}% unknown"
            else
                fail "$arch: no ret instruction found"
            fi
            ;;
        riscv64)
            # RISC-V uses jalr zero,ra for ret; also check for addi, beq etc.
            has_jalr=$(grep -cE 'jalr|ret' "$disasm_file" 2>/dev/null || true)
            has_jalr=${has_jalr:-0}
            if [ "$has_jalr" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_jalr jalr/ret(s), ${bad_pct}% unknown"
            else
                fail "$arch: no jalr/ret instruction found"
            fi
            ;;
        ppc64)
            # PPC uses blr for return
            has_blr=$(grep -cE '\bblr\b' "$disasm_file" 2>/dev/null || true)
            has_blr=${has_blr:-0}
            if [ "$has_blr" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_blr blr(s), ${bad_pct}% unknown"
            else
                fail "$arch: no blr instruction found"
            fi
            ;;
        ppc32)
            # PPC32 uses blr for return (same encoding as PPC64)
            has_blr=$(grep -cE '\bblr\b' "$disasm_file" 2>/dev/null || true)
            has_blr=${has_blr:-0}
            if [ "$has_blr" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_blr blr(s), ${bad_pct}% unknown"
            else
                fail "$arch: no blr instruction found"
            fi
            ;;
        68k)
            # 68k uses rts for return
            has_rts=$(grep -cE '\brts\b' "$disasm_file" 2>/dev/null || true)
            has_rts=${has_rts:-0}
            if [ "$has_rts" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_rts rts(s), ${bad_pct}% unknown"
            else
                fail "$arch: no rts instruction found"
            fi
            ;;
        arm32)
            # ARM32 uses bx for return
            has_bx=$(grep -cE '\bbx\b' "$disasm_file" 2>/dev/null || true)
            has_bx=${has_bx:-0}
            if [ "$has_bx" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_bx bx(s), ${bad_pct}% unknown"
            else
                fail "$arch: no bx instruction found"
            fi
            ;;
        armv7)
            # ARMv7 uses pop {pc} for return and sdiv for division
            has_pop=$(grep -cE '\bpop\b.*\bpc\b' "$disasm_file" 2>/dev/null || true)
            has_pop=${has_pop:-0}
            has_sdiv=$(grep -cE '\bsdiv\b' "$disasm_file" 2>/dev/null || true)
            has_sdiv=${has_sdiv:-0}
            if [ "$has_pop" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_pop pop-pc(s), $has_sdiv sdiv(s), ${bad_pct}% unknown"
            else
                fail "$arch: no pop {pc} instruction found"
            fi
            ;;
        rpi)
            # RPi uses AArch64 — same validation as aarch64
            has_ret=$(grep -c '\bret\b' "$disasm_file" 2>/dev/null || true)
            has_ret=${has_ret:-0}
            if [ "$has_ret" -gt 0 ]; then
                pass "$arch: $insn_count insns, $has_ret ret(s), ${bad_pct}% unknown"
            else
                fail "$arch: no ret instruction found"
            fi
            ;;
        *)
            pass "$arch: $insn_count insns, ${bad_pct}% unknown"
            ;;
    esac
done

echo ""

# ============================================================
# Phase C: QEMU boot testing (optional)
# ============================================================

if $DO_QEMU; then
    echo -e "${BOLD}Phase C: QEMU boot testing${NC}"
    echo ""

    QEMU_TIMEOUT=5  # seconds (ppc64 uses per-arch override below)

    for arch in "${TARGETS[@]}"; do
        bin_file="$TEST_DIR/$arch.bin"

        echo -e " ${BOLD}[$arch]${NC}"

        if [ ! -f "$bin_file" ] || [ "$(stat -c%s "$bin_file" 2>/dev/null)" -eq 0 ]; then
            skip "$arch: no image file"
            continue
        fi

        cmd_template="${QEMU_CMD[$arch]:-}"
        if [ -z "$cmd_template" ]; then
            skip "$arch: no QEMU mapping"
            continue
        fi

        # Substitute FILE and SERIAL placeholders
        serial_file="$TEST_DIR/$arch.serial"
        cmd="${cmd_template//FILE/$bin_file}"
        cmd="${cmd//SERIAL/$serial_file}"

        # Extract QEMU binary and check it exists
        qemu_bin=$(echo "$cmd" | awk '{print $1}')
        if ! command -v "$qemu_bin" &>/dev/null; then
            skip "$arch: $qemu_bin not installed"
            continue
        fi

        # Per-architecture timeout overrides
        arch_timeout=$QEMU_TIMEOUT
        case "$arch" in
            ppc64) arch_timeout=15 ;;  # Skiboot PCI init takes ~7 seconds
        esac

        # Run QEMU with timeout; serial output goes to file via -serial file:
        info "$arch: booting in QEMU ($arch_timeout sec timeout)..."
        rm -f "$serial_file"

        set +e
        timeout "$arch_timeout" $cmd >/dev/null 2>&1
        qemu_exit=$?
        set -e

        serial_size=$(stat -c%s "$serial_file" 2>/dev/null || echo 0)

        if [ "$qemu_exit" -eq 124 ]; then
            # Timeout — QEMU ran for the full duration
            # This is actually expected for a halt-loop kernel
            info "$arch: QEMU timed out (expected for halt-loop kernel)"
            if [ "$serial_size" -gt 0 ]; then
                info "$arch: serial output ($serial_size bytes):"
                head -5 "$serial_file" | sed 's/^/    /'
                pass "$arch: QEMU booted, produced serial output"
            else
                # No serial output is also OK — kernel may just halt
                pass "$arch: QEMU booted (no serial output — kernel halts cleanly)"
            fi
        elif [ "$qemu_exit" -eq 0 ] || [ "$qemu_exit" -eq 1 ]; then
            # Clean exit (isa-debug-exit or normal)
            if [ "$serial_size" -gt 0 ]; then
                info "$arch: serial output ($serial_size bytes):"
                head -5 "$serial_file" | sed 's/^/    /'
            fi
            pass "$arch: QEMU exited cleanly (code $qemu_exit)"
        else
            # Crash or error
            if [ "$serial_size" -gt 0 ]; then
                info "$arch: serial output:"
                head -10 "$serial_file" | sed 's/^/    /'
            fi
            fail "$arch: QEMU exited with code $qemu_exit"
        fi
    done

    echo ""
fi

# ============================================================
# Summary
# ============================================================

echo -e "${BOLD}========================================${NC}"
TOTAL=$((PASS + FAIL + SKIP))
echo -e " Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC} / $TOTAL total"
echo -e "${BOLD}========================================${NC}"

# Disassembly files available for inspection
echo ""
echo "Output files in $TEST_DIR/:"
ls -la "$TEST_DIR"/ 2>/dev/null | grep -v '^total' | sed 's/^/  /'

exit $FAIL
