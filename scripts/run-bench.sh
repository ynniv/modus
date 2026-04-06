#!/bin/bash
# Run Modus micro-benchmarks on all supported architectures
# Usage: ./scripts/run-bench.sh [x64] [i386] [arm32] [aarch64]
# Default: all working targets (x64 i386 arm32)

set -e
cd "$(dirname "$0")/.."

TARGETS="${@:-x64 i386 arm32 aarch64}"
TIMEOUT=120

echo "=== Modus Micro-Benchmarks ==="
echo ""

for target in $TARGETS; do
    echo "--- Building $target ---"
    sbcl --script mvm/build-bench.lisp "$target" 2>&1 | grep -E 'Wrote|error' || true
done

echo ""
echo "=== Running Benchmarks ==="
echo ""

for target in $TARGETS; do
    BIN="/tmp/modus-bench-${target}.bin"
    if [ ! -f "$BIN" ]; then
        echo "[$target] SKIP (no binary)"
        continue
    fi

    echo "--- $target ---"
    START=$(date +%s%N)

    case "$target" in
        x64)
            timeout $TIMEOUT qemu-system-x86_64 -m 512 -display none \
                -serial stdio -no-reboot -kernel "$BIN" 2>/dev/null || true
            ;;
        i386)
            timeout $TIMEOUT qemu-system-i386 -m 256 -display none \
                -serial stdio -no-reboot -kernel "$BIN" 2>/dev/null || true
            ;;
        arm32)
            timeout $TIMEOUT qemu-system-arm -M raspi2b -m 1G -display none \
                -serial stdio -monitor none -kernel "$BIN" 2>/dev/null || true
            ;;
        aarch64)
            timeout $TIMEOUT qemu-system-aarch64 -machine virt -cpu cortex-a57 \
                -m 512 -display none -serial stdio -semihosting \
                -kernel "$BIN" 2>/dev/null || true
            ;;
    esac

    END=$(date +%s%N)
    ELAPSED=$(( (END - START) / 1000000 ))
    echo "  wall: ${ELAPSED}ms"
    echo ""
done
