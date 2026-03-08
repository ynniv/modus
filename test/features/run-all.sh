#!/bin/bash
# run-all.sh - Run feature tests
#
# Usage:
#   ./test/features/run-all.sh              # QEMU tests only
#   ./test/features/run-all.sh --hardware   # include Pi Zero 2 W tests
#   ./test/features/run-all.sh --self-host  # include self-hosting tests
#   ./test/features/run-all.sh x64          # only x64 tests
#   ./test/features/run-all.sh rpi          # only RPi 3B tests
#   ./test/features/run-all.sh x64-repl     # single test

set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

HARDWARE=false
SELF_HOST=false
FILTER=""

for arg in "$@"; do
    case "$arg" in
        --hardware) HARDWARE=true ;;
        --self-host) SELF_HOST=true ;;
        *) FILTER="$arg" ;;
    esac
done

PASS=0
FAIL=0
SKIP=0

run_test() {
    local test="$1"
    local name=$(basename "$test" .sh)

    # Skip hardware tests unless --hardware
    if [[ "$name" == pizero2w-* ]] && [ "$HARDWARE" = false ]; then
        echo "SKIP: $name (hardware)"
        SKIP=$((SKIP + 1))
        return
    fi

    # Skip self-host tests unless --self-host (long-running, ~10min each)
    if [[ "$name" == *-self-host ]] && [ "$SELF_HOST" = false ]; then
        echo "SKIP: $name (self-host)"
        SKIP=$((SKIP + 1))
        return
    fi

    echo "--- $name ---"
    if bash "$test"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Collect tests
tests=()
for f in "$SCRIPT_DIR"/*.sh; do
    name=$(basename "$f" .sh)
    [ "$name" = "run-all" ] && continue
    [ "$name" = "lib" ] && continue

    if [ -n "$FILTER" ]; then
        [[ "$name" == ${FILTER}* ]] || continue
    fi

    tests+=("$f")
done

echo "=== Modus Feature Tests ==="
echo ""

for t in "${tests[@]}"; do
    run_test "$t"
done

echo "=== Results ==="
echo "  Pass: $PASS  Fail: $FAIL  Skip: $SKIP"

[ "$FAIL" -eq 0 ]
