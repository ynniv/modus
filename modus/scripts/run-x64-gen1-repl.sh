#!/bin/bash
# run-x64-gen1-repl.sh — Build and run self-hosted Modus64 Gen1 (serial REPL)
#
# Pipeline: SBCL cross-compiles Gen0, Gen0 natively compiles Gen1,
# Gen1 boots to interactive serial REPL.
# Caches Gen0/Gen1 and skips rebuilds when source files are unchanged.
#
# Usage:
#   ./run-x64-gen1-repl.sh             # boot Gen1 REPL
#   ./run-x64-gen1-repl.sh --rebuild   # force full rebuild
#
# Ctrl-A X to quit QEMU

set -e
cd "$(dirname "$0")/../.."

FORCE=0
for arg in "$@"; do
    case "$arg" in
        --rebuild) FORCE=1 ;;
    esac
done

QMP_PORT=4444
GEN0="/tmp/modus64-gen0.elf"
GEN1="/tmp/modus64-gen1.elf"
GEN0_HASH="/tmp/modus64-gen0.hash"
GEN1_HASH="/tmp/modus64-gen1.hash"
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"

# Compute a content hash of all source files that affect the build
source_hash() {
    cat lib/modus64/cross/packages.lisp \
        lib/modus64/cross/x64-asm.lisp \
        lib/modus64/cross/cross-compile.lisp \
        lib/modus64/cross/build.lisp \
        lib/modus64/mvm/mvm.lisp \
        lib/modus64/mvm/compiler.lisp \
        lib/modus64/mvm/translate-x64.lisp \
    | sha256sum | cut -d' ' -f1
}

SRCHASH=$(source_hash)

# Step 1: Cross-compile Gen0 (skip if cached)
if [ "$FORCE" -eq 0 ] && [ -f "$GEN0" ] && [ -f "$GEN0_HASH" ] && [ "$(cat "$GEN0_HASH")" = "$SRCHASH" ]; then
    echo "Step 1/3: Gen0 cached ($(stat -c%s "$GEN0") bytes)"
else
    echo "Step 1/3: Cross-compiling Gen0..."
    sbcl --control-stack-size 64 \
         --eval '(push (truename "lib/modus64/") asdf:*central-registry*)' \
         --eval '(asdf:load-system :modus64)' \
         --eval "(modus64.build:build-kernel-mvm \"$GEN0\")" \
         --eval '(quit)' > /dev/null 2>&1
    echo "$SRCHASH" > "$GEN0_HASH"
    # Invalidate Gen1 cache since Gen0 changed
    rm -f "$GEN1_HASH"
    echo "  Gen0: $(stat -c%s "$GEN0") bytes"
fi

# Step 2: Self-host Gen1 from Gen0 (skip if cached)
if [ "$FORCE" -eq 0 ] && [ -f "$GEN1" ] && [ -f "$GEN1_HASH" ] && [ "$(cat "$GEN1_HASH")" = "$SRCHASH" ]; then
    echo "Step 2/3: Gen1 cached ($(stat -c%s "$GEN1") bytes)"
else
    echo "Step 2/3: Self-hosting Gen1 from Gen0..."
    python3 "$SCRIPTDIR/self-host-gen1.py" "$GEN0" "$GEN1" "$QMP_PORT"

    if [ ! -f "$GEN1" ]; then
        echo "FAIL: Gen1 not produced."
        exit 1
    fi
    echo "$SRCHASH" > "$GEN1_HASH"
    echo "  Gen1: $(stat -c%s "$GEN1") bytes"
fi

# Step 3: Boot Gen1 (serial REPL)
echo "Step 3/3: Booting self-hosted kernel (REPL)..."
exec "$SCRIPTDIR/no-thp-exec" qemu-system-x86_64 \
    -kernel "$GEN1" -m 512 \
    -cpu qemu64 -smp 1 \
    -nographic
