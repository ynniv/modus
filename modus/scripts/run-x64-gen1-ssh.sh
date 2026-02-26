#!/bin/bash
# run-x64-gen1-ssh.sh — Build and run self-hosted Modus64 Gen1 (SSH server)
#
# Pipeline: SBCL cross-compiles Gen0, Gen0 natively compiles Gen1,
# Gen1 boots with networking + SSH.
# Caches Gen0/Gen1 and skips rebuilds when source files are unchanged.
#
# Usage:
#   ./run-x64-gen1-ssh.sh [PORT]             # SSH mode (default port 2222)
#   ./run-x64-gen1-ssh.sh [PORT] --rebuild   # force full rebuild
#
# Connect with: ssh -p $PORT -o StrictHostKeyChecking=no test@localhost

set -e
cd "$(dirname "$0")/../.."

PORT=2222
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --rebuild) FORCE=1 ;;
        *)         PORT="$arg" ;;
    esac
done

QMP_PORT=4444
GEN0="/tmp/modus64-gen0.elf"
GEN1="/tmp/modus64-gen1.elf"
GEN0_HASH="/tmp/modus64-gen0.hash"
GEN1_HASH="/tmp/modus64-gen1.hash"
LOGFILE="/tmp/modus64-ssh.log"
SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
QEMU_PID=""

cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null
    fi
    exit 0
}
trap cleanup INT TERM

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

# Step 3: Boot Gen1 with SSH
echo "Step 3/3: Booting self-hosted kernel with SSH..."
> "$LOGFILE"
"$SCRIPTDIR/no-thp-exec" qemu-system-x86_64 \
    -kernel "$GEN1" -append "(progn (net-init-dhcp) (ed25519-init) (ssh-server 22))" -m 512 \
    -cpu qemu64 -smp 1 \
    -nographic \
    -device 'e1000,netdev=net0,romfile=,rombar=0' \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:22" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    > "$LOGFILE" 2>&1 &
QEMU_PID=$!

# Wait for SSH server
echo "  Waiting for SSH..."
TRIES=0
while [ $TRIES -lt 120 ]; do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "QEMU exited unexpectedly. Log:"
        cat "$LOGFILE"
        exit 1
    fi
    if grep -q "SSH:" "$LOGFILE" 2>/dev/null; then
        break
    fi
    sleep 0.5
    TRIES=$((TRIES + 1))
done

if ! grep -q "SSH:" "$LOGFILE" 2>/dev/null; then
    echo "Timed out waiting for SSH server. Log:"
    cat "$LOGFILE"
    cleanup
    exit 1
fi

echo ""
echo "Self-hosted Modus64 SSH server ready on port $PORT."
echo "  ssh -p $PORT -o StrictHostKeyChecking=no test@localhost"
echo ""
echo "Press Ctrl-C to stop."

wait "$QEMU_PID" 2>/dev/null
QEMU_PID=""
