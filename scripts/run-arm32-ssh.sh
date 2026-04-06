#!/bin/bash
# run-arm32-ssh.sh — Build and run ARM32 (ARMv7) SSH image in QEMU
#
# Usage:
#   ./scripts/run-arm32-ssh.sh [port] [expr]
#   ./scripts/run-arm32-ssh.sh 2222 "(+ 1 2)"   # batch test
#
# SSH: ssh -p 2222 test@localhost
# Ctrl-A X to quit QEMU

set -e
cd "$(dirname "$0")/.."

PORT=${1:-2222}
EXPR="${2:-}"
LOGFILE="/tmp/modus-arm32-ssh.log"
QEMU_PID=""

cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null
    fi
    exit 0
}
trap cleanup INT TERM

echo "Building ARM32 (ARMv7 raspi2b) SSH image..."
sbcl --script mvm/build-arm32-ssh.lisp
echo "Build OK"

pkill -9 -f 'qemu-system-arm.*modus-arm32-ssh' 2>/dev/null || true
sleep 0.5

> "$LOGFILE"
qemu-system-arm \
    -M raspi2b \
    -m 1G \
    -nographic \
    -kernel /tmp/modus-arm32-ssh.bin \
    -device usb-net,netdev=net0 \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:22" \
    > "$LOGFILE" 2>&1 &
QEMU_PID=$!

# Wait for SSH server to be ready
echo "Booting (DWC2 init + USB enum + crypto init)..."
TRIES=0
while [ $TRIES -lt 180 ]; do
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

if [ -n "$EXPR" ]; then
    sleep 5
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 -p "$PORT" test@localhost "$EXPR" 2>/dev/null || true
    cleanup
else
    echo ""
    echo "Modus ARM32 SSH server ready on port $PORT."
    echo "  ssh -p $PORT -o StrictHostKeyChecking=no test@localhost"
    echo ""
    echo "Press Ctrl-C to stop."

    wait "$QEMU_PID" 2>/dev/null
    QEMU_PID=""
fi
