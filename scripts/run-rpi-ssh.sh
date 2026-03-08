#!/bin/bash
# run-rpi-ssh.sh — Build and run RPi SSH server in QEMU (raspi3b + DWC2 USB + CDC Ethernet)
# Connect with: ssh -p $PORT -o StrictHostKeyChecking=no test@localhost

set -e
cd "$(dirname "$0")/.."

PORT=${1:-2222}
LOGFILE="/tmp/modus64-rpi-ssh.log"
QEMU_PID=""

cleanup() {
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null
    fi
    exit 0
}
trap cleanup INT TERM

# Build kernel
echo "Building RPi SSH kernel (DWC2 USB + CDC Ethernet)..."
sbcl --script mvm/build-rpi-ssh.lisp
echo "Build complete."

pkill -9 -f 'qemu-system-aarch64.*kernel8-ssh' 2>/dev/null || true
sleep 0.5

# Start QEMU raspi3b with USB networking
> "$LOGFILE"
qemu-system-aarch64 \
    -machine raspi3b \
    -kernel /tmp/kernel8-ssh.img \
    -display none \
    -serial stdio \
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

echo ""
echo "Modus64 RPi SSH server ready on port $PORT."
echo "  ssh -p $PORT -o StrictHostKeyChecking=no test@localhost"
echo ""
echo "Press Ctrl-C to stop."

# Wait for QEMU to exit or Ctrl-C
wait "$QEMU_PID" 2>/dev/null
QEMU_PID=""
