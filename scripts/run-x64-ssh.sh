#!/bin/bash
# run-x64-ssh.sh — Build and run Modus64 SSH server
# The kernel reads -append "(progn ...)" via eval-cmdline to auto-start SSH
# Connect with: ssh -p $PORT -o StrictHostKeyChecking=no test@localhost

set -e
cd "$(dirname "$0")/.."

PORT=${1:-2222}
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

# Build kernel
echo "Building kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus64)' \
     --eval '(modus64.build:build-kernel-mvm "/tmp/modus64.elf")' \
     --eval '(quit)' > /dev/null 2>&1
echo "Build complete."

pkill -9 -f 'qemu.*modus64.elf' 2>/dev/null || true
sleep 0.5

# Start QEMU in background with output to log
> "$LOGFILE"
"$SCRIPTDIR/no-thp-exec" qemu-system-x86_64 \
    -kernel /tmp/modus64.elf -append "(progn (net-init-dhcp) (ssh-server 22))" -m 512 \
    -cpu qemu64 -smp 1 \
    -nographic \
    -device 'e1000,netdev=net0,romfile=,rombar=0' \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:22" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    > "$LOGFILE" 2>&1 &
QEMU_PID=$!

# Wait for SSH server to be ready (it prints "SSH:" when listening)
echo "Booting..."
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
echo "Modus64 SSH server ready on port $PORT."
echo "  ssh -p $PORT -o StrictHostKeyChecking=no test@localhost"
echo ""
echo "Press Ctrl-C to stop."

# Wait for QEMU to exit or Ctrl-C
wait "$QEMU_PID" 2>/dev/null
QEMU_PID=""
