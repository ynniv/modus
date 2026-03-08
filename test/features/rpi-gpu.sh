#!/bin/bash
# Test: RPi 3B QEMU — GPU framebuffer initializes
TEST_NAME="rpi-gpu"
source "$(dirname "$0")/lib.sh"

TIMEOUT=120

echo "Building RPi peripherals kernel..."
sbcl --script mvm/build-rpi-periph.lisp > /dev/null 2>&1

# Periph kernel uses mini UART (serial1), not PL011 (serial0)
> "$LOGFILE"
qemu-system-aarch64 -machine raspi3b \
    -kernel /tmp/piboot/kernel8.img -display none \
    -serial null -serial stdio \
    > "$LOGFILE" 2>&1 &
QEMU_PID=$!
wait_for "DONE" 120
pass
