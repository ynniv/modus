#!/bin/bash
# run-rpi-hid.sh — Build and run RPi HID REPL in QEMU (raspi3b + USB keyboard)
# USB keyboard drives the REPL; serial console shows output.
# Add -device usb-mouse or -device usb-tablet for mouse/tablet support.

set -e
cd "$(dirname "$0")/../.."

LOGFILE="/tmp/modus64-rpi-hid.log"
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
echo "Building RPi HID kernel (DWC2 USB + Keyboard)..."
sbcl --script lib/modus64/mvm/build-rpi-hid.lisp
echo "Build complete."

pkill -9 -f 'qemu-system-aarch64.*kernel8-hid' 2>/dev/null || true
sleep 0.5

# Start QEMU raspi3b with USB keyboard
# -serial stdio routes serial output to terminal
# -device usb-kbd creates a USB HID keyboard
# With -display none, QEMU routes terminal stdin to the USB keyboard
qemu-system-aarch64 \
    -machine raspi3b \
    -kernel /tmp/kernel8-hid.img \
    -display none \
    -serial stdio \
    -device usb-kbd \
    2>"$LOGFILE"
