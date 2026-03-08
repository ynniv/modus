#!/bin/bash
# Run RPi BCM2835 peripheral diagnostic in QEMU
# Mini UART output on serial1 (stdio), framebuffer on GTK display

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

# Build if needed
if [ ! -f /tmp/piboot/kernel8.img ] || [ "$1" = "--build" ]; then
    echo "Building..."
    sbcl --script mvm/build-rpi-periph.lisp || exit 1
fi

exec qemu-system-aarch64 -M raspi3b \
    -kernel /tmp/piboot/kernel8.img \
    -serial null -serial stdio \
    -display gtk
