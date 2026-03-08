#!/bin/bash
# Test: RPi 3B QEMU — USB HID keyboard boots
TEST_NAME="rpi-hid"
source "$(dirname "$0")/lib.sh"

TIMEOUT=120

echo "Building RPi HID kernel..."
sbcl --script mvm/build-rpi-hid.lisp > /dev/null 2>&1

boot_rpi /tmp/kernel8-hid.img -device usb-kbd
wait_for ">" 120
pass
