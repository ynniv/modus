#!/bin/bash
# Test: RPi 3B QEMU — SSH server boots
TEST_NAME="rpi-ssh"
source "$(dirname "$0")/lib.sh"

TIMEOUT=180

echo "Building RPi SSH kernel..."
sbcl --script mvm/build-rpi-ssh.lisp > /dev/null 2>&1

boot_rpi /tmp/kernel8-ssh.img \
    -device usb-net,netdev=net0 \
    -netdev "user,id=net0"
wait_for "SSH:" 180
pass
