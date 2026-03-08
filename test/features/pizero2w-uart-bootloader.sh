#!/bin/bash
# Test: Pi Zero 2 W — UART bootloader (requires real hardware + Pi 5 host)
TEST_NAME="pizero2w-uart-bootloader"
source "$(dirname "$0")/lib.sh"

echo "Building UART bootloader kernel..."
sbcl --script mvm/build-uart-bootloader.lisp > /dev/null 2>&1
[ -f /tmp/piboot/kernel8.img ] || fail "kernel not built"

echo "NOTE: UART bootloader test requires Pi 5 host with serial connection."
echo "  This test only verifies the build succeeds."
pass
