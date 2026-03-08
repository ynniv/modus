#!/bin/bash
# Test: Pi Zero 2 W — GPU framebuffer (requires real hardware + HDMI)
TEST_NAME="pizero2w-gpu"
source "$(dirname "$0")/lib.sh"

echo "Building Pi Zero 2 W HDMI kernel..."
sbcl --script mvm/build-pizero2w-hdmi.lisp > /dev/null 2>&1
[ -f /tmp/piboot/kernel8.img ] || fail "kernel not built"

echo "NOTE: Deploy kernel and verify HDMI output visually."
echo "  This test only verifies the build succeeds."
pass
