#!/bin/bash
# Test: Pi Zero 2 W — USB CDC-ECM networking (requires real hardware)
TEST_NAME="pizero2w-usb-cdc"
source "$(dirname "$0")/lib.sh"

PI_HOST=${PI_HOST:-10.0.0.2}

echo "Checking USB CDC-ECM connectivity to $PI_HOST..."
ping -c 1 -W 5 "$PI_HOST" > /dev/null 2>&1 || fail "cannot ping $PI_HOST"
pass
