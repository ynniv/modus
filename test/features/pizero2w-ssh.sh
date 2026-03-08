#!/bin/bash
# Test: Pi Zero 2 W — SSH server responds to eval (requires real hardware)
TEST_NAME="pizero2w-ssh"
source "$(dirname "$0")/lib.sh"

PI_HOST=${PI_HOST:-10.0.0.2}

result=$(echo "(+ 1 2)" | ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null test@"$PI_HOST" 2>/dev/null) || fail "SSH failed"
echo "$result" | grep -q "3" || fail "expected 3, got '$result'"
pass
