#!/bin/bash
# Test: Pi Zero 2 W — Actor system, multiple SSH connections (requires real hardware)
TEST_NAME="pizero2w-actors"
source "$(dirname "$0")/lib.sh"

PI_HOST=${PI_HOST:-10.0.0.2}
SSH_OPTS="-o ConnectTimeout=30 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

r1=$(echo "(+ 1 1)" | ssh $SSH_OPTS test@"$PI_HOST" 2>/dev/null) || fail "SSH conn 1 failed"
r2=$(echo "(+ 2 2)" | ssh $SSH_OPTS test@"$PI_HOST" 2>/dev/null) || fail "SSH conn 2 failed"
echo "$r1" | grep -q "2" || fail "conn 1: expected 2, got '$r1'"
echo "$r2" | grep -q "4" || fail "conn 2: expected 4, got '$r2'"
pass
