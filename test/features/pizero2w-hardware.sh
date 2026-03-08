#!/bin/bash
# Test: Pi Zero 2 W — Real hardware boot (requires Pi Zero 2 W)
TEST_NAME="pizero2w-hardware"
source "$(dirname "$0")/lib.sh"

PI_HOST=${PI_HOST:-10.0.0.2}

echo "Checking Pi Zero 2 W is reachable at $PI_HOST..."
ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    test@"$PI_HOST" "(+ 0 1)" > "$LOGFILE" 2>&1 || fail "cannot reach Pi at $PI_HOST"
grep -q "1" "$LOGFILE" || fail "Pi not responding correctly"
pass
