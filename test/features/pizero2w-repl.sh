#!/bin/bash
# Test: Pi Zero 2 W — Serial REPL (requires real hardware)
TEST_NAME="pizero2w-repl"
source "$(dirname "$0")/lib.sh"

PI_HOST=${PI_HOST:-10.0.0.2}

echo "Building Pi Zero 2 W SSH kernel..."
sbcl --script mvm/build-pizero2w-ssh.lisp > /dev/null 2>&1
[ -f /tmp/piboot/kernel8.img ] || fail "kernel not built"

echo "NOTE: Deploy kernel to Pi Zero 2 W and connect."
echo "  Expecting Pi at $PI_HOST (set PI_HOST to override)"

ssh -o ConnectTimeout=30 -o StrictHostKeyChecking=no \
    test@"$PI_HOST" "hello" > "$LOGFILE" 2>&1 || fail "cannot reach Pi at $PI_HOST"
pass
