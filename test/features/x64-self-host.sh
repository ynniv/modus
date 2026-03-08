#!/bin/bash
# Test: x86-64 QEMU — Self-hosting via cross-architecture fixpoint
# Proves: Gen0(x64) → Gen1(aarch64) → Gen2(x64) → Gen3(aarch64), Gen1 == Gen3
TEST_NAME="x64-self-host"
source "$(dirname "$0")/lib.sh"

TIMEOUT=600

echo "Running cross-architecture fixpoint..."
scripts/run-fixpoint.sh > "$LOGFILE" 2>&1 || fail "fixpoint script failed"

grep -q "PASS" "$LOGFILE" || fail "fixpoint did not pass"
pass
