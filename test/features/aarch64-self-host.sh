#!/bin/bash
# Test: AArch64 QEMU virt — Self-hosting (cross-arch fixpoint)
TEST_NAME="aarch64-self-host"
source "$(dirname "$0")/lib.sh"

TIMEOUT=300

echo "Running cross-architecture fixpoint (x64 -> aarch64 -> x64)..."
scripts/run-fixpoint.sh > "$LOGFILE" 2>&1 || fail "fixpoint script failed"

grep -q "PASS" "$LOGFILE" || fail "fixpoint did not pass"
pass
