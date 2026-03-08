#!/bin/bash
# run-aarch64-repl.sh — Build and run AArch64 REPL image in QEMU (virt)
#
# Usage:
#   ./run-aarch64-repl.sh
#
# Ctrl-A X to quit QEMU

set -e
cd "$(dirname "$0")/.."

echo "Building AArch64 REPL image..."
sbcl --script mvm/build-aarch64-repl.lisp
echo "Build OK"

exec qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a57 \
    -m 512 \
    -kernel /tmp/modus64-aarch64.bin \
    -nographic \
    -semihosting
