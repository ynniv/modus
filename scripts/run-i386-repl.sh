#!/bin/bash
# run-i386-repl.sh — Build and run i386 REPL image in QEMU
#
# Usage:
#   ./scripts/run-i386-repl.sh
#
# Ctrl-A X to quit QEMU

set -e
cd "$(dirname "$0")/.."

echo "Building i386 REPL image..."
sbcl --script mvm/build-i386-repl.lisp
echo "Build OK"

exec qemu-system-i386 \
    -kernel /tmp/modus64-i386.bin \
    -m 256 \
    -display none \
    -serial stdio \
    -no-reboot
