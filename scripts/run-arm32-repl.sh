#!/bin/bash
# run-arm32-repl.sh — Build and run ARM32 (ARMv7) REPL image in QEMU
#
# Usage:
#   ./scripts/run-arm32-repl.sh              # interactive REPL
#   ./scripts/run-arm32-repl.sh "(+ 1 2)"    # eval expression, print result, exit
#
# Ctrl-A X to quit QEMU (interactive mode)

set -e
cd "$(dirname "$0")/.."

BIN=/tmp/modus-arm32.bin

if [ ! -f "$BIN" ] || [ mvm/build-arm32-repl.lisp -nt "$BIN" ]; then
    echo "Building ARM32 (ARMv7) REPL image..." >&2
    sbcl --script mvm/build-arm32-repl.lisp >&2
fi

if [ -n "$1" ]; then
    exec "$(dirname "$0")/run-repl-eval.sh" arm32 "$BIN" "$1"
fi

exec qemu-system-arm \
    -M virt,highmem=off \
    -cpu cortex-a15 \
    -m 256 \
    -kernel "$BIN" \
    -nographic
