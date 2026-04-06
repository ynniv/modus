#!/bin/bash
# run-i386-repl.sh — Build and run i386 REPL image in QEMU
#
# Usage:
#   ./scripts/run-i386-repl.sh              # interactive REPL
#   ./scripts/run-i386-repl.sh "(+ 1 2)"    # eval expression, print result, exit
#
# Ctrl-A X to quit QEMU (interactive mode)

set -e
cd "$(dirname "$0")/.."

BIN=/tmp/modus-i386.bin

if [ ! -f "$BIN" ] || [ mvm/build-i386-repl.lisp -nt "$BIN" ]; then
    echo "Building i386 REPL image..." >&2
    sbcl --script mvm/build-i386-repl.lisp >&2
fi

if [ -n "$1" ]; then
    exec "$(dirname "$0")/run-repl-eval.sh" i386 "$BIN" "$1"
fi

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
NO_THP=""
[ -x "$SCRIPTDIR/no-thp-exec" ] && NO_THP="$SCRIPTDIR/no-thp-exec"

exec $NO_THP qemu-system-i386 \
    -kernel "$BIN" \
    -m 256 \
    -display none \
    -serial stdio \
    -no-reboot
