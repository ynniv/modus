#!/bin/bash
# run-x64-console-repl.sh — Build and run Modus x64 console REPL (VGA + PS/2 keyboard)
#
# Usage:
#   ./scripts/run-x64-console-repl.sh              # interactive REPL
#   ./scripts/run-x64-console-repl.sh "(+ 1 2)"    # eval expression, print result, exit
#
# Ctrl-A X to quit QEMU (interactive mode)
#
# VGA text mode output (80x25) + PS/2 keyboard input + serial I/O.
# For GRUB boot on real hardware, see: ./scripts/make-grub-usb.sh

set -e
cd "$(dirname "$0")/.."

BIN=/tmp/modus-x64-console.bin
TIMEOUT=${REPL_TIMEOUT:-60}

# Build if needed (check all source files)
NEED_BUILD=0
if [ ! -f "$BIN" ]; then NEED_BUILD=1; fi
for src in mvm/build-x64-console-repl.lisp mvm/repl-source.lisp net/uefi-console.lisp \
           boot/boot-x64.lisp boot/boot-uefi-x64.lisp mvm/compiler.lisp mvm/translate-x64.lisp; do
    [ -f "$src" ] && [ "$src" -nt "$BIN" ] && NEED_BUILD=1
done
if [ "$NEED_BUILD" = 1 ]; then
    echo "Building x64 console REPL..." >&2
    sbcl --script mvm/build-x64-console-repl.lisp >&2
fi

# Batch mode: eval expression and print result
if [ -n "$1" ]; then
    FIFO=$(mktemp -u /tmp/modus-fifo.XXXXXX)
    OUT=$(mktemp /tmp/modus-eval.XXXXXX)
    mkfifo "$FIFO"
    trap 'rm -f "$OUT" "$FIFO"; kill $QPID 2>/dev/null; wait $QPID 2>/dev/null' EXIT

    timeout "$TIMEOUT" qemu-system-x86_64 \
        -kernel "$BIN" -m 512 -nographic -no-reboot < "$FIFO" > "$OUT" 2>/dev/null &
    QPID=$!
    exec 3>"$FIFO"

    for i in $(seq 1 300); do
        kill -0 $QPID 2>/dev/null || { echo "QEMU died" >&2; exit 1; }
        if tail -1 "$OUT" 2>/dev/null | grep -q '^> $'; then break; fi
        sleep 0.1
    done
    if ! tail -1 "$OUT" 2>/dev/null | grep -q '^> $'; then
        echo "Timeout waiting for prompt" >&2; exit 1
    fi

    sleep 0.3
    printf '%s\n' "$1" >&3
    sleep 1
    exec 3>&-
    sleep 0.5

    tr -d '\r' < "$OUT" | sed -n '/^> .*[^ ]/{n; /^>/!{/^$/!p;};}' | head -1
    exit 0
fi

# Interactive mode
echo "Booting x64 console REPL (Ctrl-A X to quit)..." >&2
exec qemu-system-x86_64 \
    -kernel "$BIN" -m 512 \
    -nographic \
    -no-reboot
