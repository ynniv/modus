#!/bin/bash
# Build and run Modus64 REPL
# Ctrl-A X to quit QEMU
# Ctrl-A C to toggle monitor

set -e
cd "$(dirname "$0")/../.."

echo "Building kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename "lib/modus64/") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus64)' \
     --eval '(modus64.build:build-kernel-mvm "/tmp/modus64.elf")' \
     --eval '(quit)' > /dev/null 2>&1
echo "Build OK"

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPTDIR/no-thp-exec" qemu-system-x86_64 \
    -kernel /tmp/modus64.elf -m 256 \
    -nographic \
    -nic none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
