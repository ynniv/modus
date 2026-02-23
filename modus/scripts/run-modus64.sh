#!/bin/bash
# Build and run Modus64 REPL
# Ctrl-A X to quit QEMU
# Ctrl-A C to toggle monitor

set -e
cd "$(dirname "$0")/../.."

echo "Building kernel..."
cd lib/modus64
sbcl --control-stack-size 64 \
     --load cross/packages.lisp \
     --load cross/x64-asm.lisp \
     --load cross/cross-compile.lisp \
     --load cross/build.lisp \
     --eval '(modus64.build:build-kernel "/tmp/modus64.elf")' \
     --eval '(quit)' > /dev/null 2>&1
cd ../..
echo "Build OK"

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPTDIR/no-thp-exec" qemu-system-x86_64 \
    -kernel /tmp/modus64.elf -m 256 \
    -nographic \
    -nic none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
