#!/bin/bash
# Test: x86-64 QEMU — Serial REPL boots and shows prompt
TEST_NAME="x64-repl"
source "$(dirname "$0")/lib.sh"

echo "Building x64 REPL kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus64)' \
     --eval '(modus64.build:build-kernel-mvm "/tmp/modus64.elf")' \
     --eval '(quit)' > /dev/null 2>&1

boot_x64 /tmp/modus64.elf
wait_for ">"
pass
