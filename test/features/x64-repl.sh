#!/bin/bash
# Test: x86-64 QEMU — Serial REPL boots and shows prompt
TEST_NAME="x64-repl"
source "$(dirname "$0")/lib.sh"

echo "Building x64 REPL kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus)' \
     --eval '(modus.build:build-kernel-mvm "/tmp/modus.elf")' \
     --eval '(quit)' > /dev/null 2>&1

boot_x64 /tmp/modus.elf
wait_for ">"
pass
