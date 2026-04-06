#!/bin/bash
# Test: x86-64 QEMU — SMP + actors boot (SSH server starts)
TEST_NAME="x64-actors"
source "$(dirname "$0")/lib.sh"

PORT=22$(( RANDOM % 90 + 10 ))

echo "Building x64 SSH kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus)' \
     --eval '(modus.build:build-kernel-mvm "/tmp/modus.elf")' \
     --eval '(quit)' > /dev/null 2>&1

boot_x64 /tmp/modus.elf -smp 2 \
    -append "(progn (net-init-dhcp) (ssh-server 22))" \
    -device 'e1000,netdev=net0,romfile=,rombar=0' \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:22"
wait_for "SSH:" 90
pass
