#!/bin/bash
# Test: x86-64 QEMU — SSH server boots (eval-cmdline auto-start)
TEST_NAME="x64-ssh"
source "$(dirname "$0")/lib.sh"

PORT=22$(( RANDOM % 90 + 10 ))

echo "Building x64 SSH kernel..."
sbcl --control-stack-size 64 \
     --eval '(push (truename ".") asdf:*central-registry*)' \
     --eval '(asdf:load-system :modus64)' \
     --eval '(modus64.build:build-kernel-mvm "/tmp/modus64.elf")' \
     --eval '(quit)' > /dev/null 2>&1

boot_x64 /tmp/modus64.elf \
    -append "(progn (net-init-dhcp) (ssh-server 22))" \
    -device 'e1000,netdev=net0,romfile=,rombar=0' \
    -netdev "user,id=net0,hostfwd=tcp::${PORT}-:22"
wait_for "SSH:" 90
pass
