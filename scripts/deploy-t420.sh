#!/bin/bash
# deploy-t420.sh — Build and deploy Modus i386 image to T420 via Pi Zero 2 W
#
# Usage: ./scripts/deploy-t420.sh [pi-address]
# Example: ./scripts/deploy-t420.sh 192.168.1.42
#
# The Pi must be set up with setup-pizero-gadget.sh first.

PI="${1:-pi-zero}"  # Pi hostname or IP

set -e

echo "=== Building i386 diagnostic SSH image ==="
sbcl --script mvm/build-i386-diag-ssh.lisp

echo ""
echo "=== Deploying to Pi at $PI ==="
# Stop gadget, copy image, restart
ssh "pi@$PI" "sudo /home/pi/stop-gadget.sh"
scp /tmp/modus-i386-diag-ssh.img "pi@$PI:/home/pi/modus.img"
ssh "pi@$PI" "sudo /home/pi/start-gadget.sh"

echo ""
echo "=== Done! Reboot T420 to load new image ==="
