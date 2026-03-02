#!/bin/bash
# deploy-pizero2w.sh - Build, deploy, and connect to Pi Zero 2 W
#
# Usage: ./scripts/deploy-pizero2w.sh [build|boot|net|ssh|all]
#
# Prerequisites:
#   - Pi Zero 2 W in USB boot mode (BCM2710 Boot in lsusb)
#   - /tmp/usbboot/rpiboot built
#   - /tmp/piboot/ with bootcode.bin, start.elf, fixup.dat, config.txt
#   - sudo access for rpiboot and network config

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT_DIR="/tmp/piboot"
RPIBOOT="/tmp/usbboot/rpiboot"
KERNEL_IMG="$BOOT_DIR/kernel8.img"
PI_IP="10.0.0.2"
HOST_IP="10.0.0.1"
PI_MAC="02:00:00:00:00:01"

cmd_build() {
    echo "=== Building Pi Zero 2 W SSH kernel ==="
    cd "$SCRIPT_DIR"
    sbcl --script mvm/build-pizero2w-ssh.lisp
    ls -la "$KERNEL_IMG"
}

cmd_boot() {
    echo "=== Deploying kernel via rpiboot ==="

    # Check Pi is in boot mode
    if ! lsusb | grep -q "0a5c:2764"; then
        echo "ERROR: Pi not found in USB boot mode"
        echo "  Expected: Bus NNN Device NNN: ID 0a5c:2764 Broadcom Corp. BCM2710 Boot"
        echo "  Try: physically unplug and replug the Pi"
        exit 1
    fi

    # Check kernel exists
    if [ ! -f "$KERNEL_IMG" ]; then
        echo "ERROR: No kernel at $KERNEL_IMG — run 'build' first"
        exit 1
    fi

    echo "Sending bootcode.bin + start.elf + kernel8.img..."
    sudo "$RPIBOOT" -d "$BOOT_DIR"
    echo "Boot complete. Waiting for USB gadget enumeration..."

    # Wait for CDC-ECM device to appear
    for i in $(seq 1 30); do
        IFACE=$(ip -o link 2>/dev/null | grep -i "$PI_MAC" | awk -F'[: ]' '{print $3}')
        if [ -n "$IFACE" ]; then
            echo "USB Ethernet interface: $IFACE"
            return 0
        fi
        sleep 1
    done

    echo "WARNING: USB Ethernet interface not detected after 30s"
    echo "  Check dmesg for USB enumeration status"
    return 1
}

cmd_net() {
    echo "=== Configuring host network ==="

    # Find interface by MAC
    IFACE=$(ip -o link 2>/dev/null | grep -i "$PI_MAC" | awk -F'[: ]' '{print $3}')
    if [ -z "$IFACE" ]; then
        echo "ERROR: No USB Ethernet interface with MAC $PI_MAC"
        echo "  Check: ip link show"
        exit 1
    fi

    echo "Found interface: $IFACE"

    # Configure IP
    if ! ip addr show "$IFACE" 2>/dev/null | grep -q "$HOST_IP"; then
        sudo ip addr add "$HOST_IP/24" dev "$IFACE"
    fi
    sudo ip link set "$IFACE" up

    echo "Interface $IFACE configured: $HOST_IP/24"
    echo "Waiting for Pi to respond to ARP..."

    for i in $(seq 1 10); do
        if ping -c 1 -W 1 "$PI_IP" >/dev/null 2>&1; then
            echo "Pi responding at $PI_IP"
            return 0
        fi
        sleep 1
    done

    echo "WARNING: Pi not responding to ping at $PI_IP"
    return 1
}

cmd_ssh() {
    echo "=== SSH to Pi Zero 2 W ==="
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 test@"$PI_IP"
}

cmd_all() {
    cmd_build
    cmd_boot
    cmd_net
    cmd_ssh
}

# Main
case "${1:-all}" in
    build) cmd_build ;;
    boot)  cmd_boot ;;
    net)   cmd_net ;;
    ssh)   cmd_ssh ;;
    all)   cmd_all ;;
    *)
        echo "Usage: $0 [build|boot|net|ssh|all]"
        echo "  build - Build kernel image"
        echo "  boot  - Deploy via rpiboot"
        echo "  net   - Configure host networking"
        echo "  ssh   - SSH to Pi"
        echo "  all   - Do everything"
        exit 1
        ;;
esac
