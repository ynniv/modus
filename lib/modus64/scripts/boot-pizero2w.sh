#!/bin/bash
# boot-pizero2w.sh - Boot and SSH into Pi Zero 2 W over plain USB
#
# No GPIO UART bridge needed. Works with both USB boot and SD card boot:
#   USB boot:  Pi in boot mode → rpiboot sends kernel → CDC-ECM → SSH
#   SD card:   Pi already running → wait for CDC-ECM → SSH
#
# Usage: ./scripts/boot-pizero2w.sh [--no-actors]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BOOT_DIR="/tmp/piboot"
RPIBOOT="/tmp/usbboot/rpiboot"
KERNEL_IMG="$BOOT_DIR/kernel8.img"
PI_IP="10.0.0.2"
HOST_IP="10.0.0.1"
PI_MAC="02:00:00:00:00:01"

die() { echo "ERROR: $*" >&2; exit 1; }

# Actors by default (cooperative scheduling, multi-connection SSH)
BUILD_SCRIPT="mvm/build-pizero2w-actors.lisp"
if [ "${1:-}" = "--no-actors" ]; then
    BUILD_SCRIPT="mvm/build-pizero2w-ssh.lisp"
    echo "=== Pi Zero 2 W (single-threaded) ==="
else
    echo "=== Pi Zero 2 W ==="
fi

# --- Check if CDC-ECM already up (SD card boot, already running) ---
IFACE=$(ip -o link 2>/dev/null | grep -i "$PI_MAC" | awk -F'[: ]' '{print $3}')
if [ -n "$IFACE" ]; then
    echo "Pi already up on $IFACE — skipping build and rpiboot."
else
    # --- Build ---
    command -v sbcl >/dev/null || die "sbcl not found"
    echo "Building kernel..."
    cd "$SCRIPT_DIR"
    sbcl --noinform --script "$BUILD_SCRIPT"

    # --- USB boot or SD card? ---
    if lsusb 2>/dev/null | grep -q "0a5c:2764"; then
        # Pi is in USB boot mode — send kernel via rpiboot
        [ -x "$RPIBOOT" ]              || die "rpiboot not found at $RPIBOOT"
        [ -f "$BOOT_DIR/bootcode.bin" ] || die "bootcode.bin not in $BOOT_DIR"
        [ -f "$BOOT_DIR/start.elf" ]    || die "start.elf not in $BOOT_DIR"

        echo "Pi in USB boot mode — sending boot files..."
        sudo "$RPIBOOT" -d "$BOOT_DIR"
    else
        echo "Pi not in USB boot mode — assuming SD card boot."
        echo "Plug in Pi and power on."
    fi

    # --- Wait for CDC-ECM interface ---
    echo "Waiting for USB Ethernet..."
    for i in $(seq 1 90); do
        IFACE=$(ip -o link 2>/dev/null | grep -i "$PI_MAC" | awk -F'[: ]' '{print $3}')
        [ -n "$IFACE" ] && break
        sleep 1
    done
    [ -n "$IFACE" ] || die "USB Ethernet not detected after 90s (check dmesg)"
fi

echo "Interface: $IFACE"

# --- Configure host network ---
if ! ip addr show "$IFACE" 2>/dev/null | grep -q "$HOST_IP"; then
    sudo ip addr add "$HOST_IP/24" dev "$IFACE"
fi
sudo ip link set "$IFACE" up
sudo ip neigh replace "$PI_IP" lladdr "$PI_MAC" dev "$IFACE" 2>/dev/null || true

# --- Enable NAT for Pi internet access ---
sudo sysctl -q -w net.ipv4.ip_forward=1
OUTIF=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')
if [ -n "$OUTIF" ]; then
    sudo iptables -t nat -C POSTROUTING -s "$PI_IP" -o "$OUTIF" -j MASQUERADE 2>/dev/null || \
        sudo iptables -t nat -A POSTROUTING -s "$PI_IP" -o "$OUTIF" -j MASQUERADE
fi
echo "Host: $HOST_IP  Pi: $PI_IP  NAT: ${OUTIF:-none}"

# --- Wait for SSH ---
echo "Waiting for SSH..."
for i in $(seq 1 120); do
    if echo "" | nc -w 2 "$PI_IP" 22 2>/dev/null | grep -q SSH; then
        break
    fi
    sleep 2
done

# --- Connect ---
echo ""
exec ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null test@"$PI_IP"
