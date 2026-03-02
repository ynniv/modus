#!/usr/bin/env python3
"""Deploy kernel to Pi Zero 2 W over UART.

Usage: python3 deploy-kernel.py /path/to/kernel8.img

Resets the Pi Zero 2 W via GPIO17, waits for the UART bootloader,
sends the kernel image, and verifies the checksum response.

Requires: pyserial, RPi.GPIO (on Raspberry Pi 5)
Install: pip3 install pyserial RPi.GPIO
"""

import serial
import sys
import time

SERIAL_PORT = '/dev/ttyAMA0'
BAUD = 115200
RESET_PIN = 17
MAGIC = 0x55
ACK = 0xAA


def reset_target():
    """Reset Pi Zero 2 W via GPIO17."""
    try:
        import RPi.GPIO as GPIO
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(RESET_PIN, GPIO.OUT)
        GPIO.output(RESET_PIN, GPIO.LOW)
        time.sleep(0.3)
        # Release: set to input with no pull (default pull-down holds in reset)
        GPIO.setup(RESET_PIN, GPIO.IN, pull_up_down=GPIO.PUD_OFF)
        print("Reset via GPIO17")
    except (ImportError, RuntimeError):
        print("GPIO not available — please reset the target manually")
        input("Press Enter when target is reset...")


def deploy(kernel_path):
    """Send kernel image over UART."""
    with open(kernel_path, 'rb') as f:
        data = f.read()

    size = len(data)
    print(f"Kernel: {kernel_path} ({size} bytes, {size/1024:.1f} KB)")
    est_seconds = size * 10 / BAUD  # 10 bits per byte (8N1)
    print(f"Estimated transfer time: {est_seconds:.0f}s at {BAUD} baud")

    # Open serial first so we capture all boot output
    # Short timeout for fast polling during boot wait
    ser = serial.Serial(SERIAL_PORT, BAUD, timeout=0.1)
    ser.reset_input_buffer()

    # Reset target
    reset_target()

    # Wait for "RDY\n" — bootloader prints this right before entering UART wait
    print("Waiting for bootloader...", end='', flush=True)
    boot_output = b''
    deadline = time.time() + 10  # 10 second max wait
    while time.time() < deadline:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            boot_output += chunk
            # "RDY\n" means bootloader is ready to receive magic byte
            if b'RDY' in boot_output:
                break
    print()
    if boot_output:
        print(f"Boot output: {boot_output.decode('ascii', errors='replace').strip()}")
    if b'RDY' not in boot_output:
        print("Bootloader not detected (no RDY). Aborting.")
        ser.close()
        sys.exit(1)

    # Send magic byte
    print("Sending magic byte...")
    ser.write(bytes([MAGIC]))

    # Wait for ACK
    ack = ser.read(1)
    if not ack or ack[0] != ACK:
        print(f"No ACK received (got {ack!r}). Bootloader may have timed out.")
        ser.close()
        sys.exit(1)
    print("ACK received")

    # Send 4-byte size (little-endian)
    ser.write(size.to_bytes(4, 'little'))

    # Send kernel data
    print(f"Sending {size} bytes...", end='', flush=True)
    chunk_size = 256
    sent = 0
    while sent < size:
        end = min(sent + chunk_size, size)
        ser.write(data[sent:end])
        sent = end
        # Print progress every 64KB
        if sent % 65536 < chunk_size:
            print(f"\rSending {size} bytes... {sent*100//size}%", end='', flush=True)
    print(f"\rSending {size} bytes... done")

    # Send checksum
    checksum = sum(data) & 0xFF
    ser.write(bytes([checksum]))
    print(f"Checksum: 0x{checksum:02X}")

    # Wait for response
    ser.timeout = 5
    resp = ser.read(10)
    if resp:
        print(f"Response: {resp.decode('ascii', errors='replace').strip()}")
    else:
        print("No response (timeout)")

    ser.close()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <kernel8.img>")
        sys.exit(1)
    deploy(sys.argv[1])
