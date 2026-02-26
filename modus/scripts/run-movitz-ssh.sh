#!/bin/bash
# run-movitz-ssh.sh — Run Modus32 (Movitz) SSH server
# Connect with: ssh -p 2222 -i ~/.ssh/id_ed25519 test@localhost

cd "$(dirname "$0")/../.."
MODUS_DIR="$(pwd)"

# Kill any existing instance
pkill -9 -f 'qemu.*modus/modus.img' 2>/dev/null
sleep 1

echo "========================================"
echo "Modus SSH Server"
echo "========================================"
echo "Connect: ssh -p 2222 -i ~/.ssh/id_ed25519 test@localhost"
echo "Press Ctrl+C to stop"
echo "========================================"
echo ""

python3 -u << 'PYTHON'
import subprocess
import time
import os
import signal
import sys
import base64
from pathlib import Path

proc = None

def load_ed25519_keys():
    """Load Ed25519 public keys from ~/.ssh/*.pub files."""
    keys = []
    ssh_dir = Path.home() / '.ssh'
    if not ssh_dir.exists():
        return keys

    for pub_file in ssh_dir.glob('*.pub'):
        try:
            content = pub_file.read_text().strip()
            if not content.startswith('ssh-ed25519 '):
                continue
            parts = content.split()
            if len(parts) < 2:
                continue
            # Decode the base64 blob
            blob = base64.b64decode(parts[1])
            # SSH format: 4-byte len + "ssh-ed25519" + 4-byte len + 32-byte key
            # Skip first 19 bytes (4 + 11 + 4), take next 32
            if len(blob) >= 51:  # 19 + 32
                pubkey = blob[19:51]
                comment = parts[2] if len(parts) > 2 else pub_file.name
                keys.append((pubkey, comment))
        except Exception as e:
            print(f"Warning: couldn't read {pub_file}: {e}")
    return keys

def cleanup(sig=None, frame=None):
    print("\nShutting down...")
    if proc:
        proc.terminate()
        try: proc.wait(timeout=3)
        except: proc.kill()
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

proc = subprocess.Popen(
    ['qemu-system-i386', '-enable-kvm',
     '-drive', 'file=modus/modus.img,format=raw',
     '-boot', 'c', '-m', '512', '-nographic',
     '-device', 'e1000,netdev=net0',
     '-netdev', 'user,id=net0,hostfwd=tcp::2222-:22'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    bufsize=0
)

os.set_blocking(proc.stdout.fileno(), False)

def read():
    try:
        d = proc.stdout.read(8192)
        return d.decode('utf-8', errors='replace') if d else ''
    except:
        return ''

def send(cmd):
    proc.stdin.write((cmd + '\n').encode())
    proc.stdin.flush()

# Boot
sys.stdout.write("Booting")
sys.stdout.flush()
for _ in range(45):
    time.sleep(1)
    out = read()
    if 'MODUS' in out:
        break
    sys.stdout.write(".")
    sys.stdout.flush()
print(" OK")
time.sleep(2)
read()

# Initialize
print("Network...", end=' ', flush=True)
send('(e1000-probe)')
time.sleep(6)
read()
print("OK")

print("SSH keys...", end=' ', flush=True)
send('(muerte::ssh-init)')
time.sleep(15)
read()
print("OK")

# Load and add SSH keys from ~/.ssh
keys = load_ed25519_keys()
if keys:
    print(f"Adding {len(keys)} SSH key(s)...", flush=True)
    for pubkey, comment in keys:
        send('(muerte::ssh-key-start)')
        time.sleep(0.2)
        # Send key in 8-byte chunks
        for offset in range(0, 32, 8):
            chunk = pubkey[offset:offset+8]
            hex_bytes = ' '.join(f'#x{b:02x}' for b in chunk)
            send(f'(muerte::ssh-key-set {offset} {hex_bytes})')
            time.sleep(0.1)
        send('(muerte::ssh-key-add)')
        time.sleep(0.3)
        read()
        print(f"  + {comment}")
else:
    print("No Ed25519 keys found, using default...", end=' ', flush=True)
    send('(muerte::ssh-use-default-key)')
    time.sleep(1)
    read()
    print("OK")

print("Server...", end=' ', flush=True)
send('(muerte::ssh-server :port 22)')
time.sleep(3)
read()
print("OK")

print("")
print("========================================")
print("SSH server ready on port 2222")
print("========================================")
print("")

# Monitor for connections - show ALL output for debugging
while proc.poll() is None:
    out = read()
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    time.sleep(0.1)

print("Server exited")
PYTHON
