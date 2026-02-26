#!/bin/bash
# run-movitz-repl.sh — Run Modus32 (Movitz) in QEMU
#
# Usage:
#   ./run-movitz-repl.sh              # interactive REPL
#   ./run-movitz-repl.sh '(+ 1 2)'   # evaluate expression and exit

cd "$(dirname "$0")/../.."

IMAGE_PATH="modus/modus.img"
LOGDIR="modus/log"
mkdir -p "$LOGDIR"

if [ ! -f "$IMAGE_PATH" ]; then
  echo "Error: Image '$IMAGE_PATH' not found. Run ./modus/scripts/build-movitz.sh first."
  exit 1
fi

KVM_OPTS=""
if [ -r /dev/kvm ]; then
  KVM_OPTS="-enable-kvm"
fi

QEMU_ARGS=(
  qemu-system-i386
  $KVM_OPTS
  -drive "file=$IMAGE_PATH,format=raw"
  -boot c
  -m 512
  -nographic
  -device e1000,netdev=net0
  -netdev user,id=net0
)

# Interactive REPL mode
if [ $# -eq 0 ]; then
  # Disable XON/XOFF flow control - raw byte 0x13 in output can freeze terminal
  stty -ixon 2>/dev/null || true
  echo "Booting Modus... (Ctrl+C to stop)"
  exec "${QEMU_ARGS[@]}"
fi

# Expression evaluation mode
EXPR="$*"

exec python3 -u - "$EXPR" "${QEMU_ARGS[@]}" << 'PYTHON'
import subprocess, sys, os, time, signal, re
from datetime import datetime

expr = sys.argv[1]
qemu_cmd = sys.argv[2:]

logdir = os.path.join(os.getcwd(), 'modus', 'log')
timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
logfile = os.path.join(logdir, f'run-{timestamp}.log')
log = open(logfile, 'w')

def logw(msg):
    log.write(f'[{time.monotonic():.1f}] {msg}\n')
    log.flush()

logw(f'expr: {expr}')
logw(f'qemu: {" ".join(qemu_cmd)}')

proc = subprocess.Popen(
    qemu_cmd,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    bufsize=0
)

os.set_blocking(proc.stdout.fileno(), False)

def cleanup(code=0):
    logw(f'cleanup code={code}')
    log.close()
    proc.terminate()
    try: proc.wait(timeout=3)
    except: proc.kill()
    sys.exit(code)

def sighandler(sig=None, frame=None):
    logw(f'signal {sig}')
    cleanup(1)

signal.signal(signal.SIGINT, sighandler)
signal.signal(signal.SIGTERM, sighandler)

def read():
    try:
        d = proc.stdout.read(8192)
        if d:
            text = d.decode('utf-8', errors='replace')
            logw(f'read ({len(d)} bytes): {repr(text[:200])}')
            return text
        return ''
    except:
        return ''

def send(cmd):
    logw(f'send: {repr(cmd)}')
    proc.stdin.write((cmd + '\n').encode())
    proc.stdin.flush()

# Wait for REPL prompt
sys.stderr.write("Booting...")
sys.stderr.flush()
buf = ''
for i in range(60):
    time.sleep(1)
    out = read()
    buf += out
    if 'MODUS(' in buf or 'LOS0>' in buf:
        logw(f'prompt found after {i+1}s')
        break
    sys.stderr.write(".")
    sys.stderr.flush()
else:
    sys.stderr.write(" timeout\n")
    logw(f'timeout. buf tail: {repr(buf[-200:])}')
    cleanup(1)

sys.stderr.write(" ok\n")
time.sleep(1)
read()  # drain

# Send expression
send(expr)
time.sleep(2)
out = read()

logw(f'raw response: {repr(out)}')

# Extract result: strip ANSI escapes, prompts, and echoed input
out = re.sub(r'\x1b\[[^a-zA-Z]*[a-zA-Z]', '', out)
out = re.sub(r'MODUS\(\d+\):\s*', '', out)
out = re.sub(r'LOS0>\s*', '', out)
out = out.replace(expr, '', 1)
result = out.strip()

logw(f'result: {repr(result)}')

if result:
    print(result)

cleanup(0)
PYTHON
