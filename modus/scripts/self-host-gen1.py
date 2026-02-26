#!/usr/bin/env python3
"""Self-host Gen1 from Gen0: boot Gen0 in QEMU, run (build-image), extract Gen1 via QMP."""
import subprocess, time, os, select, re, socket, sys, ctypes

# Disable THP before spawning QEMU — inherited by child process.
# Without this, QEMU's madvise(MADV_HUGEPAGE) on guest RAM triggers
# THP compaction that hangs 30+ seconds on large NUMA systems.
try:
    ctypes.CDLL("libc.so.6").prctl(41, 1, 0, 0, 0)  # PR_SET_THP_DISABLE
except Exception:
    pass

gen0 = sys.argv[1] if len(sys.argv) > 1 else "/tmp/modus64-gen0.elf"
gen1 = sys.argv[2] if len(sys.argv) > 2 else "/tmp/modus64-gen1.elf"
qmp_port = int(sys.argv[3]) if len(sys.argv) > 3 else 4444
script_dir = os.path.dirname(os.path.abspath(__file__))
no_thp = os.path.join(script_dir, 'no-thp-exec')

proc = subprocess.Popen(
    [no_thp, 'qemu-system-x86_64', '-kernel', gen0, '-nographic', '-m', '512',
     '-qmp', f'tcp:localhost:{qmp_port},server,nowait'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

def read_until(marker, timeout=120):
    buf = b""
    start = time.time()
    while time.time() - start < timeout:
        ready, _, _ = select.select([proc.stdout], [], [], 0.1)
        if ready:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk: break
            buf += chunk
            if marker.encode() in buf:
                # Drain trailing output (e.g. digits after "D:")
                for _ in range(5):
                    r, _, _ = select.select([proc.stdout], [], [], 0.1)
                    if r:
                        buf += os.read(proc.stdout.fileno(), 4096)
                    else:
                        break
                return buf.decode(errors='replace'), True
    return buf.decode(errors='replace'), False

out, ok = read_until("> ", timeout=60)
if not ok:
    print(f"FAIL: Gen0 REPL not ready. Output: {out[-200:]}", file=sys.stderr, flush=True)
    proc.kill(); sys.exit(1)
print("  Gen0 REPL ready.", flush=True)

proc.stdin.write(b"(build-image)\n"); proc.stdin.flush()
out, ok = read_until("D:", timeout=600)
if not ok:
    print(f"  FAIL: build-image timeout. Output: ...{out[-300:]}", file=sys.stderr, flush=True)
    proc.kill(); sys.exit(1)

m = re.search(r'D:\s*(\d+)', out)
if not m:
    print(f"  FAIL: no image size. Output: ...{out[-200:]}", file=sys.stderr, flush=True)
    proc.kill(); sys.exit(1)

size = int(m.group(1))
print(f"  Image built: {size} bytes", flush=True)

# Extract image via QMP pmemsave
sys.stdout.write("  Extracting image...")
sys.stdout.flush()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(('localhost', qmp_port))
s.recv(4096)
s.send(b'{"execute":"qmp_capabilities"}\n')
s.recv(4096)
s.send(f'{{"execute":"pmemsave","arguments":{{"val":134217728,"size":{size},"filename":"{gen1}"}}}}\n'.encode())
# Wait for pmemsave to complete (returns {"return": {}})
s.recv(4096)
s.close()

proc.kill(); proc.wait()
actual = os.path.getsize(gen1)
print(f" {actual} bytes", flush=True)
