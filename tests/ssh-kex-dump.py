#!/usr/bin/env python3
"""
ssh-kex-dump.py — Connect to Modus SSH, dump raw KEXDH_REPLY, verify signature.

Usage: python3 tests/ssh-kex-dump.py [host] [port]

Performs the SSH key exchange manually and prints exactly what goes wrong.
"""

import socket, struct, hashlib, os, sys

def ssh_str(data):
    return struct.pack('>I', len(data)) + data

def ssh_mpint(data):
    d = data.lstrip(b'\x00') or b'\x00'
    if d[0] & 0x80:
        d = b'\x00' + d
    return struct.pack('>I', len(d)) + d

def read_u32(data, off):
    return struct.unpack('>I', data[off:off+4])[0]

host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
port = int(sys.argv[2]) if len(sys.argv) > 2 else 2222

print(f"Connecting to {host}:{port}...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(120)
sock.connect((host, port))

# 1. Version exchange
server_ver_line = b''
while not server_ver_line.endswith(b'\n'):
    server_ver_line += sock.recv(1)
server_ver = server_ver_line.rstrip(b'\r\n')
print(f"Server version: {server_ver}")

client_ver = b'SSH-2.0-kex-dump'
sock.sendall(client_ver + b'\r\n')
print(f"Client version: {client_ver}")

# 2. Build and send client KEXINIT
client_kexinit_payload = bytearray()
client_kexinit_payload.append(20)  # SSH_MSG_KEXINIT
client_kexinit_payload.extend(os.urandom(16))  # cookie
# kex algorithms
kex_algo = b'curve25519-sha256'
client_kexinit_payload.extend(struct.pack('>I', len(kex_algo)) + kex_algo)
# host key algorithms
hk_algo = b'ssh-ed25519'
client_kexinit_payload.extend(struct.pack('>I', len(hk_algo)) + hk_algo)
# encryption c2s, s2c
enc = b'chacha20-poly1305@openssh.com'
client_kexinit_payload.extend(struct.pack('>I', len(enc)) + enc)
client_kexinit_payload.extend(struct.pack('>I', len(enc)) + enc)
# mac c2s, s2c
mac = b'none'
client_kexinit_payload.extend(struct.pack('>I', len(mac)) + mac)
client_kexinit_payload.extend(struct.pack('>I', len(mac)) + mac)
# comp c2s, s2c
comp = b'none'
client_kexinit_payload.extend(struct.pack('>I', len(comp)) + comp)
client_kexinit_payload.extend(struct.pack('>I', len(comp)) + comp)
# lang c2s, s2c
client_kexinit_payload.extend(struct.pack('>I', 0))
client_kexinit_payload.extend(struct.pack('>I', 0))
# first_kex_follows, reserved
client_kexinit_payload.append(0)
client_kexinit_payload.extend(struct.pack('>I', 0))

I_C = bytes(client_kexinit_payload)
print(f"Client KEXINIT: {len(I_C)} bytes, type={I_C[0]}")

# Send as SSH packet
def send_packet(sock, payload):
    pad_len = 8 - ((5 + len(payload)) % 8)
    if pad_len < 4:
        pad_len += 8
    packet_len = 1 + len(payload) + pad_len
    pkt = struct.pack('>I', packet_len) + bytes([pad_len]) + payload + os.urandom(pad_len)
    sock.sendall(pkt)

def recv_packet(sock):
    # Read 4-byte length
    hdr = b''
    while len(hdr) < 4:
        hdr += sock.recv(4 - len(hdr))
    packet_len = struct.unpack('>I', hdr)[0]
    # Read rest
    data = b''
    while len(data) < packet_len:
        data += sock.recv(packet_len - len(data))
    pad_len = data[0]
    payload = data[1:packet_len - pad_len]
    return payload

send_packet(sock, I_C)

# 3. Receive server KEXINIT
I_S = recv_packet(sock)
print(f"Server KEXINIT: {len(I_S)} bytes, type={I_S[0]}")

# 4. Send KEX_ECDH_INIT with our ephemeral key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
client_priv = X25519PrivateKey.generate()
client_pub = client_priv.public_key()
from cryptography.hazmat.primitives import serialization
e = client_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

kex_init_payload = bytes([30]) + struct.pack('>I', 32) + e  # type=30 + string(e)
send_packet(sock, kex_init_payload)
print(f"Sent KEX_ECDH_INIT: client ephemeral = {e[:4].hex()}...")

# 5. Receive KEXDH_REPLY
reply = recv_packet(sock)
print(f"\nKEXDH_REPLY: {len(reply)} bytes, type={reply[0]}")

if reply[0] != 31:
    print(f"ERROR: expected type 31, got {reply[0]}")
    sys.exit(1)

# Parse KEXDH_REPLY: K_S, f, sig_blob
off = 1
ks_len = read_u32(reply, off); off += 4
K_S = reply[off:off+ks_len]; off += ks_len
print(f"  K_S (host key blob): {ks_len} bytes")
print(f"    first 8: {K_S[:8].hex()}")

f_len = read_u32(reply, off); off += 4
f = reply[off:off+f_len]; off += f_len
print(f"  f (server ephemeral): {f_len} bytes")
print(f"    = {f.hex()}")

sig_blob_len = read_u32(reply, off); off += 4
sig_blob = reply[off:off+sig_blob_len]; off += sig_blob_len
print(f"  sig_blob: {sig_blob_len} bytes")

# Parse sig_blob: string(algo) + string(sig)
sig_off = 0
algo_len = read_u32(sig_blob, sig_off); sig_off += 4
algo = sig_blob[sig_off:sig_off+algo_len]; sig_off += algo_len
sig_len = read_u32(sig_blob, sig_off); sig_off += 4
sig = sig_blob[sig_off:sig_off+sig_len]
print(f"  sig algo: {algo}")
print(f"  sig: {sig.hex()}")

# 6. Compute shared secret K
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
server_pub = X25519PublicKey.from_public_bytes(f)
K = client_priv.exchange(server_pub)
print(f"\nShared secret K: {K[:4].hex()}...")

# 7. Compute exchange hash H
V_C = ssh_str(client_ver)
V_S = ssh_str(server_ver)
I_C_str = ssh_str(I_C)
I_S_str = ssh_str(I_S)
K_S_str = ssh_str(K_S)
e_str = ssh_str(e)
f_str = ssh_str(f)
K_mpint = ssh_mpint(K)

hash_input = V_C + V_S + I_C_str + I_S_str + K_S_str + e_str + f_str + K_mpint
H = hashlib.sha256(hash_input).digest()
print(f"Exchange hash H: {H[:4].hex()} (from {len(hash_input)} bytes input)")

# 8. Verify signature
# Extract host public key from K_S
ks_off = 0
ks_algo_len = read_u32(K_S, ks_off); ks_off += 4
ks_algo = K_S[ks_off:ks_off+ks_algo_len]; ks_off += ks_algo_len
ks_pk_len = read_u32(K_S, ks_off); ks_off += 4
host_pubkey = K_S[ks_off:ks_off+ks_pk_len]
print(f"Host public key: {host_pubkey.hex()}")

import nacl.signing
verify_key = nacl.signing.VerifyKey(host_pubkey)
try:
    verify_key.verify(H, sig)
    print("\n*** SIGNATURE VALID ***")
except nacl.exceptions.BadSignatureError:
    print("\n*** SIGNATURE INVALID ***")
    # Try to figure out what the server signed
    # The server's H might differ. Let's see what H the sig was made for.
    # We can't recover H from sig alone, but we can check components.
    print(f"\nDebug: hash input length = {len(hash_input)}")
    print(f"  V_C: {len(V_C)} bytes, starts {V_C[:8].hex()}")
    print(f"  V_S: {len(V_S)} bytes, starts {V_S[:8].hex()}")
    print(f"  I_C: {len(I_C_str)} bytes")
    print(f"  I_S: {len(I_S_str)} bytes")
    print(f"  K_S: {len(K_S_str)} bytes")
    print(f"  e:   {len(e_str)} bytes")
    print(f"  f:   {len(f_str)} bytes")
    print(f"  K:   {len(K_mpint)} bytes, starts {K_mpint[:8].hex()}")

    # Also try signing H ourselves with the known private key (zeros)
    # to see what signature the server SHOULD produce
    signing_key = nacl.signing.SigningKey(b'\x00' * 32)
    expected_sig = signing_key.sign(H).signature
    print(f"\n  Expected sig for our H: {expected_sig[:4].hex()}...")
    print(f"  Actual sig from server: {sig[:4].hex()}...")
    if expected_sig == sig:
        print("  Sigs match! Server signed the same H but verify failed (shouldn't happen)")
    else:
        print("  Sigs differ — server computed a different H")
        # Sign our H and check
        our_pubkey = signing_key.verify_key.encode()
        print(f"  Our pubkey:    {our_pubkey.hex()}")
        print(f"  Server pubkey: {host_pubkey.hex()}")

sock.close()
