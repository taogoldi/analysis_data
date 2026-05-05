#!/usr/bin/env python3
"""
decode_piasaba.py - Tao Goldi 2026-04

Decodes the GuLoader stage-1 shellcode from `piasaba` in this campaign.

Pipeline:
  1. Strip the trailing 0xAC filesize-padding (last 17000 bytes).
  2. XOR-decrypt with 4-byte sliding key 0x49ED06B1.
  3. Output recoverable shellcode containing 9 PEB walks and a custom
     hash-based API resolution loop.

The 4-byte key was recovered statically by stride-4 byte-frequency
analysis: each position modulo 4 has a strongly dominant byte (0x49 at
i%4==0, 0xED at i%4==1, 0x06 at i%4==2, 0xB1 at i%4==3). Those dominant
bytes are the cipher-of-zero, i.e. the key bytes themselves.

API hash function recovered from the disassembly at offset 0x2EE78:

    H = 0
    for each byte b of UTF-16-LE-low-byte module-or-API name:
        if 0x61 <= b <= 0x7A: b -= 0x20      # a-z -> A-Z
        H = (H + b) XOR 0x182DE6AD
    return H

Usage: python3 decode_piasaba.py <path/to/piasaba> [output.bin]
"""
from __future__ import annotations
import sys, struct

XOR_KEY = bytes.fromhex('49ED06B1')
PAD_BYTE = 0xAC
HASH_KEY = 0x182DE6AD


def strip_pad(data: bytes) -> bytes:
    end = len(data)
    while end > 0 and data[end - 1] == PAD_BYTE:
        end -= 1
    return data[:end]


def xor_decode(data: bytes, key: bytes = XOR_KEY) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def gl_hash(name: str) -> int:
    """GuLoader API/module hash (case-insensitive, ASCII only)."""
    h = 0
    for ch in name:
        b = ord(ch)
        if 0x61 <= b <= 0x7A:
            b -= 0x20
        h = ((h + b) ^ HASH_KEY) & 0xFFFFFFFF
    return h


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else 'piasaba_decoded.bin'

    raw = open(inp, 'rb').read()
    print(f'Input: {inp} ({len(raw)} bytes)')

    body = strip_pad(raw)
    print(f'After stripping 0xAC pad: {len(body)} bytes (removed {len(raw)-len(body)})')

    decoded = xor_decode(body)
    open(out, 'wb').write(decoded)
    print(f'Output: {out} ({len(decoded)} bytes)')

    # Verification: count PEB walks and known API hash matches
    peb_walks = decoded.count(b'\x64\xa1\x30\x00\x00\x00')
    print(f'PEB walks (mov eax, fs:[0x30]): {peb_walks}')

    quick = ['VirtualAlloc', 'VirtualProtect', 'CreateProcessA', 'CreateProcessW',
             'kernel32', 'CreateFileA', 'HttpSendRequestA', 'WinHttpSendRequest',
             'NtCreateThread', 'CheckRemoteDebuggerPresent']
    print('Known API hash matches:')
    for name in quick:
        h = gl_hash(name)
        if struct.pack('<I', h) in decoded:
            print(f'  {name:36s}  hash=0x{h:08x}  found')


if __name__ == '__main__':
    main()
