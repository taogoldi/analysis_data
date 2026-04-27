"""
VerShadow stage-2 decryptor.

The loader downloads a blob from https://files.catbox.moe/v5fllr.bin and applies
two transforms to recover the in-memory .NET assembly:

  1. RC4 (KSA + PRGA) with a 16-byte key embedded at .data RVA 0x4030.
  2. A per-byte transform driven by a 32-byte key embedded at .data RVA 0x4040:
        plain[i] = (rc4_out[i] - key32[(i+1) & 0x1f]) ^ key32[i & 0x1f]

The resulting buffer is a .NET assembly (PE/COFF starting with "MZ") that the
loader passes to _AppDomain::Load_3 via a SafeArray.

Key material extracted from c73947cf188f442bed228f62a3ba5611009fdc2f1878aaed7065db95ede05521.exe
"""

import sys

RC4_KEY = bytes.fromhex("3089f010897626b235ac34723f5ed64c")
KEY32   = bytes.fromhex(
    "3255803f115d04014145c5d685f6fb26"
    "e1e5315fd3e206dd6cb21607f297cb63"
)


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n, b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def stage2(rc4_out: bytes) -> bytes:
    out = bytearray(len(rc4_out))
    for i, b in enumerate(rc4_out):
        out[i] = ((b - KEY32[(i + 1) & 0x1f]) & 0xFF) ^ KEY32[i & 0x1f]
    return bytes(out)


def decrypt(blob: bytes) -> bytes:
    return stage2(rc4(RC4_KEY, blob))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: decrypt_stage2.py <ciphertext> <plaintext>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        ct = f.read()
    pt = decrypt(ct)
    with open(sys.argv[2], "wb") as f:
        f.write(pt)
    head = pt[:4]
    print(f"wrote {len(pt)} bytes, magic={head!r} -> {'PE/COFF' if head[:2]==b'MZ' else 'unknown'}")
