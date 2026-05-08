#!/usr/bin/env python3
"""
verify_sample_text_identity.py - prove that Sample B and Sample C share
byte-identical PoolParty code despite being different on-disk files.

The headline finding for Sample C is that the 29 KB size delta against
Sample B is delivery wrapping (pe_to_shellcode), not new code. This
script extracts the .text section from each binary, trims trailing
alignment padding, and compares the trimmed bodies byte-by-byte.

Usage:
    python3 verify_sample_text_identity.py <sample_B.bin> <sample_C.bin>

Expected output:
    .text trim-equal: True
    Sample B trimmed: 592,879 bytes  (sha256 80f0...)
    Sample C trimmed: 592,879 bytes  (sha256 80f0...)
    Both samples carry the same PoolParty code body.

Author: Tao Goldi
"""

from __future__ import annotations
import argparse
import hashlib
import sys

import pefile


def get_text_bytes(path: str) -> bytes:
    pe = pefile.PE(path, fast_load=True)
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        if name == ".text":
            return pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
    raise SystemExit(f"no .text section in {path}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("sample_b", help="canonical PoolParty (Sample B) binary")
    p.add_argument("sample_c", help="pe_to_shellcode-wrapped variant (Sample C) binary")
    args = p.parse_args()

    bB = get_text_bytes(args.sample_b)
    bC = get_text_bytes(args.sample_c)

    bB_trim = bB.rstrip(b"\x00")
    bC_trim = bC.rstrip(b"\x00")

    print(f"Sample B raw .text:  {len(bB):>8,} bytes")
    print(f"Sample C raw .text:  {len(bC):>8,} bytes")
    print(f"Sample B trimmed:    {len(bB_trim):>8,} bytes  (sha256 {hashlib.sha256(bB_trim).hexdigest()[:16]})")
    print(f"Sample C trimmed:    {len(bC_trim):>8,} bytes  (sha256 {hashlib.sha256(bC_trim).hexdigest()[:16]})")
    print(f".text trim-equal:    {bB_trim == bC_trim}")
    if bB_trim == bC_trim:
        print()
        print("Both samples carry the same PoolParty code body. The size delta")
        print("between the two files is the pe_to_shellcode wrapper attached to")
        print("Sample C; the inner PoolParty PE is byte-equivalent to Sample B.")
        return 0
    # If they diverge, locate first byte that differs
    n = min(len(bB_trim), len(bC_trim))
    for i in range(n):
        if bB_trim[i] != bC_trim[i]:
            ctx = max(0, i - 8)
            print()
            print(f"first divergence at trimmed-offset 0x{i:X}:")
            print(f"  B[{ctx:#x}..{i+8:#x}]: {bB_trim[ctx:i+8].hex(' ')}")
            print(f"  C[{ctx:#x}..{i+8:#x}]: {bC_trim[ctx:i+8].hex(' ')}")
            return 1
    print(f"shorter file is a prefix of the longer; first {n:,} bytes match")
    return 1


if __name__ == "__main__":
    sys.exit(main())
