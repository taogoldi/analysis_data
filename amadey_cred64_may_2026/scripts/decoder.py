#!/usr/bin/env python3
"""
Amadey 5.78 cred plugin string decoder.

Reproduces the three-stage pipeline:
    stored_blob -> keystream-build -> Vigenere decode -> Base64 decode -> plaintext

The Vigenere stage uses a 63-char custom alphabet (a-z A-Z 0-9 SPACE).
Spaces in the ciphertext are passed through unchanged so they can act as
in-band separators ahead of the Base64 padding bytes. Non-alphabet bytes
(like `=` padding) are also passed through.

Usage:
    python3 decoder.py blob1 blob2 ...
    python3 decoder.py --file blobs.txt    # one blob per line
    python3 decoder.py --bin cred64.dll    # auto-extract from .rdata

Reference values for the 2026-03-08 cred64.dll build (botnet 54e64e):
    SHA256:    3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69
    Vigenere:  a42cf94a609810d038dd0ca0d030ffef
    RC4 (C2):  592deb617de745dd747a896c20d17d0f
    Botnet ID: 54e64e

Author: Tao Goldi
"""

from __future__ import annotations

import argparse
import base64
import re
import sys

ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
KEY  = "a42cf94a609810d038dd0ca0d030ffef"


def vigenere_decrypt(blob: str, key: str = KEY) -> str:
    """Per-byte Vigenere decrypt using ALPH as the alphabet."""
    out = []
    ki = 0
    for c in blob:
        if c == " ":                                # in-band separator
            out.append(c)
            continue
        ci = ALPH.find(c)
        if ci < 0:                                  # outside the alphabet -> pass through
            out.append(c)
            continue
        k_idx = ALPH.find(key[ki % len(key)])
        out.append(ALPH[(ci - k_idx + len(ALPH)) % len(ALPH)])
        ki += 1
    return "".join(out)


def b64_decode(s: str) -> bytes:
    """Standard base64 decode with forgiving padding."""
    pad = (-len(s)) % 4
    return base64.b64decode(s + ("=" * pad))


def decode(blob: str, key: str = KEY) -> str:
    """Full three-stage decode of a stored blob."""
    vig = vigenere_decrypt(blob, key=key)
    return b64_decode(vig).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers for batch / binary modes
# ---------------------------------------------------------------------------

# Heuristic for harvesting candidate Vigenere+B64 blobs from a binary's
# .rdata. The encoded text is alphanumeric + spaces + `=` padding, length
# bounded so we don't pick up junk symbols.
BLOB_RE = re.compile(rb"[A-Za-z0-9 ]{8,}={0,3}")


def harvest(binary_bytes: bytes) -> list[str]:
    return [m.decode("ascii") for m in BLOB_RE.findall(binary_bytes)]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("blobs", nargs="*", help="ciphertext blobs to decode")
    p.add_argument("--file", help="path to a file with one blob per line")
    p.add_argument("--bin", help="path to a binary to harvest blobs from (e.g. cred64.dll)")
    p.add_argument("--key", default=KEY, help=f"Vigenere key (default: {KEY})")
    p.add_argument("--printable-only", action="store_true",
                   help="suppress blobs whose decoded output is not mostly printable")
    args = p.parse_args()

    work: list[str] = list(args.blobs)
    if args.file:
        with open(args.file) as fh:
            work.extend(line.strip() for line in fh if line.strip())
    if args.bin:
        with open(args.bin, "rb") as fh:
            work.extend(harvest(fh.read()))

    if not work:
        p.error("no blobs to decode (positional, --file, or --bin)")

    seen = set()
    for blob in work:
        if blob in seen:
            continue
        seen.add(blob)
        try:
            plain = decode(blob, key=args.key)
        except Exception as e:
            plain = f"<decode-error: {e}>"
        if args.printable_only:
            ratio = sum(c.isprintable() for c in plain) / max(1, len(plain))
            if ratio < 0.85:
                continue
        print(f"{blob}\n  -> {plain!r}\n")


if __name__ == "__main__":
    main()
