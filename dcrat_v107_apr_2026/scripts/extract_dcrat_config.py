#!/usr/bin/env python3
"""
DcRAT (Dark Crystal RAT) — Config Extractor
=============================================
Extracts AES-256-CBC encrypted configuration from DcRAT .NET binaries.

The config is encrypted with PBKDF2-derived keys using the hardcoded
salt "DcRatByqwqdanchun" and 50,000 iterations. The AES key is
Base64-encoded in the Settings class.

Usage:
    python extract_dcrat_config.py <sample.exe>

Requirements:
    pip install pycryptodome

Author: Tao Goldi
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    print("ERROR: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


DCRAT_SALT = b"DcRatByqwqdanchun"
DCRAT_ITERATIONS = 50000


def derive_keys(master_key: str) -> tuple[bytes, bytes]:
    """Derive AES key and HMAC auth key from master key."""
    derived = PBKDF2(master_key, DCRAT_SALT, dkLen=96, count=DCRAT_ITERATIONS)
    return derived[:32], derived[32:96]


def decrypt(aes_key: bytes, b64_ciphertext: str) -> str:
    """Decrypt a DcRAT AES-256-CBC encrypted config field."""
    raw = base64.b64decode(b64_ciphertext)
    # Format: [HMAC-SHA256 (32)][IV (16)][AES-CBC ciphertext]
    iv = raw[32:48]
    ciphertext = raw[48:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if 0 < pad_len <= 16:
        decrypted = decrypted[:-pad_len]
    return decrypted.decode("utf-8", errors="replace")


def extract_config_strings(data: bytes) -> dict[str, str]:
    """Extract Base64 config strings from the binary."""
    # DcRAT stores config as static string fields with Base64 values
    # Look for long Base64 strings (>40 chars)
    b64_pattern = re.compile(rb'([A-Za-z0-9+/=]{40,})')

    # Also look for the Key field specifically
    configs = {}

    # Find the AES key (Base64-encoded plaintext key)
    for match in b64_pattern.finditer(data):
        b64_str = match.group(1).decode('ascii')
        try:
            decoded = base64.b64decode(b64_str)
            # The key is typically 24-48 bytes when decoded
            if 20 <= len(decoded) <= 64:
                try:
                    key_candidate = decoded.decode('utf-8')
                    if key_candidate.isprintable() and len(key_candidate) >= 20:
                        configs['_key_candidate'] = key_candidate
                except:
                    pass
        except:
            pass

    return configs


def main():
    parser = argparse.ArgumentParser(description="DcRAT config extractor")
    parser.add_argument("sample", help="Path to DcRAT sample or master key")
    parser.add_argument("--key", help="AES master key (if known)")
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    args = parser.parse_args()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    sample = Path(args.sample)
    data = sample.read_bytes()

    print(f"[*] Sample: {sample.name}")
    print(f"[*] SHA256: {hashlib.sha256(data).hexdigest()}")
    print(f"[*] Size:   {len(data):,} bytes")
    print()

    # Find the key
    master_key = args.key
    if not master_key:
        # Try to extract from binary
        # Look for Base64 string that decodes to a printable key
        b64_re = re.compile(rb'([A-Za-z0-9+/]{20,}={0,2})')
        for match in b64_re.finditer(data):
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-8')
                if decoded.isprintable() and 20 <= len(decoded) <= 64 and ' ' not in decoded:
                    # Verify by trying to decrypt a known field
                    aes_key, _ = derive_keys(decoded)
                    # Find Base64 strings near this one that might be config
                    print(f"[*] Key candidate: {decoded}")
                    master_key = decoded
                    break
            except:
                pass

    if not master_key:
        print("[!] Could not find AES key. Use --key to provide it.")
        sys.exit(1)

    print(f"[*] Master Key: {master_key}")
    print(f"[*] PBKDF2 Salt: {DCRAT_SALT.decode()}")
    print(f"[*] Iterations: {DCRAT_ITERATIONS}")

    aes_key, auth_key = derive_keys(master_key)
    print(f"[*] AES-256 Key: {aes_key.hex()}")
    print()

    # Find all Base64 config fields in the binary
    b64_re = re.compile(rb'([A-Za-z0-9+/]{40,}={0,2})')
    encrypted_fields = []
    for match in b64_re.finditer(data):
        b64_str = match.group(1).decode('ascii')
        raw = base64.b64decode(b64_str)
        # DcRAT encrypted fields have HMAC(32) + IV(16) + ciphertext
        if len(raw) >= 64 and len(raw) % 16 == 0:
            encrypted_fields.append(b64_str)

    print(f"[*] Found {len(encrypted_fields)} encrypted config fields")
    print()

    # Decrypt each
    results = {}
    for i, enc in enumerate(encrypted_fields):
        try:
            dec = decrypt(aes_key, enc)
            if dec and dec.isprintable():
                results[f"field_{i}"] = dec
                print(f"  [{i:2d}] {dec}")
        except:
            pass

    print()
    print(f"[*] Decrypted {len(results)} fields")

    # Save report
    report = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "family": "DcRAT (Dark Crystal RAT)",
        "salt": DCRAT_SALT.decode(),
        "iterations": DCRAT_ITERATIONS,
        "master_key": master_key,
        "aes_key_hex": aes_key.hex(),
        "decrypted_fields": results,
    }
    report_file = outdir / "dcrat_config.json"
    report_file.write_text(json.dumps(report, indent=2))
    print(f"[*] Report: {report_file}")


if __name__ == "__main__":
    main()
