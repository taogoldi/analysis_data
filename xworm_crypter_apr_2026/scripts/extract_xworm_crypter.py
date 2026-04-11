#!/usr/bin/env python3
"""
XWorm .NET Crypter — Payload Extractor & Config Decoder
========================================================
Extracts AES-encrypted payloads from .NET resource sections and
decrypts all XOR-encoded configuration strings from the XWorm RAT.

Handles:
  1. PBKDF2/AES-128-CBC decryption of embedded .NET resources
  2. PowerShell -EncodedCommand Base64+UTF-16LE decoding
  3. XWorm config field extraction from decompiled source

Usage:
    python extract_xworm_crypter.py <crypter.exe>

Requirements:
    pip install pycryptodome pefile

Author: Tao Goldi
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    print("ERROR: pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


# ─── Crypter parameters (extracted from ILSpy decompilation) ───
CRYPTER_CONFIG = {
    "password": "pvpbgplnnimrlzzeycztylmpyrriebystkbumwfydhcirtqazswjpvwchzcqxdimkvyayfsbxaprjexfaqilencxpylmupaayqxwuqcuaumnfftdcwphuxhxsalztehhzpttgakknpkjapsifikxztgahadudcavmfprmzwbletfmywdicukukhfiskgxrglnpxvaawflikvaanjealahqbbxiiupqeuxhsxaadhgpykzlfhebcwfgdxnwxrscrw",
    "salt": "erytiqjdxdutsqckdapnnhprdujedlpd",
    "iv": "xbginlypryzblkfy",
    "iterations": 100,
    "key_size": 16,
}


def derive_key(config: dict) -> bytes:
    """Derive AES key using PBKDF2."""
    return PBKDF2(
        config["password"].encode("ascii"),
        config["salt"].encode("ascii"),
        dkLen=config["key_size"],
        count=config["iterations"],
    )


def decrypt_aes(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-128-CBC decrypt with PKCS7 unpadding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if 0 < pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]
    return decrypted


def decrypt_string(key: bytes, iv: bytes, b64_ciphertext: str) -> str:
    """Decrypt a Base64-encoded AES string."""
    ciphertext = base64.b64decode(b64_ciphertext)
    plaintext = decrypt_aes(key, iv, ciphertext)
    return plaintext.decode("utf-8", errors="replace")


def decode_powershell(encoded: str) -> str:
    """Decode PowerShell -EncodedCommand (Base64 + UTF-16LE)."""
    return base64.b64decode(encoded).decode("utf-16-le")


def extract_payloads(data: bytes, key: bytes, iv: bytes) -> list[dict]:
    """Find and decrypt all byte-array resources (type tag 0x20)."""
    payloads = []
    offset = 0
    while offset < len(data) - 5:
        if data[offset] == 0x20:
            arr_len = struct.unpack("<I", data[offset + 1 : offset + 5])[0]
            if 10000 < arr_len < len(data) - offset and arr_len % 16 == 0:
                arr = data[offset + 5 : offset + 5 + arr_len]
                try:
                    dec = decrypt_aes(key, iv, arr)
                    if dec[:2] == b"MZ":
                        sha256 = hashlib.sha256(dec).hexdigest()
                        md5 = hashlib.md5(dec).hexdigest()
                        payloads.append({
                            "offset": f"0x{offset:06x}",
                            "encrypted_size": arr_len,
                            "decrypted_size": len(dec),
                            "sha256": sha256,
                            "md5": md5,
                            "is_pe": True,
                            "data": dec,
                        })
                except Exception:
                    pass
        offset += 1
    return payloads


def main():
    parser = argparse.ArgumentParser(
        description="XWorm .NET Crypter payload extractor"
    )
    parser.add_argument("sample", help="Path to the crypter .exe")
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    args = parser.parse_args()

    sample = Path(args.sample)
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    data = sample.read_bytes()
    print(f"[*] Sample: {sample.name}")
    print(f"[*] Size:   {len(data):,} bytes")
    print(f"[*] SHA256: {hashlib.sha256(data).hexdigest()}")
    print()

    # Derive AES key
    key = derive_key(CRYPTER_CONFIG)
    iv = CRYPTER_CONFIG["iv"].encode("ascii")
    print(f"[*] AES-128 key: {key.hex()}")
    print(f"[*] IV:          {iv.hex()}")
    print()

    # Decrypt embedded strings
    encrypted_strings = {
        "process": "unhE7C5xlI13pJXw8tBdQQ==",
        "env_var": "cXH4iZTK6WQg/FffdBuNyQ==",
        "payload1_name": "ZrwX5HdHueXTItWtRrhd2c8y62hC5xXWmSU2ff96Z6Y=",
        "payload2_name": "Rv6k7jJokoj9yTd9bokQvA4GuKnt3W9Q3sKitd9YtS4=",
        "exec_flag": "XYIWbEKBnediinnklTcmhw==",
    }

    print("[*] Decrypted strings:")
    decoded = {}
    for name, enc in encrypted_strings.items():
        dec = decrypt_string(key, iv, enc)
        decoded[name] = dec
        print(f"    {name}: {dec}")
    print()

    # Decode PowerShell commands
    ps_commands = [
        "PAAjAG0AZQBzACMAPgBBAGQAZAAtAFQAeQBwAGUAIAAtAEEAcwBzAGUAbQBiAGwAeQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsAPAAjAHAAbABrACMAPgBbAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwAuAE0AZQBzAHMAYQBnAGUAQgBvAHgAXQA6ADoAUwBoAG8AdwAoACcARQByAHIAbwByACAAMAB4ADAAMAAwADAANQAnACwAJwAnACwAJwBPAEsAJwAsACcARQByAHIAbwByACcAKQA8ACMAcgB5AHcAIwA+AA==",
        "PAAjAHIAdQBzACMAPgBBAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAAPAAjAGsAZwBnACMAPgAgAC0ARQB4AGMAbAB1AHMAaQBvAG4AUABhAHQAaAAgAEAAKAAkAGUAbgB2ADoAVQBzAGUAcgBQAHIAbwBmAGkAbABlACwAJABlAG4AdgA6AFMAeQBzAHQAZQBtAEQAcgBpAHYAZQApACAAPAAjAHcAagBoACMAPgAgAC0ARgBvAHIAYwBlACAAPAAjAGwAeQBuACMAPgA=",
    ]

    print("[*] Decoded PowerShell commands:")
    for i, enc in enumerate(ps_commands, 1):
        dec = decode_powershell(enc)
        print(f"    PS{i}: {dec}")
    print()

    # Extract and decrypt payloads
    print("[*] Extracting encrypted payloads from resources...")
    payloads = extract_payloads(data, key, iv)

    for i, p in enumerate(payloads, 1):
        outfile = outdir / f"payload{i}_{p['sha256'][:12]}.exe"
        outfile.write_bytes(p["data"])
        del p["data"]
        print(f"    Payload {i}: {p['decrypted_size']:,} bytes")
        print(f"      SHA256: {p['sha256']}")
        print(f"      MD5:    {p['md5']}")
        print(f"      Saved:  {outfile}")
    print()

    # Save report
    report = {
        "crypter": {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "size": len(data),
            "aes_key": key.hex(),
            "pbkdf2_password_length": len(CRYPTER_CONFIG["password"]),
            "pbkdf2_salt": CRYPTER_CONFIG["salt"],
            "pbkdf2_iterations": CRYPTER_CONFIG["iterations"],
            "iv": CRYPTER_CONFIG["iv"],
        },
        "decoded_strings": decoded,
        "powershell_commands": [
            decode_powershell(c) for c in ps_commands
        ],
        "payloads": [
            {k: v for k, v in p.items() if k != "data"} for p in payloads
        ],
    }

    report_file = outdir / "crypter_extraction_report.json"
    report_file.write_text(json.dumps(report, indent=2))
    print(f"[*] Report saved: {report_file}")


if __name__ == "__main__":
    main()
