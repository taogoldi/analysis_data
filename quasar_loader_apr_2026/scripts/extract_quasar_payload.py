#!/usr/bin/env python3
"""
Quasar RAT Loader: Payload Extractor + Config Decoder
=======================================================
Extracts the encrypted Quasar RAT payload from a custom native x64 loader
and decrypts the Quasar v1.4.1 C2 configuration.

The loader uses a custom byte-level cipher:
  1. Byte-pair swap across the entire buffer
  2. Per-byte: SUB(counter) -> SUB(0x10) -> XOR(counter-0x1B) -> ROR(5)

The Quasar config uses PBKDF2/AES-256-CBC/HMAC-SHA256 with a custom 32-byte salt.

Usage:
    python extract_quasar_payload.py <loader.exe> [--extract-config]

Requirements:
    pip install pefile pycryptodome

Author: Tao Goldi
"""

import argparse
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

try:
    import pefile
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    print("ERROR: pip install pefile pycryptodome", file=sys.stderr)
    sys.exit(1)


# ─── Loader Cipher Constants ───
ENCRYPTED_BLOB_OFFSET_IN_DATA = 0xA40  # offset within .data section
BLOB_SIZE = 0x31D5FF                    # 3,266,047 bytes
ANTI_SANDBOX_SLEEP_MS = 5000            # Sleep(5000) before decryption


def decrypt_loader_payload(pe_data: bytes) -> bytes:
    """
    Decrypt the encrypted payload from the loader's .data section.

    Algorithm (reversed from disassembly at 0x140001000):
      1. Byte-pair swap: for i in range(0, size, 2): swap(blob[i], blob[i+1])
      2. Per-byte cipher: for each byte at index i:
           cl = blob[i]
           cl = (cl - (i & 0xFF)) & 0xFF     # SUB counter
           cl = (cl - 0x10) & 0xFF            # SUB 16
           cl = cl ^ ((i - 0x1B) & 0xFF)      # XOR (counter - 27)
           cl = ROR(cl, 5)                     # rotate right 5 bits
           blob[i] = cl
    """
    pe = pefile.PE(data=pe_data)

    # Find .data section
    data_section = None
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        if name == ".data":
            data_section = s
            break

    if not data_section:
        raise ValueError(".data section not found")

    blob_file_offset = data_section.PointerToRawData + ENCRYPTED_BLOB_OFFSET_IN_DATA
    blob = bytearray(pe_data[blob_file_offset : blob_file_offset + BLOB_SIZE])

    print(f"[*] Encrypted blob: {len(blob):,} bytes at file offset 0x{blob_file_offset:x}")
    print(f"[*] First 16 bytes (encrypted): {bytes(blob[:16]).hex()}")

    # Step 1: Byte-pair swap
    print("[*] Step 1: Byte-pair swap...")
    i = 0
    while i < BLOB_SIZE:
        if i + 1 < len(blob):
            blob[i], blob[i + 1] = blob[i + 1], blob[i]
        i += 2

    # Step 2: Per-byte SUB + SUB + XOR + ROR cipher
    print("[*] Step 2: SUB + SUB + XOR + ROR per-byte decryption...")
    for i in range(len(blob)):
        cl = blob[i]
        counter_low = i & 0xFF
        al = (i - 0x1B) & 0xFF

        cl = (cl - counter_low) & 0xFF  # SUB counter
        cl = (cl - 0x10) & 0xFF         # SUB 16
        cl = cl ^ al                     # XOR (counter - 27)
        cl = ((cl >> 5) | (cl << 3)) & 0xFF  # ROR 5
        blob[i] = cl

    print(f"[*] First 16 bytes (decrypted): {bytes(blob[:16]).hex()}")

    # Verify MZ header
    if blob[:2] != b"MZ":
        print("[!] WARNING: Decrypted data does not start with MZ header")
    else:
        pe_offset = struct.unpack("<I", blob[0x3C:0x40])[0]
        if blob[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            print(f"[+] PE header confirmed at offset 0x{pe_offset:x}")

    return bytes(blob)


# ─── Quasar Config Decryption ───
QUASAR_SALT = bytes([
    191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
    2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
    210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
    57, 65,
])
QUASAR_ITERATIONS = 50000


def decrypt_quasar_config(master_key: str, encrypted_fields: dict) -> dict:
    """Decrypt Quasar v1.4.1 AES-256-CBC config fields."""
    derived = PBKDF2(master_key, QUASAR_SALT, dkLen=96, count=QUASAR_ITERATIONS)
    aes_key = derived[:32]

    results = {}
    for name, b64_value in encrypted_fields.items():
        try:
            raw = base64.b64decode(b64_value)
            # Format: [HMAC-SHA256 (32)][IV (16)][AES-CBC ciphertext]
            iv = raw[32:48]
            ct = raw[48:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            dec = cipher.decrypt(ct)
            pad_len = dec[-1]
            if 0 < pad_len <= 16:
                dec = dec[:-pad_len]
            results[name] = dec.decode("utf-8", errors="replace")
        except Exception as e:
            results[name] = f"ERROR: {e}"

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Quasar RAT loader payload extractor + config decoder"
    )
    parser.add_argument("sample", help="Path to the loader executable")
    parser.add_argument(
        "--extract-config",
        action="store_true",
        help="Also extract Quasar C2 config from the decrypted payload",
    )
    parser.add_argument(
        "--key",
        default="45567C0614C4584B61EF8AB3B378784EFE4A57F8",
        help="Quasar encryption key (default: extracted from this sample)",
    )
    parser.add_argument("-o", "--output", default=".", help="Output directory")
    args = parser.parse_args()

    sample = Path(args.sample)
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    pe_data = sample.read_bytes()

    print(f"[*] Loader: {sample.name}")
    print(f"[*] SHA256: {hashlib.sha256(pe_data).hexdigest()}")
    print(f"[*] Size:   {len(pe_data):,} bytes")
    print()

    # Extract payload
    payload = decrypt_loader_payload(pe_data)
    payload_hash = hashlib.sha256(payload).hexdigest()

    outfile = outdir / f"quasar_payload_{payload_hash[:12]}.exe"
    outfile.write_bytes(payload)
    print(f"\n[+] Payload extracted: {outfile}")
    print(f"[+] SHA256: {payload_hash}")
    print(f"[+] Size:   {len(payload):,} bytes")

    # Check if it's .NET
    try:
        payload_pe = pefile.PE(data=payload)
        clr = payload_pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        is_dotnet = clr.Size > 0
        print(f"[+] .NET:   {is_dotnet}")
        print(f"[+] Machine: {hex(payload_pe.FILE_HEADER.Machine)}")

        # Check version info
        if hasattr(payload_pe, "FileInfo"):
            for entry in payload_pe.FileInfo:
                for st in entry:
                    if hasattr(st, "StringTable"):
                        for table in st.StringTable:
                            for k, v in table.entries.items():
                                k_str = k.decode()
                                v_str = v.decode()
                                if v_str and k_str in (
                                    "FileDescription",
                                    "ProductName",
                                    "FileVersion",
                                ):
                                    print(f"[+] {k_str}: {v_str}")
    except Exception:
        pass

    # Extract Quasar config
    if args.extract_config:
        print(f"\n[*] Decrypting Quasar config with key: {args.key}")

        # Known encrypted fields from this sample
        encrypted_fields = {
            "Version": "vwPa2r5ojNTjqo2AqI47vPs3PCAM1KuR7IVOjDZNMQmUpI8HdddKl6+PwudJbtORHf1jWeQVhd/z2DfXetXDnA==",
            "C2_Hosts": "cM6dedB3MxmXiZNaVITAymTPRcnO6npIC9NLSQ4VaJUk5KTNOWkOn1IxB9IFiatQxdDKJ9NEWaRoCk7lShkxZPie2wQpvl8Zc6t0VfyW82s=",
            "SubDir": "i1UdSeWYnWjuFFEZfd4mlJ5vyVxPWD3+lmdGGMmiU8ouDYIwXj63J2w3pKLYmAIiDjWMyLEt9W6wr5D+YH+YfA==",
            "FileName": "1pSqyT72rSfhfJ0CJsYlonpocVltsmz2APXXgzBRhqJLhXdvIkmzaDWFmQ2P8xk2XajR9QpYaHPqwpEPiCkhWQ==",
            "Mutex": "jhIpM6Gr0s4RG1qdv4cz3TUyJqb0JJaYta8/m6+IQtP5neTeM9npswBOQ0NcGjObzfySvIMYgKSPPX99GWwLTA==",
            "StartupKey": "fdKMHmWxH7LqLNzGqxyZmWprxLAJlkyIF2nL3hpsOzJ3CGVSQRoPYgi3nyT34OrXxOMbMYveMk/1VDtpW7bl0qG9rkSyvo/Kfii3OYV4u7TZEpmOU2KioQ7WInlpfyWj",
            "LogDir": "uwbokc0AhrWugPDV3f95J0S0wqdvjTh1/wxQ2/xU45X1B3yPn94sldzJlcOyxGszaH6Ot4udaF3QdwynmdZW0k/9pyVVzgJGleeRlUzgSQk=",
            "ServerSignature": "N44FH0tQDxrJglD8xR/N1qQK3U/Gp1yoShA73qe4KrODwnbKAmAmu4AxyntU3nCNr8YLzmfeX1fPd/Q7oWqm/A==",
        }

        config = decrypt_quasar_config(args.key, encrypted_fields)
        print("\n[+] Decrypted Quasar Config:")
        for name, value in config.items():
            print(f"    {name:15s} = {value}")

        # Save report
        report = {
            "loader": {
                "sha256": hashlib.sha256(pe_data).hexdigest(),
                "size": len(pe_data),
                "cipher": "byte-swap + SUB + SUB + XOR + ROR5",
            },
            "payload": {
                "sha256": payload_hash,
                "size": len(payload),
                "family": "Quasar RAT v1.4.1",
            },
            "config": config,
            "encryption_key": args.key,
        }
        report_file = outdir / "quasar_extraction_report.json"
        report_file.write_text(json.dumps(report, indent=2))
        print(f"\n[+] Report: {report_file}")


if __name__ == "__main__":
    main()
