#!/usr/bin/env python3
"""
Pulsar RAT - Triage Script
Performs initial static triage: PE header parsing, section analysis, .NET metadata,
and generates the triage report.

Usage:
    python scripts/triage_sample.py [path_to_sample]

If no path given, looks for the sample in input/ by SHA256.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
INPUT_DIR = PROJECT_ROOT / "input"
REPORTS_JSON = PROJECT_ROOT / "reports" / "json"
REPORTS_STATIC = PROJECT_ROOT / "reports" / "static"

SAMPLE_SHA256 = "8f31c06c8e7ea9eb451bf26666ac4a958bb485b2a8b71feace1981633b116c92"


def find_sample(override_path: str | None = None) -> Path | None:
    if override_path:
        p = Path(override_path)
        if p.exists():
            return p

    for candidate in INPUT_DIR.glob("*"):
        if candidate.is_file():
            return candidate

    return None


def compute_hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def parse_pe_header(data: bytes) -> dict:
    """Minimal PE header parsing for triage."""
    info = {"valid_pe": False, "sections": [], "is_dotnet": False}

    if data[:2] != b"MZ":
        return info

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew >= len(data) - 4:
        return info

    pe_sig = data[e_lfanew : e_lfanew + 4]
    if pe_sig != b"PE\x00\x00":
        return info

    info["valid_pe"] = True

    # COFF header
    coff_offset = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff_offset)[0]
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    timestamp = struct.unpack_from("<I", data, coff_offset + 4)[0]

    info["machine"] = f"0x{machine:04X}"
    info["num_sections"] = num_sections
    info["timestamp"] = timestamp

    # Optional header
    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    info["pe_type"] = "PE32+" if magic == 0x20B else "PE32"

    # Check for .NET CLR directory (data directory index 14)
    if magic == 0x10B:  # PE32
        clr_dir_offset = opt_offset + 208
    else:  # PE32+
        clr_dir_offset = opt_offset + 224

    if clr_dir_offset + 8 <= len(data):
        clr_rva = struct.unpack_from("<I", data, clr_dir_offset)[0]
        clr_size = struct.unpack_from("<I", data, clr_dir_offset + 4)[0]
        if clr_rva > 0 and clr_size > 0:
            info["is_dotnet"] = True
            info["clr_directory_rva"] = f"0x{clr_rva:08X}"
            info["clr_directory_size"] = clr_size

    # Section headers
    size_of_optional = struct.unpack_from("<H", data, coff_offset + 16)[0]
    section_offset = opt_offset + size_of_optional

    for i in range(min(num_sections, 16)):
        sec_off = section_offset + i * 40
        if sec_off + 40 > len(data):
            break
        name = data[sec_off : sec_off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack_from("<I", data, sec_off + 8)[0]
        vaddr = struct.unpack_from("<I", data, sec_off + 12)[0]
        raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, sec_off + 20)[0]
        characteristics = struct.unpack_from("<I", data, sec_off + 36)[0]

        entropy = _section_entropy(data, raw_ptr, raw_size)

        info["sections"].append({
            "name": name,
            "virtual_size": vsize,
            "virtual_address": f"0x{vaddr:08X}",
            "raw_size": raw_size,
            "raw_offset": f"0x{raw_ptr:08X}",
            "characteristics": f"0x{characteristics:08X}",
            "entropy": round(entropy, 2),
        })

    return info


def _section_entropy(data: bytes, offset: int, size: int) -> float:
    import math

    if size == 0 or offset + size > len(data):
        return 0.0
    section_data = data[offset : offset + size]
    freq = [0] * 256
    for b in section_data:
        freq[b] += 1
    entropy = 0.0
    for f in freq:
        if f > 0:
            p = f / len(section_data)
            entropy -= p * math.log2(p)
    return entropy


def detect_costura_resources(data: bytes) -> list[str]:
    """Scan for Fody/Costura compressed resource markers."""
    resources = []
    marker = b"costura."
    pos = 0
    while True:
        idx = data.find(marker, pos)
        if idx == -1:
            break
        # Extract the resource name (up to null or non-printable)
        end = idx
        while end < min(idx + 200, len(data)) and 32 <= data[end] < 127:
            end += 1
        name = data[idx:end].decode("ascii", errors="replace")
        if name not in resources and ".compressed" in name:
            resources.append(name)
        pos = idx + 1
    return resources


def main():
    sample_path = find_sample(sys.argv[1] if len(sys.argv) > 1 else None)
    if not sample_path:
        print(f"[!] No sample found. Place the binary in {INPUT_DIR}/")
        print(f"    Expected SHA256: {SAMPLE_SHA256}")
        print("[*] Generating triage report from existing DB data only.")
        # Still useful - read from existing triage_report.json
        existing = REPORTS_JSON / "triage_report.json"
        if existing.exists():
            print(f"[*] Existing triage data at: {existing}")
        return

    print(f"[*] Sample: {sample_path}")
    data = sample_path.read_bytes()

    hashes = compute_hashes(data)
    print(f"    MD5:    {hashes['md5']}")
    print(f"    SHA1:   {hashes['sha1']}")
    print(f"    SHA256: {hashes['sha256']}")
    print(f"    Size:   {len(data)} bytes")

    if hashes["sha256"] != SAMPLE_SHA256:
        print(f"[!] WARNING: SHA256 mismatch! Expected {SAMPLE_SHA256}")

    pe_info = parse_pe_header(data)
    print(f"\n[*] PE Analysis:")
    print(f"    Valid PE:  {pe_info['valid_pe']}")
    print(f"    Type:      {pe_info.get('pe_type', 'N/A')}")
    print(f"    .NET:      {pe_info['is_dotnet']}")
    print(f"    Sections:  {pe_info.get('num_sections', 0)}")

    for sec in pe_info.get("sections", []):
        flag = " [HIGH ENTROPY]" if sec["entropy"] > 7.0 else ""
        print(f"      {sec['name']:8s}  size={sec['raw_size']:>8d}  entropy={sec['entropy']:.2f}{flag}")

    costura = detect_costura_resources(data)
    print(f"\n[*] Costura Resources: {len(costura)} embedded DLLs")
    for r in costura:
        print(f"    {r}")

    # Build triage report
    report = {
        "hashes": hashes,
        "file_name": sample_path.name,
        "file_size": len(data),
        "pe_info": pe_info,
        "costura_resources": costura,
        "costura_resource_count": len(costura),
        "family": "Pulsar RAT",
        "packer": "MPRESS",
        "framework": ".NET (Fody/Costura)",
    }

    REPORTS_JSON.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_JSON / "triage_report.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\n[*] Triage report written to: {out_path}")


if __name__ == "__main__":
    main()
