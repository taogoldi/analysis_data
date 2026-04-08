#!/usr/bin/env python3
"""
Pulsar RAT - Costura/Fody Embedded DLL Extractor

Extracts compressed .NET resources embedded via Fody/Costura.
Each resource is named 'costura.<assembly>.dll.compressed' and stored
as a deflate-compressed blob inside .NET managed resources.

Usage:
    python scripts/extract_costura.py [path_to_sample]

Output: artifacts/ directory with extracted DLLs
"""

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
INPUT_DIR = PROJECT_ROOT / "input"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
REPORTS_JSON = PROJECT_ROOT / "reports" / "json"

# Known Costura resource names from FLOSS analysis
KNOWN_RESOURCES = [
    "costura.messagepack.dll.compressed",
    "costura.messagepack.annotations.dll.compressed",
    "costura.system.buffers.dll.compressed",
    "costura.system.collections.immutable.dll.compressed",
    "costura.system.memory.dll.compressed",
    "costura.system.numerics.vectors.dll.compressed",
    "costura.system.runtime.compilerservices.unsafe.dll.compressed",
    "costura.system.threading.tasks.extensions.dll.compressed",
    "costura.pulsar.common.dll.compressed",
]


def find_sample() -> Path | None:
    for candidate in INPUT_DIR.glob("*"):
        if candidate.is_file() and candidate.suffix in (".exe", ".dll", ""):
            return candidate
    return None


def extract_dotnet_resources(data: bytes) -> list[tuple[str, bytes]]:
    """
    Search for Costura-compressed resources in .NET assembly.
    Costura stores each DLL as a deflate-compressed blob.
    The resource name appears as a UTF-16 or UTF-8 string before the blob.
    """
    extracted = []

    for resource_name in KNOWN_RESOURCES:
        # Search for the resource name marker in the binary
        marker_utf8 = resource_name.encode("utf-8")
        marker_utf16 = resource_name.encode("utf-16-le")

        for marker in [marker_utf8, marker_utf16]:
            pos = 0
            while True:
                idx = data.find(marker, pos)
                if idx == -1:
                    break

                # After the resource name, scan for a deflate stream
                # Costura typically has a small header then the compressed data
                search_start = idx + len(marker)
                blob = _find_deflate_stream(data, search_start, search_start + 2048)
                if blob:
                    dll_name = resource_name.replace("costura.", "").replace(".compressed", "")
                    extracted.append((dll_name, blob))
                    print(f"  [+] {dll_name}: {len(blob)} bytes decompressed")
                    break

                pos = idx + 1

    return extracted


def _find_deflate_stream(data: bytes, start: int, end: int) -> bytes | None:
    """Try to find and decompress a deflate stream in the given range."""
    for offset in range(start, min(end, len(data) - 2)):
        # Deflate streams commonly start with 0x78 (zlib header)
        if data[offset] == 0x78 and data[offset + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            try:
                decompressed = zlib.decompress(data[offset:offset + 1024 * 1024])
                if len(decompressed) > 100:  # Sanity check
                    return decompressed
            except (zlib.error, OverflowError):
                continue

        # Also try raw deflate (no zlib header) - Costura uses this sometimes
        try:
            decompressed = zlib.decompress(data[offset:offset + 1024 * 1024], -15)
            if len(decompressed) > 1000 and decompressed[:2] == b"MZ":
                return decompressed
        except (zlib.error, OverflowError):
            continue

    return None


def main():
    sample_path = find_sample()
    if not sample_path:
        print("[!] No sample found in input/. Place the binary there first.")
        print("[*] Skipping Costura extraction - will use IOC report data.")
        return

    print(f"[*] Loading sample: {sample_path}")
    data = sample_path.read_bytes()
    print(f"    Size: {len(data)} bytes")

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] Scanning for Costura-compressed resources...")
    extracted = extract_dotnet_resources(data)

    if not extracted:
        print("[!] No Costura resources decompressed.")
        print("    The sample may use a custom Costura loader or the resources")
        print("    may be additionally encrypted. Try dnSpy for manual extraction.")
        return

    # Write extracted DLLs
    manifest = []
    for dll_name, dll_data in extracted:
        out_path = ARTIFACTS_DIR / dll_name
        out_path.write_bytes(dll_data)
        sha256 = hashlib.sha256(dll_data).hexdigest()
        manifest.append({
            "name": dll_name,
            "size": len(dll_data),
            "sha256": sha256,
            "output_path": str(out_path.relative_to(PROJECT_ROOT)),
        })
        print(f"  [*] Wrote {dll_name} ({len(dll_data)} bytes, SHA256: {sha256[:16]}...)")

    # Write extraction manifest
    manifest_path = REPORTS_JSON / "costura_extraction.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"\n[*] Extraction manifest: {manifest_path}")
    print(f"[*] Total extracted: {len(extracted)} DLLs")


if __name__ == "__main__":
    main()
