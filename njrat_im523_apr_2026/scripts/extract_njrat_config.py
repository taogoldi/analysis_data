#!/usr/bin/env python3
"""
njRAT v0.7d Configuration Extractor
====================================
Extracts C2 server, port, mutex, campaign tag, and other config values
from njRAT .NET binaries by parsing UTF-16LE strings from the PE.

Usage:
    python extract_njrat_config.py <sample.exe>

Author: Tao Goldi
License: CC BY 4.0
"""

import base64
import hashlib
import json
import struct
import sys
from pathlib import Path


def extract_wide_strings(data: bytes, min_len: int = 3) -> list[tuple[int, str]]:
    """Extract UTF-16LE strings from binary data."""
    results = []
    i = 0
    while i < len(data) - 2:
        s = b""
        j = i
        while j < len(data) - 1:
            c = data[j] | (data[j + 1] << 8)
            if 0x20 <= c < 0x7F:
                s += bytes([c])
                j += 2
            else:
                break
        if len(s) >= min_len:
            results.append((i, s.decode("ascii", errors="replace")))
        i = max(j, i + 2)
    return results


def find_njrat_config(strings: list[tuple[int, str]]) -> dict:
    """Identify njRAT config fields from extracted strings."""
    config = {}

    # Build lookup
    str_map = {offset: value for offset, value in strings}
    str_list = [(offset, value) for offset, value in strings]

    # Find separator (njRAT signature)
    for offset, value in str_list:
        if value == "|'|'|":
            config["separator"] = value
            config["separator_offset"] = hex(offset)
            break

    # Find version string (im5XX pattern)
    for offset, value in str_list:
        if value.startswith("im5") and len(value) <= 8:
            config["version"] = value
            break

    # Find C2 host (domain or IP)
    for offset, value in str_list:
        if ("." in value and len(value) > 5 and
                not value.startswith("Software") and
                not value.endswith(".exe") and
                not value.endswith(".dll") and
                not value.endswith(".inf") and
                not value.endswith(".txt") and
                any(c.isalpha() for c in value) and
                "\\" not in value and " " not in value and
                not value.startswith("set ") and
                not value.startswith("HKEY")):
            if value.count(".") >= 1:
                config["c2_host"] = value
                config["c2_host_offset"] = hex(offset)
                break

    # Find mutex (32-char hex string = MD5)
    for offset, value in str_list:
        if len(value) == 32 and all(c in "0123456789abcdef" for c in value):
            config["mutex"] = value
            config["mutex_offset"] = hex(offset)
            break

    # Find campaign tag (Base64)
    for offset, value in str_list:
        if len(value) >= 4 and len(value) <= 40:
            try:
                decoded = base64.b64decode(value).decode("utf-8")
                if decoded.isprintable() and len(decoded) >= 2:
                    config["campaign_tag_b64"] = value
                    config["campaign_tag"] = decoded
                    break
            except Exception:
                continue

    # Find persistence key
    for offset, value in str_list:
        if "CurrentVersion\\Run" in value:
            config["persistence_key"] = value
            break

    # Find drop name
    for offset, value in str_list:
        if value.endswith(".exe") and len(value) < 30 and "cmd" not in value.lower():
            if "drop_name" not in config:
                config["drop_name"] = value

    # Find port (look near C2 host)
    if "c2_host_offset" in config:
        host_off = int(config["c2_host_offset"], 16)
        for offset, value in str_list:
            if abs(offset - host_off) < 100 and value.isdigit():
                port = int(value)
                if 1 <= port <= 65535:
                    config["c2_port"] = port
                    break

    return config


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sample.exe>", file=sys.stderr)
        sys.exit(1)

    sample = Path(sys.argv[1])
    data = sample.read_bytes()

    # Hashes
    print("=== SAMPLE HASHES ===")
    print(f"MD5:    {hashlib.md5(data).hexdigest()}")
    print(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
    print(f"Size:   {len(data):,} bytes")
    print()

    # Extract strings
    strings = extract_wide_strings(data)
    print(f"Wide strings extracted: {len(strings)}")
    print()

    # Find config
    config = find_njrat_config(strings)

    if not config:
        print("ERROR: No njRAT config found", file=sys.stderr)
        sys.exit(1)

    print("=== njRAT CONFIGURATION ===")
    for key, value in config.items():
        if not key.endswith("_offset"):
            print(f"  {key:25s} = {value}")
    print()

    # Output JSON
    json_path = sample.parent.parent / "reports" / "json" / "njrat_config.json"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(json_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Config written to {json_path}")


if __name__ == "__main__":
    main()
