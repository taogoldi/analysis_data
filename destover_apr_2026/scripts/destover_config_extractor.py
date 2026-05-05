#!/usr/bin/env python3
"""
Destover backdoor static config extractor.

Pulls the hard-coded C2 IPs, the obfuscated import-table cleartext, and
key Authenticode metadata out of a Destover/Wiper sample without executing
it. The dot-space junk in the API name strings is stripped by a single
character class regex; that is the entire de-obfuscation step the malware
itself does at runtime before passing the cleaned name to GetProcAddress.

Author: Tao Goldi
Reference: https://taogoldi.github.io/reverse-engineer/

Usage:
    python destover_config_extractor.py <sample.exe>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# ---------- helpers ---------------------------------------------------------

def hashes(buf: bytes) -> dict[str, str]:
    return {
        "md5":    hashlib.md5(buf).hexdigest(),
        "sha1":   hashlib.sha1(buf).hexdigest(),
        "sha256": hashlib.sha256(buf).hexdigest(),
    }


# Wide string carved out of a UTF-16LE region: any printable ASCII followed
# by a null byte, repeated >= 6 times, terminated by a wide null.
_WIDE_RX = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_ASCII_RX = re.compile(rb"[\x20-\x7e]{6,}")


def find_wide(buf: bytes) -> list[str]:
    return [m.group(0).decode("utf-16le", errors="ignore")
            for m in _WIDE_RX.finditer(buf)]


def find_ascii(buf: bytes) -> list[str]:
    return [m.group(0).decode("ascii", errors="ignore")
            for m in _ASCII_RX.finditer(buf)]


_IPV4_RX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def carve_c2(wide_strings: list[str]) -> list[str]:
    """Pull IPv4 literals from the wide-string corpus, drop placeholders."""
    out = []
    seen = set()
    for s in wide_strings:
        if not _IPV4_RX.match(s):
            continue
        if s == "0.0.0.0":           # placeholder used to seed the table
            continue
        if s.startswith("127."):     # local probe addresses
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


# An obfuscated import is an ASCII string composed of letters, dots and
# spaces whose collapsed form starts with a capital letter and looks like
# a Win32 API name. We bound the form to avoid pulling normal English
# sentences out of resource strings.
_API_LIKE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,40}$")


def decode_obfuscated_apis(ascii_strings: list[str]) -> list[str]:
    """Strip dot-space junk from the API name table and keep API-shaped names."""
    seen: set[str] = set()
    out: list[str] = []
    for s in ascii_strings:
        # Only consider strings that contain both a dot and a space, since
        # the encoder always inserts both classes of junk.
        if "." not in s or " " not in s:
            continue
        cleaned = re.sub(r"[.\s]", "", s)
        if not _API_LIKE.match(cleaned):
            continue
        # Heuristic filter: lowercase first letter is rarely an API name in
        # this binary; the ones we want all begin with an uppercase letter
        # or start with a known prefix.
        if not (cleaned[0].isupper() or cleaned.startswith("inet_")
                or cleaned.startswith("__")):
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def extract_signer(buf: bytes) -> dict[str, str | None]:
    """Pull the Authenticode signer common-name out of the embedded PKCS#7.

    Avoids parsing ASN.1: the relevant strings (signer CN, locality, issuer)
    appear verbatim in the certificate and a substring search is sufficient
    for the SPE-signed Destover variant we care about here.
    """
    text = buf.decode("latin1", errors="ignore")
    signer = "Sony Pictures Entertainment Inc." if \
        "Sony Pictures Entertainment Inc." in text else None
    issuer = "DigiCert Assured ID Code Signing CA-1" if \
        "DigiCert Assured ID Code Signing CA-1" in text else None
    locality = "Culver City" if "CULVER CITY" in text else None
    return {"signer_cn": signer, "issuer_cn": issuer, "locality": locality}


def extract_version_info(buf: bytes) -> dict[str, str | None]:
    """Pull the masquerade markers from VS_VERSION_INFO without parsing it."""
    text = buf.decode("utf-16le", errors="ignore")
    fields = {}
    for k in ("CompanyName", "FileDescription", "InternalName",
              "OriginalFilename", "ProductName"):
        i = text.find(k)
        if i < 0:
            fields[k] = None
            continue
        # value follows the key, separated by null terminators which the
        # ignore-decode collapsed; take the next non-empty printable token
        rest = text[i + len(k):i + len(k) + 80]
        rest = rest.lstrip("\x00 ").rstrip("\x00 ")
        fields[k] = rest.split("\x00", 1)[0] if rest else None
    return fields


# ---------- main ------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sample", help="Path to the suspected Destover binary")
    ap.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON instead of the human report")
    args = ap.parse_args()

    p = Path(args.sample)
    buf = p.read_bytes()
    h = hashes(buf)

    wide = find_wide(buf)
    ascii_ = find_ascii(buf)

    config = {
        "sample":            str(p),
        "size":              len(buf),
        "hashes":            h,
        "c2_servers":        carve_c2(wide),
        "obfuscated_apis":   decode_obfuscated_apis(ascii_),
        "signer":            extract_signer(buf),
        "version_info":      extract_version_info(buf),
    }

    if args.json:
        print(json.dumps(config, indent=2, sort_keys=False))
        return 0

    print(f"--- Destover static config extraction ---")
    print(f"  file   : {p}")
    print(f"  size   : {config['size']} bytes")
    print(f"  md5    : {h['md5']}")
    print(f"  sha256 : {h['sha256']}")
    print()
    print(f"--- Authenticode signer ---")
    for k, v in config["signer"].items():
        print(f"  {k:14s}: {v}")
    print()
    print(f"--- VS_VERSION_INFO masquerade ---")
    for k, v in config["version_info"].items():
        print(f"  {k:18s}: {v}")
    print()
    print(f"--- C2 servers ---")
    if not config["c2_servers"]:
        print("  (none recovered)")
    for ip in config["c2_servers"]:
        print(f"  {ip}")
    print()
    print(f"--- Decoded obfuscated APIs ({len(config['obfuscated_apis'])}) ---")
    for name in config["obfuscated_apis"]:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
