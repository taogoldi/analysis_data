#!/usr/bin/env python3
"""
Pulsar RAT - Configuration Extractor

Extracts C2 configuration from Pulsar RAT samples including:
- C2 server address and port
- AES-256 encryption key / passphrases
- Mutex name
- Installation path and registry keys
- Campaign ID / group tag

Pulsar RAT (a QuasarRAT fork) stores its config in a dedicated Settings class
with Base64-encoded or plaintext values. The config may also be AES-encrypted
with a hardcoded key.

Usage:
    python scripts/extract_config.py [path_to_sample]

Output: reports/json/config_report.json
"""

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
INPUT_DIR = PROJECT_ROOT / "input"
REPORTS_JSON = PROJECT_ROOT / "reports" / "json"

# Patterns for .NET string metadata table references
# Pulsar/Quasar config fields are typically stored as string constants
CONFIG_PATTERNS = {
    "c2_host": [
        rb"(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?)",
        rb"(?:https?://)?([\w.-]+\.(?:com|net|org|io|xyz|top|ru|cn|tk|cc|pw)(?::\d{1,5})?)",
    ],
    "mutex": [
        rb"([A-Za-z0-9]{8,32}(?:Mutex|_mtx|MUTEX))",
        rb"(?:Mutex|mutex|MUTEX)[\"'\s:=]+([A-Za-z0-9_-]{8,64})",
    ],
    "aes_key": [
        rb"(?:AES|Aes|aes|Key|key|Password|password|Passphrase)[\"'\s:=]+([A-Za-z0-9+/=]{16,64})",
        rb"(?:EncryptionKey|DecryptionKey|CryptoKey)[\"'\s:=]+([A-Za-z0-9+/=]{16,64})",
    ],
    "install_path": [
        rb"(%(?:AppData|Temp|ProgramData|LocalAppData)%[\\\/][\w\\\/.-]+\.exe)",
        rb"(C:\\(?:Users|Windows|ProgramData)\\[^\x00]{5,120}\.exe)",
    ],
    "tag": [
        rb"(?:Tag|tag|Group|group|Campaign)[\"'\s:=]+([A-Za-z0-9_-]{2,32})",
    ],
    "version": [
        rb"(?:Version|version)[\"'\s:=]+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",
        rb"Pulsar[.,\s]+(?:Version\s+)?(\d+\.\d+\.\d+)",
    ],
}

# .NET UserString heap marker patterns
DOTNET_STRING_PATTERNS = [
    # Base64-encoded config values (common in Quasar/Pulsar)
    rb"([A-Za-z0-9+/]{20,}={0,2})",
]


def extract_config_from_binary(data: bytes) -> dict:
    """Extract configuration values using pattern matching."""
    config = {}

    for field, patterns in CONFIG_PATTERNS.items():
        matches = set()
        for pattern in patterns:
            for match in re.finditer(pattern, data):
                value = match.group(1).decode("ascii", errors="replace").strip()
                if len(value) > 2:
                    matches.add(value)
        if matches:
            config[field] = sorted(matches)

    return config


def extract_base64_candidates(data: bytes) -> list[dict]:
    """Find and decode Base64-encoded strings that might be config values."""
    candidates = []
    seen = set()

    for match in re.finditer(rb"([A-Za-z0-9+/]{24,512}={0,2})", data):
        b64_str = match.group(1).decode("ascii", errors="replace")
        if b64_str in seen:
            continue
        seen.add(b64_str)

        try:
            decoded = base64.b64decode(b64_str)
            # Check if it decodes to something meaningful
            if all(32 <= b < 127 for b in decoded) and len(decoded) > 4:
                decoded_str = decoded.decode("ascii")
                candidates.append({
                    "encoded": b64_str,
                    "decoded": decoded_str,
                    "offset": match.start(),
                    "looks_like": _classify_decoded(decoded_str),
                })
            elif decoded[:2] == b"MZ":
                candidates.append({
                    "encoded": b64_str[:40] + "...",
                    "decoded": f"[PE binary, {len(decoded)} bytes]",
                    "offset": match.start(),
                    "looks_like": "embedded_pe",
                })
        except Exception:
            continue

    return candidates


def _classify_decoded(value: str) -> str:
    """Classify a decoded Base64 string."""
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value):
        return "ip_address"
    if re.match(r"[\w.-]+\.(com|net|org|io|xyz|ru|cn)", value):
        return "domain"
    if "\\" in value and value.endswith(".exe"):
        return "file_path"
    if len(value) >= 16 and re.match(r"[A-Za-z0-9+/=]+$", value):
        return "possible_key"
    return "unknown"


def extract_dotnet_strings(data: bytes) -> list[str]:
    """Extract strings from .NET UserString heap (simplified)."""
    strings = []
    # .NET metadata signature
    idx = data.find(b"BSJB")
    if idx == -1:
        return strings

    # Look for readable strings near the metadata
    for match in re.finditer(rb"([\x20-\x7e]{8,256})", data[idx:]):
        s = match.group(1).decode("ascii", errors="replace")
        # Filter for config-relevant strings
        keywords = ["mutex", "key", "aes", "password", "install", "startup",
                     "registry", "version", "tag", "group", "server", "port",
                     "pulsar", "quasar", "client", "admin"]
        if any(kw in s.lower() for kw in keywords):
            strings.append(s)

    return list(set(strings))[:100]


def main():
    sample_path = None
    for candidate in INPUT_DIR.glob("*"):
        if candidate.is_file():
            sample_path = candidate
            break

    if not sample_path:
        print("[!] No sample found in input/. Generating config template from known data.")
        config = {
            "family": "Pulsar RAT",
            "version": "2.4.5.0",
            "encryption": {
                "algorithm": "AES-256",
                "mode": "CBC",
                "key_derivation": "SHA256(passphrase)",
                "serialization": "MessagePack 3.1.4.0",
                "note": "Place sample in input/ to extract actual encryption keys",
            },
            "c2": {
                "protocol": "TCP with AES-256 encryption",
                "serialization": "MessagePack",
                "note": "Place sample in input/ to extract actual C2 address",
            },
            "capabilities": [
                "Remote desktop / screen capture",
                "Keylogger (application hook)",
                "Clipboard monitoring",
                "Browser credential theft (Chrome/Firefox/Opera/Brave)",
                "DPAPI credential store decryption",
                "File manager (upload/download/delete)",
                "Process manager (list/kill/start)",
                "Registry editor",
                "Remote shell",
                "UAC bypass",
                "System information gathering",
                "Network connection enumeration",
            ],
            "anti_analysis": [
                "IsDebuggerPresent check",
                "ProcessDebugPort / ProcessDebugFlags queries",
                "Sandbox hostname/username detection",
                "Delayed execution (sleep-based evasion)",
            ],
            "persistence_mechanisms": [
                "Registry file association hijacking",
                "Startup folder entry",
                "Registry Run key",
            ],
        }

        REPORTS_JSON.mkdir(parents=True, exist_ok=True)
        out_path = REPORTS_JSON / "config_report.json"
        out_path.write_text(json.dumps(config, indent=2))
        print(f"[*] Config template written to: {out_path}")
        return

    print(f"[*] Loading sample: {sample_path}")
    data = sample_path.read_bytes()

    print(f"\n[*] Extracting configuration patterns...")
    config = extract_config_from_binary(data)
    for field, values in config.items():
        print(f"    {field}: {values}")

    print(f"\n[*] Scanning Base64-encoded values...")
    b64_candidates = extract_base64_candidates(data)
    for c in b64_candidates[:20]:
        print(f"    [{c['looks_like']}] {c['decoded'][:80]}")

    print(f"\n[*] Extracting .NET metadata strings...")
    dotnet_strings = extract_dotnet_strings(data)
    for s in dotnet_strings[:20]:
        print(f"    {s}")

    # Build config report
    report = {
        "family": "Pulsar RAT",
        "extracted_config": config,
        "base64_decoded": b64_candidates[:50],
        "dotnet_config_strings": dotnet_strings,
    }

    REPORTS_JSON.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_JSON / "config_report.json"
    out_path.write_text(json.dumps(report, indent=2))
    print(f"\n[*] Config report: {out_path}")


if __name__ == "__main__":
    main()
