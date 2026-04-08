#!/usr/bin/env python3
"""
Pulsar RAT - String Decoder

Decodes obfuscated strings found in the Pulsar RAT sample:
- Base64-encoded configuration values
- XOR-obfuscated strings (common in Quasar/Pulsar variants)
- .NET resource string tables
- Costura assembly manifest strings

Usage:
    python scripts/decode_strings.py [path_to_sample]

Output: reports/json/decoded_strings.json, reports/static/suspicious_strings.txt
"""

import base64
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
INPUT_DIR = PROJECT_ROOT / "input"
REPORTS_JSON = PROJECT_ROOT / "reports" / "json"
REPORTS_STATIC = PROJECT_ROOT / "reports" / "static"

# Suspicious string categories
SUSPICIOUS_KEYWORDS = {
    "c2_indicators": [
        "connect", "socket", "tcpclient", "webclient", "httpwebrequest",
        "download", "upload", "send", "receive", "beacon",
    ],
    "credential_theft": [
        "password", "credential", "cookie", "login", "decrypt", "dpapi",
        "chrome", "firefox", "opera", "brave", "browser", "wallet",
        "logins.json", "Login Data", "Web Data", "Cookies",
    ],
    "evasion": [
        "debugger", "sandbox", "vmware", "virtualbox", "vbox", "qemu",
        "wireshark", "fiddler", "procmon", "regmon", "ollydbg",
        "isdebuggerpresent", "checkremotedebugger", "ntquerysysteminformation",
        "processdebugport", "processdebugflags",
    ],
    "persistence": [
        "startup", "run\\", "runonce", "currentversion\\run",
        "scheduledjob", "taskscheduler", "autostart", "autorun",
    ],
    "keylogging": [
        "keylog", "getasynckeystate", "setwindowshookex", "wh_keyboard",
        "keydown", "keyup", "keystroke",
    ],
    "system_recon": [
        "systeminfo", "computername", "username", "osversion", "machinename",
        "getdrives", "environment", "processor", "totalphysicalmemory",
    ],
    "process_manipulation": [
        "createprocess", "openprocess", "writeprocessmemory", "virtualallocex",
        "ntqueryinformationprocess", "createremotethread", "inject",
    ],
    "file_operations": [
        "deletefile", "movefile", "copyfile", "createfile", "writefile",
        "getfiles", "getdirectories", "filestream", "ziparchive",
    ],
}


def extract_all_strings(data: bytes, min_length: int = 6) -> list[dict]:
    """Extract ASCII and UTF-16LE strings from binary."""
    strings = []

    # ASCII strings
    for match in re.finditer(rb"([\x20-\x7e]{%d,})" % min_length, data):
        s = match.group(1).decode("ascii", errors="replace")
        strings.append({"value": s, "encoding": "ascii", "offset": match.start()})

    # UTF-16LE strings (common in .NET)
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length, data):
        s = match.group(0).decode("utf-16-le", errors="replace")
        if s and not all(c in " \t\n\r" for c in s):
            strings.append({"value": s, "encoding": "utf-16-le", "offset": match.start()})

    return strings


def categorize_string(s: str) -> list[str]:
    """Categorize a string by matching against suspicious keyword sets."""
    categories = []
    s_lower = s.lower()
    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        if any(kw in s_lower for kw in keywords):
            categories.append(category)
    return categories


def decode_xor_candidates(data: bytes) -> list[dict]:
    """Try single-byte XOR decoding on high-entropy regions."""
    results = []
    # Find regions that look XOR-encoded (high entropy, consistent byte distribution)
    for key in range(1, 256):
        # Only try on small interesting regions, not the whole binary
        # Look for known Pulsar strings XOR'd
        targets = [b"Pulsar", b"Settings", b"Client", b"Server", b"Password"]
        for target in targets:
            xored = bytes(b ^ key for b in target)
            idx = data.find(xored)
            if idx != -1:
                # Decode surrounding context
                start = max(0, idx - 20)
                end = min(len(data), idx + 200)
                decoded_region = bytes(b ^ key for b in data[start:end])
                decoded_str = decoded_region.decode("ascii", errors="replace")
                # Filter to printable
                decoded_str = "".join(c if 32 <= ord(c) < 127 else "." for c in decoded_str)
                results.append({
                    "xor_key": f"0x{key:02X}",
                    "offset": idx,
                    "matched_target": target.decode(),
                    "decoded_context": decoded_str.strip(),
                })
    return results


def main():
    sample_path = None
    for candidate in INPUT_DIR.glob("*"):
        if candidate.is_file():
            sample_path = candidate
            break

    if sample_path:
        print(f"[*] Loading sample: {sample_path}")
        data = sample_path.read_bytes()
    else:
        print("[!] No sample in input/. Using FLOSS data from reports.")
        floss_path = REPORTS_JSON / "floss_summary.json"
        if not floss_path.exists():
            print("[!] No FLOSS data either. Nothing to decode.")
            return
        floss_data = json.loads(floss_path.read_text())
        _analyze_floss_strings(floss_data)
        return

    print(f"\n[*] Extracting strings (min length 6)...")
    all_strings = extract_all_strings(data)
    print(f"    Total strings: {len(all_strings)}")

    # Categorize
    suspicious = []
    for s in all_strings:
        cats = categorize_string(s["value"])
        if cats:
            s["categories"] = cats
            suspicious.append(s)

    print(f"    Suspicious strings: {len(suspicious)}")
    for cat in SUSPICIOUS_KEYWORDS:
        count = sum(1 for s in suspicious if cat in s.get("categories", []))
        if count:
            print(f"      {cat}: {count}")

    # XOR decode
    print(f"\n[*] Trying XOR decode...")
    xor_results = decode_xor_candidates(data)
    if xor_results:
        for r in xor_results:
            print(f"    Key={r['xor_key']}, matched '{r['matched_target']}' at 0x{r['offset']:X}")
            print(f"      -> {r['decoded_context'][:100]}")
    else:
        print("    No XOR-encoded config strings found (may use AES instead)")

    # Write reports
    REPORTS_JSON.mkdir(parents=True, exist_ok=True)
    REPORTS_STATIC.mkdir(parents=True, exist_ok=True)

    report = {
        "total_strings": len(all_strings),
        "suspicious_strings": suspicious[:200],
        "xor_decode_results": xor_results,
        "categories_summary": {
            cat: sum(1 for s in suspicious if cat in s.get("categories", []))
            for cat in SUSPICIOUS_KEYWORDS
        },
    }

    (REPORTS_JSON / "decoded_strings.json").write_text(json.dumps(report, indent=2))
    print(f"\n[*] Decoded strings report: reports/json/decoded_strings.json")

    # Write suspicious strings text file
    with open(REPORTS_STATIC / "suspicious_strings.txt", "w") as f:
        f.write(f"# Suspicious Strings - Pulsar RAT\n")
        f.write(f"# Total: {len(suspicious)} suspicious out of {len(all_strings)} total\n\n")
        for cat in SUSPICIOUS_KEYWORDS:
            cat_strings = [s for s in suspicious if cat in s.get("categories", [])]
            if cat_strings:
                f.write(f"\n## {cat.upper()} ({len(cat_strings)})\n")
                for s in cat_strings[:30]:
                    f.write(f"  0x{s['offset']:08X} [{s['encoding']}] {s['value'][:120]}\n")

    print(f"[*] Suspicious strings: reports/static/suspicious_strings.txt")


def _analyze_floss_strings(floss_data: dict):
    """Analyze strings from FLOSS report when no binary is available."""
    REPORTS_STATIC.mkdir(parents=True, exist_ok=True)

    iocs = floss_data.get("iocs", [])
    top_strings = floss_data.get("top_strings", [])

    print(f"[*] FLOSS IOCs: {len(iocs)}")
    print(f"[*] FLOSS top strings: {len(top_strings)}")

    # Categorize FLOSS strings
    suspicious = []
    for entry in top_strings:
        s = entry.get("string", "")
        cats = categorize_string(s)
        if cats:
            suspicious.append({"value": s, "categories": cats, "type": entry.get("type", "")})

    with open(REPORTS_STATIC / "suspicious_strings.txt", "w") as f:
        f.write(f"# Suspicious Strings - Pulsar RAT (from FLOSS data)\n")
        f.write(f"# IOCs: {len(iocs)}, Suspicious: {len(suspicious)}\n\n")

        f.write("## EMBEDDED HASHES (Costura DLLs)\n")
        for ioc in iocs:
            f.write(f"  [{ioc['ioc_type']}] {ioc['value']}\n")

        for cat in SUSPICIOUS_KEYWORDS:
            cat_strings = [s for s in suspicious if cat in s.get("categories", [])]
            if cat_strings:
                f.write(f"\n## {cat.upper()} ({len(cat_strings)})\n")
                for s in cat_strings[:30]:
                    f.write(f"  [{s['type']}] {s['value'][:120]}\n")

    print(f"[*] Wrote: reports/static/suspicious_strings.txt")


if __name__ == "__main__":
    main()
