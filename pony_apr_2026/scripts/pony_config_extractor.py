#!/usr/bin/env python3
"""
Pony / Fareit config extractor.

Pulls URLs, FTP/browser targets, HWID format, HTTP fingerprints,
and the entry-point anti-emulation stub from a Pony stealer PE.

Usage:
    python3 pony_config_extractor.py <sample.exe>
"""

import argparse
import json
import re
import struct
import sys
from dataclasses import asdict, dataclass, field
from typing import List, Optional

import pefile


@dataclass
class PonyConfig:
    sha256: str = ""
    md5: str = ""
    image_base: int = 0
    entry_point: int = 0
    compile_stamp: int = 0
    dead_drop_urls: List[str] = field(default_factory=list)
    payload_urls: List[str] = field(default_factory=list)
    hwid_format: Optional[str] = None
    user_agent: Optional[str] = None
    http_post_template: Optional[str] = None
    http_get_template: Optional[str] = None
    ack_token: Optional[str] = None
    ftp_registry_keys: List[str] = field(default_factory=list)
    browser_artifacts: List[str] = field(default_factory=list)
    email_registry_keys: List[str] = field(default_factory=list)
    nss_symbols: List[str] = field(default_factory=list)
    sqlite_symbols: List[str] = field(default_factory=list)
    anti_debug: List[str] = field(default_factory=list)
    self_delete_artifact: Optional[str] = None
    entry_anti_emulation: Optional[dict] = None
    interesting_strings: List[str] = field(default_factory=list)


# Strings that uniquely identify a Pony build
PONY_MARKERS = [
    b"STATUS-IMPORT-OK",
    b"Client Hash",
    b"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)",
]

# Credential store keys we expect Pony to target
FTP_REG_PATTERNS = [
    rb"Software\\[^\x00]*FTP[^\x00]*",
    rb"Software\\[^\x00]*FileZilla[^\x00]*",
    rb"Software\\[^\x00]*WinSCP[^\x00]*",
    rb"Software\\[^\x00]*FlashFXP[^\x00]*",
    rb"Software\\[^\x00]*CuteFTP[^\x00]*",
    rb"Software\\[^\x00]*WS_FTP[^\x00]*",
    rb"Software\\[^\x00]*BulletProof[^\x00]*",
    rb"Software\\[^\x00]*Martin Prikryl[^\x00]*",  # WinSCP
    rb"Software\\[^\x00]*VanDyke[^\x00]*",
    rb"Software\\[^\x00]*Ghisler[^\x00]*",
    rb"Software\\[^\x00]*BPFTP[^\x00]*",
    rb"Software\\[^\x00]*TurboFTP[^\x00]*",
    rb"Software\\[^\x00]*FTPWare[^\x00]*",
    rb"Software\\[^\x00]*Sota[^\x00]*",
    rb"Software\\[^\x00]*LeapWare[^\x00]*",
    rb"Software\\[^\x00]*ExpanDrive[^\x00]*",
    rb"Software\\[^\x00]*NCH Software[^\x00]*",
    rb"Software\\[^\x00]*South River[^\x00]*",
]

EMAIL_REG_PATTERNS = [
    rb"Software\\Microsoft\\Internet Account Manager[^\x00]*",
    rb"Software\\Microsoft\\Office\\Outlook[^\x00]*",
    rb"Software\\Microsoft\\Windows Live[^\x00]*",
    rb"Software\\Microsoft\\Windows Mail[^\x00]*",
    rb"Software\\RIT\\The Bat![^\x00]*",
    rb"Software\\IncrediMail[^\x00]*",
    rb"Software\\RimArts[^\x00]*",
]

BROWSER_ARTIFACTS = [
    b"signons.sqlite",
    b"signons2.txt",
    b"signons3.txt",
    b"logins.json",
    b"Login Data",
    b"Web Data",
    b"moz_logins",
    b"Chrome",
    b"Chromium",
    b"ChromePlus",
    b"Firefox",
    b"SeaMonkey",
    b"K-Meleon",
    b"RockMelt",
    b"Comodo",
    b"Yandex",
    b"Epic",
    b"Opera",
    b"wand.dat",
]


def extract_ascii_strings(data: bytes, minlen: int = 6) -> List[bytes]:
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


def looks_like_pony(data: bytes) -> bool:
    return sum(m in data for m in PONY_MARKERS) >= 2


def extract_urls(data: bytes) -> List[bytes]:
    return list(set(re.findall(rb"https?://[a-zA-Z0-9./\-_?=&%+]+", data)))


def classify_urls(urls: List[bytes]):
    dead_drops, payload = [], []
    for u in urls:
        s = u.decode(errors="replace")
        if "ibsensoftware.com" in s:
            continue  # APLib author string
        if "/forum/viewtopic.php" in s or "/forum/showthread.php" in s:
            dead_drops.append(s)
        elif s.lower().endswith(".exe"):
            payload.append(s)
        else:
            dead_drops.append(s)
    return sorted(dead_drops), sorted(payload)


def find_first(data: bytes, needle: bytes, tail: int = 0) -> Optional[str]:
    idx = data.find(needle)
    if idx == -1:
        return None
    if tail == 0:
        # Read until null byte
        end = data.find(b"\x00", idx)
        end = end if end != -1 else idx + 512
        return data[idx:end].decode("latin-1", errors="replace")
    return data[idx:idx + tail].decode("latin-1", errors="replace")


def find_regex_matches(data: bytes, patterns: List[bytes]) -> List[str]:
    out = set()
    for p in patterns:
        for m in re.findall(p, data):
            out.add(m.decode("latin-1", errors="replace"))
    return sorted(out)


def extract_entry_stub(pe: pefile.PE, data: bytes) -> dict:
    """Detect the classic Pony GetTickCount-mod-7 anti-emulation gate."""
    image_base = pe.OPTIONAL_HEADER.ImageBase
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_fo = pe.get_offset_from_rva(ep_rva)

    stub = {
        "entry_point": hex(image_base + ep_rva),
        "entry_bytes": data[ep_fo:ep_fo + 16].hex(),
        "obfuscation_pattern": None,
        "anti_emulation": None,
    }

    # Pattern: push eax; pop eax; push <addr>; clc; jb <+1>; ret
    # 50 58 68 xx xx xx xx F8 72 01 C3
    m = re.search(rb"\x50\x58\x68(....)\xf8\x72\x01\xc3", data[ep_fo:ep_fo + 32])
    if m:
        target = struct.unpack("<I", m.group(1))[0]
        stub["obfuscation_pattern"] = "push/pop/push-clc-jb-ret indirect call"
        stub["resolved_target"] = hex(target)

        # Follow target: look for GetTickCount mod-N gate
        target_fo = pe.get_offset_from_rva(target - image_base)
        tbytes = data[target_fo:target_fo + 48]
        # call imp.GetTickCount (E8 xx xx xx xx or FF 25 stub) then mov ecx,N; xor edx,edx; div ecx; cmp edx,K
        m2 = re.search(
            rb"\xe8[\x00-\xff]{4}\xb9(.)\x00\x00\x00\x33\xd2\xf7\xf1\x83\xfa(.)",
            tbytes,
        )
        if m2:
            stub["anti_emulation"] = {
                "type": "GetTickCount mod-N gate",
                "modulus": m2.group(1)[0],
                "expected_remainder": m2.group(2)[0],
                "note": "loops until (GetTickCount() mod N) == K; stalls sandboxes that return constant ticks",
            }
    return stub


def analyze(path: str) -> PonyConfig:
    import hashlib

    with open(path, "rb") as f:
        data = f.read()

    cfg = PonyConfig()
    cfg.sha256 = hashlib.sha256(data).hexdigest()
    cfg.md5 = hashlib.md5(data).hexdigest()

    if not looks_like_pony(data):
        print("[!] Binary does not match Pony markers — proceeding anyway", file=sys.stderr)

    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ]
    )
    cfg.image_base = pe.OPTIONAL_HEADER.ImageBase
    cfg.entry_point = cfg.image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    cfg.compile_stamp = pe.FILE_HEADER.TimeDateStamp

    cfg.entry_anti_emulation = extract_entry_stub(pe, data)

    urls = extract_urls(data)
    cfg.dead_drop_urls, cfg.payload_urls = classify_urls(urls)

    cfg.hwid_format = find_first(data, b"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}")
    cfg.user_agent = find_first(data, b"Mozilla/4.0")
    cfg.http_post_template = find_first(data, b"POST %s HTTP/1.0")
    cfg.http_get_template = find_first(data, b"GET %s HTTP/1.0")
    cfg.ack_token = find_first(data, b"STATUS-IMPORT-OK")
    if b"abcd.bat" in data:
        cfg.self_delete_artifact = "abcd.bat"

    cfg.ftp_registry_keys = find_regex_matches(data, FTP_REG_PATTERNS)
    cfg.email_registry_keys = find_regex_matches(data, EMAIL_REG_PATTERNS)

    found_browser = [b.decode() for b in BROWSER_ARTIFACTS if b in data]
    cfg.browser_artifacts = sorted(set(found_browser))

    # NSS / SQLite symbols dynamically resolved
    nss = [
        "NSS_Init",
        "NSS_Shutdown",
        "NSSBase64_DecodeBuffer",
        "PK11_GetInternalKeySlot",
        "PK11_Authenticate",
        "PK11SDR_Decrypt",
        "PK11_FreeSlot",
        "SECITEM_FreeItem",
    ]
    cfg.nss_symbols = [s for s in nss if s.encode() in data]
    sqlite = [
        "sqlite3_open",
        "sqlite3_close",
        "sqlite3_prepare",
        "sqlite3_step",
        "sqlite3_column_bytes",
        "sqlite3_column_blob",
    ]
    cfg.sqlite_symbols = [s for s in sqlite if s.encode() in data]

    cfg.anti_debug = []
    if cfg.entry_anti_emulation and cfg.entry_anti_emulation.get("anti_emulation"):
        cfg.anti_debug.append("GetTickCount mod-N entry-gate (stalls sandboxes)")
    # PEB BeingDebugged: mov eax, fs:[30h]; movzx eax, [eax+2]
    if re.search(rb"\x64\xa1\x30\x00\x00\x00\x0f\xb6\x40\x02", data):
        cfg.anti_debug.append("PEB.BeingDebugged read (fs:[30h]+2)")

    # Grab other high-signal strings
    interesting = []
    for marker in [
        b"Client Hash",
        b"HWID",
        b"abcd.bat",
        b"Content-Encoding: binary",
        b"identification",
        b"identitymgr",
        b"inetcomm server passwords",
        b"outlook account manager passwords",
    ]:
        if marker in data:
            interesting.append(marker.decode())
    cfg.interesting_strings = sorted(set(interesting))

    return cfg


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sample")
    ap.add_argument("-j", "--json", action="store_true", help="Emit JSON to stdout")
    args = ap.parse_args()

    cfg = analyze(args.sample)

    if args.json:
        print(json.dumps(asdict(cfg), indent=2, default=str))
        return

    print("=" * 68)
    print(f"Pony/Fareit config extractor — {args.sample}")
    print("=" * 68)
    print(f"SHA-256   : {cfg.sha256}")
    print(f"MD5       : {cfg.md5}")
    print(f"ImageBase : {hex(cfg.image_base)}")
    print(f"EntryPoint: {hex(cfg.entry_point)}")
    print(f"Compiled  : {cfg.compile_stamp}")
    print()

    print("--- Entry-point anti-emulation ---")
    ae = cfg.entry_anti_emulation
    if ae:
        print(f"  Bytes at EP: {ae['entry_bytes']}")
        if ae.get("obfuscation_pattern"):
            print(f"  Obfuscation: {ae['obfuscation_pattern']}")
            print(f"  Resolves to: {ae.get('resolved_target')}")
        if ae.get("anti_emulation"):
            a = ae["anti_emulation"]
            print(f"  Anti-emulation gate: {a['type']}")
            print(f"    loop until (GetTickCount() mod {a['modulus']}) == {a['expected_remainder']}")
            print(f"    {a['note']}")
    print()

    print("--- Dead-drop URLs (config / payload list) ---")
    for u in cfg.dead_drop_urls:
        print(f"  {u}")
    print()
    print("--- Payload download URLs ---")
    for u in cfg.payload_urls:
        print(f"  {u}")
    print()
    print("--- HTTP fingerprint ---")
    print(f"  User-Agent : {cfg.user_agent}")
    print(f"  Ack token  : {cfg.ack_token}")
    print(f"  POST tmpl  : {repr(cfg.http_post_template)[:120]}...")
    print()
    print("--- Anti-debug ---")
    for x in cfg.anti_debug:
        print(f"  {x}")
    print()
    print("--- FTP client registry targets ---")
    for k in cfg.ftp_registry_keys:
        print(f"  {k}")
    print()
    print("--- Email client registry targets ---")
    for k in cfg.email_registry_keys:
        print(f"  {k}")
    print()
    print(f"--- Browser artifacts ({len(cfg.browser_artifacts)}) ---")
    print("  " + ", ".join(cfg.browser_artifacts))
    print()
    print("--- Dynamic symbol resolution ---")
    print(f"  NSS:    {cfg.nss_symbols}")
    print(f"  SQLite: {cfg.sqlite_symbols}")
    print()
    print(f"HWID format: {cfg.hwid_format}")
    print(f"Self-delete: {cfg.self_delete_artifact}")


if __name__ == "__main__":
    main()
