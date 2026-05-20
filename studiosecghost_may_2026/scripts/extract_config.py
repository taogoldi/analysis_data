"""
StudioSecGhost: static config extractor.

The agent stores its operational config in .rdata as plain UTF-16LE strings
adjacent to the [INIT]/[NET]/[CHROME]/[VNC] log format strings. There is no
encryption, no XOR, no resource decryption. This script lifts the config
fields out by name and emits a single JSON document the operator panel could
have produced.

Run:
    python3 scripts/extract_config.py [path_to_exe] > config.json
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

import pefile

# Default sample path is resolved relative to this script's parent directory.
# Override by passing an absolute path on argv[1].
_REPO = Path(__file__).resolve().parent.parent
DEFAULT_SAMPLE = _REPO / "sample" / (
    "5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852.exe"
)


@dataclass
class StudioSecGhostConfig:
    c2_ip: Optional[str]
    c2_port_candidates: List[int]
    bounce_html_filenames: List[str]
    task_xml_filename_fmt: Optional[str]
    cleanup_batch: Optional[str]
    banner_class: Optional[str]
    banner_title: Optional[str]
    anchor_class_a: Optional[str]
    anchor_class_b: Optional[str]
    ghost_window_title: Optional[str]
    browsers: List[dict]
    blocklist: List[str]
    firefox_prefs_key: Optional[str]
    browser_args_chromium: Optional[str]
    browser_args_firefox: Optional[str]


IPV4_RE_UTF16 = re.compile(
    rb"((?:\d\x00){1,3}\.\x00(?:\d\x00){1,3}\.\x00(?:\d\x00){1,3}\.\x00(?:\d\x00){1,3})"
)


def _decode_utf16(b: bytes) -> str:
    try:
        return b.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return b.decode("utf-16-le", errors="replace").rstrip("\x00")


def _all_utf16_strings(blob: bytes, min_chars: int = 4):
    """Yield (offset, string) for every wide-string in blob >= min_chars."""
    i = 0
    n = len(blob)
    while i < n - 1:
        # Find a printable ASCII char followed by null
        if 0x20 <= blob[i] <= 0x7e and blob[i + 1] == 0:
            start = i
            chars = []
            while i < n - 1 and 0x20 <= blob[i] <= 0x7e and blob[i + 1] == 0:
                chars.append(chr(blob[i]))
                i += 2
            if len(chars) >= min_chars:
                yield start, "".join(chars)
        else:
            i += 1


def _find_one(strings, predicate):
    for off, s in strings:
        if predicate(s):
            return s
    return None


def _find_many(strings, predicate):
    return [s for _, s in strings if predicate(s)]


def main(sample_path: Path) -> int:
    pe = pefile.PE(str(sample_path), fast_load=False)
    data = sample_path.read_bytes()

    rdata = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rdata")
    rdata_bytes = rdata.get_data()

    strings = list(_all_utf16_strings(rdata_bytes))

    # --- C2 IP (UTF-16LE IPv4 literal in .rdata) -----------------------
    c2_ip = None
    for off, s in strings:
        if re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s):
            c2_ip = s
            break

    # --- Plausible port values -----------------------------------------
    # Scan all wide-string numbers in the same .rdata page as the IP.
    port_candidates: List[int] = []
    if c2_ip:
        ip_off_in_rdata = next(off for off, s in strings if s == c2_ip)
        page_start = max(0, ip_off_in_rdata - 0x200)
        page_end = min(len(rdata_bytes), ip_off_in_rdata + 0x200)
        page_strings = [s for off, s in strings
                        if page_start <= off <= page_end]
        for s in page_strings:
            if s.isdigit() and 1 <= int(s) <= 65535:
                port_candidates.append(int(s))

    # --- Specific named items -------------------------------------------
    bounce_names = _find_many(
        strings, lambda s: s.endswith(".html") and ("bounce" in s.lower() or "chrome_update_manifest" in s)
    )
    task_xml = _find_one(strings, lambda s: "chrome_task_" in s and s.endswith(".xml"))
    cleanup = _find_one(strings, lambda s: s.endswith("cleanup.bat"))
    banner_class = _find_one(strings, lambda s: s == "StudioSecVNC_Banner")
    banner_title = _find_one(strings, lambda s: s == "StudioSecVNC Banner")
    anchor_a = _find_one(strings, lambda s: s == "GSystem")
    anchor_b = _find_one(strings, lambda s: s == ".SecAnchor")
    ghost_title = _find_one(strings, lambda s: s == "StudioSecGhost")
    firefox_key = _find_one(strings, lambda s: s == "browser.sessionstore.resume_from_crash")

    # --- Browser install paths ------------------------------------------
    browsers: List[dict] = []
    for keyword, name, klass in [
        ("chrome.exe", "Chrome", "Chrome_WidgetWin_1"),
        ("msedge.exe", "Edge", None),
        ("firefox.exe", "Firefox", "MozillaWindowClass"),
    ]:
        install_paths = [
            s for _, s in strings
            if s.lower().endswith(keyword) and ("Program Files" in s or "AppData" in s)
        ]
        browsers.append({
            "name": name,
            "process": keyword,
            "window_class": klass,
            "install_paths_observed": install_paths,
        })

    # --- Anti-analysis blocklist ---------------------------------------
    blocklist_seed = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "devenv.exe", "processhacker.exe", "procmon.exe", "procexp.exe",
        "dnspy.exe", "ghidra", "cheatengine",
    }
    blocklist_found = sorted(
        s.lower() for _, s in strings
        if s.lower() in blocklist_seed
    )

    # --- Browser launch arg literals -----------------------------------
    chromium_args = _find_one(
        strings, lambda s: "--hide-crash-restore-bubble" in s
    )
    firefox_args = _find_one(
        strings, lambda s: "-new-instance" in s and "-no-remote" in s
    )

    cfg = StudioSecGhostConfig(
        c2_ip=c2_ip,
        c2_port_candidates=sorted(set(port_candidates)),
        bounce_html_filenames=sorted(set(bounce_names)),
        task_xml_filename_fmt=task_xml,
        cleanup_batch=cleanup,
        banner_class=banner_class,
        banner_title=banner_title,
        anchor_class_a=anchor_a,
        anchor_class_b=anchor_b,
        ghost_window_title=ghost_title,
        browsers=browsers,
        blocklist=blocklist_found,
        firefox_prefs_key=firefox_key,
        browser_args_chromium=chromium_args,
        browser_args_firefox=firefox_args,
    )

    print(json.dumps(asdict(cfg), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SAMPLE
    sys.exit(main(path))
