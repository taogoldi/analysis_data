#!/usr/bin/env python3
"""Compare local Mirai sample against Fortinet Gayfemboy campaign indicators."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


CAMPAIGN_STRINGS = [
    "cross-compiling.org",
    "i-kiss-boys.com",
    "furry-femboys.top",
    "twinkfinder.nl",
    "3gipcam.com",
    "twinks :3",
    "meowmeow",
    "whattheflip",
    "^kill^",
    "/tmp/.",
    "/bot.",
    "/.ai",
    "dvrlocker",
    "127.0.0.1",
    "1.1.1.1",
    "8.8.8.8",
    "8.8.4.4",
    "47272",
]

LINEAGE_STRINGS = [
    "watchdogd",
    "/proc/%s/exe",
    "/proc/%s/cmdline",
    "/proc/%s/maps",
    "M-SEARCH * HTTP/1.1",
    "Via: SIP/2.0/UDP 192.168.1.1:5060",
    "!SIGKILL",
]

# Elastic rule Linux_Trojan_Gafgyt_d0c57a2e related motif.
BYTE_PATTERNS = {
    "elastic_d0c57a2e": "07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89",
    "dns_decode_alt": "0F B6 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89",
}


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        type=Path,
        default=None,
        help="ELF sample path (default: first *.elf under input/)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=root / "reports" / "json" / "fortinet_gayfemboy_overlap.json",
        help="JSON output path",
    )
    return parser.parse_args()


def first_elf(input_dir: Path) -> Path:
    cands = sorted(input_dir.glob("*.elf"))
    if not cands:
        raise FileNotFoundError(f"No ELF found under {input_dir}")
    return cands[0]


def run_strings(sample: Path) -> list[str]:
    out = subprocess.check_output(["strings", "-a", "-n", "3", str(sample)], text=True, errors="ignore")
    return [s.strip() for s in out.splitlines() if s.strip()]


def find_string_hits(corpus: list[str], needles: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for n in needles:
        vals = [s for s in corpus if n in s]
        if vals:
            out[n] = vals[:5]
    return out


def find_pattern_hits(blob: bytes, pattern_hex: str) -> list[int]:
    pat = bytes.fromhex(pattern_hex)
    offs: list[int] = []
    i = 0
    while True:
        j = blob.find(pat, i)
        if j < 0:
            break
        offs.append(j)
        i = j + 1
    return offs


def classify(campaign_count: int, lineage_count: int, pattern_count: int) -> str:
    if campaign_count >= 4:
        return "likely same campaign family/profile"
    if campaign_count >= 1 and (lineage_count >= 3 or pattern_count >= 1):
        return "partial campaign overlap (needs deeper validation)"
    if campaign_count == 0 and (lineage_count >= 3 or pattern_count >= 1):
        return "mirai-lineage overlap only (not enough for same campaign)"
    return "insufficient overlap"


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    sample = args.sample or first_elf(root / "input")
    sample_rel = str(sample.relative_to(root)) if sample.is_relative_to(root) else sample.name

    strings_list = run_strings(sample)
    blob = sample.read_bytes()

    campaign_hits = find_string_hits(strings_list, CAMPAIGN_STRINGS)
    lineage_hits = find_string_hits(strings_list, LINEAGE_STRINGS)
    pattern_hits = {name: find_pattern_hits(blob, sig) for name, sig in BYTE_PATTERNS.items()}
    non_empty_patterns = {k: v for k, v in pattern_hits.items() if v}

    result = {
        "sample": sample_rel,
        "campaign_name": "Gayfemboy Mirai-based botnet (Fortinet, 2024-09-18)",
        "campaign_indicator_hits": campaign_hits,
        "lineage_overlap_hits": lineage_hits,
        "byte_pattern_hits": {k: [hex(x) for x in v[:10]] for k, v in non_empty_patterns.items()},
        "summary": {
            "campaign_indicator_hit_count": len(campaign_hits),
            "lineage_overlap_hit_count": len(lineage_hits),
            "byte_pattern_hit_count": len(non_empty_patterns),
            "assessment": classify(len(campaign_hits), len(lineage_hits), len(non_empty_patterns)),
        },
        "notes": [
            "Campaign indicators are mostly string/IOC level and may be absent in other Mirai derivatives.",
            "Byte-pattern overlap in decode_header supports shared resolver implementation lineage.",
            "Final attribution should combine static overlap with infrastructure and runtime telemetry.",
        ],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[fortinet-compare] sample: {sample}")
    print(f"[fortinet-compare] output: {args.out}")
    print(
        "[fortinet-compare] assessment:",
        result["summary"]["assessment"],
        f"(campaign={result['summary']['campaign_indicator_hit_count']}, "
        f"lineage={result['summary']['lineage_overlap_hit_count']}, "
        f"patterns={result['summary']['byte_pattern_hit_count']})",
    )


if __name__ == "__main__":
    main()

