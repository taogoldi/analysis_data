#!/usr/bin/env python3
"""Extract fixed-offset rodata artifacts for screenshot-friendly references."""

from __future__ import annotations

import argparse
from pathlib import Path

from kaiji_analysis_lib import file_offset_to_va, parse_elf_sections, write_json, write_text

TARGET_STRINGS = [
    "YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=",
    "echo \"*/1 * * * * root /.mod \" >> /etc/crontab",
    "/usr/lib/systemd/system/quotaoff.service",
    "/boot/System.mod",
    "/usr/sbin/ifconfig.cfg",
    "main.Ares_Tcp",
    "main.Ares_L3_Udp",
    "main.Ares_ipspoof",
    "main.Killcpu",
]


def find_all(data: bytes, needle: bytes):
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            return
        yield i
        start = i + 1


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    args = ap.parse_args()

    sample = args.sample
    data = sample.read_bytes()
    sections = parse_elf_sections(sample)

    hits = []
    for s in TARGET_STRINGS:
        for off in find_all(data, s.encode("utf-8")):
            va = file_offset_to_va(sections, off)
            chunk_start = max(0, off - 24)
            chunk_end = min(len(data), off + len(s) + 24)
            chunk = data[chunk_start:chunk_end]
            hits.append(
                {
                    "needle": s,
                    "offset": off,
                    "va": va,
                    "hex_window": chunk.hex(),
                }
            )

    hits.sort(key=lambda x: x["offset"])
    write_json(args.out_json, {"sample": str(sample), "hits": hits})

    lines = ["# RODATA Artifacts", ""]
    for h in hits:
        va = f"0x{h['va']:x}" if isinstance(h.get("va"), int) else "N/A"
        lines.append(f"- `{h['needle']}` at file offset `0x{h['offset']:x}` (VA `{va}`)")
    write_text(args.out_md, "\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
