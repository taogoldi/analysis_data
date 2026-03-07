#!/usr/bin/env python3
"""Extract persistence-related script/unit command blocks from Kaiji sample bytes."""

from __future__ import annotations

import argparse
from pathlib import Path

from kaiji_analysis_lib import file_offset_to_va, parse_elf_sections, write_json, write_text

PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E

TARGET_NEEDLES = [
    b"/usr/lib/systemd/system/quotaoff.service",
    b"systemctl daemon-reload",
    b"echo \"*/1 * * * * root /.mod \" >> /etc/crontab",
    b"ExecStart=/boot/System.mod",
    b"ExecReload=/boot/System.mod",
    b"ExecStop=/boot/System.mod",
    b"/etc/profile.d/gateway.sh",
    b"/etc/profile.d/bash_cfg.sh",
]


def is_printable_byte(b: int) -> bool:
    return PRINTABLE_MIN <= b <= PRINTABLE_MAX


def find_all(data: bytes, needle: bytes):
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos == -1:
            return
        yield pos
        start = pos + 1


def bounded_printable_run(data: bytes, at: int) -> tuple[int, int, str]:
    left = at
    while left > 0 and is_printable_byte(data[left - 1]):
        left -= 1

    right = at
    while right < len(data) and is_printable_byte(data[right]):
        right += 1

    text = data[left:right].decode("ascii", "ignore")
    return left, right, text


def compact_context(data: bytes, at: int, radius: int = 96) -> str:
    lo = max(0, at - radius)
    hi = min(len(data), at + radius)
    chunk = data[lo:hi]
    out = []
    for b in chunk:
        if is_printable_byte(b):
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    args = ap.parse_args()

    sample = args.sample.resolve()
    data = sample.read_bytes()
    sections = parse_elf_sections(sample)

    hits = []
    for needle in TARGET_NEEDLES:
        for off in find_all(data, needle):
            left, right, run_text = bounded_printable_run(data, off)
            hits.append(
                {
                    "marker": needle.decode("ascii", "ignore"),
                    "offset": off,
                    "va": file_offset_to_va(sections, off),
                    "run_start_offset": left,
                    "run_end_offset": right,
                    "printable_run": run_text,
                    "context": compact_context(data, off),
                }
            )

    hits.sort(key=lambda x: x["offset"])

    # High-value extracted blocks for the report.
    service_lines = sorted(
        {
            h["marker"]
            for h in hits
            if h["marker"].startswith("ExecStart=")
            or h["marker"].startswith("ExecReload=")
            or h["marker"].startswith("ExecStop=")
        }
    )
    systemctl_blocks = sorted(
        {
            h["printable_run"]
            for h in hits
            if "systemctl daemon-reload" in h["marker"] or "systemctl daemon-reload" in h["printable_run"]
        }
    )
    cron_blocks = sorted(
        {
            h["printable_run"]
            for h in hits
            if "crontab" in h["marker"] or "crontab" in h["printable_run"]
        }
    )

    obj = {
        "sample": str(sample),
        "hit_count": len(hits),
        "hits": hits,
        "extracted": {
            "service_unit_lines": service_lines,
            "systemctl_related_blocks": systemctl_blocks,
            "cron_related_blocks": cron_blocks,
        },
    }
    write_json(args.out_json, obj)

    md = [
        "# Persistence Script Block Extraction",
        "",
        f"- Sample: `{sample.name}`",
        f"- Total marker hits: `{len(hits)}`",
        "",
        "## Extracted Service Unit Lines",
    ]
    if service_lines:
        md.extend([f"- `{x}`" for x in service_lines])
    else:
        md.append("- _none recovered_")

    md.extend(["", "## Extracted systemctl Blocks"])
    if systemctl_blocks:
        md.extend([f"- `{x}`" for x in systemctl_blocks])
    else:
        md.append("- _none recovered_")

    md.extend(["", "## Extracted Cron Blocks"])
    if cron_blocks:
        md.extend([f"- `{x}`" for x in cron_blocks])
    else:
        md.append("- _none recovered_")

    md.extend(["", "## Marker Anchors"])
    for h in hits:
        va = f"0x{h['va']:x}" if isinstance(h.get("va"), int) else "N/A"
        md.append(f"- `{h['marker']}` at file offset `0x{h['offset']:x}` (VA `{va}`)")

    write_text(args.out_md, "\n".join(md) + "\n")


if __name__ == "__main__":
    main()
