#!/usr/bin/env python3
"""Stage1 static triage for Kaiji-like Go ELF sample."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

from kaiji_analysis_lib import (
    ExtractedString,
    dedupe_strings,
    decode_base64_candidates,
    extract_ascii_strings,
    file_offset_to_va,
    find_domains_ips_urls,
    normalize_for_hunt,
    parse_elf_sections,
    section_by_name,
    sha256_file,
    write_json,
    write_text,
)

PERSISTENCE_MARKERS = [
    "/etc/crontab",
    "quotaoff.service",
    "/usr/lib/systemd/system/quotaoff.service",
    "/boot/System.mod",
    "/usr/sbin/ifconfig.cfg",
    "/etc/profile.d/gateway.sh",
    "/etc/profile.d/bash_cfg.sh",
    "/etc/opt.services.cfg",
    "systemctl daemon-reload",
    "systemctl enable quotaoff.service",
    "echo \"*/1 * * * * root /.mod \" >> /etc/crontab",
]

GO_MODULE_MARKERS = [
    "main.Ares_",
    "main.Killcpu",
    "main.watchdog",
    "main.Watchdog",
    "ares_",
    "killcpu.go",
    "watchdog.go",
]

BEHAVIOR_MARKERS = [
    "encoding/base64",
    "os/exec.Command",
    "syscall.Ptrace",
    "net.DialTCP",
    "net.DialUDP",
    "SIGKILL",
    "/bin/sh",
]


def hunt_markers(strings: List[ExtractedString], markers: List[str], sections) -> List[Dict[str, object]]:
    out = []
    seen = set()
    for s in strings:
        text_norm = normalize_for_hunt(s.value)
        for marker in markers:
            if marker.lower() in text_norm.lower():
                key = (s.offset, marker)
                if key in seen:
                    continue
                seen.add(key)
                idx = text_norm.lower().find(marker.lower())
                if idx == -1:
                    snippet = text_norm[:180]
                else:
                    start = max(0, idx - 80)
                    end = min(len(text_norm), idx + len(marker) + 80)
                    snippet = text_norm[start:end]
                out.append(
                    {
                        "marker": marker,
                        "offset": s.offset,
                        "va": file_offset_to_va(sections, s.offset),
                        "context": snippet,
                    }
                )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=Path, required=True, help="Path to ELF sample")
    ap.add_argument("--out-json", type=Path, required=True, help="Output JSON report")
    ap.add_argument("--out-strings", type=Path, required=True, help="Output suspicious string list")
    args = ap.parse_args()

    sample = args.sample
    data = sample.read_bytes()
    sections = parse_elf_sections(sample)
    rodata = section_by_name(sections, ".rodata")
    gopclntab = section_by_name(sections, ".gopclntab")

    strings_all = dedupe_strings(extract_ascii_strings(data, base_offset=0, min_len=4))

    decoded_b64 = decode_base64_candidates(strings_all)
    decoded_texts = [d["decoded"] for d in decoded_b64]

    raw_texts = [s.value for s in strings_all]
    net_iocs = find_domains_ips_urls(raw_texts + decoded_texts)

    persistence_hits = hunt_markers(strings_all, PERSISTENCE_MARKERS, sections)
    go_module_hits = hunt_markers(strings_all, GO_MODULE_MARKERS, sections)
    behavior_hits = hunt_markers(strings_all, BEHAVIOR_MARKERS, sections)

    ares_functions = sorted(
        {
            s.value
            for s in strings_all
            if s.value.startswith("main.Ares_") or s.value in {"main.Killcpu", "main.watchdog", "main.Watchdog"}
        }
    )

    decoded_host_ports = set()
    for item in decoded_b64:
        decoded = str(item.get("decoded", ""))
        if ":" not in decoded:
            continue
        host = decoded.split("|", 1)[0]
        if ":" not in host:
            continue
        hp = host.strip().lower()
        if "." in hp:
            decoded_host_ports.add(hp)

    potential_c2 = sorted(set(net_iocs["host_ports"]) | decoded_host_ports)

    report = {
        "sample": {
            "path": sample.name,
            "sha256": sha256_file(sample),
            "size_bytes": len(data),
            "entry_point_va": "0x464a20",
            "format": "ELF64 x86-64 static Go",
        },
        "sections": [
            {
                "name": s.name,
                "offset": s.offset,
                "size": s.size,
                "vaddr": s.vaddr,
            }
            for s in sections
            if s.name
        ],
        "go_indicators": {
            "rodata_present": rodata is not None,
            "gopclntab_present": gopclntab is not None,
            "ares_functions": ares_functions,
        },
        "persistence_indicators": persistence_hits,
        "behavior_indicators": behavior_hits,
        "network_iocs": net_iocs,
        "base64_decoded_candidates": decoded_b64,
        "potential_c2_candidates": potential_c2,
        "notes": [
            "Static extraction recovered a Base64-decoded C2-like token: air.xem.lat:25194|(odk)/*-.",
            "Threat-rip URL was Cloudflare-gated during this run; external IOC claims were not fetched programmatically.",
        ],
    }

    write_json(args.out_json, report)

    lines = []
    lines.append("# Suspicious string hits\n")
    for block_name, hits in [
        ("Persistence", persistence_hits),
        ("Behavior", behavior_hits),
        ("Go/Ares Module", go_module_hits),
    ]:
        lines.append(f"## {block_name}")
        for h in hits:
            va = f"0x{h['va']:x}" if isinstance(h.get("va"), int) else "N/A"
            lines.append(f"- {h['marker']} | off=0x{h['offset']:x} | va={va} | {h['context']}")
        lines.append("")

    lines.append("## Base64 Decodes")
    for d in decoded_b64:
        lines.append(
            f"- off=0x{d['source_offset']:x} | {d['source']} => {d['decoded']} "
            f"(printable={d['printable_ratio']}, H={d['decoded_entropy']})"
        )
    lines.append("")

    write_text(args.out_strings, "\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
