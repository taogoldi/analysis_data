#!/usr/bin/env python3
"""Generate a static triage report for the Mirai ELF sample."""

from __future__ import annotations

import argparse
from pathlib import Path

from mirai_analysis_lib import (
    collect_strings,
    extract_domain_like,
    extract_ipv4_candidates,
    get_first_elf,
    is_public_ipv4,
    key_bot_symbols,
    parse_nm_symbols,
    parse_objdump_sections,
    run_cmd,
    sha256_file,
    symbols_by_name,
    write_json,
    write_text,
)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        type=Path,
        default=None,
        help="Path to ELF sample. Defaults to first *.elf in input/",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=root / "reports",
        help="Output report directory",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    sample = args.sample or get_first_elf(root / "input")
    outdir = args.outdir

    sample_rel = str(sample.relative_to(root)) if sample.is_relative_to(root) else sample.name
    file_info = run_cmd(["file", str(sample)]).strip()
    if ": " in file_info:
        file_info = file_info.split(": ", 1)[1]
    sample_size = sample.stat().st_size
    sample_sha256 = sha256_file(sample)

    nm_txt = run_cmd(["nm", "-n", str(sample)])
    symbols = parse_nm_symbols(nm_txt)
    sym_map = symbols_by_name(symbols)

    objdump_h = run_cmd(["objdump", "-h", str(sample)])
    sections = parse_objdump_sections(objdump_h)

    all_strings = collect_strings(sample, min_len=3)
    ipv4s = extract_ipv4_candidates(all_strings)
    public_ipv4s = [ip for ip in ipv4s if is_public_ipv4(ip)]
    domains = extract_domain_like(all_strings)

    methods = sorted(
        {
            s
            for s in all_strings
            if s in {"udp", "syn", "ack", "udpslam", "junk", "raknet", "udpburst"}
        }
    )
    commands = sorted({s for s in all_strings if s.startswith("!") or s.startswith("get ")})
    anti_infection_paths = [
        s
        for s in all_strings
        if s.startswith("/usr/bin/")
        or s.startswith("/bin/")
        or s.startswith("/proc/")
        or s.startswith("/dev/")
    ]
    anti_infection_paths = sorted(set(anti_infection_paths))

    key_syms = key_bot_symbols(sym_map.keys())
    key_symbol_rows = [{"name": name, "address": f"0x{sym_map[name]:x}"} for name in key_syms if name in sym_map]

    report = {
        "sample": {
            "file": sample.name,
            "path": sample_rel,
            "sha256": sample_sha256,
            "size_bytes": sample_size,
            "file_type_summary": file_info,
        },
        "sections": sections,
        "key_symbols": key_symbol_rows,
        "strings_summary": {
            "total_strings": len(all_strings),
            "public_ipv4_candidates": public_ipv4s,
            "all_ipv4_candidates": ipv4s,
            "domain_like_candidates": domains[:80],
            "method_tokens": methods,
            "command_tokens": commands,
            "anti_infection_paths": anti_infection_paths[:80],
        },
        "assessment": {
            "family_hint": "Mirai-like",
            "confidence": "high",
            "basis": [
                "Named DDoS method dispatch in main (udp/syn/ack/udpslam/junk/raknet/udpburst)",
                "Killer thread + infection-tool disabling + process scan-and-kill loops",
                "Mirai-style network flood payload strings (SSDP/SIP/memcached/NTP/CHARGEN)",
                "Hardcoded authorized server IP check before command execution",
            ],
        },
    }

    write_json(outdir / "json" / "triage_report.json", report)
    write_text(outdir / "static" / "symbols_nm.txt", nm_txt)
    write_text(outdir / "static" / "strings.txt", "\n".join(all_strings) + "\n")
    write_text(outdir / "static" / "objdump_sections.txt", objdump_h)

    print(f"[triage] sample: {sample}")
    print(f"[triage] sha256: {sample_sha256}")
    print(f"[triage] report: {outdir / 'json' / 'triage_report.json'}")


if __name__ == "__main__":
    main()
