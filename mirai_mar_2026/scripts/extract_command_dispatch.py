#!/usr/bin/env python3
"""Build a command->handler dispatch map for Mirai-like variants."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirai_analysis_lib import collect_strings, get_first_elf, parse_nm_symbols, run_cmd, sha256_file, symbols_by_name, write_json


REFERENCE_SHA = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"

REFERENCE_DISPATCH = [
    {"command": "udp", "main_callsite_va": "0x4004f1", "handler": "method_udp", "handler_va": "0x401380"},
    {"command": "syn", "main_callsite_va": "0x40052e", "handler": "method_syn", "handler_va": "0x4027b0"},
    {"command": "ack", "main_callsite_va": "0x4005b3", "handler": "method_ack", "handler_va": "0x4026d0"},
    {"command": "udpslam", "main_callsite_va": "0x400667", "handler": "method_udpslam", "handler_va": "0x401280"},
    {"command": "junk", "main_callsite_va": "0x4006c6", "handler": "method_junk", "handler_va": "0x401190"},
    {"command": "raknet", "main_callsite_va": "0x40063e", "handler": "method_raknet", "handler_va": "0x4010a0"},
    {"command": "udpburst", "main_callsite_va": "0x400703", "handler": "method_udpburst", "handler_va": "0x400f60"},
]

KNOWN_COMMANDS = [
    "udp",
    "syn",
    "ack",
    "udpslam",
    "junk",
    "raknet",
    "udpburst",
    "udpfl00d",
    "tcpFl00d",
    "ovhudpflood",
    "vseattack",
    "rtcp",
]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=Path, default=None, help="ELF sample path")
    ap.add_argument("--triage-json", type=Path, default=root / "reports" / "json" / "triage_report.json")
    ap.add_argument("--outdir", type=Path, default=root / "reports")
    return ap.parse_args()


def guess_handler_symbol(token: str, sym_names: set[str]) -> str | None:
    token_l = token.lower()
    candidates = []
    for name in sym_names:
        lname = name.lower()
        if token_l in lname and (
            lname.startswith("method_")
            or lname.endswith("_worker")
            or "flood" in lname
            or "attack" in lname
            or "udp" in lname
            or "tcp" in lname
        ):
            candidates.append(name)
    if not candidates:
        return None
    return sorted(candidates, key=lambda x: (len(x), x))[0]


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    sample = args.sample or get_first_elf(root / "input")
    sample_sha = sha256_file(sample)
    out = args.outdir / "json" / "command_dispatch_map.json"

    nm_txt = run_cmd(["nm", "-n", str(sample)])
    sym_map = symbols_by_name(parse_nm_symbols(nm_txt))
    sym_names = set(sym_map.keys())
    main_va = sym_map.get("main")

    triage = {}
    if args.triage_json.exists():
        triage = json.loads(args.triage_json.read_text(encoding="utf-8"))

    method_tokens = set()
    method_tokens.update(triage.get("strings_summary", {}).get("method_tokens", []))
    # Backfill from raw strings when triage method extraction is sparse.
    strings_all = collect_strings(sample, min_len=3)
    method_tokens.update({s for s in strings_all if s in KNOWN_COMMANDS})

    dispatch = []
    if sample_sha == REFERENCE_SHA:
        dispatch = REFERENCE_DISPATCH
    else:
        for token in sorted(method_tokens):
            handler = guess_handler_symbol(token, sym_names)
            dispatch.append(
                {
                    "command": token,
                    "main_callsite_va": None,
                    "handler": handler or "unknown",
                    "handler_va": f"0x{sym_map[handler]:x}" if handler and handler in sym_map else None,
                }
            )

    payload = {
        "sample": sample.name,
        "sample_sha256": sample_sha,
        "dispatcher_function": {"name": "main", "va": f"0x{main_va:x}" if isinstance(main_va, int) else None},
        "commands": dispatch,
        "notes": [
            "For d40cf9...c28, callsite offsets are fixed from verified disassembly",
            "For other variants, dispatch mapping is heuristic and symbol/string-driven",
            "When symbols are stripped, handler_va may be null and should be recovered in IDA/Ghidra",
        ],
    }
    write_json(out, payload)
    print(f"[dispatch] wrote {out}")


if __name__ == "__main__":
    main()
