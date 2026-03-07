#!/usr/bin/env python3
"""Extract C2/config artifacts from Mirai-like ELF .rodata for multiple variants."""

from __future__ import annotations

import argparse
from pathlib import Path

from mirai_analysis_lib import (
    collect_strings,
    extract_ipv4_candidates,
    get_first_elf,
    is_public_ipv4,
    sha256_file,
    parse_objdump_hexdump,
    read_c_string,
    run_cmd,
    write_json,
    write_text,
)


REFERENCE_VA = {
    "authorized_server_ip": 0x41498A,
    "sigkill_cmd": 0x4149C6,
    "method_udp": 0x4149E7,
    "method_syn": 0x4149EB,
    "method_ack": 0x4149EF,
    "method_udpslam": 0x4149F3,
    "method_junk": 0x4149FB,
    "method_raknet": 0x414A00,
    "method_udpburst": 0x414A07,
    "hello_cmd": 0x414A28,
    "hello_resp": 0x414A2F,
    "busybox_binary": 0x414BB6,
}

REFERENCE_TOOL_PATHS = [
    0x414B48,  # /usr/bin/wget
    0x414B56,  # /usr/bin/curl
    0x414B64,  # /usr/bin/tftp
    0x414B72,  # /usr/bin/ftp
    0x414B7F,  # /usr/bin/scp
    0x414B8C,  # /usr/bin/nc
    0x414B98,  # /usr/bin/netcat
    0x414BA8,  # /usr/bin/ncat
]

REFERENCE_SAMPLE_SHA256 = "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28"


def find_ascii_offsets(byte_map: dict[int, int], needle: str, limit: int = 8) -> list[str]:
    blob = bytes(byte_map.get(k, 0) for k in sorted(byte_map))
    if not blob:
        return []
    base = min(byte_map.keys())
    pat = needle.encode("utf-8", errors="ignore")
    if not pat:
        return []
    out: list[str] = []
    pos = 0
    while len(out) < limit:
        idx = blob.find(pat, pos)
        if idx < 0:
            break
        out.append(f"0x{base + idx:x}")
        pos = idx + 1
    return out


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, default=None)
    parser.add_argument("--outdir", type=Path, default=root / "reports")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    sample = args.sample or get_first_elf(root / "input")
    outdir = args.outdir

    sample_sha = sha256_file(sample)
    rodata_dump = run_cmd(["objdump", "-s", "-j", ".rodata", str(sample)])
    byte_map = parse_objdump_hexdump(rodata_dump)
    strings_all = collect_strings(sample, min_len=3)

    extracted = {}
    if sample_sha == REFERENCE_SAMPLE_SHA256:
        for name, va in REFERENCE_VA.items():
            extracted[name] = {"va": f"0x{va:x}", "value": read_c_string(byte_map, va)}
    else:
        for name, va in REFERENCE_VA.items():
            extracted[name] = {"va": f"0x{va:x}", "value": ""}

    tool_paths = []
    if sample_sha == REFERENCE_SAMPLE_SHA256:
        for va in REFERENCE_TOOL_PATHS:
            tool_paths.append({"va": f"0x{va:x}", "value": read_c_string(byte_map, va)})

    method_markers = [
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
    methods = sorted({s.lower() for s in strings_all if s.lower() in {m.lower() for m in method_markers}})
    cmd_markers = sorted({s for s in strings_all if s.startswith("!") and len(s) < 32})
    ipv4s = extract_ipv4_candidates(strings_all)
    public_ipv4s = [ip for ip in ipv4s if is_public_ipv4(ip)]

    interesting_tokens = [
        "/etc/config/resolv.conf",
        "M-SEARCH * HTTP/1.1",
        "Via: SIP/2.0/UDP 192.168.1.1:5060",
        "TSource Engine Query",
        "watchdog_maintain",
        "watchdog_pid",
        "KHserverHACKER",
    ]
    token_va_map = {
        t: find_ascii_offsets(byte_map, t) for t in interesting_tokens if t in strings_all
    }

    sample_rel = str(sample.relative_to(root)) if sample.is_relative_to(root) else sample.name

    old_extract_ok = sum(1 for x in extracted.values() if x["value"]) >= 4
    report = {
        "sample": sample_rel,
        "sample_sha256": sample_sha,
        "artifacts": extracted,
        "infection_tool_paths": tool_paths,
        "variant_artifacts": {
            "public_ipv4_candidates": public_ipv4s,
            "command_tokens": cmd_markers,
            "method_tokens": methods,
            "interesting_token_va_candidates": token_va_map,
        },
        "notes": [
            "Reference VA map is sample-specific to d40cf9...c28 and is best-effort on other variants",
            "Variant artifact block is string-driven and intended for cross-variant reproducibility",
            "Authorized server IP checks may be absent or encoded differently in other variants",
            f"Reference VA extraction {'succeeded' if old_extract_ok else 'not applicable/empty'} for this sample",
        ],
    }

    write_text(outdir / "static" / "rodata_dump.txt", rodata_dump)
    write_json(outdir / "json" / "rodata_artifacts.json", report)

    print(f"[rodata] extracted: {outdir / 'json' / 'rodata_artifacts.json'}")


if __name__ == "__main__":
    main()
