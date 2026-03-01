#!/usr/bin/env python3
"""Extract sample-specific C2/config artifacts from Mirai .rodata."""

from __future__ import annotations

import argparse
from pathlib import Path

from mirai_analysis_lib import (
    get_first_elf,
    parse_objdump_hexdump,
    read_c_string,
    run_cmd,
    write_json,
    write_text,
)


SAMPLE_VA = {
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

INFECTION_TOOL_PATHS = [
    0x414B48,  # /usr/bin/wget
    0x414B56,  # /usr/bin/curl
    0x414B64,  # /usr/bin/tftp
    0x414B72,  # /usr/bin/ftp
    0x414B7F,  # /usr/bin/scp
    0x414B8C,  # /usr/bin/nc
    0x414B98,  # /usr/bin/netcat
    0x414BA8,  # /usr/bin/ncat
]


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

    rodata_dump = run_cmd(["objdump", "-s", "-j", ".rodata", str(sample)])
    byte_map = parse_objdump_hexdump(rodata_dump)

    extracted = {}
    for name, va in SAMPLE_VA.items():
        extracted[name] = {"va": f"0x{va:x}", "value": read_c_string(byte_map, va)}

    tool_paths = []
    for va in INFECTION_TOOL_PATHS:
        tool_paths.append({"va": f"0x{va:x}", "value": read_c_string(byte_map, va)})

    sample_rel = str(sample.relative_to(root)) if sample.is_relative_to(root) else sample.name

    report = {
        "sample": sample_rel,
        "artifacts": extracted,
        "infection_tool_paths": tool_paths,
        "notes": [
            "All VAs are sample-specific for d40cf9...c28.elf",
            "Authorized server IP is compared in verify_server_ip() before command processing",
            "Method command strings are parsed in main() and dispatched to method_* handlers",
        ],
    }

    write_text(outdir / "static" / "rodata_dump.txt", rodata_dump)
    write_json(outdir / "json" / "rodata_artifacts.json", report)

    print(f"[rodata] extracted: {outdir / 'json' / 'rodata_artifacts.json'}")


if __name__ == "__main__":
    main()
