#!/usr/bin/env python3
"""Build a command->handler dispatch map from known Stage1 main() offsets."""

from __future__ import annotations

from pathlib import Path

from mirai_analysis_lib import write_json


DISPATCH = [
    {"command": "udp", "main_callsite_va": "0x4004f1", "handler": "method_udp", "handler_va": "0x401380"},
    {"command": "syn", "main_callsite_va": "0x40052e", "handler": "method_syn", "handler_va": "0x4027b0"},
    {"command": "ack", "main_callsite_va": "0x4005b3", "handler": "method_ack", "handler_va": "0x4026d0"},
    {"command": "udpslam", "main_callsite_va": "0x400667", "handler": "method_udpslam", "handler_va": "0x401280"},
    {"command": "junk", "main_callsite_va": "0x4006c6", "handler": "method_junk", "handler_va": "0x401190"},
    {"command": "raknet", "main_callsite_va": "0x40063e", "handler": "method_raknet", "handler_va": "0x4010a0"},
    {"command": "udpburst", "main_callsite_va": "0x400703", "handler": "method_udpburst", "handler_va": "0x400f60"},
]


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    out = root / "reports" / "json" / "command_dispatch_map.json"
    payload = {
        "sample": "d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf",
        "dispatcher_function": {"name": "main", "va": "0x4002a0"},
        "commands": DISPATCH,
        "notes": [
            "Offsets are sample-specific and extracted from main() disassembly",
            "Command parsing format string located near VA 0x4149cf",
        ],
    }
    write_json(out, payload)
    print(f"[dispatch] wrote {out}")


if __name__ == "__main__":
    main()

