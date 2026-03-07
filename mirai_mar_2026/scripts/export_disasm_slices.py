#!/usr/bin/env python3
"""Export disassembly slices around key Mirai functions."""

from __future__ import annotations

import argparse
from pathlib import Path

from mirai_analysis_lib import (
    get_first_elf,
    parse_nm_symbols,
    run_cmd,
    symbols_by_name,
    write_json,
    write_text,
)


KEY_SYMBOLS = [
    "main",
    "verify_server_ip",
    "force_sigkill",
    "killer_thread_func",
    "daemonize_process",
    "disable_infection_tools",
    "scan_and_kill",
    "cmdline_scan_match",
    "memory_scan_match",
    "are_infection_tools_disabled",
    "method_udp",
    "method_syn",
    "method_ack",
    "method_udpslam",
    "method_junk",
    "method_raknet",
    "method_udpburst",
    "udp_worker",
    "tcp_worker",
    "tcp_ack_worker",
    "udpslam_worker",
    "udpburst_worker",
    "get_local_ip",
]


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, default=None)
    parser.add_argument("--outdir", type=Path, default=root / "reports" / "disasm")
    return parser.parse_args()


def export_symbol(sample: Path, symbol: str) -> str:
    return run_cmd(["objdump", "-d", "-M", "intel", f"--disassemble-symbols={symbol}", str(sample)])


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    sample = args.sample or get_first_elf(root / "input")
    outdir = args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    nm_txt = run_cmd(["nm", "-n", str(sample)])
    sym_map = symbols_by_name(parse_nm_symbols(nm_txt))

    exported = []
    for sym in KEY_SYMBOLS:
        if sym not in sym_map:
            continue
        try:
            dis = export_symbol(sample, sym)
        except RuntimeError:
            continue
        out_path = outdir / f"{sym}.asm"
        write_text(out_path, dis)
        exported.append({"symbol": sym, "address": f"0x{sym_map[sym]:x}", "file": str(out_path)})

    # Variant fallback: if symbol recovery is sparse, still dump a useful window around main().
    if len(exported) < 3 and "main" in sym_map:
        main_ea = sym_map["main"]
        start = max(0, main_ea - 0x300)
        stop = main_ea + 0x1800
        dis = run_cmd(
            [
                "objdump",
                "-d",
                "-M",
                "intel",
                f"--start-address=0x{start:x}",
                f"--stop-address=0x{stop:x}",
                str(sample),
            ]
        )
        out_path = outdir / "main_window.asm"
        write_text(out_path, dis)
        exported.append({"symbol": "main_window", "address": f"0x{main_ea:x}", "file": str(out_path)})

    write_json(outdir / "disasm_index.json", {"sample": str(sample), "exported": exported})
    print(f"[disasm] exported {len(exported)} symbols to {outdir}")


if __name__ == "__main__":
    main()
