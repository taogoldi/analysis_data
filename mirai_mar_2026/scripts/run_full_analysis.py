#!/usr/bin/env python3
"""Run the full static analysis pipeline for a Mirai-like ELF sample."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from mirai_analysis_lib import find_matching_capa_json, get_first_elf


def run_step(root: Path, rel_script: str, extra_args: list[str] | None = None) -> None:
    script = root / "scripts" / rel_script
    print(f"[pipeline] running {script.name}")
    cmd = ["python3", str(script)]
    if extra_args:
        cmd.extend(extra_args)
    subprocess.run(cmd, cwd=str(root), check=True)


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sample", type=Path, default=None, help="ELF sample path")
    ap.add_argument("--outdir", type=Path, default=root / "reports", help="Output directory")
    ap.add_argument("--capa-json", type=Path, default=None, help="Optional CAPA JSON input")
    ap.add_argument("--skip-capa", action="store_true", help="Skip CAPA helper normalization step")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    sample = args.sample.resolve() if args.sample else get_first_elf(root / "input")
    outdir = args.outdir.resolve()

    common = ["--sample", str(sample), "--outdir", str(outdir)]
    run_step(root, "triage_mirai_elf.py", common)
    run_step(root, "extract_mirai_rodata_artifacts.py", common)
    run_step(
        root,
        "extract_command_dispatch.py",
        ["--sample", str(sample), "--triage-json", str(outdir / "json" / "triage_report.json"), "--outdir", str(outdir)],
    )
    run_step(root, "export_disasm_slices.py", ["--sample", str(sample), "--outdir", str(outdir / "disasm")])
    run_step(
        root,
        "compare_fortinet_gayfemboy.py",
        ["--sample", str(sample), "--out", str(outdir / "json" / "fortinet_gayfemboy_overlap.json")],
    )

    if not args.skip_capa:
        capa_json = args.capa_json.resolve() if args.capa_json else find_matching_capa_json(root, sample)
        if capa_json and capa_json.exists():
            run_step(
                root,
                "parse_helper_capa_summary.py",
                ["--input", str(capa_json), "--out", str(outdir / "json" / "helper_capa_summary.json")],
            )
        else:
            print("[pipeline] CAPA helper JSON not found, skipping parse_helper_capa_summary.py")

    print("[pipeline] complete")


if __name__ == "__main__":
    main()
