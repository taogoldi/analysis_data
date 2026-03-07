#!/usr/bin/env python3
"""Run end-to-end offline analysis pipeline for Kaiji sample."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from kaiji_analysis_lib import write_text


def run(cmd):
    print("[+]", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True, help="Kaiji project root")
    args = ap.parse_args()

    root = args.root.resolve()
    scripts = root / "scripts"
    input_sample = root / "input" / "0a70d7699c8e0629597dcc03b1aef0beebec03ae0580f2c070fb2bfd2fd89a71.elf"

    triage_json = root / "reports" / "json" / "triage_report.json"
    strings_txt = root / "reports" / "static" / "suspicious_strings.txt"
    config_json = root / "reports" / "json" / "config_report.json"
    config_txt = root / "reports" / "static" / "config_extract.txt"
    ioc_json = root / "reports" / "json" / "ioc_report.json"
    ioc_md = root / "reports" / "static" / "ioc_report.md"
    persist_json = root / "reports" / "json" / "persistence_blocks.json"
    persist_md = root / "reports" / "static" / "persistence_blocks.md"
    matrix_json = root / "reports" / "json" / "capability_matrix.json"
    matrix_md = root / "reports" / "static" / "capability_matrix.md"

    run(
        [
            sys.executable,
            str(scripts / "triage_kaiji_elf.py"),
            "--sample",
            str(input_sample),
            "--out-json",
            str(triage_json),
            "--out-strings",
            str(strings_txt),
        ]
    )

    run(
        [
            sys.executable,
            str(scripts / "extract_kaiji_config.py"),
            "--triage-json",
            str(triage_json),
            "--out-json",
            str(config_json),
            "--out-text",
            str(config_txt),
            "--external-c2",
            "air.duffy.baby:888",
        ]
    )

    run(
        [
            sys.executable,
            str(scripts / "build_ioc_report.py"),
            "--triage",
            str(triage_json),
            "--config",
            str(config_json),
            "--out-json",
            str(ioc_json),
            "--out-md",
            str(ioc_md),
        ]
    )

    run(
        [
            sys.executable,
            str(scripts / "extract_persistence_script_blocks.py"),
            "--sample",
            str(input_sample),
            "--out-json",
            str(persist_json),
            "--out-md",
            str(persist_md),
        ]
    )

    run(
        [
            sys.executable,
            str(scripts / "go_symbol_capability_matrix.py"),
            "--triage",
            str(triage_json),
            "--out-json",
            str(matrix_json),
            "--out-md",
            str(matrix_md),
        ]
    )

    triage = json.loads(triage_json.read_text(encoding="utf-8"))
    cfg = json.loads(config_json.read_text(encoding="utf-8"))
    persist = json.loads(persist_json.read_text(encoding="utf-8"))
    matrix = json.loads(matrix_json.read_text(encoding="utf-8"))

    md = [
        "# Kaiji Analysis Report",
        "",
        f"- Sample SHA-256: `{triage['sample']['sha256']}`",
        f"- Size: `{triage['sample']['size_bytes']}` bytes",
        "- Format: `ELF64 x86-64 static Go`",
        "",
        "## Key Findings",
        "",
        f"- Persistence indicators: `{len(triage['persistence_indicators'])}`",
        f"- Behavior indicators: `{len(triage['behavior_indicators'])}`",
        f"- Base64 decoded candidates: `{len(triage['base64_decoded_candidates'])}`",
        f"- C2 candidates: `{', '.join(cfg['c2_candidates'])}`",
        f"- Persistence script blocks extracted: `{persist['hit_count']}`",
        f"- Capability matrix rows: `{matrix['symbol_count']}`",
        "",
        "## Ares/Attack Modules",
    ]

    for fn in triage["go_indicators"]["ares_functions"]:
        md.append(f"- `{fn}`")

    md.extend(
        [
            "",
            "## Notes",
            "- This pass is static/offline only; no live execution or C2 interaction.",
            "- External IOC `air.duffy.baby:888` was preserved as analyst-provided context.",
            "",
        ]
    )

    write_text(root / "reports" / "analysis_report.md", "\n".join(md))


if __name__ == "__main__":
    main()
