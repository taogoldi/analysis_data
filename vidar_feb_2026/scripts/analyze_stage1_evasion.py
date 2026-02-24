#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sv_analysis_lib import extract_patch_bytes, query_stage1_behavior, write_json


def main() -> None:
    ap = argparse.ArgumentParser(description="Summarize AMSI/ETW patching and anti-sandbox evidence from stage1")
    ap.add_argument("--sample", default="input/22.exe", help="Path to stage1 sample")
    ap.add_argument("--sqlite", default="analysis/ida/22.exe.sqlite", help="Path to IDA/Diaphora sqlite export")
    ap.add_argument("--out", default="artifacts", help="Output directory")
    args = ap.parse_args()

    sample = Path(args.sample)
    if not sample.exists() and sample.as_posix() == "input/22.exe":
        legacy = Path("22.exe")
        if legacy.exists():
            sample = legacy
    db = Path(args.sqlite)
    if not db.exists() and db.as_posix() == "analysis/ida/22.exe.sqlite":
        legacy_db = Path("22.exe.sqlite")
        if legacy_db.exists():
            db = legacy_db
    sample = sample.resolve()
    db = db.resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    patch_info = extract_patch_bytes(sample)
    behavior = query_stage1_behavior(db)

    report = {
        "patches": patch_info,
        "behavior": behavior,
    }

    out_path = out_dir / "stage1_evasion_report.json"
    write_json(out_path, report)

    print("[+] stage1 evasion analysis complete")
    print(f"    amsi patch: {patch_info['amsi_patch_hex']} ({patch_info['amsi_patch_meaning']})")
    print(f"    etw patch:  {patch_info['etw_patch_hex']} ({patch_info['etw_patch_meaning']})")
    print(
        f"    etw alt:    {patch_info['etw_fallback_patch_hex']} "
        f"({patch_info['etw_fallback_patch_meaning']})"
    )
    print(f"    anti-sandbox indicators: {len(behavior['anti_sandbox_indicators'])}")
    print(f"    report: {out_path}")


if __name__ == "__main__":
    main()
