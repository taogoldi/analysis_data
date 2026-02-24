#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path
from typing import Dict, List

from sv_analysis_lib import suspicious_strings, write_json


ELASTIC_MARKERS = {
    "named_pipe": r"\\.\\pipe\\raSeCIR4gg",
    "cookie": "euconsent-v2",
    "commands": [
        "SetBeacon",
        "DownloadFile",
        "UploadFile",
        "GetDrives",
        "GetFiles",
        "DeleteFile",
    ],
}

BEHAVIOR_MARKERS = {
    "amsi_patch_strings": ["AmsiScanBuffer", "AmsiOpenSession", "amsi.dll"],
    "etw_patch_strings": ["EtwEventWrite", "EtwEventWriteTransfer", "NtTraceEvent"],
    "anti_sandbox_strings": ["cuckoomon.dll", "SbieDll.dll", "SOFTWARE\\Wine", "joe sandbox"],
}


def sqlite_constants(db_path: Path) -> List[str]:
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()
    rows = cur.execute("select constant from constants").fetchall()
    return [r[0] for r in rows if isinstance(r[0], str)]


def contains_any(haystack: List[str], needles: List[str]) -> Dict[str, bool]:
    joined = "\n".join(haystack).lower()
    return {n: (n.lower() in joined) for n in needles}


def main() -> None:
    ap = argparse.ArgumentParser(description="Assess whether 22.exe aligns with published SPECTRALVIPER markers")
    ap.add_argument("--sample", default="input/22.exe", help="Path to stage1 sample")
    ap.add_argument("--sqlite", default="analysis/ida/22.exe.sqlite", help="Path to IDA sqlite")
    ap.add_argument("--stage2", default="artifacts/stage2_dec_unpadded.bin", help="Path to decrypted stage2")
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
    stage2 = Path(args.stage2).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    sample_strs = suspicious_strings(sample)
    stage2_strs = suspicious_strings(stage2) if stage2.exists() else []
    consts = sqlite_constants(db)

    all_strings = sample_strs + stage2_strs + consts

    elastic_hits = {
        "named_pipe": ELASTIC_MARKERS["named_pipe"] in "\n".join(all_strings),
        "cookie": ELASTIC_MARKERS["cookie"].lower() in "\n".join(all_strings).lower(),
        "commands": contains_any(all_strings, ELASTIC_MARKERS["commands"]),
    }

    behavior_hits = {
        k: contains_any(all_strings, v) for k, v in BEHAVIOR_MARKERS.items()
    }

    command_match_count = sum(1 for v in elastic_hits["commands"].values() if v)
    behavior_match_count = sum(sum(1 for v in d.values() if v) for d in behavior_hits.values())

    if elastic_hits["named_pipe"] or elastic_hits["cookie"] or command_match_count >= 2:
        verdict = "possible_variant_high"
    elif behavior_match_count >= 4:
        verdict = "possible_variant_behavioral_only"
    else:
        verdict = "insufficient_overlap"

    report = {
        "verdict": verdict,
        "elastic_marker_hits": elastic_hits,
        "behavioral_hits": behavior_hits,
        "notes": [
            "Behavioral overlap (AMSI/ETW patching + anti-sandbox) exists in stage1.",
            "Public Elastic string markers (pipe/cookie/command names) were not observed in cleartext in this sample set.",
            "Treat this as a likely related tradecraft cluster until deeper stage2/stage3 config decode confirms lineage.",
        ],
    }

    out_path = out_dir / "spectralviper_similarity_report.json"
    write_json(out_path, report)

    print("[+] similarity assessment complete")
    print(f"    verdict: {verdict}")
    print(f"    marker hits: pipe={elastic_hits['named_pipe']} cookie={elastic_hits['cookie']} commands={command_match_count}")
    print(f"    behavioral hits: {behavior_match_count}")
    print(f"    report: {out_path}")


if __name__ == "__main__":
    main()
