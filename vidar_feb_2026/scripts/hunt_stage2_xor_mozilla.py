#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from sv_analysis_lib import find_single_byte_xor_plaintext_hits, sha256_file, write_json


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Reproduce THOR-like single-byte XOR Mozilla/5.0 detection on decrypted Stage2"
    )
    ap.add_argument("--stage2", default="artifacts/stage2_dec_unpadded.bin", help="Decrypted stage2 path")
    ap.add_argument("--out", default="artifacts", help="Output directory")
    ap.add_argument("--yara-rule", default="", help="Optional YARA rule file to validate match")
    ap.add_argument("--yara-bin", default="yara", help="YARA executable path (default: yara)")
    args = ap.parse_args()

    stage2 = Path(args.stage2).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    plaintext = b"Mozilla/5.0"
    hits = find_single_byte_xor_plaintext_hits(stage2, plaintext)

    report = {
        "stage2_basename": stage2.name,
        "stage2_sha256": sha256_file(stage2),
        "target_plaintext": plaintext.decode("latin1"),
        "hit_count": len(hits),
        "hits": hits,
        "note": (
            "Hit means raw bytes at offset XORed with a single byte decode to target_plaintext. "
            "This reproduces the same core heuristic used by XOR-string hunting rules."
        ),
    }

    yara_rule = Path(args.yara_rule).expanduser().resolve() if args.yara_rule else None
    if yara_rule and yara_rule.exists():
        proc = subprocess.run(
            [args.yara_bin, str(yara_rule), str(stage2)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        report["yara_validation"] = {
            "rule_path": str(yara_rule),
            "return_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "matched": bool(proc.stdout.strip()),
        }

    out_path = out_dir / "stage2_xor_mozilla_report.json"
    write_json(out_path, report)

    print("[+] Stage2 XOR-Mozilla hunt complete")
    print(f"    stage2_sha256: {report['stage2_sha256']}")
    print(f"    target: {report['target_plaintext']}")
    print(f"    hit_count: {report['hit_count']}")
    print(f"    report: {out_path}")


if __name__ == "__main__":
    main()
