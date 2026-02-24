#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sv_analysis_lib import import_table, sha256_file, suspicious_strings, write_json


def main() -> None:
    ap = argparse.ArgumentParser(description="Quick IOC/config hunt in decrypted stage2 payload")
    ap.add_argument("--stage2", default="artifacts/stage2_dec_unpadded.bin", help="Decrypted stage2 path")
    ap.add_argument("--out", default="artifacts", help="Output directory")
    args = ap.parse_args()

    stage2 = Path(args.stage2).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    imports = import_table(stage2)
    strings = suspicious_strings(stage2)

    report = {
        "stage2": str(stage2),
        "stage2_sha256": sha256_file(stage2),
        "imports": imports,
        "suspicious_strings": strings,
    }

    out_path = out_dir / "stage2_ioc_report.json"
    write_json(out_path, report)

    print("[+] stage2 IOC hunt complete")
    print(f"    stage2_sha256: {report['stage2_sha256']}")
    print(f"    import dll count: {len(imports)}")
    print(f"    suspicious string count: {len(strings)}")
    print(f"    report: {out_path}")


if __name__ == "__main__":
    main()
