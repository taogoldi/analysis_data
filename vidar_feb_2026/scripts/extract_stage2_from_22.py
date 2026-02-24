#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sv_analysis_lib import extract_stage2, write_json


# These offsets are sample-specific to 22.exe.
ENC_BLOB_VA = 0x140005140
ENC_SIZE_VA = 0x1400A3560
KEY_VA = 0x1400A35A0
IV_VA = 0x1400A3590


def main() -> None:
    ap = argparse.ArgumentParser(description="Extract and decrypt embedded stage2 payload from 22.exe")
    ap.add_argument("--sample", default="input/22.exe", help="Path to stage1 sample (default: input/22.exe)")
    ap.add_argument("--out", default="artifacts", help="Output directory (default: artifacts)")
    args = ap.parse_args()

    sample = Path(args.sample)
    if not sample.exists() and sample.as_posix() == "input/22.exe":
        # Backward compatibility with old flat layout.
        legacy = Path("22.exe")
        if legacy.exists():
            sample = legacy
    sample = sample.resolve()
    out_dir = Path(args.out).resolve()

    result = extract_stage2(
        sample=sample,
        enc_blob_va=ENC_BLOB_VA,
        enc_size_va=ENC_SIZE_VA,
        key_va=KEY_VA,
        iv_va=IV_VA,
        out_dir=out_dir,
    )

    write_json(out_dir / "stage2_extract_report.json", result)

    print("[+] stage2 extraction complete")
    print(f"    sample: {result['sample']}")
    print(f"    sample_sha256: {result['sample_sha256']}")
    print(f"    enc_size: {result['enc_size']} bytes")
    print(f"    dec_unpadded_sha256: {result['dec_unpadded_sha256']}")
    print(f"    starts_with_mz: {result['dec_starts_mz']}")
    print(f"    report: {out_dir / 'stage2_extract_report.json'}")


if __name__ == "__main__":
    main()
