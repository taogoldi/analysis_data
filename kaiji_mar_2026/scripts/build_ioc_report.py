#!/usr/bin/env python3
"""Build IOC-focused report from triage/config outputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from kaiji_analysis_lib import write_json, write_text


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--triage", type=Path, required=True)
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    args = ap.parse_args()

    triage = json.loads(args.triage.read_text(encoding="utf-8"))
    cfg = json.loads(args.config.read_text(encoding="utf-8"))

    iocs = {
        "sample_sha256": triage["sample"]["sha256"],
        "c2_candidates": cfg["c2_candidates"],
        "domains": triage["network_iocs"]["domains"],
        "ipv4": triage["network_iocs"]["ipv4"],
        "urls": triage["network_iocs"]["urls"],
        "persistence_paths": cfg["persistence_paths"],
        "attack_modules": triage["go_indicators"]["ares_functions"],
    }

    write_json(args.out_json, iocs)

    md = [
        "# IOC Report",
        "",
        f"- Sample SHA-256: `{iocs['sample_sha256']}`",
        "",
        "## C2 Candidates",
    ]
    for x in iocs["c2_candidates"]:
        md.append(f"- `{x}`")

    md.append("\n## Persistence Paths")
    for x in iocs["persistence_paths"]:
        md.append(f"- `{x}`")

    md.append("\n## Attack Module Strings")
    for x in iocs["attack_modules"]:
        md.append(f"- `{x}`")

    write_text(args.out_md, "\n".join(md) + "\n")


if __name__ == "__main__":
    main()
