#!/usr/bin/env python3
"""Map recovered Go symbols to analyst-facing capability tags."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from kaiji_analysis_lib import write_json, write_text


def classify_symbol(sym: str) -> dict:
    s = sym.lower()
    row = {
        "symbol": sym,
        "family": "kaiji-like/ares-like",
        "capability": "unknown",
        "attack_surface": "unknown",
        "tactic": "unknown",
        "confidence": "low",
        "rationale": "no direct mapping rule",
    }

    if "ares_tcp" in s:
        row.update(
            {
                "capability": "tcp_flood_module",
                "attack_surface": "network",
                "tactic": "impact",
                "confidence": "medium",
                "rationale": "Ares_Tcp symbol namespace indicates TCP attack path.",
            }
        )
    elif "ares_l3_udp" in s or "ares_plain_udp" in s:
        row.update(
            {
                "capability": "udp_flood_module",
                "attack_surface": "network",
                "tactic": "impact",
                "confidence": "medium",
                "rationale": "Ares UDP/L3 naming indicates UDP attack routines.",
            }
        )
    elif "ipspoof" in s:
        row.update(
            {
                "capability": "ip_spoofing_support",
                "attack_surface": "network",
                "tactic": "impact",
                "confidence": "medium",
                "rationale": "ipspoof naming indicates source-address spoof helper.",
            }
        )
    elif "killcpu" in s:
        row.update(
            {
                "capability": "local_resource_exhaustion",
                "attack_surface": "host",
                "tactic": "impact",
                "confidence": "medium",
                "rationale": "Killcpu naming indicates CPU stress/sabotage routine.",
            }
        )
    elif "watchdog" in s:
        row.update(
            {
                "capability": "self_protection_or_recovery",
                "attack_surface": "host",
                "tactic": "defense_evasion",
                "confidence": "low",
                "rationale": "watchdog naming often maps to process/service resiliency.",
            }
        )
    elif "ares_send" in s or "ares_tcp_read" in s:
        row.update(
            {
                "capability": "attack_transport_io",
                "attack_surface": "network",
                "tactic": "impact",
                "confidence": "low",
                "rationale": "send/read helpers support attack traffic orchestration.",
            }
        )

    return row


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--triage", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    args = ap.parse_args()

    triage = json.loads(args.triage.read_text(encoding="utf-8"))
    symbols = sorted(set(triage.get("go_indicators", {}).get("ares_functions", [])))
    rows = [classify_symbol(s) for s in symbols]

    cap_count = Counter(r["capability"] for r in rows)
    tactic_count = Counter(r["tactic"] for r in rows)

    obj = {
        "sample_sha256": triage["sample"]["sha256"],
        "symbol_count": len(rows),
        "rows": rows,
        "summary": {
            "capability_counts": dict(sorted(cap_count.items())),
            "tactic_counts": dict(sorted(tactic_count.items())),
        },
    }
    write_json(args.out_json, obj)

    md = [
        "# Go Symbol Capability Matrix",
        "",
        f"- Sample SHA-256: `{obj['sample_sha256']}`",
        f"- Symbol rows: `{obj['symbol_count']}`",
        "",
        "## Capability Counts",
    ]
    for k, v in sorted(cap_count.items()):
        md.append(f"- `{k}`: {v}")

    md.extend(
        [
            "",
            "## Symbol Matrix",
            "",
            "| Symbol | Capability | Surface | Tactic | Confidence |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for r in rows:
        md.append(
            f"| `{r['symbol']}` | `{r['capability']}` | `{r['attack_surface']}` | `{r['tactic']}` | `{r['confidence']}` |"
        )

    write_text(args.out_md, "\n".join(md) + "\n")


if __name__ == "__main__":
    main()
