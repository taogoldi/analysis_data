#!/usr/bin/env python3
"""Normalize the helper capa summary JSON into analysis reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirai_analysis_lib import write_json


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=root / "helpers" / "capa_d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.json",
    )
    parser.add_argument("--out", type=Path, default=root / "reports" / "json" / "helper_capa_summary.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))

    capa_block = data.get("capa", {})
    summary_block = capa_block.get("summary", {})
    summary_ai = summary_block.get("ai", {}) if isinstance(summary_block, dict) else {}

    out = {
        "source": data.get("source"),
        "variant": data.get("variant", {}),
        "live_urls": data.get("live_urls", []),
        "capa_summary": {
            "findings_count": capa_block.get("findings_count"),
            "risk_score": capa_block.get("risk_score"),
            "risk_level": capa_block.get("risk_level"),
            "needs_investigation": capa_block.get("needs_investigation"),
            "red_alert": capa_block.get("red_alert"),
            "engine_version": capa_block.get("engine_version"),
            "ruleset_version": capa_block.get("ruleset_version"),
            "summary_ai": {
                "used": summary_ai.get("used"),
                "confidence": summary_ai.get("confidence"),
                "reverse_priority": summary_ai.get("reverse_priority"),
                "reverse_focus": summary_ai.get("reverse_focus", []),
                "actions": summary_ai.get("actions", []),
                "rationale": summary_ai.get("rationale"),
            },
            "notable_signals": capa_block.get("notable_signals", []),
        },
    }
    write_json(args.out, out)
    print(f"[capa-helper] wrote {args.out}")


if __name__ == "__main__":
    main()
