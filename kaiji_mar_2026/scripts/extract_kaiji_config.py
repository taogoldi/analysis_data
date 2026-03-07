#!/usr/bin/env python3
"""Extract and normalize configuration-like artifacts from triage output."""

from __future__ import annotations

import argparse
from pathlib import Path

from kaiji_analysis_lib import write_json, write_text


def split_c2_token(token: str) -> dict:
    # Observed format in this sample: host:port|tag
    out = {
        "raw": token,
        "host": None,
        "port": None,
        "tag": None,
    }
    left, sep, right = token.partition("|")
    host, sep2, port = left.partition(":")
    if host and sep2 and port.isdigit():
        out["host"] = host
        out["port"] = int(port)
    if sep and right:
        out["tag"] = right
    return out


KNOWN_SERVICE_LINES = [
    "ExecStart=/boot/System.mod",
    "ExecReload=/boot/System.mod",
    "ExecStop=/boot/System.mod",
    "systemctl daemon-reload;systemctl enable quotaoff.service;systemctl start quotaoff.service",
]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--triage-json", type=Path, required=True)
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-text", type=Path, required=True)
    ap.add_argument(
        "--external-c2",
        default="air.duffy.baby:888",
        help="User- or intel-supplied external C2 candidate to preserve in report",
    )
    args = ap.parse_args()

    triage = __import__("json").loads(args.triage_json.read_text(encoding="utf-8"))

    decoded = triage.get("base64_decoded_candidates", [])
    decoded_strings = [d.get("decoded", "") for d in decoded]

    parsed_tokens = []
    for s in decoded_strings:
        if ":" in s:
            parsed_tokens.append(split_c2_token(s))

    c2_host_ports = set(triage.get("network_iocs", {}).get("host_ports", []))
    for p in parsed_tokens:
        if p.get("host") and p.get("port"):
            c2_host_ports.add(f"{p['host']}:{p['port']}")

    if args.external_c2:
        c2_host_ports.add(args.external_c2)

    persistence_markers = sorted(
        {
            h["marker"]
            for h in triage.get("persistence_indicators", [])
            if "/" in h.get("marker", "") or h.get("marker", "").endswith(".service")
        }
    )

    service_artifacts = set()
    for h in triage.get("persistence_indicators", []):
        ctx = h.get("context", "")
        for line in KNOWN_SERVICE_LINES:
            if line in ctx:
                service_artifacts.add(line)

    config = {
        "sample_sha256": triage["sample"]["sha256"],
        "decoded_config_tokens": decoded_strings,
        "parsed_tokens": parsed_tokens,
        "c2_candidates": sorted(c2_host_ports),
        "persistence_paths": persistence_markers,
        "service_artifacts": sorted(service_artifacts),
        "analysis_limitations": [
            "Static-only pass: no live C2 interaction was performed.",
            "Decoded C2 token recovered from embedded Base64; additional runtime config may exist.",
            "External IOC air.duffy.baby:888 was user-supplied and not directly recovered from this binary during this run.",
        ],
    }

    write_json(args.out_json, config)

    text_lines = [
        "# Kaiji Config Extraction\n",
        f"Sample SHA-256: {config['sample_sha256']}",
        "",
        "Decoded tokens:",
    ]
    for t in config["decoded_config_tokens"]:
        text_lines.append(f"- {t}")
    text_lines.append("")
    text_lines.append("C2 candidates:")
    for c2 in config["c2_candidates"]:
        text_lines.append(f"- {c2}")
    text_lines.append("")
    text_lines.append("Persistence artifacts:")
    for p in config["persistence_paths"]:
        text_lines.append(f"- {p}")

    write_text(args.out_text, "\n".join(text_lines) + "\n")


if __name__ == "__main__":
    main()
