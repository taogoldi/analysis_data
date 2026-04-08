#!/usr/bin/env python3
"""
Pulsar RAT - Full Analysis Orchestrator
Runs all analysis stages in sequence: triage -> extract -> decode -> report
"""

import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent
STAGES = [
    ("triage_sample.py", "Triage & metadata extraction"),
    ("extract_costura.py", "Costura/Fody DLL extraction"),
    ("extract_config.py", "C2 config & encryption key extraction"),
    ("decode_strings.py", "Obfuscated string decoding"),
]


def run_stage(script_name: str, description: str) -> bool:
    script_path = SCRIPTS_DIR / script_name
    if not script_path.exists():
        print(f"  [SKIP] {script_name} not found")
        return True

    print(f"\n{'='*60}")
    print(f"  Stage: {description}")
    print(f"  Script: {script_name}")
    print(f"{'='*60}\n")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=SCRIPTS_DIR.parent,
    )
    if result.returncode != 0:
        print(f"\n  [FAIL] {script_name} exited with code {result.returncode}")
        return False

    print(f"\n  [OK] {description} complete")
    return True


def main():
    print("Pulsar RAT - Full Analysis Pipeline")
    print(f"Working directory: {SCRIPTS_DIR.parent}")

    failed = []
    for script_name, description in STAGES:
        if not run_stage(script_name, description):
            failed.append(script_name)

    print(f"\n{'='*60}")
    if failed:
        print(f"  Pipeline finished with {len(failed)} failure(s): {', '.join(failed)}")
        sys.exit(1)
    else:
        print(f"  Pipeline complete. All {len(STAGES)} stages passed.")
        print(f"  Reports: reports/json/ and reports/static/")


if __name__ == "__main__":
    main()
