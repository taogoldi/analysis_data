#!/usr/bin/env python3
"""Run the full static analysis pipeline for the Mirai sample."""

from __future__ import annotations

import subprocess
from pathlib import Path


def run_step(root: Path, rel_script: str) -> None:
    script = root / "scripts" / rel_script
    print(f"[pipeline] running {script.name}")
    subprocess.run(["python3", str(script)], cwd=str(root), check=True)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    run_step(root, "triage_mirai_elf.py")
    run_step(root, "extract_mirai_rodata_artifacts.py")
    run_step(root, "extract_command_dispatch.py")
    run_step(root, "export_disasm_slices.py")
    run_step(root, "compare_fortinet_gayfemboy.py")
    print("[pipeline] complete")


if __name__ == "__main__":
    main()
