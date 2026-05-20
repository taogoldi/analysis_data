# StudioSecGhost -- Analysis Artifacts (May 2026)

Artifacts for the [StudioSecGhost hVNC agent analysis](https://taogoldi.github.io/reverse-engineer/blog/studiosecghost-hvnc-browser-piggyback/).

SHA-256: `5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852`

TLP: TLP:CLEAR | Author: taogoldi | Date: 2026-05-19

## Contents

- `detection/studiosecghost.rules` -- Suricata rules (sids 9300101-9300104)
- `scripts/recon.py` -- pefile + capstone packing/obfuscation indicator pass
- `scripts/extract_config.py` -- sample-agnostic UTF-16LE config lifter
- `scripts/deep_disasm.py` -- targeted function reversing with string xref + IAT annotation
- `scripts/render_terminal_screenshots.py` -- PIL/Pillow terminal-style PNG screenshot generator
- `scripts/ida_rename_studiosecghost.py` -- IDA Python rename pass (26 anchors)
- `reports/extracted_config.json` -- full static config lifted from .rdata
- `reports/studiosecghost_analysis_report.json` -- pefile PE analysis report
- `reports/deep_disasm.txt` -- full disassembly snapshot (~3,500 lines)

YARA rules are in [taogoldi/YARA/hvnc/studiosecghost](https://github.com/taogoldi/YARA/tree/main/hvnc/studiosecghost).

**Do not share the binary.** Reference by SHA-256 only and pull from MalwareBazaar / VirusTotal.
