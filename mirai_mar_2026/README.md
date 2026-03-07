# Mirai ELF Analysis Workspace

## Sample

- File: `input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf`
- SHA-256: `d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28`
- Type: `ELF 64-bit LSB executable, x86-64, statically linked, not stripped`
- Variant file: `input/094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb.elf`
- Variant SHA-256: `094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb`

## Pipeline

Run everything:

```bash
python3 scripts/run_full_analysis.py --sample input/d40cf9c95dcedf4f19e4a5f5bb744c8e98af87eb5703c850e6fda3b613668c28.elf --outdir reports/variant_d40cf9c95dce
python3 scripts/run_full_analysis.py --sample input/094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb.elf --outdir reports/variant_094e9d6ee057 --capa-json input/capa_094e9d6ee057d38f40c35f018488e35ab6ccd006ed261b17322e78fd5ea2c0cb.json
```

Individual steps:

```bash
python3 scripts/triage_mirai_elf.py --sample input/<sha>.elf --outdir reports/variant_<sha12>
python3 scripts/extract_mirai_rodata_artifacts.py --sample input/<sha>.elf --outdir reports/variant_<sha12>
python3 scripts/extract_command_dispatch.py --sample input/<sha>.elf --triage-json reports/variant_<sha12>/json/triage_report.json --outdir reports/variant_<sha12>
python3 scripts/export_disasm_slices.py --sample input/<sha>.elf --outdir reports/variant_<sha12>/disasm
python3 scripts/compare_fortinet_gayfemboy.py --sample input/<sha>.elf --out reports/variant_<sha12>/json/fortinet_gayfemboy_overlap.json
python3 scripts/parse_helper_capa_summary.py --sample input/<sha>.elf --input input/capa_<sha>.json --out reports/variant_<sha12>/json/helper_capa_summary.json
```

## Output Artifacts

- `reports/variant_<sha12>/json/triage_report.json`:
  sample metadata, section map, key symbols, IOC candidates, family assessment.
- `reports/variant_<sha12>/json/rodata_artifacts.json`:
  artifact extraction with reference VA map for d40 sample and variant-safe string-driven extraction for other samples.
- `reports/variant_<sha12>/json/command_dispatch_map.json`:
  command string to handler function mapping with fixed callsites for d40 and heuristic mapping for other variants.
- `reports/variant_<sha12>/disasm/*.asm`:
  disassembly slices for key Stage1 functions.
- `reports/variant_<sha12>/json/helper_capa_summary.json`:
  normalized CAPA summary for the selected sample.
- `reports/static/*.txt`:
  raw strings, symbol table, and section summaries.
- `reports/variant_<sha12>/json/fortinet_gayfemboy_overlap.json`:
  overlap map against Fortinet Gayfemboy campaign IOCs and resolver-byte motifs.

## IDA Python

- `ida_python/mirai_stage1_annotator.py`
  - variant-aware function/data renaming and control-flow comments
  - string-xref annotations for both d40 and 094e branches
- `ida_python/mirai_string_hunt_annotator.py`
  - IOC string xref tagging (C2 IP, kill command, payload markers)
- `ida_python/mirai_dns_resolver_pattern_annotator.py`
  - variant-agnostic pattern search for DNS decode routine
  - auto-rename/type/comment for DNS resolver parsing path

## Notebook

- `notebooks/mirai_stage1_analysis.ipynb`:
  interactive walkthrough that runs the static scripts and summarizes findings.

## Detection

- `detection/mirai_like_d40cf9_rules.yar`
  - high-fidelity rule for d40 sample
  - high-fidelity rule for 094e sample
  - family-level heuristic rule validated against both samples
