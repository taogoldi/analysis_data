# Mirai Static Analysis Notes

## What This Sample Appears To Be

This ELF is a Mirai-like Stage1 bot with high confidence based on:

- Explicit method dispatch strings (`udp`, `syn`, `ack`, `udpslam`, `junk`, `raknet`, `udpburst`)
- Killer/competition-removal logic (`disable_infection_tools`, `scan_and_kill`)
- Hardcoded authorized server IP verification path before command execution
- DDoS payload templates (SSDP, SIP, CHARGEN, memcached/NTP-style probes)

## High-Signal Findings

- Authorized C2 IP string: `144.172.108.230` (VA `0x41498A`)
- Server trust gate function: `verify_server_ip` (VA `0x4001C0`)
- Kill command token: `!SIGKILL` (VA `0x4149C6`)
- Main parser/dispatch loop: `main` (VA `0x4002A0`)
- Anti-infection tools path list loaded in `disable_infection_tools`:
  - `/usr/bin/wget`, `/usr/bin/curl`, `/usr/bin/tftp`, `/usr/bin/ftp`
  - `/usr/bin/scp`, `/usr/bin/nc`, `/usr/bin/netcat`, `/usr/bin/ncat`

## Analyst Workflow In This Folder

1. `python3 scripts/run_full_analysis.py`
2. Review:
   - `reports/json/triage_report.json`
   - `reports/json/rodata_artifacts.json`
   - `reports/json/fortinet_gayfemboy_overlap.json`
   - `reports/disasm/disasm_index.json`
3. Load sample in IDA and run:
   - `ida_python/mirai_stage1_annotator.py`
   - `ida_python/mirai_string_hunt_annotator.py`
