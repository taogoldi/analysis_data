# Pony / Fareit — April 2026 analysis bundle

Companion artefacts for the blog post  
**[Pony/Fareit: Inside the Credential Machine That Targeted 60+ FTP Clients](https://taogoldi.github.io/reverse-engineer/blog/pony-fareit-credential-machine/)**.

Sample analysed: `805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236`  
(32-bit PE32 credential stealer; not redistributed from this repository.)

## Contents

| Path | Purpose |
|---|---|
| [`scripts/pony_config_extractor.py`](scripts/pony_config_extractor.py) | One-shot static extractor. Pulls URLs, FTP/email/browser targets, HWID format, User-Agent, ack token, and auto-detects the `GetTickCount` anti-emulation modulus. `pefile` only; pure static. |
| [`scripts/ida_pony_setup.py`](scripts/ida_pony_setup.py) | IDAPython: installs TEB/PEB/sockaddr_in structs, renames 6 key functions, sets Hex-Rays prototypes, prototypes WSock32 imports, annotates `FS:[0x30]` as `TEB_MIN.ProcessEnvironmentBlock`. |
| [`scripts/ida_pony_md5_pretty.py`](scripts/ida_pony_md5_pretty.py) | IDAPython: defines `MD5_STATE`, installs `MD5_T_CONST` enum with all 64 RFC 1321 constants, retypes `md5_transform`, renames the 67 SSA temporaries using the a/d/c/b rotation convention. |
| [`scripts/README_screenshots.md`](scripts/README_screenshots.md) | Guide for capturing every figure in the blog post from a fresh IDA database. |
| [`detection/pony_stealer.yar`](detection/pony_stealer.yar) | Two paired YARA rules (credential-theft tell-set + HTTP network fingerprint). |
| [`reports/pony_stealer_analysis_report.json`](reports/pony_stealer_analysis_report.json) | Structured hand-authored report — crypto, capabilities, IOCs, MITRE mapping, variant-timeline note. |
| [`reports/pony_extracted_config.json`](reports/pony_extracted_config.json) | Machine-readable output of the extractor script on the analysed sample. |
| [`docs/pony_stealer_blog_draft.md`](docs/pony_stealer_blog_draft.md) | Source markdown of the blog post (kept here for archival / offline reading). |
| [`docs/kill_chain.mmd`](docs/kill_chain.mmd) | Mermaid source for the kill-chain flowchart. |

## Quickstart — extractor

```bash
pip install pefile
python3 scripts/pony_config_extractor.py /path/to/pony_sample.exe
# or JSON:
python3 scripts/pony_config_extractor.py -j /path/to/pony_sample.exe > extracted.json
```

## Quickstart — IDAPython

In IDA Pro 7.7 – 9.x, with the sample loaded and auto-analysis complete:

1. `File > Script file...` → `scripts/ida_pony_setup.py`
2. `File > Script file...` → `scripts/ida_pony_md5_pretty.py`
3. Close any open pseudocode tab, jump to `md5_transform` (`0x00402D3E`), press `F5`.

## License

Scripts and reports in this directory are released under the **MIT License**. YARA rules carry their own author/reference metadata.

## Not included

- The sample binary itself (available on request for legitimate research; do not expect us to post malware to a public repository).
- Screenshots of the analysed sample — those live in the blog post assets at `taogoldi.github.io/reverse-engineer`.

## Credit

Prior-art referenced in the blog post:

- [Guillaume Orlando — Malware Analysis: Pony](https://guillaumeorlando.github.io/Pony-malware-analysis)
- [Malpedia: win.pony](https://malpedia.caad.fkie.fraunhofer.de/details/win.pony)
- [XyliBox — Pony 1.9 (Win32/Fareit)](https://www.xylibox.com/2013/05/pony-19-win32fareit.html)
- [InfoSec Institute — Reversing the Pony Trojan Part I / II](https://resources.infosecinstitute.com/topic/reversing-the-pony-trojan-part-i/)

See the blog post's *Prior Art and Further Reading* section for the full bibliography.
