# SPECTRALVIPER Precursor Notes (22.exe)

This note is an evidence-backed precursor for a future write-up. It documents what is confirmed from `22.exe` and what still needs deeper reversing.

## Sample identity

- File: `22.exe`
- SHA-256: `0cb5a2e3c8aa7c80c8bbfb3a5f737c75807aa0e689dd4ad0a0466d113d8a6b9d`
- Type: `PE32+ x86-64`

## Stage map

- Stage0: `22.exe` loader/stager with defense-evasion checks and patching routines.
- Stage1: Embedded AES-CBC encrypted blob in `.data`.
- Stage2: Decrypted in-memory PE (`artifacts/stage2_dec_unpadded.bin`, SHA-256 `5fa52aa9046334c86da1e9746dfe9d7bb23ec69a8b2ab77d98efd2cb1af012f3`).
- Stage3/config: Not fully decoded yet from stage2; only low-confidence string artifacts seen in cleartext.

## Confirmed defense evasion behavior

### AMSI bypass

Function path:

- `sub_140002EA0` calls patch primitive `sub_1400041A0`
- Targets: `AmsiScanBuffer`, fallback `AmsiOpenSession`

Patch bytes extracted from sample-specific VA `0x140005120`:

- `b8 57 00 07 80 c3`
- Semantics: `mov eax, 0x80070057 ; ret`

This forces AMSI routines to return a failure code quickly, reducing script/content scanning coverage.

### ETW patch

Function path:

- `sub_140002F00` calls patch primitive `sub_140004270`
- Targets: `EtwEventWrite`, `EtwEventWriteTransfer`, `NtTraceEvent`

Patch bytes extracted:

- Primary (`0x1400A3570`): `31 c0 c3` -> `xor eax, eax ; ret`
- Alternate (`0x1400A3580`): `c2 14 00` -> `ret 0x14`

Net effect: telemetry function bodies are overwritten in memory after `VirtualProtect(PAGE_EXECUTE_READWRITE)`.

### Anti-sandbox / anti-analysis checks

The stage1 contains multiple environment scoring checks and explicit sandbox markers:

- Cuckoo: `\\.\\pipe\\cuckoo`, `cuckoomon.dll`
- Sandboxie/Wine: `SbieDll.dll`, `SOFTWARE\\Wine`, Sandboxie uninstall key
- Analyst-style usernames/hostnames: `joe sandbox`, `sand box`, `maltest`, `SANDBOX`, etc.
- Process checks: `ProcessHacker.exe`, `injector.exe`
- Human-activity gate: cursor/keyboard sampling (`GetCursorPos`, `GetAsyncKeyState`)

These checks are aggregated into a heuristic score before later execution steps.

## Deobfuscation/decryption pipeline (implemented)

A deterministic extraction path is now scripted:

1. Read encrypted blob size from VA `0x1400A3560` (`0x9E410` bytes).
2. Read encrypted blob from VA `0x140005140`.
3. Read AES-256 key from VA `0x1400A35A0` (32 bytes).
4. Read AES-CBC IV from VA `0x1400A3590` (16 bytes).
5. Decrypt and unpad to recover stage2 PE.

Outputs are written under `artifacts/`:

- `enc_blob.bin`
- `aes_key.hex`
- `aes_iv.hex`
- `stage2_dec_raw.bin`
- `stage2_dec_unpadded.bin`

## C2/config status

What is confirmed right now:

- Stage2 is a valid PE and imports mostly local host/process/FS APIs.
- Cleartext C2 URL/domain was not recovered from current static triage output.
- A few low-confidence strings are present (for example `%DOWNLOADS%`, `\Network\Cookies`), but they are not enough to claim final C2.

What to do next for full config recovery:

- Reverse stage2 string/API resolver logic and locate its decryption routine.
- Identify command-dispatch table and network primitive resolution path.
- Dump post-decryption config blob at runtime boundary or emulate the decode routine offline.

## Variant assessment vs Elastic SPECTRALVIPER report

Current confidence: **possible related tradecraft; not yet a high-confidence same variant attribution**.

Why this is plausible:

- The sample strongly overlaps on tradecraft class: staged payload decryption, AMSI patching, ETW patching, anti-sandbox scoring.

Why this remains unconfirmed:

- Public string markers noted in Elastic reporting (for example the specific pipe/cookie/command labels) were not observed in cleartext in this sample set.
- That gap can happen with builder/version changes, but without decoded config/command layer we should avoid over-claiming.

## Files added for repeatable analysis

- `scripts/sv_analysis_lib.py`
- `scripts/extract_stage2_from_22.py`
- `scripts/analyze_stage1_evasion.py`
- `scripts/hunt_stage2_iocs.py`
- `scripts/assess_spectralviper_similarity.py`
- `notebooks/spectralviper_deobfuscation_walkthrough.ipynb`

