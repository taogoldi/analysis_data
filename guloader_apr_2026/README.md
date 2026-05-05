# GuLoader (NSIS variant) staging Remcos 7.2.3 Pro - analysis bundle

Companion artefacts for the blog post at
<https://taogoldi.github.io/reverse-engineer/blog/guloader-nsis-shellcode-loader/>.

## Sample identification

| Field | Value |
|---|---|
| Outer family | GuLoader (also known as CloudEye, VBdropper) |
| Outer SHA-256 | `39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6` |
| Outer MD5 | `7d784ec37ec7bcac8a9c735a35b06449` |
| File size | 1,043,029 bytes |
| Format | NSIS-3 Unicode self-extracting installer (PE32, Windows GUI, i386) |
| Compile timestamp | 2025-03-08 23:05:20 UTC |
| Original delivery name | `RFQ__________pdf.exe` (Request-for-Quotation phishing lure) |
| Final-stage family | Remcos 7.2.3 Pro |
| Remcos C2 | `31.57.184.186:2404` (raw TCP, default Remcos port) |
| Remcos botnet name | `RemoteHost` |
| Remcos mutex | `Rmc-JUY15N` |
| Final-stage packer | MPRESS (per ANY.RUN tagging) |
| Stage-2 staging | Google Drive (`drive.google.com` direct-download URL) |

## Layout

```
guloader_apr_2026/
├── README.md                          (this file)
├── docs/
│   └── guloader_blog_draft.md         blog source markdown
├── detection/
│   └── guloader_nsis.yar              4 YARA rules:
│                                      - GuLoader_NSIS_Outer (outer dropper)
│                                      - GuLoader_NSIS_DroppedScriptArtifacts
│                                      - GuLoader_NSIS_DecoyPadding
│                                      - GuLoader_NSIS_Generic
├── scripts/
│   ├── nsis_disasm.py                 NSIS-3 Unicode bytecode disassembler
│   ├── nsis_disasm2.py                same, with raw control-flow args
│   ├── nsis_emulator.py               NSIS opcode emulator capturing System::Call
│   ├── decode_piasaba.py              4-byte XOR + 0xAC pad strip for the
│                                       stage-1 shellcode container
│   ├── build_rainbow.py               GuLoader-hash rainbow table builder
│   ├── ida_apply_rainbow.py           IDAPython: apply API names to dwords
│   ├── ida_strip_junk.py              IDAPython: mark anti-disasm junk as data
│   ├── ida_map_slots.py               IDAPython: map [ebp+SLOT] to API names
│   ├── emulate_shellcode.py           Unicorn shellcode emulator with fake PEB
│   ├── rainbow_table.txt              precomputed rainbow output
│   └── gen_og_card.py                 social card generator
├── reports/json/
│   ├── guloader_analysis_report.json  structured static + cross-reference report
│   ├── nsis_disasm_full.txt           full 228-entry opcode dump
│   └── nsis_disasm_v2.txt             v2 dump with raw control-flow args
└── images/
    ├── kill_chain.{mmd,png}           outer execution flow
    ├── dropped_files.{mmd,png}        19 dropped files mapped by role
    └── nsis_obfuscation.{mmd,png}     word-salad obfuscation diagram
```

## What is and isn't redistributed

- All YARA rules, scripts (NSIS disassembler, emulator, decoder, rainbow table builder, three IDAPython helpers, Unicorn shellcode emulator), the structured analysis JSON, the full opcode dump, and the three Mermaid diagrams are here.
- The NSIS dropper binary, the encrypted `piasaba` and `Toolers` blobs, the dropped `System.dll` plugin, and the downloaded Remcos PE are **not** redistributed. Pull from MalwareBazaar:
  <https://bazaar.abuse.ch/sample/39c0135a0e8d46053fbcaa4efe6cbc83d33cf8e7be43efbca1622b2f77c7b9c6/>

## Mirrors

- YARA rules also live under [taogoldi/YARA/loaders/guloader](https://github.com/taogoldi/YARA/tree/main/loaders/guloader).
- Downloads index for the post: <https://taogoldi.github.io/reverse-engineer/downloads/guloader/>.

## Reusing the tooling

```
# Disassemble the NSIS bytecode
python3 scripts/nsis_disasm.py path/to/sample.exe > opcodes.txt

# Decrypt the stage-1 shellcode container
python3 scripts/decode_piasaba.py path/to/piasaba path/to/piasaba_decoded.bin

# Build a rainbow table over candidate API/module names and search a binary
python3 scripts/build_rainbow.py path/to/piasaba_decoded.bin
```

## License / attribution

YARA rules and scripts: MIT, attribute as Tao Goldi when reused.
The blog source markdown is CC BY 4.0 (matches the rest of the catalogue).
