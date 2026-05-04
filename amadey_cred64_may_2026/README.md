# Amadey 5.78 `cred64.dll` plugin (botnet `54e64e`) — analysis bundle

Companion artefacts for the blog post at
<https://taogoldi.github.io/reverse-engineer/blog/amadey-cred64-credential-stealer-plugin/>.

## Sample identification

| Field | Value |
|---|---|
| Family | Amadey 5.78 |
| Plugin | `cred` (credential stealer, x64 build) |
| Botnet ID | `54e64e` |
| SHA256 (x64) | `3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69` |
| SHA256 (x86 sibling) | `b27ecd6a59c7d2471f7d407567d1b33068845ec89f5e0a76e18dc720cc69e80d` |
| Compile timestamp | 2026-03-08 19:10:56 UTC |
| C2 | `hxxp://91.92.242[.]236/oPvjr94jfe/index.php` |
| Panel | `hxxp://91.92.242[.]236/oPvjr94jfe/Login.php` |

## Layout

```
amadey_cred64_may_2026/
├── README.md                          (this file)
├── docs/
│   └── amadey_cred64_blog_draft.md    blog source markdown
├── detection/
│   └── amadey_cred64.yar              7 YARA rules (PDB, key, encrypted config,
│                                       exports, import profile, wifi, composite)
├── scripts/
│   ├── decoder.py                     Vigenère + Base64 reproduction
│   └── ida_rename_amadey.py           idempotent IDApython annotation pass
├── reports/json/
│   ├── decoded_strings.json           99 decoded config strings
│   └── amadey_cred64_analysis_report.json
├── images/
│   ├── killchain.{mmd,png}
│   ├── string_decrypt.{mmd,png}
│   └── ida/                           Hex-Rays + hex-view screenshots
└── c2_probe/
    └── panel_artifacts/               headers and HTML captured during the
                                       live C2 probe (no malware binaries)
```

## What is and isn't redistributed

- The YARA rules, the decoder script, the IDApython annotation pass, the
  decoded strings table, the analysis JSON, the kill-chain and decode-pipeline
  diagrams, and the IDA screenshots are all here.
- The `cred64.dll` and `cred.dll` malware binaries are **not** redistributed
  in this bundle. Pull them from MalwareBazaar if you need the live samples:
  <https://bazaar.abuse.ch/sample/3bdcb32460e5a613c35b14205e4a98ad50a03a1d7d17f4c30f2935c6f6d5db69/>

## Mirrors

- YARA rules also live under [taogoldi/YARA/stealers/amadey](https://github.com/taogoldi/YARA/tree/main/stealers/amadey).
- Downloads index for the post: <https://taogoldi.github.io/reverse-engineer/downloads/amadey-cred64/>.

## Reusing the decoder

```
python3 scripts/decoder.py 'OMvwTRBuH9OvB9LoFd=='
# -> '91.92.242.236'

python3 scripts/decoder.py --bin cred64.dll --printable-only
# harvests every Vigenère+B64 blob in the binary and prints the decoded form
```

The keystream / Vigenère / Base64 algorithm and key constants are documented
inline in `scripts/decoder.py` and in the blog post §"String Obfuscation".

## License / attribution

YARA rules and scripts: MIT, attribute as Tao Goldi when reused.
The blog source markdown is CC BY 4.0 (matches the rest of the catalogue).
