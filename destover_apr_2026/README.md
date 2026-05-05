# Destover (SPE Wiper / Wiper.A) analysis bundle

Companion artefacts for the blog post at
<https://taogoldi.github.io/reverse-engineer/blog/destover-sony-signed-backdoor/>.

## Sample identification

| Field | Value |
|---|---|
| Family | Destover (also tracked as Wiper.A, SPE Wiper, Volgmer-related) |
| Actor | Lazarus Group / DarkSeoul |
| Campaign | Sony Pictures Entertainment intrusion (Nov-Dec 2014) |
| SHA-256 | `4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c` |
| SHA-1 | `8397c1e1f0b9d53a114850f6b3ae8c1f2b2d1590` |
| MD5 | `e904bf93403c0fb08b9683a9e858c73e` |
| Size | 91,888 bytes |
| Format | PE32 GUI x86 |
| Compile timestamp | 2014-07-07 08:01:09 UTC |
| Authenticode signing time | 2014-12-05 21:29:35 UTC |
| Signer | Sony Pictures Entertainment Inc. (Culver City, CA) |
| Issuer | DigiCert Assured ID Code Signing CA-1 (revoked Dec 2014) |
| C2 IPs | `203.131.222.102:443` (Thailand), `208.105.226.235:443` (United States) |

## Layout

```
destover_apr_2026/
├── README.md                            (this file)
├── docs/
│   └── destover_blog_draft.md           blog source markdown
├── detection/
│   └── destover.yar                     two paired YARA rules:
│                                        - Destover_Lazarus_Backdoor_2014
│                                        - Destover_Stolen_Sony_Certificate
├── scripts/
│   ├── destover_config_extractor.py     pulls C2 IPs, decoded API list,
│                                         version-info masquerade, and
│                                         Authenticode signer in one static pass
│   └── gen_og_card.py                   social card generator
├── reports/json/
│   └── destover_analysis_report.json    structured static + family report
└── images/
    ├── kill_chain.{mmd,png}             execution flow (entry to shutdown)
    ├── api_obfuscation.{mmd,png}        dot-space API decoding diagram
    └── c2_state_machine.{mmd,png}       full C2 thread state machine
```

## What is and isn't redistributed

- The two paired YARA rules, the static config extractor, the structured
  analysis JSON, and the kill-chain / API-obfuscation / C2-state-machine
  diagrams are all here.
- The Destover binary itself is **not** redistributed in this bundle. Pull
  from MalwareBazaar or VirusTotal:
  <https://bazaar.abuse.ch/sample/4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c/>

## Mirrors

- YARA rules also live under [taogoldi/YARA/backdoors/destover](https://github.com/taogoldi/YARA/tree/main/backdoors/destover).
- Downloads index for the post: <https://taogoldi.github.io/reverse-engineer/downloads/destover/>.

## Reusing the config extractor

```
python3 scripts/destover_config_extractor.py path/to/Destover.exe
```

Pulls the Authenticode signer, the version-info masquerade fields, the two
hard-coded C2 IPs, and the full decoded list of dot-space-obfuscated Win32
API names. Pure static; no detonation, no network, no sandbox required.

## License / attribution

YARA rules and scripts: MIT, attribute as Tao Goldi when reused.
The blog source markdown is CC BY 4.0 (matches the rest of the catalogue).
