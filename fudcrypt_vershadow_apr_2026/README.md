# FUD Crypt — VerShadow VERSION.dll Carrier (April 2026)

Analyst artefacts for the post:
**[VerShadow / FUD Crypt: A MinGW VERSION.dll Carrier With A Catbox Fallback And A Live Test Payload](https://taogoldi.github.io/reverse-engineer/blog/fudcrypt-vershadow-version-dll-carrier/)**

## Sample identifiers (loader)

| | |
| --- | --- |
| SHA256  | `c73947cf188f442bed228f62a3ba5611009fdc2f1878aaed7065db95ede05521` |
| SHA1    | `9215d1233d6110b156480cc70d79afdf49181d37` |
| MD5     | `3201f19c0bb2ddf430ae6da4d30a8cd9` |
| Imphash | `e2c01fb3adc4845e1ae802a2da8afff9` |
| TLSH    | `T1FC341D91B281FDB6DC698F7820D25309A3BAF081971DEB2F6620FE3C025EB54D573685` |

## Stage-2 (decrypted .NET QA stub)

| | |
| --- | --- |
| SHA256 | `86e9024c21478f7fa59bf95aef8e7bfb869ed872e8a92e7ca19118df0f74f457` |
| SHA1   | `d81b50362c2255c0ac46f3ea894b0f2802372a49` |
| MD5    | `1c38f7abf65f19221e9f8b1bd345e6bc` |

## Stage-2 ciphertext (live pull from catbox on 2026-04-26)

| | |
| --- | --- |
| URL    | `hxxps[:]//files[.]catbox[.]moe/v5fllr[.]bin` |
| SHA256 | `3f631c11de145502d509b5c4b94c461da32ebadf010284c826895e253439b2f5` |

## Folder layout

- `detection/` — YARA rules (mirrored under [taogoldi/YARA/loaders/fudcrypt](https://github.com/taogoldi/YARA/tree/main/loaders/fudcrypt))
  - `vershadow.yar` — loader rule + generic ROR-13 resolver rule
  - `fudcrypt_test_payload.yar` — .NET QA stub rule (catches operator smoke-tests left exposed)
- `scripts/` — Python decryption pipeline
  - `decrypt_stage2.py` — RC4 + 32-byte rolling SUB+XOR pipeline lifted from the loader's `.data`
- `reports/json/` — full structured analysis
  - `vershadow_analysis_report.json` — schema-versioned static + dynamic + cross-reference report
- `images/` — Mermaid sources and rendered PNGs (kill chain, CLR sequence, DLL search order)
- `docs/` — blog source markdown

## Not in this bundle

The carrier executable, the encrypted catbox blob, and the decrypted .NET assembly are not redistributed here. Analysts who want them can pull from the upstream sources cited in the post (MalwareBazaar archive entry, Hybrid Analysis sample pages, the catbox URL while it lasts).
