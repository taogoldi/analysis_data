# PoolParty thread-pool process injection - analysis bundle

Companion artifacts for the blog post at
<https://taogoldi.github.io/reverse-engineer/blog/poolparty-itw-2026/>.

## Sample identification

| Field | Sample A | Sample B | Sample C |
|---|---|---|---|
| Role | Small dropper, single TP_DIRECT variant | Canonical SafeBreach research build, all 8 variants | March 2026 ITW campaign artifact |
| SHA-256 | `24c141656d4a9f75513d167f0a4664a8bfe63ecd93e27b5e5b150b0e89b0e8b7` | `4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5` | `849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c` |
| File size | ~50 KB | ~808 KB | ~837 KB |
| Headline trait | `论文` PDB path; defeats existing capa TP_WORK rule by register-allocation luck | `boost::log` documentary phase strings name every variant in plain ASCII / wide | `.text` byte-equivalent to Sample B after trim; outer `pe_to_shellcode` reflective loader with malformed-MZ trampoline |
| Family names | PoolParty / PoolInject (Microsoft, ESET, Sophos, Trend, Kaspersky) |  |  |

Sample B's `.text` and Sample C's `.text` are **byte-identical after trimming trailing alignment padding** (both 592,879 bytes; same `sha256` prefix `84d3d739bf76d53b`). The 29 KB on-disk delta between them is delivery wrapping (the hasherezade `pe_to_shellcode` stub), not new code. The `scripts/verify_sample_text_identity.py` helper reproduces this proof.

## Layout

```
poolparty_may_2026/
├── README.md                                 (this file)
├── docs/
│   └── poolparty_blog_draft.md               blog source markdown
├── detection/
│   ├── poolparty.yar                         cross-variant YARA, 4 detection paths
│   └── capa/
│       ├── inject-shellcode-using-thread-pool-work-insertion-with-tp_direct.yml
│       ├── inject-shellcode-using-thread-pool-work-insertion-with-tp_alpc.yml
│       ├── inject-shellcode-using-thread-pool-work-insertion-with-tp_job.yml
│       ├── inject-shellcode-using-thread-pool-work-insertion-with-tp_wait.yml
│       └── inject-shellcode-using-worker-factory-start-routine-overwrite.yml
├── scripts/
│   ├── api_hash_reverser.py                  CRC32-IEEE-802.3 reverser for Sample C's
│   │                                          pe_to_shellcode wrapper hashes
│   ├── verify_sample_text_identity.py        byte-level proof Sample C is wrapped Sample B
│   └── poolparty_rename_sample_b.py          IDAPython annotation pass for Sample B
├── images/                                   IDA screenshots (Sample B variant 7 / variant 6)
└── sample/
    └── README.md                             corpus identification and acquisition notes
```

## What is and isn't redistributed

The three sample binaries themselves are **not** redistributed in this bundle. Pull them from VirusTotal, MalwareBazaar, MWDB CERT-PL, or the SafeBreach reference repository by SHA-256:

- Sample A: VT search by `24c141656d4a9f75513d167f0a4664a8bfe63ecd93e27b5e5b150b0e89b0e8b7`
- Sample B: <https://github.com/SafeBreach-Labs/PoolParty> (compiled artifact) or VT by `4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5`
- Sample C: <https://mwdb.cert.pl/file/849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c>

The blog post contains every offset, hex value, and fingerprint needed to verify the analysis end to end against the original binaries.

## Capa rules status

The five rules in `detection/capa/` are **draft nursery candidates**, not finished detections. They are ready for local testing today and intended for upstream PR to `mandiant/capa-rules` after capa-lint and a wider corpus burn-in. They are released under the same Apache 2.0 license as upstream `capa-rules`.

## YARA rule

`detection/poolparty.yar` is also mirrored at <https://github.com/taogoldi/YARA/tree/main/injectors/poolparty>.

## License

Apache 2.0 for the rules and scripts. Blog text is CC BY 4.0.
