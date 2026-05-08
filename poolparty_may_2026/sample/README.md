# PoolParty corpus, companion binaries to `poolparty_blog_draft.md`

> ⚠️ **THESE ARE LIVE MALWARE BINARIES.** ⚠️
>
> Every file in this directory is a real, in-the-wild PoolParty
> implementation flagged as malicious by 32–56 of 70+ AV engines on
> VirusTotal. Treat them with the same handling discipline you'd apply
> to a MalwareBazaar pull:
>
> - Extract only inside an air-gapped or isolated VM / container.
> - Do **not** double-click on a host you care about. Windows Defender
>   will quarantine, but assume execution = infection.
> - Do not redistribute outside controlled channels (research peers,
>   sandbox uploads). The originals are publicly available on
>   VirusTotal under the SHA-256s below; cite the SHA, not the file.

## Contents

All three samples are wrapped in standard password-protected ZIPs. The
password is the same across all three:

```
infected
```

(Convention used by MalwareBazaar, vx-underground, abuse.ch, and most
malware-research distributions.)

| Archive | SHA-256 (extracted) | Size (raw) | Detection | Tag |
|---|---|---|---|---|
| `sample_A_24c14165_PoolInject_50KB.zip` | `24c141656d4a9f75513d167f0a4664a8bfe63ecd93e27b5e5b150b0e89b0e8b7` | 50,688 B | 32 / 70 | Smallest dropper, defeats existing capa rules |
| `sample_B_4cfc8ee7_PoolPartyA_canonical.zip` | `4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5` | 807,936 B | 56 / 73 | Canonical multi-variant tool; Microsoft `VirTool:Win64/PoolParty.A!MTB` |
| `sample_C_849e64db_ITW_USBLBR26.zip` | `849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c` | 837,120 B | 52 / 71 | March 2026 ITW campaign bundle; Trend `Trojan.Win32.POOLPARTY.USBLBR26` |

## Why they're here

Concrete reproducibility for the analysis in
[`../docs/poolparty_blog_draft.md`](../docs/poolparty_blog_draft.md). Specifically:

- The capa runs in **Step 3** ("Static fingerprint via capa") were
  performed against these exact files.
- The disassembly snippet at `0x14001bba4` in the **"Variant 7 in the
  wild"** subsection was pulled from `sample_B`.
- The five new capa rules listed in **Step 6** include these SHA-256s
  as `examples:` entries so a future capa contributor can verify the
  rules fire on real ITW.

## Extracting (one example)

```bash
# Linux / macOS, into an isolated container:
unzip -P infected sample_B_4cfc8ee7_PoolPartyA_canonical.zip
# Result: 4cfc8ee7…f0c2a0247a382c5.bin  in current directory.

# Confirm hash matches before any further action:
sha256sum 4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5.bin
```

## Verification on VirusTotal

If you'd rather pull from VT than trust this archive, the same SHAs are
on VirusTotal, paste any of the three SHA-256s into
<https://www.virustotal.com/gui/search>. Submitter and first-seen
timestamps will match.

## Removal

```bash
rm sample_A_*.zip sample_B_*.zip sample_C_*.zip
```

If you cloned this repo on a machine where you don't want these files
present, the parent `.gitattributes` does **not** force-fetch them via
LFS, so a `git rm` plus push is sufficient. (They're not LFS-tracked;
they're 360 KB each, well under git's soft limit.)
