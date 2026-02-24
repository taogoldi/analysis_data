# 22.exe Execution Workflow And Stage Offsets

## High-level flow

```text
22.exe (Stage0 loader)
  -> AMSI/ETW in-memory patching
  -> Anti-sandbox scoring gates
  -> Read encrypted blob/key/IV from .data/.rdata
  -> AES-256-CBC decrypt
  -> stage2_dec_unpadded.bin (Stage2 PE)
  -> Stage2 resolver/decoder logic (config not fully decoded yet)
```

## Sample-specific offsets (22.exe)

- Image base: `0x140000000`
- AMSI patch bytes VA: `0x140005120` (hex: `b857000780c3`)
- Encrypted stage2 blob VA: `0x140005140`
- Encrypted blob size VA: `0x1400A3560` (value: `0x9E410`)
- ETW patch bytes VA (primary): `0x1400A3570` (hex: `31c0c3`)
- ETW patch bytes VA (fallback): `0x1400A3580` (hex: `c21400`)
- AES IV VA: `0x1400A3590`
- AES key VA: `0x1400A35A0`

## Config extraction guidance

1. Reverse stage2 entry/call graph to locate string/API resolver and decode loops.
2. Identify encoded data reads from `.data` / `.rdata` and their transformation routine.
3. Dump post-decode buffers (or reimplement decoder offline) and validate with URL/command schema checks.
4. Record function VA, blob offset, key/seed state, output size, and resulting indicators.

