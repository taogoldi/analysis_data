"""
StudioSecGhost: deep recon pass.
- Packing indicators (entropy windows, TLS callbacks, anomalous imports).
- LLVM-style obfuscation indicators (CFF, opaque-predicate patterns).
- Locate the C2 IP literal and surrounding config blob.
- Map subsystem strings to .rdata offsets and look up the first xref via
  a quick code scan (no IDA needed for the byte search).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Default sample path is resolved relative to this script's parent directory.
# Override by passing an absolute path on argv[1].
_REPO = Path(__file__).resolve().parent.parent
SAMPLE = _REPO / "sample" / (
    "5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852.exe"
)

ANCHORS_ASCII = [
    b"[INIT] Agent running. All subsystems active.",
    b"[INIT] NetInit (WSAStartup) failed. Aborting.",
    b"[CHROME] Found ghost among hidden windows: HWND=%p",
    b"[CHROME] Firefox prefs.js patched: crash recovery disabled.",
    b"[VNC] StreamThread started (%dx%d)%s.",
    b"[VNC] WindowCapturer: init OK (%dx%d), HWND=%p.",
    b"[NET] AgentNetwork started. Target: %ls:%u",
    b"[NET] AUTH_LOGIN sent: '%ls' (browsers: %d, active: %d)",
    b"[INIT] Replica deployed: slot %d",
    b"[INIT] Watchdog restored replica slot %d",
]

C2_IP_UTF16 = "2.26.122.211".encode("utf-16-le")
C2_IP_ASCII = b"2.26.122.211"


def main() -> None:
    data = SAMPLE.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)

    print("=" * 70)
    print("PACKING / OBFUSCATION RECON")
    print("=" * 70)

    # --- TLS callbacks ---------------------------------------------------
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls and tls.struct.AddressOfCallBacks:
        print(f"TLS callback table @ VA {tls.struct.AddressOfCallBacks:#x}")
        # Walk callbacks
        rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        off = pe.get_offset_from_rva(rva)
        cb_count = 0
        while True:
            cb_va = int.from_bytes(data[off:off+8], "little")
            if cb_va == 0:
                break
            print(f"  callback[{cb_count}] = {cb_va:#x}")
            cb_count += 1
            off += 8
        if cb_count == 0:
            print("  (table present but empty)")
    else:
        print("TLS callbacks: NONE")

    # --- Section entropy windowing for packed regions --------------------
    print("\nSection entropy (windowed, 4KB blocks):")
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        raw = s.get_data()
        whole = pe_entropy(raw)
        # 4KB windows
        windows = []
        for i in range(0, len(raw), 4096):
            chunk = raw[i:i+4096]
            if len(chunk) >= 256:
                windows.append(pe_entropy(chunk))
        if windows:
            hi = max(windows)
            lo = min(windows)
            print(f"  {name:<10} whole={whole:.3f}  windows: lo={lo:.3f} hi={hi:.3f}  n={len(windows)}")

    # --- Anomalous imports flag -----------------------------------------
    print("\nImport DLL set:")
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for d in pe.DIRECTORY_ENTRY_IMPORT:
            dll = d.dll.decode("ascii", errors="replace")
            print(f"  {dll}: {len(d.imports)} imports")
    has_loadlib = any(
        imp.name == b"LoadLibraryA"
        for d in pe.DIRECTORY_ENTRY_IMPORT
        for imp in d.imports if imp.name
    )
    has_getproc = any(
        imp.name == b"GetProcAddress"
        for d in pe.DIRECTORY_ENTRY_IMPORT
        for imp in d.imports if imp.name
    )
    has_virtalloc = any(
        imp.name and imp.name.startswith(b"VirtualAlloc")
        for d in pe.DIRECTORY_ENTRY_IMPORT
        for imp in d.imports if imp.name
    )
    print(f"\nLoadLibraryA imported: {has_loadlib}")
    print(f"GetProcAddress imported: {has_getproc}")
    print(f"VirtualAlloc* imported: {has_virtalloc}")
    print("  (all three present together is a classic packer/unpacker signal)")

    # --- Locate C2 IP ----------------------------------------------------
    print("\n" + "=" * 70)
    print("C2 IP LITERAL LOCATIONS")
    print("=" * 70)
    offsets_utf16 = list(_find_all(data, C2_IP_UTF16))
    offsets_ascii = list(_find_all(data, C2_IP_ASCII))
    for off in offsets_utf16:
        rva = pe.get_rva_from_offset(off)
        va = pe.OPTIONAL_HEADER.ImageBase + rva
        sect = _section_of_rva(pe, rva)
        print(f"  UTF-16LE @ file=0x{off:x}  RVA=0x{rva:x}  VA={va:#x}  section={sect}")
        # Show 64 bytes of surrounding context
        ctx = data[off-32:off+64]
        print(f"    ctx: {ctx.hex(' ')}")
    for off in offsets_ascii:
        rva = pe.get_rva_from_offset(off)
        sect = _section_of_rva(pe, rva)
        print(f"  ASCII    @ file=0x{off:x}  RVA=0x{rva:x}  section={sect}")

    # --- Anchor-string addressability ------------------------------------
    print("\n" + "=" * 70)
    print("ANCHOR STRING -> RDATA OFFSET / VA")
    print("=" * 70)
    text_section = next(s for s in pe.sections if s.Name.startswith(b".text"))
    text_data = text_section.get_data()
    text_va = pe.OPTIONAL_HEADER.ImageBase + text_section.VirtualAddress

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    for anchor in ANCHORS_ASCII:
        hits = list(_find_all(data, anchor))
        if not hits:
            print(f"  NOT FOUND: {anchor[:60]!r}")
            continue
        off = hits[0]
        rva = pe.get_rva_from_offset(off)
        va = pe.OPTIONAL_HEADER.ImageBase + rva
        xref_va = _find_lea_to(text_data, text_va, va, md)
        xref_str = f"first lea @ {xref_va:#x}" if xref_va else "NO LEA REF FOUND"
        print(f"  VA={va:#x}  off=0x{off:x}  {xref_str}  : {anchor[:50]!r}")

    # --- Obfuscation indicators in .text --------------------------------
    print("\n" + "=" * 70)
    print(".text OBFUSCATION INDICATORS")
    print("=" * 70)
    text = text_data
    # Counts that should be near-zero in clean MSVC output
    je_jne_chains = len(re.findall(rb"\x0f\x84.{4}\x0f\x85", text))  # je rel32 ; jne rel32
    indirect_jmp = text.count(b"\xff\xe0") + text.count(b"\xff\xe1") + \
                   text.count(b"\xff\xe2") + text.count(b"\xff\xe3")
    indirect_call = text.count(b"\xff\xd0") + text.count(b"\xff\xd1") + \
                    text.count(b"\xff\xd2")
    xor_eax_pattern = len(re.findall(rb"\x33\xc0\x0f[\x84\x85]", text))
    int3_padding = text.count(b"\xcc")
    nop_runs = len(re.findall(rb"\x90{4,}", text))
    print(f"  je rel32 ; jne rel32 chains (CFF predicate hint): {je_jne_chains}")
    print(f"  reg-only indirect JMP (jmp rax/rcx/rdx/rbx) ops: {indirect_jmp}")
    print(f"  reg-only indirect CALL (call rax/rcx/rdx) ops: {indirect_call}")
    print(f"  xor eax,eax ; je/jne (opaque predicate?): {xor_eax_pattern}")
    print(f"  int3 bytes (function-alignment padding, normal): {int3_padding}")
    print(f"  nop runs >=4 (rare in optimised MSVC): {nop_runs}")


# ---- helpers ----

def _find_all(blob: bytes, needle: bytes):
    start = 0
    while True:
        idx = blob.find(needle, start)
        if idx < 0:
            return
        yield idx
        start = idx + 1


def _section_of_rva(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
    return "?"


def pe_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def _find_lea_to(text: bytes, text_va: int, target_va: int, md) -> int | None:
    """Disassemble .text and return the first `lea reg, [rip+disp]` whose
    effective address equals target_va. Returns the instruction VA, or None.
    """
    for insn in md.disasm(text, text_va):
        if insn.mnemonic == "lea" and "rip" in insn.op_str:
            # operand looks like  reg, [rip + 0x...]
            # Effective addr = end_of_insn + disp
            try:
                # capstone gives op_str like "rax, [rip + 0x1234]" or "rax, [rip - 0x10]"
                m = re.search(r"\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]", insn.op_str)
                if not m:
                    continue
                sign = 1 if m.group(1) == "+" else -1
                disp = sign * int(m.group(2), 16)
                eff = insn.address + insn.size + disp
                if eff == target_va:
                    return insn.address
            except Exception:
                pass
    return None


if __name__ == "__main__":
    main()
