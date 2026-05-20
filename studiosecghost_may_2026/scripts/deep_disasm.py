"""
StudioSecGhost: deep static disassembly of the routines that matter.

Answers the open questions from the analysis without needing IDA Pro:
  - Where does net_agent_start get the C2 port from?
  - Is the blocklist scan _wcsicmp or wcsstr?
  - What is the exact ghost-window title-compare API?
  - What does the Firefox prefs.js patch actually write?
  - Where is the command dispatch table?
  - Is there any wire-format XOR / obfuscation?
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

REPO = Path(__file__).resolve().parent.parent
SAMPLE = REPO / "sample" / (
    "5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852.exe"
)

# Anchors we already know -- each is the VA of a lea load of a known string.
ANCHORS = {
    "net_agent_start_log_lea": 0x140005f7f,
    "chrome_found_ghost_lea": 0x140008f51,
    "chrome_prefs_patched_lea": 0x14000762f,
    "vnc_stream_started_lea": 0x14000f607,
    "vnc_window_capturer_lea": 0x14000f5de,
    "init_replica_lea": 0x140002ac2,
    "init_watchdog_lea": 0x14000394a,
    "net_auth_login_lea": 0x14000ec75,
    "init_agent_running_lea": 0x140006027,
    "init_net_init_failed_lea": 0x140005b99,
}

# Known string VAs
STRING_VAS = {
    "c2_ip": 0x140049bb8,
    "studiosecghost_search": 0,  # discover
}


def main() -> None:
    pe = pefile.PE(str(SAMPLE), fast_load=False)
    data = SAMPLE.read_bytes()

    # Build IAT lookup
    iat = {}
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        dll = d.dll.decode()
        for imp in d.imports:
            if imp.name:
                iat[imp.address] = f"{dll}:{imp.name.decode()}"
            else:
                iat[imp.address] = f"{dll}:Ordinal_{imp.ordinal}"

    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
    tb = text.get_data()
    tv = pe.OPTIONAL_HEADER.ImageBase + text.VirtualAddress

    rdata = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rdata")
    rdata_bytes = rdata.get_data()
    rdata_va = pe.OPTIONAL_HEADER.ImageBase + rdata.VirtualAddress

    # Find StudioSecGhost UTF-16LE search literal
    needle = "StudioSecGhost".encode("utf-16-le")
    off = rdata_bytes.find(needle)
    if off >= 0:
        # there may be many; find the standalone one (followed by null)
        while off >= 0:
            after = rdata_bytes[off + len(needle):off + len(needle) + 2]
            if after == b"\x00\x00":
                STRING_VAS["studiosecghost_search"] = rdata_va + off
                break
            off = rdata_bytes.find(needle, off + 2)
    print(f"StudioSecGhost search literal VA: {STRING_VAS['studiosecghost_search']:#x}")

    # Find all function starts (heuristic: int3-pad followed by prologue byte)
    funcs = _find_func_starts(tb, tv)
    print(f"\nFunctions discovered by prologue scan: {len(funcs)}")

    # Map each anchor VA to its containing function
    anchor_to_func = {}
    for name, anchor_va in ANCHORS.items():
        fn = _containing_func(funcs, anchor_va)
        anchor_to_func[name] = fn
        print(f"  {name:<35} anchor={anchor_va:#x}  func={fn:#x}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    out_path = REPO / "reports" / "json" / "deep_disasm.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out = []

    # -----------------------------------------------------------------
    # 1. net_agent_start: trace EBX (the port) back from the log lea
    # -----------------------------------------------------------------
    fn_start = anchor_to_func["net_agent_start_log_lea"]
    fn_end = _next_func_after(funcs, fn_start)
    if fn_end is None:
        fn_end = fn_start + 0x2000
    out.append(_section_header(f"net_agent_start  @ {fn_start:#x}..{fn_end:#x}"))
    fn_disasm = _disasm_function(tb, tv, fn_start, fn_end, md, iat, max_lines=600)
    out.append(fn_disasm)

    # Specifically: locate every write to ebx in this function (where the port
    # could be loaded from). Patterns: 'mov ebx, ...', 'mov ebx, [...]', etc.
    ebx_writes = _find_register_writes(tb, tv, fn_start, fn_end, md, "ebx")
    out.append("\n--- WRITES TO EBX (port candidate) ---")
    for w in ebx_writes:
        out.append(f"  {w}")

    # -----------------------------------------------------------------
    # 2. Blocklist scan: find by xref to CreateToolhelp32Snapshot
    # -----------------------------------------------------------------
    iat_inv = {v: k for k, v in iat.items()}
    snap_iat_va = iat_inv.get("KERNEL32.dll:CreateToolhelp32Snapshot")
    p32first_iat_va = iat_inv.get("KERNEL32.dll:Process32FirstW")
    p32next_iat_va = iat_inv.get("KERNEL32.dll:Process32NextW")

    callers = _find_callers_of_iat(tb, tv, md, snap_iat_va)
    out.append(_section_header(
        f"CreateToolhelp32Snapshot callers: {[hex(c) for c in callers]}"
    ))
    for caller_va in callers:
        fn = _containing_func(funcs, caller_va)
        fn_end2 = _next_func_after(funcs, fn) or fn + 0x800
        out.append(f"\n=== Function {fn:#x}..{fn_end2:#x} (contains CreateToolhelp32Snapshot call) ===")
        out.append(_disasm_function(tb, tv, fn, fn_end2, md, iat, max_lines=300))

    # -----------------------------------------------------------------
    # 3. Ghost-window acquisition: find via xref to "StudioSecGhost"
    # -----------------------------------------------------------------
    ghost_va = STRING_VAS["studiosecghost_search"]
    if ghost_va:
        refs = _find_lea_refs_to(tb, tv, md, ghost_va)
        out.append(_section_header(
            f"References to 'StudioSecGhost' wide string @ {ghost_va:#x}: "
            f"{[hex(r) for r in refs]}"
        ))
        for ref_va in refs:
            fn = _containing_func(funcs, ref_va)
            fn_end3 = _next_func_after(funcs, fn) or fn + 0x600
            out.append(f"\n=== Function {fn:#x}..{fn_end3:#x} (refs StudioSecGhost) ===")
            out.append(_disasm_function(tb, tv, fn, fn_end3, md, iat, max_lines=300))

    # -----------------------------------------------------------------
    # 4. chrome_patch_firefox_prefs: dump full function around its log lea
    # -----------------------------------------------------------------
    fn_start = anchor_to_func["chrome_prefs_patched_lea"]
    fn_end = _next_func_after(funcs, fn_start) or fn_start + 0x800
    out.append(_section_header(f"chrome_patch_firefox_prefs  @ {fn_start:#x}..{fn_end:#x}"))
    out.append(_disasm_function(tb, tv, fn_start, fn_end, md, iat, max_lines=500))

    # -----------------------------------------------------------------
    # 5. CMD_* dispatch: look for cmp/sub of small integers (opcode dispatch)
    # near calls to recv()
    # -----------------------------------------------------------------
    recv_iat = iat_inv.get("WS2_32.dll:recv")
    recv_callers = _find_callers_of_iat(tb, tv, md, recv_iat)
    out.append(_section_header(
        f"recv() callers: {[hex(c) for c in recv_callers]}"
    ))
    for caller_va in recv_callers[:5]:
        fn = _containing_func(funcs, caller_va)
        fn_end4 = _next_func_after(funcs, fn) or fn + 0x1500
        out.append(f"\n=== recv-containing function {fn:#x}..{fn_end4:#x} ===")
        out.append(_disasm_function(tb, tv, fn, fn_end4, md, iat, max_lines=500))

    # -----------------------------------------------------------------
    # 6. Scan rdata for the scheduled-task XML template
    # -----------------------------------------------------------------
    out.append(_section_header("Scheduled task XML template (utf-16 search)"))
    for needle_str in ("<Triggers>", "<LogonTrigger", "<TimeTrigger",
                       "RestartOnFailure", "Count>999<", "schtasks "):
        nb = needle_str.encode("utf-16-le")
        idx = rdata_bytes.find(nb)
        if idx >= 0:
            va = rdata_va + idx
            out.append(f"  utf-16  '{needle_str}' @ {va:#x}")
        else:
            ascii_idx = data.find(needle_str.encode("ascii"))
            if ascii_idx >= 0:
                rva = pe.get_rva_from_offset(ascii_idx)
                va = pe.OPTIONAL_HEADER.ImageBase + rva
                out.append(f"  ascii   '{needle_str}' @ {va:#x}")
            else:
                out.append(f"  '{needle_str}': NOT FOUND")

    # -----------------------------------------------------------------
    # 7. XOR / packed wire-protocol check: count bulk-xor patterns in .text
    # -----------------------------------------------------------------
    out.append(_section_header("Bulk-XOR loop indicators in .text"))
    # xor byte ptr [reg+ridx], al/imm  inside a loop
    bulk_xor_byteptr_reg = len(re.findall(rb"\x30[\x00-\x3f]", tb))  # xor [reg], r8
    bulk_xor_byteptr_imm = len(re.findall(rb"\x80[\x30-\x37]", tb))  # xor byte [reg], imm8
    bulk_xor_reg_reg = len(re.findall(rb"\x32", tb))  # xor r8, r/m8
    bulk_xor_eax_eax = len(re.findall(rb"\x33\xc0", tb))  # xor eax,eax (zero idiom)
    out.append(f"  xor byte/dword [reg], reg sequences (Modrm 0x30): {bulk_xor_byteptr_reg}")
    out.append(f"  xor byte ptr [reg], imm8  sequences (Modrm 0x80 0x30-0x37): {bulk_xor_byteptr_imm}")
    out.append(f"  xor r8/r/m8 (0x32 opcode): {bulk_xor_reg_reg}")
    out.append(f"  xor eax,eax (zero idiom, normal): {bulk_xor_eax_eax}")

    out_path.write_text("\n".join(out))
    print(f"\nWrote deep disassembly to {out_path}")
    print(f"  total lines: {sum(1 for _ in (line for chunk in out for line in chunk.split(chr(10))))}")


# -- helpers ------------------------------------------------------------

def _section_header(title: str) -> str:
    return f"\n{'=' * 78}\n{title}\n{'=' * 78}"


def _find_func_starts(tb: bytes, tv: int) -> list[int]:
    """Heuristic: function starts after >=1 int3 byte and the first
    non-int3 byte is a common MSVC prologue opcode."""
    funcs = []
    prologue_starts = (
        0x48,  # rex.w prefix (most x64 prologues)
        0x4c,  # rex.wr prefix
        0x55,  # push rbp
        0x53,  # push rbx
        0x56,  # push rsi
        0x57,  # push rdi
        0x40,  # rex prefix
        0x41,  # rex.b prefix (push r12/r13/r14/r15)
    )
    in_int3 = False
    i = 0
    while i < len(tb):
        if tb[i] == 0xcc:
            in_int3 = True
        else:
            if in_int3 and tb[i] in prologue_starts:
                funcs.append(tv + i)
            in_int3 = False
        i += 1
    return funcs


def _containing_func(funcs: list[int], va: int) -> int:
    """Return the function start <= va, or va if none found."""
    candidates = [f for f in funcs if f <= va]
    return max(candidates) if candidates else va


def _next_func_after(funcs: list[int], va: int) -> int | None:
    candidates = [f for f in funcs if f > va]
    return min(candidates) if candidates else None


def _disasm_function(tb: bytes, tv: int, start_va: int, end_va: int,
                     md, iat: dict, max_lines: int = 400) -> str:
    start_off = start_va - tv
    end_off = end_va - tv
    lines = []
    count = 0
    for insn in md.disasm(tb[start_off:end_off], start_va):
        line = f"{insn.address:016x}: {insn.mnemonic:8} {insn.op_str}"
        # Annotate IAT-targeted calls and absolute lea references
        if insn.mnemonic in ('call', 'jmp') and 'rip' in insn.op_str:
            m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]', insn.op_str)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                disp = sign * int(m.group(2), 16)
                target = insn.address + insn.size + disp
                if target in iat:
                    line += f"   ; -> {iat[target]}"
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]', insn.op_str)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                disp = sign * int(m.group(2), 16)
                target = insn.address + insn.size + disp
                line += f"   ; -> {target:#x}"
        lines.append(line)
        count += 1
        if count >= max_lines:
            lines.append(f"  ... truncated at {max_lines} lines")
            break
        if insn.mnemonic == 'ret':
            # Continue past one ret for tail blocks, but stop at next int3
            pass
    return "\n".join(lines)


def _find_register_writes(tb: bytes, tv: int, start_va: int, end_va: int,
                          md, reg: str) -> list[str]:
    """Return human-readable lines of any instruction that writes to `reg`
    inside the byte window."""
    start_off = start_va - tv
    end_off = end_va - tv
    out = []
    for insn in md.disasm(tb[start_off:end_off], start_va):
        if insn.mnemonic.startswith(('mov', 'lea', 'add', 'sub', 'xor', 'or', 'and',
                                     'movzx', 'movsx', 'pop')):
            # First operand is the destination
            ops = insn.op_str.split(',', 1)
            if ops and ops[0].strip() == reg:
                out.append(f"{insn.address:#016x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic == 'ret' and insn.address > start_va + 0x10:
            # Allow continuing past short rets, but stop on a fresh int3 block
            pass
    return out


def _find_callers_of_iat(tb: bytes, tv: int, md, iat_va: int | None) -> list[int]:
    if iat_va is None:
        return []
    callers = []
    for insn in md.disasm(tb, tv):
        if insn.mnemonic == 'call' and 'rip' in insn.op_str:
            m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]', insn.op_str)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                disp = sign * int(m.group(2), 16)
                target = insn.address + insn.size + disp
                if target == iat_va:
                    callers.append(insn.address)
    return callers


def _find_lea_refs_to(tb: bytes, tv: int, md, target_va: int) -> list[int]:
    refs = []
    for insn in md.disasm(tb, tv):
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]', insn.op_str)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                disp = sign * int(m.group(2), 16)
                eff = insn.address + insn.size + disp
                if eff == target_va:
                    refs.append(insn.address)
    return refs


if __name__ == "__main__":
    main()
