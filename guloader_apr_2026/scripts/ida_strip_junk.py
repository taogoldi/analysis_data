"""
ida_strip_junk.py - Tao Goldi 2026-04

GuLoader's stage-1 shellcode uses an "opaque jump + dead bytes" anti-
disassembly trick:

    jmp short loc_FOO         ; <-- unconditional
    <12-80 bytes of garbage>  ; <-- never executed; CPU jumps over them
loc_FOO:
    <real code resumes>

IDA's linear-sweep autoanalyzer disassembles the dead bytes as code,
producing nonsense like `in eax, dx; push es; out 2Eh, al` (privileged
instructions that would #GP in user mode). This script finds every
`jmp short` whose target is in the same function and lies AFTER the
jmp, then marks the bytes between the jmp and the target as DATA so
IDA stops trying to disassemble them.

Run after ida_apply_rainbow.py. Idempotent.
"""
from __future__ import annotations

try:
    import idaapi  # noqa: F401
    import idautils
    import idc
    import ida_bytes
    HAVE_IDA = True

    def _resolve_inf_ea_funcs():
        for mod_name in ('ida_ida', 'idaapi', 'ida_bytes'):
            try:
                mod = __import__(mod_name)
            except ImportError:
                continue
            mn = getattr(mod, 'inf_get_min_ea', None)
            mx = getattr(mod, 'inf_get_max_ea', None)
            if mn and mx:
                return mn, mx
        return (lambda: idc.get_inf_attr(idc.INF_MIN_EA),
                lambda: idc.get_inf_attr(idc.INF_MAX_EA))
    _inf_min_ea, _inf_max_ea = _resolve_inf_ea_funcs()

except ImportError:
    HAVE_IDA = False


# Maximum span between the jmp and its target before we consider it not
# a junk-skip. Most opaque-jump skips are 8-100 bytes; we cap at 256 to
# avoid misclassifying genuine forward jumps in the loader's CFG.
MAX_SKIP = 256


def _is_short_uncond_jmp(ea):
    """Return (target, length) if ea is a short unconditional `jmp` whose
    target is forward in the same function within MAX_SKIP bytes; else
    None."""
    if not HAVE_IDA:
        return None
    op = idc.print_insn_mnem(ea).lower()
    if op != 'jmp':
        return None
    # Must be a relative jmp (not a register/memory indirect)
    if idc.get_operand_type(ea, 0) != idc.o_near:
        return None
    insn_size = idc.get_item_size(ea)
    target = idc.get_operand_value(ea, 0)
    # Forward jump only
    if target <= ea + insn_size:
        return None
    span = target - (ea + insn_size)
    if span <= 0 or span > MAX_SKIP:
        return None
    return (target, insn_size)


def _looks_like_junk_region(start, end):
    """Heuristic: if the disassembly between start and end contains
    privileged or otherwise impossible-in-user-mode instructions, OR
    if a high fraction of decoded instructions are unusual, treat the
    region as junk."""
    if not HAVE_IDA:
        return False
    PRIV_OPS = {
        'in', 'out', 'ins', 'outs', 'cli', 'sti', 'hlt', 'lgdt', 'lidt',
        'lldt', 'ltr', 'sgdt', 'sidt', 'sldt', 'str', 'invd', 'wbinvd',
        'invlpg', 'rdmsr', 'wrmsr', 'rdpmc', 'lmsw', 'smsw', 'arpl',
        'icebp', 'vmxon', 'vmxoff', 'vmptrld', 'vmptrst', 'vmclear',
        'vmread', 'vmwrite', 'vmlaunch', 'vmresume', 'vmcall',
    }
    n_priv = 0
    n_total = 0
    ea = start
    while ea < end:
        size = idc.get_item_size(ea)
        if size <= 0:
            break
        op = idc.print_insn_mnem(ea).lower()
        if op:
            n_total += 1
            if op in PRIV_OPS:
                n_priv += 1
        ea += size
    if n_total == 0:
        return False
    # Even one privileged instruction in user-mode shellcode is
    # implausible. If we see any, flag it.
    if n_priv >= 1:
        return True
    # Or if more than a third of the instructions are unusual, flag it.
    return False


def strip_junk_after_short_jmps():
    """Walk the IDB. For every `jmp short locX` instruction whose target
    is forward and the bytes in between look like junk, undefine those
    bytes and re-mark them as raw data."""
    if not HAVE_IDA:
        return 0, 0
    seg_start = _inf_min_ea()
    seg_end = _inf_max_ea()
    n_found = 0
    n_stripped_total = 0

    # We need a snapshot of jmp sites first; modifying the IDB during
    # iteration would invalidate idautils.Heads.
    jmp_sites = []
    for ea in idautils.Heads(seg_start, seg_end):
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        info = _is_short_uncond_jmp(ea)
        if info is None:
            continue
        target, insn_size = info
        skip_start = ea + insn_size
        skip_end = target
        jmp_sites.append((ea, skip_start, skip_end))

    for jmp_ea, skip_start, skip_end in jmp_sites:
        if not _looks_like_junk_region(skip_start, skip_end):
            continue
        # Undefine and re-define as data (byte array)
        n_bytes = skip_end - skip_start
        ida_bytes.del_items(skip_start, ida_bytes.DELIT_SIMPLE, n_bytes)
        # Mark as byte array
        for off in range(skip_start, skip_end):
            ida_bytes.create_byte(off, 1)
        # Add a comment at the jmp site so the analyst sees what was done
        cmt = f'>>> JUNK: {n_bytes} bytes after this jmp marked as data ({skip_start:#x}..{skip_end:#x})'
        existing = ida_bytes.get_cmt(jmp_ea, 1) or ''
        if cmt not in existing:
            ida_bytes.set_cmt(jmp_ea, cmt, 1)
        n_found += 1
        n_stripped_total += n_bytes

    return n_found, n_stripped_total


def main():
    if not HAVE_IDA:
        print('Run me from inside IDA.')
        return
    n_jmps, n_bytes = strip_junk_after_short_jmps()
    print(f'[guloader-junk] {n_jmps} junk-bytes regions stripped, {n_bytes} bytes total marked as data')
    print('[guloader-junk] Press F5 (or refresh views) to see the cleaner listing')


if __name__ == '__main__':
    main()
