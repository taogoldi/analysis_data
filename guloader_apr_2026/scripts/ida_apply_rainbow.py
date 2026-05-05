"""
ida_apply_rainbow.py - Tao Goldi 2026-04

IDAPython script for the GuLoader stage-1 shellcode (sample SHA256
39c0135a...c7b9c6 / piasaba_decoded.bin).

What it does:

  1. Walks the entire IDB scanning for 4-byte little-endian dwords whose
     value matches a known GuLoader API hash, and adds a repeatable
     comment ("API: <name>") on the matching item.

  2. Renames every PEB-walk site (mov eax, fs:[0x30]) as
     `peb_walk_NN` and adds a structured comment annotating the +0xC,
     +0x14, +0x10, +0x3c offsets that follow.

  3. Marks the GuLoader API-hash function at offset 0x2EE78 as
     `gl_hash_api` and the case-folding helper at 0x2EF17 as
     `gl_tolower`, with summary comments.

How to use:

  IDA Pro:    File -> Script File...  -> select this file.
  IDA Free:   same.
  Or:        idapython3 -- this works headlessly via Hex-Rays IDAPython
              command-line.

Tested under IDA 8.x and 9.x. Should work in IDA 7.x with minor edits.
Loading mode: open `piasaba_decoded.bin` as a Binary File, processor
`metapc`, 32-bit. Base address 0 (or wherever).
"""
from __future__ import annotations

# Bail out gracefully if executed outside IDA. Fold over IDA version
# differences so the script runs on 7.x, 8.x, and 9.x.
try:
    import idaapi  # noqa: F401
    import idautils  # noqa: F401
    import idc
    import ida_bytes
    import ida_funcs
    import ida_name
    HAVE_IDA = True

    # Resolve `inf_get_min_ea` / `inf_get_max_ea` across versions:
    # - IDA 9.x: in ida_ida (and also re-exported from idaapi)
    # - IDA 8.x: in idaapi (sometimes also ida_bytes)
    # - IDA 7.x: idc.get_inf_attr(idc.INF_MIN_EA)
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

    # Resolve binary-pattern search across versions:
    # - IDA 7.x/8.x: ida_search.find_binary(start, end, pattern_str, radix, dir)
    # - IDA 9.x: ida_bytes.bin_search returns a tuple; signature varies
    def _bin_search_bytes(start, end, pattern_bytes):
        """Find next occurrence of `pattern_bytes` in [start, end). Returns
        BADADDR-equivalent (-1) if not found."""
        # Build a hex-string pattern like "64 A1 30 00 00 00" for the
        # find_binary fallback; build a compiled pattern for bin_search.
        hex_pat = ' '.join(f'{b:02X}' for b in pattern_bytes)
        # Try ida_search.find_binary first (works on 7.x and 8.x).
        try:
            import ida_search  # type: ignore
            flags = ida_search.SEARCH_DOWN | ida_search.SEARCH_NEXT
            ea = ida_search.find_binary(start, end, hex_pat, 16, flags)
            return ea
        except Exception:
            pass
        # Fall back to ida_bytes.bin_search (IDA 9.x). Signature changed
        # multiple times. Try the modern form first.
        try:
            res = ida_bytes.bin_search(  # type: ignore[attr-defined]
                start, end, pattern_bytes, None,
                ida_bytes.BIN_SEARCH_FORWARD,
                ida_bytes.BIN_SEARCH_NOSHOW,
            )
            if isinstance(res, tuple):
                return res[0]
            return res
        except Exception:
            pass
        # Last resort: linear scan.
        n = len(pattern_bytes)
        ea = start
        while ea + n <= end:
            chunk = ida_bytes.get_bytes(ea, n)
            if chunk == pattern_bytes:
                return ea
            ea += 1
        return idc.BADADDR

except ImportError:
    HAVE_IDA = False


HASH_KEY = 0x182DE6AD


def gl_hash(name: str) -> int:
    h = 0
    for ch in name:
        b = ord(ch)
        if 0x61 <= b <= 0x7A:
            b -= 0x20
        h = ((h + b) ^ HASH_KEY) & 0xFFFFFFFF
    return h


# Curated API/module name list. Each entry hashed two ways: bare and
# with trailing null wchar (some loaders include the terminator).
APIS = [
    'kernel32', 'ntdll', 'user32', 'advapi32', 'wininet', 'winhttp',
    'urlmon', 'shell32', 'ws2_32', 'kernelbase', 'shlwapi', 'crypt32',
    # ntdll
    'LdrLoadDll', 'LdrGetDllHandle', 'LdrGetProcedureAddress',
    'NtCreateThreadEx', 'NtAllocateVirtualMemory', 'NtFreeVirtualMemory',
    'NtProtectVirtualMemory', 'NtWriteVirtualMemory', 'NtReadVirtualMemory',
    'NtQueryInformationProcess', 'NtQueryVirtualMemory',
    'NtUnmapViewOfSection', 'NtMapViewOfSection', 'NtCreateSection',
    'NtOpenSection', 'NtClose', 'NtSetContextThread', 'NtGetContextThread',
    'NtCreateUserProcess', 'NtSuspendThread', 'NtResumeThread',
    'NtTerminateProcess', 'NtSetInformationProcess',
    'NtSetInformationThread', 'NtSetEvent', 'RtlMoveMemory', 'RtlZeroMemory',
    'RtlCreateUserThread', 'RtlAddVectoredExceptionHandler',
    'RtlRemoveVectoredExceptionHandler', 'RtlExitUserThread',
    'RtlExitUserProcess', 'NtCreateFile', 'NtReadFile', 'NtWriteFile',
    'NtDelayExecution', 'NtTestAlert', 'NtCreateThread',
    'NtSetThreadInformation', 'NtGetThreadContext', 'EtwEventWrite',
    # kernel32 / kernelbase
    'GetModuleHandleA', 'GetModuleHandleW', 'GetModuleHandleExA',
    'GetModuleHandleExW', 'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW',
    'LoadLibraryExA', 'LoadLibraryExW', 'VirtualAlloc', 'VirtualAllocEx',
    'VirtualProtect', 'VirtualProtectEx', 'VirtualFree', 'VirtualQuery',
    'GetTempPathA', 'GetTempPathW', 'GetTempFileNameA', 'GetTempFileNameW',
    'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'CloseHandle',
    'WaitForSingleObject', 'Sleep', 'GetTickCount', 'GetCurrentProcess',
    'GetCurrentProcessId', 'GetCurrentThread', 'GetCurrentThreadId',
    'OpenProcess', 'TerminateProcess', 'IsDebuggerPresent',
    'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'OutputDebugStringW',
    'IsProcessorFeaturePresent', 'CreateThread', 'ExitThread', 'ExitProcess',
    'QueryPerformanceCounter', 'GetEnvironmentVariableA',
    'GetEnvironmentVariableW', 'GetCommandLineA', 'GetCommandLineW',
    'CreateProcessA', 'CreateProcessW', 'CreateProcessInternalW',
    'CreateProcessInternalA', 'WriteProcessMemory', 'ReadProcessMemory',
    'ResumeThread', 'SetThreadContext', 'GetThreadContext',
    'CreateRemoteThread',
    # WinHTTP / WinInet
    'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
    'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpReadData',
    'WinHttpQueryDataAvailable', 'WinHttpCloseHandle', 'WinHttpSetTimeouts',
    'WinHttpSetOption', 'WinHttpQueryHeaders', 'InternetOpenA',
    'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
    'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA',
    'HttpSendRequestW', 'InternetReadFile', 'InternetCloseHandle',
    'InternetSetOptionA', 'URLDownloadToFileA', 'URLDownloadToFileW',
    # user32
    'CallWindowProcA', 'CallWindowProcW', 'EnumResourceTypesA',
    'EnumResourceTypesW', 'EnumResourceNamesA', 'EnumResourceNamesW',
    # advapi32
    'RegOpenKeyExA', 'RegOpenKeyExW', 'RegQueryValueExA', 'RegQueryValueExW',
    'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW',
    'RegCloseKey',
    # shell32
    'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
    'SHGetFolderPathA', 'SHGetFolderPathW',
    # crypt32 / utility
    'CryptStringToBinaryA', 'CryptBinaryToStringA',
    'AddVectoredExceptionHandler', 'RemoveVectoredExceptionHandler',
    'SetUnhandledExceptionFilter',
]


def build_table():
    table = {}
    for n in APIS:
        h = gl_hash(n)
        table.setdefault(h, n)
        hn = gl_hash(n + '\x00')
        table.setdefault(hn, n + '+null')
    return table


# ---- IDA-only helpers ----

def annotate_dword_hits(table):
    """Walk the IDB. For every 4-byte LE dword that matches a known
    hash, add a repeatable comment '<-- API: name>'. Returns hit count."""
    if not HAVE_IDA:
        return 0
    hits = 0
    seg_start = _inf_min_ea()
    seg_end = _inf_max_ea()
    ea = seg_start
    while ea + 4 <= seg_end:
        dw = ida_bytes.get_dword(ea)
        if dw in table:
            cmt = f'<-- API: {table[dw]}'
            ida_bytes.set_cmt(ea, cmt, 1)  # 1 = repeatable
            hits += 1
        ea += 1
    return hits


def annotate_peb_walks():
    """Find every `mov eax, fs:[0x30]` (bytes 64 a1 30 00 00 00) and
    rename + comment it as a PEB walk site."""
    if not HAVE_IDA:
        return 0
    peb_pattern = b'\x64\xa1\x30\x00\x00\x00'
    hits = 0
    seg_start = _inf_min_ea()
    seg_end = _inf_max_ea()
    ea = seg_start
    while True:
        ea = _bin_search_bytes(ea, seg_end, peb_pattern)
        if ea == idc.BADADDR or ea is None or ea < 0 or ea >= seg_end:
            break
        # Force code, name the location, comment it
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, 6)
        idc.create_insn(ea)
        ida_name.set_name(ea, f'peb_walk_{hits:02d}', ida_name.SN_NOWARN | ida_name.SN_FORCE)
        cmt = ('PEB walk site #{}\n'
               '  fs:[0x30] = PEB\n'
               '  PEB+0xC  = PEB_LDR_DATA *Ldr\n'
               '  Ldr+0x14 = LIST_ENTRY InMemoryOrderModuleList\n'
               '  entry+0x10 = LDR_DATA_TABLE_ENTRY.DllBase\n'
               '  base+0x3C  = e_lfanew (NT headers)').format(hits)
        ida_bytes.set_cmt(ea, cmt, 1)
        hits += 1
        ea += 6
    return hits


def _create_or_get_enum():
    """Create (or fetch existing) IDA enum `gl_api_hash` for hash values."""
    if not HAVE_IDA:
        return None
    name = 'gl_api_hash'
    # Try modern API first (IDA 9.x: ida_enum is deprecated, use ida_typeinf)
    try:
        import ida_enum  # type: ignore
        eid = ida_enum.get_enum(name)
        if eid == idc.BADADDR:
            eid = ida_enum.add_enum(idc.BADADDR, name, 0x10)  # 0x10 = hex flag
        return ('enum', eid, ida_enum)
    except ImportError:
        pass
    # IDA 9.x typeinf bitfield enum approach
    try:
        import ida_typeinf  # type: ignore
        # In IDA 9.x enums became typed via ida_typeinf. We'll try the
        # classic ida_enum first (above) and only fall back here.
        return None
    except ImportError:
        return None


def annotate_instruction_immediates(table, enum_handle):
    """Walk every instruction in the IDB. For each operand whose
    immediate value matches a known API hash:
      - apply the gl_api_hash enum to the operand (so IDA substitutes
        the symbolic name in the listing)
      - add a repeatable comment with the API name

    Returns hit count.
    """
    if not HAVE_IDA or not enum_handle:
        return 0
    _, eid, ida_enum = enum_handle

    # First, make sure each hash value is a member of the enum.
    for hv, name in table.items():
        member_name = 'gl_' + name.replace('+null', '_NUL').replace('.', '_').replace('-', '_')
        # member name must be unique-ish; suffix with hex of the hash for safety
        member_name = f'{member_name}_{hv:08X}'
        try:
            ida_enum.add_enum_member(eid, member_name, hv)
        except Exception:
            # already exists or name collision; skip
            pass

    # Walk all instructions, inspect every operand, apply enum to immediates.
    # We use idautils.Heads() over the whole IDB.
    import idautils
    seg_start = _inf_min_ea()
    seg_end = _inf_max_ea()
    hits = 0
    for ea in idautils.Heads(seg_start, seg_end):
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        for op_idx in range(2):  # check operands 0 and 1 (most x86 max is 2)
            op_type = idc.get_operand_type(ea, op_idx)
            # op_type 5 = o_imm (immediate operand)
            if op_type != idc.o_imm:
                continue
            val = idc.get_operand_value(ea, op_idx)
            if val in table:
                # Apply the enum to this operand
                try:
                    idc.op_enum(ea, op_idx, eid, 0)
                except Exception:
                    pass
                # Also add a repeatable comment with the name
                cmt = f'<-- API hash: {table[val]}'
                existing = ida_bytes.get_cmt(ea, 1) or ''
                if cmt not in existing:
                    ida_bytes.set_cmt(ea, (existing + ' ' + cmt).strip(), 1)
                hits += 1
    return hits


def _bswap32(v):
    return (((v & 0xFF) << 24) | ((v & 0xFF00) << 8) |
            ((v & 0xFF0000) >> 8) | ((v & 0xFF000000) >> 24)) & 0xFFFFFFFF


def _rol32(v, k):
    k &= 31
    return ((v << k) | (v >> (32 - k))) & 0xFFFFFFFF if k else v


def _ror32(v, k):
    k &= 31
    return ((v >> k) | (v << (32 - k))) & 0xFFFFFFFF if k else v


# Known fail-handler offsets (relative to image base). Branches into these
# are part of the anti-emulation noise scaffolding and must be ignored when
# tracing constant-build chains.
_FAIL_HANDLERS_REL = (0xAAC5, 0xAFD6, 0xAA0A, 0x32B33, 0x17771, 0x10DF6)


def _is_fail_jump(ea):
    """Return True if `ea` is a Jcc whose target is a known fail handler."""
    if not HAVE_IDA:
        return False
    op = idc.print_insn_mnem(ea).lower()
    if not op.startswith('j') or op == 'jmp':
        return False
    tgt = idc.get_operand_value(ea, 0)
    base = _inf_min_ea()
    return any(tgt == base + h for h in _FAIL_HANDLERS_REL)


def _is_noise_insn(ea):
    """Return True for ops that should be skipped over during chain
    tracing (sandbox checks, junk one-byte fillers)."""
    if not HAVE_IDA:
        return False
    op = idc.print_insn_mnem(ea).lower()
    if op in ('nop', 'cld', 'clc', 'std', 'stc', 'fnop'):
        return True
    if op in ('cmp', 'test'):
        # cmp/test followed (or preceded) by a fail-jump: noise.
        # Conservative: if the cmp targets [ebp+0x7c]/[ebp+0x70]/[ebp+0x74]/[ebp+0xAC],
        # which are the loader's anti-emu sentinel slots, treat as noise.
        op0 = idc.print_operand(ea, 0)
        if any(s in op0 for s in ('[ebp+7Ch]', '[ebp+70h]', '[ebp+74h]',
                                    '[ebp+ACh]', '[ebp+48h]')):
            return True
        # cmp <reg8>, <reg8> (e.g. `cmp dl, cl`) is junk filler
        if idc.get_operand_type(ea, 0) == idc.o_reg and \
           idc.get_operand_type(ea, 1) == idc.o_reg:
            return True
    if _is_fail_jump(ea):
        return True
    if op == 'xchg':
        # xchg reg, reg with same operand is filler
        if idc.print_operand(ea, 0) == idc.print_operand(ea, 1):
            return True
    if op == 'lea':
        # lea reg, [reg] is a no-op
        op0 = idc.print_operand(ea, 0)
        op1 = idc.print_operand(ea, 1)
        if op1.startswith('[') and op1.endswith(']') and op0 == op1[1:-1]:
            return True
    return False


def _operand_targets(ea, op_idx, target):
    """Return True if operand `op_idx` of instruction at `ea` refers to
    the abstract target. Targets:
      'reg:<name>'  : a CPU register
      'mem:<text>'  : a memory operand printed exactly as <text>
      'stack:top'   : a [esp] / [esp+0] / [esp+N+var_N] reference
    """
    if not HAVE_IDA:
        return False
    op_type = idc.get_operand_type(ea, op_idx)
    op_str = idc.print_operand(ea, op_idx)
    if target.startswith('reg:'):
        reg_name = target[4:]
        return op_type == idc.o_reg and op_str.lower() == reg_name.lower()
    if target.startswith('mem:'):
        mem_str = target[4:]
        return op_str == mem_str
    if target == 'stack:top':
        # any [esp...] reference
        return '[esp' in op_str.lower()
    return False


def _decode_chain_start(ea):
    """If `ea` is a chain-start instruction (push imm / mov reg, imm /
    mov [mem], imm), return (initial_value, target_descr). Else None."""
    if not HAVE_IDA:
        return None
    op = idc.print_insn_mnem(ea).lower()
    if op == 'push' and idc.get_operand_type(ea, 0) == idc.o_imm:
        return (idc.get_operand_value(ea, 0) & 0xFFFFFFFF, 'stack:top')
    if op == 'mov' and idc.get_operand_type(ea, 1) == idc.o_imm:
        t0 = idc.get_operand_type(ea, 0)
        if t0 == idc.o_reg:
            reg = idc.print_operand(ea, 0).lower()
            return (idc.get_operand_value(ea, 1) & 0xFFFFFFFF, f'reg:{reg}')
        if t0 in (idc.o_displ, idc.o_phrase, idc.o_mem):
            mem = idc.print_operand(ea, 0)
            return (idc.get_operand_value(ea, 1) & 0xFFFFFFFF, f'mem:{mem}')
    return None


def _fold_chain(start_ea, max_steps=40):
    """Try to fold a constant-build chain starting at start_ea.

    Returns dict {value, end_ea, target, chain_eas} or None.

    Walks forward. Each instruction either:
      - MODIFIES the running target (xor/add/sub/neg/not/rol/ror/bswap):
        apply the transformation and continue.
      - is NOISE (sandbox check, junk filler): skip and continue.
      - USES the target (push reg, cmp [...] reg, call ..., mov dest reg):
        return the folded value with end_ea pointing to the use site.
      - anything else: chain broken (return None).
    """
    if not HAVE_IDA:
        return None
    head = _decode_chain_start(start_ea)
    if head is None:
        return None
    value, target = head
    chain_eas = [start_ea]

    ea = idc.next_head(start_ea)
    steps = 0
    while ea != idc.BADADDR and steps < max_steps:
        steps += 1
        op = idc.print_insn_mnem(ea).lower()

        # ----- chain mutation ops -----
        # binary ops with imm: xor/add/sub/or/and target, imm
        if op in ('xor', 'add', 'sub', 'or', 'and') and \
           _operand_targets(ea, 0, target) and \
           idc.get_operand_type(ea, 1) == idc.o_imm:
            imm = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
            if op == 'xor':
                value ^= imm
            elif op == 'add':
                value = (value + imm) & 0xFFFFFFFF
            elif op == 'sub':
                value = (value - imm) & 0xFFFFFFFF
            elif op == 'or':
                value |= imm
            elif op == 'and':
                value &= imm
            chain_eas.append(ea)
            ea = idc.next_head(ea)
            continue
        # unary in-place: neg/not/bswap
        if op in ('neg', 'not', 'bswap') and _operand_targets(ea, 0, target):
            if op == 'neg':
                value = (-value) & 0xFFFFFFFF
            elif op == 'not':
                value = (~value) & 0xFFFFFFFF
            elif op == 'bswap':
                value = _bswap32(value)
            chain_eas.append(ea)
            ea = idc.next_head(ea)
            continue
        # rotates with imm shift
        if op in ('rol', 'ror') and _operand_targets(ea, 0, target) and \
           idc.get_operand_type(ea, 1) == idc.o_imm:
            sh = idc.get_operand_value(ea, 1) & 31
            value = _rol32(value, sh) if op == 'rol' else _ror32(value, sh)
            chain_eas.append(ea)
            ea = idc.next_head(ea)
            continue

        # ----- noise ops we step over -----
        if _is_noise_insn(ea):
            ea = idc.next_head(ea)
            continue

        # ----- use sites: chain endpoint -----
        # cmp where one side IS our target: comparison endpoint
        if op == 'cmp':
            if _operand_targets(ea, 0, target) or _operand_targets(ea, 1, target):
                return {'value': value, 'end_ea': ea, 'target': target,
                        'chain_eas': chain_eas, 'use': 'cmp'}
        # push <our register>: pushed for next call
        if op == 'push' and target.startswith('reg:') and \
           _operand_targets(ea, 0, target):
            return {'value': value, 'end_ea': ea, 'target': target,
                    'chain_eas': chain_eas, 'use': 'push'}
        # call: any call after a stack-built value is the consumer
        if op == 'call':
            return {'value': value, 'end_ea': ea, 'target': target,
                    'chain_eas': chain_eas, 'use': 'call'}
        # mov dest, our_target: copying our target to somewhere else = use
        if op == 'mov' and target.startswith('reg:') and \
           idc.get_operand_type(ea, 1) == idc.o_reg and \
           _operand_targets(ea, 1, target):
            return {'value': value, 'end_ea': ea, 'target': target,
                    'chain_eas': chain_eas, 'use': 'mov_out'}

        # Any other instruction we don't recognize: chain broken.
        return None

    return None


def fold_constant_chains(table):
    """Walk the IDB, find every constant-build chain, and annotate each
    one with a comment showing its resolved value. If the value matches
    an API hash, also tag the chain start with the API name."""
    if not HAVE_IDA:
        return (0, 0)
    seg_start = _inf_min_ea()
    seg_end = _inf_max_ea()
    visited = set()  # eas that are PART OF an existing chain (not chain starts)
    n_chains = 0
    n_hash_chains = 0
    import idautils
    for ea in idautils.Heads(seg_start, seg_end):
        if ea in visited:
            continue
        if not idc.is_code(idc.get_full_flags(ea)):
            continue
        result = _fold_chain(ea)
        if result is None:
            continue
        # Only annotate chains with at least 2 mutation steps. Single-step
        # "chains" are just normal `push imm` or `mov reg, imm` and would
        # spam the listing.
        if len(result['chain_eas']) < 3:
            continue
        # Mark interior chain instructions as visited (don't re-fold them)
        for cea in result['chain_eas'][1:]:
            visited.add(cea)
        n_chains += 1
        val = result['value']
        target_descr = result['target']
        if val in table:
            n_hash_chains += 1
            api = table[val]
            cmt = (f'>>> CHAIN resolves to API HASH 0x{val:08X} = {api} '
                   f'(via {len(result["chain_eas"])-1} ops on {target_descr})')
        else:
            cmt = (f'>>> CHAIN resolves to 0x{val:08X} ({val}) '
                   f'(via {len(result["chain_eas"])-1} ops on {target_descr})')
        existing = ida_bytes.get_cmt(ea, 1) or ''
        if cmt not in existing:
            ida_bytes.set_cmt(ea, cmt, 1)
        # Also drop a short marker at the use site
        end_cmt = (f'<-- chain endpoint: {table.get(val, f"value=0x{val:08X}")}')
        existing_end = ida_bytes.get_cmt(result['end_ea'], 1) or ''
        if end_cmt not in existing_end:
            ida_bytes.set_cmt(result['end_ea'],
                               (existing_end + ' ' + end_cmt).strip(), 1)
    return (n_chains, n_hash_chains)


def add_bookmarks_at_key_sites():
    """Bookmark the ~18 highest-confidence sites so the analyst can use
    Alt+Q (or Ctrl+M -> Bookmark Manager) to jump quickly."""
    if not HAVE_IDA:
        return 0
    base = _inf_min_ea()
    sites = [
        (0x1127E, 'VirtualAlloc hash dword'),
        (0x144AB, 'CreateProcessW hash dword'),
        (0x30506, 'CreateProcessA hash dword'),
        (0x215B3, 'NtCreateSection+null hash dword'),
        (0xB7E4,  'RtlMoveMemory+null hash dword'),
        (0xB98F,  'kernel32 module-name hash dword'),
        (0x21980, 'HttpSendRequestA hash dword'),
        (0x9769,  'WinHttpSendRequest hash dword'),
        (0x104C6, 'WinHttpReadData+null hash dword'),
        (0x3D9E,  'InternetOpenA+null hash dword'),
        (0x19E91, 'ShellExecuteW+null hash dword'),
        (0x114E8, 'NtReadVirtualMemory+null hash dword'),
        (0xA779,  'WinHttpSetTimeouts hash dword (URL near here)'),
        (0xC338,  'CreateFileW+null hash dword'),
        (0x11D9A, 'CreateFileA+null hash dword'),
        (0x33431, 'GetModuleHandleW hash dword'),
        (0xB197,  'PEB walk #0'),
        (0x2EE78, 'gl_hash_api function body'),
        (0x2EF17, 'gl_tolower helper'),
    ]
    n = 0
    for off, label in sites:
        ea = base + off
        try:
            # IDA marks: slot 0..1023, label string
            idc.put_bookmark(ea, 0, 0, 0, n, label)
            n += 1
        except Exception:
            pass
    return n


def name_known_functions():
    """Force-create and name the API hash function at 0x2EE78 and the
    case-folding helper at 0x2EF17."""
    if not HAVE_IDA:
        return
    base = _inf_min_ea()
    for off, name, summary in [
        (0x2EE78, 'gl_hash_api',
         ('GuLoader API hash function.\n'
          'edx = 0\n'
          'for each byte b of UTF-16-LE-low-byte name:\n'
          '    b = uppercase(b) via gl_tolower (subroutine at 0x2EF17)\n'
          '    edx = (edx + b) XOR 0x182DE6AD\n'
          'esi += 2 each iter; loop terminates when word ptr [esi] == 0.\n'
          'Return value in edx.')),
        (0x2EF17, 'gl_tolower',
         ('Case-folding helper called from gl_hash_api.\n'
          'Takes a byte on the stack (push ecx; call this).\n'
          'Builds the constants 0x61 (\\\'a\\\') and 0x7A (\\\'z\\\') through XOR\n'
          'chains:\n'
          '  ebx = 0xd6257e2d ^ 0x824e56ae ^ 0x343747f6 + 0x9fa390ec  =>  0x61\n'
          '  ebx = 0x5dd86142 ^ 0xc26efd2b ^ 0x604963ef neg ebx        =>  0x7A\n'
          'If 0x61 <= byte <= 0x7A: byte -= 0x20\n'
          '(sub 0x5728eaf, add 0x5728e8f -> diff is exactly -0x20)\n'
          'Returns the case-folded byte in EBX.')),
    ]:
        ea = base + off
        ida_funcs.add_func(ea)
        ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
        ida_bytes.set_cmt(ea, summary, 1)


def main():
    if not HAVE_IDA:
        print('Run me from inside IDA. As a CLI standalone use build_rainbow.py.')
        return
    table = build_table()
    print(f'[guloader] Built rainbow table: {len(table)} entries')

    n_dwords = annotate_dword_hits(table)
    print(f'[guloader] Annotated {n_dwords} data-level dword sites with API names')

    n_peb = annotate_peb_walks()
    print(f'[guloader] Annotated {n_peb} PEB-walk sites')

    name_known_functions()
    print('[guloader] Named gl_hash_api @ +0x2EE78 and gl_tolower @ +0x2EF17')

    # New: enum-based instruction-operand annotation
    enum_handle = _create_or_get_enum()
    if enum_handle:
        n_imm = annotate_instruction_immediates(table, enum_handle)
        print(f'[guloader] Applied gl_api_hash enum to {n_imm} immediate operands')
        print('[guloader] (instructions like `cmp [ebp+48h], 45Ah` should now read `cmp [ebp+48h], gl_VirtualAlloc_0000045A`)')
    else:
        print('[guloader] WARN: could not create gl_api_hash enum (IDA version may not support ida_enum)')

    # New: fold the obfuscated constant-build chains
    n_chains, n_hash_chains = fold_constant_chains(table)
    print(f'[guloader] Folded {n_chains} constant-build chains; {n_hash_chains} resolve to known API hashes')
    print('[guloader] Comments at each chain start show the resolved value (search "CHAIN resolves" to find them)')

    n_marks = add_bookmarks_at_key_sites()
    print(f'[guloader] Added {n_marks} bookmarks (use Alt+Q or Ctrl+M to navigate)')

    print('[guloader] Done. Press Alt+Q for the bookmark list, or `G` -> peb_walk_00.')


if __name__ == '__main__':
    main()
