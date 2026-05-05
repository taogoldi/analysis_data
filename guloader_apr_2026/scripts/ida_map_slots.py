"""
ida_map_slots.py - Tao Goldi 2026-04

Maps `[ebp+SLOT]` function-pointer-table slots to API names by tracing
the data flow from each `call gl_hash_api` site:

    push <hashed_name_addr>     ; or other arg setup
    call gl_hash_api            ; returns API address in some register
    [some optional moves]
    mov [ebp+0xC8], eax         ; <--- store result in slot 0xC8

If we can statically resolve which API hash was constructed before the
call (via the chain folder from ida_apply_rainbow.py), we can label the
slot. After this pass, every later `call dword ptr [ebp+0xC8]` shows up
as `call dword ptr [ebp+gl_VirtualAlloc_slot]`.

Run AFTER ida_apply_rainbow.py (which creates the gl_api_hash enum and
folds the chains). Idempotent.
"""
from __future__ import annotations

try:
    import idaapi  # noqa: F401
    import idautils
    import idc
    import ida_bytes
    import ida_name
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


HASH_KEY = 0x182DE6AD


def gl_hash(name: str) -> int:
    h = 0
    for ch in name:
        b = ord(ch)
        if 0x61 <= b <= 0x7A:
            b -= 0x20
        h = ((h + b) ^ HASH_KEY) & 0xFFFFFFFF
    return h


# Lazy-load the rainbow table from build_rainbow.py so we can identify
# any hash-as-int and turn it back into an API name.
def _load_rainbow():
    apis = [
        'kernel32', 'ntdll', 'user32', 'advapi32', 'wininet', 'winhttp',
        'urlmon', 'shell32', 'ws2_32', 'kernelbase', 'shlwapi', 'crypt32',
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
        'RtlRemoveVectoredExceptionHandler', 'NtCreateFile', 'NtReadFile',
        'NtWriteFile', 'NtDelayExecution', 'NtTestAlert', 'NtCreateThread',
        'NtSetThreadInformation', 'NtGetThreadContext', 'EtwEventWrite',
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
        'CreateRemoteThread', 'WinHttpOpen', 'WinHttpConnect',
        'WinHttpOpenRequest', 'WinHttpSendRequest', 'WinHttpReceiveResponse',
        'WinHttpReadData', 'WinHttpQueryDataAvailable', 'WinHttpCloseHandle',
        'WinHttpSetTimeouts', 'WinHttpSetOption', 'WinHttpQueryHeaders',
        'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
        'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA',
        'HttpSendRequestW', 'InternetReadFile', 'InternetCloseHandle',
        'InternetSetOptionA', 'URLDownloadToFileA', 'URLDownloadToFileW',
        'CallWindowProcA', 'CallWindowProcW', 'EnumResourceTypesA',
        'EnumResourceTypesW', 'EnumResourceNamesA', 'EnumResourceNamesW',
        'RegOpenKeyExA', 'RegOpenKeyExW', 'RegQueryValueExA', 'RegQueryValueExW',
        'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA', 'RegCreateKeyExW',
        'RegCloseKey', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA',
        'ShellExecuteExW', 'SHGetFolderPathA', 'SHGetFolderPathW',
        'CryptStringToBinaryA', 'CryptBinaryToStringA',
        'AddVectoredExceptionHandler', 'RemoveVectoredExceptionHandler',
        'SetUnhandledExceptionFilter',
    ]
    table = {}
    for n in apis:
        table.setdefault(gl_hash(n), n)
        table.setdefault(gl_hash(n + '\x00'), n + '+null')
    return table


def _find_gl_hash_api_ea():
    """Find gl_hash_api by name (set by ida_apply_rainbow.py) or by
    hardcoded offset 0x2EE78 from image base."""
    if not HAVE_IDA:
        return None
    ea = ida_name.get_name_ea(idaapi.BADADDR, 'gl_hash_api')
    if ea != idaapi.BADADDR:
        return ea
    # Fallback: known offset
    return _inf_min_ea() + 0x2EE78


def _last_chain_value_before(ea, lookback=80):
    """Look back up to `lookback` instructions from `ea` for a comment
    of the form '>>> CHAIN resolves to ... 0x????????'. Return the
    hex value as int, or None if not found."""
    if not HAVE_IDA:
        return None
    cur = ea
    for _ in range(lookback):
        cur = idc.prev_head(cur)
        if cur == idc.BADADDR:
            break
        cmt = ida_bytes.get_cmt(cur, 1) or ''
        if 'CHAIN resolves to' not in cmt:
            continue
        # Pull out the hex value
        import re
        m = re.search(r'0x([0-9A-Fa-f]{1,8})', cmt)
        if m:
            return int(m.group(1), 16)
    return None


def _next_slot_store_after(ea, lookahead=20):
    """Look forward up to `lookahead` instructions from `ea` for a
    `mov [ebp+SLOT], eax` (the API resolution result store).
    Return (slot_offset, store_ea) or None."""
    if not HAVE_IDA:
        return None
    cur = ea
    for _ in range(lookahead):
        cur = idc.next_head(cur)
        if cur == idc.BADADDR:
            break
        op = idc.print_insn_mnem(cur).lower()
        if op != 'mov':
            continue
        # Must be `mov [ebp+disp], eax`
        if idc.get_operand_type(cur, 0) != idc.o_displ:
            continue
        op0 = idc.print_operand(cur, 0)
        if 'ebp' not in op0:
            continue
        # operand 1 must be eax
        if idc.get_operand_type(cur, 1) != idc.o_reg:
            continue
        op1 = idc.print_operand(cur, 1).lower()
        if op1 != 'eax':
            continue
        # Extract slot offset
        slot = idc.get_operand_value(cur, 0)
        return (slot, cur)
    return None


def map_slots():
    if not HAVE_IDA:
        return {}
    table = _load_rainbow()
    hash_api_ea = _find_gl_hash_api_ea()
    if hash_api_ea is None:
        print('[guloader-slots] gl_hash_api not found')
        return {}
    print(f'[guloader-slots] gl_hash_api at {hash_api_ea:#x}')

    # Collect every callsite that calls gl_hash_api
    calls_to_hash = []
    for xref in idautils.CodeRefsTo(hash_api_ea, 1):
        if xref == idc.BADADDR:
            continue
        op = idc.print_insn_mnem(xref).lower()
        if op != 'call':
            continue
        calls_to_hash.append(xref)
    print(f'[guloader-slots] {len(calls_to_hash)} calls to gl_hash_api found')

    slot_map = {}  # slot_offset -> (hash, api_name, store_ea)
    for call_ea in calls_to_hash:
        # Find the chain value built before this call
        h = _last_chain_value_before(call_ea, lookback=80)
        if h is None:
            continue
        # Find where the resolved API is stored (next mov [ebp+slot], eax)
        store = _next_slot_store_after(call_ea, lookahead=20)
        if store is None:
            continue
        slot, store_ea = store
        api = table.get(h, f'unk_0x{h:08X}')
        slot_map[slot] = (h, api, store_ea)

    # Apply: for every `[ebp+SLOT]` reference whose slot is in slot_map,
    # add a comment showing which API.
    if slot_map:
        seg_start = _inf_min_ea()
        seg_end = _inf_max_ea()
        n_annot = 0
        for ea in idautils.Heads(seg_start, seg_end):
            if not idc.is_code(idc.get_full_flags(ea)):
                continue
            for op_idx in range(2):
                if idc.get_operand_type(ea, op_idx) != idc.o_displ:
                    continue
                op_str = idc.print_operand(ea, op_idx)
                if 'ebp' not in op_str:
                    continue
                slot = idc.get_operand_value(ea, op_idx)
                if slot in slot_map:
                    h, api, _ = slot_map[slot]
                    cmt = f'<-- slot[{slot:#x}] = {api}'
                    existing = ida_bytes.get_cmt(ea, 1) or ''
                    if cmt not in existing:
                        ida_bytes.set_cmt(ea, (existing + ' ' + cmt).strip(), 1)
                        n_annot += 1
        print(f'[guloader-slots] Annotated {n_annot} [ebp+slot] references')

    # Print the recovered slot table
    print('\n[guloader-slots] Recovered slot table:')
    print('  slot_offset  api_hash    api_name                store_at')
    print('  -----------  ----------  ----------------------  --------')
    for slot in sorted(slot_map):
        h, api, store_ea = slot_map[slot]
        print(f'  +0x{slot:04x}      0x{h:08x}  {api:22s}  {store_ea:#x}')

    return slot_map


def main():
    if not HAVE_IDA:
        print('Run me from inside IDA after ida_apply_rainbow.py.')
        return
    map_slots()


if __name__ == '__main__':
    main()
