#!/usr/bin/env python3
"""
build_rainbow.py - Tao Goldi 2026-04

Build a hash -> API name rainbow table for the GuLoader (this campaign)
custom hash function:

    H = 0
    for each byte b of UTF-16-LE-low-byte module-or-API name:
        if 0x61 <= b <= 0x7A: b -= 0x20      # a-z -> A-Z
        H = (H + b) XOR 0x182DE6AD
    return H

Two-mode invocation:

    python3 build_rainbow.py                  # print full table
    python3 build_rainbow.py <decoded.bin>    # search the binary for any
                                              # 4-byte little-endian hash
                                              # values that match an API
"""
from __future__ import annotations
import sys, struct, re

HASH_KEY = 0x182DE6AD


def gl_hash(name: str) -> int:
    h = 0
    for ch in name:
        b = ord(ch)
        if 0x61 <= b <= 0x7A:
            b -= 0x20
        h = ((h + b) ^ HASH_KEY) & 0xFFFFFFFF
    return h


# Curated list of APIs and modules typical for shellcode loaders. Each entry
# is hashed with and without a trailing null wchar (loader code sometimes
# hashes the whole string including the null terminator).
APIS = [
    # Module names (no extension)
    'kernel32', 'ntdll', 'user32', 'advapi32', 'wininet', 'winhttp',
    'urlmon', 'shell32', 'ws2_32', 'kernelbase', 'shlwapi', 'crypt32',
    # ntdll
    'LdrLoadDll', 'LdrGetDllHandle', 'LdrGetProcedureAddress',
    'NtCreateThreadEx', 'NtAllocateVirtualMemory', 'NtFreeVirtualMemory',
    'NtProtectVirtualMemory', 'NtWriteVirtualMemory', 'NtReadVirtualMemory',
    'NtQueryInformationProcess', 'NtQueryVirtualMemory', 'NtUnmapViewOfSection',
    'NtMapViewOfSection', 'NtCreateSection', 'NtOpenSection', 'NtClose',
    'NtSetContextThread', 'NtGetContextThread', 'NtCreateUserProcess',
    'NtSuspendThread', 'NtResumeThread', 'NtTerminateProcess',
    'NtSetInformationProcess', 'NtSetInformationThread', 'NtSetEvent',
    'RtlMoveMemory', 'RtlZeroMemory', 'RtlCreateUserThread',
    'RtlAddVectoredExceptionHandler', 'RtlRemoveVectoredExceptionHandler',
    'RtlExitUserThread', 'RtlExitUserProcess',
    'NtCreateFile', 'NtReadFile', 'NtWriteFile',
    'NtDelayExecution', 'NtTestAlert', 'NtCreateThread',
    'NtSetThreadInformation', 'NtGetThreadContext',
    'EtwEventWrite',
    # kernel32 / kernelbase
    'GetModuleHandleA', 'GetModuleHandleW', 'GetModuleHandleExA',
    'GetModuleHandleExW', 'GetProcAddress',
    'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
    'VirtualFree', 'VirtualQuery',
    'GetTempPathA', 'GetTempPathW', 'GetTempFileNameA', 'GetTempFileNameW',
    'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'CloseHandle',
    'WaitForSingleObject', 'Sleep', 'GetTickCount',
    'GetCurrentProcess', 'GetCurrentProcessId', 'GetCurrentThread',
    'GetCurrentThreadId', 'OpenProcess', 'TerminateProcess',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'OutputDebugStringA', 'OutputDebugStringW',
    'IsProcessorFeaturePresent', 'CreateThread', 'ExitThread', 'ExitProcess',
    'QueryPerformanceCounter', 'GetEnvironmentVariableA',
    'GetEnvironmentVariableW', 'GetCommandLineA', 'GetCommandLineW',
    'CreateProcessA', 'CreateProcessW', 'CreateProcessInternalW',
    'CreateProcessInternalA', 'WriteProcessMemory', 'ReadProcessMemory',
    'ResumeThread', 'SetThreadContext', 'GetThreadContext', 'CreateRemoteThread',
    # WinHTTP / WinInet
    'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
    'WinHttpSendRequest', 'WinHttpReceiveResponse', 'WinHttpReadData',
    'WinHttpQueryDataAvailable', 'WinHttpCloseHandle',
    'WinHttpSetTimeouts', 'WinHttpSetOption', 'WinHttpQueryHeaders',
    'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
    'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
    'InternetReadFile', 'InternetCloseHandle', 'InternetSetOptionA',
    'URLDownloadToFileA', 'URLDownloadToFileW',
    # user32
    'CallWindowProcA', 'CallWindowProcW',
    'EnumResourceTypesA', 'EnumResourceTypesW',
    'EnumResourceNamesA', 'EnumResourceNamesW',
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


def build_table() -> dict[int, str]:
    table: dict[int, str] = {}
    for name in APIS:
        h = gl_hash(name)
        table.setdefault(h, name)
        # Also include the +null variant (may conflict with another name's
        # base hash; we keep whichever was added first so the human-readable
        # name dominates).
        hn = gl_hash(name + '\x00')
        table.setdefault(hn, name + '+null')
    return table


def main() -> None:
    table = build_table()

    if len(sys.argv) == 1:
        print(f'# Rainbow table: {len(table)} entries')
        print(f'# Hash function: H = (H + UC(b)) XOR 0x{HASH_KEY:08X} per ASCII byte')
        for h in sorted(table):
            print(f'0x{h:08x}  {table[h]}')
        return

    # Search a binary for matching hashes
    decoded = open(sys.argv[1], 'rb').read()
    print(f'Searching {sys.argv[1]} ({len(decoded)} bytes) for hash matches...')
    hits: list[tuple[int, int, str]] = []
    for h, name in table.items():
        pat = struct.pack('<I', h)
        for m in re.finditer(re.escape(pat), decoded):
            hits.append((m.start(), h, name))
    hits.sort()
    seen: set[tuple[int, str]] = set()
    print(f'Distinct (offset, hash, name) tuples (deduped by hash+name):')
    for off, h, name in hits:
        key = (h, name)
        if key in seen:
            continue
        seen.add(key)
        print(f'  off=0x{off:6x}  hash=0x{h:08x}  -> {name}')


if __name__ == '__main__':
    main()
