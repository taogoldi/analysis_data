#!/usr/bin/env python3
"""
api_hash_reverser.py - reverse the CRC32-IEEE-802.3 API hashes used in
Sample C's pe_to_shellcode wrapper.

Two hash variants live in the wrapper:
  * 0xCC329  byte-based (used for export-name lookups in the kernel32 export table)
  * 0xCC45F  Unicode-aware (used for DLL-name lookups during the PEB walk)

Both use the same algorithm:
  * Reflected IEEE-802.3 polynomial 0xEDB88320
  * Initial CRC = 0xFFFFFFFF
  * 8 bit-by-bit iterations per character
  * Optional case-fold (ASCII A-Z -> a-z) controlled by the caller (dl register)
  * Final = bitwise NOT (one's complement)

The Unicode variant strides 16 bits at a time but only consumes the low 8
bits per character (the high byte of an ASCII-encoded wide char is always
zero, so the result is identical to the byte-based variant for ASCII
content). DLL and API names in this loader are pure ASCII, so the same
Python function reproduces both variants.

Usage:
    python3 api_hash_reverser.py 0x6AE69F02
    python3 api_hash_reverser.py 0x6AE69F02 0x3FC1BD8D 0xC97C1FFF
    python3 api_hash_reverser.py --bruteforce  ; try a built-in dictionary

Author: Tao Goldi
"""

from __future__ import annotations
import argparse
import sys
from typing import Iterable


POLY = 0xEDB88320  # reflected IEEE-802.3


def shellcode_hash(s: str, case_insensitive: bool = True) -> int:
    """Faithful Python port of the wrapper's hash function.

    Mirrors the disassembly at file offsets 0xCC329 (byte) and 0xCC45F
    (Unicode-aware). For pure ASCII input both variants are identical;
    the only divergence in the binary is the input stride.
    """
    crc = 0xFFFFFFFF
    for ch in s:
        c = ord(ch)
        if case_insensitive and 0x41 <= c <= 0x5A:  # A-Z
            c += 0x20
        for _ in range(8):
            bit = (crc ^ c) & 1
            crc >>= 1
            if bit:
                crc ^= POLY
            c >>= 1
    return (~crc) & 0xFFFFFFFF


# Known hashes recovered by reverse-engineering Sample C
# (SHA-256 849e64db81b5bebe1d0b6fb82dd66a1fd8bb4094a016beff6e501bcbbf36e72c).
KNOWN: dict[int, tuple[str, str]] = {
    0x6AE69F02: ("kernel32.dll", "case-insensitive (PEB walk: BaseDllName)"),
    0x3FC1BD8D: ("LoadLibraryA", "case-sensitive (export name)"),
    0xC97C1FFF: ("GetProcAddress", "case-sensitive (export name)"),
}


# Built-in candidate dictionary for brute-forcing additional hashes
# encountered in sibling samples or future builds.
DICTIONARY: list[tuple[str, bool]] = [
    # DLLs (case-insensitive)
    *((d, True) for d in [
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll",
        "ws2_32.dll", "wininet.dll", "winhttp.dll", "shell32.dll", "ole32.dll",
        "oleaut32.dll", "shlwapi.dll", "psapi.dll", "iphlpapi.dll", "crypt32.dll",
        "secur32.dll", "msvcrt.dll", "rpcrt4.dll", "dnsapi.dll",
    ]),
    # APIs (case-sensitive). Curated for "common in shellcode loaders".
    *((a, False) for a in [
        # bootstrap pair
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
        "GetModuleHandleExA", "GetModuleHandleExW",
        # memory
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "VirtualFree", "VirtualFreeEx", "VirtualLock", "VirtualUnlock",
        # threads / processes
        "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
        "OpenProcess", "OpenThread", "ResumeThread", "SuspendThread",
        "GetCurrentProcess", "GetCurrentThread", "GetCurrentThreadId",
        "GetCurrentProcessId", "ExitThread", "ExitProcess", "TerminateProcess",
        "WaitForSingleObject", "WaitForMultipleObjects",
        # IPC
        "WriteProcessMemory", "ReadProcessMemory",
        # sync
        "CreateEventA", "CreateEventW", "SetEvent", "ResetEvent",
        # heap
        "HeapCreate", "HeapAlloc", "HeapFree", "HeapReAlloc", "GetProcessHeap",
        "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
        # files
        "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "CloseHandle",
        # misc
        "Sleep", "GetTickCount", "GetTickCount64",
        "GetCommandLineA", "GetCommandLineW",
        "FlushInstructionCache",
        # ntdll
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtFreeVirtualMemory", "NtCreateThreadEx", "NtMapViewOfSection",
        "NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtReadVirtualMemory",
        "NtFlushInstructionCache", "NtTestAlert",
        "RtlAddFunctionTable", "RtlInstallFunctionTableCallback",
        "RtlMoveMemory", "RtlZeroMemory", "RtlFillMemory",
        "LdrLoadDll", "LdrGetProcedureAddress",
    ]),
]


def lookup(target_hashes: Iterable[int]) -> None:
    target_set = {int(h, 0) if isinstance(h, str) else h for h in target_hashes}
    for h in target_set:
        if h in KNOWN:
            name, mode = KNOWN[h]
            print(f"  0x{h:08X} = {name!r}  ({mode})")
            continue
        match = None
        for name, ci in DICTIONARY:
            if shellcode_hash(name, case_insensitive=ci) == h:
                match = (name, "case-insensitive" if ci else "case-sensitive")
                break
        if match:
            print(f"  0x{h:08X} = {match[0]!r}  ({match[1]})")
        else:
            print(f"  0x{h:08X} = (unknown; not in built-in dictionary)")


def bruteforce_dump() -> None:
    """Print the hash of every dictionary entry, useful for spotting
    new hashes encountered while reversing sibling samples."""
    print(f"{'mode':14}  {'hash':10}  name")
    for name, ci in sorted(DICTIONARY, key=lambda x: (x[1], x[0].lower())):
        h = shellcode_hash(name, case_insensitive=ci)
        mode = "case-insens." if ci else "case-sens."
        print(f"  {mode:12}  0x{h:08X}  {name}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("hashes", nargs="*", help="hexadecimal hash(es) to reverse")
    p.add_argument("--bruteforce", action="store_true",
                   help="dump hashes for every dictionary entry")
    p.add_argument("--add", metavar="NAME",
                   help="hash a custom name in both modes and print the result")
    args = p.parse_args()

    if args.add:
        for ci in (True, False):
            mode = "case-insensitive" if ci else "case-sensitive"
            print(f"  {mode:18}: 0x{shellcode_hash(args.add, ci):08X}")
        return 0
    if args.bruteforce:
        bruteforce_dump()
        return 0
    if not args.hashes:
        # default demo: reverse the three known sample C hashes
        print("Reversing the three hashes baked into Sample C's pe_to_shellcode wrapper:")
        lookup(KNOWN.keys())
        return 0
    lookup(args.hashes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
