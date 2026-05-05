#!/usr/bin/env python3
"""
emulate_shellcode.py - Tao Goldi 2026-04

Concrete-execution Unicorn-based emulator for the GuLoader stage-1
shellcode in piasaba_decoded.bin.

Goals:
  1. Execute the shellcode under a faked Windows process environment
     (PEB, Ldr, kernel32 / ntdll / wininet / winhttp / user32 export
     tables seeded with our hash table).
  2. Hook the loader's API resolution: when it tries to resolve an API
     by hash, we look up the hash in our table and return a synthetic
     "API address" that we then trap on call.
  3. When the loader invokes one of those synthetic addresses, log the
     call (api name + arguments).
  4. When `WinHttpOpenRequest` or `HttpOpenRequestA/W` is called with a
     URL argument, print the URL.

What this emulator does NOT do:
  - Vectored Exception Handler dispatch. The loader uses INT3 traps
    intercepted by VEH to patch instructions in flight; we treat any
    INT3 as a hint and skip to the next instruction. This means some
    code paths may not behave like a real Windows host; we still get
    far enough to see C2 staging in most runs.
  - Complete Windows API behaviour. Most APIs we hook are stubs that
    return success without doing anything. Enough to keep the loader
    moving.

Usage:
    python3 emulate_shellcode.py [--entry 0xb197] [--max-insns 100000]
                                 [--trace] sample/piasaba_decoded.bin

Defaults to entry 0 (the loader is meant to be invoked via
CallWindowProcW(buffer_base, ...)). If 0 doesn't behave, try 0xb197.
"""
from __future__ import annotations
import argparse
import os
import struct
import sys
from typing import Optional

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
    UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
    UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_GDTR,
)


def make_gdt_entry(base: int, limit: int, access: int, flags: int) -> bytes:
    """Build an 8-byte GDT entry. Standard x86 segment-descriptor format."""
    return struct.pack('<HHBBBB',
                        limit & 0xFFFF,
                        base & 0xFFFF,
                        (base >> 16) & 0xFF,
                        access & 0xFF,
                        ((limit >> 16) & 0x0F) | ((flags & 0x0F) << 4),
                        (base >> 24) & 0xFF)

# ---- GuLoader hash function (must match scripts/build_rainbow.py) ----

HASH_KEY = 0x182DE6AD


def gl_hash(name: str) -> int:
    h = 0
    for ch in name:
        b = ord(ch)
        if 0x61 <= b <= 0x7A:
            b -= 0x20
        h = ((h + b) ^ HASH_KEY) & 0xFFFFFFFF
    return h


# ---- Rainbow table ----

API_LIST = [
    # kernel32
    ('kernel32', 'kernel32'),
    ('kernel32', 'GetModuleHandleA'), ('kernel32', 'GetModuleHandleW'),
    ('kernel32', 'GetProcAddress'),
    ('kernel32', 'LoadLibraryA'), ('kernel32', 'LoadLibraryW'),
    ('kernel32', 'VirtualAlloc'), ('kernel32', 'VirtualAllocEx'),
    ('kernel32', 'VirtualProtect'), ('kernel32', 'VirtualProtectEx'),
    ('kernel32', 'VirtualFree'), ('kernel32', 'VirtualQuery'),
    ('kernel32', 'GetTempPathA'), ('kernel32', 'GetTempPathW'),
    ('kernel32', 'GetTempFileNameA'), ('kernel32', 'GetTempFileNameW'),
    ('kernel32', 'CreateFileA'), ('kernel32', 'CreateFileW'),
    ('kernel32', 'WriteFile'), ('kernel32', 'ReadFile'),
    ('kernel32', 'CloseHandle'), ('kernel32', 'WaitForSingleObject'),
    ('kernel32', 'Sleep'), ('kernel32', 'GetTickCount'),
    ('kernel32', 'CreateThread'), ('kernel32', 'CreateRemoteThread'),
    ('kernel32', 'CreateProcessA'), ('kernel32', 'CreateProcessW'),
    ('kernel32', 'WriteProcessMemory'), ('kernel32', 'ReadProcessMemory'),
    ('kernel32', 'ResumeThread'),
    ('kernel32', 'IsDebuggerPresent'), ('kernel32', 'CheckRemoteDebuggerPresent'),
    ('kernel32', 'OutputDebugStringA'), ('kernel32', 'OutputDebugStringW'),
    ('kernel32', 'GetCurrentProcess'), ('kernel32', 'GetCurrentProcessId'),
    ('kernel32', 'AddVectoredExceptionHandler'),
    ('kernel32', 'RemoveVectoredExceptionHandler'),
    # ntdll
    ('ntdll', 'ntdll'),
    ('ntdll', 'NtAllocateVirtualMemory'), ('ntdll', 'NtProtectVirtualMemory'),
    ('ntdll', 'NtCreateSection'), ('ntdll', 'NtMapViewOfSection'),
    ('ntdll', 'NtUnmapViewOfSection'),
    ('ntdll', 'NtCreateThread'), ('ntdll', 'NtCreateThreadEx'),
    ('ntdll', 'NtSetContextThread'), ('ntdll', 'NtGetContextThread'),
    ('ntdll', 'NtReadVirtualMemory'), ('ntdll', 'NtWriteVirtualMemory'),
    ('ntdll', 'NtSuspendThread'), ('ntdll', 'NtResumeThread'),
    ('ntdll', 'NtClose'), ('ntdll', 'NtDelayExecution'),
    ('ntdll', 'NtTestAlert'),
    ('ntdll', 'RtlMoveMemory'), ('ntdll', 'RtlZeroMemory'),
    ('ntdll', 'RtlAddVectoredExceptionHandler'),
    ('ntdll', 'LdrLoadDll'), ('ntdll', 'LdrGetDllHandle'),
    ('ntdll', 'LdrGetProcedureAddress'),
    # user32
    ('user32', 'user32'),
    ('user32', 'CallWindowProcA'), ('user32', 'CallWindowProcW'),
    ('user32', 'EnumResourceTypesA'), ('user32', 'EnumResourceTypesW'),
    # advapi32
    ('advapi32', 'RegOpenKeyExA'), ('advapi32', 'RegOpenKeyExW'),
    ('advapi32', 'RegQueryValueExA'), ('advapi32', 'RegQueryValueExW'),
    ('advapi32', 'RegCreateKeyExA'), ('advapi32', 'RegCreateKeyExW'),
    ('advapi32', 'RegCloseKey'),
    # wininet
    ('wininet', 'wininet'),
    ('wininet', 'InternetOpenA'), ('wininet', 'InternetOpenW'),
    ('wininet', 'InternetConnectA'), ('wininet', 'InternetConnectW'),
    ('wininet', 'HttpOpenRequestA'), ('wininet', 'HttpOpenRequestW'),
    ('wininet', 'HttpSendRequestA'), ('wininet', 'HttpSendRequestW'),
    ('wininet', 'InternetReadFile'), ('wininet', 'InternetCloseHandle'),
    ('wininet', 'InternetSetOptionA'),
    ('wininet', 'URLDownloadToFileA'), ('wininet', 'URLDownloadToFileW'),
    # winhttp
    ('winhttp', 'winhttp'),
    ('winhttp', 'WinHttpOpen'), ('winhttp', 'WinHttpConnect'),
    ('winhttp', 'WinHttpOpenRequest'), ('winhttp', 'WinHttpSendRequest'),
    ('winhttp', 'WinHttpReceiveResponse'), ('winhttp', 'WinHttpReadData'),
    ('winhttp', 'WinHttpQueryDataAvailable'), ('winhttp', 'WinHttpCloseHandle'),
    ('winhttp', 'WinHttpSetTimeouts'), ('winhttp', 'WinHttpSetOption'),
    # shell32
    ('shell32', 'shell32'),
    ('shell32', 'ShellExecuteA'), ('shell32', 'ShellExecuteW'),
    ('shell32', 'ShellExecuteExA'), ('shell32', 'ShellExecuteExW'),
    ('shell32', 'SHGetFolderPathA'), ('shell32', 'SHGetFolderPathW'),
]


# ---- Memory layout for the emulator ----

SHELLCODE_BASE   = 0x10000000
STACK_BASE       = 0x40000000
STACK_SIZE       = 0x00100000
TEB_BASE         = 0x00400000
PEB_BASE         = 0x00500000
LDR_BASE         = 0x00600000
MODULE_BASE      = 0x70000000  # synthetic kernel32/ntdll/etc DllBase
API_TRAMPOLINE   = 0x77000000  # one fake address per resolved API
HEAP_BASE        = 0x20000000
HEAP_SIZE        = 0x10000000
GDT_ADDR         = 0xC0000000
GDT_SIZE         = 0x1000


class Emulator:
    def __init__(self, shellcode_path: str, entry_offset: int = 0,
                 max_insns: int = 200000, trace: bool = False):
        self.shellcode = open(shellcode_path, 'rb').read()
        self.entry_offset = entry_offset
        self.max_insns = max_insns
        self.trace = trace
        self.insn_count = 0

        # Build hash table (hash int -> (module_name, api_name))
        self.hash_table = {}
        for module, api in API_LIST:
            self.hash_table[gl_hash(api)] = (module, api)
            self.hash_table[gl_hash(api + '\x00')] = (module, api + '+null')

        # Allocate "fake API addresses" - each known API gets one slot
        # in API_TRAMPOLINE region
        self.api_addr_to_name = {}
        self.name_to_api_addr = {}
        for i, (module, api) in enumerate(sorted(set((m, a) for m, a in API_LIST))):
            addr = API_TRAMPOLINE + (i * 0x100)
            self.api_addr_to_name[addr] = (module, api)
            self.name_to_api_addr[(module, api)] = addr

        # Heap watermark
        self.heap_top = HEAP_BASE + 0x1000

        # Activity log
        self.api_calls = []
        self.urls_seen = []
        self.strings_seen = []

        # VEH state
        self.veh_handlers: list[int] = []  # ordered list of registered VEH callback addrs
        self.veh_active = False  # True while inside a VEH dispatch
        self.veh_state = None    # snapshot for resume after handler returns
        # Special address used as the "fake return" sentinel pushed onto
        # the stack before a VEH dispatch. We hook on it to detect that
        # the handler has finished.
        self.VEH_RETURN_SENTINEL = 0x77FFEEEE
        self.veh_dispatch_count = 0
        self.veh_skip_int3_count = 0

        self.uc: Optional[Uc] = None

    # ----- memory helpers -----

    def heap_alloc(self, size: int) -> int:
        ptr = self.heap_top
        size = (size + 0xFFF) & ~0xFFF
        self.heap_top += size
        if self.heap_top >= HEAP_BASE + HEAP_SIZE:
            raise RuntimeError('emulator heap exhausted')
        self.uc.mem_write(ptr, b'\x00' * size)
        return ptr

    def write_str(self, s: bytes) -> int:
        ptr = self.heap_alloc(len(s) + 2)
        self.uc.mem_write(ptr, s)
        return ptr

    def write_wstr(self, s: str) -> int:
        b = s.encode('utf-16-le') + b'\x00\x00'
        return self.write_str(b)

    def read_cstr(self, addr: int, max_len: int = 4096) -> bytes:
        out = bytearray()
        for i in range(max_len):
            try:
                b = self.uc.mem_read(addr + i, 1)
            except Exception:
                break
            if b == b'\x00':
                break
            out.extend(b)
        return bytes(out)

    def read_wcstr(self, addr: int, max_len: int = 4096) -> str:
        out = bytearray()
        for i in range(0, max_len, 2):
            try:
                b = bytes(self.uc.mem_read(addr + i, 2))
            except Exception:
                break
            if b == b'\x00\x00':
                break
            out.extend(b)
        try:
            return out.decode('utf-16-le', errors='replace')
        except Exception:
            return out.decode('latin-1', errors='replace')

    # ----- environment setup -----

    def setup_segments(self):
        """Set FS base = TEB_BASE so the shellcode's `mov eax, fs:[0x30]`
        reads from our fake PEB.

        We tried the GDT-load approach; it works for FS but breaks SS
        (stack writes get masked to 16-bit). The simplest path that
        works on Unicorn 2.1.4 is to use the (deprecated but still
        functional in this version) FS_BASE pseudo-register write.
        Future Unicorn versions may force us back to GDT, in which case
        we'd need a working SS selector setup too."""
        uc = self.uc
        try:
            from unicorn.x86_const import UC_X86_REG_FS_BASE
            uc.reg_write(UC_X86_REG_FS_BASE, TEB_BASE)
        except Exception as e:
            print(f'[emu] WARN: FS_BASE write failed ({e}); fs:[0x30] reads will go to 0x30')

    def patch_fs_reads(self):
        """Rewrite every `mov reg, fs:[disp]` in the shellcode with a
        direct absolute-address load `mov reg, [TEB_BASE+disp]`.

        Why: Unicorn 2.1.4's FS_BASE pseudo-register is a no-op on
        x86_32, and the GDT-load approach broke SS in our experiments.
        Patching the actual fs reads bypasses the segmentation issue
        entirely. We rely on TEB_BASE being mapped with sensible
        contents at the offsets the loader reads (Self at +0x18, PEB
        at +0x30, etc., all populated in setup_memory).

        Patterns rewritten:
          64 a1 XX YY ZZ WW       (6B) -> mov eax, fs:[XXYYZZWW]
            => `a1 <TEB_BASE+disp>` (5B) + nop
          64 8b ?? XX YY ZZ WW    (7B) -> mov reg32, fs:[XXYYZZWW]
            => `8b ?? <TEB_BASE+disp>` (6B) + nop  -- but mod-rm changes
        """
        sc = bytearray(self.shellcode)
        n_patches = 0

        # 6-byte form: 64 a1 XX YY ZZ WW
        i = 0
        while i + 6 <= len(sc):
            if sc[i] == 0x64 and sc[i+1] == 0xa1:
                disp = struct.unpack('<I', bytes(sc[i+2:i+6]))[0]
                abs_addr = (TEB_BASE + disp) & 0xFFFFFFFF
                # Replace with `a1 <abs>` (mov eax, [abs]) + nop
                sc[i] = 0xa1
                sc[i+1:i+5] = struct.pack('<I', abs_addr)
                sc[i+5] = 0x90
                n_patches += 1
                i += 6
                continue
            i += 1

        # 7-byte form: 64 8b <modrm> XX YY ZZ WW   for mov reg32, fs:[disp32]
        # The mod-rm byte uses mode 0, R/M 5 (= disp32-only), with the
        # reg field selecting the destination register. After patching
        # we keep the same mod-rm pattern but drop the FS prefix:
        #   8b <modrm> <disp> + 1 nop  (6 bytes + 1 nop = 7 bytes)
        i = 0
        while i + 7 <= len(sc):
            if (sc[i] == 0x64 and sc[i+1] == 0x8b and
                    (sc[i+2] & 0xC7) == 0x05):  # mod=00, r/m=101
                disp = struct.unpack('<I', bytes(sc[i+3:i+7]))[0]
                abs_addr = (TEB_BASE + disp) & 0xFFFFFFFF
                # Keep modrm but turn it into a regular mov (no FS prefix)
                sc[i] = 0x8b
                # sc[i+1] keeps the modrm byte (now sc[i+1] = old sc[i+2])
                sc[i+1] = sc[i+2]
                sc[i+2:i+6] = struct.pack('<I', abs_addr)
                sc[i+6] = 0x90
                n_patches += 1
                i += 7
                continue
            i += 1

        self.shellcode = bytes(sc)
        print(f'[emu] patched {n_patches} fs:[disp] reads to absolute '
              f'TEB_BASE+disp loads')

    def setup_memory(self):
        uc = self.uc
        # Patch fs reads BEFORE writing shellcode to memory
        self.patch_fs_reads()
        # Set up segmentation (FS_BASE write; mostly a no-op on 2.1.4
        # but harmless)
        self.setup_segments()
        # Map the shellcode region
        sz = (len(self.shellcode) + 0xFFF) & ~0xFFF
        uc.mem_map(SHELLCODE_BASE, sz, 7)  # rwx
        uc.mem_write(SHELLCODE_BASE, self.shellcode)

        # Stack
        uc.mem_map(STACK_BASE - STACK_SIZE, STACK_SIZE, 7)

        # TEB / PEB / LDR
        uc.mem_map(TEB_BASE, 0x10000, 7)
        uc.mem_map(PEB_BASE, 0x10000, 7)
        uc.mem_map(LDR_BASE, 0x10000, 7)

        # Heap
        uc.mem_map(HEAP_BASE, HEAP_SIZE, 7)

        # Synthetic module base + API trampolines (we map a whole segment
        # that covers our trampoline region). The instruction at each
        # trampoline is a single INT3 (0xCC) which we trap and dispatch.
        uc.mem_map(MODULE_BASE, 0x10000000, 7)
        # Fill the trampoline region with INT3s
        for addr in self.api_addr_to_name:
            uc.mem_write(addr, b'\xcc' + b'\x00' * 0xFF)

        # ----- Build TEB -----
        # NT_TIB fields:
        #   +0x00 ExceptionList
        #   +0x04 StackBase
        #   +0x08 StackLimit
        #   +0x18 Self
        # TEB-specific:
        #   +0x20 ClientId.UniqueProcess
        #   +0x24 ClientId.UniqueThread
        #   +0x30 ProcessEnvironmentBlock
        #   +0x34 LastErrorValue
        # Seed every dword in 0..0x100 with a non-zero placeholder so
        # that reads from arbitrary TEB offsets don't appear as 0.
        for off in range(0, 0x200, 4):
            uc.mem_write(TEB_BASE + off, struct.pack('<I', 0x77000000 + off))
        uc.mem_write(TEB_BASE + 0x00, struct.pack('<I', 0xFFFFFFFF))  # ExceptionList sentinel
        uc.mem_write(TEB_BASE + 0x04, struct.pack('<I', STACK_BASE))   # StackBase
        uc.mem_write(TEB_BASE + 0x08, struct.pack('<I', STACK_BASE - STACK_SIZE))
        uc.mem_write(TEB_BASE + 0x18, struct.pack('<I', TEB_BASE))     # Self
        uc.mem_write(TEB_BASE + 0x20, struct.pack('<I', 0x1234))        # PID
        uc.mem_write(TEB_BASE + 0x24, struct.pack('<I', 0x5678))        # TID
        uc.mem_write(TEB_BASE + 0x30, struct.pack('<I', PEB_BASE))      # PEB

        # Alias TEB at low addresses (0..0x1000). Any fs: prefixed read
        # we couldn't statically patch (e.g. `fs:[ebx]` indirect form)
        # falls through as a non-segmented read because Unicorn 2.1.4
        # treats the fs prefix as a no-op (FS_BASE is effectively 0).
        # By mirroring TEB data at the low aliased range, those reads
        # still return sensible values.
        uc.mem_map(0x0, 0x1000, 7)
        for off in range(0, 0x200, 4):
            val = struct.unpack('<I', bytes(uc.mem_read(TEB_BASE + off, 4)))[0]
            uc.mem_write(off, struct.pack('<I', val))

        # PEB.BeingDebugged = 0
        uc.mem_write(PEB_BASE + 0x02, b'\x00')
        # PEB.NtGlobalFlag = 0
        uc.mem_write(PEB_BASE + 0x68, struct.pack('<I', 0))
        # PEB.Ldr = LDR_BASE
        uc.mem_write(PEB_BASE + 0x0C, struct.pack('<I', LDR_BASE))
        # PEB.ProcessParameters = points somewhere in PEB+0x100
        uc.mem_write(PEB_BASE + 0x10, struct.pack('<I', PEB_BASE + 0x100))

        # ----- Build PEB_LDR_DATA -----
        # PEB_LDR_DATA at LDR_BASE
        # +0x0C: InLoadOrderModuleList (LIST_ENTRY)
        # +0x14: InMemoryOrderModuleList (LIST_ENTRY)
        # +0x1C: InInitializationOrderModuleList (LIST_ENTRY)

        # We seed three modules: kernel32, ntdll, user32 (the loader walks
        # the InMemoryOrderModuleList from +0x14, dereferences each
        # LDR_DATA_TABLE_ENTRY, and reads DllBase at offset 0x10).
        modules = [
            ('kernel32.dll', MODULE_BASE + 0x000000),
            ('ntdll.dll',    MODULE_BASE + 0x100000),
            ('user32.dll',   MODULE_BASE + 0x200000),
            ('wininet.dll',  MODULE_BASE + 0x300000),
            ('winhttp.dll',  MODULE_BASE + 0x400000),
            ('shell32.dll',  MODULE_BASE + 0x500000),
            ('advapi32.dll', MODULE_BASE + 0x600000),
        ]
        # Allocate LDR_DATA_TABLE_ENTRY for each module and link them.
        ldr_entries = []
        for i, (name, base) in enumerate(modules):
            entry = LDR_BASE + 0x100 + (i * 0x100)
            # We'll fill in the LIST_ENTRY links after allocation
            # Layout (relevant fields only):
            #   +0x00: InLoadOrderLinks (Flink, Blink)
            #   +0x08: InMemoryOrderLinks (Flink, Blink)
            #   +0x10: InInitializationOrderLinks (Flink, Blink)
            #   +0x18: DllBase
            #   +0x1C: EntryPoint
            #   +0x20: SizeOfImage
            #   +0x24: FullDllName  (UNICODE_STRING)
            #   +0x2C: BaseDllName  (UNICODE_STRING)
            uc.mem_write(entry + 0x18, struct.pack('<I', base))
            uc.mem_write(entry + 0x20, struct.pack('<I', 0x100000))
            # Allocate the wchar buffer for the name
            wname = name.encode('utf-16-le') + b'\x00\x00'
            wname_addr = self.write_str(wname)
            # FullDllName UNICODE_STRING { Length, MaxLen, Buffer }
            uc.mem_write(entry + 0x24,
                          struct.pack('<HHI', len(wname) - 2,
                                       len(wname), wname_addr))
            # BaseDllName same data
            uc.mem_write(entry + 0x2C,
                          struct.pack('<HHI', len(wname) - 2,
                                       len(wname), wname_addr))
            # Some loaders also read +0x10 (entry->DllBase, skipping the
            # +0x18 layout). We mirror the DllBase to +0x10 for safety.
            uc.mem_write(entry + 0x10, struct.pack('<I', base))
            ldr_entries.append(entry)

        # Link them into a circular doubly-linked list at LDR+0x14
        # (InMemoryOrderModuleList). The list head is at LDR_BASE + 0x14.
        list_head = LDR_BASE + 0x14
        for i, entry in enumerate(ldr_entries):
            flink = ldr_entries[(i + 1) % len(ldr_entries)] + 0x08
            blink = ldr_entries[(i - 1) % len(ldr_entries)] + 0x08
            uc.mem_write(entry + 0x08, struct.pack('<II', flink, blink))
        # List head Flink -> first entry's InMemoryOrderLinks
        # List head Blink -> last entry's InMemoryOrderLinks
        uc.mem_write(list_head,
                      struct.pack('<II',
                                   ldr_entries[0] + 0x08,
                                   ldr_entries[-1] + 0x08))

        # Also seed the +0x0C InLoadOrderLinks list for completeness
        for i, entry in enumerate(ldr_entries):
            flink = ldr_entries[(i + 1) % len(ldr_entries)] + 0x00
            blink = ldr_entries[(i - 1) % len(ldr_entries)] + 0x00
            uc.mem_write(entry + 0x00, struct.pack('<II', flink, blink))
        uc.mem_write(LDR_BASE + 0x0C,
                      struct.pack('<II',
                                   ldr_entries[0] + 0x00,
                                   ldr_entries[-1] + 0x00))

        # ----- Build a fake export directory at each module base -----
        # IMAGE_DOS_HEADER -> e_lfanew at +0x3C
        # IMAGE_NT_HEADERS -> Optional Header DataDirectory[0] (export)
        # IMAGE_EXPORT_DIRECTORY -> { ..., NumberOfFunctions, ..., AddressOfNames, ... }
        for module_name, base in modules:
            mod_short = module_name.split('.')[0]
            # MZ header at base
            uc.mem_write(base, b'MZ')
            uc.mem_write(base + 0x3C, struct.pack('<I', 0x100))  # e_lfanew
            # PE\0\0 signature at base + 0x100
            uc.mem_write(base + 0x100, b'PE\x00\x00')
            # IMAGE_FILE_HEADER at base+0x104, OptionalHeader at base+0x118
            # OptionalHeader.DataDirectory[0] = ExportTable RVA (at OH+0x60 for 32-bit)
            export_dir_rva = 0x1000
            uc.mem_write(base + 0x118 + 0x60,
                          struct.pack('<II', export_dir_rva, 0x1000))

            # Build IMAGE_EXPORT_DIRECTORY at base + 0x1000
            ed = base + export_dir_rva
            # Collect APIs for this module
            apis_for_mod = [a for (m, a) in API_LIST if m == mod_short and a != mod_short]
            n = len(apis_for_mod)
            # ExportDirectory layout:
            #   +0x14: NumberOfFunctions
            #   +0x18: NumberOfNames
            #   +0x1C: AddressOfFunctions  (RVA -> array of function RVAs)
            #   +0x20: AddressOfNames      (RVA -> array of name RVAs)
            #   +0x24: AddressOfNameOrdinals (RVA -> array of WORDs)
            functions_rva = export_dir_rva + 0x40
            names_rva     = export_dir_rva + 0x40 + (n * 4)
            ordinals_rva  = export_dir_rva + 0x40 + (n * 8)
            strpool_rva   = export_dir_rva + 0x40 + (n * 10)
            uc.mem_write(ed + 0x14, struct.pack('<I', n))
            uc.mem_write(ed + 0x18, struct.pack('<I', n))
            uc.mem_write(ed + 0x1C, struct.pack('<I', functions_rva))
            uc.mem_write(ed + 0x20, struct.pack('<I', names_rva))
            uc.mem_write(ed + 0x24, struct.pack('<I', ordinals_rva))
            # Lay out names + functions. GuLoader's hash function reads
            # the low byte of each wchar and advances esi by 2 - it
            # expects UTF-16. We write names in UTF-16-LE in the export
            # string pool (this violates PE format but our fake module
            # is opaque to anything except the loader's walker).
            cur_str_rva = strpool_rva
            for i, api in enumerate(apis_for_mod):
                name_bytes = api.encode('utf-16-le') + b'\x00\x00'
                uc.mem_write(base + cur_str_rva, name_bytes)
                uc.mem_write(base + names_rva + (i * 4),
                              struct.pack('<I', cur_str_rva))
                uc.mem_write(base + ordinals_rva + (i * 2),
                              struct.pack('<H', i))
                api_addr = self.name_to_api_addr.get((mod_short, api))
                if api_addr is None:
                    rva = 0xDEAD0000 + i
                else:
                    rva = api_addr - base
                uc.mem_write(base + functions_rva + (i * 4),
                              struct.pack('<I', rva & 0xFFFFFFFF))
                cur_str_rva += len(name_bytes)

    # ----- hooks -----

    def hook_code(self, uc, address, size, user_data):
        self.insn_count += 1
        if not hasattr(self, '_eip_set'):
            self._eip_set = set()
            self._eip_count = {}
            self._max_eip = 0
            self._patched_loops = set()
        self._eip_set.add(address)
        self._eip_count[address] = self._eip_count.get(address, 0) + 1
        if address > self._max_eip:
            self._max_eip = address

        # Anti-stall: if any EIP has been hit > 500 times, find the
        # backward Jcc that's looping us and force EIP past it. We do
        # this directly (mutating EIP from the hook) rather than
        # patching memory, because Unicorn's TCG aggressively caches
        # translated blocks and a memory patch doesn't always take
        # effect mid-run.
        if (self._eip_count[address] == 500 and
                address not in self._patched_loops):
            self._patched_loops.add(address)
            new_eip = self._find_loop_exit(uc, address)
            if new_eip is not None:
                print(f'[emu] BREAK_LOOP: skipping past stall loop at '
                      f'{address:#x} -> {new_eip:#x}')
                uc.reg_write(UC_X86_REG_EIP, new_eip)
                # Force the emulator to re-fetch the next instruction
                try:
                    uc.emu_stop()
                    # Restart emulation at the new EIP. This re-enters
                    # the run loop in our caller.
                except Exception:
                    pass
        if self.insn_count > self.max_insns:
            print(f'[emu] max_insns ({self.max_insns}) reached, stopping')
            print(f'[emu] unique EIPs hit: {len(self._eip_set)}; '
                  f'max EIP reached: {self._max_eip:#x} '
                  f'(offset {self._max_eip - SHELLCODE_BASE:#x})')
            top = sorted(self._eip_count.items(), key=lambda x: -x[1])[:10]
            print(f'[emu] hottest EIPs (top 10):')
            for ea, n in top:
                off = ea - SHELLCODE_BASE
                try:
                    bc = bytes(uc.mem_read(ea, 6)).hex()
                except Exception:
                    bc = '??'
                print(f'  offset {off:#08x}  hits={n:7d}  bytes={bc}')
            uc.emu_stop()
            return
        # Check for INT3 (anti-debug or our trampoline trap)
        try:
            byte = bytes(uc.mem_read(address, 1))
        except Exception:
            return
        if byte == b'\xcc':
            self.handle_int3(uc, address)
            return
        if self.trace and self.insn_count <= 50:
            try:
                eax = uc.reg_read(UC_X86_REG_EAX)
                ebx = uc.reg_read(UC_X86_REG_EBX)
                ecx = uc.reg_read(UC_X86_REG_ECX)
                edx = uc.reg_read(UC_X86_REG_EDX)
                esi = uc.reg_read(UC_X86_REG_ESI)
                edi = uc.reg_read(UC_X86_REG_EDI)
                esp = uc.reg_read(UC_X86_REG_ESP)
                ebp = uc.reg_read(UC_X86_REG_EBP)
                eip = uc.reg_read(UC_X86_REG_EIP)
                bytecode = bytes(uc.mem_read(eip, min(8, size)))
                print(f'  #{self.insn_count:3d} {eip:#010x} {bytecode.hex():16s} '
                      f'  eax={eax:#010x} ebx={ebx:#010x} esp={esp:#010x} ebp={ebp:#010x}')
            except Exception as e:
                print(f'  #{self.insn_count}: trace error: {e}')

    def _find_loop_exit(self, uc, hot_eip):
        """Find the EA just past the backward-Jcc that's looping us.
        Returns the fall-through address, or None if no loop exit
        could be found."""
        try:
            blob = bytes(uc.mem_read(hot_eip, 64))
        except Exception:
            return None
        for off in range(64 - 1):
            b = blob[off]
            if 0x70 <= b <= 0x7F or b == 0xE3:
                disp = blob[off + 1]
                if disp >= 0x80:
                    target_ea = hot_eip + off + 2 + (disp - 0x100)
                    if target_ea <= hot_eip:
                        return hot_eip + off + 2
        return None

    def _try_break_loop(self, uc, hot_eip):
        """We've detected a hot loop. Scan forward up to 32 bytes for a
        short backward Jcc (opcode 0x70-0x7F or 0xE3) and replace it
        with NOPs so execution falls through. Returns True if patched."""
        try:
            blob = bytes(uc.mem_read(hot_eip, 64))
        except Exception:
            return False
        for off in range(64 - 1):
            b = blob[off]
            # Short Jcc opcodes 0x70..0x7F (jo, jno, jb, jae, je, jne, ...)
            # plus 0xE3 (jecxz) and 0xEB (jmp short)
            if 0x70 <= b <= 0x7F or b == 0xE3:
                # Disp is signed byte at off+1
                disp = blob[off + 1]
                if disp >= 0x80:
                    # Negative -> backward jump -> loop tail
                    target_ea = hot_eip + off + 2 + (disp - 0x100)
                    if target_ea <= hot_eip:
                        # Patch the 2-byte Jcc with two NOPs
                        ea_to_patch = hot_eip + off
                        try:
                            uc.mem_write(ea_to_patch, b'\x90\x90')
                            # Invalidate Unicorn's translation cache for
                            # this range so the patch takes effect.
                            try:
                                uc.ctl_remove_cache(ea_to_patch,
                                                     ea_to_patch + 16)
                            except Exception:
                                # Some Unicorn versions name it differently
                                try:
                                    uc.ctl_request_cache(ea_to_patch,
                                                          ea_to_patch + 16)
                                except Exception:
                                    pass
                            print(f'[emu] BREAK_LOOP: patched Jcc at '
                                  f'{ea_to_patch:#x} (was 0x{blob[off]:02x} '
                                  f'0x{blob[off+1]:02x}) -> NOP NOP, breaking '
                                  f'stall loop at {hot_eip:#x}')
                            return True
                        except Exception:
                            return False
        return False

    def handle_int3(self, uc, address):
        # Check VEH return sentinel first — handler is finishing
        if address == self.VEH_RETURN_SENTINEL:
            self._veh_handler_returned(uc)
            return
        if address in self.api_addr_to_name:
            module, api = self.api_addr_to_name[address]
            self.dispatch_api(uc, address, module, api)
            return
        # In-loader INT3 (anti-debug bait). If a VEH is registered,
        # dispatch to it. Otherwise just skip past the INT3.
        if self.veh_handlers and not self.veh_active:
            self._dispatch_veh(uc, address)
        else:
            self.veh_skip_int3_count += 1
            uc.reg_write(UC_X86_REG_EIP, address + 1)

    # ---- VEH dispatch ----

    def _dispatch_veh(self, uc, int3_addr: int):
        """Build EXCEPTION_RECORD + CONTEXT + EXCEPTION_POINTERS and
        call the most-recently-registered VEH. Execution will resume
        here when the handler returns (we trap on the sentinel)."""
        self.veh_dispatch_count += 1

        # ---- Build EXCEPTION_RECORD (at least 0x50 bytes, x86) ----
        # +0x00 ExceptionCode    DWORD = STATUS_BREAKPOINT (0x80000003)
        # +0x04 ExceptionFlags   DWORD = 0
        # +0x08 ExceptionRecord  PTR   = NULL (no chain)
        # +0x0C ExceptionAddress PTR   = int3_addr
        # +0x10 NumberParameters DWORD = 0
        # +0x14..0x50 ExceptionInformation [15] DWORD
        er = self.heap_alloc(0x60)
        uc.mem_write(er + 0x00, struct.pack('<I', 0x80000003))
        uc.mem_write(er + 0x04, struct.pack('<I', 0))
        uc.mem_write(er + 0x08, struct.pack('<I', 0))
        uc.mem_write(er + 0x0C, struct.pack('<I', int3_addr))
        uc.mem_write(er + 0x10, struct.pack('<I', 0))

        # ---- Build CONTEXT (32-bit Windows) ----
        # Layout (Windows SDK winnt.h CONTEXT for x86):
        #   +0x000 ContextFlags
        #   +0x004 Dr0..Dr7 (24 bytes)
        #   +0x01C FloatSave (FLOATING_SAVE_AREA, 112 bytes)
        #   +0x08C SegGs
        #   +0x090 SegFs
        #   +0x094 SegEs
        #   +0x098 SegDs
        #   +0x09C Edi
        #   +0x0A0 Esi
        #   +0x0A4 Ebx
        #   +0x0A8 Edx
        #   +0x0AC Ecx
        #   +0x0B0 Eax
        #   +0x0B4 Ebp
        #   +0x0B8 Eip
        #   +0x0BC SegCs
        #   +0x0C0 EFlags
        #   +0x0C4 Esp
        #   +0x0C8 SegSs
        #   +0x0CC ExtendedRegisters[512]
        ctx = self.heap_alloc(0x300)
        from unicorn.x86_const import (
            UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
            UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
            UC_X86_REG_EFLAGS,
        )
        regs = {
            'edi': uc.reg_read(UC_X86_REG_EDI),
            'esi': uc.reg_read(UC_X86_REG_ESI),
            'ebx': uc.reg_read(UC_X86_REG_EBX),
            'edx': uc.reg_read(UC_X86_REG_EDX),
            'ecx': uc.reg_read(UC_X86_REG_ECX),
            'eax': uc.reg_read(UC_X86_REG_EAX),
            'ebp': uc.reg_read(UC_X86_REG_EBP),
            'esp': uc.reg_read(UC_X86_REG_ESP),
            'eflags': uc.reg_read(UC_X86_REG_EFLAGS),
        }
        # ContextFlags = CONTEXT_FULL = 0x10007
        uc.mem_write(ctx + 0x000, struct.pack('<I', 0x10007))
        uc.mem_write(ctx + 0x09C, struct.pack('<I', regs['edi']))
        uc.mem_write(ctx + 0x0A0, struct.pack('<I', regs['esi']))
        uc.mem_write(ctx + 0x0A4, struct.pack('<I', regs['ebx']))
        uc.mem_write(ctx + 0x0A8, struct.pack('<I', regs['edx']))
        uc.mem_write(ctx + 0x0AC, struct.pack('<I', regs['ecx']))
        uc.mem_write(ctx + 0x0B0, struct.pack('<I', regs['eax']))
        uc.mem_write(ctx + 0x0B4, struct.pack('<I', regs['ebp']))
        uc.mem_write(ctx + 0x0B8, struct.pack('<I', int3_addr))   # Eip
        uc.mem_write(ctx + 0x0C0, struct.pack('<I', regs['eflags']))
        uc.mem_write(ctx + 0x0C4, struct.pack('<I', regs['esp']))

        # ---- Build EXCEPTION_POINTERS (8 bytes) ----
        ep = self.heap_alloc(8)
        uc.mem_write(ep, struct.pack('<II', er, ctx))

        # ---- Push args + sentinel return; redirect EIP to handler ----
        # __stdcall LONG VectoredHandler(EXCEPTION_POINTERS *ExceptionInfo)
        esp = regs['esp']
        # Push arg
        esp -= 4
        uc.mem_write(esp, struct.pack('<I', ep))
        # Push sentinel return address (we'll trap on this as INT3)
        esp -= 4
        uc.mem_write(esp, struct.pack('<I', self.VEH_RETURN_SENTINEL))
        uc.reg_write(UC_X86_REG_ESP, esp)

        # Save state for resume
        self.veh_state = {
            'int3_addr': int3_addr,
            'ctx_addr': ctx,
            'er_addr': er,
            'ep_addr': ep,
            'orig_regs': regs,
        }
        self.veh_active = True

        # Place an INT3 at the sentinel address so we trap when the
        # handler `ret`s into it. We map a tiny 1-page region to host it.
        if not getattr(self, '_sentinel_mapped', False):
            try:
                uc.mem_map(self.VEH_RETURN_SENTINEL & ~0xFFF, 0x1000, 7)
            except Exception:
                pass
            uc.mem_write(self.VEH_RETURN_SENTINEL, b'\xcc')
            self._sentinel_mapped = True

        # Use most-recently-registered handler
        handler = self.veh_handlers[-1]
        if self.veh_dispatch_count <= 5:
            print(f'[veh] INT3 at {int3_addr:#x} -> dispatch to handler {handler:#x}')
        uc.reg_write(UC_X86_REG_EIP, handler)

    def _veh_handler_returned(self, uc):
        """Called when the VEH return sentinel fires. Read EAX and the
        possibly-modified CONTEXT.Eip, and resume."""
        if not self.veh_state:
            uc.reg_write(UC_X86_REG_EIP, self.VEH_RETURN_SENTINEL + 1)
            return
        from unicorn.x86_const import (
            UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
            UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
            UC_X86_REG_EFLAGS,
        )
        ret_val = uc.reg_read(UC_X86_REG_EAX)
        ctx = self.veh_state['ctx_addr']
        # Read potentially-modified CONTEXT
        new_eip = struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0B8, 4)))[0]

        if self.veh_dispatch_count <= 5:
            int3 = self.veh_state['int3_addr']
            print(f'[veh] handler returned eax={ret_val:#x}; '
                  f'CONTEXT.Eip {int3:#x} -> {new_eip:#x}')

        # If handler returned -1 (EXCEPTION_CONTINUE_EXECUTION), restore
        # the modified CONTEXT and resume at new_eip.
        if (ret_val & 0xFFFFFFFF) == 0xFFFFFFFF:
            uc.reg_write(UC_X86_REG_EDI,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x09C, 4)))[0])
            uc.reg_write(UC_X86_REG_ESI,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0A0, 4)))[0])
            uc.reg_write(UC_X86_REG_EBX,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0A4, 4)))[0])
            uc.reg_write(UC_X86_REG_EDX,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0A8, 4)))[0])
            uc.reg_write(UC_X86_REG_ECX,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0AC, 4)))[0])
            uc.reg_write(UC_X86_REG_EAX,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0B0, 4)))[0])
            uc.reg_write(UC_X86_REG_EBP,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0B4, 4)))[0])
            uc.reg_write(UC_X86_REG_ESP,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0C4, 4)))[0])
            uc.reg_write(UC_X86_REG_EFLAGS,
                         struct.unpack('<I', bytes(uc.mem_read(ctx + 0x0C0, 4)))[0])
            uc.reg_write(UC_X86_REG_EIP, new_eip)
        else:
            # EXCEPTION_CONTINUE_SEARCH or unknown: restore original
            # registers and skip past the INT3.
            r = self.veh_state['orig_regs']
            uc.reg_write(UC_X86_REG_EAX, r['eax'])
            uc.reg_write(UC_X86_REG_EBX, r['ebx'])
            uc.reg_write(UC_X86_REG_ECX, r['ecx'])
            uc.reg_write(UC_X86_REG_EDX, r['edx'])
            uc.reg_write(UC_X86_REG_ESI, r['esi'])
            uc.reg_write(UC_X86_REG_EDI, r['edi'])
            uc.reg_write(UC_X86_REG_EBP, r['ebp'])
            uc.reg_write(UC_X86_REG_ESP, r['esp'])
            uc.reg_write(UC_X86_REG_EIP,
                         self.veh_state['int3_addr'] + 1)

        self.veh_active = False
        self.veh_state = None

    # ----- API stubs -----

    def dispatch_api(self, uc, addr, module, api):
        esp = uc.reg_read(UC_X86_REG_ESP)
        # Read return address and up to 8 stdcall arguments
        try:
            ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
        except Exception:
            ret_addr = 0
        args = []
        for i in range(8):
            try:
                a = struct.unpack('<I',
                                   bytes(uc.mem_read(esp + 4 + i * 4, 4)))[0]
                args.append(a)
            except Exception:
                args.append(0)

        # Log
        self.api_calls.append((module, api, args[:6]))
        info = f'[API] {module}!{api}('
        info += ', '.join(f'{a:#x}' for a in args[:4])
        info += ')'
        print(info)

        # Specific stubs that produce useful output
        bare = api.replace('+null', '')
        if bare in ('GetProcAddress',):
            # arg0 = hModule, arg1 = lpProcName (string)
            try:
                name = self.read_cstr(args[1]).decode('latin-1', errors='replace')
                print(f'    GetProcAddress -> "{name}"')
                # Find matching API trampoline
                ret = 0
                for (m, a), addr2 in self.name_to_api_addr.items():
                    if a == name:
                        ret = addr2
                        break
                if ret == 0:
                    print(f'    (no stub for {name})')
                self._stdcall_return(uc, esp, args, ret, n_args=2)
            except Exception:
                self._stdcall_return(uc, esp, args, 0, n_args=2)
            return

        if bare in ('LoadLibraryA', 'LoadLibraryExA'):
            try:
                name = self.read_cstr(args[0]).decode('latin-1', errors='replace')
                print(f'    LoadLibraryA -> "{name}"')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, MODULE_BASE + 0x800000,
                                   n_args=1 if bare == 'LoadLibraryA' else 3)
            return

        if bare in ('LoadLibraryW', 'LoadLibraryExW'):
            try:
                name = self.read_wcstr(args[0])
                print(f'    LoadLibraryW -> "{name}"')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, MODULE_BASE + 0x800000,
                                   n_args=1 if bare == 'LoadLibraryW' else 3)
            return

        if bare == 'VirtualAlloc':
            size = args[1]
            ret = self.heap_alloc(size if size else 0x1000)
            print(f'    VirtualAlloc(size={size:#x}) -> {ret:#x}')
            self._stdcall_return(uc, esp, args, ret, n_args=4)
            return

        if bare == 'VirtualProtect':
            self._stdcall_return(uc, esp, args, 1, n_args=4)
            return

        if bare in ('CheckRemoteDebuggerPresent', 'IsDebuggerPresent'):
            # Always say "no debugger"
            if bare == 'CheckRemoteDebuggerPresent' and args[1]:
                # *pbDebuggerPresent = 0
                try:
                    uc.mem_write(args[1], b'\x00\x00\x00\x00')
                except Exception:
                    pass
            self._stdcall_return(uc, esp, args, 0,
                                   n_args=2 if bare == 'CheckRemoteDebuggerPresent' else 0)
            uc.reg_write(UC_X86_REG_EAX, 0)
            return

        if bare in ('InternetOpenA', 'InternetOpenW'):
            try:
                if bare == 'InternetOpenA':
                    s = self.read_cstr(args[0]).decode('latin-1', errors='replace')
                else:
                    s = self.read_wcstr(args[0])
                self.strings_seen.append(('UA', s))
                print(f'    User-Agent: {s!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 0xDEAD0001, n_args=5)
            return

        if bare in ('InternetConnectA', 'InternetConnectW'):
            try:
                if bare == 'InternetConnectA':
                    host = self.read_cstr(args[1]).decode('latin-1', errors='replace')
                else:
                    host = self.read_wcstr(args[1])
                self.urls_seen.append(('host', host))
                print(f'    >>> C2 HOST: {host!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 0xDEAD0002, n_args=8)
            return

        if bare in ('HttpOpenRequestA', 'HttpOpenRequestW'):
            try:
                if bare == 'HttpOpenRequestA':
                    obj = self.read_cstr(args[2]).decode('latin-1', errors='replace')
                else:
                    obj = self.read_wcstr(args[2])
                self.urls_seen.append(('path', obj))
                print(f'    >>> C2 PATH: {obj!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 0xDEAD0003, n_args=8)
            return

        if bare in ('WinHttpOpen',):
            try:
                ua = self.read_wcstr(args[0]) if args[0] else ''
                if ua: print(f'    User-Agent: {ua!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 0xDEAD0010, n_args=5)
            return

        if bare == 'WinHttpConnect':
            try:
                host = self.read_wcstr(args[1])
                self.urls_seen.append(('host', host))
                print(f'    >>> C2 HOST: {host!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 0xDEAD0011, n_args=4)
            return

        if bare == 'WinHttpOpenRequest':
            try:
                verb = self.read_wcstr(args[1]) if args[1] else 'GET'
                path = self.read_wcstr(args[2]) if args[2] else ''
                self.urls_seen.append(('request', f'{verb} {path}'))
                print(f'    >>> C2 REQUEST: {verb} {path!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 0xDEAD0012, n_args=7)
            return

        if bare in ('CreateProcessA', 'CreateProcessW'):
            try:
                if bare == 'CreateProcessA':
                    cmd = self.read_cstr(args[1]).decode('latin-1', errors='replace')
                else:
                    cmd = self.read_wcstr(args[1])
                print(f'    >>> CreateProcess: {cmd!r}')
            except Exception:
                pass
            self._stdcall_return(uc, esp, args, 1, n_args=10)
            return

        if bare in ('AddVectoredExceptionHandler',
                    'RtlAddVectoredExceptionHandler'):
            # arg0 = First (1=add to head, 0=add to tail)
            # arg1 = Handler (PVECTORED_EXCEPTION_HANDLER)
            handler_ea = args[1]
            self.veh_handlers.append(handler_ea)
            print(f'    >>> VEH REGISTERED at {handler_ea:#x} '
                  f'(total handlers: {len(self.veh_handlers)})')
            self._stdcall_return(uc, esp, args,
                                  0xDEAD0100 + len(self.veh_handlers),
                                  n_args=2)
            return

        if bare in ('RemoveVectoredExceptionHandler',
                    'RtlRemoveVectoredExceptionHandler'):
            # We can't really un-register without a real handle->index
            # map; just pretend it succeeded.
            self._stdcall_return(uc, esp, args, 1, n_args=1)
            return

        # Generic stub: return success, take 0 args (caller must clean
        # if cdecl; for stdcall we don't know argcount, so guess 0).
        self._stdcall_return(uc, esp, args, 1, n_args=0)

    def _stdcall_return(self, uc, esp, args, ret_value, n_args):
        # Set EAX = return value
        uc.reg_write(UC_X86_REG_EAX, ret_value & 0xFFFFFFFF)
        # Pop return address into EIP
        try:
            ret_addr = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
        except Exception:
            ret_addr = 0
        # stdcall: ret n_args*4 (caller doesn't clean)
        # cdecl:   ret 0 (caller cleans)
        # We assume stdcall (Windows default).
        uc.reg_write(UC_X86_REG_ESP, esp + 4 + n_args * 4)
        uc.reg_write(UC_X86_REG_EIP, ret_addr)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        eip = uc.reg_read(UC_X86_REG_EIP)
        print(f'[emu] Invalid memory access at {address:#x} '
              f'(size={size}, EIP={eip:#x})')
        return False  # stop emulation

    # ----- run -----

    def run(self):
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc = uc

        self.setup_memory()

        # Initial registers (FS_BASE handled via GDT in setup_segments)
        uc.reg_write(UC_X86_REG_ESP, STACK_BASE - 0x1000)
        uc.reg_write(UC_X86_REG_EBP, STACK_BASE - 0x2000)
        # Some shellcode expects specific args at [esp+...]; we leave
        # them zero. Many GuLoader variants enter via CallWindowProcW,
        # so the stack should look like:
        #   [esp+0]  return address (we use 0xDEADDEAD)
        #   [esp+4]  hwnd
        #   [esp+8]  uMsg
        #   [esp+C]  wParam
        #   [esp+10] lParam
        uc.mem_write(STACK_BASE - 0x1000,
                      struct.pack('<5I', 0xDEADDEAD, 0, 0, 0, 0))

        # Hooks
        uc.hook_add(UC_HOOK_CODE, self.hook_code)
        uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)

        entry = SHELLCODE_BASE + self.entry_offset
        end = SHELLCODE_BASE + len(self.shellcode)
        print(f'[emu] entry = {entry:#x}, shellcode end = {end:#x}')
        # Restart-loop: emulation may stop because we patched a stall
        # loop (we call uc.emu_stop in the hook). Resume from the new
        # EIP each time. We also re-set FS_BASE on each restart in case
        # Unicorn resets it across emu_start calls.
        from unicorn.x86_const import UC_X86_REG_FS_BASE
        cur_eip = entry
        while self.insn_count < self.max_insns:
            try:
                uc.reg_write(UC_X86_REG_FS_BASE, TEB_BASE)
            except Exception:
                pass
            try:
                uc.emu_start(cur_eip, end, count=self.max_insns)
            except unicorn.UcError as e:
                eip = uc.reg_read(UC_X86_REG_EIP)
                print(f'[emu] unicorn error at EIP={eip:#x}: {e}')
                break
            new_eip = uc.reg_read(UC_X86_REG_EIP)
            if new_eip == cur_eip:
                break
            cur_eip = new_eip
            if self.insn_count >= self.max_insns:
                break

        print(f'\n[emu] Executed {self.insn_count} instructions')
        if hasattr(self, '_eip_set'):
            print(f'[emu] unique EIPs hit: {len(self._eip_set)}; '
                  f'max EIP reached: {self._max_eip:#x} '
                  f'(offset {self._max_eip - SHELLCODE_BASE:#x})')
        print(f'[emu] Total API calls: {len(self.api_calls)}')
        if self.urls_seen:
            print('\n[emu] === C2 STAGING ARTIFACTS ===')
            for kind, val in self.urls_seen:
                print(f'  {kind}: {val!r}')
        else:
            print('[emu] No C2 staging APIs reached. Common causes:')
            print('       - VEH not driven (anti-debug intercepted us)')
            print('       - Wrong entry point (try --entry 0xb197)')
            print('       - Loader expects a specific input register state')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('shellcode', help='path to piasaba_decoded.bin')
    p.add_argument('--entry', type=lambda s: int(s, 0), default=0,
                    help='entry offset within the shellcode (default 0)')
    p.add_argument('--max-insns', type=int, default=500000,
                    help='max instructions to emulate')
    p.add_argument('--trace', action='store_true',
                    help='print first 200 instructions')
    args = p.parse_args()

    e = Emulator(args.shellcode, entry_offset=args.entry,
                  max_insns=args.max_insns, trace=args.trace)
    e.run()


if __name__ == '__main__':
    main()
