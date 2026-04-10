"""
IDAPython: Annotate Backdoor.Win64.Gsb (Factory-v3 Go implant)
================================================================
Run this in IDA Pro with the sample loaded.

Phase 1: Renames CJK-obfuscated functions to meaningful names
Phase 2: Sets proper Win32 API prototypes on wrapper functions
Phase 3: Adds analyst comments at key offsets

Usage in IDA:
    File -> Script file -> select this .py
    Or: Alt+F7 -> paste path

Author: Tao Goldi
"""

import idaapi
import idc
import ida_name
import ida_typeinf
import ida_hexrays
import ida_nalt

# ─── PHASE 1: FUNCTION RENAMES ───
RENAMES = {
    0x00471700: ("main_init", "Go module initializer"),
    0x00471740: ("main_VirtualAlloc_wrapper",
                 "Wraps VirtualAlloc via LazyProc.Call.\n"
                 "CJK name: main.简短平衡战斗 (Brief Balance Battle)\n"
                 "Prototype: LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)"),
    0x00471EC0: ("main_main",
                 "Entry point.\n"
                 "1. Nuclear reactor simulation cover code (map[GridRef]float64)\n"
                 "2. Calls main_PayloadBuilder to build shellcode\n"
                 "3. Calls main_VirtualAlloc_wrapper with PAGE_EXECUTE_READWRITE (0x40)\n"
                 "4. Copies payload into RWX memory\n"
                 "5. Calls main_DynamicAPIResolver + syscall.Syscall to execute"),
    0x004727A0: ("main_slice_map_ops",
                 "Slice/map operations + runtime.rand.\n"
                 "CJK name: main.提升武装意识到 (Improve Armed Awareness)"),
    0x00472FC0: ("main_DynamicAPIResolver",
                 "Dynamic API resolution chain:\n"
                 "  1. syscall.LoadLibrary(dll_name) -> HMODULE\n"
                 "  2. main_StringDecryptor(encrypted_name) -> decrypted API name\n"
                 "  3. syscall.GetProcAddress(hModule, func_name) -> FARPROC\n"
                 "  4. main_DirectSyscall(proc, args...) -> execute\n"
                 "CJK name: main.账户男孩酒吧 (Account Boy Bar)"),
    0x004738A0: ("main_map_alloc",
                 "Map access + memory allocation.\n"
                 "CJK name: main.也青铜爆炸 (Also Bronze Explosion)"),
    0x00473D60: ("main_StringDecryptor",
                 "Decrypts API function names from encrypted data at runtime.\n"
                 "Called between LoadLibrary and GetProcAddress.\n"
                 "Input: encrypted byte array\n"
                 "Output: plaintext function name string\n"
                 "CJK name: main.牛肉古代桥 (Beef Ancient Bridge)"),
    0x004740E0: ("main_DirectSyscall",
                 "Direct syscall execution:\n"
                 "  1. syscall.LazyProc.Find -> resolve procedure\n"
                 "  2. syscall.SyscallN(proc, nargs, args...) -> invoke\n"
                 "Bypasses usermode API hooks entirely.\n"
                 "CJK name: main.资产酒吧协助 (Asset Bar Assist)"),
    0x004747C0: ("main_PayloadBuilder",
                 "Largest closure (3973 bytes). Builds the shellcode/payload\n"
                 "data in memory. Output is copied to RWX-allocated region.\n"
                 "Contains interleaved reactor simulation cover math.\n"
                 "CJK name: main.讨价还价黄铜道歉 (Bargain Brass Apology)"),
}


# ─── PHASE 2: FUNCTION PROTOTYPES ───
# Set proper C-style prototypes so the decompiler shows Win32 parameter names
PROTOTYPES = {
    # main_VirtualAlloc_wrapper — matches VirtualAlloc signature
    0x00471740: "struct { void* lpBaseAddress; unsigned __int64 error; } __fastcall main_VirtualAlloc_wrapper(void* lpAddress, unsigned __int64 dwSize, unsigned int flAllocationType, unsigned int flProtect);",

    # main_PayloadBuilder — returns a struct with base + size
    0x004747C0: "__int64 __fastcall main_PayloadBuilder();",

    # main_DynamicAPIResolver — takes buffer info + flags, returns resolved data
    0x00472FC0: "struct { __int64 r0; __int64 r1; __int64 r2; __int64 r3; __int64 r4; __int64 r5; } __fastcall main_DynamicAPIResolver(__int64 lpBuffer, unsigned __int64 dwBufferSize, unsigned __int64 nNumberOfBytesToWrite, unsigned int dwCreationFlags, unsigned int dwDesiredAccess, unsigned __int8 bInheritHandle);",

    # main_StringDecryptor — takes encrypted data, returns string
    0x00473D60: "struct { __int64 r0; __int64 r1; } __fastcall main_StringDecryptor(__int64 pEncryptedData, unsigned int nEncryptedLen);",

    # main_DirectSyscall — takes proc + args, invokes via SyscallN
    0x004740E0: "void __fastcall main_DirectSyscall(__int64 lpResolvedProc, unsigned int nArgCount);",

    # main_map_alloc
    0x004738A0: "__int64 __fastcall main_map_alloc(unsigned __int64 nCapacity, void* pTypeDescriptor, __int64 pKeyData, unsigned __int64 nKeyLen);",
}


# ─── PHASE 3: INLINE COMMENTS ───
COMMENTS = {
    # ── main.main: VirtualAlloc RWX ──
    0x004720E0: ">>> PAYLOAD BUILD: main_PayloadBuilder() constructs shellcode/PE payload in memory",
    0x004720E5: "Store pointer to payload struct {base, size, ...}",
    0x004720ED: "lpAddress = payload base address (first field of struct)",
    0x004720F0: "dwSize = payload size in bytes (dword at struct+8)",
    0x004720F6: "flAllocationType = MEM_COMMIT | MEM_RESERVE (0x3000)",
    0x004720FB: "flProtect = PAGE_EXECUTE_READWRITE (0x40) — SHELLCODE STAGING",
    0x00472100: ">>> VirtualAlloc(lpAddress, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)",
    0x00472105: "Check if VirtualAlloc returned NULL or error",
    0x00472121: "Retry: VirtualAlloc(NULL, dwSize, 0x3000, PAGE_EXECUTE_READWRITE)",
    0x00472126: ">>> VirtualAlloc retry — lpAddress=NULL forces OS to choose base",

    # ── main.main: goroutine launches ──
    0x004720C3: "Goroutine: main_map_alloc (reactor cover operations)",
    0x004720E0: ">>> TRANSITION: cover code ends, payload construction begins",
    0x004724D6: ">>> Goroutine: main_DynamicAPIResolver — LoadLibrary + GetProcAddress chain",
    0x00472499: "Goroutine: main_slice_map_ops (additional cover operations)",

    # ── main.main: reactor cover code ──
    0x00471F95: "── COVER CODE START: nuclear reactor simulation (map[GridRef]float64) ──",
    0x00471FB6: "Cover: runtime.mapassign_fast64 — populate reactor lattice cell",
    0x00472018: "Cover: 0x3FF8000000000000 = 1.5 (IEEE 754) — neutron flux coefficient",

    # ── main.main: final execution ──
    0x00472100: ">>> VirtualAlloc(lpAddress, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)",

    # ── main.账户男孩酒吧: LoadLibrary + GetProcAddress ──
    0x004733F5: ">>> syscall.LoadLibrary(lpLibFileName) — load target DLL by name",
    0x004733FA: "if (hModule == NULL) goto error_handler",
    0x00473529: ">>> main_StringDecryptor(pEncryptedName) — decrypt API function name at runtime",
    0x00473539: ">>> syscall.GetProcAddress(hModule, lpDecryptedProcName) — resolve function pointer",
    0x00473540: "if (lpProcAddress == NULL) goto error_handler",
    0x00473555: ">>> main_DirectSyscall — execute resolved API via SyscallN",

    # ── main.资产酒吧协助: SyscallN ──
    0x00474225: "Load LazyDLL/LazyProc global pointer",
    0x00474235: ">>> syscall.LazyProc.Find() — resolve Windows API at runtime",
    0x0047423A: "if (result != 0) goto error_handler — proc not found",
    0x00474250: "lpProcAddr = LazyProc.addr (offset +0x20 in struct)",
    0x00474254: "fnPtr = *lpProcAddr (actual function pointer at +0x18)",
    0x00474278: "nargs = 2 — number of arguments for SyscallN",
    0x00474280: ">>> syscall.SyscallN(fnPtr, 2, arg0, arg1) — DIRECT SYSCALL (bypasses API hooks)",
    0x00474285: "Check syscall return value (NTSTATUS or BOOL)",

    # ── main.牛肉古代桥: String decryptor ──
    0x00473D60: "── STRING DECRYPTOR: transforms encrypted bytes into plaintext API names ──",

    # ── main.main: syscall.Syscall at the end ──
    # (the final call after DynamicAPIResolver returns)
}


# ─── PHASE 4: CONSTANT DEFINITIONS ───
# Add enum-like comments for magic constants
CONSTANT_COMMENTS = {
    # In the decompiled code, 0x3000 and 64 appear as VirtualAlloc args
    # IDA sometimes shows 12288 instead of 0x3000
    # These comments help when reading the pseudocode
}


def apply_prototype(addr, proto_str):
    """Apply a C function prototype to a function in IDA."""
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    if ida_typeinf.parse_decl(tif, til, proto_str, ida_typeinf.PT_SIL) is not None:
        ida_typeinf.apply_tinfo(addr, tif, ida_typeinf.TINFO_DEFINITE)
        return True
    return False


def main():
    print("[*] ════════════════════════════════════════════════════════")
    print("[*] Annotating Backdoor.Win64.Gsb (Factory-v3 Go implant)")
    print("[*] ════════════════════════════════════════════════════════")

    # Phase 1: Rename functions
    print("\n[*] Phase 1: Renaming CJK-obfuscated functions...")
    renamed = 0
    for addr, (name, comment) in RENAMES.items():
        if ida_name.set_name(addr, name, ida_name.SN_FORCE):
            renamed += 1
            print("  [+] 0x{:08X} -> {}".format(addr, name))
        else:
            print("  [-] FAILED: 0x{:08X} -> {}".format(addr, name))
        idc.set_func_cmt(addr, comment, 1)  # repeatable comment
    print("  {} functions renamed".format(renamed))

    # Phase 2: Set prototypes
    print("\n[*] Phase 2: Setting Win32-style function prototypes...")
    proto_ok = 0
    for addr, proto in PROTOTYPES.items():
        if apply_prototype(addr, proto):
            proto_ok += 1
            fname = idc.get_func_name(addr)
            print("  [+] Prototype set for {} @ 0x{:08X}".format(fname, addr))
        else:
            print("  [-] FAILED prototype for 0x{:08X}".format(addr))
            print("      Proto: {}".format(proto[:80]))
    print("  {} prototypes applied".format(proto_ok))

    # Phase 3: Inline comments
    print("\n[*] Phase 3: Adding analyst comments...")
    commented = 0
    for addr, comment in COMMENTS.items():
        idc.set_cmt(addr, comment, 0)
        commented += 1
    print("  {} comments added".format(commented))

    # Final summary
    print("\n[*] ════════════════════════════════════════════════════════")
    print("[*] DONE: {} renames, {} prototypes, {} comments".format(
        renamed, proto_ok, commented))
    print("[*]")
    print("[*] Screenshot locations:")
    print("[*]   #1 Graph:       G -> 0x471EC0  (main_main overview)")
    print("[*]   #2 Decompile:   0x4720E0-0x472130  (VirtualAlloc RWX)")
    print("[*]   #3 Decompile:   0x4733F5-0x473555  (LoadLib+GetProc)")
    print("[*]   #4 Decompile:   0x474225-0x474290  (SyscallN)")
    print("[*]   #5 Func list:   Shift+F3 filter 'main_'")
    print("[*]   #6 Strings:     Shift+F12 filter 'BeamEnvelope'")
    print("[*]   #7 Decompile:   0x473D60  (StringDecryptor)")
    print("[*]")
    print("[*] TIP: Press F5 to re-decompile after prototype changes")
    print("[*] ════════════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
