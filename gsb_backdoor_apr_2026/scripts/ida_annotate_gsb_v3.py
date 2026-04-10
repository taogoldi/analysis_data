"""
IDAPython v3: Annotate Backdoor.Win64.Gsb — Local Variable Renaming
=====================================================================
Compatible with IDA 7.x and 8.x (uses user_lvar_modifier_t)

Usage in IDA:
    File -> Script file -> select this .py

Author: Tao Goldi
"""

import idaapi
import idc
import ida_hexrays

MAIN_MAIN = 0x00471EC0

# ─── Variable renames for main_main ───
RENAMES = {
    "v72":    "pPayloadStruct",
    "v81":    "allocResult_1",
    "v82":    "allocResult_2",
    "r0":     "lpBaseAddress",
    "r1":     "dwAllocError",
    "r0_1":   "lpRWXMemory",
    "v22":    "dwPayloadSize",
    "r0_2":   "lpRWXMemory_saved",
    "v78":    "reactorMap_1",
    "v75":    "reactorMap_2",
    "_r1_1":  "nLatticeCells",
    "_r5":    "lpResolvedAPIResult",
    "r0_4":   "lpRWXMemory_final",
}


def rename_lvars(func_addr, rename_map):
    """Rename local variables using the lvar_saved_info_t approach (IDA 7.x+)."""
    cfunc = ida_hexrays.decompile(func_addr)
    if not cfunc:
        print("  [-] Cannot decompile 0x{:08X}".format(func_addr))
        return 0

    count = 0
    lvars = cfunc.get_lvars()

    # Build the saved info vector
    lsi_vec = ida_hexrays.lvar_uservec_t()
    lsi_vec.lvvec = ida_hexrays.lvar_saved_infos_t()

    for lvar in lvars:
        if lvar.name in rename_map:
            new_name = rename_map[lvar.name]

            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lvar
            lsi.name = new_name
            lsi_vec.lvvec.push_back(lsi)

            print("  [+] {} -> {}".format(lvar.name, new_name))
            count += 1

    if count > 0:
        ida_hexrays.save_user_lvar_settings(func_addr, lsi_vec)

    return count


def add_asm_comments():
    """Add comments in both ASM and decompiler views."""
    comments = {
        0x004720E0: ">>> PAYLOAD: main_PayloadBuilder() builds shellcode in memory",
        0x004720F6: "flAllocationType = MEM_COMMIT | MEM_RESERVE (0x3000)",
        0x004720FB: "flProtect = PAGE_EXECUTE_READWRITE (0x40) — RWX SHELLCODE STAGING",
        0x00472100: ">>> VirtualAlloc(lpAddress, dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)",
        0x00472126: ">>> VirtualAlloc RETRY with lpAddress=NULL",
        0x004733F5: ">>> LoadLibraryW(lpDllName) — resolve DLL handle at runtime",
        0x00473529: ">>> main_StringDecryptor() — decrypt encrypted API function name",
        0x00473539: ">>> GetProcAddress(hModule, lpDecryptedProcName) — resolve function pointer",
        0x00473555: ">>> Execute resolved API via main_DirectSyscall (SyscallN)",
        0x00474235: ">>> LazyProc.Find() — resolve Windows API procedure at runtime",
        0x00474278: "nargs = 2 — argument count for SyscallN invocation",
        0x00474280: ">>> SyscallN(fnPtr, nargs, arg0, arg1) — DIRECT SYSCALL bypassing API hooks",
    }

    count = 0
    for addr, cmt in comments.items():
        idc.set_cmt(addr, cmt, 0)
        count += 1
        print("  [+] Comment at 0x{:08X}".format(addr))

    return count


def main():
    print("[*] ════════════════════════════════════════════════════════")
    print("[*] Gsb Backdoor v3 — Decompiler Variable Renaming")
    print("[*] ════════════════════════════════════════════════════════")

    print("\n[*] Renaming variables in main_main...")
    n_renamed = rename_lvars(MAIN_MAIN, RENAMES)

    print("\n[*] Adding ASM comments...")
    n_comments = add_asm_comments()

    print("\n[*] ════════════════════════════════════════════════════════")
    print("[*] DONE: {} variables renamed, {} comments added".format(n_renamed, n_comments))
    print("[*] Press F5 in main_main to refresh the decompiler view")
    print("[*] ════════════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
