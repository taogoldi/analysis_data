"""
IDAPython: Annotate the Quasar Loader decryption function
============================================================
Renames functions, applies comments, and optionally creates enums
to make the decompiled view publication-ready.

Usage in IDA:
    File -> Script file -> select this .py
    (Alt+F7 -> select this .py)

NOTE: This script MUST be run inside IDA Pro's Python console.
      It will NOT work from a regular terminal (the ida_* modules
      only exist inside IDA's embedded Python environment).

Author: Tao Goldi
"""

import idc

# Try importing optional modules (available in IDA Pro, may be
# missing in IDA Free or older versions)
try:
    import ida_name
    HAS_IDA_NAME = True
except ImportError:
    HAS_IDA_NAME = False

try:
    import ida_enum
    HAS_IDA_ENUM = True
except ImportError:
    HAS_IDA_ENUM = False


MAIN_FUNC = 0x140001000


def safe_set_name(ea, name):
    """Rename an address, using ida_name if available, idc fallback."""
    if HAS_IDA_NAME:
        ida_name.set_name(ea, name, ida_name.SN_FORCE)
    else:
        idc.set_name(ea, name, idc.SN_NOWARN)


def main():
    print("[*] ════════════════════════════════════════════════════════")
    print("[*] Annotating Quasar Loader (0x140001000)")
    print("[*] ════════════════════════════════════════════════════════")

    # ─── Rename the main function ───
    print("\n[*] Renaming functions...")
    safe_set_name(MAIN_FUNC, "DecryptAndDropQuasar")
    idc.set_func_cmt(MAIN_FUNC,
        "Quasar RAT loader main function.\n"
        "1. Sleep(5000) anti-sandbox delay\n"
        "2. Byte-pair swap across 3.26MB encrypted buffer\n"
        "3. Per-byte cipher: SUB(counter) -> SUB(0x10) -> XOR(counter-0x1B) -> ROR(5)\n"
        "4. Drop decrypted PE to %%PUBLIC%%\\Libraries\\win_update_host.exe\n"
        "5. Execute via ShellExecuteA(\"open\")\n\n"
        "Encrypted buffer: lpBuffer at .data+0xA40 (VA 0x140018A40)\n"
        "Buffer size: 0x31D600 = 3,266,048 bytes\n"
        "Decrypted payload: Quasar RAT v1.4.1 (.NET PE)", 1)
    print("  [+] Renamed 0x{:X} -> DecryptAndDropQuasar".format(MAIN_FUNC))

    # ─── Rename the encrypted buffer ───
    safe_set_name(0x140018A40, "g_EncryptedQuasarPayload")
    print("  [+] Renamed 0x140018A40 -> g_EncryptedQuasarPayload")

    # ─── Create enums for constants (IDA Pro only) ───
    if HAS_IDA_ENUM:
        print("\n[*] Creating enums...")

        # File attributes
        file_attr_enum = ida_enum.add_enum(idc.BADADDR, "FileAttributes", 0)
        if file_attr_enum != idc.BADADDR:
            ida_enum.add_enum_member(file_attr_enum, "FILE_ATTRIBUTE_NORMAL", 0x80)
            ida_enum.add_enum_member(file_attr_enum, "FILE_ATTRIBUTE_HIDDEN", 0x02)
            print("  [+] Created FileAttributes enum")

        # CreateFile access
        access_enum = ida_enum.add_enum(idc.BADADDR, "FileAccess", 0)
        if access_enum != idc.BADADDR:
            ida_enum.add_enum_member(access_enum, "GENERIC_WRITE", 0x40000000)
            ida_enum.add_enum_member(access_enum, "GENERIC_READ", 0x80000000)
            print("  [+] Created FileAccess enum")

        # CreateFile disposition
        disp_enum = ida_enum.add_enum(idc.BADADDR, "CreationDisposition", 0)
        if disp_enum != idc.BADADDR:
            ida_enum.add_enum_member(disp_enum, "CREATE_ALWAYS", 2)
            ida_enum.add_enum_member(disp_enum, "OPEN_EXISTING", 3)
            print("  [+] Created CreationDisposition enum")
    else:
        print("\n[!] ida_enum not available (IDA Free?). Skipping enum creation.")
        print("    Enums are cosmetic only -- comments still apply.")

    # ─── Add inline comments ───
    print("\n[*] Adding comments...")

    comments = {
        # Sleep
        0x140001024: "Anti-sandbox: Sleep(5000ms) before decryption",
        0x140001029: ">>> kernel32!Sleep(5000) -- 5-second delay to evade sandbox timeouts",

        # Byte-swap loop
        0x14000102F: "-- STEP 1: Byte-pair swap --",
        0x140001031: "rdi = &g_EncryptedQuasarPayload (VA 0x140018A40, .data+0xA40)",
        0x140001040: "Swap loop: blob[i] <-> blob[i+1] for i in range(0, 0x31D5FF, 2)",
        0x14000105D: "Loop bound: 0x31D5FF = 3,266,047 (entire encrypted payload)",

        # Decryption loop
        0x140001066: "-- STEP 2: Per-byte decryption cipher --",
        0x140001070: "For each byte: SUB(counter) -> SUB(0x10) -> XOR(counter-0x1B) -> ROR(5)",
        0x140001073: "eax = counter - 0x1B (27) -- offset for XOR operation",
        0x140001077: "cl = blob[i] -- load current encrypted byte",
        0x14000107B: "cl -= (counter & 0xFF) -- subtract counter (first transformation)",
        0x140001081: "cl -= 0x10 -- subtract 16 (second transformation)",
        0x140001084: "cl ^= al -- XOR with (counter - 27) (third transformation)",
        0x140001086: "cl = ROR(cl, 5) -- rotate right 5 bits (fourth transformation)",
        0x140001089: "blob[i] = cl -- write decrypted byte back",

        # Drop path
        0x14000108E: "-- STEP 3: Drop decrypted PE to disk --",
        # The ExpandEnvironmentStringsA call
    }

    for addr, cmt in comments.items():
        idc.set_cmt(addr, cmt, 0)
        print("  [+] Comment at 0x{:08X}".format(addr))

    # ─── Repeatable comment on the encrypted buffer ───
    print("\n[*] Adding repeatable comments for key addresses...")
    idc.set_cmt(0x140018A40, "Encrypted Quasar RAT payload (3.26MB, custom byte cipher)", 1)

    print("\n[*] ════════════════════════════════════════════════════════")
    print("[*] DONE. Press F5 to refresh the decompiled view.")
    print("[*]")
    print("[*] Key screenshot locations:")
    print("[*]   #1 Sleep + setup:     0x140001000 (F5 decompiled)")
    print("[*]   #2 Swap loop:         0x140001040 (ASM view)")
    print("[*]   #3 Cipher loop:       0x140001070 (ASM view)")
    print("[*]   #4 Full decompiled:   0x140001000 (F5)")
    print("[*]   #5 Drop path + exec:  after 0x14000108E (F5)")
    print("[*]")
    print("[*] After F5, the decompiled code should show:")
    print("[*]   Sleep(5000)")
    print("[*]   // byte-swap loop with annotated comments")
    print("[*]   // cipher loop with SUB/XOR/ROR comments")
    print("[*]   ExpandEnvironmentStringsA(\"%PUBLIC%\\Libraries\\win_update_host.exe\")")
    print("[*]   CreateFileA(lpDst, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)")
    print("[*]   WriteFile(hFile, g_EncryptedQuasarPayload, 0x31D600, ...)")
    print("[*]   ShellExecuteA(0, \"open\", lpDst, 0, 0, 0)")
    print("[*] ════════════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
