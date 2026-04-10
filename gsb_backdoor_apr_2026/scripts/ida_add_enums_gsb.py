"""
IDAPython: Add Win32 enum constants for VirtualAlloc parameters
================================================================
Defines MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE as enum
members, then applies them to the operands in main_main so IDA's
decompiler shows symbolic names instead of raw hex.

Usage: File -> Script file -> select this .py

Author: Tao Goldi
"""

import idc
import ida_enum
import ida_bytes
import ida_hexrays

def create_or_get_enum(enum_name):
    """Get existing enum or create a new one."""
    eid = ida_enum.get_enum(enum_name)
    if eid == idc.BADADDR:
        eid = ida_enum.add_enum(idc.BADADDR, enum_name, 0)  # 0 = hex
        print("  [+] Created enum: {}".format(enum_name))
    else:
        print("  [=] Enum exists: {}".format(enum_name))
    return eid

def add_enum_member_safe(eid, name, value):
    """Add an enum member, skip if already exists."""
    if ida_enum.get_enum_member_by_name(name) != idc.BADADDR:
        print("  [=] Member exists: {} = 0x{:X}".format(name, value))
        return
    res = ida_enum.add_enum_member(eid, name, value, idc.BADADDR)
    if res == 0:
        print("  [+] Added: {} = 0x{:X}".format(name, value))
    else:
        print("  [-] Failed to add: {} = 0x{:X} (err={})".format(name, value, res))

def main():
    print("[*] ════════════════════════════════════════════════════════")
    print("[*] Adding Win32 enum constants for VirtualAlloc")
    print("[*] ════════════════════════════════════════════════════════")

    # ─── Create enums ───
    print("\n[*] Creating enums...")

    # flAllocationType enum
    alloc_enum = create_or_get_enum("AllocationType")
    add_enum_member_safe(alloc_enum, "MEM_COMMIT", 0x1000)
    add_enum_member_safe(alloc_enum, "MEM_RESERVE", 0x2000)
    add_enum_member_safe(alloc_enum, "MEM_COMMIT_RESERVE", 0x3000)  # combined
    add_enum_member_safe(alloc_enum, "MEM_RESET", 0x80000)
    add_enum_member_safe(alloc_enum, "MEM_TOP_DOWN", 0x100000)

    # flProtect enum
    prot_enum = create_or_get_enum("MemoryProtection")
    add_enum_member_safe(prot_enum, "PAGE_NOACCESS", 0x01)
    add_enum_member_safe(prot_enum, "PAGE_READONLY", 0x02)
    add_enum_member_safe(prot_enum, "PAGE_READWRITE", 0x04)
    add_enum_member_safe(prot_enum, "PAGE_EXECUTE", 0x10)
    add_enum_member_safe(prot_enum, "PAGE_EXECUTE_READ", 0x20)
    add_enum_member_safe(prot_enum, "PAGE_EXECUTE_READWRITE", 0x40)

    # ─── Apply enums to operands in main_main ───
    print("\n[*] Applying enums to VirtualAlloc call operands...")

    # In the ASM at these addresses, the constants are mov immediates:
    # 0x004720F6: mov ecx, 0x3000  (flAllocationType)
    # 0x004720FB: mov edi, 0x40    (flProtect)
    # Also the retry at:
    # 0x0047211C: mov ecx, 0x3000
    # 0x00472121: mov edi, 0x40

    targets = [
        (0x004720F6, 1, alloc_enum),   # mov ecx, 0x3000 → MEM_COMMIT_RESERVE
        (0x004720FB, 1, prot_enum),    # mov edi, 0x40   → PAGE_EXECUTE_READWRITE
        (0x0047211C, 1, alloc_enum),   # retry: mov ecx, 0x3000
        (0x00472121, 1, prot_enum),    # retry: mov edi, 0x40
    ]

    for addr, opnum, eid in targets:
        # Get the enum ID
        ename = ida_enum.get_enum_name(eid)
        res = idc.op_enum(addr, opnum, eid, 0)
        if res:
            print("  [+] Applied {} at 0x{:08X} op{}".format(ename, addr, opnum))
        else:
            print("  [-] Failed at 0x{:08X} op{} — try manually: Edit > Operand type > Enum".format(addr, opnum))

    # ─── Also apply to the ASM view for the VirtualAlloc_wrapper calls ───
    # Add comments showing the combined meaning
    idc.set_cmt(0x004720F6, "flAllocationType = MEM_COMMIT | MEM_RESERVE (0x3000)", 0)
    idc.set_cmt(0x004720FB, "flProtect = PAGE_EXECUTE_READWRITE (0x40) — RWX!", 0)

    print("\n[*] ════════════════════════════════════════════════════════")
    print("[*] DONE. Press F5 in main_main to refresh decompiler.")
    print("[*]")
    print("[*] Expected result in pseudocode:")
    print("[*]   main_VirtualAlloc_wrapper(")
    print("[*]       *pPayloadStruct,")
    print("[*]       *(pPayloadStruct + 8),")
    print("[*]       MEM_COMMIT_RESERVE,            // was: 0x3000")
    print("[*]       PAGE_EXECUTE_READWRITE);        // was: 0x40")
    print("[*]")
    print("[*] If the decompiler still shows 0x3000/64, right-click")
    print("[*] the constant in pseudocode -> Set Enum -> select the enum")
    print("[*] ════════════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
