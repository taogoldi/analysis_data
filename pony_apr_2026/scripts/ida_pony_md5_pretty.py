"""
Pony stealer — IDAPython beautifier for md5_transform at 0x00402d3e.

Turns Hex-Rays' sea-of-v-variables output for the MD5 compression
function into readable pseudocode by:

  1. Defining struct MD5_STATE { A, B, C, D }.
  2. Defining enum MD5_T_CONST with T1..T64 = the RFC 1321 constants.
  3. Retyping md5_transform as  void(MD5_STATE*, const uint32_t[16]*, int).
  4. Renaming every SSA temporary (v6..v72, state_1) with names that
     reflect the round / step / letter-being-updated pattern of MD5.

Run order:
  - Run ida_pony_setup.py first (installs base types + renames md5_transform).
  - Then File > Script file... > this file.
  - Re-open md5_transform's pseudocode tab (close and F5 again).

In the MD5 compression rotation, each step updates exactly one of
A / B / C / D in the order:  a d c b  a d c b  ...  16 times per round,
so each round produces 4 new values of each letter.  We name the
intermediate SSA temporaries accordingly (e.g. r1_a1 is the A result
after step 1 of round 1, r1_d1 is D after step 2, etc.).
"""

from __future__ import print_function

import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf

# ida_enum was removed in IDA 9.x (enums unified into the type system).
# We keep the import optional purely for older IDA builds that still have it;
# the main code path uses parse_decls which works on every version.
try:
    import ida_enum  # noqa: F401
except ImportError:
    ida_enum = None


MD5_FUNC_EA = 0x00402D3E
MD5_IV_EA   = 0x00402D01


# ---------------------------------------------------------------------------
# 1.  MD5_STATE struct  +  uint32_t[16] block typedef
# ---------------------------------------------------------------------------

MD5_TYPES = r"""
typedef struct MD5_STATE {
    unsigned int A;   // +0x00
    unsigned int B;   // +0x04
    unsigned int C;   // +0x08
    unsigned int D;   // +0x0c
} MD5_STATE;

typedef unsigned int MD5_BLOCK[16];   // one 512-bit MD5 block
"""


def install_types():
    til = ida_typeinf.get_idati()
    flags = getattr(ida_typeinf, "PT_SIL",
                    getattr(ida_typeinf, "PT_SILENT", 0))
    try:
        rc = ida_typeinf.parse_decls(til, MD5_TYPES, None, flags)
    except TypeError:
        rc = ida_typeinf.parse_decls(til, MD5_TYPES, None)
    if rc == 0:
        print("[+] MD5_STATE / MD5_BLOCK types installed")
    else:
        print("[!] %d parse errors (usually harmless redefinitions)" % rc)


# ---------------------------------------------------------------------------
# 2.  MD5_T_CONST enum — all 64 RFC 1321 T-table constants
# ---------------------------------------------------------------------------
#
# Hex-Rays shows `-0x28955B88` in the pseudocode; with this enum applied
# the user can right-click the immediate in Hex-Rays > "Symbolic constant"
# and pick the matching Tn, which renders as T1, T2, ... inline.

MD5_T_TABLE = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]


def install_md5_t_enum():
    """
    Declare the enum via parse_decls so we don't depend on ida_enum.
    Works on IDA 7.x / 8.x (classic enum API) and IDA 9.x (unified type system).
    """
    lines = ["enum MD5_T_CONST : unsigned int {"]
    for i, val in enumerate(MD5_T_TABLE, start=1):
        # Force unsigned-int interpretation with a cast to avoid signed overflow
        # when parse_decls encodes values like 0xE8C7B756.
        lines.append("    T%d = (unsigned int)0x%08XU," % (i, val))
    lines.append("};")
    src = "\n".join(lines)

    til = ida_typeinf.get_idati()
    flags = getattr(ida_typeinf, "PT_SIL",
                    getattr(ida_typeinf, "PT_SILENT", 0))
    try:
        rc = ida_typeinf.parse_decls(til, src, None, flags)
    except TypeError:
        rc = ida_typeinf.parse_decls(til, src, None)
    if rc == 0:
        print("[+] MD5_T_CONST enum installed (T1..T64)")
    else:
        # Some IDA builds refuse to redeclare — fall back to replace-all form.
        replace_flags = flags | getattr(ida_typeinf, "PT_REPLACE", 0x0200)
        try:
            rc = ida_typeinf.parse_decls(til, src, None, replace_flags)
        except TypeError:
            rc = ida_typeinf.parse_decls(til, src, None)
        if rc == 0:
            print("[+] MD5_T_CONST enum replaced (T1..T64)")
        else:
            print("[!] MD5_T_CONST enum parse_decls errors: %d (continuing)" % rc)


# ---------------------------------------------------------------------------
# 3.  Retype md5_transform
# ---------------------------------------------------------------------------

# IDA auto-detects this function as  int __cdecl (...)  in the Hex-Rays
# view; changing the return type or calling convention triggers a stack-
# purge mismatch warning.  Keep both as-is and only narrow the argument
# types.  The trailing "return v75" in the pseudocode is really just the
# initial block_count value — we still mark the return type int so the
# prototype is consistent with the decompiler's view.

MD5_PROTO_CANDIDATES = [
    # Preferred: match auto-detected cc, narrow arg types.
    "int __cdecl md5_transform(MD5_STATE *state, const MD5_BLOCK *blocks, int block_count);",
    # Fallback: no cc specified, let IDA keep whatever it detected.
    "int md5_transform(MD5_STATE *state, const MD5_BLOCK *blocks, int block_count);",
    # Last-resort fallback: no struct types, just names.
    "int __cdecl md5_transform(unsigned int *state, const unsigned char *blocks, int block_count);",
]


def retype_md5_transform():
    for proto in MD5_PROTO_CANDIDATES:
        if idc.SetType(MD5_FUNC_EA, proto):
            print("[+] md5_transform prototype set:")
            print("    %s" % proto)
            return
    print("[-] failed to set md5_transform prototype (tried %d variants)" % len(MD5_PROTO_CANDIDATES))


# ---------------------------------------------------------------------------
# 4.  Rename the SSA temporaries to match MD5 rotation
# ---------------------------------------------------------------------------
#
# MD5 updates A, D, C, B in strict rotation each step.  Within a single
# 64-byte block the sequence is:
#
#   step  1:  A <- ...   (pseudocode: v9,  v13, v17, ... depending on round)
#   step  2:  D <- ...
#   step  3:  C <- ...
#   step  4:  B <- ...
#   step  5:  A <- ...
#   ...
#
# The Hex-Rays decompile introduces one fresh SSA temporary per step.
# For the build analysed here that mapping is:
#
#   v6/v7/v8   = initial B/C/D loaded from state
#   *state_1   = initial A loaded from state[0] (no distinct lvar)
#
#   Round 1 outputs:  v9 v10 v11 v12   v13 v14 v15 v16
#                     v17 v18 v19 v20  v21 v22 v23 v24
#   Round 2 outputs:  v25 .. v40
#   Round 3 outputs:  v41 .. v56
#   Round 4 outputs:  v57 .. v68
#   Final values:     v69=A  v70=D  v71=C  v72=B   (folded into *state)

ROUND_LETTERS = ["a", "d", "c", "b"]   # rotation order within each step


def build_rename_map():
    m = {
        "state_1":  "state",
        "v6":       "b_init",
        "v7":       "c_init",
        "v8":       "d_init",
    }
    # 4 rounds * 16 steps = 64 SSA temps, starting at v9.
    # Each round produces 4 full cycles of (a, d, c, b).
    step_v = 9
    for rnd in range(1, 5):
        for cycle in range(1, 5):    # 4 cycles per round (16 steps total)
            for letter in ROUND_LETTERS:
                m["v%d" % step_v] = "r%d_%s%d" % (rnd, letter, cycle)
                step_v += 1

    # The last 4 assignments (v69..v72) fold back into state.
    # Their names are also the "final" register values — overwrite to
    # emphasize that role when the reader sees the state[i] += X lines.
    m["v69"] = "A_final"
    m["v70"] = "D_final"
    m["v71"] = "C_final"
    m["v72"] = "B_final"
    return m


def rename_lvars(func_ea, rename_map):
    cf = ida_hexrays.decompile(func_ea)
    if cf is None:
        print("[-] Decompilation failed at 0x%x" % func_ea)
        return 0
    ok = 0
    miss = 0
    # Collect current lvar names so we only rename existing ones.
    current = {lv.name for lv in cf.get_lvars()}
    for old_name, new_name in rename_map.items():
        if old_name not in current:
            miss += 1
            continue
        if ida_hexrays.rename_lvar(func_ea, old_name, new_name):
            ok += 1
        else:
            print("[-] rename failed: %s -> %s" % (old_name, new_name))
    print("[+] %d locals renamed (%d not present in current decompile)" % (ok, miss))
    return ok


# ---------------------------------------------------------------------------
# 5.  Header comment with the MD5 operation legend
# ---------------------------------------------------------------------------

MD5_LEGEND = """MD5 compression — RFC 1321.
state = 4 x uint32 { A, B, C, D }   IV at 0x00402D01 = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}
blocks = array of 16 x uint32 little-endian words (512-bit block)
Per step the rotation updates one letter at a time: A, D, C, B, A, D, C, B ...
Round 1 uses F(B,C,D) and shifts 7/12/17/22.
Round 2 uses G(B,C,D) and shifts 5/9/14/20.
Round 3 uses H(B,C,D) and shifts 4/11/16/23.
Round 4 uses I(B,C,D) and shifts 6/10/15/21.
T-table constants are the MD5_T_CONST enum (right-click > Symbolic constant)."""


def comment_md5_header():
    idc.set_cmt(MD5_FUNC_EA, MD5_LEGEND, 1)
    print("[+] header comment attached to md5_transform")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("  Pony — MD5 transform beautifier")
    print("=" * 72)
    install_types()
    install_md5_t_enum()
    retype_md5_transform()

    rename_map = build_rename_map()
    rename_lvars(MD5_FUNC_EA, rename_map)

    comment_md5_header()

    print("-" * 72)
    print("Done.  To see the changes:")
    print("  1. Close the md5_transform pseudocode tab if open.")
    print("  2. Jump to 0x%08x and press F5 again." % MD5_FUNC_EA)
    print("  3. To render T-constants symbolically, right-click each")
    print("     immediate literal in pseudocode > Symbolic constant >")
    print("     select the matching T1..T64 from MD5_T_CONST.")
    print("=" * 72)


if __name__ == "__main__":
    main()
