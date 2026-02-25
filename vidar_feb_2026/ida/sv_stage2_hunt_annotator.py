"""
Stage2 IDA annotator for SPECTRALVIPER-like payloads.

Goals:
- Find and annotate PEB-walk candidates.
- Find and annotate API-hashing candidates (if present).
- Point to likely config locations (cleartext strings + candidate data blobs).
- Rename functions/globals/locals and apply useful structs/enums.

Usage:
  1) Load stage2 payload in IDA (for this project: artifacts/stage2_dec_unpadded.bin).
  2) File -> Script file... -> sv_stage2_hunt_annotator.py

Tip:
  If you already know exact addresses, set MANUAL_ADDRS below and re-run for deterministic naming.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Tuple

import idc
import idautils
import idaapi
import ida_bytes
import ida_funcs
import ida_frame
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment

try:
    import ida_hexrays  # type: ignore
    HAS_HEXRAYS = True
except Exception:
    ida_hexrays = None  # type: ignore
    HAS_HEXRAYS = False

try:
    import ida_struct  # type: ignore
    HAS_IDA_STRUCT = True
except Exception:
    ida_struct = None  # type: ignore
    HAS_IDA_STRUCT = False


# Optional hard overrides (fill as needed).
# Use integer EAs, e.g. 0x140012340
MANUAL_ADDRS: Dict[str, Optional[int]] = {
    "stage2_entry": None,
    "peb_walk_func": None,
    "api_hash_func": None,
    "config_decode_func": None,
    "config_blob": None,
    "config_size": None,
}


FUNC_COMMENTS = {
    "stage2_entry": "Likely Stage2 execution entry/orchestrator.",
    "peb_walk_func": "Likely PEB/LDR traversal routine for module resolution.",
    "api_hash_func": "Likely API hash resolver/comparator routine.",
    "config_decode_func": "Likely config decode/parse routine.",
}


SUSPICIOUS_STRING_PATTERNS = (
    r"http",
    r"https",
    r"/api",
    r"/chat",
    r"cookie",
    r"user-agent",
    r"beacon",
    r"download",
    r"upload",
    r"command",
    r"task",
    r"config",
    r"chrome",
    r"mozilla",
    r"network",
)


def log(msg: str) -> None:
    print(f"[sv2_annotator] {msg}")


def safe_set_name(ea: int, new_name: str) -> bool:
    if ea is None or ea == idaapi.BADADDR:
        return False
    if ida_name.set_name(ea, new_name, ida_name.SN_CHECK):
        return True
    return ida_name.set_name(ea, new_name + "_sv2", ida_name.SN_CHECK)


def safe_set_cmt(ea: int, text: str) -> None:
    if ea and ea != idaapi.BADADDR:
        ida_bytes.set_cmt(ea, text, 0)


def is_code_ea(ea: int) -> bool:
    f = ida_bytes.get_full_flags(ea)
    return ida_bytes.is_code(f)


def enum_or_create(name: str) -> int:
    eid = idc.get_enum(name)
    if eid == idaapi.BADADDR:
        eid = idc.add_enum(-1, name, 0)
    return eid


def add_enum_member_safe(eid: int, name: str, val: int) -> None:
    if eid == idaapi.BADADDR:
        return
    if idc.get_enum_member_by_name(name) != idaapi.BADADDR:
        return
    idc.add_enum_member(eid, name, val, -1)


def ensure_enums() -> None:
    e1 = enum_or_create("SV2_PEB_OFFSETS")
    add_enum_member_safe(e1, "PEB_LDR_OFFSET", 0x18)
    add_enum_member_safe(e1, "PEB_PROCESS_PARAMETERS_OFFSET", 0x20)
    add_enum_member_safe(e1, "TEB_PEB_PTR_X64", 0x60)
    add_enum_member_safe(e1, "TEB_PEB_PTR_X86", 0x30)

    e2 = enum_or_create("SV2_PE_CONSTS")
    add_enum_member_safe(e2, "IMAGE_DOS_SIGNATURE", 0x5A4D)
    add_enum_member_safe(e2, "IMAGE_NT_SIGNATURE", 0x4550)
    add_enum_member_safe(e2, "E_LFANEW", 0x3C)
    add_enum_member_safe(e2, "EXPORT_DIR_RVA_OFFSET", 0x78)

    e3 = enum_or_create("SV2_WIN_PROTECT")
    add_enum_member_safe(e3, "PAGE_READWRITE", 0x04)
    add_enum_member_safe(e3, "PAGE_EXECUTE_READWRITE", 0x40)

    log("Enums ensured")


def ensure_structs() -> None:
    decls = r'''
    typedef struct LIST_ENTRY_SV2 {
      unsigned __int64 Flink;
      unsigned __int64 Blink;
    } LIST_ENTRY_SV2;

    typedef struct UNICODE_STRING_SV2 {
      unsigned short Length;
      unsigned short MaximumLength;
      unsigned __int64 Buffer;
    } UNICODE_STRING_SV2;

    typedef struct PEB_LDR_DATA_SV2 {
      unsigned int Length;
      unsigned char Initialized;
      unsigned char _pad0[3];
      unsigned __int64 SsHandle;
      LIST_ENTRY_SV2 InLoadOrderModuleList;
      LIST_ENTRY_SV2 InMemoryOrderModuleList;
      LIST_ENTRY_SV2 InInitializationOrderModuleList;
    } PEB_LDR_DATA_SV2;

    typedef struct LDR_DATA_TABLE_ENTRY_SV2 {
      LIST_ENTRY_SV2 InLoadOrderLinks;
      LIST_ENTRY_SV2 InMemoryOrderLinks;
      LIST_ENTRY_SV2 InInitializationOrderLinks;
      unsigned __int64 DllBase;
      unsigned __int64 EntryPoint;
      unsigned int SizeOfImage;
      unsigned int _pad1;
      UNICODE_STRING_SV2 FullDllName;
      UNICODE_STRING_SV2 BaseDllName;
    } LDR_DATA_TABLE_ENTRY_SV2;

    typedef struct PEB_SV2 {
      unsigned char Reserved1[0x18];
      unsigned __int64 Ldr;
      unsigned __int64 ProcessParameters;
    } PEB_SV2;

    typedef struct IMAGE_EXPORT_DIRECTORY_SV2 {
      unsigned int Characteristics;
      unsigned int TimeDateStamp;
      unsigned short MajorVersion;
      unsigned short MinorVersion;
      unsigned int Name;
      unsigned int Base;
      unsigned int NumberOfFunctions;
      unsigned int NumberOfNames;
      unsigned int AddressOfFunctions;
      unsigned int AddressOfNames;
      unsigned int AddressOfNameOrdinals;
    } IMAGE_EXPORT_DIRECTORY_SV2;
    '''
    idc.parse_decls(decls, idc.PT_TYP)
    log("Struct typedefs ensured")


def all_functions() -> List[int]:
    return list(idautils.Functions())


def func_items(fea: int) -> Sequence[int]:
    return list(idautils.FuncItems(fea))


def text_of_operand(ea: int, op: int) -> str:
    try:
        return idc.print_operand(ea, op) or ""
    except Exception:
        return ""


def has_peb_operand_text(op_text: str) -> bool:
    t = op_text.lower().replace(" ", "")
    return (
        "gs:60h" in t
        or "gs:[60h]" in t
        or "fs:30h" in t
        or "fs:[30h]" in t
    )


def function_score_peb_walk(fea: int) -> Tuple[int, List[int]]:
    score = 0
    sites: List[int] = []
    for ea in func_items(fea):
        mnem = idc.print_insn_mnem(ea).lower()
        op0 = text_of_operand(ea, 0)
        op1 = text_of_operand(ea, 1)
        if has_peb_operand_text(op0) or has_peb_operand_text(op1):
            score += 20
            sites.append(ea)
        # common PEB/LDR offsets used during module list walking
        for t in (op0, op1):
            tl = t.lower().replace(" ", "")
            if "+18h" in tl or "+20h" in tl or "+30h" in tl:
                score += 1
        if mnem in ("lodsb", "scasb"):
            score += 1
    return score, sites


def function_score_api_hash(fea: int) -> Tuple[int, Dict[str, int]]:
    stats = {
        "rotates": 0,
        "mix_ops": 0,
        "cmp_imm32": 0,
        "pe_consts": 0,
        "byte_loop": 0,
    }
    score = 0

    for ea in func_items(fea):
        m = idc.print_insn_mnem(ea).lower()
        if m in ("ror", "rol", "rcr", "rcl"):
            stats["rotates"] += 1
            score += 4
        if m in ("xor", "add", "sub", "imul", "mul"):
            stats["mix_ops"] += 1
            score += 1
        if m in ("lodsb", "scasb"):
            stats["byte_loop"] += 1
            score += 2

        for op in (0, 1, 2):
            if idc.get_operand_type(ea, op) == idc.o_imm:
                v = idc.get_operand_value(ea, op)
                if v in (0x5A4D, 0x4550, 0x3C, 0x78):
                    stats["pe_consts"] += 1
                    score += 3
                if v > 0xFFFF and v <= 0xFFFFFFFF:
                    stats["cmp_imm32"] += 1
                    score += 1

    # normalize high-noise arithmetic functions
    if stats["rotates"] == 0 and stats["pe_consts"] == 0:
        score //= 2

    return score, stats


def entry_function() -> Optional[int]:
    ep: Optional[int] = None

    # IDA 7.x compatibility path (may be missing in IDA 9.x builds)
    if hasattr(idc, "get_entrypoint"):
        try:
            e = idc.get_entrypoint()
            if e not in (None, idaapi.BADADDR):
                ep = int(e)
        except Exception:
            pass

    # Preferred portable path: idautils.Entries()
    if ep is None:
        try:
            for _idx, _ord, ea, _name in idautils.Entries():
                if ea not in (None, idaapi.BADADDR):
                    ep = int(ea)
                    break
        except Exception:
            pass

    # Direct ida_entry fallback (API naming can vary across versions)
    if ep is None:
        try:
            import ida_entry  # type: ignore

            qty = ida_entry.get_entry_qty()
            if qty > 0:
                ord0 = ida_entry.get_entry_ordinal(0)
                ea = ida_entry.get_entry(ord0)
                if ea not in (None, idaapi.BADADDR):
                    ep = int(ea)
        except Exception:
            pass

    # Last-resort image start EA fallback
    if ep is None:
        try:
            import ida_ida  # type: ignore

            ea = ida_ida.inf_get_start_ea()
            if ea not in (None, idaapi.BADADDR):
                ep = int(ea)
        except Exception:
            pass

    if ep is None or ep == idaapi.BADADDR:
        return None

    f = ida_funcs.get_func(ep)
    if not f:
        return None
    return f.start_ea


def suspicious_strings() -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    pats = [re.compile(p, re.I) for p in SUSPICIOUS_STRING_PATTERNS]
    s = idautils.Strings()

    # IDA string-type constants moved across versions; keep this robust.
    configured = False
    try:
        str_c = getattr(idautils.Strings, "STR_C")
        str_u = getattr(idautils.Strings, "STR_UNICODE")
        s.setup(strtypes=str_c | str_u)
        configured = True
    except Exception:
        pass

    if not configured:
        try:
            str_c = getattr(idc, "STRTYPE_C", None)
            str_u = (
                getattr(idc, "STRTYPE_C_16", None)
                or getattr(idc, "STRTYPE_UNICODE", None)
            )
            if str_c is not None and str_u is not None:
                s.setup(strtypes=int(str_c) | int(str_u))
            elif str_c is not None:
                s.setup(strtypes=int(str_c))
            else:
                s.setup()
            configured = True
        except Exception:
            pass

    if not configured:
        try:
            s.setup()
        except Exception:
            pass

    for st in s:
        try:
            text = str(st)
        except Exception:
            continue
        if any(p.search(text) for p in pats):
            out.append((st.ea, text))
    return out


def data_segments() -> List[ida_segment.segment_t]:
    segs: List[ida_segment.segment_t] = []
    for n in idautils.Segments():
        seg = ida_segment.getseg(n)
        if not seg:
            continue
        name = ida_segment.get_segm_name(seg).lower()
        if name in (".data", ".rdata", ".bss"):
            segs.append(seg)
    return segs


def guess_config_blob_candidates(limit: int = 8) -> List[Tuple[int, int]]:
    """Return candidate (ea, xref_count) for data items with code xrefs."""
    cands: List[Tuple[int, int]] = []
    for seg in data_segments():
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_data(flags):
                xrefs = 0
                for xr in idautils.XrefsTo(ea, 0):
                    if is_code_ea(xr.frm):
                        xrefs += 1
                if 1 <= xrefs <= 6:
                    cands.append((ea, xrefs))
            item_sz = ida_bytes.get_item_size(ea)
            ea += item_sz if item_sz > 0 else 1

    # prefer moderate xref density
    cands.sort(key=lambda t: (t[1], -t[0]), reverse=True)
    return cands[:limit]


def find_single_byte_xor_plaintext_hits(plaintext: bytes, max_hits: int = 32) -> List[Tuple[int, int]]:
    """
    Scan readable segments for raw bytes that decode to plaintext under one-byte XOR.
    Returns (ea, xor_key).
    """
    if not plaintext:
        return []

    needle_len = len(plaintext)
    hits: List[Tuple[int, int]] = []
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if not seg:
            continue
        if not (seg.perm & ida_segment.SEGPERM_READ):
            continue
        seg_size = seg.end_ea - seg.start_ea
        if seg_size < needle_len:
            continue

        blob = ida_bytes.get_bytes(seg.start_ea, seg_size)
        if not blob:
            continue

        for off in range(0, seg_size - needle_len + 1):
            key = blob[off] ^ plaintext[0]
            matched = True
            for i in range(1, needle_len):
                if (blob[off + i] ^ key) != plaintext[i]:
                    matched = False
                    break
            if not matched:
                continue
            hits.append((seg.start_ea + off, key))
            if len(hits) >= max_hits:
                return hits
    return hits


def rename_frame_var(func_ea: int, old_name: str, new_name: str) -> None:
    if HAS_IDA_STRUCT:
        f = ida_funcs.get_func(func_ea)
        if not f:
            return
        frame = ida_frame.get_frame(f)
        if not frame:
            return
        m = ida_struct.get_member_by_name(frame, old_name)
        if m:
            ida_struct.set_member_name(frame, m.soff, new_name)
        return

    sid = idc.get_frame_id(func_ea)
    if sid in (idc.BADADDR, -1):
        return
    off = idc.get_member_offset(sid, old_name)
    if off != -1:
        idc.set_member_name(sid, off, new_name)


def rename_known_locals(func_ea: int, mapping: Dict[str, str]) -> None:
    for old, new in mapping.items():
        rename_frame_var(func_ea, old, new)


def hexrays_rename_lvars(func_ea: int, mapping: Dict[str, str]) -> None:
    if not HAS_HEXRAYS:
        return
    if not ida_hexrays.init_hexrays_plugin():
        return
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return
    if not cfunc:
        return

    def _rename_lvar_compat(old_name: str, new_name: str) -> bool:
        renamed = False

        if hasattr(cfunc, "rename_lvar"):
            for lv in cfunc.get_lvars():
                if lv.name == old_name:
                    try:
                        if cfunc.rename_lvar(lv, new_name, True):
                            renamed = True
                    except Exception:
                        pass

        if not renamed and hasattr(ida_hexrays, "rename_lvar"):
            try:
                renamed = bool(ida_hexrays.rename_lvar(func_ea, old_name, new_name))
            except Exception:
                pass

        if not renamed and hasattr(ida_hexrays, "modify_user_lvar_info"):
            try:
                for lv in cfunc.get_lvars():
                    if lv.name == old_name:
                        lsi = ida_hexrays.lvar_saved_info_t()
                        lsi.ll = lv
                        lsi.name = new_name
                        if ida_hexrays.modify_user_lvar_info(func_ea, ida_hexrays.MLI_NAME, lsi):
                            renamed = True
            except Exception:
                pass

        return renamed

    changed = False
    for old_name, new_name in mapping.items():
        if _rename_lvar_compat(old_name, new_name):
            changed = True
    if changed:
        if hasattr(cfunc, "save_user_labels"):
            cfunc.save_user_labels()


def apply_manual_overrides() -> None:
    for key, ea in MANUAL_ADDRS.items():
        if not ea:
            continue
        if key == "stage2_entry":
            safe_set_name(ea, "stage2_entry_orchestrator")
        elif key == "peb_walk_func":
            safe_set_name(ea, "sv2_peb_walk_resolve_modules")
        elif key == "api_hash_func":
            safe_set_name(ea, "sv2_resolve_api_by_hash")
        elif key == "config_decode_func":
            safe_set_name(ea, "sv2_decode_or_parse_config")
        elif key == "config_blob":
            safe_set_name(ea, "g_sv2_config_blob")
        elif key == "config_size":
            safe_set_name(ea, "g_sv2_config_size")

        if key in FUNC_COMMENTS:
            safe_set_cmt(ea, FUNC_COMMENTS[key])


def annotate_stage2() -> None:
    ensure_enums()
    ensure_structs()

    apply_manual_overrides()

    # Entry point rename
    epf = entry_function()
    if epf:
        safe_set_name(epf, "stage2_entrypoint")
        safe_set_cmt(epf, "Stage2 entrypoint function (from PE entry RVA).")

    # PEB walk candidate
    peb_scores: List[Tuple[int, int, List[int]]] = []
    for fea in all_functions():
        score, sites = function_score_peb_walk(fea)
        if score > 0:
            peb_scores.append((score, fea, sites))
    peb_scores.sort(reverse=True, key=lambda t: t[0])

    if peb_scores:
        score, fea, sites = peb_scores[0]
        safe_set_name(fea, "sv2_peb_walk_candidate")
        safe_set_cmt(fea, f"PEB-walk heuristic score={score}.")
        for s in sites[:8]:
            safe_set_cmt(s, "PEB access candidate (gs:60h/fs:30h).")
        log(f"PEB candidate: {hex(fea)} score={score}")

        rename_known_locals(
            fea,
            {
                "arg_0": "module_hash_or_seed",
                "var_10": "ldr_entry",
                "var_18": "module_base",
            },
        )
        hexrays_rename_lvars(
            fea,
            {
                "a1": "module_hash",
                "v1": "peb",
                "v2": "ldr",
                "v3": "ldr_head",
                "v4": "entry",
                "v5": "module_base",
                "v6": "module_name",
            },
        )

    # API-hash candidate
    hash_scores: List[Tuple[int, int, Dict[str, int]]] = []
    for fea in all_functions():
        score, stats = function_score_api_hash(fea)
        # avoid huge wrapper noise
        if score >= 18:
            hash_scores.append((score, fea, stats))
    hash_scores.sort(reverse=True, key=lambda t: t[0])

    if hash_scores:
        score, fea, stats = hash_scores[0]
        safe_set_name(fea, "sv2_api_hash_candidate")
        safe_set_cmt(fea, f"API-hash heuristic score={score} stats={stats}")
        log(f"API-hash candidate: {hex(fea)} score={score} stats={stats}")

        hexrays_rename_lvars(
            fea,
            {
                "a1": "module_base_or_seed",
                "a2": "target_api_hash",
                "v1": "export_dir",
                "v2": "name_count",
                "v3": "name_rvas",
                "v4": "ordinal_table",
                "v5": "func_table",
                "v6": "name_ptr",
                "v7": "rolling_hash",
                "v8": "resolved_api",
            },
        )

    # Suspicious strings + config hints
    s_hits = suspicious_strings()
    for i, (ea, text) in enumerate(s_hits[:40], 1):
        safe_set_name(ea, f"g_sv2_str_hint_{i:02d}")
        safe_set_cmt(ea, f"Suspicious string hint: {text[:120]}")

    if s_hits:
        log(f"Suspicious strings tagged: {len(s_hits)}")

    xor_hits = find_single_byte_xor_plaintext_hits(b"Mozilla/5.0", max_hits=16)
    for idx, (ea, key) in enumerate(xor_hits, 1):
        safe_set_name(ea, f"g_sv2_xor_mozilla_hit_{idx:02d}")
        safe_set_cmt(
            ea,
            f"Single-byte XOR hit: bytes here decode to 'Mozilla/5.0' with key=0x{key:02x}.",
        )
    if xor_hits:
        log(f"XORed Mozilla/5.0 hits: {len(xor_hits)}")
        for ea, key in xor_hits[:8]:
            log(f"  {hex(ea)} key=0x{key:02x}")

    cfg_cands = guess_config_blob_candidates(limit=10)
    for idx, (ea, xr) in enumerate(cfg_cands, 1):
        nm = f"g_sv2_cfg_blob_candidate_{idx:02d}"
        safe_set_name(ea, nm)
        safe_set_cmt(ea, f"Config/data candidate by xref heuristic (code xrefs={xr}).")

    if cfg_cands:
        log("Config blob candidates:")
        for ea, xr in cfg_cands[:5]:
            log(f"  {hex(ea)} xrefs={xr}")

    # Try to identify a config-decode function as one that references both string hints and cfg candidates
    def func_of_ea(ea: int) -> Optional[int]:
        f = ida_funcs.get_func(ea)
        return f.start_ea if f else None

    func_counter: Dict[int, int] = {}
    for ea, _txt in s_hits:
        for xr in idautils.XrefsTo(ea, 0):
            ff = func_of_ea(xr.frm)
            if ff is not None:
                func_counter[ff] = func_counter.get(ff, 0) + 1
    for ea, _xr in cfg_cands:
        for xr in idautils.XrefsTo(ea, 0):
            ff = func_of_ea(xr.frm)
            if ff is not None:
                func_counter[ff] = func_counter.get(ff, 0) + 2

    if func_counter:
        cfg_func = sorted(func_counter.items(), key=lambda kv: kv[1], reverse=True)[0][0]
        safe_set_name(cfg_func, "sv2_config_decode_candidate")
        safe_set_cmt(cfg_func, f"Config-decode candidate score={func_counter[cfg_func]}.")
        log(f"Config decode candidate: {hex(cfg_func)} score={func_counter[cfg_func]}")

        hexrays_rename_lvars(
            cfg_func,
            {
                "a1": "cfg_blob",
                "a2": "cfg_size",
                "v1": "cfg_out",
                "v2": "cursor",
                "v3": "decoded_len",
            },
        )

    # Manual address comments reinforce final output
    for k, ea in MANUAL_ADDRS.items():
        if ea and k in FUNC_COMMENTS:
            safe_set_cmt(ea, FUNC_COMMENTS[k])

    log("Stage2 annotation complete")


def main() -> None:
    annotate_stage2()
    ida_kernwin.refresh_idaview_anyway()


if __name__ == "__main__":
    main()
