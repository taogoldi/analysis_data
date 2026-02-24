"""
IDA Python helper for 22.exe stage-decrypt/evasion path.

What it does:
- Renames core stage/decrypt functions.
- Renames key globals (encrypted blob, key/iv, patch bytes).
- Adds comments at critical instructions/values.
- Creates useful enums/structs for this workflow.
- Renames frame vars and Hex-Rays decompiler vars where possible.

Run inside IDA on the loaded 22.exe database:
    File -> Script file... -> sv_stage_decrypt_annotator.py
"""

import idc
import idaapi
import ida_funcs
import ida_name
import ida_bytes
import ida_frame

try:
    import ida_struct  # type: ignore
    HAS_IDA_STRUCT = True
except Exception:
    ida_struct = None  # type: ignore
    HAS_IDA_STRUCT = False

try:
    import ida_hexrays  # type: ignore
    HAS_HEXRAYS = True
except Exception:
    ida_hexrays = None  # type: ignore
    HAS_HEXRAYS = False


BASE = 0x140000000


FUNC_RENAMES = {
    0x140004530: "stage0_main_orchestrator",
    0x140002FF0: "decrypt_stage2_blob_alloc_unpad",
    0x140002FA0: "preflight_env_gate",
    0x140002D00: "aes256_expand_key_and_store_iv",
    0x140002820: "aes256_cbc_decrypt_inplace",
    0x140002EA0: "patch_amsi_exports",
    0x140002F00: "patch_etw_exports",
    0x140003E50: "reflective_load_pe_from_memory",
}


GLOBAL_RENAMES = {
    0x140005140: "g_stage2_encrypted_blob",
    0x1400A3560: "g_stage2_encrypted_blob_size",
    0x1400A3590: "g_stage2_aes_iv",
    0x1400A35A0: "g_stage2_aes_key",
    0x140005120: "g_amsi_patch_bytes",
    0x1400A3570: "g_etw_patch_bytes_primary",
    0x1400A3580: "g_etw_patch_bytes_fallback",
}


FUNC_TYPES = {
    0x140004530: "int __fastcall stage0_main_orchestrator(void);",
    0x140002FF0: (
        "int __fastcall decrypt_stage2_blob_alloc_unpad("
        "const void *enc_blob, unsigned int enc_blob_size, "
        "void **out_dec_blob, unsigned int *out_dec_size);"
    ),
    0x140002D00: (
        "void __fastcall aes256_expand_key_and_store_iv("
        "unsigned char *aes_ctx, const unsigned char *key_32, const void *iv_16);"
    ),
    0x140002820: (
        "void __fastcall aes256_cbc_decrypt_inplace("
        "unsigned char *aes_ctx, void *cipher_buf, unsigned __int64 data_size);"
    ),
    0x140002EA0: "int __fastcall patch_amsi_exports(void);",
    0x140002F00: "int __fastcall patch_etw_exports(void);",
    0x140003E50: "int __fastcall reflective_load_pe_from_memory(void *image_base, unsigned int image_size);",
}


# Disassembly/frame variable renames
FRAME_VAR_RENAMES = {
    0x140004530: {
        "lpAddress": "stage2_heap_base",
        "var_14": "stage2_dec_size",
        "Src": "stage2_dec_buf",
    },
    0x140002FF0: {
        "var_128": "aes_ctx_tmp",
    },
}


# Hex-Rays variable rename maps (best-effort)
HR_LVAR_RENAMES = {
    0x140002FF0: {
        "a1": "enc_blob",
        "a2": "enc_blob_size",
        "a3": "out_dec_blob",
        "a4": "out_dec_size",
        "v3": "dec_blob_ptr",
        "v5": "alloc_ptr",
        "v6": "aes_ctx",
        "v8": "pad_val",
    },
    0x140004530: {
        "v1": "stage2_heap_base",
        "v2": "stage2_dec_size",
        "v3": "stage2_dec_buf",
        "v4": "load_result",
    },
    0x140002D00: {
        "a1": "aes_ctx",
        "a2": "aes_key_32",
        "a3": "aes_iv_16",
    },
    0x140002820: {
        "a1": "aes_ctx",
        "a2": "cipher_buf",
        "a3": "data_size",
    },
}


COMMENTS = {
    0x140004530: "Stage0 orchestrator: preflight -> AMSI/ETW patch -> decrypt Stage2 -> reflective load.",
    0x14000456A: "Load encrypted blob size from g_stage2_encrypted_blob_size.",
    0x14000457A: "Encrypted blob source g_stage2_encrypted_blob.",
    0x140004581: "decrypt_stage2_blob_alloc_unpad(enc_blob, size, &out_ptr, &out_len)",
    0x140004598: "reflective_load_pe_from_memory(stage2_dec_buf, stage2_dec_size)",
    0x1400045A4: "VirtualFree(..., MEM_RELEASE=0x8000).",
    0x14000303C: "AES IV pointer: g_stage2_aes_iv.",
    0x140003046: "AES key pointer: g_stage2_aes_key.",
    0x14000304D: "Expand AES-256 key schedule into local ctx.",
    0x14000305B: "AES-CBC decrypt in place for stage2 blob.",
    0x140003066: "Read PKCS#7 pad value from last decrypted byte.",
    0x140003079: "If pad in 1..16, trim plaintext size.",
    0x140002D00: "AES-256 key expansion + IV stash (ctx[0xF0..0xFF]).",
    0x140002820: "AES-256 CBC decryption core; includes round transforms and CBC XOR chaining.",
    0x140002EA0: "AMSI patch routine (AmsiScanBuffer/AmsiOpenSession).",
    0x140002F00: "ETW patch routine (EtwEventWrite/EtwEventWriteTransfer/NtTraceEvent).",
}


GLOBAL_COMMENTS = {
    0x140005120: "AMSI patch bytes: B8 57 00 07 80 C3 => mov eax, 0x80070057; ret",
    0x1400A3570: "ETW patch bytes (primary): 31 C0 C3 => xor eax,eax; ret",
    0x1400A3580: "ETW patch bytes (fallback): C2 14 00 => ret 0x14",
    0x1400A3590: "AES-CBC IV (16 bytes) used for stage2 blob decrypt.",
    0x1400A35A0: "AES-256 key (32 bytes) used for stage2 blob decrypt.",
    0x1400A3560: "Encrypted stage2 blob size dword (sample observed: 0x9E410).",
    0x140005140: "Encrypted stage2 blob bytes source.",
}


OPERAND_ENUM_BINDINGS = [
    # ea, opnum, enum_name
    (0x14000300D, 1, "WIN_MEM_ALLOC_TYPE"),  # 0x3000
    (0x140003013, 1, "WIN_PAGE_PROTECT"),    # 0x4
    (0x1400045A4, 1, "WIN_MEM_FREE_TYPE"),   # 0x8000
]


def log(msg):
    print("[sv_annotator] " + msg)


def safe_set_name(ea, new_name):
    if ida_name.set_name(ea, new_name, ida_name.SN_CHECK):
        return True
    # fallback in case collision
    return ida_name.set_name(ea, new_name + "_sv", ida_name.SN_CHECK)


def safe_set_cmt(ea, text):
    ida_bytes.set_cmt(ea, text, 0)


def create_or_get_enum(enum_name):
    eid = idc.get_enum(enum_name)
    if eid == idaapi.BADADDR:
        eid = idc.add_enum(-1, enum_name, 0)
    return eid


def add_enum_const(enum_id, name, value):
    # tolerate duplicates/reruns
    existing = idc.get_enum_member_by_name(name)
    if existing != idaapi.BADADDR:
        return
    idc.add_enum_member(enum_id, name, value, -1)


def build_enums():
    mem_alloc = create_or_get_enum("WIN_MEM_ALLOC_TYPE")
    add_enum_const(mem_alloc, "MEM_COMMIT", 0x1000)
    add_enum_const(mem_alloc, "MEM_RESERVE", 0x2000)
    add_enum_const(mem_alloc, "MEM_COMMIT_RESERVE", 0x3000)

    page_prot = create_or_get_enum("WIN_PAGE_PROTECT")
    add_enum_const(page_prot, "PAGE_READWRITE", 0x04)
    add_enum_const(page_prot, "PAGE_EXECUTE_READWRITE", 0x40)

    mem_free = create_or_get_enum("WIN_MEM_FREE_TYPE")
    add_enum_const(mem_free, "MEM_RELEASE", 0x8000)

    log("Enums ensured: WIN_MEM_ALLOC_TYPE / WIN_PAGE_PROTECT / WIN_MEM_FREE_TYPE")


def bind_operand_enums():
    for ea, opnum, enum_name in OPERAND_ENUM_BINDINGS:
        eid = idc.get_enum(enum_name)
        if eid == idaapi.BADADDR:
            continue
        idc.op_enum(ea, opnum, eid, 0)


def apply_function_renames():
    for ea, name in FUNC_RENAMES.items():
        if ida_funcs.get_func(ea):
            ok = safe_set_name(ea, name)
            log("rename func %s @ %s -> %s" % ("ok" if ok else "skip", hex(ea), name))


def apply_global_renames():
    for ea, name in GLOBAL_RENAMES.items():
        ok = safe_set_name(ea, name)
        log("rename global %s @ %s -> %s" % ("ok" if ok else "skip", hex(ea), name))


def apply_types():
    for ea, t in FUNC_TYPES.items():
        if ida_funcs.get_func(ea):
            if idc.SetType(ea, t):
                log("type ok @ %s" % hex(ea))
            else:
                log("type skip @ %s" % hex(ea))


def rename_frame_vars(func_ea, renames):
    # Prefer ida_struct path when available.
    if HAS_IDA_STRUCT:
        f = ida_funcs.get_func(func_ea)
        if not f:
            return
        frame = ida_frame.get_frame(f)
        if not frame:
            return
        for old, new in renames.items():
            m = ida_struct.get_member_by_name(frame, old)
            if m:
                ida_struct.set_member_name(frame, m.soff, new)
        return

    # Fallback for IDA builds without ida_struct module.
    sid = idc.get_frame_id(func_ea)
    if sid in (idc.BADADDR, -1):
        return
    for old, new in renames.items():
        off = idc.get_member_offset(sid, old)
        if off != -1:
            idc.set_member_name(sid, off, new)


def apply_frame_var_renames():
    for func_ea, mapping in FRAME_VAR_RENAMES.items():
        rename_frame_vars(func_ea, mapping)
        log("frame vars updated @ %s" % hex(func_ea))


def apply_comments():
    for ea, c in COMMENTS.items():
        safe_set_cmt(ea, c)
    for ea, c in GLOBAL_COMMENTS.items():
        safe_set_cmt(ea, c)


def create_structs():
    # Parse C declarations into Local Types
    decls = r'''
    typedef struct AES256_CTX_SV {
      unsigned char round_keys[0xF0];
      unsigned char iv[0x10];
    } AES256_CTX_SV;

    typedef struct STAGE2_DECRYPT_OUT_SV {
      void *buf;
      unsigned int size;
    } STAGE2_DECRYPT_OUT_SV;
    '''
    idc.parse_decls(decls, idc.PT_TYP)
    log("Local structs ensured: AES256_CTX_SV, STAGE2_DECRYPT_OUT_SV")


def try_hexrays_var_renames(func_ea, rename_map):
    if not ida_hexrays.init_hexrays_plugin():
        return
    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return
    if not cfunc:
        return

    def _rename_lvar_compat(old_name, new_name):
        # IDA versions differ: some expose cfunc.rename_lvar(), others expose
        # ida_hexrays.rename_lvar(func_ea, old, new).
        # Try both, then fall back silently.
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
            # Legacy fallback path.
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
    for old_name, new_name in rename_map.items():
        if _rename_lvar_compat(old_name, new_name):
            changed = True

    if changed:
        if hasattr(cfunc, "save_user_labels"):
            cfunc.save_user_labels()
        try:
            cfunc.refresh_func_ctext()
        except Exception:
            pass


def apply_hexrays_renames():
    if not HAS_HEXRAYS:
        log("Hex-Rays python module not found: skipping decompiler lvar rename pass")
        return
    if not ida_hexrays.init_hexrays_plugin():
        log("Hex-Rays not available: skipping decompiler lvar rename pass")
        return
    for func_ea, mapping in HR_LVAR_RENAMES.items():
        try_hexrays_var_renames(func_ea, mapping)
        log("hexrays lvar rename pass @ %s" % hex(func_ea))


def main():
    log("starting")
    build_enums()
    create_structs()
    apply_function_renames()
    apply_global_renames()
    apply_types()
    apply_frame_var_renames()
    apply_comments()
    bind_operand_enums()
    apply_hexrays_renames()
    log("done")


if __name__ == "__main__":
    main()
