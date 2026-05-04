"""
Amadey cred64.dll — IDApython annotation pass.

Run this inside IDA (File -> Script file...) on cred64.dll
(SHA256 3bdcb324...db69, image base 0x180000000).

What it does:
  - renames known data globals (Vigenere key, alphabet, botnet ID,
    runtime std::string holding the key)
  - renames known functions (Main, Save, keystream builder)
  - applies meaningful prototypes so Hex-Rays output reads cleanly
  - renames local variables in functions whose semantics we know
  - adds repeatable comments documenting the Amadey scheme

Idempotent: safe to re-run after extending.

To extend (e.g. once you find the actual Vigenere decode loop or the
HTTP exfil routine), add a block to the FUNCTIONS list and, if you
want local var renames, an entry to RENAME_LOCALS.
"""

import idaapi
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import idc


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _rename(ea, name):
    if not ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE):
        print(f"[!] rename failed at 0x{ea:X} -> {name}")
    else:
        print(f"[+] 0x{ea:X}  {name}")


def _ensure_func(ea):
    if ida_funcs.get_func(ea) is None:
        if not ida_funcs.add_func(ea):
            print(f"[!] could not create function at 0x{ea:X}")


def _set_proto(ea, proto):
    tif = ida_typeinf.tinfo_t()
    # parse_decl wants a trailing semicolon
    if not proto.endswith(";"):
        proto = proto + ";"
    parsed = ida_typeinf.parse_decl(tif, None, proto, ida_typeinf.PT_SIL)
    if parsed is None:
        # Loud failure: this is the bug that made amadey_b64_decode keep
        # showing as a one-arg call -- IDA does not know `std::string`.
        # Use plain `void *` / `void **` in prototypes for max portability.
        raise RuntimeError(
            f"parse_decl failed for prototype at 0x{ea:X}: {proto!r}. "
            f"Most likely an unknown type name (e.g. std::string). "
            f"Use void*/void** instead."
        )
    if not ida_typeinf.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE):
        raise RuntimeError(f"apply_tinfo failed at 0x{ea:X}")


def _cmt(ea, text, repeatable=True):
    idc.set_cmt(ea, text, 1 if repeatable else 0)


def _rename_locals(func_ea, mapping):
    """Decompile func_ea and rename local variables per `mapping`
    (dict of old_name -> new_name)."""
    cfunc = ida_hexrays.decompile(func_ea)
    if cfunc is None:
        print(f"[!] could not decompile 0x{func_ea:X}")
        return
    lvars = cfunc.get_lvars()
    for lv in lvars:
        new = mapping.get(lv.name)
        if new and new != lv.name:
            if ida_hexrays.rename_lvar(func_ea, lv.name, new):
                print(f"    lvar {lv.name} -> {new}")
            else:
                print(f"    [!] lvar rename failed: {lv.name} -> {new}")


# ---------------------------------------------------------------------------
# Known data globals
# ---------------------------------------------------------------------------

DATA = [
    (0x180117318, "g_amadey_vigenere_key_str",
        "Amadey Vigenere string-decryption key (32 ASCII hex). "
        "Same value lives in cred.dll x86 sibling. Per-build/per-operator."),
    (0x180117FA0, "g_amadey_vigenere_alphabet",
        "Amadey Vigenere alphabet (63 chars: a-z A-Z 0-9 SPACE). "
        "SPACE acts as a pass-through during decode."),
    (0x180117364, "g_amadey_botnet_id",
        "Amadey botnet/campaign ID '54e64e'. Triage-classified."),
    (0x18012CD18, "g_amadey_key_stdstr",
        "Runtime MSVC std::string holding a copy of "
        "g_amadey_vigenere_key_str. Layout: "
        "  +0x00 .. +0x0F  SSO buffer (or heap ptr in first 8 bytes)\n"
        "  +0x10           size  (== 32 for this key)\n"
        "  +0x18           capacity"),
    (0x18012D398, "g_amadey_alphabet_stdstr",
        "Runtime MSVC std::string holding a copy of "
        "g_amadey_vigenere_alphabet (the 63-char alphabet). Same layout as "
        "g_amadey_key_stdstr; size == 63 lives at 0x18012D3A8."),
    (0x18012D3A8, "g_amadey_alphabet_size",
        "Size field of g_amadey_alphabet_stdstr (== 63 at runtime). "
        "amadey_vigenere_decode reads this for the modular arithmetic."),
    (0x18010D510, "g_amadey_http_empty_response_str",
        "C string used as the fallback empty response by amadey_http_post "
        "when any of host / path / body inputs is empty."),
]


# ---------------------------------------------------------------------------
# Known functions
# ---------------------------------------------------------------------------

FUNCTIONS = [
    # -- Exports --
    {
        "ea": 0x1800BFDA0,
        "name": "amadey_cred_Main",
        "proto": None,                  # full prototype unknown until reversed further
        "comment":
            "Exported entry called by the parent Amadey loader. Drives the "
            "stealer body: anti-debug, victim SID, Taskkill loop, browser/wallet/"
            "messenger harvest, archive build, and HTTP POST to the C2.",
    },
    {
        "ea": 0x1800056D0,
        "name": "amadey_cred_Save_stub",
        "proto": "void __fastcall amadey_cred_Save_stub();",
        "comment":
            "Exported but stub. Likely a placeholder for a 'save to disk' mode "
            "that was never wired up in this build.",
    },

    # -- Helpers --
    {
        "ea": 0x18008A820,
        "name": "amadey_keystream_build",
        # NB: prototype uses `void **` instead of `std::string *` because IDA's
        # type parser does not know `std::string` and parse_decl fails silently
        # on that name. `void **` matches Hex-Rays' own inference for these
        # MSVC string structs and forces the correct argument count.
        "proto":
            "void **__fastcall amadey_keystream_build("
            "void **out, void **encrypted_in);",
        "comment":
            "Builds a keystream of length encrypted_in.size() by replicating "
            "g_amadey_key_stdstr with modular indexing. The Vigenere decoder "
            "(caller of this function -- xref it!) consumes the resulting "
            "keystream against the ciphertext.",
    },

    {
        "ea": 0x18008A8E0,
        "name": "amadey_vigenere_decode",
        "proto":
            "void **__fastcall amadey_vigenere_decode("
            "void **out, void **ciphertext, void **keystream);",
        "comment":
            "Per-byte Vigenere decode against g_amadey_alphabet_stdstr.\n"
            "  for i in 0..ciphertext.size():\n"
            "    c = ciphertext[i]\n"
            "    if isalnum(c) or c == ' ':\n"
            "      ci = alphabet.find(c)         # -1 if not in alphabet\n"
            "      ki = alphabet.find(keystream[i])\n"
            "      out[i] = alphabet[(alpha_len + ci - ki) % alpha_len]\n"
            "    else:\n"
            "      out[i] = c                    # pass through (e.g. '=' padding)\n"
            "Output is a base64 string that is then base64-decoded by "
            "amadey_b64_decode. The orchestrator wiring all three stages is "
            "amadey_decode_string at 0x18008AAC0.",
    },
    {
        "ea": 0x18008AAC0,
        "name": "amadey_decode_string",
        "proto":
            "void **__fastcall amadey_decode_string("
            "void **out, void **encrypted_in);",
        "comment":
            "Top-level Amadey string-decode orchestrator. Three-stage pipeline:\n"
            "  1. amadey_keystream_build(&keystream, encrypted_in)\n"
            "  2. amadey_vigenere_decode(&b64_str, encrypted_in, &keystream)\n"
            "  3. amadey_b64_decode(out, &b64_str)\n"
            "Then frees the temporaries and resets encrypted_in to an empty "
            "SSO std::string (so it consumes/destroys the input ciphertext).",
    },
    {
        "ea": 0x180089840,
        "name": "amadey_b64_decode",
        "proto":
            "void **__fastcall amadey_b64_decode("
            "void **out, void **b64_in);",
        "comment":
            "Standard base64 decode of b64_in into out. Called as the third "
            "stage of amadey_decode_string after Vigenere-decoding the .rdata "
            "blob. Setting this prototype is what makes amadey_decode_string's "
            "pseudocode reveal the (out, &b64_str) call signature; without it, "
            "Hex-Rays drops the second argument and shows it as one-arg.",
    },
    {
        "ea": 0x1800C1DC0,
        "name": "stdstring_resize",
        "proto": None,
        "comment":
            "MSVC std::basic_string<char>::resize / _Reallocate_grow_by helper. "
            "Called by both decode helpers right after the SSO/heap layout "
            "init (`*a1 = 0; a1[2] = 0; a1[3] = 15;`) to grow the output to "
            "ciphertext_len bytes.",
    },
    {
        "ea": 0x1800C1F30,
        "name": "stdstring_assign_cstr",
        "proto":
            "void **__fastcall stdstring_assign_cstr("
            "void **dst, const char *src, unsigned __int64 src_len);",
        "comment":
            "MSVC std::basic_string<char>::assign(const char*, size_t). Used "
            "by amadey_http_post to load the literal "
            "'Content-Type: application/x-www-form-urlencoded' header into a "
            "std::string. If src_len == 0, behaves as 'assign-from-empty'.",
    },
    {
        "ea": 0x1800C3260,
        "name": "stdstring_grow_for_append",
        "proto": None,
        "comment":
            "Helper that grows a std::string before appending bytes via "
            "memmove. Called by amadey_http_post when the response buffer "
            "is at capacity and InternetReadFile delivered another chunk.",
    },
    # ---- C2 / network ----
    {
        "ea": 0x18008B500,
        "name": "amadey_http_post",
        "proto":
            "void **__fastcall amadey_http_post("
            "void **out_response, void **host, void **path, void **body);",
        "comment":
            "Reusable HTTP POST helper. Inputs are MSVC std::strings:\n"
            "  host  -- e.g. '91.92.242.236'\n"
            "  path  -- e.g. '/oPvjr94jfe/index.php'\n"
            "  body  -- raw bytes to POST (already RC4-encrypted by caller)\n"
            "Behavior:\n"
            "  InternetOpenW(szAgent, PRECONFIG)\n"
            "  InternetConnectA(host, INTERNET_DEFAULT_HTTP_PORT=80, ..., HTTP)\n"
            "  HttpOpenRequestA('POST', path, ...)\n"
            "  HttpSendRequestA(\n"
            "      'Content-Type: application/x-www-form-urlencoded',\n"
            "      headers_len,\n"
            "      body.data(), body.size())\n"
            "  loop InternetReadFile -> append to response std::string\n"
            "  return response in out_response\n"
            "If any input std::string is empty, returns the empty response "
            "loaded from g_amadey_http_empty_response_str.\n"
            "All three input std::strings are CONSUMED (reset to empty SSO).\n"
            "NOTE: This function does NOT do RC4. The body arrives already "
            "encrypted. The RC4 transform site is in the CALLER of this "
            "function (xref it).",
    },
]


# ---------------------------------------------------------------------------
# Local-variable renames keyed by function start EA
# ---------------------------------------------------------------------------

RENAME_LOCALS = {
    # amadey_keystream_build at 0x18008A820 (per the user's pasted decomp)
    0x18008A820: {
        "a1":      "out",
        "a2":      "encrypted_in",
        "Size":    "ciphertext_len",
        "Size_1":  "ciphertext_len_saved",
        "Size_2":  "out_write_idx",
        "v5":      "key_len",
        "v7":      "key_idx_raw",
        "v8":      "key_idx",
        "v9":      "out_buf_ptr",
        "v10":     "key_buf_ptr",
        "v11":     "out_buf_ptr_for_terminator",
    },
    # amadey_http_post at 0x18008B500
    0x18008B500: {
        "a1":               "out_response",
        "lpszServerName_1": "host_stdstr",
        "lpszObjectName_1": "path_stdstr",
        "lpOptional_1":     "body_stdstr",
        "v7":               "out_response_alias",
        # response buffer assembly state
        "p_Src_1":          "response_buf_data",
        "v45":              "response_buf_size_capacity",
        "n15":              "response_buf_capacity_at_loop_top",
        "v9":               "response_buf_size_at_loop_top",
        # Content-Type header std::string
        "lpszHeaders_1":    "headers_stdstr_data",
        "dwHeadersLength":  "headers_len_unused",  # always 0 in this build
        "n15_1":            "headers_capacity",
        "n15_2":            "headers_capacity_saved",
        "v17":              "chunk_len",
        # WinINet handles
        "hInternet_1":      "hInternet_open",
        "hInternet_2":      "hInternet_connect_alias",
        "hInternet_3":      "hInternet_open_for_close",
        "hFile_1":           "hFile_request_alias",
        # body / path / host pointer aliases (Hex-Rays SSO-branch decay)
        "lpszServerName":   "host_cstr_for_connect",
        "lpszObjectName":   "path_cstr_for_request",
        "lpOptional":       "body_cstr_for_send",
        "lpszHeaders":      "headers_cstr_for_send",
        # response-append working pointers
        "p_Src":            "response_buf_data_ptr_for_append",
        "v19":              "response_append_dst",
        "v21":              "response_buf_size_capacity_saved",
        # cleanup pointer aliases for the four std::strings being freed
        "lpszHeaders_2":    "headers_free_target",
        "v24":              "host_free_target",
        "v26":              "path_free_target",
        "v28":              "body_free_target",
        "v31":              "host_free_target_empty_path",
        "v33":              "path_free_target_empty_path",
        "v35":              "body_free_target_empty_path",
        "n0x10":             "host_capacity",
        "n0x10_1":           "path_capacity",
        "n0x10_2":           "body_capacity",
        "n0x10_3":           "host_capacity_empty_path",
        "n0x10_4":           "path_capacity_empty_path",
        "n0x10_5":           "body_capacity_empty_path",
    },
    # amadey_decode_string at 0x18008AAC0 (orchestrator)
    0x18008AAC0: {
        "Src":     "out",
        "a2":      "ciphertext",
        # The b64-intermediate std::string lives at [rbp-58h]; Hex-Rays
        # exposes its first qword (data ptr / SSO start) as v9, and its
        # capacity field as n0x10. After setting amadey_b64_decode's
        # prototype this gets cleaner.
        "v9":      "b64_str_data_ptr",
        "n0x10":   "b64_str_capacity",
        # The keystream std::string lives at [rbp-38h], passed as v11.
        "v11":     "keystream_str",
        "n0x10_1": "keystream_capacity",
        # Cleanup pointer aliases for the three free() branches.
        "v4":      "b64_str_free_target",
        "v5":      "keystream_free_target",
        "v7":      "ciphertext_free_target",
        "n0x10_2": "ciphertext_capacity",
    },
    # amadey_vigenere_decode at 0x18008A8E0
    0x18008A8E0: {
        "a1":      "out",
        "a2":      "ciphertext",
        "a3":      "keystream",
        "Size":    "ciphertext_len",
        "Size_1":  "ciphertext_len_saved",
        "i":       "i",
        # ciphertext data-pointer aliases (Hex-Rays splits it because of the
        # SSO branch repeated inline)
        "v9":      "ciphertext_buf_ptr_1",
        "v11":     "ciphertext_buf_ptr_2",
        "v12":     "ciphertext_buf_ptr_passthrough",
        "v14":     "ciphertext_buf_ptr_for_lookup",
        # alphabet pointer / length / capacity scratch
        "v15":     "alphabet_buf_ptr",
        "v17":     "alphabet_scan_idx_for_ci",
        "v22":     "alphabet_scan_idx_for_ki",
        "n0x10":   "ciphertext_capacity",
        "n0x10_2": "alphabet_capacity",
        # ci / ki, the alphabet indices for ciphertext byte and keystream byte
        "v16":     "ci_alphabet_index",
        "v21":     "ki_alphabet_index",
        "v18":     "ciphertext_byte",
        "v23":     "keystream_byte",
        # output buffer pointer in its various Hex-Rays incarnations
        "v13":     "out_buf_ptr_passthrough",
        "v25":     "out_buf_ptr_for_decoded",
        "v26":     "out_buf_ptr_for_terminator",
        # keystream pointer
        "v19":     "alphabet_buf_ptr_inner_ci",
        "v20":     "keystream_buf_ptr",
        "v24":     "alphabet_buf_ptr_inner_ki",
    },
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run():
    print("=== Amadey cred64.dll annotation pass ===")

    print("\n[*] data globals")
    for ea, name, comment in DATA:
        _rename(ea, name)
        if comment:
            _cmt(ea, comment, repeatable=True)

    print("\n[*] functions")
    for fn in FUNCTIONS:
        ea = fn["ea"]
        _ensure_func(ea)
        _rename(ea, fn["name"])
        if fn.get("proto"):
            _set_proto(ea, fn["proto"])
        if fn.get("comment"):
            _cmt(ea, fn["comment"], repeatable=True)

    print("\n[*] local variable renames (requires Hex-Rays)")
    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays not available; skipping lvar renames")
    else:
        for func_ea, mapping in RENAME_LOCALS.items():
            print(f"  in 0x{func_ea:X}")
            _rename_locals(func_ea, mapping)

    print("\n=== done ===")
    print("Next:")
    print("  1. Xref amadey_http_post (0x18008B500) with Ctrl+X. The CALLER")
    print("     of this function is the actual exfil site -- it builds the")
    print("     RC4-encrypted body std::string and then calls into here.")
    print("     Paste that caller's pseudocode to find the RC4 transform.")
    print("  2. Read g_amadey_http_empty_response_str (0x18010D510) bytes")
    print("     to see what the empty-input fallback returns.")
    print("  3. Xref amadey_decode_string (0x18008AAC0). EVERY decoded config")
    print("     string in this DLL goes through it -- the consumer functions")
    print("     for taskkill, sql query, netsh, C2 IP, etc. show up there.")
    print("  4. Imports view -> CryptUnprotectData -> Ctrl+X for the Chromium")
    print("     credential routine.")


run()
