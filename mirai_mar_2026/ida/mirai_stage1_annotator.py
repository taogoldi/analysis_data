"""
IDA 9.x variant-aware Stage1 annotator for Mirai-like ELF samples.

Usage:
  File -> Script file... -> mirai_stage1_annotator.py
"""

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import idautils
import idc


STRING_SYMBOLS = {
    "144.172.108.230": "g_authorized_server_ip",
    "!SIGKILL": "g_cmd_sigkill",
    "M-SEARCH * HTTP/1.1": "g_msearch_payload",
    "Via: SIP/2.0/UDP 192.168.1.1:5060": "g_sip_payload",
    "udpburst": "g_method_udpburst",
    "udpslam": "g_method_udpslam",
    "raknet": "g_method_raknet",
    "udpfl00d": "g_method_udpfl00d",
    "tcpFl00d": "g_method_tcpfl00d",
    "ovhudpflood": "g_method_ovhudpflood",
    "watchdog_maintain": "g_watchdog_maintain",
    "KHserverHACKER": "g_variant_tag_khserverhacker",
}

FUNCTION_RENAMES = {
    "main": "stage1_main_loop",
    "verify_server_ip": "verify_server_ip",
    "force_sigkill": "force_sigkill",
    "killer_thread_func": "killer_thread_func",
    "disable_infection_tools": "disable_infection_tools",
    "scan_and_kill": "scan_and_kill_tools",
    "__dns_lookup": "dns_lookup_with_resolver",
}

FALLBACK_SAMPLE_SPECIFIC = {
    0x4001C0: "verify_server_ip",
    0x400260: "force_sigkill",
    0x4002A0: "stage1_main_loop",
    0x400730: "killer_thread_func",
}

SAMPLE_SPECIFIC_COMMENTS = {
    0x40031F: "inet_pton() writes authorized C2 target IP into sockaddr_in",
    0x40033F: "Post-connect peer verification gate",
    0x400412: "Command prefix check for !SIGKILL path",
    0x4004F1: "Dispatch: udp",
    0x40052E: "Dispatch: syn",
    0x4005B3: "Dispatch: ack",
    0x400667: "Dispatch: udpslam",
    0x4006C6: "Dispatch: junk",
    0x40063E: "Dispatch: raknet",
    0x400703: "Dispatch: udpburst",
}


def log(msg):
    print(f"[mirai_annotator] {msg}")


def set_name(ea, name):
    if ea == idc.BADADDR:
        return False
    ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
    if ok:
        log(f"renamed 0x{ea:x} -> {name}")
    return bool(ok)


def find_string_ea(needle):
    for s in idautils.Strings():
        try:
            if str(s) == needle:
                return int(s.ea)
        except Exception:
            continue
    return idc.BADADDR


def rename_known_functions():
    # Name-based renames (portable across variants if symbols exist).
    for old_name, new_name in FUNCTION_RENAMES.items():
        ea = idc.get_name_ea_simple(old_name)
        if ea != idc.BADADDR:
            set_name(ea, new_name)

    # Conservative fallback only when a function actually exists at that address.
    for ea, new_name in FALLBACK_SAMPLE_SPECIFIC.items():
        if ida_funcs.get_func(ea):
            set_name(ea, new_name)


def rename_and_annotate_strings():
    hits = 0
    for needle, sym_name in STRING_SYMBOLS.items():
        ea = find_string_ea(needle)
        if ea == idc.BADADDR:
            continue
        ida_bytes.create_strlit(ea, 0, idc.STRTYPE_C)
        set_name(ea, sym_name)
        xrefs = 0
        for x in idautils.XrefsTo(ea):
            xrefs += 1
            idc.set_cmt(x.frm, f"String ref: {needle}", 1)
        log(f"string {needle!r} @ 0x{ea:x}, xrefs={xrefs}")
        hits += 1
    log(f"strings annotated: {hits}")


def maybe_apply_sample_specific_comments():
    # Gate old fixed comments behind known old marker strings.
    if find_string_ea("!SIGKILL") == idc.BADADDR or find_string_ea("udpburst") == idc.BADADDR:
        return
    for ea, cmt in SAMPLE_SPECIFIC_COMMENTS.items():
        if ida_funcs.get_func(ea):
            idc.set_cmt(ea, cmt, 1)
    log("applied sample-specific dispatch comments where valid")


def main():
    rename_known_functions()
    rename_and_annotate_strings()
    maybe_apply_sample_specific_comments()
    ida_kernwin.refresh_idaview_anyway()
    log("stage1 annotation complete")


if __name__ == "__main__":
    main()
