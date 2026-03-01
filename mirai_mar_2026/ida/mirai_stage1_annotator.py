"""
IDA 9.x-compatible Stage1 annotator for d40cf9...c28 Mirai-like ELF.

Usage:
  File -> Script file... -> mirai_stage1_annotator.py
"""

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import idautils
import idc


KEY_FUNCTIONS = {
    0x4001C0: "verify_server_ip",
    0x400260: "force_sigkill",
    0x4002A0: "stage1_main_loop",
    0x400730: "killer_thread_func",
    0x400940: "daemonize_process",
    0x400A10: "disable_infection_tools",
    0x400D60: "scan_and_kill_tools",
    0x400F60: "method_udpburst",
    0x4010A0: "method_raknet",
    0x401190: "method_junk",
    0x401280: "method_udpslam",
    0x401380: "method_udp",
    0x4026D0: "method_ack",
    0x4027B0: "method_syn",
}


DATA_SYMBOLS = {
    0x41498A: "g_authorized_server_ip",
    0x4149C6: "g_cmd_sigkill",
    0x4149E7: "g_method_udp",
    0x4149EB: "g_method_syn",
    0x4149EF: "g_method_ack",
    0x4149F3: "g_method_udpslam",
    0x4149FB: "g_method_junk",
    0x414A00: "g_method_raknet",
    0x414A07: "g_method_udpburst",
    0x414A28: "g_cmd_hello",
}


FUNC_COMMENTS = {
    0x4001C0: "Validates connected peer IP against hardcoded authorized server IP string.",
    0x400260: "Emergency termination path used on !SIGKILL command.",
    0x4002A0: "Primary bot loop: connect -> verify IP -> parse commands -> dispatch attack methods.",
    0x400730: "Background killer thread; repeatedly disables infection tools and kills competing processes.",
    0x400A10: "Disables/removes known downloader binaries and hardens busybox path.",
    0x400D60: "Scans /proc and terminates processes matching competitor/infection-tool markers.",
}


INSN_COMMENTS = {
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


def rename_ea(ea, new_name):
    if ea == idc.BADADDR:
        return False
    flags = ida_name.SN_NOWARN | ida_name.SN_FORCE
    ok = ida_name.set_name(ea, new_name, flags)
    if ok:
        log(f"renamed 0x{ea:x} -> {new_name}")
    return bool(ok)


def ensure_function(ea):
    if ida_funcs.get_func(ea):
        return
    ida_funcs.add_func(ea)


def apply_function_annotations():
    for ea, name in KEY_FUNCTIONS.items():
        ensure_function(ea)
        rename_ea(ea, name)
        cmt = FUNC_COMMENTS.get(ea)
        if cmt:
            idc.set_func_cmt(ea, cmt, 1)


def apply_data_annotations():
    for ea, name in DATA_SYMBOLS.items():
        rename_ea(ea, name)
        ida_bytes.create_strlit(ea, 0, idc.STRTYPE_C)


def apply_instruction_comments():
    for ea, cmt in INSN_COMMENTS.items():
        idc.set_cmt(ea, cmt, 1)


def annotate_xrefs_to_authorized_ip():
    target = DATA_SYMBOLS[0x41498A]
    ea = idc.get_name_ea_simple(target)
    if ea == idc.BADADDR:
        return
    for x in idautils.XrefsTo(ea):
        idc.set_cmt(x.frm, "Uses hardcoded authorized server IP", 1)


def main():
    apply_function_annotations()
    apply_data_annotations()
    apply_instruction_comments()
    annotate_xrefs_to_authorized_ip()
    ida_kernwin.refresh_idaview_anyway()
    log("stage1 annotation complete")


if __name__ == "__main__":
    main()

