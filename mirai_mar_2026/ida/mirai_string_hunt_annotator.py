"""
IDA 9.x helper for Mirai-like string/xref hunting.

This script tags high-signal strings and annotates all xrefs for rapid triage.
"""

import ida_bytes
import ida_kernwin
import idautils
import idc


TARGET_STRINGS = [
    "144.172.108.230",
    "!SIGKILL",
    "1337SoraLOADER",
    "M-SEARCH * HTTP/1.1",
    "Via: SIP/2.0/UDP 192.168.1.1:5060",
    "/proc/%s/cmdline",
    "/proc/%s/maps",
    "/bin/busybox",
    "disable_infection_tools",
    "scan_and_kill",
    "watchdog_maintain",
    "watchdog_pid",
    "udpfl00d",
    "tcpFl00d",
    "ovhudpflood",
    "TSource Engine Query",
    "KHserverHACKER",
    "/etc/config/resolv.conf",
    "__dns_lookup",
]


def log(msg):
    print(f"[mirai_hunt] {msg}")


def find_string_ea(needle):
    for s in idautils.Strings():
        try:
            val = str(s)
        except Exception:
            continue
        if val == needle:
            return int(s.ea)
    return idc.BADADDR


def annotate_string(needle):
    ea = find_string_ea(needle)
    if ea == idc.BADADDR:
        log(f"missing string: {needle!r}")
        return 0

    ida_bytes.create_strlit(ea, 0, idc.STRTYPE_C)
    hit_count = 0
    for x in idautils.XrefsTo(ea):
        hit_count += 1
        idc.set_cmt(x.frm, f"String ref: {needle}", 1)
    log(f"{needle!r} at 0x{ea:x}, xrefs={hit_count}")
    return hit_count


def main():
    total = 0
    for needle in TARGET_STRINGS:
        total += annotate_string(needle)
    ida_kernwin.refresh_idaview_anyway()
    log(f"done, total xrefs tagged: {total}")


if __name__ == "__main__":
    main()
