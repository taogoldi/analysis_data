"""Address-agnostic byte-pattern annotator for Kaiji-like Go ELF samples.

This script searches raw segment bytes for fixed ASCII signatures and then
annotates both hit locations and xref sites. It does not rely on hard-coded EAs.
"""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_segment
import idautils
import idc

PATTERNS = [
    (b"YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=", "embedded_base64_c2"),
    (b"/usr/lib/systemd/system/quotaoff.service", "persist_systemd_path"),
    (b"echo \"*/1 * * * * root /.mod \" >> /etc/crontab", "persist_cron_cmd"),
    (b"ExecStart=/boot/System.mod", "service_execstart"),
    (b"main.Ares_Tcp", "ares_tcp_symbol"),
    (b"main.Ares_L3_Udp", "ares_udp_symbol"),
    (b"main.Ares_ipspoof", "ares_spoof_symbol"),
    (b"main.Killcpu", "killcpu_symbol"),
]


def seg_ranges():
    # IDA API behavior can vary by version/build; idautils.Segments() yields start EAs reliably.
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if seg:
            yield int(seg.start_ea), int(seg.end_ea)


def find_bytes(pattern: bytes):
    hits = []
    for start, end in seg_ranges():
        blob = ida_bytes.get_bytes(start, end - start)
        if not blob:
            continue
        idx = 0
        while True:
            pos = blob.find(pattern, idx)
            if pos == -1:
                break
            hits.append(start + pos)
            idx = pos + 1
    return hits


def set_rep_comment(ea: int, text: str):
    old = idc.get_cmt(ea, 1) or ""
    if text in old:
        return
    if old:
        text = old + " | " + text
    idc.set_cmt(ea, text, 1)


def maybe_name_data(ea: int, alias: str):
    cur = ida_name.get_name(ea)
    if cur:
        return
    ida_name.set_name(ea, f"g_{alias}_{ea:x}", ida_name.SN_NOWARN)


def annotate_hit(ea: int, alias: str):
    set_rep_comment(ea, f"Kaiji pattern hit: {alias}")
    maybe_name_data(ea, alias)

    for xr in idautils.XrefsTo(ea):
        frm = int(xr.frm)
        set_rep_comment(frm, f"xref -> pattern {alias}")
        f = ida_funcs.get_func(frm)
        if not f:
            continue
        fname = ida_name.get_name(f.start_ea)
        if fname.startswith("sub_"):
            ida_name.set_name(f.start_ea, f"kaiji_{alias}_{f.start_ea:x}", ida_name.SN_NOWARN)


def main():
    ida_kernwin.msg("[kaiji_pattern] starting byte-pattern scan...\n")
    total = 0

    for patt, alias in PATTERNS:
        hits = find_bytes(patt)
        ida_kernwin.msg(f"[kaiji_pattern] {alias}: {len(hits)} hit(s)\n")
        for ea in hits:
            annotate_hit(ea, alias)
            total += 1

    ida_kernwin.msg(f"[kaiji_pattern] completed. total hits annotated: {total}\n")


if __name__ == "__main__":
    main()
