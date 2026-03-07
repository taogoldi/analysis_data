"""IDA 9.3-compatible annotator for Kaiji-like Go ELF stage1 samples.

What it does:
- Locates high-signal string literals (persistence paths, Base64 C2 token, Ares modules).
- Annotates string EAs and xrefs.
- Renames caller functions when default auto names are still present.
- Adds comments that survive re-analysis.
"""

from __future__ import annotations

import re

import ida_funcs
import ida_kernwin
import ida_name
import idautils
import idc

TARGETS = {
    "/usr/lib/systemd/system/quotaoff.service": "kaiji_persist_systemd",
    "echo \"*/1 * * * * root /.mod \" >> /etc/crontab": "kaiji_persist_cron",
    "/usr/sbin/ifconfig.cfg": "kaiji_dropper_path_cfg",
    "/boot/System.mod": "kaiji_dropper_system_mod",
    "YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=": "kaiji_embedded_b64_c2",
    "main.Ares_Tcp": "kaiji_attack_ares_tcp",
    "main.Ares_L3_Udp": "kaiji_attack_ares_udp",
    "main.Ares_ipspoof": "kaiji_attack_ares_ipspoof",
    "main.Killcpu": "kaiji_attack_killcpu",
}


def is_default_func_name(name: str) -> bool:
    return bool(re.match(r"^(sub|loc|nullsub|j_)[0-9A-Fa-f_]+$", name))


def unique_name(base: str) -> str:
    if ida_name.get_name_ea(idc.BADADDR, base) == idc.BADADDR:
        return base
    i = 1
    while True:
        cand = f"{base}_{i}"
        if ida_name.get_name_ea(idc.BADADDR, cand) == idc.BADADDR:
            return cand
        i += 1


def all_strings():
    s = idautils.Strings()
    s.setup()
    for item in s:
        yield int(item.ea), str(item)


def set_comment(ea: int, text: str):
    old = idc.get_cmt(ea, 1) or ""
    if text in old:
        return
    if old:
        text = old + " | " + text
    idc.set_cmt(ea, text, 1)


def annotate_target(text: str, alias: str):
    hit_count = 0
    for sea, sval in all_strings():
        if text not in sval:
            continue

        hit_count += 1
        set_comment(sea, f"Kaiji indicator: {alias}")

        # Name the string object if it is currently anonymous.
        cur_name = ida_name.get_name(sea)
        if not cur_name:
            ida_name.set_name(sea, unique_name("g_" + alias), ida_name.SN_NOWARN)

        # Annotate and optionally rename callers.
        for xr in idautils.XrefsTo(sea):
            frm = int(xr.frm)
            set_comment(frm, f"uses indicator string: {text[:80]}")

            f = ida_funcs.get_func(frm)
            if not f:
                continue
            f_name = ida_name.get_name(f.start_ea)
            if is_default_func_name(f_name):
                ida_name.set_name(f.start_ea, unique_name(alias), ida_name.SN_NOWARN)

    return hit_count


def main():
    ida_kernwin.msg("[kaiji_annotator] starting...\n")
    total = 0
    for text, alias in TARGETS.items():
        n = annotate_target(text, alias)
        total += n
        if n:
            ida_kernwin.msg(f"[kaiji_annotator] {alias}: {n} hit(s)\n")

    ida_kernwin.msg(f"[kaiji_annotator] done. total string-hit groups: {total}\n")


if __name__ == "__main__":
    main()
