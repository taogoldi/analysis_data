"""Rename recovered Go symbols to analyst-friendly aliases when present."""

from __future__ import annotations

import ida_kernwin
import ida_name
import idautils
import idc

RENAME_MAP = {
    "main.Ares_Tcp": "kaiji_attack_tcp",
    "main.Ares_Tcp_Hex": "kaiji_attack_tcp_hex",
    "main.Ares_Tcp_Keep": "kaiji_attack_tcp_keep",
    "main.Ares_L3_Udp": "kaiji_attack_udp",
    "main.Ares_L3_Udp_Hex": "kaiji_attack_udp_hex",
    "main.Ares_ipspoof": "kaiji_attack_ipspoof",
    "main.Killcpu": "kaiji_killcpu",
    "main.watchdog": "kaiji_watchdog",
    "main.Watchdog": "kaiji_watchdog_controller",
}


def try_rename(old_name: str, new_name: str) -> bool:
    ea = ida_name.get_name_ea(idc.BADADDR, old_name)
    if ea == idc.BADADDR:
        return False
    ok = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN)
    if ok:
        idc.set_cmt(ea, f"renamed from {old_name}", 1)
    return bool(ok)


def main():
    ida_kernwin.msg("[kaiji_go_renamer] applying renames...\n")
    applied = 0
    for old, new in RENAME_MAP.items():
        if try_rename(old, new):
            applied += 1
            ida_kernwin.msg(f"[kaiji_go_renamer] {old} -> {new}\n")
    ida_kernwin.msg(f"[kaiji_go_renamer] done. applied {applied} rename(s).\n")


if __name__ == "__main__":
    main()
