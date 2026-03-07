"""Export indicator-string xref callsites into CSV/JSON for Kaiji triage.

IDA 9.3 compatible.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import ida_funcs
import ida_kernwin
import ida_nalt
import ida_name
import idautils
import idc

TARGETS = {
    "YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=": "embedded_b64_c2",
    "/usr/lib/systemd/system/quotaoff.service": "persist_systemd_unit_path",
    "echo \"*/1 * * * * root /.mod \" >> /etc/crontab": "persist_cron_line",
    "systemctl daemon-reload": "persist_systemctl_chain",
    "ExecStart=/boot/System.mod": "persist_service_execstart",
    "ExecReload=/boot/System.mod": "persist_service_execreload",
    "ExecStop=/boot/System.mod": "persist_service_execstop",
    "/usr/sbin/ifconfig.cfg": "drop_path_cfg",
    "main.Ares_Tcp": "symbol_ares_tcp",
    "main.Ares_L3_Udp": "symbol_ares_l3_udp",
    "main.Ares_ipspoof": "symbol_ares_ipspoof",
    "main.Killcpu": "symbol_killcpu",
    "main.watchdog": "symbol_watchdog",
}


def all_strings():
    s = idautils.Strings()
    s.setup()
    for item in s:
        yield int(item.ea), str(item)


def get_out_paths() -> tuple[Path, Path]:
    idb_path = Path(idc.get_idb_path()) if idc.get_idb_path() else None
    input_name = ida_nalt.get_root_filename() or "kaiji_sample"

    if idb_path:
        out_dir = idb_path.parent
    else:
        out_dir = Path.cwd()

    csv_path = out_dir / f"{input_name}_callsite_map.csv"
    json_path = out_dir / f"{input_name}_callsite_map.json"
    return csv_path, json_path


def collect_rows():
    rows = []
    for sea, sval in all_strings():
        for needle, tag in TARGETS.items():
            if needle not in sval:
                continue

            for xr in idautils.XrefsTo(sea):
                frm = int(xr.frm)
                f = ida_funcs.get_func(frm)
                fstart = int(f.start_ea) if f else idc.BADADDR
                fname = ida_name.get_name(fstart) if f else ""

                row = {
                    "tag": tag,
                    "needle": needle,
                    "string_ea": f"0x{sea:x}",
                    "xref_ea": f"0x{frm:x}",
                    "function_start_ea": f"0x{fstart:x}" if fstart != idc.BADADDR else "",
                    "function_name": fname,
                    "disasm": idc.generate_disasm_line(frm, 0) or "",
                }
                rows.append(row)
                idc.set_cmt(frm, f"kaiji_callsite::{tag}", 1)

    # Deduplicate while preserving order.
    seen = set()
    uniq = []
    for r in rows:
        key = (r["tag"], r["string_ea"], r["xref_ea"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    return uniq


def write_outputs(rows):
    csv_path, json_path = get_out_paths()
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "tag",
                "needle",
                "string_ea",
                "xref_ea",
                "function_start_ea",
                "function_name",
                "disasm",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    json_path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return csv_path, json_path


def main():
    ida_kernwin.msg("[kaiji_callsite_mapper] collecting xref callsites...\n")
    rows = collect_rows()
    csv_path, json_path = write_outputs(rows)
    ida_kernwin.msg(f"[kaiji_callsite_mapper] rows={len(rows)}\n")
    ida_kernwin.msg(f"[kaiji_callsite_mapper] csv={csv_path}\n")
    ida_kernwin.msg(f"[kaiji_callsite_mapper] json={json_path}\n")


if __name__ == "__main__":
    main()
