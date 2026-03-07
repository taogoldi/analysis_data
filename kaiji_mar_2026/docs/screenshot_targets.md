# Screenshot Targets For Blog Integration

Use these names so insertion is deterministic.

## Core Evidence (ASM/Hex)

1. `asm_kaiji_b64_c2_xref.png`
- Anchor: file offset `0x11A593`, VA `0x51A593`
- Show: string + xrefs for `YWlyLnhlbS5sYXQ6MjUxOTR8KG9kaykvKi0=`
- Why: proves embedded encoded C2 material.

2. `hex_kaiji_b64_c2_token_0x11A593.png`
- Anchor: file offset `0x11A593`, VA `0x51A593`
- Show: raw bytes + ASCII pane
- Why: low-level confirmation before decode.

3. `asm_kaiji_systemd_path_quotaoff.png`
- Anchor: file offset `0x118FA3`, VA `0x518FA3`
- Show: `/usr/lib/systemd/system/quotaoff.service` with xrefs
- Why: persistence intent.

4. `asm_kaiji_cron_persist_cmd.png`
- Anchor: file offset `0x119F18`, VA `0x519F18`
- Show: `echo "*/1 * * * * root /.mod " >> /etc/crontab` with xrefs
- Why: cron fallback persistence.

5. `asm_kaiji_service_exec_lines.png`
- Anchor: file offset `0x11B6BE`, VA `0x51B6BE`
- Show: `ExecStart=/boot/System.mod`, plus nearby `ExecReload`/`ExecStop`
- Why: service template behavior.

6. `asm_kaiji_systemctl_chain.png`
- Anchor: file offset `0x11B568`, VA `0x51B568`
- Show: `systemctl daemon-reload; ... enable/start quotaoff.service`
- Why: deployment command chain.

7. `asm_kaiji_drop_path_ifconfig_cfg.png`
- Anchor: file offset `0x1154B0`, VA `0x5154B0`
- Show: `/usr/sbin/ifconfig.cfg` with xrefs
- Why: dropped-path indicator.

8. `strings_kaiji_ares_family_cluster.png`
- Anchors:
  - `main.Ares_ipspoof`: offset `0x150936`, VA `0x550936`
  - `main.Ares_Tcp`: offset `0x1509C1`, VA `0x5509C1`
  - `main.Ares_L3_Udp`: offset `0x150BB0`, VA `0x550BB0`
  - `main.Killcpu`: offset `0x150FF5`, VA `0x550FF5`
- Why: family/capability alignment.

9. `strings_kaiji_watchdog_symbol.png`
- Anchor: file offset `0x1514E2`, VA `0x5514E2`
- Show: `main.watchdog`
- Why: resiliency/control-loop signal.

## Decompiler Views (from Xrefs)

10. `c_kaiji_c2_decode_caller.png`
- Pivot: from xref(s) to VA `0x51A593`
- Show: pseudocode for one caller function using the token
- Why: ties static string to logic.

11. `c_kaiji_persist_service_caller.png`
- Pivot: from xref(s) to VA `0x518FA3` or `0x51B6BE`
- Show: pseudocode in the caller where service path/template is used
- Why: demonstrates execution intent.

12. `c_kaiji_cron_caller.png`
- Pivot: from xref(s) to VA `0x519F18`
- Show: pseudocode in the caller for cron command construction/use
- Why: shows behavior beyond string presence.

## Automation Artifacts

13. `ida_kaiji_stage1_annotator_output.png`
- Show IDA Output after `ida_python/kaiji_stage1_annotator.py`

14. `ida_kaiji_pattern_annotator_output.png`
- Show IDA Output after `ida_python/kaiji_pattern_annotator.py`

15. `ida_kaiji_xref_mapper_output.png`
- Show IDA Output after `ida_python/kaiji_xref_callsite_mapper.py`
- Include generated file path line (`*_callsite_map.csv`).

16. `notebook_kaiji_summary_cell.png`
- Show summary dict in `notebooks/kaiji_stage1_analysis.ipynb`
- Include decoded token + C2 candidates + capability buckets.
