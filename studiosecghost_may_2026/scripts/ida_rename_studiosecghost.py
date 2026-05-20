"""
IDApython annotation script for the StudioSecGhost hVNC agent.
Sample SHA256: 5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852
Author: taogoldi  (2026-05-19)  TLP: TLP:CLEAR

The script is idempotent: re-run it after reversing each new function. It
locates known anchor strings (which this build leaves in plaintext), renames
the function that references each one, and adds a repeatable comment.

Run inside IDA's Python prompt:
    exec(open(r"scripts/ida_rename_studiosecghost.py").read())
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name

# ---------------------------------------------------------------------------
# Anchor strings: literal -> (function name, repeatable comment)
# Each tuple identifies a function uniquely via a one-of-a-kind plaintext
# string referenced by exactly one routine.
# ---------------------------------------------------------------------------
ANCHORS = [
    ("[INIT] Agent running. All subsystems active.",
     "agent_main",
     "Top-level orchestrator. Spawns lifecycle threads after subsystem init."),

    ("[INIT] NetInit (WSAStartup) failed. Aborting.",
     "agent_net_init",
     "Calls WSAStartup; aborts the agent if it fails."),

    ("[INIT] GDI+ initialised.",
     "agent_gdiplus_init",
     "GdiplusStartup wrapper; required before WindowCapturer can encode JPEG."),

    ("[INIT] Anchor window created: HWND=%p",
     "agent_create_anchor_window",
     "Creates the hidden anchor window (class GSystem / .SecAnchor) used as "
     "the command message pump."),

    ("[INIT] Replica deployed: slot %d",
     "agent_deploy_replica",
     "Copies the current image into a numbered replica slot under %TEMP%/% "
     "APPDATA% and registers a scheduled task that points at it."),

    ("[INIT] Watchdog restored replica slot %d",
     "agent_watchdog_restore",
     "Background watchdog: if any replica slot or its scheduled task is "
     "deleted, redeploys both. Forces Count=999 restart-on-failure."),

    ("[INIT] Watchdog thread started.",
     "agent_watchdog_thread",
     "Entry point of the watchdog thread."),

    ("[INIT] Banner thread launched.",
     "agent_banner_thread",
     "Creates the StudioSecVNC_Banner layered window with the "
     "'SECURITY AUDIT IN PROGRESS' message."),

    ("[INIT] Self-delete scheduled. Exiting.",
     "agent_self_delete",
     "Drops ssv_cleanup.bat to %TEMP% and launches it via cmd.exe /C."),

    ("[CHROME] Lifecycle manager started.",
     "chrome_lifecycle_manager",
     "Per-browser lifecycle loop: detect installed browser, write bounce "
     "HTML, launch the browser, search for the StudioSecGhost window, "
     "cloak it, hand the HWND to the streaming subsystem."),

    ("[CHROME] Firefox prefs.js patched: crash recovery disabled.",
     "chrome_patch_firefox_prefs",
     "Opens profiles.ini, locates the default profile, appends "
     "user_pref('browser.sessionstore.resume_from_crash', false) to "
     "prefs.js."),

    ("[CHROME] Failed to create bounce HTML.",
     "chrome_write_bounce_html",
     "Renders the bounce HTML template (title = StudioSecGhost) into "
     "%TEMP%/studiosec_bounce.html or chrome_update_manifest.html."),

    ("[CHROME] Found ghost among hidden windows: HWND=%p",
     "chrome_acquire_ghost",
     "EnumWindows + GetWindowTextW pass that finds the bounce-HTML window "
     "by its title and cloaks it with ShowWindow(SW_HIDE) and "
     "SetWindowPos."),

    ("[CHROME] Chrome IPC sent (PID %lu). Interceptor active...",
     "chrome_ipc_intercept",
     "Sends an IPC message to the parent Chrome process so subsequent "
     "ghost-window creation events surface to the agent's interceptor."),

    ("[CHROME] Switching browser: %ls -> %ls",
     "chrome_switch_browser",
     "Hot-swap from one targeted browser to another on operator command."),

    ("[VNC] StreamThread started (%dx%d)%s.",
     "vnc_stream_thread",
     "Frame producer: WindowCapturer -> GDI+ -> JPEG -> NET send loop. "
     "Honours operator quality preset."),

    ("[VNC] WindowCapturer: init OK (%dx%d), HWND=%p.",
     "vnc_window_capturer_init",
     "GetDC + CreateCompatibleDC + CreateCompatibleBitmap on the ghost "
     "HWND. Falls back to GetDesktopWindow if no ghost is available."),

    ("[NET] AgentNetwork started. Target: %ls:%u",
     "net_agent_start",
     "Net thread entry: parses C2 host:port, connects, runs the command "
     "loop, reconnects on failure with backoff."),

    ("[NET] Handshake complete.",
     "net_handshake",
     "Sends handshake, awaits ACK, sends AUTH_LOGIN with operator tag + "
     "browser inventory."),

    ("[NET] CMD_UPLOAD_EXECUTE: %ls (%u bytes)",
     "net_cmd_upload_execute",
     "Receives a filename + raw bytes, drops to disk, CreateProcessW, "
     "waits, returns exit code in the reply packet."),

    ("[NET] Screenshot sent: %dx%d, %u bytes JPEG.",
     "net_send_screenshot",
     "Wraps a JPEG blob in a length-prefixed packet and sends it to the C2."),

    ("[NET] AUTH_LOGIN sent: '%ls' (browsers: %d, active: %d)",
     "net_auth_login",
     "Builds and sends the AUTH_LOGIN packet: operator tag (UTF-16LE), "
     "browser count, active browser index."),

    ("[NET] Reconnecting in %d s...",
     "net_reconnect_backoff",
     "Reconnect-with-backoff loop: sleeps then retries the full "
     "connect -> handshake -> auth sequence."),

    ("[NET] CMD_RE_DETECT_BROWSERS received.",
     "net_cmd_redetect_browsers",
     "Handles CMD_RE_DETECT_BROWSERS: re-runs browser detection and "
     "sends BROWSERS_UPDATED."),

    ("[NET] CMD_UNINSTALL received.",
     "net_cmd_uninstall",
     "Dispatches the uninstall sequence: schtasks /Delete, drops "
     "ssv_cleanup.bat, closes ghost + anchor, self-deletes."),

    ("[NET] Oversized packet dropped (%u bytes).",
     "net_packet_guard",
     "Sanity-checks inbound packet length before allocating a receive "
     "buffer; drops packets exceeding the hard limit."),

    # -----------------------------------------------------------------------
    # TBD / suspected -- strings that point at routines not yet fully named;
    # comment these out until the function is confirmed in IDA.
    # -----------------------------------------------------------------------
    # ("[INIT] Agent already running. Exiting.",
    #  "agent_single_instance_check",
    #  "CreateMutexW guard; also runs the anti-analysis process blocklist scan."),
    #
    # ("[INIT] OS: %ls %ls | CPU: %ls",
    #  "agent_collect_sysinfo",
    #  "Reads ProductName, DisplayVersion (HKLM\\CurrentVersion) and "
    #  "ProcessorNameString; bundles them into a SYSTEM_INFO packet."),
]

# ---------------------------------------------------------------------------
# Implementation
# ---------------------------------------------------------------------------

def _find_string_ea(literal: str) -> int:
    """Return the EA of *literal* (ASCII) in the binary, or idc.BADADDR."""
    encoded = literal.encode("utf-8")
    # NOTE: find_bytes positional args are (bs, range_start, range_end, mask=None,
    # flags=BIN_SEARCH_FORWARD). Pass flags by keyword so it is not confused
    # with the mask parameter.
    return ida_bytes.find_bytes(
        encoded,
        range_start=0,
        range_end=idc.BADADDR,
        flags=ida_bytes.BIN_SEARCH_FORWARD,
    )


def rename_from_anchors() -> None:
    renamed = 0
    skipped = 0
    not_found = 0

    for anchor_str, func_name, comment in ANCHORS:
        str_ea = _find_string_ea(anchor_str)
        if str_ea == idc.BADADDR:
            print(f"[SKIP] String not found: {anchor_str!r}")
            not_found += 1
            continue

        # Collect all cross-references to this string address.
        xrefs = list(idautils.DataRefsTo(str_ea))
        if not xrefs:
            print(f"[SKIP] No xrefs to string at {str_ea:#x}: {anchor_str!r}")
            skipped += 1
            continue

        func_eas = set()
        for xref_ea in xrefs:
            fn = ida_funcs.get_func(xref_ea)
            if fn:
                func_eas.add(fn.start_ea)

        if len(func_eas) != 1:
            print(f"[WARN] {len(func_eas)} functions ref string {anchor_str!r} "
                  f"-- skipping to avoid misname")
            skipped += 1
            continue

        func_ea = next(iter(func_eas))
        current_name = idc.get_func_name(func_ea)

        # Skip if already correctly named (idempotent).
        if current_name == func_name:
            skipped += 1
            continue

        ok = ida_name.set_name(func_ea, func_name,
                               ida_name.SN_FORCE | ida_name.SN_NOCHECK)
        if ok:
            idc.set_func_cmt(func_ea, comment, 1)  # 1 = repeatable
            print(f"[OK]   {current_name} -> {func_name}  ({func_ea:#x})")
            renamed += 1
        else:
            print(f"[FAIL] set_name failed for {func_name} at {func_ea:#x}")
            skipped += 1

    print(f"\n=== StudioSecGhost rename pass done: "
          f"{renamed} renamed, {skipped} skipped, {not_found} not found ===")


if __name__ == "__main__":
    # Running as a script inside the IDA interpreter.
    idaapi.auto_wait()
    rename_from_anchors()
