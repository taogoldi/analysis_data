"""
poolparty_rename_sample_b.py, IDAPython annotation script for Sample B
(SHA-256 4cfc8ee7f76a8c7aca96fa783a8d90e915fc1f720062a8241f0c2a0247a382c5).

Compatible with IDA 8.x and IDA 9.x (uses ida_typeinf, not the legacy
ida_struct module that was removed in 9.0).

Run inside IDA on the open Sample B database:
  File -> Script File... -> select this file
  (or  Alt-F7 then choose this file)

Idempotent: safe to re-run after manual edits, it will not clobber names
that have already been changed away from IDA defaults like sub_*.

What this script does:
  1. Defines two C structs (InjectionCtx, TP_DIRECT_FORGED) via
     parse_decls so they're visible in the Local Types view and
     usable as variable types in the decompiler.
  2. Renames boost::log helper subroutines (using the verbose log-message
     strings the binary still carries, they are documentary).
  3. Renames variant-implementation entry points (TP_DIRECT, TP_WORK,
     TP_ALPC, TP_JOB, TP_TIMER).
  4. Renames the WinAPI status-check helpers.
  5. Sets a clean prototype on RemoteTpDirectInsertion so subsequent
     F5 decompiles use named struct field references.

Read the printed summary at the end of the IDA Output window to see what
got renamed (or skipped because it had already been renamed manually).
"""

import idaapi
import idc
import ida_funcs
import ida_name
import ida_typeinf


# ---------------------------------------------------------------------------
# Address book, must match Sample B (SHA-256 4cfc8ee7…)
# ---------------------------------------------------------------------------

VARIANT_FUNCS = {
    0x14001B630: ("RemoteTpDirectInsertion",
                  "Variant 7 (TP_DIRECT). Allocates remote memory, writes a forged "
                  "_TP_DIRECT struct, then NtSetIoCompletion against the target's "
                  "IoCompletionPortHandle with CompletionKey = remote struct ptr."),
    0x14001625C: ("RemoteTpWorkInsertion",
                  "Variant 1 (TP_WORK). CreateThreadpoolWork-based insertion."),
    0x1400191F3: ("RemoteTpAlpcInsertion",
                  "Variant 6 (TP_ALPC). TpAllocAlpcCompletion + ALPC port pivot."),
    0x14001A603: ("RemoteTpJobInsertion",
                  "Variant 8 (TP_JOB). TpAllocJobNotification + AssignProcessToJobObject."),
    0x14001C7B5: ("RemoteTpTimerInsertion",
                  "Variant 2 (TP_TIMER). NtSetTimer2 cross-process expiration trigger."),
}

HELPER_FUNCS = {
    0x140014480: ("check_winapi_bool",
                  "Throws std::runtime_error on FALSE return. Args: "
                  "(string& apiName, BOOL retval)."),
    0x1400141D0: ("check_winapi_ntstatus",
                  "Throws std::runtime_error on !NT_SUCCESS. Args: "
                  "(string& apiName, NTSTATUS status)."),
    0x140013410: ("format_winapi_error",
                  "Formats a Win32 error from GetLastError() into a string."),
}

LOG_FUNCS = {
    0x14004C9C0: ("boost_log_get_record",
                  "boost::log severity-aware get-record helper."),
    0x1400507C0: ("boost_log_filter_pass",
                  "Returns whether the current severity level passes the filter."),
    0x14004D760: ("boost_log_open_record",
                  "Opens a log record and returns a writable severity slot pointer."),
    0x1400509E0: ("boost_log_acquire_record",
                  "Acquires a record under the SRWLock, populates 'Block' out-param."),
    0x140050A00: ("boost_log_emit",
                  "Pushes a populated record into the sink chain."),
    0x140050510: ("boost_log_release_record",
                  "Releases the record after emit."),
    0x140047810: ("boost_log_make_compound",
                  "boost::log::aux::stream_provider<char>::allocate_compound."),
    0x1400079E0: ("boost_log_flush_stream",
                  "Flushes the compound stream into the record buffer."),
    0x140007690: ("boost_log_write_str",
                  "Writes a (const char*, size_t) string literal into the compound. "
                  "Args 2+3 carry the documentary log message text."),
    0x14000A070: ("boost_log_init_altstringbuf",
                  "boost::io::basic_altstringbuf<char>::ctor for format args."),
    0x14000A100: ("boost_log_format_into",
                  "Routes a std::string through the boost::format pipeline."),
    0x14000C100: ("boost_log_apply_arg",
                  "Applies a format argument (the %p substitution) into the buffer."),
    0x14001D9F0: ("boost_log_record_pump",
                  "guard_check_icall_nop callback target, log record pump."),
    0x14001D810: ("boost_log_feed_record",
                  "Feeds a formatted record into the boost::log compound."),
    0x140005F80: ("boost_log_destroy_buf",
                  "Destructor for the basic_altstringbuf format buffer."),
}


# ---------------------------------------------------------------------------
# C declarations for the structs we want to add to Local Types
# ---------------------------------------------------------------------------

STRUCT_DECLS = """
struct InjectionCtx {
    __int64 pad_00;
    __int64 pad_08;
    __int64 ppTargetProcessHandle;   // **HANDLE for OpenProcess result
    __int64 pad_18;
    __int64 pad_20;
    __int64 pad_28;
    __int64 targetCookieOrPid;       // loaded into v111 high qword
    __int64 ppIoCompletionPortHandle;// **HANDLE for the duplicated IoCompletion
};

struct TP_DIRECT_FORGED {
    void *CleanupGroupMember;        // _TP_CLEANUP_GROUP_MEMBER fwd-link
    void *Pool;                      // *_TP_POOL, read out of target
    void *Callback;                  // shellcode entrypoint
    void *Context;                   // passed to Callback
    void *CleanupGroup;
    void *FinalizationCallback;
    void *RaceDll;
    void *ActivationContext;
    int   CallbackPriority;
    int   CallbackFlags;
};
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_default_name(ea):
    """True if the current name at ea is still IDA's auto-generated one."""
    name = idc.get_name(ea, ida_name.GN_VISIBLE) or ""
    return (
        not name
        or name.startswith("sub_")
        or name.startswith("loc_")
        or name.startswith("off_")
        or name.startswith("nullsub_")
        or name.startswith("j_")
    )


def _rename(ea, new_name, comment=None):
    """Rename ea iff it currently has a default name."""
    if not _has_default_name(ea):
        old = idc.get_name(ea, ida_name.GN_VISIBLE)
        print(f"  [skip] 0x{ea:x}  already named: {old}")
        return False
    if not idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_NOCHECK):
        print(f"  [FAIL] 0x{ea:x} -> {new_name}")
        return False
    if comment:
        idc.set_func_cmt(ea, comment, 1)
    print(f"  [ok ]  0x{ea:x} -> {new_name}")
    return True


def _add_local_types(decls):
    """Parse a C declaration block and add the resulting types to the
    binary's Local Types collection (visible in View -> Open subviews
    -> Local Types). Works on IDA 8.x and 9.x."""
    # parse_decls returns the number of errors (0 = success).
    # The HTI_DCL flag tells the parser these are top-level declarations.
    errors = ida_typeinf.parse_decls(None, decls, None,
                                     ida_typeinf.HTI_DCL)
    if errors:
        print(f"  [WARN] parse_decls reported {errors} error(s), types may be partially added")
    else:
        print("  [ok ]  structs added to Local Types")


def _set_func_prototype(ea, proto):
    """Apply a C-style prototype string to a function."""
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, proto, ida_typeinf.PT_SIL):
        if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
            print(f"  [proto]  0x{ea:x} <- {proto.split('(')[0].strip()}(...)")
            return True
    print(f"  [proto FAIL] 0x{ea:x}  {proto}")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 72)
    print("PoolParty Sample B annotator (IDA 8.x / 9.x compatible)")
    print("=" * 72)

    if not ida_funcs.get_func(0x14001B630):
        print(f"WARNING: no function defined at 0x14001B630, wrong binary?")

    print("\n[1/4] Adding struct declarations to Local Types")
    _add_local_types(STRUCT_DECLS)

    print("\n[2/4] Renaming variant entry points")
    for ea, (name, comment) in VARIANT_FUNCS.items():
        _rename(ea, name, comment)

    print("\n[3/4] Renaming WinAPI status-check helpers")
    for ea, (name, comment) in HELPER_FUNCS.items():
        _rename(ea, name, comment)

    print("\n[4/4] Renaming boost::log helpers (collapses log noise in F5)")
    for ea, (name, comment) in LOG_FUNCS.items():
        _rename(ea, name, comment)

    print("\nApplying prototype to RemoteTpDirectInsertion")
    _set_func_prototype(
        0x14001B630,
        "void __fastcall RemoteTpDirectInsertion(InjectionCtx *ctx,"
        " __int64 unused2, __int64 unused3, __int64 unused4)",
    )

    print("\nDone. Press F5 on RemoteTpDirectInsertion (G -> 14001B630) to "
          "re-decompile. The boost::log calls should collapse, the WinAPI "
          "calls should keep their parameter names, and the InjectionCtx "
          "struct fields will be referenced by name.")


if __name__ == "__main__":
    main()
