"""
Pony stealer — IDAPython prep script for blog-post screenshots.

Run once:
    File > Script file...  (Alt-F7)  ->  pick this script

It will:
  - Define TEB / PEB / sockaddr_in / hostent / WSock32 prototypes in the
    type library so Hex-Rays can apply them.
  - Rename the six key functions we reference in the write-up.
  - Set argument-typed prototypes so F5 produces clean pseudocode.
  - Attach repeatable comments on each anti-analysis stub.

After it finishes, navigate to each renamed function and press F5 to
capture the decompiled-code screenshots.

Tested on IDA 7.7 / 8.x / 9.x on Windows and macOS.  Pure stdlib +
public IDA SDK; no plugins required.
"""

from __future__ import print_function

import idc
import idaapi
import ida_name
import ida_typeinf
import ida_bytes


# ---------------------------------------------------------------------------
# 1. C type / struct definitions
# ---------------------------------------------------------------------------
#
# We define only the fields we need.  IDA will merge these into the active
# TIL; existing definitions of the same names are replaced.

TYPE_BLOCK = r"""
typedef unsigned long  DWORD;
typedef unsigned short WORD;
typedef unsigned char  BYTE;
typedef int            BOOL;
typedef int            SOCKET;
typedef void          *HANDLE;
typedef void          *LPVOID;
typedef const char    *LPCSTR;

struct in_addr {
    unsigned long S_addr;
};

struct sockaddr_in {
    short          sin_family;       // AF_INET = 2
    unsigned short sin_port;         // network-byte-order port
    struct in_addr sin_addr;
    char           sin_zero[8];
};

struct hostent {
    char  *h_name;
    char **h_aliases;
    short  h_addrtype;
    short  h_length;
    char **h_addr_list;
};

/* Minimal PEB / TEB layouts — only the bytes we annotate. */
typedef struct _PEB_MIN {
    BYTE InheritedAddressSpace;       // +0x00
    BYTE ReadImageFileExecOptions;    // +0x01
    BYTE BeingDebugged;               // +0x02  <-- anti-debug target
    BYTE BitField;                    // +0x03
} PEB_MIN;

typedef struct _TEB_MIN {
    char     _pad0[0x30];
    PEB_MIN *ProcessEnvironmentBlock; // +0x30  <-- FS:[0x30] reads this
} TEB_MIN;
"""


def apply_types():
    til = ida_typeinf.get_idati()
    # IDA 8/9 uses PT_SIL; older versions used PT_SILENT; either way the numeric
    # value of "silent mode" is 1. Fall back to 0 (default, may pop dialogs) if
    # neither constant is exposed.
    flags = getattr(ida_typeinf, "PT_SIL",
                    getattr(ida_typeinf, "PT_SILENT", 0))
    try:
        rc = ida_typeinf.parse_decls(til, TYPE_BLOCK, None, flags)
    except TypeError:
        # Some IDA builds expose parse_decls with a different arg count.
        rc = ida_typeinf.parse_decls(til, TYPE_BLOCK, None)
    if rc == 0:
        print("[+] Type block parsed cleanly")
    else:
        print("[!] %d type parse errors (usually harmless redefinitions)" % rc)


# ---------------------------------------------------------------------------
# 2. Function renames
# ---------------------------------------------------------------------------

RENAMES = [
    (0x00410329, "pony_entry_trampoline",
     "push/pop/push-addr/clc/jb+1/ret indirect-call obfuscation; resolves to pony_anti_emulation_gate"),

    (0x00410335, "pony_anti_emulation_gate",
     "Loops calling GetTickCount() until (result mod 7) == 5. Stalls sandboxes that return constant ticks."),

    (0x00402d3e, "md5_transform",
     "Full MD5 block compression. IV at 0x00402d01; round constants 0xd76aa478 ... 0xeb86d391 visible inline."),

    (0x0041113d, "aplib_init_with_integrity",
     "APLib decompressor init. Self-tamper check: rolls a 0xABEEFBEE hash over the first 256 bytes of the "
     "APLib copyright banner; aborts if the hash != 0."),

    (0x00403641, "pony_tcp_connect",
     "Creates an AF_INET/SOCK_STREAM/IPPROTO_TCP socket and connects to host/port supplied by caller."),

    (0x0040f759, "peb_being_debugged_check_inline",
     "Inline anti-debug: FS:[0x30] -> TEB.PEB, byte +2 is BeingDebugged. Sets debugger-handled flag if non-zero."),
]


def rename_functions():
    for ea, name, _ in RENAMES:
        if idc.get_func_name(ea) is None and not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            print("[-] 0x%08x is not inside a function — skipping rename" % ea)
            continue
        # SN_FORCE overrides any previous auto-generated name.
        if ida_name.set_name(ea, name, ida_name.SN_FORCE):
            print("[+] 0x%08x  ->  %s" % (ea, name))
        else:
            print("[!] failed to rename 0x%08x" % ea)


# ---------------------------------------------------------------------------
# 3. Function prototypes
# ---------------------------------------------------------------------------
#
# Sets the Hex-Rays-visible signature.  Use SetType; on failure we log but
# keep going — most failures mean IDA can't resolve a referenced type,
# which is usually recoverable by re-running after apply_types() succeeds.

PROTOTYPES = [
    (0x00402d3e,
     "int __cdecl md5_transform(unsigned int *state, const unsigned char *blocks, int block_count);"),

    # APLib init signature per aPLib public API: (context, src_len, dst_len, src, dst, cb, user).
    (0x0041113d,
     "unsigned int __cdecl aplib_init_with_integrity("
     "void *ctx, int src_size, int dst_size, const void *src, void *dst, void *cb, void *user);"),

    (0x00403641,
     "int __cdecl pony_tcp_connect(const char *host, unsigned short port, int timeout_ms);"),
]


def apply_prototypes():
    for ea, proto in PROTOTYPES:
        if idc.SetType(ea, proto):
            print("[+] prototype set at 0x%08x" % ea)
        else:
            print("[!] prototype failed at 0x%08x  (re-run after type parse)" % ea)


# ---------------------------------------------------------------------------
# 4. WSock32 import prototypes (so F5 types socket/connect/htons correctly)
# ---------------------------------------------------------------------------

WSOCK_PROTOS = {
    "socket":        "SOCKET __stdcall socket(int af, int type, int protocol);",
    "connect":       "int __stdcall connect(SOCKET s, const struct sockaddr_in *name, int namelen);",
    "gethostbyname": "struct hostent * __stdcall gethostbyname(const char *name);",
    "inet_addr":     "unsigned long __stdcall inet_addr(const char *cp);",
    "htons":         "unsigned short __stdcall htons(unsigned short hostshort);",
    "send":          "int __stdcall send(SOCKET s, const char *buf, int len, int flags);",
    "recv":          "int __stdcall recv(SOCKET s, char *buf, int len, int flags);",
    "closesocket":   "int __stdcall closesocket(SOCKET s);",
    "WSAStartup":    "int __stdcall WSAStartup(WORD wVersionRequested, void *lpWSAData);",
    "GetTickCount":  "DWORD __stdcall GetTickCount(void);",
}


def prototype_imports():
    # Walk import thunks and set prototypes on any matching name.
    applied = 0
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        def cb(ea, name, ord_, applied=applied):
            if name and name in WSOCK_PROTOS:
                if idc.SetType(ea, WSOCK_PROTOS[name]):
                    print("[+] import prototype: %s" % name)
            return True
        idaapi.enum_import_names(i, cb)


# ---------------------------------------------------------------------------
# 5. Repeatable comments on anti-analysis gotchas
# ---------------------------------------------------------------------------

COMMENTS = [
    (0x00410329,
     "ENTRY: push eax / pop eax / push 0x410335 / clc / jb +1 / ret\n"
     "Effectively an indirect jmp to 0x410335. The jb is never taken (clc sets CF=0)."),

    (0x00410335,
     "ANTI-EMULATION GATE: loop while ((GetTickCount() % 7) != 5)\n"
     "Real systems exit in microseconds; sandboxes that stub GetTickCount hang here.\n"
     "One-byte bypass: change CMP EDX, 5 -> CMP EDX, EDX."),

    (0x0040f759,
     "ANTI-DEBUG: FS:[0x30] -> PEB (see TEB_MIN.ProcessEnvironmentBlock).\n"
     "CMP BYTE [EAX+2], 0 tests PEB.BeingDebugged.\n"
     "If JE not taken, the handler at 0x40101f is invoked."),

    (0x0041113d,
     "APLIB INIT + INTEGRITY CHECK: hash=0xabeefbee rolled over first 256 bytes of\n"
     "the APLib copyright banner; must equal 0 or function aborts.\n"
     "Protects the banner from in-place patching."),

    (0x00402d01,
     "MD5 initial state: A=0x67452301  B=0xefcdab89  C=0x98badcfe  D=0x10325476"),

    (0x00403641,
     "Creates SOCK_STREAM socket (socket(2, 1, 6) == AF_INET/SOCK_STREAM/IPPROTO_TCP),\n"
     "builds sockaddr_in and calls connect(). Caller passes host string and port."),
]


def apply_comments():
    for ea, text in COMMENTS:
        # set_cmt(ea, text, repeatable=1) shows the comment wherever ea is xref'd
        idc.set_cmt(ea, text, 1)
        print("[+] comment at 0x%08x" % ea)


# ---------------------------------------------------------------------------
# 6. Optional: mark FS:[0x30] operand as a struct offset
# ---------------------------------------------------------------------------
#
# This tags the displacement in `mov eax, fs:[0x30]` as the
# TEB_MIN.ProcessEnvironmentBlock field so the ASM view renders it symbolically.

def _get_struct_tid(name):
    """
    Resolve a struct tid across IDA 7/8 (get_named_type_tid(til, name))
    and IDA 9.x (get_named_type_tid(name)).  Falls back to get_struc_id.
    """
    # IDA 9.x signature
    try:
        tid = ida_typeinf.get_named_type_tid(name)
        if tid not in (idaapi.BADADDR, 0, -1):
            return tid
    except TypeError:
        pass
    # IDA 7/8 signature
    try:
        til = ida_typeinf.get_idati()
        tid = ida_typeinf.get_named_type_tid(til, name)
        if tid not in (idaapi.BADADDR, 0, -1):
            return tid
    except TypeError:
        pass
    # Very old SDK fallback via idc
    try:
        import ida_struct
        sid = ida_struct.get_struc_id(name)
        if sid != idaapi.BADADDR:
            return sid
    except Exception:
        pass
    return idaapi.BADADDR


def annotate_peb_fs_read(ea=0x0040f759):
    """
    Mark the 0x30 displacement in the 'mov eax, fs:[0x30]' instruction at `ea`
    as TEB_MIN.ProcessEnvironmentBlock.  Op index 1 is the memory operand.
    """
    teb_sid = _get_struct_tid("TEB_MIN")
    if teb_sid == idaapi.BADADDR:
        print("[-] TEB_MIN not in TIL; skipping FS:[0x30] struct-offset annotation")
        return
    # op_stroff: turn an immediate/displacement into a struct-member reference
    # Args: ea, op_index, list-of-tids, delta
    try:
        # IDA 9 expects a path (tuple/list); older versions accept a scalar.
        try:
            ida_bytes.op_stroff(ea, 1, [teb_sid], 0)
        except TypeError:
            ida_bytes.op_stroff(ea, 1, teb_sid, 0)
        print("[+] annotated FS:[0x30] at 0x%08x as TEB_MIN.ProcessEnvironmentBlock" % ea)
    except Exception as e:
        print("[!] op_stroff failed: %r  (not critical; skip)" % e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("  Pony stealer — IDAPython setup")
    print("=" * 72)
    apply_types()
    rename_functions()
    apply_prototypes()
    prototype_imports()
    apply_comments()
    annotate_peb_fs_read()
    print("-" * 72)
    print("Done. For each decompiled-code screenshot:")
    print("  -  Jump to md5_transform          (0x00402d3e)  -> F5")
    print("  -  Jump to aplib_init_with_integrity (0x0041113d) -> F5")
    print("  -  Jump to pony_tcp_connect       (0x00403641)  -> F5")
    print("Hex-Rays comments (// ...) pick up the repeatable comments above.")
    print("=" * 72)


if __name__ == "__main__":
    main()
