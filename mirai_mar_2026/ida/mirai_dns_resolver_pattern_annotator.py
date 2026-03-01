"""
IDA 9.x variant-agnostic DNS resolver annotator for Mirai-like samples.

This script does NOT rely on fixed addresses.
It locates decode logic by byte signatures, then annotates the discovered
functions (types, names, struct, comments) so pseudocode is easier to read.

Usage:
  File -> Script file... -> mirai_dns_resolver_pattern_annotator.py
"""

import ida_funcs
import ida_bytes
import ida_kernwin
import ida_name
import idautils
import idc


DECODE_STRUCT_NAME = "dns_header_decoded_t"
DNS_RCODE_ENUM = "dns_rcode_t"

# Primary YARA-linked motif (Elastic d0c57a2e).
PATTERN_DECODE_PRIMARY = "07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89"
# Same motif without the leading context byte.
PATTERN_DECODE_ALT = "0F B6 07 0F B6 57 01 C1 E0 08 09 D0 89 06 0F BE 47 02 C1 E8 1F 89"
# Tail motif from this family of decoders (header length return = 12).
PATTERN_DECODE_TRAILER = "0F B6 47 0A 0F B6 57 0B C1 E0 08 09 D0 89 46 2C B8 0C 00 00 00 C3"


def log(msg):
    print(f"[mirai_dns_pat] {msg}")


def set_name(ea, name):
    if ea == idc.BADADDR:
        return False
    return bool(ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE))


def ensure_function(ea):
    if ea == idc.BADADDR:
        return False
    if ida_funcs.get_func(ea):
        return True
    return bool(ida_funcs.add_func(ea))


def find_pattern_hits(pattern):
    """
    Version-safe pattern search for IDA 9.3+.
    Uses raw segment bytes instead of ida_search.find_binary(), which is absent
    in some builds.
    """
    hits = []
    pat = bytes.fromhex(pattern)
    if not pat:
        return hits

    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        seg_size = seg_end - seg_start
        if seg_size <= 0:
            continue

        blob = ida_bytes.get_bytes(seg_start, seg_size)
        if not blob:
            continue

        pos = 0
        while True:
            idx = blob.find(pat, pos)
            if idx < 0:
                break
            hits.append(seg_start + idx)
            pos = idx + 1
    return hits


def rank_decode_function():
    patterns = [PATTERN_DECODE_PRIMARY, PATTERN_DECODE_ALT, PATTERN_DECODE_TRAILER]
    func_score = {}
    func_hits = {}

    for pat in patterns:
        hits = find_pattern_hits(pat)
        log(f"pattern hits ({pat[:24]}...): {len(hits)}")
        for h in hits:
            f = ida_funcs.get_func(h)
            if not f:
                ensure_function(h)
                f = ida_funcs.get_func(h)
            if not f:
                continue
            start = f.start_ea
            func_score[start] = func_score.get(start, 0) + 1
            func_hits.setdefault(start, []).append((h, pat))

    if not func_score:
        return idc.BADADDR, []

    # Highest score wins; tie-breaker = earliest EA.
    best = sorted(func_score.items(), key=lambda x: (-x[1], x[0]))[0][0]
    return best, func_hits.get(best, [])


def find_dns_lookup_caller(decode_ea):
    if decode_ea == idc.BADADDR:
        return idc.BADADDR
    decode_f = ida_funcs.get_func(decode_ea)
    if not decode_f:
        return idc.BADADDR

    caller_counts = {}
    for x in idautils.XrefsTo(decode_f.start_ea):
        f = ida_funcs.get_func(x.frm)
        if not f:
            continue
        if f.start_ea == decode_f.start_ea:
            continue
        caller_counts[f.start_ea] = caller_counts.get(f.start_ea, 0) + 1

    if not caller_counts:
        return idc.BADADDR
    return sorted(caller_counts.items(), key=lambda x: (-x[1], x[0]))[0][0]


def ensure_decode_struct():
    sid = idc.get_struc_id(DECODE_STRUCT_NAME)
    if sid != idc.BADADDR:
        return sid

    sid = idc.add_struc(-1, DECODE_STRUCT_NAME, 0)
    if sid == idc.BADADDR:
        return sid

    fields = [
        ("id", 0x00),
        ("qr", 0x04),
        ("opcode", 0x08),
        ("aa", 0x0C),
        ("tc", 0x10),
        ("rd", 0x14),
        ("ra", 0x18),
        ("rcode", 0x1C),
        ("qdcount", 0x20),
        ("ancount", 0x24),
        ("nscount", 0x28),
        ("arcount", 0x2C),
    ]
    for name, off in fields:
        idc.add_struc_member(sid, name, off, idc.FF_DWORD | idc.FF_DATA, -1, 4)
    return sid


def ensure_dns_rcode_enum():
    eid = idc.get_enum(DNS_RCODE_ENUM)
    if eid != idc.BADADDR:
        return eid

    eid = idc.add_enum(-1, DNS_RCODE_ENUM, 0)
    if eid == idc.BADADDR:
        return eid

    members = [
        ("DNS_RCODE_NOERROR", 0),
        ("DNS_RCODE_FORMERR", 1),
        ("DNS_RCODE_SERVFAIL", 2),
        ("DNS_RCODE_NXDOMAIN", 3),
        ("DNS_RCODE_NOTIMP", 4),
        ("DNS_RCODE_REFUSED", 5),
    ]
    for name, value in members:
        idc.add_enum_member(eid, name, value, -1)
    return eid


def apply_types(decode_ea, lookup_ea):
    decls = r"""
typedef struct dns_header_decoded_t {
  int id;
  int qr;
  int opcode;
  int aa;
  int tc;
  int rd;
  int ra;
  int rcode;
  int qdcount;
  int ancount;
  int nscount;
  int arcount;
} dns_header_decoded_t;
"""
    idc.parse_decls(decls, idc.PT_SILENT)

    if decode_ea != idc.BADADDR:
        idc.SetType(
            decode_ea,
            "unsigned __int64 __fastcall decode_dns_header(const unsigned char *wire, dns_header_decoded_t *out)",
        )

    if lookup_ea != idc.BADADDR:
        idc.SetType(
            lookup_ea,
            "unsigned __int64 __fastcall dns_lookup_with_resolver(unsigned char *qname, int qtype, int ns_count, __int64 ns_array, unsigned char **raw_reply_opt, unsigned long long *answer_out)",
        )


def annotate_decode(decode_ea, hits):
    if decode_ea == idc.BADADDR:
        return

    set_name(decode_ea, "decode_dns_header")
    idc.set_func_cmt(
        decode_ea,
        "Auto-identified via byte pattern search. "
        "Parses DNS wire header fields into dns_header_decoded_t.",
        1,
    )

    for hit_ea, pat in hits:
        idc.set_cmt(hit_ea, f"Pattern hit for decode header motif: {pat}", 1)


def annotate_lookup(lookup_ea, decode_ea):
    if lookup_ea == idc.BADADDR:
        return

    set_name(lookup_ea, "dns_lookup_with_resolver")
    idc.set_func_cmt(
        lookup_ea,
        "Likely resolver routine inferred from xref to decode_dns_header and DNS query/answer flow.",
        1,
    )

    if decode_ea != idc.BADADDR:
        decode_start = ida_funcs.get_func(decode_ea).start_ea if ida_funcs.get_func(decode_ea) else decode_ea
        for x in idautils.XrefsTo(decode_start):
            f = ida_funcs.get_func(x.frm)
            if f and f.start_ea == lookup_ea:
                idc.set_cmt(x.frm, "Decodes DNS response header into local decoded struct.", 1)


def main():
    decode_ea, decode_hits = rank_decode_function()
    if decode_ea == idc.BADADDR:
        log("No decode-header byte pattern found. No changes applied.")
        return

    lookup_ea = find_dns_lookup_caller(decode_ea)

    ensure_decode_struct()
    ensure_dns_rcode_enum()
    apply_types(decode_ea, lookup_ea)
    annotate_decode(decode_ea, decode_hits)
    annotate_lookup(lookup_ea, decode_ea)

    ida_kernwin.refresh_idaview_anyway()
    log(f"decode_dns_header @ 0x{decode_ea:x}")
    if lookup_ea != idc.BADADDR:
        log(f"dns_lookup_with_resolver @ 0x{lookup_ea:x}")
    else:
        log("dns_lookup_with_resolver caller not found from xrefs")
    log("done")


if __name__ == "__main__":
    main()
