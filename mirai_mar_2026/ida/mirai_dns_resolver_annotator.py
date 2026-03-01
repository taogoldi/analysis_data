"""
IDA 9.x resolver annotator for Mirai-like ELF samples.

Focus:
  - __decode_header / _decode_header
  - __dns_lookup / _dns_lookup
  - DNS header field struct + comments
  - YARA-hit context for Elastic rule Linux_Trojan_Gafgyt_d0c57a2e

Usage:
  File -> Script file... -> mirai_dns_resolver_annotator.py
"""

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import idautils
import idc


# Known addresses from this sample. If symbols exist, they are preferred.
FALLBACK_DECODE_EA = 0x414034
FALLBACK_LOOKUP_EA = 0x41312C

DECODE_NAMES = ["__decode_header", "_decode_header", "decode_header"]
LOOKUP_NAMES = ["__dns_lookup", "_dns_lookup", "dns_lookup"]

DECODE_STRUCT_NAME = "dns_header_decoded_t"
DNS_RCODE_ENUM = "dns_rcode_t"


def log(msg):
    print(f"[mirai_dns] {msg}")


def set_name(ea, name):
    if ea == idc.BADADDR:
        return False
    return bool(ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE))


def find_named_ea(candidates):
    for n in candidates:
        ea = idc.get_name_ea_simple(n)
        if ea != idc.BADADDR:
            return ea
    return idc.BADADDR


def ensure_function(ea):
    if ea == idc.BADADDR:
        return False
    if ida_funcs.get_func(ea):
        return True
    return bool(ida_funcs.add_func(ea))


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
    # Define type declarations once for better decompiler output.
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


def annotate_decode(decode_ea):
    if decode_ea == idc.BADADDR:
        return

    set_name(decode_ea, "decode_dns_header")
    idc.set_func_cmt(
        decode_ea,
        "Parses 12-byte DNS wire header into dns_header_decoded_t fields. "
        "This is protocol parsing logic and commonly reused across resolver codebases.",
        1,
    )

    # Per-field comments keyed by known offsets in this sample.
    comments = {
        decode_ea + 0x0C: "out->id = (wire[0] << 8) | wire[1]",
        decode_ea + 0x15: "out->qr = (wire[2] >> 7) & 1",
        decode_ea + 0x28: "out->opcode = (wire[2] >> 3) & 0xF",
        decode_ea + 0x35: "out->aa = (wire[2] >> 2) & 1",
        decode_ea + 0x41: "out->tc = (wire[2] >> 1) & 1",
        decode_ea + 0x4D: "out->rd = wire[2] & 1",
        decode_ea + 0x5B: "out->ra = (wire[3] >> 7) & 1",
        decode_ea + 0x66: "out->rcode = wire[3] & 0xF",
        decode_ea + 0x79: "out->qdcount = (wire[4] << 8) | wire[5]",
        decode_ea + 0x8C: "out->ancount = (wire[6] << 8) | wire[7]",
        decode_ea + 0x9F: "out->nscount = (wire[8] << 8) | wire[9]",
        decode_ea + 0xB2: "out->arcount = (wire[10] << 8) | wire[11]",
    }
    for ea, cmt in comments.items():
        idc.set_cmt(ea, cmt, 1)

    # YARA relation for the reported hit.
    idc.set_cmt(
        decode_ea + 0x03,
        "Elastic YARA Linux_Trojan_Gafgyt_d0c57a2e byte-sequence overlaps this decoder.",
        1,
    )


def annotate_lookup(lookup_ea, decode_ea):
    if lookup_ea == idc.BADADDR:
        return

    set_name(lookup_ea, "dns_lookup_with_resolver")
    idc.set_func_cmt(
        lookup_ea,
        "Resolver path: build query header/question, send UDP DNS request, poll/recv response, "
        "decode header, then parse answer records.",
        1,
    )

    # Mark decode_header call sites.
    if decode_ea != idc.BADADDR:
        for x in idautils.XrefsTo(decode_ea):
            f = ida_funcs.get_func(x.frm)
            if f and f.start_ea == lookup_ea:
                idc.set_cmt(x.frm, "Decodes DNS response header into local dns_header_decoded_t (12 ints).", 1)

    # Heuristic: comment likely resolver milestones based on known call names.
    targets = {
        "encode_header": "Encodes outbound DNS header.",
        "_encode_header": "Encodes outbound DNS header.",
        "__encode_header": "Encodes outbound DNS header.",
        "encode_question": "Encodes DNS question section.",
        "_encode_question": "Encodes DNS question section.",
        "decode_answer": "Parses DNS answer RR entries.",
        "_decode_answer": "Parses DNS answer RR entries.",
        "length_question": "Computes encoded DNS question length.",
        "_length_question": "Computes encoded DNS question length.",
    }

    for ea in idautils.FuncItems(lookup_ea):
        if idc.print_insn_mnem(ea) != "call":
            continue
        callee = idc.get_name(idc.get_operand_value(ea, 0), ida_name.GN_VISIBLE) or ""
        for key, cmt in targets.items():
            if key in callee:
                idc.set_cmt(ea, cmt, 1)
                break


def main():
    decode_ea = find_named_ea(DECODE_NAMES)
    if decode_ea == idc.BADADDR:
        decode_ea = FALLBACK_DECODE_EA
    lookup_ea = find_named_ea(LOOKUP_NAMES)
    if lookup_ea == idc.BADADDR:
        lookup_ea = FALLBACK_LOOKUP_EA

    ensure_function(decode_ea)
    ensure_function(lookup_ea)

    sid = ensure_decode_struct()
    eid = ensure_dns_rcode_enum()
    apply_types(decode_ea, lookup_ea)
    annotate_decode(decode_ea)
    annotate_lookup(lookup_ea, decode_ea)

    ida_kernwin.refresh_idaview_anyway()
    log(f"decode_ea=0x{decode_ea:x}, lookup_ea=0x{lookup_ea:x}")
    log(f"struct={DECODE_STRUCT_NAME} sid={sid}, enum={DNS_RCODE_ENUM} eid={eid}")
    log("resolver annotation complete")


if __name__ == "__main__":
    main()
