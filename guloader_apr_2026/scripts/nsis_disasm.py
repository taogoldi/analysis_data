#!/usr/bin/env python3
"""
nsis_disasm.py - Tao Goldi 2026-04

Minimal NSIS-3 Unicode bytecode disassembler used to study GuLoader's NSIS-stage
script. Inflates the FirstHeader at offset 0x22a00, parses the Entries block,
and prints opcode + raw_offset arguments. String references are resolved with
a heuristic decoder for both ASCII fragments and Unicode variable markers.

Usage:
    python3 nsis_disasm.py <nsis_installer.exe>
"""
from __future__ import annotations
import struct
import sys
import zlib

EW = {
    0: 'NOP_ZERO', 1: 'RET', 2: 'NOP', 3: 'ABORT', 4: 'QUIT',
    5: 'CALL', 6: 'UPDATETEXT', 7: 'SLEEP', 8: 'BRINGTOFRONT', 9: 'CHDETAILSVIEW',
    10: 'SETFILEATTRIBUTES', 11: 'CREATEDIR', 12: 'IFFILEEXISTS', 13: 'SETFLAG', 14: 'IFFLAG',
    15: 'GETFLAG', 16: 'RENAME', 17: 'GETFULLPATHNAME', 18: 'SEARCHPATH', 19: 'GETTEMPFILENAME',
    20: 'EXTRACTFILE', 21: 'DELETEFILE', 22: 'MESSAGEBOX', 23: 'RMDIR', 24: 'STRLEN',
    25: 'ASSIGNVAR', 26: 'STRCMP', 27: 'READENVSTR', 28: 'INTCMP', 29: 'INTOP',
    30: 'INTFMT', 31: 'PUSHPOP', 32: 'FINDWINDOW', 33: 'SENDMESSAGE', 34: 'ISWINDOW',
    35: 'GETDLGITEM', 36: 'SETCTLCOLORS', 37: 'SETBRANDINGIMAGE', 38: 'CREATEFONT', 39: 'SHOWWINDOW',
    40: 'SHELLEXEC', 41: 'EXECUTE', 42: 'GETFILETIME', 43: 'GETDLLVERSION', 44: 'REGISTERDLL',
    45: 'CREATESHORTCUT', 46: 'COPYFILES', 47: 'REBOOT', 48: 'WRITEINI', 49: 'READINISTR',
    50: 'DELREG', 51: 'WRITEREG', 52: 'READREGSTR', 53: 'REGENUM', 54: 'FCLOSE',
    55: 'FOPEN', 56: 'FPUTS', 57: 'FGETS', 58: 'FSEEK', 59: 'FINDCLOSE',
    60: 'FINDNEXT', 61: 'FINDFIRST', 62: 'WRITEUNINSTALLER', 63: 'LOG', 64: 'SECTIONSET',
    65: 'INSTTYPESET', 66: 'GETOSINFO', 67: 'RESERVEDOPCODE', 68: 'LOCKWINDOW', 69: 'FPUTWS',
    70: 'FGETWS',
}


def find_first_header(data: bytes) -> int:
    sig = b'\xef\xbe\xad\xdeNullsoftInst'
    return data.find(sig) - 4


def inflate_header(data: bytes, first_off: int) -> bytes:
    header_size = struct.unpack('<I', data[first_off + 16:first_off + 20])[0]
    comp_size = header_size & 0x7fffffff
    hd_start = first_off + 28
    return zlib.decompress(data[hd_start + 4:hd_start + comp_size], -zlib.MAX_WBITS)


def decode_string(hdr: bytes, strings_off: int, strings_end: int, off: int) -> str:
    if off < 0 or strings_off + off >= strings_end:
        return ''
    p = strings_off + off
    out: list[str] = []
    while p + 1 < strings_end:
        wc = hdr[p] | (hdr[p + 1] << 8)
        if wc == 0:
            break
        if 0xE000 <= wc <= 0xE0FF:
            p += 2
            if p + 1 >= strings_end:
                break
            idx = hdr[p] | (hdr[p + 1] << 8)
            p += 2
            kind = (wc >> 8) & 3
            tag = {0: 'VAR', 1: 'SHELL', 2: 'LANG'}.get(kind, 'X')
            out.append(f'${tag}{idx}')
            continue
        out.append(chr(wc))
        p += 2
    return ''.join(out)


def parse_entries_offset(hdr: bytes) -> tuple[int, int]:
    """Parse the inflated header to recover Block[2] (Entries) offset/num
    and the strings block offset.

    Block table starts at offset 0x4 (after the flags dword in NSIS-3); each
    block header is two uint32s (offset, num). For our use we only need the
    Entries block (idx 2) and the strings block (idx 3).
    """
    block_table = 0x4
    entries_off, entries_num = struct.unpack('<II', hdr[block_table + 16:block_table + 24])
    strings_off, _ = struct.unpack('<II', hdr[block_table + 24:block_table + 32])
    langtables_off, _ = struct.unpack('<II', hdr[block_table + 32:block_table + 40])
    return entries_off, entries_num, strings_off, langtables_off


def disasm(path: str) -> None:
    data = open(path, 'rb').read()
    first_off = find_first_header(data)
    if first_off < 0:
        print('NSIS first header not found', file=sys.stderr)
        sys.exit(1)
    hdr = inflate_header(data, first_off)
    entries_off, entries_num, strings_off, strings_end = parse_entries_offset(hdr)

    print(f'NSIS first header @ 0x{first_off:x}')
    print(f'Inflated header size: {len(hdr)} bytes')
    print(f'Entries: 0x{entries_num:x} ({entries_num}) at 0x{entries_off:x}')
    print(f'Strings: 0x{strings_off:x}..0x{strings_end:x}')
    print()

    for i in range(entries_num):
        eo = entries_off + i * 28
        which, = struct.unpack('<I', hdr[eo:eo + 4])
        offsets = struct.unpack('<6i', hdr[eo + 4:eo + 28])
        name = EW.get(which, f'EW_{which}')
        args: list[str] = []
        for off in offsets:
            if off == 0:
                args.append('0')
            elif 0 < off < 0x4000:
                s = decode_string(hdr, strings_off, strings_end, off)
                if s and any(c.isprintable() for c in s):
                    args.append(repr(s)[:80])
                else:
                    args.append(str(off))
            else:
                args.append(str(off))
        print(f'{i:4} EW_{name:18} {", ".join(args)}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    disasm(sys.argv[1])
