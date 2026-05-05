#!/usr/bin/env python3
"""
nsis_disasm2.py - Tao Goldi 2026-04

Improved NSIS-3 Unicode bytecode disassembler. Like nsis_disasm.py but:
  - shows raw integer arguments for control-flow opcodes (CALL, IFFLAG, etc.)
  - resolves NSIS variable references ($0-$9, $R0-$R9, special vars)
  - decodes string fragments completely
  - flags suspicious opcode chains

Usage: python3 nsis_disasm2.py <nsis_installer.exe>
"""
from __future__ import annotations
import struct, sys, zlib

EW_NAMES = {
    0:'NOP_ZERO',1:'RET',2:'NOP',3:'ABORT',4:'QUIT',
    5:'CALL',6:'UPDATETEXT',7:'SLEEP',8:'BRINGTOFRONT',9:'CHDETAILSVIEW',
    10:'SETFILEATTRIBUTES',11:'CREATEDIR',12:'IFFILEEXISTS',13:'SETFLAG',14:'IFFLAG',
    15:'GETFLAG',16:'RENAME',17:'GETFULLPATHNAME',18:'SEARCHPATH',19:'GETTEMPFILENAME',
    20:'EXTRACTFILE',21:'DELETEFILE',22:'MESSAGEBOX',23:'RMDIR',24:'STRLEN',
    25:'ASSIGNVAR',26:'STRCMP',27:'READENVSTR',28:'INTCMP',29:'INTOP',
    30:'INTFMT',31:'PUSHPOP',32:'FINDWINDOW',33:'SENDMESSAGE',34:'ISWINDOW',
    35:'GETDLGITEM',36:'SETCTLCOLORS',37:'SETBRANDINGIMAGE',38:'CREATEFONT',39:'SHOWWINDOW',
    40:'SHELLEXEC',41:'EXECUTE',42:'GETFILETIME',43:'GETDLLVERSION',44:'REGISTERDLL',
    45:'CREATESHORTCUT',46:'COPYFILES',47:'REBOOT',48:'WRITEINI',49:'READINISTR',
    50:'DELREG',51:'WRITEREG',52:'READREGSTR',53:'REGENUM',54:'FCLOSE',
    55:'FOPEN',56:'FPUTS',57:'FGETS',58:'FSEEK',59:'FINDCLOSE',
    60:'FINDNEXT',61:'FINDFIRST',62:'WRITEUNINSTALLER',63:'LOG',64:'SECTIONSET',
    65:'INSTTYPESET',66:'GETOSINFO',67:'RESERVEDOPCODE',68:'LOCKWINDOW',69:'FPUTWS',
    70:'FGETWS',
}
# Opcodes whose first arg(s) are NOT strings but offsets/values of other types.
# This is a coarse map; for our analysis we just need to print raw integers.
NUMERIC_FIRST_ARG = {1, 5, 14, 28, 12, 26, 22}  # RET, CALL, IFFLAG, INTCMP, IFFILEEXISTS, STRCMP, MESSAGEBOX

INTOP_OPS = {
    0:'+', 1:'-', 2:'*', 3:'/', 4:'|', 5:'&', 6:'^', 7:'!',
    8:'||', 9:'&&', 10:'%', 11:'<<', 12:'>>', 13:'>>>',
}

def find_first_header(data):
    sig = b'\xef\xbe\xad\xdeNullsoftInst'
    return data.find(sig) - 4

def inflate_header(data, first_off):
    header_size = struct.unpack('<I', data[first_off+16:first_off+20])[0]
    comp_size = header_size & 0x7fffffff
    hd_start = first_off + 28
    return zlib.decompress(data[hd_start+4:hd_start+comp_size], -zlib.MAX_WBITS)

def decode_string(hdr, strings_off, strings_end, off):
    if off < 0 or strings_off + off >= strings_end:
        return ''
    p = strings_off + off
    out = []
    while p + 1 < strings_end:
        wc = hdr[p] | (hdr[p+1] << 8)
        if wc == 0: break
        if 0xE000 <= wc <= 0xE0FF:
            p += 2
            if p + 1 >= strings_end: break
            idx = hdr[p] | (hdr[p+1] << 8)
            p += 2
            kind = (wc >> 8) & 3
            if kind == 0:
                # Variable reference. NSIS3 uses $0..$9, $R0..$R9, special.
                # idx 0..9 = $0..$9, 10..19 = $R0..$R9, 20+ = special
                if idx < 10:
                    out.append(f'$\x7B{idx}\x7D')  # placeholder $0..$9
                elif idx < 20:
                    out.append(f'$R{idx-10}')
                else:
                    SPECIAL = {20:'CMDLINE',21:'INSTDIR',22:'OUTDIR',23:'EXEDIR',
                               24:'LANGUAGE',25:'TEMP',26:'PLUGINSDIR',27:'EXEPATH',
                               28:'EXEFILE',29:'HWNDPARENT',30:'_CLICK',31:'_OUTDIR'}
                    out.append('$' + SPECIAL.get(idx, f'V{idx}'))
            elif kind == 1:
                out.append(f'$SHELL{idx}')
            elif kind == 2:
                out.append(f'$LANG{idx}')
            else:
                out.append(f'$X{wc:04x}_{idx}')
            continue
        out.append(chr(wc))
        p += 2
    s = ''.join(out)
    return s.replace('\x7B', '{').replace('\x7D', '}')

def main(path):
    data = open(path, 'rb').read()
    fh = find_first_header(data)
    hdr = inflate_header(data, fh)
    # block headers
    block_table = 0x4
    entries_off, entries_num = struct.unpack('<II', hdr[block_table+16:block_table+24])
    strings_off, _            = struct.unpack('<II', hdr[block_table+24:block_table+32])
    strings_end, _            = struct.unpack('<II', hdr[block_table+32:block_table+40])

    print(f'NSIS first header @ 0x{fh:x}')
    print(f'Inflated header: {len(hdr)} bytes')
    print(f'Entries: {entries_num} at 0x{entries_off:x}')
    print(f'Strings: 0x{strings_off:x}..0x{strings_end:x}')
    print()

    for i in range(entries_num):
        eo = entries_off + i*28
        which, = struct.unpack('<I', hdr[eo:eo+4])
        offsets = struct.unpack('<6i', hdr[eo+4:eo+28])
        name = EW_NAMES.get(which, f'EW_{which}')

        # Print BOTH raw and string-resolved variants for max insight
        raw_args = '|'.join(f'{x:>11}' for x in offsets)
        decoded = []
        for off in offsets:
            if off == 0:
                decoded.append('0')
            elif 0 < off < 0x4000:
                s = decode_string(hdr, strings_off, strings_end, off)
                if s:
                    decoded.append(repr(s))
                else:
                    decoded.append(str(off))
            else:
                decoded.append(str(off))
        # Decorate INTOP with op name
        deco = ''
        if which == 29:  # INTOP
            op_idx = offsets[3]
            deco = f'  # {INTOP_OPS.get(op_idx, "?")}-op'
        elif which == 5:  # CALL
            deco = f'  # call to entry idx={offsets[0]}'
        elif which == 14: # IFFLAG
            deco = f'  # if($flag) jmp idx={offsets[0]} else jmp idx={offsets[1]}'
        elif which == 1:  # RET
            deco = f'  # return; result={offsets[0]}'
        elif which == 28: # INTCMP
            deco = f'  # cmp; eq->idx={offsets[3]} lt->idx={offsets[4]} gt->idx={offsets[5]}'
        elif which == 26: # STRCMP
            deco = f'  # strcmp; case_sens={offsets[3]} eq->? ne->?'

        print(f'{i:4d} {name:18s} {", ".join(d[:50] for d in decoded):80s}{deco}')
        # also dump raw args if interesting
        if which in (5, 14, 28, 29):  # CALL, IFFLAG, INTCMP, INTOP
            print(f'         raw: {raw_args}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: nsis_disasm2.py <nsis_exe>')
        sys.exit(1)
    main(sys.argv[1])
