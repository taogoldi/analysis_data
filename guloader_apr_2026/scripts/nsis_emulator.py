#!/usr/bin/env python3
"""
nsis_emulator.py - Tao Goldi 2026-04

Concrete NSIS-3 Unicode bytecode emulator. Implements just enough opcodes to
trace GuLoader-style scripts to their `System::Call` invocations and dump the
runtime-assembled API definition strings + arguments.

Limitations: not a full NSIS implementation. We model only the subset of
opcodes needed to drive the loader. File I/O and registry ops are simulated
(no real disk writes); System::Call invocations are LOGGED rather than
dispatched.

Usage: python3 nsis_emulator.py <nsis_exe> [--trace]
"""
from __future__ import annotations
import struct, sys, zlib, os
from collections import defaultdict

# Opcode names from official NSIS exehead/exehead.h
EW_NAMES = {
    0:'NOP_ZERO',1:'RET',2:'NOP',3:'ABORT',4:'QUIT',5:'CALL',6:'UPDATETEXT',
    7:'SLEEP',8:'BRINGTOFRONT',9:'CHDETAILSVIEW',10:'SETFILEATTRIBUTES',
    11:'CREATEDIR',12:'IFFILEEXISTS',13:'SETFLAG',14:'IFFLAG',15:'GETFLAG',
    16:'RENAME',17:'GETFULLPATHNAME',18:'SEARCHPATH',19:'GETTEMPFILENAME',
    20:'EXTRACTFILE',21:'DELETEFILE',22:'MESSAGEBOX',23:'RMDIR',24:'STRLEN',
    25:'ASSIGNVAR',26:'STRCMP',27:'READENVSTR',28:'INTCMP',29:'INTOP',30:'INTFMT',
    31:'PUSHPOP',32:'FINDWINDOW',33:'SENDMESSAGE',34:'ISWINDOW',35:'GETDLGITEM',
    36:'SETCTLCOLORS',37:'SETBRANDINGIMAGE',38:'CREATEFONT',39:'SHOWWINDOW',
    40:'SHELLEXEC',41:'EXECUTE',42:'GETFILETIME',43:'GETDLLVERSION',
    44:'REGISTERDLL',45:'CREATESHORTCUT',46:'COPYFILES',47:'REBOOT',
    48:'WRITEINI',49:'READINISTR',50:'DELREG',51:'WRITEREG',52:'READREGSTR',
    53:'REGENUM',54:'FCLOSE',55:'FOPEN',56:'FPUTS',57:'FGETS',58:'FSEEK',
    59:'FINDCLOSE',60:'FINDNEXT',61:'FINDFIRST',62:'WRITEUNINSTALLER',63:'LOG',
    64:'SECTIONSET',65:'INSTTYPESET',66:'GETOSINFO',67:'RESERVEDOPCODE',
    68:'LOCKWINDOW',69:'FPUTWS',70:'FGETWS',
}

INTOP_OPS = {
    0:'+', 1:'-', 2:'*', 3:'/', 4:'|', 5:'&', 6:'^', 7:'~',
    8:'||', 9:'&&', 10:'%', 11:'<<', 12:'>>', 13:'>>>',
}

# ---------- header parsing ----------

def find_first_header(data):
    sig = b'\xef\xbe\xad\xdeNullsoftInst'
    return data.find(sig) - 4

def inflate_header(data, fh):
    header_size = struct.unpack('<I', data[fh+16:fh+20])[0]
    comp_size = header_size & 0x7fffffff
    return zlib.decompress(data[fh+28+4:fh+28+comp_size], -zlib.MAX_WBITS)

def parse_blocks(hdr):
    block_table = 0x4
    entries_off, entries_num = struct.unpack('<II', hdr[block_table+16:block_table+24])
    strings_off, _ = struct.unpack('<II', hdr[block_table+24:block_table+32])
    strings_end, _ = struct.unpack('<II', hdr[block_table+32:block_table+40])
    return entries_off, entries_num, strings_off, strings_end


# ---------- string pool decoder with variable interpolation ----------

class NSISStringDecoder:
    """Decodes NSIS-3 Unicode strings from the string pool, expanding
    variable references against a runtime variable map.

    NSIS-3 unicode encoding uses wchars 0xE000..0xE0FF as 'shell context
    markers' that introduce a 16-bit follow-up index. The high byte
    determines the kind of reference:
        0xE0 (kind=0): NSIS variable ($0..$9, $R0..$R9, special vars)
        0xE1 (kind=1): shell folder reference
        0xE2 (kind=2): language string reference
    """
    SPECIAL_VARS = {
        20:'CMDLINE',21:'INSTDIR',22:'OUTDIR',23:'EXEDIR',24:'LANGUAGE',
        25:'TEMP',26:'PLUGINSDIR',27:'EXEPATH',28:'EXEFILE',29:'HWNDPARENT',
        30:'_CLICK',31:'_OUTDIR',
    }

    def __init__(self, hdr, strings_off, strings_end):
        self.hdr = hdr
        self.so = strings_off
        self.se = strings_end

    def var_name(self, idx):
        if idx < 10: return f'${idx}'
        if idx < 20: return f'$R{idx-10}'
        return '$' + self.SPECIAL_VARS.get(idx, f'V{idx}')

    def decode(self, off, env):
        """Decode a NSIS-3 string with variable interpolation.

        This sample uses an ANSI-style marker scheme: wchar 0x80XX is a
        variable reference where the variable index = XX (low byte).
        A wchar 0x0003 (NSCODE_SKIP) is treated as an escape marker
        that introduces the var-ref wchar.

        Strings can start at ODD byte offsets, in which case the leading
        byte (0x00 from the high-byte of a preceding wchar) is skipped
        so that subsequent wchar reads stay aligned.
        """
        if off <= 0:
            return ''
        if self.so + off >= self.se:
            return ''
        p = self.so + off
        # If offset is odd and the byte at p is 0, advance one byte to
        # restore wchar alignment.
        if (off & 1) and p < self.se and self.hdr[p] == 0:
            p += 1
        out = []
        while p + 1 < self.se:
            wc = self.hdr[p] | (self.hdr[p+1] << 8)
            if wc == 0:
                break
            # NSCODE_SKIP (0x0003): just an escape marker, consume and move on
            if wc == 0x0003:
                p += 2
                continue
            # Variable reference: wchar 0x80XX -> var idx XX
            if 0x8000 <= wc <= 0x80FF:
                idx = wc & 0xFF
                out.append(env.get(idx, ''))
                p += 2
                continue
            # Shell folder reference: wchar 0x81XX -> shell folder XX
            if 0x8100 <= wc <= 0x81FF:
                idx = wc & 0xFF
                out.append(f'<SHELL{idx}>')
                p += 2
                continue
            # Lang string reference: wchar 0x82XX -> lang XX
            if 0x8200 <= wc <= 0x82FF:
                idx = wc & 0xFF
                out.append(f'<LANG{idx}>')
                p += 2
                continue
            # Regular wchar
            try:
                out.append(chr(wc))
            except ValueError:
                pass
            p += 2
        return ''.join(out)


# ---------- emulator ----------

class NSISEmulator:
    def __init__(self, hdr, entries_off, entries_num, strings_off, strings_end,
                 trace=False):
        self.hdr = hdr
        self.entries_off = entries_off
        self.entries_num = entries_num
        self.strings_off = strings_off
        self.strings_end = strings_end
        self.decoder = NSISStringDecoder(hdr, strings_off, strings_end)
        self.trace = trace

        # Variables: idx -> string. NSIS has $0..$9 (idx 0..9), $R0..$R9
        # (idx 10..19), and special vars (idx 20+).
        self.vars = {}
        # Special vars seeded with reasonable defaults
        self.vars[21] = 'C:\\Program Files'  # INSTDIR
        self.vars[22] = 'C:\\Program Files'  # OUTDIR
        self.vars[23] = 'C:\\Windows'        # EXEDIR
        self.vars[25] = 'C:\\Users\\victim\\AppData\\Local\\Temp'
        self.vars[26] = self.vars[25] + r'\nsXXXX.tmp\$_PLUGINSDIR_'

        # Stack for PUSH/POP
        self.stack = []
        # Call stack: (return_idx,)
        self.callstack = []
        # NSIS flag array (g_exec_flags). Indexed by flag id.
        self.flags = defaultdict(int)
        # Counter for fake temp filenames
        self._tempn = 0
        # File handle storage: { handle_id: { 'path': str, 'mode': int, 'pos': int, 'data': bytes } }
        self.handles = {}
        self._next_handle = 1

        # Activity log
        self.log = []
        self.system_calls = []
        self.extract_calls = []

        # Step limit (safety)
        self.max_steps = 100000

    # --- helpers ---
    def get_entry(self, i):
        if i < 0 or i >= self.entries_num:
            return None
        eo = self.entries_off + i * 28
        which, = struct.unpack('<I', self.hdr[eo:eo+4])
        offsets = struct.unpack('<6i', self.hdr[eo+4:eo+28])
        return which, offsets

    def s(self, off):
        """Decode a string (with variable interpolation)."""
        return self.decoder.decode(off, self.vars)

    def assign(self, var_idx, value):
        if value is None: value = ''
        self.vars[var_idx] = value

    def var_idx_from_arg(self, arg):
        """Some opcodes use arg as a variable INDEX directly. Heuristic:
        if the arg points into the strings pool and decodes to a single
        variable reference, return that index.

        For NSIS, opcode args that are variable indices are stored as a
        special form: an offset that points into the strings pool to a
        single-character variable marker. Practically we can decode and
        look at the resulting representation."""
        # The most reliable interpretation: read the string at offset and
        # check if the FIRST wchar is a variable marker.
        if arg <= 0 or self.strings_off + arg >= self.strings_end:
            return None
        p = self.strings_off + arg
        wc = self.hdr[p] | (self.hdr[p+1] << 8)
        if 0xE000 <= wc <= 0xE0FF:
            idx = self.hdr[p+2] | (self.hdr[p+3] << 8)
            return idx
        return None

    # --- step ---
    def step(self, ip):
        e = self.get_entry(ip)
        if e is None:
            return None  # halt
        which, offs = e
        name = EW_NAMES.get(which, f'EW_{which}')

        if self.trace:
            print(f'  ip={ip:4d} {name:18s} args={offs}')

        # Fall-through next IP:
        next_ip = ip + 1

        if which == 1:  # RET
            if self.callstack:
                next_ip = self.callstack.pop()
            else:
                return None  # done
            return next_ip

        if which == 5:  # CALL
            tgt = offs[0]
            if tgt > 0 and tgt < self.entries_num:
                self.callstack.append(next_ip)
                return tgt
            return next_ip

        if which == 14:  # IFFLAG
            # arg[0] = jmp if matched, arg[1] = jmp if not matched
            # arg[2] = flag index, arg[3] = new value to assign after test
            jmp_t = offs[0]
            jmp_f = offs[1]
            flag_idx = offs[2]
            new_val = offs[3]
            cur = self.flags[flag_idx]
            taken = bool(cur)
            # Update flag (NSIS sets flag to new_val regardless of test in some
            # variants; in others it ANDs with new_val). We'll just assign.
            if new_val != -1 and new_val != 0:
                self.flags[flag_idx] = new_val
            elif new_val == 0:
                self.flags[flag_idx] = 0
            if taken and 0 < jmp_t < self.entries_num:
                return jmp_t
            if (not taken) and 0 < jmp_f < self.entries_num:
                return jmp_f
            return next_ip

        if which == 13:  # SETFLAG: g_exec_flags[arg0] = arg1
            flag_idx = offs[0]
            v = offs[1]
            self.flags[flag_idx] = v
            return next_ip

        if which == 25:  # ASSIGNVAR
            # arg[0] = destination variable index (raw int)
            # arg[1] = source string offset
            # arg[2] = start (string offset, default 0)
            # arg[3] = length (string offset, default = full)
            var_idx = offs[0]
            v = self.s(offs[1])
            start = self.s(offs[2]) or '0'
            length = self.s(offs[3]) or ''
            try: start_i = int(start, 0)
            except: start_i = 0
            try: end_i = int(length, 0)
            except: end_i = -1
            if start_i or end_i >= 0:
                if end_i >= 0:
                    v = v[start_i:start_i+end_i]
                else:
                    v = v[start_i:]
            self.assign(var_idx, v)
            return next_ip

        if which == 31:  # PUSHPOP
            # NSIS source: arg[0] = string OR var idx, arg[1] = direction (0=push 1=pop 2=exch)
            kind = offs[1]
            if kind == 0:
                # push value (string)
                self.stack.append(self.s(offs[0]))
            elif kind == 1:
                # pop into variable: arg[0] is var index
                v = self.stack.pop() if self.stack else ''
                self.assign(offs[0], v)
            elif kind == 2:
                # exchange top of stack with var
                if self.stack:
                    cur = self.vars.get(offs[0], '')
                    self.assign(offs[0], self.stack[-1])
                    self.stack[-1] = cur
            return next_ip

        if which == 29:  # INTOP
            # arg[0] = dst var idx, arg[1]=op1 string, arg[2]=op2 string, arg[3]=op type
            dst_idx = offs[0]
            a = self.s(offs[1])
            b = self.s(offs[2])
            op = offs[3]
            try: ai = int(a, 0) if a else 0
            except: ai = 0
            try: bi = int(b, 0) if b else 0
            except: bi = 0
            r = 0
            try:
                if op == 0: r = ai + bi
                elif op == 1: r = ai - bi
                elif op == 2: r = ai * bi
                elif op == 3: r = ai // bi if bi else 0
                elif op == 4: r = ai | bi
                elif op == 5: r = ai & bi
                elif op == 6: r = ai ^ bi
                elif op == 7: r = ~ai
                elif op == 8: r = int(bool(ai) or bool(bi))
                elif op == 9: r = int(bool(ai) and bool(bi))
                elif op == 10: r = ai % bi if bi else 0
                elif op == 11: r = ai << bi
                elif op == 12: r = ai >> bi
                elif op == 13: r = (ai & 0xffffffff) >> bi
            except: r = 0
            self.assign(dst_idx, str(r))
            return next_ip

        if which == 30:  # INTFMT: var = sprintf(fmt, num)
            dst_idx = offs[0]
            fmt = self.s(offs[1])
            num = self.s(offs[2])
            try: n = int(num, 0) if num else 0
            except: n = 0
            try:
                # crude printf-like: handle %d, %x, %i
                if '%x' in fmt or '%X' in fmt:
                    r = fmt.replace('%x', f'{n:x}').replace('%X', f'{n:X}')
                else:
                    r = fmt.replace('%d', str(n)).replace('%i', str(n))
            except:
                r = str(n)
            self.assign(dst_idx, r)
            return next_ip

        if which == 28:  # INTCMP: a, b, eq, lt, gt
            a = self.s(offs[0])
            b = self.s(offs[1])
            try: ai = int(a, 0) if a else 0
            except: ai = 0
            try: bi = int(b, 0) if b else 0
            except: bi = 0
            j_eq, j_lt, j_gt = offs[2], offs[3], offs[4]
            if ai == bi and j_eq > 0: return j_eq
            if ai < bi and j_lt > 0: return j_lt
            if ai > bi and j_gt > 0: return j_gt
            return next_ip

        if which == 26:  # STRCMP
            a = self.s(offs[0])
            b = self.s(offs[1])
            j_eq = offs[2]
            j_ne = offs[3]
            case_sens = bool(offs[4])
            eq = (a == b) if case_sens else (a.lower() == b.lower())
            if eq and j_eq > 0: return j_eq
            if not eq and j_ne > 0: return j_ne
            return next_ip

        if which == 27:  # READENVSTR: var = getenv(name)
            dst_idx = offs[0]
            name = self.s(offs[1])
            v = os.environ.get(name, '')
            if not v:
                # synthesize plausible defaults
                if name.upper() == 'TEMP':
                    v = self.vars[25]
                elif name.upper() == 'APPDATA':
                    v = 'C:\\Users\\victim\\AppData\\Roaming'
                elif name.upper() == 'COMSPEC':
                    v = 'C:\\Windows\\System32\\cmd.exe'
                else:
                    v = ''
            self.assign(dst_idx, v)
            return next_ip

        if which == 24:  # STRLEN
            dst_idx = offs[0]
            v = self.s(offs[1])
            self.assign(dst_idx, str(len(v)))
            return next_ip

        if which == 55:  # FOPEN
            # arg[0]=dest var idx, arg[1]=desired access, arg[2]=disposition,
            # arg[3]=filename string offset
            handle_var_idx = offs[0]
            mode = offs[1]
            path = self.s(offs[3])
            h = self._next_handle
            self._next_handle += 1
            data = b''
            # If file exists on disk in our extracted tree, read it
            real_path = self._resolve_path(path)
            if real_path and os.path.exists(real_path):
                data = open(real_path, 'rb').read()
            self.handles[h] = {'path': path, 'real': real_path, 'mode': mode, 'pos': 0, 'data': data}
            self.assign(handle_var_idx, str(h))
            self.log.append(('FOPEN', path, real_path, mode, h, len(data)))
            return next_ip

        if which == 54:  # FCLOSE
            h_str = self.s(offs[0])
            try: h = int(h_str)
            except: h = 0
            if h in self.handles:
                self.log.append(('FCLOSE', self.handles[h]['path'], h))
                del self.handles[h]
            return next_ip

        if which == 57:  # FGETS - reads up to N bytes (or 1 line)
            h_str = self.s(offs[0])
            dst_idx = offs[1]
            max_str = self.s(offs[2])
            try: h = int(h_str)
            except: h = 0
            try: maxb = int(max_str)
            except: maxb = 0
            v = ''
            if h in self.handles:
                hd = self.handles[h]
                if maxb > 0:
                    chunk = hd['data'][hd['pos']:hd['pos']+maxb]
                    hd['pos'] += len(chunk)
                else:
                    # read line
                    end = hd['data'].find(b'\n', hd['pos'])
                    if end < 0: end = len(hd['data'])
                    chunk = hd['data'][hd['pos']:end+1]
                    hd['pos'] = end + 1
                # represent as latin-1 to preserve bytes
                v = chunk.decode('latin-1', errors='replace')
                self.log.append(('FGETS', hd['path'], h, len(chunk), v[:32]))
            self.assign(dst_idx, v)
            return next_ip

        if which == 56:  # FPUTS
            h_str = self.s(offs[0])
            data = self.s(offs[1])
            try: h = int(h_str)
            except: h = 0
            if h in self.handles:
                hd = self.handles[h]
                hd['data'] = hd['data'][:hd['pos']] + data.encode('latin-1', errors='replace') + hd['data'][hd['pos']:]
                hd['pos'] += len(data)
                self.log.append(('FPUTS', hd['path'], h, len(data), data[:32]))
            return next_ip

        if which == 58:  # FSEEK
            h_str = self.s(offs[0])
            mode = offs[1]
            off_str = self.s(offs[2])
            try: h = int(h_str)
            except: h = 0
            try: off_int = int(off_str, 0)
            except: off_int = 0
            if h in self.handles:
                hd = self.handles[h]
                if mode == 0: hd['pos'] = off_int
                elif mode == 1: hd['pos'] += off_int
                elif mode == 2: hd['pos'] = len(hd['data']) + off_int
                self.log.append(('FSEEK', hd['path'], h, mode, off_int, hd['pos']))
            return next_ip

        if which == 20:  # EXTRACTFILE
            flags = offs[0]
            name = self.s(offs[1])
            position = offs[2]
            self.extract_calls.append({'flags': flags, 'name': name, 'pos': position, 'ip': ip})
            self.log.append(('EXTRACTFILE', name, flags, position))
            return next_ip

        if which == 11:  # CREATEDIR
            d = self.s(offs[0])
            self.log.append(('CREATEDIR', d))
            return next_ip

        if which == 16:  # RENAME
            src = self.s(offs[0])
            dst = self.s(offs[1])
            self.log.append(('RENAME', src, dst))
            return next_ip

        if which == 21:  # DELETEFILE
            f = self.s(offs[0])
            self.log.append(('DELETEFILE', f))
            return next_ip

        if which == 19:  # GETTEMPFILENAME: writes a temp-filename string to var[arg0]
            dst = offs[0]
            self._tempn += 1
            v = f'C:\\Users\\victim\\AppData\\Local\\Temp\\nstmp{self._tempn:04x}.tmp'
            self.assign(dst, v)
            self.log.append(('GETTEMPFILENAME', dst, v))
            return next_ip

        if which == 17:  # GETFULLPATHNAME: writes the resolved full path
            dst = offs[0]
            inp = self.s(offs[1])
            self.assign(dst, inp)
            return next_ip

        if which == 53:  # REGENUM (no-op for now)
            dst = offs[0]
            self.assign(dst, '')
            return next_ip

        if which == 33:  # SENDMESSAGE (no-op, but assign result to var if present)
            dst = offs[4]
            if 0 <= dst < 256:
                self.assign(dst, '0')
            return next_ip

        if which == 32:  # FINDWINDOW (no-op)
            dst = offs[0]
            self.assign(dst, '0')
            return next_ip

        if which == 44:  # REGISTERDLL = System::Call dispatch
            # Args (based on NSIS source for `RegisterDLL`):
            #   parm0 = library path/name (resolved from string + variables)
            #   parm1 = function name (e.g. "Call" for System.dll)
            #   parm2 = display text or extra
            #   parm3 = no_unload flag
            #   parm4 = action (1=register, 0=call/Call, 2=unregister)
            dll = self.s(offs[0])
            fn  = self.s(offs[1])
            extra = self.s(offs[2])
            no_unload = offs[3]
            action = offs[4]
            entry = {
                'ip': ip,
                'dll': dll,
                'fn': fn,
                'extra': extra,
                'no_unload': no_unload,
                'action': action,
                'vars_snapshot': dict(self.vars),
                'stack_snapshot': list(self.stack),
            }
            self.system_calls.append(entry)
            self.log.append(('REGISTERDLL', dll[:80], fn[:80], extra[:80]))
            return next_ip

        if which == 51:  # WRITEREG
            self.log.append(('WRITEREG', offs[0], self.s(offs[1])[:60], self.s(offs[2])[:60]))
            return next_ip

        if which == 52:  # READREGSTR
            dst_idx = self.var_idx_from_arg(offs[0])
            if dst_idx is not None:
                self.assign(dst_idx, '')
            return next_ip

        # Many opcodes are NO-OPs for our purposes (UI, dialogs, etc.)
        # We just silently pass through.
        return next_ip

    def _resolve_path(self, path):
        """Map a script-style path to a real path on disk in our
        extracted tree. We strip the $PLUGINSDIR / $TEMP / $INSTDIR
        prefixes and look under sample/nsis_extract/."""
        if not path:
            return None
        # Replace special prefixes
        candidates = []
        base = 'sample/nsis_extract'
        candidates.append(os.path.join(base, path.replace('\\', '/')))
        # Try stripping initial backslash
        candidates.append(os.path.join(base, path.lstrip('\\').replace('\\', '/')))
        # Try matching by basename anywhere in the tree
        bn = os.path.basename(path.replace('\\', '/'))
        if bn:
            for root, _, files in os.walk(base):
                if bn in files:
                    candidates.append(os.path.join(root, bn))
        for c in candidates:
            if c and os.path.exists(c):
                return c
        return None

    def run(self, start_ip):
        ip = start_ip
        steps = 0
        last_ips = []
        while ip is not None and steps < self.max_steps:
            last_ips.append(ip)
            if len(last_ips) > 200:
                last_ips.pop(0)
            ip = self.step(ip)
            steps += 1
        # If we hit max_steps, dump where we got stuck
        if steps >= self.max_steps:
            from collections import Counter
            top = Counter(last_ips).most_common(8)
            print(f'[STUCK] Last 200 ips most-frequent: {top}')
            print(f'[STUCK] last_ips tail: {last_ips[-20:]}')
            print(f'[STUCK] callstack: {self.callstack}')
            print(f'[STUCK] flag: {self.flag}')
            print(f'[STUCK] stack: {self.stack[-12:]}')
        return steps


def main():
    args = sys.argv[1:]
    trace = '--trace' in args
    args = [a for a in args if not a.startswith('--')]
    path = args[0]
    data = open(path, 'rb').read()
    fh = find_first_header(data)
    hdr = inflate_header(data, fh)
    eo, en, so, se = parse_blocks(hdr)

    emu = NSISEmulator(hdr, eo, en, so, se, trace=trace)
    # Section 1 entry is at idx 171 for this sample
    print('=' * 70)
    print('NSIS emulator: tracing from idx 171 (Section 1 entry)')
    print('=' * 70)
    steps = emu.run(171)
    print(f'\nExecuted {steps} opcodes\n')
    if emu.callstack: print(f'callstack at end: {emu.callstack}')
    if emu.stack: print(f'stack at end: {emu.stack[-12:]}')

    print('=' * 70)
    print('REGISTERDLL (System::Call) invocations:')
    print('=' * 70)
    for sc in emu.system_calls:
        print(f'\n[ip={sc["ip"]}]')
        print(f'  dll  : {sc["dll"]!r}')
        print(f'  fn   : {sc["fn"]!r}')
        print(f'  extra: {sc["extra"]!r}')
        print(f'  no_unload={sc["no_unload"]} action={sc["action"]}')
        print(f'  stack at call: {sc["stack_snapshot"][-12:]}')
        # Print non-empty user vars
        nv = {k:v for k,v in sc["vars_snapshot"].items() if k < 30 and v}
        for k in sorted(nv):
            print(f'    var[{k}] = {nv[k]!r}')

    print('\n' + '=' * 70)
    print('FILE I/O log (last 40 events):')
    print('=' * 70)
    for ev in emu.log[-40:]:
        print(f'  {ev}')

    print('\n' + '=' * 70)
    print('FINAL VARIABLE STATE:')
    print('=' * 70)
    for k in sorted(emu.vars):
        v = emu.vars[k]
        if v:
            print(f'  var[{k}]({emu.decoder.var_name(k)}) = {v!r}')


if __name__ == '__main__':
    main()
