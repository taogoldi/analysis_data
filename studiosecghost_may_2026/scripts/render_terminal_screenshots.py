"""
Render the static-analysis script outputs as terminal-style PNG screenshots
suitable for inlining in the blog post. Produces:

  images/screenshot_recon.png
  images/screenshot_extract_config.png
  images/screenshot_deep_disasm_port.png
  images/screenshot_deep_disasm_blocklist.png
  images/screenshot_deep_disasm_ghost.png

Each image is a fixed-width 'terminal' frame with a title bar, a dark
background, and the script's actual textual output rendered in Menlo.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
IMAGES = REPO / "images"
IMAGES.mkdir(exist_ok=True)
SAMPLE = REPO / "sample" / (
    "5940c41ab003399680a04d726587eed242e4ad8969abe4b5617d712ff190a852.exe"
)
DEEP_DISASM_TXT = REPO / "reports" / "json" / "deep_disasm.txt"

# Solarized-dark-like palette tuned for printed-page contrast
BG          = (16, 22, 30)         # almost-black
TITLEBAR    = (32, 40, 50)
BORDER      = (52, 65, 80)
FG          = (220, 224, 230)      # default text
FG_DIM      = (140, 152, 168)      # faint text / comments
FG_HI       = (255, 220, 90)       # yellow highlight
FG_GREEN    = (140, 220, 130)      # green for success / matches
FG_BLUE     = (110, 180, 240)      # blue for headings
FG_RED      = (255, 130, 130)      # red for the prompt or scary bits
FG_MAGENTA  = (210, 150, 240)      # IAT annotations
DOT_RED     = (255, 95, 87)
DOT_YELLOW  = (255, 189, 46)
DOT_GREEN   = (39, 201, 63)

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FONT_SIZE_BODY  = 16
FONT_SIZE_TITLE = 14

PROMPT = "$ "


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONT_PATH, size)


def _measure(font, text: str) -> tuple[int, int]:
    bbox = font.getbbox(text)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


def render(
    out_path: Path,
    title: str,
    lines: list[tuple[str, tuple[int, int, int]]],
    *,
    cols: int = 100,
    padding: int = 20,
    title_h: int = 36,
) -> None:
    """Lines is a list of (text, color) tuples; each is one rendered line."""
    body_font = _font(FONT_SIZE_BODY)
    title_font = _font(FONT_SIZE_TITLE)

    # Per-line height with a little vertical breathing room
    char_w, _ = _measure(body_font, "M")
    line_h = body_font.getbbox("Mg")[3] + 4

    width = padding * 2 + char_w * cols
    body_h = padding * 2 + line_h * len(lines)
    height = title_h + body_h

    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)

    # Title bar
    d.rectangle([0, 0, width, title_h], fill=TITLEBAR)
    d.line([(0, title_h), (width, title_h)], fill=BORDER, width=1)

    # Three dots (mac-style window controls)
    dot_y = title_h // 2
    for i, color in enumerate((DOT_RED, DOT_YELLOW, DOT_GREEN)):
        cx = 16 + i * 18
        d.ellipse([cx - 6, dot_y - 6, cx + 6, dot_y + 6], fill=color)

    # Title text (centered)
    tw, th = _measure(title_font, title)
    d.text(((width - tw) // 2, (title_h - th) // 2 - 2),
           title, font=title_font, fill=FG_DIM)

    # Body lines
    y = title_h + padding
    for text, color in lines:
        d.text((padding, y), text, font=body_font, fill=color)
        y += line_h

    # Outer border
    d.rectangle([0, 0, width - 1, height - 1], outline=BORDER, width=1)

    img.save(out_path, optimize=True)
    print(f"  wrote {out_path}  ({width}x{height})")


def _run(cmd: list[str]) -> str:
    """Run a command and return stdout (utf-8)."""
    res = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return res.stdout


def _colorize_disasm_line(line: str) -> tuple[str, tuple[int, int, int]]:
    """Pick a color for one disasm line based on its content."""
    if not line.strip():
        return line, FG
    # Header bars
    if set(line.strip()) <= {"="}:
        return line, FG_BLUE
    if line.startswith("===") and line.endswith("==="):
        return line, FG_BLUE
    # Truncation marker
    if line.strip().startswith("..."):
        return line, FG_DIM
    # IAT annotation lines (everything after the ';' should appear dimmer)
    if "; ->" in line and "[OK]" not in line:
        return line, FG
    # Highlight ports / VAs we care about
    if "0x115c" in line:
        return line, FG_HI
    return line, FG


def render_recon() -> None:
    """First screenshot: recon.py output -- packing/obfuscation summary."""
    out = _run([str(REPO / ".venv/bin/python"), str(REPO / "scripts/recon.py")])

    # We only want the high-signal bits. Strip down to ~38 lines.
    raw = out.splitlines()

    # Keep packing section, entropy table, imports header line, key flags,
    # obfuscation indicators.
    keep_prefixes = (
        "=", "TLS", "  callback", "  (table",
        "Section entropy",
        "  .text", "  .rdata", "  .data", "  .pdata", "  .fptable", "  .rsrc", "  .reloc",
        "Import DLL", "  USER32", "  GDI32", "  WS2_32", "  gdiplus",
        "  ole32", "  KERNEL32", "  SHELL32", "  ADVAPI32",
        "LoadLibrary", "GetProcAddress", "VirtualAlloc", "  (all three",
        "C2 IP LITERAL", "  UTF-16LE", "  ASCII",
        ".text OBFUSCATION", "  je rel32", "  reg-only", "  xor eax",
        "  int3 bytes", "  nop runs",
    )
    filtered = []
    for ln in raw:
        if any(ln.startswith(p) for p in keep_prefixes):
            filtered.append(ln[:96])
        if "PACKING / OBFUSCATION RECON" in ln:
            filtered.append(ln[:96])

    # Pre-pend the command line that produced this
    lines: list[tuple[str, tuple[int, int, int]]] = [
        (f"{PROMPT}python scripts/recon.py", FG_GREEN),
        ("", FG),
    ]
    for ln in filtered[:40]:
        if set(ln.strip()) <= {"="}:
            lines.append((ln, FG_BLUE))
        elif ln.startswith(("LoadLibrary", "GetProcAddress", "VirtualAlloc")):
            color = FG_RED if ": True" in ln else FG_GREEN
            lines.append((ln, color))
        elif "PACKING" in ln or "RECON" in ln:
            lines.append((ln, FG_BLUE))
        elif ln.startswith("  je rel32") or ln.startswith("  xor eax") or ln.startswith("  nop runs"):
            tail = ln.split(":")[-1].strip()
            color = FG_GREEN if tail == "0" else FG_HI
            lines.append((ln, color))
        elif ln.startswith("  UTF-16LE"):
            lines.append((ln, FG_HI))
        else:
            lines.append((ln, FG))

    render(IMAGES / "screenshot_recon.png",
           "Terminal -- recon.py  (StudioSecGhost packing/obfuscation pass)",
           lines, cols=100)


def render_extract_config() -> None:
    """Second screenshot: extract_config.py JSON output."""
    out = _run([str(REPO / ".venv/bin/python"),
                str(REPO / "scripts/extract_config.py")])

    # Truncate to roughly fit a single screenshot
    raw = out.splitlines()

    # Compact arrays for readability in the screenshot
    compact = []
    skip_until_next_top_key = False
    for ln in raw:
        if ln.startswith("    \"") and "install_paths_observed" in ln:
            # Replace the long install path block with an inline summary
            compact.append('      "install_paths_observed": [ ... 2 entries ... ],')
            skip_until_next_top_key = True
            continue
        if skip_until_next_top_key:
            if ln.strip().startswith("]"):
                skip_until_next_top_key = False
            continue
        compact.append(ln[:96])

    lines: list[tuple[str, tuple[int, int, int]]] = [
        (f"{PROMPT}python scripts/extract_config.py", FG_GREEN),
        ("", FG),
    ]
    for ln in compact[:46]:
        if ln.strip().startswith('"') and ':' in ln:
            key = ln.split(':', 1)[0]
            val = ln[len(key):]
            # Render keys in blue, values in default
            # Just color the whole line slightly to keep it readable
            if 'c2_ip' in ln or 'c2_port' in ln or 'StudioSec' in ln or '2.26' in ln:
                lines.append((ln, FG_HI))
            elif 'banner_class' in ln or 'anchor_class' in ln or 'ghost_window' in ln:
                lines.append((ln, FG_GREEN))
            else:
                lines.append((ln, FG))
        elif set(ln.strip()) <= {"{", "}", "[", "]", ","}:
            lines.append((ln, FG_DIM))
        else:
            lines.append((ln, FG))

    render(IMAGES / "screenshot_extract_config.png",
           "Terminal -- extract_config.py  (static config lift from .rdata)",
           lines, cols=100)


_DISASM_CACHE = {}


def _disasm_window(start_va: int, end_va: int) -> list[str]:
    """Disassemble [start_va, end_va) live with capstone and return annotated
    listing lines that look like the ones in deep_disasm.txt."""
    if (start_va, end_va) in _DISASM_CACHE:
        return _DISASM_CACHE[(start_va, end_va)]

    import re
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    p = pefile.PE(str(SAMPLE), fast_load=False)
    raw = SAMPLE.read_bytes()
    text = next(s for s in p.sections if s.Name.rstrip(b"\x00") == b".text")
    tb = text.get_data()
    tv = p.OPTIONAL_HEADER.ImageBase + text.VirtualAddress
    iat = {}
    for d in p.DIRECTORY_ENTRY_IMPORT:
        for imp in d.imports:
            if imp.name:
                iat[imp.address] = f"{d.dll.decode()}:{imp.name.decode()}"

    def read_str(va, kind):
        for s in p.sections:
            sva = p.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
            if sva <= va < sva + max(s.Misc_VirtualSize, s.SizeOfRawData):
                off = (va - sva) + s.PointerToRawData
                if kind == "ascii":
                    end = raw.find(b"\x00", off, off + 200)
                    if end < 0:
                        return None
                    try:
                        return raw[off:end].decode("utf-8")
                    except UnicodeDecodeError:
                        return None
                else:
                    out = []
                    for i in range(80):
                        lo, hi = raw[off + i * 2], raw[off + i * 2 + 1]
                        if lo == 0 and hi == 0:
                            return "".join(out)
                        if hi == 0 and 0x20 <= lo <= 0x7e:
                            out.append(chr(lo))
                        else:
                            return None
                    return None

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    out_lines = []
    start_off = start_va - tv
    end_off = end_va - tv
    for insn in md.disasm(tb[start_off:end_off], start_va):
        line = f"{insn.address:016x}: {insn.mnemonic:8} {insn.op_str}"
        if insn.mnemonic in ("call", "jmp", "lea") and "rip" in insn.op_str:
            m = re.search(r"\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]", insn.op_str)
            if m:
                sign = 1 if m.group(1) == "+" else -1
                disp = sign * int(m.group(2), 16)
                tgt = insn.address + insn.size + disp
                if tgt in iat:
                    line += f"   ; -> {iat[tgt]}"
                elif insn.mnemonic == "lea":
                    s = read_str(tgt, "utf16") or read_str(tgt, "ascii")
                    if s and len(s) >= 3:
                        line += f"   ; -> {tgt:#x}  \"{s[:50]}\""
                    else:
                        line += f"   ; -> {tgt:#x}"
                else:
                    line += f"   ; -> {tgt:#x}"
        out_lines.append(line)
    _DISASM_CACHE[(start_va, end_va)] = out_lines
    return out_lines


def render_deep_disasm_port() -> None:
    """Killer screenshot: the actual mov ebx, 0x115c line that proves port=4444."""
    # Grab 0x140005de0..0x140005e80 -- the CreateEventW + CreateThread bootstrap
    window = _disasm_window(0x140005de0, 0x140005e80)
    # Add a leading prompt + annotation
    lines: list[tuple[str, tuple[int, int, int]]] = [
        (f"{PROMPT}python scripts/deep_disasm.py  |  grep -A30 '140005de0'", FG_GREEN),
        ("", FG),
        ("=" * 96, FG_BLUE),
        (" Port lift -- VA 0x140005DEC inside the agent main loop ", FG_BLUE),
        ("=" * 96, FG_BLUE),
        ("", FG),
    ]
    # Highlight specific lines
    for ln in window[:32]:
        if "0x115c" in ln:
            lines.append((ln, FG_HI))
        elif "WaitForSingleObject" in ln or "CreateEventW" in ln or "CreateThread" in ln:
            lines.append((ln, FG_MAGENTA))
        elif ln.startswith("0000"):
            # Color the IAT annotations dimmer
            if "; ->" in ln:
                head, tail = ln.split("; ->", 1)
                lines.append((head + "; ->" + tail, FG))
            else:
                lines.append((ln, FG))
        else:
            lines.append((ln, FG))
    lines.append(("", FG))
    lines.append(("# 0x115c = 4444 decimal. Stored at [rbp+0xb8] = sockaddr-prep stack slot.", FG_DIM))
    lines.append(("# Network thread spawned at lpStartAddress = 0x14000E7B0 (lea r8, [rip+0x898C]).", FG_DIM))

    render(IMAGES / "screenshot_deep_disasm_port.png",
           "Terminal -- deep_disasm.py  (C2 port lift from .text)",
           lines, cols=96)


def render_deep_disasm_blocklist() -> None:
    """Show the unrolled 15-entry wcsstr chain for the anti-analysis routine."""
    window = _disasm_window(0x140005860, 0x140005a00)
    lines: list[tuple[str, tuple[int, int, int]]] = [
        (f"{PROMPT}python scripts/deep_disasm.py  |  grep -A40 '140005860'", FG_GREEN),
        ("", FG),
        ("=" * 96, FG_BLUE),
        (" Anti-analysis routine -- 15 unrolled wcsstr() calls @ 0x140005860+ ", FG_BLUE),
        ("=" * 96, FG_BLUE),
        ("", FG),
    ]
    # Re-disassemble inline to get IAT annotations (the saved dump may have
    # truncated this region). For simplicity, just render what's there.
    for ln in window[:40]:
        if "wcsstr" in ln.lower() or "0x1400153e0" in ln.lower():
            lines.append((ln, FG_MAGENTA))
        elif any(name in ln for name in ('"ollydbg', '"x64dbg', '"ida', '"windbg',
                                          '"dnspy', '"ghidra', '"cheatengine',
                                          '"x32dbg', '"devenv', '"processhacker',
                                          '"procmon', '"procexp')):
            lines.append((ln, FG_HI))
        elif "jne" in ln:
            lines.append((ln, FG_RED))
        else:
            lines.append((ln, FG))
    lines.append(("", FG))
    lines.append(("# Each lea rdx,<name>; lea rcx,parent_exe; call wcsstr; test rax,rax; jne exit_path.", FG_DIM))
    lines.append(("# Substring match -- not _wcsicmp. Parent process is the target, not the proc list.", FG_DIM))

    render(IMAGES / "screenshot_deep_disasm_blocklist.png",
           "Terminal -- deep_disasm.py  (anti-analysis wcsstr chain)",
           lines, cols=96)


def render_deep_disasm_ghost() -> None:
    """Show the EnumWindows callback that finds windows titled StudioSecGhost."""
    window = _disasm_window(0x140008640, 0x1400086c8)
    lines: list[tuple[str, tuple[int, int, int]]] = [
        (f"{PROMPT}python scripts/deep_disasm.py  |  grep -A22 '140008640'", FG_GREEN),
        ("", FG),
        ("=" * 96, FG_BLUE),
        (" EnumWindows callback -- find any top-level window titled 'StudioSecGhost' ", FG_BLUE),
        ("=" * 96, FG_BLUE),
        ("", FG),
    ]
    for ln in window[:24]:
        if "GetWindowTextW" in ln or "0x1400153e0" in ln:
            lines.append((ln, FG_MAGENTA))
        elif "0x140049280" in ln:
            lines.append((ln, FG_HI))
        elif "jne" in ln or "ret" in ln:
            lines.append((ln, FG_RED))
        else:
            lines.append((ln, FG))
    lines.append(("", FG))
    lines.append(("# 0x140049280 = L\"StudioSecGhost\". Compare fn 0x1400153E0 is SSE2 wcsstr.", FG_DIM))
    lines.append(("# Non-NULL rax -> match -> cloak path (WS_EX_LAYERED + SetLayeredWindowAttributes).", FG_DIM))

    render(IMAGES / "screenshot_deep_disasm_ghost.png",
           "Terminal -- deep_disasm.py  (ghost-window EnumWindows callback)",
           lines, cols=96)


def main() -> None:
    print("Generating terminal-style screenshots ...")
    render_recon()
    render_extract_config()
    render_deep_disasm_port()
    render_deep_disasm_blocklist()
    render_deep_disasm_ghost()
    print("done.")


if __name__ == "__main__":
    main()
