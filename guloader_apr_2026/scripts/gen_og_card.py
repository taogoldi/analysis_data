#!/usr/bin/env python3
"""GuLoader OG card. Output: blog/assets/images/social/guloader-card.jpg (1200x630)."""
from PIL import Image, ImageDraw, ImageFont
import os, random

OUT_PATH = "/Users/yakovgoldberg/Projects/blog/assets/images/social/guloader-card.jpg"
W, H = 1200, 630
BG, PANEL, BORDER = (12,12,14), (24,24,29), (60,60,68)
TEXT_HI, TEXT_MED, TEXT_LO = (240,240,240), (170,170,175), (110,110,118)
ACCENT = (227,60,73)

TITLE      = "GuLoader"
SUBTITLE   = "NSIS-stage shellcode loader, word-salad obfuscation, Remcos final stage"
TAG_LINE   = "CloudEye  |  NSIS-3  |  System::Call  |  Remcos 7.2.3 Pro  |  31.57.184.186:2404"
AUTHOR     = "Tao Goldi"
SITE_URL   = "taogoldi.github.io/reverse-engineer"
PROMPT_TAG = "$ tao@goldi:~/guloader"

HEX_DUMP_LINES = [
    "0x22a00 NSIS FirstHeader   inflate -> 0x16410 bytes / 228 entries",
    "EW_EXTRACTFILE      x20    -> 19 dropped files in %TEMP%",
    "EW_REGISTERDLL       x4    -> System::Call(VirtualAlloc, ...)",
    "Maynard.pen     8.96 MB    99.0% byte 0x5A   (sandbox-bypass decoy)",
    "Ganocephala176.ham 8.64 MB 99.0% byte 0xB7   (sandbox-bypass decoy)",
    "piasaba          229 KB    XOR 49 ED 06 B1 + 0xAC pad",
    "Toolers          154 KB    sparse, ~55% zeros, sub-cipher payload",
    "gl_hash_api      H = (H + UC(b)) XOR 0x182DE6AD     (custom add-XOR)",
    "Stage-2 fetch    drive.google.com -> %TEMP%\\exe.exe",
    "Final            %ProgramData%\\Remcos\\remcos.exe (MPRESS-packed)",
    "C2               raw TCP   31.57.184.186:2404",
    "                 Rmc-JUY15N   botnet=RemoteHost",
    "                 HKCU\\...\\Run = Rmc-JUY15N",
    "PEB walks        9 sites  (mov eax, fs:[0x30])",
    "Resolved APIs    31 hash matches (VirtualAlloc, NtCreateThread, ...)",
]

FONT_PATHS = {
    "title":  "/System/Library/Fonts/Supplemental/Arial Black.ttf",
    "sans":   "/System/Library/Fonts/Helvetica.ttc",
    "sans_b": "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "mono":   "/System/Library/Fonts/Menlo.ttc",
}
def font(k, sz):
    p = FONT_PATHS[k]
    return ImageFont.truetype(p, sz, index=0) if p.endswith(".ttc") else ImageFont.truetype(p, sz)

def render():
    img = Image.new("RGB", (W, H), BG)
    bg = Image.new("RGBA", (W, H), (0,0,0,0)); bgd = ImageDraw.Draw(bg)
    msmall = font("mono", 14)
    y = 18
    while y < H:
        line = random.choice(HEX_DUMP_LINES)
        fade = max(0.35, 1.0 - (y / H) * 0.55)
        col = tuple(int(c*fade) for c in TEXT_LO) + (int(255*0.55),)
        bgd.text((24, y), line, font=msmall, fill=col); y += 20
    img.paste(bg, (0,0), bg)
    grad = Image.new("RGBA", (W, H), (0,0,0,0)); gd = ImageDraw.Draw(grad)
    for x in range(int(W*0.78)):
        a = int(225 * (1.0 - (x / (W*0.78)) ** 1.4))
        gd.line([(x,0),(x,H)], fill=(BG[0], BG[1], BG[2], a))
    img.paste(grad, (0,0), grad)
    d = ImageDraw.Draw(img)
    bx = 56
    d.rectangle([bx, 90, bx+6, H-90], fill=ACCENT)
    f_tag = font("mono", 22)
    d.text((bx+28, 92), PROMPT_TAG, font=f_tag, fill=TEXT_MED)
    bb = d.textbbox((bx+28, 92), PROMPT_TAG, font=f_tag)
    d.rectangle([bb[2]+8, bb[1]+4, bb[2]+20, bb[3]-2], fill=TEXT_MED)
    f_title = font("title", 130)
    title_y = 145
    d.text((bx+28, title_y), TITLE, font=f_title, fill=TEXT_HI)
    tb = d.textbbox((bx+28, title_y), TITLE, font=f_title)
    uy = tb[3] + 14
    d.rectangle([bx+28, uy, bx+28+220, uy+5], fill=ACCENT)
    f_sub = font("sans_b", 24)
    d.text((bx+28, uy+28), SUBTITLE, font=f_sub, fill=TEXT_MED)
    f_tagln = font("mono", 16)
    d.text((bx+28, uy+68), TAG_LINE, font=f_tagln, fill=TEXT_LO)
    f_auth_lab = font("mono", 18); f_auth_n = font("sans_b", 28)
    ay = H - 110
    d.text((bx+28, ay), "AUTHOR", font=f_auth_lab, fill=TEXT_LO)
    d.text((bx+28, ay+22), AUTHOR, font=f_auth_n, fill=TEXT_HI)
    f_url = font("mono", 18)
    ub = d.textbbox((0,0), SITE_URL, font=f_url)
    d.text((W - (ub[2]-ub[0]) - 56, H-60), SITE_URL, font=f_url, fill=TEXT_MED)
    chip_text = "RE  //  TLP:WHITE"; f_chip = font("mono", 16)
    cb = d.textbbox((0,0), chip_text, font=f_chip)
    cw, ch = cb[2]-cb[0], cb[3]-cb[1]
    px, py = 16, 10
    cx2, cy1 = W-56, 56
    cx1 = cx2 - cw - 2*px; cy2 = cy1 + ch + 2*py
    d.rectangle([cx1, cy1, cx2, cy2], outline=BORDER, width=1)
    d.text((cx1+px, cy1+py-2), chip_text, font=f_chip, fill=TEXT_MED)
    d.rectangle([0,0,W-1,H-1], outline=(40,40,46), width=1)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    img.save(OUT_PATH, format="JPEG", quality=92, optimize=True)
    print(f"wrote {OUT_PATH}  size={os.path.getsize(OUT_PATH)} bytes")

if __name__ == "__main__":
    random.seed(29)
    render()
