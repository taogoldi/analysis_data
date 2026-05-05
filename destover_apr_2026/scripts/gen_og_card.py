#!/usr/bin/env python3
"""
Generate the OG / Twitter social card for the Destover post.
Output: assets/images/social/destover-card.jpg (1200x630).

Same dark-aesthetic recipe as the site-level card under the blog repo,
specialized for the Destover write-up. Edit the CONFIG block to iterate.
"""

from PIL import Image, ImageDraw, ImageFont
import os
import random

OUT_PATH = "/Users/yakovgoldberg/Projects/blog/assets/images/social/destover-card.jpg"

W, H = 1200, 630

BG       = (12,  12,  14)
PANEL    = (24,  24,  29)
BORDER   = (60,  60,  68)
TEXT_HI  = (240, 240, 240)
TEXT_MED = (170, 170, 175)
TEXT_LO  = (110, 110, 118)
ACCENT   = (227,  60,  73)

TITLE       = "Destover"
SUBTITLE    = "The Sony-Signed Backdoor That Walked Through The Front Door"
TAG_LINE    = "Lazarus  |  DarkSeoul  |  Wiper.A  |  SPE Wiper  |  Nov 2014"
AUTHOR      = "Tao Goldi"
SITE_URL    = "taogoldi.github.io/reverse-engineer"
PROMPT_TAG  = "$ tao@goldi:~/destover"

HEX_DUMP_LINES = [
    "0040766e  E8 CD F9 FF FF                  call    main",
    "00401040  55 8B EC 81 EC 0C 01 00 00      sub     esp, 0x10c",
    "00401047  56 BE 88 3B 41 00               mov     esi, off_413b88",
    "0040104D  68 68 00 41 00                  push    offset str_default",
    "00401052  56                              push    esi",
    "00401053  E8 C5 59 00 00                  call    copy_wide_string",
    "00401058  83 C6 28                        add     esi, 28h",
    "0040105B  81 FE 18 3D 41 00               cmp     esi, 0x413d18",
    "00401061  7C E5                           jl      short loc_401047",
    "                                          ; Authenticode -- SPE Inc.",
    "00410068  32 30 33 2E 31 33 31 2E         '203.131.'",
    "00410088  32 30 38 2E 31 30 35 2E         '208.105.'",
    "                                          ; default placeholder slot",
    "00410xxx  30 2E 30 2E 30 2E 30 00         '0.0.0.0\\0'",
    "                                          ; revoked DigiCert chain",
    "                                          DigiCert Assured ID CSCA-1",
]

FONT_PATHS = {
    "title":  "/System/Library/Fonts/Supplemental/Arial Black.ttf",
    "sans":   "/System/Library/Fonts/Helvetica.ttc",
    "sans_b": "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "mono":   "/System/Library/Fonts/Menlo.ttc",
}


def font(kind, size):
    path = FONT_PATHS[kind]
    if path.endswith(".ttc"):
        return ImageFont.truetype(path, size, index=0)
    return ImageFont.truetype(path, size)


def render():
    img = Image.new("RGB", (W, H), BG)

    # Background hex dump
    bg_layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bgd = ImageDraw.Draw(bg_layer)
    mono_small = font("mono", 14)
    line_h = 20
    y = 18
    while y < H:
        line = random.choice(HEX_DUMP_LINES)
        fade = max(0.35, 1.0 - (y / H) * 0.55)
        col = tuple(int(c * fade) for c in TEXT_LO) + (int(255 * 0.55),)
        bgd.text((24, y), line, font=mono_small, fill=col)
        y += line_h
    img.paste(bg_layer, (0, 0), bg_layer)

    # Left-side darkening for legibility
    grad = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grad)
    for x in range(0, int(W * 0.78)):
        a = int(225 * (1.0 - (x / (W * 0.78)) ** 1.4))
        gd.line([(x, 0), (x, H)], fill=(BG[0], BG[1], BG[2], a))
    img.paste(grad, (0, 0), grad)

    d = ImageDraw.Draw(img)

    # Accent bar
    bar_x = 56
    d.rectangle([bar_x, 90, bar_x + 6, H - 90], fill=ACCENT)

    # Prompt tag with cursor block
    f_tag = font("mono", 22)
    d.text((bar_x + 28, 92), PROMPT_TAG, font=f_tag, fill=TEXT_MED)
    bbox = d.textbbox((bar_x + 28, 92), PROMPT_TAG, font=f_tag)
    cursor_x = bbox[2] + 8
    d.rectangle([cursor_x, bbox[1] + 4, cursor_x + 12, bbox[3] - 2], fill=TEXT_MED)

    # Big title
    f_title = font("title", 130)
    title_y = 145
    d.text((bar_x + 28, title_y), TITLE, font=f_title, fill=TEXT_HI)

    # Underline accent
    tbbox = d.textbbox((bar_x + 28, title_y), TITLE, font=f_title)
    underline_y = tbbox[3] + 14
    d.rectangle([bar_x + 28, underline_y, bar_x + 28 + 220, underline_y + 5], fill=ACCENT)

    # Subtitle
    f_sub = font("sans_b", 26)
    d.text((bar_x + 28, underline_y + 28), SUBTITLE, font=f_sub, fill=TEXT_MED)

    # Tag line
    f_taglne = font("mono", 16)
    d.text((bar_x + 28, underline_y + 70), TAG_LINE, font=f_taglne, fill=TEXT_LO)

    # Author footer
    f_auth_label = font("mono", 18)
    f_auth_name  = font("sans_b", 28)
    auth_y = H - 110
    d.text((bar_x + 28, auth_y), "AUTHOR", font=f_auth_label, fill=TEXT_LO)
    d.text((bar_x + 28, auth_y + 22), AUTHOR, font=f_auth_name, fill=TEXT_HI)

    # Site URL
    f_url = font("mono", 18)
    url_bbox = d.textbbox((0, 0), SITE_URL, font=f_url)
    url_w = url_bbox[2] - url_bbox[0]
    d.text((W - url_w - 56, H - 60), SITE_URL, font=f_url, fill=TEXT_MED)

    # Top-right chip
    chip_text = "RE  //  TLP:WHITE"
    f_chip = font("mono", 16)
    cb = d.textbbox((0, 0), chip_text, font=f_chip)
    cw, ch = cb[2] - cb[0], cb[3] - cb[1]
    pad_x, pad_y = 16, 10
    cx2 = W - 56
    cy1 = 56
    cx1 = cx2 - cw - 2 * pad_x
    cy2 = cy1 + ch + 2 * pad_y
    d.rectangle([cx1, cy1, cx2, cy2], outline=BORDER, width=1)
    d.text((cx1 + pad_x, cy1 + pad_y - 2), chip_text, font=f_chip, fill=TEXT_MED)

    # Outer 1px frame
    d.rectangle([0, 0, W - 1, H - 1], outline=(40, 40, 46), width=1)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    img.save(OUT_PATH, format="JPEG", quality=92, optimize=True)
    print(f"wrote {OUT_PATH}  ({W}x{H})  size={os.path.getsize(OUT_PATH)} bytes")


if __name__ == "__main__":
    random.seed(28)
    render()
