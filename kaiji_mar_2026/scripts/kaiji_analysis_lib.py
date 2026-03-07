#!/usr/bin/env python3
"""Reusable helpers for offline Kaiji ELF triage."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24}\b")
IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>]+", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"\b([a-zA-Z0-9.-]+):(\d{2,5})\b")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")


@dataclass
class ElfSection:
    index: int
    name: str
    offset: int
    size: int
    vaddr: int
    flags: int

    @property
    def end_offset(self) -> int:
        return self.offset + self.size


@dataclass
class ExtractedString:
    offset: int
    value: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = float(len(data))
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def parse_elf_sections(path: Path) -> List[ElfSection]:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    if data[4] != 2:
        raise ValueError("Only ELF64 is supported")

    endian = "<" if data[5] == 1 else ">"
    ehdr = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
    (_, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx) = ehdr

    shdr_fmt = endian + "IIQQQQIIQQ"
    shdr_size = struct.calcsize(shdr_fmt)
    if shentsize != shdr_size:
        raise ValueError(f"Unexpected section header size: {shentsize}")

    sections_raw = [struct.unpack_from(shdr_fmt, data, shoff + i * shentsize) for i in range(shnum)]
    shstr = sections_raw[shstrndx]
    shstr_off = shstr[4]
    shstr_size = shstr[5]
    shstrtab = data[shstr_off : shstr_off + shstr_size]

    def sec_name(name_off: int) -> str:
        if name_off >= len(shstrtab):
            return ""
        end = shstrtab.find(b"\x00", name_off)
        if end == -1:
            end = len(shstrtab)
        return shstrtab[name_off:end].decode("utf-8", "ignore")

    out: List[ElfSection] = []
    for i, sh in enumerate(sections_raw):
        name = sec_name(sh[0])
        out.append(
            ElfSection(
                index=i,
                name=name,
                flags=sh[2],
                vaddr=sh[3],
                offset=sh[4],
                size=sh[5],
            )
        )
    return out


def section_by_name(sections: Iterable[ElfSection], name: str) -> Optional[ElfSection]:
    for sec in sections:
        if sec.name == name:
            return sec
    return None


def file_offset_to_va(sections: Iterable[ElfSection], file_offset: int) -> Optional[int]:
    for sec in sections:
        if sec.size == 0:
            continue
        if sec.offset <= file_offset < sec.end_offset:
            return sec.vaddr + (file_offset - sec.offset)
    return None


def extract_ascii_strings(blob: bytes, base_offset: int = 0, min_len: int = 4) -> List[ExtractedString]:
    out: List[ExtractedString] = []
    start = None
    buf = bytearray()

    for idx, b in enumerate(blob):
        if 32 <= b <= 126:
            if start is None:
                start = idx
            buf.append(b)
            continue

        if start is not None and len(buf) >= min_len:
            out.append(ExtractedString(offset=base_offset + start, value=buf.decode("ascii", "ignore")))
        start = None
        buf.clear()

    if start is not None and len(buf) >= min_len:
        out.append(ExtractedString(offset=base_offset + start, value=buf.decode("ascii", "ignore")))

    return out


def dedupe_strings(strings: Iterable[ExtractedString]) -> List[ExtractedString]:
    seen = set()
    out: List[ExtractedString] = []
    for s in strings:
        key = (s.offset, s.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def decode_base64_candidates(strings: Iterable[ExtractedString], printable_threshold: float = 0.70) -> List[Dict[str, object]]:
    out: List[Dict[str, object]] = []
    seen = set()

    for s in strings:
        token = s.value.strip()
        if token in seen:
            continue
        if len(token) < 12 or len(token) % 4 != 0:
            continue
        if not BASE64_RE.match(token):
            continue

        try:
            dec = base64.b64decode(token, validate=True)
        except Exception:
            continue

        if not dec:
            continue

        printable = sum(1 for c in dec if 32 <= c <= 126 or c in (9, 10, 13)) / len(dec)
        if printable < printable_threshold:
            continue

        decoded_text = dec.decode("utf-8", "ignore")
        if not decoded_text or len(decoded_text) < 8:
            continue

        seen.add(token)
        out.append(
            {
                "source_offset": s.offset,
                "source": token,
                "decoded": decoded_text,
                "printable_ratio": round(printable, 4),
                "decoded_entropy": round(shannon_entropy(dec), 4),
            }
        )

    return out


def find_domains_ips_urls(strings: Iterable[str]) -> Dict[str, List[str]]:
    domains = set()
    ipv4 = set()
    urls = set()
    host_ports = set()

    for s in strings:
        for m in DOMAIN_RE.finditer(s):
            domains.add(m.group(0).lower())
        for m in IPV4_RE.finditer(s):
            ipv4.add(m.group(0))
        for m in URL_RE.finditer(s):
            urls.add(m.group(0))
        for m in HOST_PORT_RE.finditer(s):
            host = m.group(1).lower()
            port = int(m.group(2))
            if port < 1 or port > 65535:
                continue
            is_ipv4 = bool(IPV4_RE.fullmatch(host))
            # Drop timestamp-like and format-like junk such as "15:04" or "z07:00".
            if "." not in host and not is_ipv4:
                continue
            if not is_ipv4 and not any(c.isalpha() for c in host):
                continue
            host_ports.add(f"{host}:{port}")

    return {
        "domains": sorted(domains),
        "ipv4": sorted(ipv4),
        "urls": sorted(urls),
        "host_ports": sorted(host_ports),
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def normalize_for_hunt(s: str) -> str:
    return " ".join(s.strip().split())
