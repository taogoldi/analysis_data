#!/usr/bin/env python3
"""Shared helpers for static Mirai ELF analysis."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def run_cmd(args: List[str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        err = proc.stderr.strip()
        raise RuntimeError(f"command failed ({' '.join(args)}): {err}")
    return proc.stdout


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_objdump_sections(text: str) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    # Example line:
    #  2 .text         000146d8 0000000000400100 TEXT
    rx = re.compile(r"^\s*(\d+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S+)\s*$")
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        idx, name, size_hex, vma_hex, section_type = m.groups()
        rows.append(
            {
                "idx": int(idx),
                "name": name,
                "size": int(size_hex, 16),
                "vma": int(vma_hex, 16),
                "type": section_type,
            }
        )
    return rows


def parse_nm_symbols(text: str) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    # Example:
    # 00000000004002a0 T main
    #                  w _Jv_RegisterClasses
    rx = re.compile(r"^\s*([0-9a-fA-F]*)\s+([A-Za-z])\s+(.+)$")
    for line in text.splitlines():
        m = rx.match(line)
        if not m:
            continue
        addr_s, sym_type, name = m.groups()
        addr: Optional[int] = int(addr_s, 16) if addr_s else None
        rows.append({"address": addr, "type": sym_type, "name": name.strip()})
    return rows


def symbols_by_name(symbols: Iterable[Dict[str, object]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for sym in symbols:
        name = str(sym["name"])
        addr = sym.get("address")
        if isinstance(addr, int):
            out[name] = addr
    return out


def parse_objdump_hexdump(section_dump: str) -> Dict[int, int]:
    """
    Parse `objdump -s -j .rodata` lines into a VA->byte map.

    Expected row format:
      414980 64206c65 6e3d2564 0a003134 342e3137
    """
    byte_map: Dict[int, int] = {}
    rx = re.compile(r"^\s*([0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{8}\s+){1,4})")
    for line in section_dump.splitlines():
        m = rx.match(line)
        if not m:
            continue
        base = int(m.group(1), 16)
        hex_groups = m.group(2).split()
        blob = bytes.fromhex("".join(hex_groups))
        for i, b in enumerate(blob):
            byte_map[base + i] = b
    return byte_map


def read_c_string(byte_map: Dict[int, int], start: int, max_len: int = 2048) -> str:
    data = bytearray()
    for i in range(max_len):
        b = byte_map.get(start + i)
        if b is None or b == 0:
            break
        data.append(b)
    return data.decode("utf-8", errors="replace")


def collect_strings(path: Path, min_len: int = 4) -> List[str]:
    out = run_cmd(["strings", "-a", "-n", str(min_len), str(path)])
    return [line.strip() for line in out.splitlines() if line.strip()]


def extract_ipv4_candidates(strings_list: Iterable[str]) -> List[str]:
    rx = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    out: List[str] = []
    for s in strings_list:
        for m in rx.findall(s):
            try:
                ipaddress.ip_address(m)
            except ValueError:
                continue
            out.append(m)
    return sorted(set(out))


def is_public_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return isinstance(ip, ipaddress.IPv4Address) and ip.is_global


def extract_domain_like(strings_list: Iterable[str]) -> List[str]:
    rx = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,24}\b")
    out: List[str] = []
    for s in strings_list:
        for m in rx.findall(s):
            if "/" in m:
                continue
            out.append(m.lower())
    return sorted(set(out))


def get_first_elf(input_dir: Path) -> Path:
    cands = sorted(input_dir.glob("*.elf"))
    if not cands:
        raise FileNotFoundError(f"no .elf files under {input_dir}")
    return cands[0]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj: object) -> None:
    import json

    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")


def key_bot_symbols(symbol_names: Iterable[str]) -> List[str]:
    wants = {
        "main",
        "verify_server_ip",
        "force_sigkill",
        "killer_thread_func",
        "daemonize_process",
        "disable_infection_tools",
        "scan_and_kill",
        "cmdline_scan_match",
        "memory_scan_match",
        "are_infection_tools_disabled",
        "get_local_ip",
        "method_udp",
        "method_syn",
        "method_ack",
        "method_udpslam",
        "method_junk",
        "method_raknet",
        "method_udpburst",
        "udp_worker",
        "udpburst_worker",
        "udpslam_worker",
        "tcp_worker",
        "tcp_ack_worker",
        "raknet_worker",
        "init_payload_set",
    }
    out: List[str] = []
    for name in sorted(set(symbol_names)):
        if name in wants or name.startswith("method_") or name.endswith("_worker"):
            out.append(name)
    return out

