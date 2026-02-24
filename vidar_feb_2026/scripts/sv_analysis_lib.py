#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass
class PESection:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int


@dataclass
class PEInfo:
    image_base: int
    sections: List[PESection]

    def rva_to_off(self, rva: int) -> Optional[int]:
        for sec in self.sections:
            span = max(sec.vsize, sec.raw_size)
            if sec.va <= rva < sec.va + span:
                return sec.raw_ptr + (rva - sec.va)
        return None

    def va_to_off(self, va: int) -> Optional[int]:
        return self.rva_to_off(va - self.image_base)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def parse_pe(path: Path) -> Tuple[PEInfo, bytes]:
    b = path.read_bytes()
    if b[:2] != b"MZ":
        raise ValueError(f"{path} is not an MZ executable")

    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    if b[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ValueError(f"{path} does not contain a valid PE header")

    num_sections = struct.unpack_from("<H", b, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", b, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", b, e_lfanew + 24)[0]

    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", b, e_lfanew + 24 + 24)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", b, e_lfanew + 24 + 28)[0]
    else:
        raise ValueError(f"Unsupported PE optional header magic: {magic:#x}")

    section_off = e_lfanew + 24 + opt_size
    sections: List[PESection] = []
    for i in range(num_sections):
        o = section_off + i * 40
        raw_name = b[o : o + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("latin1", "ignore")
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", b, o + 8)
        sections.append(PESection(name=name, va=va, vsize=vsize, raw_ptr=raw_ptr, raw_size=raw_size))

    return PEInfo(image_base=image_base, sections=sections), b


def read_va(data: bytes, pe: PEInfo, va: int, size: int) -> bytes:
    off = pe.va_to_off(va)
    if off is None:
        raise ValueError(f"VA {va:#x} is not mapped to a raw file offset")
    return data[off : off + size]


def read_u32_va(data: bytes, pe: PEInfo, va: int) -> int:
    blob = read_va(data, pe, va, 4)
    return struct.unpack_from("<I", blob, 0)[0]


def pkcs7_unpad(buf: bytes) -> bytes:
    if not buf:
        return buf
    n = buf[-1]
    if n == 0 or n > 16:
        return buf
    if len(buf) < n:
        return buf
    if buf[-n:] != bytes([n]) * n:
        return buf
    return buf[:-n]


def aes256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES-CBC IV must be 16 bytes, got {len(iv)}")

    try:
        from Cryptodome.Cipher import AES  # type: ignore

        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    except Exception:
        pass

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        from cryptography.hazmat.backends import default_backend  # type: ignore

        dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
        return dec.update(ciphertext) + dec.finalize()
    except Exception:
        pass

    proc = subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-d",
            "-nopad",
            "-K",
            key.hex(),
            "-iv",
            iv.hex(),
        ],
        input=ciphertext,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"OpenSSL decryption failed: {proc.stderr.decode('utf-8', 'ignore').strip()}")
    return proc.stdout


def extract_stage2(
    sample: Path,
    enc_blob_va: int,
    enc_size_va: int,
    key_va: int,
    iv_va: int,
    out_dir: Path,
) -> Dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)

    pe, data = parse_pe(sample)
    enc_size = read_u32_va(data, pe, enc_size_va)
    enc_blob = read_va(data, pe, enc_blob_va, enc_size)
    key = read_va(data, pe, key_va, 32)
    iv = read_va(data, pe, iv_va, 16)

    dec_raw = aes256_cbc_decrypt(enc_blob, key, iv)
    dec_unpadded = pkcs7_unpad(dec_raw)

    p_enc = out_dir / "enc_blob.bin"
    p_key = out_dir / "aes_key.hex"
    p_iv = out_dir / "aes_iv.hex"
    p_raw = out_dir / "stage2_dec_raw.bin"
    p_unpadded = out_dir / "stage2_dec_unpadded.bin"

    p_enc.write_bytes(enc_blob)
    p_key.write_text(key.hex(), encoding="utf-8")
    p_iv.write_text(iv.hex(), encoding="utf-8")
    p_raw.write_bytes(dec_raw)
    p_unpadded.write_bytes(dec_unpadded)

    return {
        "sample": str(sample),
        "sample_sha256": sha256_file(sample),
        "image_base": hex(pe.image_base),
        "enc_blob_va": hex(enc_blob_va),
        "enc_size_va": hex(enc_size_va),
        "enc_size": enc_size,
        "key_va": hex(key_va),
        "iv_va": hex(iv_va),
        "enc_sha256": hashlib.sha256(enc_blob).hexdigest(),
        "dec_raw_sha256": hashlib.sha256(dec_raw).hexdigest(),
        "dec_unpadded_sha256": hashlib.sha256(dec_unpadded).hexdigest(),
        "dec_starts_mz": dec_unpadded[:2] == b"MZ",
        "outputs": {
            "enc_blob": str(p_enc),
            "aes_key_hex": str(p_key),
            "aes_iv_hex": str(p_iv),
            "stage2_dec_raw": str(p_raw),
            "stage2_dec_unpadded": str(p_unpadded),
        },
    }


def extract_patch_bytes(sample: Path) -> Dict[str, str]:
    pe, data = parse_pe(sample)

    amsi = read_va(data, pe, 0x140005120, 6)
    etw_primary = read_va(data, pe, 0x1400A3570, 3)
    etw_fallback = read_va(data, pe, 0x1400A3580, 3)

    return {
        "amsi_patch_hex": amsi.hex(),
        "amsi_patch_meaning": "mov eax, 0x80070057 ; ret",
        "etw_patch_hex": etw_primary.hex(),
        "etw_patch_meaning": "xor eax, eax ; ret",
        "etw_fallback_patch_hex": etw_fallback.hex(),
        "etw_fallback_patch_meaning": "ret 0x14",
    }


def query_stage1_behavior(sqlite_path: Path) -> Dict[str, object]:
    con = sqlite3.connect(str(sqlite_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    def fetch_one_name(name: str) -> Optional[sqlite3.Row]:
        return cur.execute("select * from functions where name = ?", (name,)).fetchone()

    key_funcs = [
        "sub_140002EA0",
        "sub_140002F00",
        "sub_140003130",
        "sub_1400031C0",
        "sub_140003260",
        "sub_140003320",
        "sub_140003470",
        "sub_140003500",
        "sub_140003AA0",
        "sub_140003E50",
    ]

    functions: List[Dict[str, object]] = []
    for fn in key_funcs:
        row = fetch_one_name(fn)
        if not row:
            continue
        constants = cur.execute(
            "select constant from constants where func_id = ? order by constant", (row["id"],)
        ).fetchall()
        functions.append(
            {
                "name": row["name"],
                "address": row["address"],
                "rva": row["rva"],
                "constants": [x[0] for x in constants],
            }
        )

    anti_sandbox_hits = cur.execute(
        """
        select f.name, f.address, f.rva, c.constant
        from constants c
        join functions f on f.id = c.func_id
        where lower(c.constant) like '%cuckoo%'
           or lower(c.constant) like '%sandbox%'
           or lower(c.constant) like '%sbie%'
           or lower(c.constant) like '%wine%'
           or lower(c.constant) like '%maltest%'
           or lower(c.constant) like '%agent.py%'
        order by f.address
        """
    ).fetchall()

    return {
        "key_functions": functions,
        "anti_sandbox_indicators": [dict(x) for x in anti_sandbox_hits],
    }


def import_table(path: Path) -> Dict[str, List[str]]:
    pe, data = parse_pe(path)

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    opt_off = e_lfanew + 24
    dd_off = opt_off + (0x70 if magic == 0x20B else 0x60)
    imp_rva, _imp_sz = struct.unpack_from("<II", data, dd_off + 8)
    imp_off = pe.rva_to_off(imp_rva)
    if imp_off is None:
        return {}

    imports: Dict[str, List[str]] = {}
    o = imp_off
    while True:
        oft, _timestamp, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, o)
        if (oft, name_rva, ft) == (0, 0, 0):
            break
        name_off = pe.rva_to_off(name_rva)
        if name_off is None:
            break
        dll_end = data.find(b"\x00", name_off)
        dll = data[name_off:dll_end].decode("latin1", "ignore")

        thunk_rva = oft or ft
        thunk_off = pe.rva_to_off(thunk_rva)
        fnames: List[str] = []
        if thunk_off is not None:
            while True:
                if magic == 0x20B:
                    val = struct.unpack_from("<Q", data, thunk_off)[0]
                    step = 8
                    ordinal_flag = 1 << 63
                else:
                    val = struct.unpack_from("<I", data, thunk_off)[0]
                    step = 4
                    ordinal_flag = 1 << 31

                if val == 0:
                    break
                if val & ordinal_flag:
                    fnames.append(f"ordinal_{val & 0xFFFF}")
                else:
                    hn_off = pe.rva_to_off(val)
                    if hn_off is None:
                        fnames.append("<bad_rva>")
                    else:
                        end = data.find(b"\x00", hn_off + 2)
                        fn = data[hn_off + 2 : end].decode("latin1", "ignore")
                        fnames.append(fn)
                thunk_off += step

        imports[dll] = fnames
        o += 20

    return imports


def suspicious_strings(path: Path) -> List[str]:
    data = path.read_bytes()
    hits: List[str] = []
    needles = (
        "http",
        "www.",
        "/api",
        "cookie",
        "user-agent",
        "mozilla",
        "chrome",
        "wininet",
        "winhttp",
        "socket",
        "connect",
        "upload",
        "download",
        "beacon",
        "sandbox",
        "cuckoo",
        "amsi",
        "etw",
    )

    i = 0
    while i < len(data):
        j = i
        while j < len(data) and 32 <= data[j] < 127:
            j += 1
        if j - i >= 6:
            s = data[i:j].decode("latin1", "ignore")
            low = s.lower()
            if any(n in low for n in needles):
                hits.append(s)
        i = j + 1

    out: List[str] = []
    i = 0
    while i + 1 < len(data):
        j = i
        chars: List[str] = []
        while j + 1 < len(data):
            c = data[j]
            z = data[j + 1]
            if z == 0 and 32 <= c < 127:
                chars.append(chr(c))
                j += 2
            else:
                break
        if len(chars) >= 6:
            s = "".join(chars)
            low = s.lower()
            if any(n in low for n in needles):
                out.append(s)
            i = j
        else:
            i += 1

    deduped = []
    seen = set()
    for s in hits + out:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    return deduped


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True), encoding="utf-8")
