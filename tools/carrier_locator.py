# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 EdLovecraft
"""Reference implementation of the driver-version-independent carrier locator.

Mirrors src/unlock_core.h (ScanImage, ParseCudaElf, LocateSass, LocatePtx,
ClassifyCarrier) so the tests can cross-check the C++ build, and doubles as an
offline check after a driver update:

    python tools/carrier_locator.py                 # active driver, summary
    python tools/carrier_locator.py --json out.json  # machine-readable result
    python tools/carrier_locator.py --cuda-ab        # plus CUDA A/B of the patched carriers (numpy)

Nothing here writes to driver files or to any other process.
"""
from __future__ import annotations

import argparse
import ctypes as c
import hashlib
import json
from pathlib import Path
import struct
import sys
import winreg

CEILING_NITS = 2000
SUPPORTED_SM = 89
ORIGINAL = (0x3F8020C5, 0x3F800000)  # tolerance 1.001, ceiling 1.0
LOWER_BOUND = 0xBA83126F             # -0.001
KNOWN = {  # original SHA-256 -> (label, SHA-256 after the 2000-nit patch)
    "f08e2619636e181ecf0fddbee78488b6719f47521ccb8595b5fb12fff6a8d6c6":
        ("validated sm80 CUBIN", "c30752fe8783535691a64ad3eaa46ae5a865a3beb070c66731af0f34a6bd5e28"),
    "d41d157c91be935c2a84217bb38686d140bcfde70606f640aeeaba8aa0c56776":
        ("validated PTX", "972d512e0ae905ea9dca21d4314f02139479b581111d1983aa4ddc6155bb94b5"),
}
DRTM_TEXT = b".text.truehdr_drtm"
PTX_ENTRY = b".entry truehdr_drtm("
OP_FSETP, OP_FSEL, OP_FMNMX = 0x80B, 0x808, 0x809


class Reject(Exception):
    pass


def float_bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def target_constants(nits: int) -> tuple[int, int]:
    return float_bits((nits + 1) / 1000.0), float_bits(nits / 1000.0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_cuda_elf(data: bytes, at: int):
    avail = len(data) - at
    if avail < 64 or data[at:at + 7] != b"\x7fELF\x02\x01\x01" or data[at + 7] not in (0x33, 0x41):
        return None
    phoff, shoff = struct.unpack_from("<QQ", data, at + 0x20)
    flags, = struct.unpack_from("<I", data, at + 0x30)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, at + 0x36)
    if shentsize != 64 or not 0 < shnum <= 4096 or shstrndx >= shnum:
        return None
    if shoff > avail or shnum * 64 > avail - shoff:
        return None
    end = shoff + shnum * 64
    if phnum:
        if phentsize < 56 or phoff > avail or phnum * phentsize > avail - phoff:
            return None
        end = max(end, phoff + phnum * phentsize)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, at + shoff + 64 * i) for i in range(shnum)]
    str_offset, str_size = sections[shstrndx][4], sections[shstrndx][5]
    if str_offset > avail or str_size > avail - str_offset:
        return None
    texts = []
    for name, stype, _, _, offset, size, *_ in sections:
        if stype != 8:
            if offset > avail or size > avail - offset:
                return None
            end = max(end, offset + size)
        if name >= str_size:
            return None
        start = at + str_offset + name
        stop = data.find(b"\0", start, at + str_offset + str_size)
        if stop < 0:
            return None
        if data[start:stop] == DRTM_TEXT:
            texts.append((offset, size))
    abi = data[at + 7]
    sm = flags & 0xFF if abi == 0x33 else (flags >> 8) & 0xFF
    return dict(size=end, sm=sm, abi=abi, texts=texts)


def ptx_target_sm(header: bytes) -> int:
    at = header.find(b".target sm_")
    if at < 0:
        return 0
    i, sm = at + 11, 0
    while i < len(header) and i < at + 15 and 48 <= header[i] <= 57:
        sm = sm * 10 + header[i] - 48
        i += 1
    if i < len(header) and chr(header[i]).isalpha():
        return -1
    return sm


def is_ptx_text(b: int) -> bool:
    return b in (9, 10, 13) or 0x20 <= b < 0x7F


def scan_span(data: bytes, base: int, size: int, rva: int, out: list) -> None:
    span = data[base:base + size]
    pos = 0
    while pos + 8 <= len(span):
        at = span.find(b"\x7fELF\x02\x01\x01", pos)  # same hits as memchr(0x7F) + memcmp in C++
        if at < 0 or len(span) - at < 8:
            break
        pos = at + 1
        if span[at + 7] not in (0x33, 0x41):
            continue
        carrier = dict(kind="CUBIN", rva=rva + at, abi=span[at + 7], span=span, start=at, reason="")
        layout = parse_cuda_elf(span, at)
        if layout:
            if not layout["texts"]:
                continue
            carrier.update(size=layout["size"], sm=layout["sm"], code=layout["texts"][0])
            if len(layout["texts"]) != 1:
                carrier["reason"] = "several .text.truehdr_drtm sections"
            out.append(carrier)
            pos = at + layout["size"]
            continue
        limit = span.find(b"\x7fELF", at + 4)
        limit = len(span) if limit < 0 else limit
        if span.find(DRTM_TEXT, at, limit) >= 0:
            carrier.update(size=limit - at, sm=0, code=(0, 0),
                           reason="unparseable CUDA ELF containing .text.truehdr_drtm")
            out.append(carrier)
    start_from = 0
    while True:
        entry = span.find(PTX_ENTRY, start_from)
        if entry < 0:
            break
        start, floor = entry, max(0, entry - (16 << 20))
        while start > floor and is_ptx_text(span[start - 1]):
            start -= 1
        carrier = dict(kind="PTX", rva=rva + start, abi=0, span=span, start=start, code=(entry - start, 0),
                       sm=ptx_target_sm(span[start:entry]), reason="")
        nul = span.find(b"\0", entry)
        if nul < 0:
            carrier.update(size=len(span) - start, reason="unterminated PTX module")
            out.append(carrier)
            break
        carrier["size"] = nul + 1 - start
        out.append(carrier)
        start_from = nul + 1


def scan_image(data: bytes) -> list:
    """File-layout scan of every initialized, readable, non-executable PE section."""
    if data[:2] != b"MZ":
        raise Reject("not a PE image")
    e_lfanew, = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise Reject("not a PE image")
    machine, count = struct.unpack_from("<HH", data, e_lfanew + 4)
    optional_size, = struct.unpack_from("<H", data, e_lfanew + 20)
    if machine != 0x8664:
        raise Reject("not an x64 PE image")
    table = e_lfanew + 24 + optional_size
    carriers = []
    for i in range(count):
        _, vsize, va, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, table + 40 * i)
        flags, = struct.unpack_from("<I", data, table + 40 * i + 36)
        if not flags & 0x40 or not flags & 0x40000000 or flags & 0x20000000:
            continue
        length = min(raw_size, vsize) if vsize else raw_size
        if not length or raw_ptr >= len(data):
            continue
        scan_span(data, raw_ptr, min(length, len(data) - raw_ptr), va, carriers)
    return carriers


def scan_buffer(data: bytes) -> list:
    """Bare CUBIN/PTX files (test vectors) are scanned as one span at offset 0."""
    if data[:2] == b"MZ":
        return scan_image(data)
    carriers = []
    scan_span(data, 0, len(data), 0, carriers)
    return carriers


def locate_sass(blob: bytes, text: int, text_size: int, k: tuple[int, int]):
    tolerance, ceiling = k
    if not text_size or text_size % 16:
        raise Reject("kernel code size is not a multiple of 16 bytes")
    code = []
    for i in range(text_size // 16):
        lo, hi = struct.unpack_from("<QQ", blob, text + 16 * i)
        code.append(dict(op=lo & 0xFFF, guard=(lo >> 12) & 0xF, ra=(lo >> 24) & 0xFF, imm=lo >> 32,
                         cmp=(hi >> 12) & 0xF, pd=(hi >> 17) & 7, pd2=(hi >> 20) & 7, pp=(hi >> 23) & 0xF))
    imm_form = lambda w: (w["op"] & 0xF00) == 0x800
    tests = []
    for i, w in enumerate(code):
        if imm_form(w) and w["imm"] == tolerance:
            if w["op"] != OP_FSETP:
                raise Reject("the gamut tolerance constant is used by a non-FSETP instruction")
            tests.append(i)
    if len(tests) != 18:
        raise Reject(f"expected 18 gamut tolerance tests, found {len(tests)}")
    for t in tests:
        if code[t]["guard"] != 7:
            raise Reject("a gamut tolerance test is predicated")
        if not any(w["op"] == OP_FSETP and w["imm"] == LOWER_BOUND and w["ra"] == code[t]["ra"]
                   for w in code[max(0, t - 8):t + 9]):
            raise Reject("a gamut tolerance test lacks its -0.001 lower-bound test")
    groups = [[tests[0]]]
    for a, b in zip(tests, tests[1:]):
        if b - a <= 8:
            groups[-1].append(b)
        else:
            groups.append([b])
    if len(groups) != 6:
        raise Reject(f"expected 6 three-channel gamut test groups, found {len(groups)}")
    if any(len(g) != 3 or len({code[i]["ra"] for i in g}) != 3 for g in groups):
        raise Reject("a gamut test group does not cover three distinct channels")
    sites = [(text + 16 * t + 4, True) for t in tests]
    pairs = minima = 0
    for first, second in zip(groups[0::2], groups[1::2]):
        if second[0] - first[-1] > 160:
            raise Reject("the two gamut tests of a path are too far apart")
        candidates = {code[i]["ra"] for i in first}
        tested = candidates | {code[i]["ra"] for i in second}
        begin = second[-1] + 1
        end = min(len(code), begin + 64)
        clamps, paired = {}, set()
        for j in range(begin, end):
            w = code[j]
            if not imm_form(w) or w["imm"] != ceiling or w["ra"] not in tested:
                continue
            if w["op"] == OP_FMNMX:
                if w["pp"] != 7 or w["guard"] != 7:
                    raise Reject("a ceiling FMNMX is not an unconditional minimum")
                clamps.setdefault(w["ra"], []).append([j])
                minima += 1
            elif w["op"] == OP_FSETP:
                if w["cmp"] != 6 or w["pd2"] != 7 or w["pp"] != 7 or w["guard"] != 7:
                    raise Reject("a ceiling comparison is not FSETP.GE.AND Pn, PT, c, ceiling, PT")
                selects = [s for s in range(j + 1, min(end, j + 25))
                           if code[s]["op"] == OP_FSEL and code[s]["imm"] == ceiling and code[s]["ra"] == w["ra"]
                           and code[s]["pp"] == (8 | w["pd"]) and code[s]["guard"] == 7]
                if len(selects) != 1:
                    raise Reject("a ceiling comparison has no unique FSEL partner")
                paired.add(selects[0])
                clamps.setdefault(w["ra"], []).append([j, selects[0]])
                pairs += 1
        for j in range(begin, end):
            w = code[j]
            if w["op"] == OP_FSEL and w["imm"] == ceiling and w["ra"] in tested and j not in paired:
                raise Reject("an FSEL with the ceiling constant is not part of a recognized clamp")
        if len(clamps) != 3:
            raise Reject(f"expected three clamped channels per path, found {len(clamps)}")
        for reg, entries in clamps.items():
            if len(entries) != 1 or reg not in candidates:
                raise Reject("a channel is clamped twice or is not a gamut candidate")
            sites += [(text + 16 * i + 4, False) for i in entries[0]]
    idiom = "FSETP+FSEL" if pairs and not minima else "FMNMX" if minima and not pairs else "mixed"
    return sorted(sites), idiom


def ptx_literal(bits: int) -> bytes:
    return b"0f%08X" % bits


def parse_ptx_statement(blob: bytes, begin: int, end: int):
    space = b" \t\r"
    i = begin
    while i < end and blob[i] in space:
        i += 1
    if i >= end or blob[i] == ord("/"):
        return None

    def token():
        nonlocal i
        start = i
        while i < end and blob[i] not in space:
            i += 1
        value = blob[start:i]
        while i < end and blob[i] in space:
            i += 1
        return value

    first, guarded = token(), False
    if first.startswith(b"@"):
        guarded, first = True, token()
    semicolon = blob.find(b";", i)
    if semicolon < 0 or semicolon >= end:
        return None
    operands, start = [], i
    for j in range(i, semicolon + 1):
        if j != semicolon and blob[j] != ord(","):
            continue
        a, b = start, j
        while a < b and blob[a] in space:
            a += 1
        while b > a and blob[b - 1] in space:
            b -= 1
        operands.append((blob[a:b], a))
        start = j + 1
    return dict(opcode=first, guarded=guarded, operands=operands)


def locate_ptx(blob: bytes, entry: int, k: tuple[int, int]):
    tolerance, ceiling = ptx_literal(k[0]), ptx_literal(k[1])
    lower = ptx_literal(LOWER_BOUND)
    body_end = blob.find(b".entry ", entry + len(PTX_ENTRY))
    body_end = len(blob) if body_end < 0 else body_end
    occurrences = blob.count(tolerance, entry, body_end)
    statements, begin = [], entry
    while begin < body_end:
        end = blob.find(b"\n", begin)
        end = body_end if end < 0 or end > body_end else end
        statement = parse_ptx_statement(blob, begin, end)
        if statement:
            statements.append(statement)
        begin = end + 1
    tests, candidates = [], set()
    for s in statements:
        for o, (text, offset) in enumerate(s["operands"]):
            if text != tolerance:
                continue
            ops = s["operands"]
            if (s["guarded"] or s["opcode"] != b"setp.le.f32" or len(ops) != 3 or o != 2
                    or not ops[0][0].startswith(b"%p") or not ops[1][0].startswith(b"%f")):
                raise Reject("the gamut tolerance literal is used outside setp.le.f32 %p, %f, literal")
            candidates.add(ops[1][0])
            tests.append(offset)
    if occurrences != 18 or len(tests) != 18:
        raise Reject(f"expected 18 gamut tolerance tests, found {len(tests)} of {occurrences} literals")
    if len(candidates) != 9:
        raise Reject(f"expected 9 gamut candidate registers, found {len(candidates)}")
    for candidate in candidates:
        if not any(not s["guarded"] and s["opcode"] == b"setp.ge.f32" and len(s["operands"]) == 3
                   and s["operands"][1][0] == candidate and s["operands"][2][0] == lower for s in statements):
            raise Reject("a gamut candidate lacks its -0.001 lower-bound test")
    clamps, pairs, minima = {}, 0, 0
    for s in statements:
        ops = s["operands"]
        if s["guarded"] or len(ops) != 3 or ops[2][0] != ceiling or ops[1][0] not in candidates:
            continue
        if s["opcode"] == b"setp.ge.f32":
            predicate, value = ops[0][0], ops[1][0]
            selects = [t["operands"][1][1] for t in statements
                       if not t["guarded"] and t["opcode"] == b"selp.f32" and len(t["operands"]) == 4
                       and t["operands"][1][0] == ceiling and t["operands"][2][0] == value
                       and t["operands"][3][0] == predicate]
            if len(selects) != 1:
                raise Reject("a ceiling comparison has no unique selp partner")
            clamps.setdefault(value, []).append([ops[2][1], selects[0]])
            pairs += 1
        elif s["opcode"] == b"min.f32":
            clamps.setdefault(ops[1][0], []).append([ops[2][1]])
            minima += 1
    if len(clamps) != len(candidates):
        raise Reject(f"expected one ceiling clamp per candidate, found {len(clamps)}")
    sites = [(offset, True) for offset in tests]
    for entries in clamps.values():
        if len(entries) != 1:
            raise Reject("a gamut candidate is clamped to the ceiling more than once")
        sites += [(offset, False) for offset in entries[0]]
    idiom = "setp+selp" if pairs and not minima else "min" if minima and not pairs else "mixed"
    return sorted(sites), idiom


def usable_on(carrier: dict, device_sm: int = SUPPORTED_SM) -> bool:
    sm = carrier["sm"]
    if sm == 0:
        return True
    if sm < 0:
        return False
    if carrier["kind"] == "PTX":
        return sm <= device_sm
    return sm // 10 == device_sm // 10 and sm <= device_sm


def classify(carrier: dict, nits: int = CEILING_NITS) -> dict:
    blob = carrier["span"][carrier["start"]:carrier["start"] + carrier["size"]]
    result = dict(kind=carrier["kind"], rva=carrier["rva"], size=carrier["size"], sm=carrier["sm"],
                  abi=carrier["abi"], usable=usable_on(carrier), sha256=sha256(blob), state="invalid",
                  sites=[], idiom="", reason=carrier["reason"], known=None, patched_sha256=None)
    if not carrier["reason"]:
        locate = ((lambda k: locate_sass(blob, carrier["code"][0], carrier["code"][1], k))
                  if carrier["kind"] == "CUBIN" else (lambda k: locate_ptx(blob, carrier["code"][0], k)))
        try:
            result["sites"], result["idiom"] = locate(ORIGINAL)
            result["state"] = "original"
        except Reject as error:
            try:
                result["sites"], result["idiom"] = locate(target_constants(nits))
                result["state"] = "patched"
            except Reject:
                result["reason"] = str(error)
    if result["state"] == "original":
        patched = build_patched(blob, result, nits)
        result["patched_sha256"] = sha256(patched)
        result["patched"] = patched
        if result["sha256"] in KNOWN:
            result["known"] = KNOWN[result["sha256"]][0]
    elif result["state"] == "patched":
        result["known"] = next((label for label, after in KNOWN.values() if after == result["sha256"]), None)
    result["bytes"] = blob
    return result


def build_patched(blob: bytes, result: dict, nits: int) -> bytes:
    out = bytearray(blob)
    target = target_constants(nits)
    for offset, tolerance in result["sites"]:
        before, after = (ORIGINAL[0], target[0]) if tolerance else (ORIGINAL[1], target[1])
        if result["kind"] == "CUBIN":
            assert struct.unpack_from("<I", out, offset)[0] == before
            struct.pack_into("<I", out, offset, after)
        else:
            assert out[offset:offset + 10] == ptx_literal(before)
            out[offset:offset + 10] = ptx_literal(after)
    return bytes(out)


def locate_file(path: Path, nits: int = CEILING_NITS) -> list[dict]:
    return [classify(carrier, nits) for carrier in scan_buffer(Path(path).read_bytes())]


def public(result: dict) -> dict:
    """JSON view, matching the C++ test harness fields."""
    return {key: value for key, value in result.items() if key not in ("bytes", "patched")}


def active_driver_dir() -> Path:
    """The same lookup as the proxy: NVIDIA display devices -> UserModeDriverName."""
    class DisplayDevice(c.Structure):
        _fields_ = [("cb", c.c_ulong), ("DeviceName", c.c_wchar * 32), ("DeviceString", c.c_wchar * 128),
                    ("StateFlags", c.c_ulong), ("DeviceID", c.c_wchar * 128), ("DeviceKey", c.c_wchar * 128)]
    directories = set()
    index = 0
    while True:
        device = DisplayDevice()
        device.cb = c.sizeof(device)
        if not c.windll.user32.EnumDisplayDevicesW(None, index, c.byref(device), 0):
            break
        index += 1
        key = device.DeviceKey
        prefix = "\\Registry\\Machine\\"
        if "ven_10de" not in device.DeviceID.lower() or not key.startswith(prefix):
            continue
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key[len(prefix):]) as handle:
                value, _ = winreg.QueryValueEx(handle, "UserModeDriverName")
        except OSError:
            continue
        for item in value if isinstance(value, list) else [value]:
            path = Path(item)
            if path.is_absolute() and path.name.lower() in ("nvwgf2umx.dll", "nvldumdx.dll"):
                directories.add(path.parent)
    if len(directories) != 1:
        raise RuntimeError(f"cannot identify one active NVIDIA driver directory: {sorted(directories)}")
    return directories.pop()


def luminance(out, pq: bool):
    """Per-pixel luminance in nits of the kernel's scRGB (Rec.709, 80 nits = 1.0) or PQ Rec.2020 output."""
    import numpy as np
    rgb = out[0, :, :3].astype(np.float64)
    if pq:
        pw = np.maximum(rgb, 0) ** (1 / 78.84375)
        rgb = (np.maximum(pw - 0.8359375, 0) / (18.8515625 - 18.6875 * pw)) ** (1 / 0.1593017578125) * 10000
        return rgb @ [0.2627, 0.6780, 0.0593]
    return (rgb * 80) @ [0.2126, 0.7152, 0.0722]


def cuda_ab(results: list[dict]) -> list[dict]:
    """Requested 700/1000/1260/2000 nits, scRGB and PQ, original vs patched, per usable carrier."""
    import numpy as np
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from ptx_cuda_probe import Lab
    rows = []
    lab = Lab(width=257, height=1)
    try:
        ramp = np.zeros((1, 257, 4), np.float32)
        ramp[0, :, :3] = np.linspace(0, 1, 257)[:, None]
        lab.upload(ramp)
        seen = set()
        for result in results:
            if not result["usable"] or result["state"] != "original" or result["sha256"] in seen:
                continue
            seen.add(result["sha256"])
            original, patched = lab.load(result["bytes"]), lab.load(result["patched"])
            for requested in (700, 1000, 1260, 2000):
                for pq in (False, True):
                    params = lab.params(path=1, peak=requested, flag42=1, flag43=int(pq), pq=pq)
                    before, after = lab.run(original, params), lab.run(patched, params)
                    y0, y1 = luminance(before, pq), luminance(after, pq)
                    rows.append(dict(carrier=f"{result['kind']} sm{result['sm']} {result['sha256'][:16]}",
                                     requested=requested, output="PQ" if pq else "scRGB",
                                     original_white=round(float(y0[-1]), 3),
                                     patched_white=round(float(y1[-1]), 3),
                                     original_top19_levels=int(len(np.unique(y0[-19:]))),
                                     patched_top19_levels=int(len(np.unique(y1[-19:]))),
                                     finite=bool(np.isfinite(after).all()),
                                     unchanged_below_1000=bool(requested > 1000 or np.array_equal(before, after))))
    finally:
        lab.close()
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", type=Path,
                        help="driver DLLs or bare CUBIN/PTX files (default: the active driver's two modules)")
    parser.add_argument("--json", type=Path, help="write the full result as JSON")
    parser.add_argument("--cuda-ab", action="store_true", help="run the patched carriers in an owned CUDA context")
    args = parser.parse_args()
    paths = args.paths or [active_driver_dir() / name for name in ("nvAIHDRx.dll", "nvwgf2umx.dll")]
    report, all_results = [], []
    for path in paths:
        results = locate_file(path)
        all_results += results
        report.append(dict(file=str(path), carriers=[public(r) for r in results]))
        print(path)
        for r in results:
            sites = f"{len(r['sites'])} sites ({r['idiom']})" if r["state"] != "invalid" else r["reason"]
            tier = "" if r["state"] == "invalid" else (" tier=known" if r["known"] else " tier=structural")
            print(f"  {r['kind']:5s} sm{r['sm']:<4d} rva=0x{r['rva']:x} size={r['size']} {r['sha256'][:16]} "
                  f"{r['state']}{tier}: {sites}{'' if r['usable'] else ' (not executable on SM 8.9)'}")
    usable = [r for r in all_results if r["usable"]]
    verdict = ("PATCHABLE" if usable and all(r["state"] == "original" for r in usable)
               else "REJECTED")
    print(f"Verdict for the proxy on SM 8.9: {verdict}; usable carriers={len(usable)}, "
          f"structural={sum(1 for r in usable if r['state'] == 'original' and not r['known'])}")
    if args.cuda_ab:
        rows = cuda_ab(all_results)
        for row in rows:
            print(f"  A/B {row['carrier']} {row['requested']:5d} {row['output']:5s} "
                  f"white {row['original_white']:9.3f} -> {row['patched_white']:9.3f}; top19 levels "
                  f"{row['original_top19_levels']:2d} -> {row['patched_top19_levels']:2d}; finite={row['finite']} "
                  f"unchanged<=1000={row['unchanged_below_1000']}")
        report.append(dict(cuda_ab=rows))
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    return 0 if verdict == "PATCHABLE" else 1


if __name__ == "__main__":
    sys.exit(main())
