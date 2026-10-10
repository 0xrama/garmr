#!/usr/bin/env python3
"""
C: locate the initializer of Kinibi's dispatch pointer [0x54000+0x8c].

KINIBI_MCLF_KEY.md established:
  - every driver wrapper (cmd 0xad/0xac/0x32/...) does ldr wN,[0x54000+0x8c]; blr
  - Kinibi code never writes that pointer -> ATF writes it during handoff
  - the atf partition references the Kinibi BSS page 0x08540000 as data literals

This script dumps every ATF reference to that page (both builds), interprets
the surrounding literals as candidate descriptor entries, and — if a
(dest, value) pair for +0x8c emerges — disassembles the Kinibi code at that
address, which should be the real driver dispatcher.

Usage:
  uv run --with capstone --no-project python analysis/find_handler.py
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))

import mtk_cert  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

T12 = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "tee.img")
T14 = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "tee.img")
K12_PATH = os.path.join(HERE, "kinibi_core.bin")

PAGE_LO, PAGE_HI = 0x08540000, 0x08541000
TARGET = 0x0854008C


def parts_of(path):
    data = open(path, "rb").read()
    return data, mtk_cert.parse_parts(data)


def scan_literals(atf: bytes, label: str):
    print(f"\n=== {label}: u32 literals in [0x{PAGE_LO:08x}, 0x{PAGE_HI:08x}) ===")
    hits = []
    for off in range(0, len(atf) - 4, 4):
        v = struct.unpack_from("<I", atf, off)[0]
        if PAGE_LO <= v < PAGE_HI:
            hits.append((off, v))
    for off, v in hits:
        print(f"  atf+0x{off:06x}: 0x{v:08x}")
    # context: dump u32 grid around each hit
    print(f"\n  context grids:")
    for off, v in hits:
        lo = max(0, off - 0x10)
        hi = min(len(atf), off + 0x14)
        row = " ".join(
            f"{struct.unpack_from('<I', atf, a)[0]:08x}" for a in range(lo, hi, 4)
        )
        mark = " <== 0x8c!" if v == TARGET else ""
        print(f"   0x{off:06x}: {row}{mark}")
    return hits


def main() -> int:
    d12, p12 = parts_of(T12)
    d14, p14 = parts_of(T14)
    atf12 = bytes(d12[next(p for p in p12 if p.name == "atf").data_off:][: next(p for p in p12 if p.name == "atf").dsize])
    atf14 = bytes(d14[next(p for p in p14 if p.name == "atf").data_off:][: next(p for p in p14 if p.name == "atf").dsize])
    print(f"atf12: {len(atf12)} bytes; atf14: {len(atf14)} bytes")

    h12 = scan_literals(atf12, "atf 20-5-12")
    h14 = scan_literals(atf14, "atf 20-5-14")

    # unaligned exact search for 0x0854008c
    needle = struct.pack("<I", TARGET)
    for label, atf in (("12", atf12), ("14", atf14)):
        s, out = 0, []
        while True:
            i = atf.find(needle, s)
            if i < 0:
                break
            out.append(i)
            s = i + 1
        print(f"\nexact 0x0854008c literals in atf {label}: {[hex(x) for x in out] or 'NONE'}")

    # candidate handler: literal right after a 0x0854008c reference
    kinibi = open(K12_PATH, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for label, atf, hits in (("12", atf12, h12), ("14", atf14, h14)):
        for off, v in hits:
            if v != TARGET:
                continue
            for delta in (4, -4):
                a = off + delta
                if 0 <= a < len(atf) - 4:
                    cand = struct.unpack_from("<I", atf, a)[0]
                    if 0x08000000 <= cand < 0x08000000 + len(kinibi):
                        koff = cand - 0x08000000
                        print(f"\n=== candidate handler 0x{cand:08x} (kinibi+0x{koff:x}, from atf {label} 0x{off:x}{delta:+d}) ===")
                        for insn in md.disasm(kinibi[koff : koff + 0x80], koff):
                            print(f"  0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
