#!/usr/bin/env python3
"""
Re-pin the two LK patch sites that were recompiled in 20-5-14.

bypass_security_control   old lk+0x4d7fc  (bl sec-control; tbz w0,#0)
vbmeta_device_state_locked old lk+0x7c1e4 (cmp/branch; csel -> locked/open)

Both sit below the first code-insertion point, so their functions are at the
same offsets in 20-5-14; only the instruction selection changed. This script
disassembles both windows in both builds with capstone and prints them
side-by-side so the new patch bytes can be chosen against real instructions.

Usage:
  uv run --with capstone --no-project python analysis/repin_20_5_14.py
"""
from __future__ import annotations

import difflib
import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))

import mtk_cert  # noqa: E402

OLD = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "lk.img")
NEW = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "lk.img")

SITES = {
    "bypass_security_control": 0x4D7FC,
    "vbmeta_device_state_locked": 0x7C1E4,
}
WINDOW_BEFORE = 0x60
WINDOW_AFTER = 0x60


def lk_bytes(path: str) -> bytes:
    data = open(path, "rb").read()
    part = next(p for p in mtk_cert.parse_parts(data) if p.name == "lk")
    return bytes(data[part.data_off:part.data_off + part.dsize])


def disasm(data: bytes, start: int, length: int) -> list[str]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    out = []
    for insn in md.disasm(data[start:start + length], start):
        out.append(f"0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")
    return out


def main() -> int:
    old, new = lk_bytes(OLD), lk_bytes(NEW)

    anchors = [
        b"androidboot.vbmeta.device_state",
        b"verifiedbootstate",
        b"Security control",
        b"preflash",
    ]
    print("=== string anchors ===")
    for a in anchors:
        print(f"  {a.decode():<36} old=0x{old.find(a):x} new=0x{new.find(a):x}")

    for name, site in SITES.items():
        lo = site - WINDOW_BEFORE
        print(f"\n=== {name} (old lk+0x{site:x}) ===")
        old_lines = disasm(old, lo, WINDOW_BEFORE + WINDOW_AFTER)
        new_lines = disasm(new, lo, WINDOW_BEFORE + WINDOW_AFTER)
        for line in difflib.unified_diff(old_lines, new_lines, fromfile="20-5-12", tofile="20-5-14", lineterm="", n=6):
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                print(line)
            elif line.startswith(("+++", "---", "@@")):
                print(line)

        print("\n--- new build window ---")
        for l in new_lines:
            print(f"  {l}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
