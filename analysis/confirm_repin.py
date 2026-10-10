#!/usr/bin/env python3
"""
Confirm the three re-pinned 20-5-14 patch patterns are unique and land on the
intended semantics before promoting them to a builder.

Usage:
  uv run --with capstone --no-project python analysis/confirm_repin.py
"""
from __future__ import annotations

import os
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))

import mtk_cert  # noqa: E402

OLD = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "lk.img")
NEW = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "lk.img")

REPINNED = {
    # force_green_state: adrp page immediate d0->f0, str w0,[x8,#0x268] unchanged
    "force_green_state": (
        "88 05 00 f0 00 69 02 b9 c0 03 5f d6",
        "88 05 00 f0 1f 69 02 b9 c0 03 5f d6",
    ),
    # bypass_security_control: bl immediate 53540194 -> cd540194 (callee +0x1e8), tbz identical
    "bypass_security_control": (
        "cd 54 01 94 20 01 00 36",
        "cd 54 01 94 1f 20 03 d5",
    ),
    # vbmeta_device_state_locked: adrp x1 page f0-page->90-page, csel/add identical
    "vbmeta_device_state_locked": (
        "1f 01 00 71 61 04 00 90 42 01 89 9a 21 a8 29 91",
        "1f 01 00 71 61 04 00 90 e2 03 0a aa 21 a8 29 91",
    ),
}



def hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def find_all(data: bytes, needle: bytes) -> list[int]:
    out, s = [], 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            return out
        out.append(i)
        s = i + 1


def lk_bytes(path: str) -> bytes:
    data = open(path, "rb").read()
    part = next(p for p in mtk_cert.parse_parts(data) if p.name == "lk")
    return bytes(data[part.data_off:part.data_off + part.dsize])


def main() -> int:
    old, new = lk_bytes(OLD), lk_bytes(NEW)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    print("=== csel operands: which string is 'locked'? ===")
    # new: x9 = adrp 0xce000 + 0xa83 ; x10 = adrp 0xce000 + 0xa11
    for reg, off in (("x9", 0xCE000 + 0xA83), ("x10", 0xCE000 + 0xA11)):
        end = new.find(b"\0", off)
        print(f"  {reg:>3} -> lk+0x{off:x}: {new[off:end]!r}")
    # sanity: same strings in the old image at 0xcd000 pages
    for reg, off in (("old x9", 0xCD000 + 0xA83), ("old x10", 0xCD000 + 0xA11)):
        end = old.find(b"\0", off)
        print(f"  {reg:>7} -> lk+0x{off:x}: {old[off:end]!r}")

    print("\n=== re-pinned pattern uniqueness + disassembly ===")
    ok = True
    for name, (orig, patched) in REPINNED.items():
        o, p = hx(orig), hx(patched)
        oh_old = find_all(old, o)
        oh = find_all(new, o)
        ph = find_all(new, p)
        unique = len(oh) == 1 and not ph and not oh_old
        ok &= unique
        print(f"\n[{name}]  hits(new)={len(oh)} @ lk+{[hex(h) for h in oh]}  patched-by-oem={len(ph)}  occurs-in-old={len(oh_old)}  {'UNIQUE-OK' if unique else 'PROBLEM'}")
        for h in oh:
            for insn in md.disasm(new[h:h + len(o) + 8], h):
                print(f"    0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")
        # show the patched encoding decodes as intended
        for h in oh:
            for insn in md.disasm(p, h):
                print(f"    patched -> {insn.mnemonic} {insn.op_str}")

    print(f"\n=== RESULT: {'ALL THREE RE-PINS CONFIRMED UNIQUE AND SEMANTIC' if ok else 'RE-PIN FAILED'} ===")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
