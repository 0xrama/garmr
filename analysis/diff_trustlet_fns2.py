#!/usr/bin/env python3
"""
E (robust): semantic fingerprint of the two rebuilt trustlet regions,
prologue-aligned, comparing call-target multisets and adrp page sets.

Usage:
  uv run --with capstone --no-project python analysis/diff_trustlet_fns2.py
"""
from __future__ import annotations

import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

OLD = os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet.tlbin")
NEW = os.path.join(ROOT, "poc/trustlet_patch/stock_trustlet_20_5_14.tlbin")

REGIONS = [
    ("region A", 0x1A848, 0x1BAD5),
    ("region B", 0x33417, 0x34C0E),
]

PROLOGUE = re.compile(rb"\xfd\x7b[\x90-\xbf\xa9]a9|[\x00-\xff]\x7b[ba\xa9]", re.DOTALL)


def find_prologue(data: bytes, before: int) -> int:
    """Nearest `stp x29, x30, [sp, #-imm]!` (fd 7b ?? a9) at or before `before`."""
    i = before & ~3
    while i > 0x80:
        w = int.from_bytes(data[i : i + 4], "little")
        # stp x29,x30,[sp,#-imm]!  => 0xA9????FD | FD 7B ?? A9 little-endian
        if data[i] == 0xFD and data[i + 1] == 0x7B and (w & 0xFFE00C00) == 0xA9800000:
            # mask: opcode a98.. with pre-index writeback, x29,x30 pair
            return i
        i -= 4
    return before


def fingerprint(data: bytes, lo: int, hi: int, md):
    insns = list(md.disasm(data[lo:hi], lo))
    calls = Counter()
    pages = Counter()
    mn = []
    for i in insns:
        if i.mnemonic in ("bl", "b") and i.op_str.startswith("#0x"):
            calls[(i.mnemonic, i.op_str)] += 1
        if i.mnemonic == "adrp":
            m = re.search(r"#(0x[0-9a-f]+)", i.op_str)
            if m:
                pages[m.group(1)] += 1
        mn.append(i.mnemonic)
    return insns, calls, pages, mn


def main() -> int:
    old = open(OLD, "rb").read()
    new = open(NEW, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True

    for name, lo, hi in REGIONS:
        po, pn = find_prologue(old, lo), find_prologue(new, lo)
        print(f"\n===== {name} 0x{lo:x}..0x{hi:x} =====")
        print(f"  prologue-aligned: old @0x{po:x}, new @0x{pn:x}")
        io, co, pg_o, mo = fingerprint(old, po, hi, md)
        iN, cN, pg_N, mN = fingerprint(new, pn, hi, md)
        print(f"  insns: old {len(io)}, new {len(iN)}")

        # mnemonic-sequence similarity
        sm = difflib_seq_ratio(mo, mN)
        print(f"  mnemonic-sequence similarity: {sm:.2%}")

        co_c, cN_c = Counter(co), Counter(cN)
        only_old = co_c - cN_c
        only_new = cN_c - co_c
        print(f"  call targets only in OLD: {dict(only_old) if only_old else 'none'}")
        print(f"  call targets only in NEW: {dict(only_new) if only_new else 'none'}")
        print(f"  adrp pages OLD: {dict(pg_o)}")
        print(f"  adrp pages NEW: {dict(pg_N)}")

        # do any NEW instructions call is_locked or touch the RoT page?
        hot = [l for l in (f"0x{i.address:06x} {i.mnemonic} {i.op_str}" for i in iN)
               if "0x19ec0" in l or "0x73000" in l or "0x72000" in l]
        print(f"  NEW refs to is_locked/0x73000/0x72000: {hot if hot else 'none'}")


def difflib_seq_ratio(a, b):
    import difflib

    return difflib.SequenceMatcher(None, a, b).ratio()


if __name__ == "__main__":
    raise SystemExit(main())
