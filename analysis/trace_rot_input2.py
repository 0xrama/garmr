#!/usr/bin/env python3
"""
D follow-up: full disassembly of the function that computes is_locked's
input (writer @0x19fa4), plus its callers, to determine whether the value
originates from the TCI (HAL/normal world) or from secure-side state.

Usage:
  uv run --with capstone --no-project python analysis/trace_rot_input2.py
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

STOCK = os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet_20_5_14.tlbin")


def main() -> int:
    data = open(STOCK, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    insns = list(md.disasm(data[0x80:], 0x80))
    by_addr = {i.address: n for n, i in enumerate(insns)}

    def dump(lo, hi, title):
        print(f"\n=== {title} (0x{lo:x}..0x{hi:x}) ===")
        for i in insns:
            if lo <= i.address < hi:
                print(f"  0x{i.address:06x}  {i.bytes.hex(' '):<14} {i.mnemonic:<8} {i.op_str}")

    # Find the function start containing 0x19fa4: scan back for a prologue.
    idx = by_addr.get(0x19FA4)
    start = 0x19E00
    for j in range(idx, max(0, idx - 400), -1):
        if insns[j].mnemonic == "stp" and "x29, x30" in insns[j].op_str and "!" in insns[j].op_str:
            start = insns[j].address
            break
    print(f"writer function prologue scan: start @0x{start:x}")
    dump(start, start + 0x260, "is_locked writer function")

    # Callers of this function
    print(f"\n=== xrefs: bl #0x{start:x} ===")
    for i in insns:
        if i.mnemonic == "bl":
            try:
                t = int(i.op_str.strip("#"), 16)
            except ValueError:
                continue
            if t == start:
                print(f"  caller @0x{i.address:x}")

    # The second device-locked path around 0x1cd5c for context
    dump(0x1CC00, 0x1CDA0, "attestation selection site (0x1cc44/0x1cd5c neighborhood)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
