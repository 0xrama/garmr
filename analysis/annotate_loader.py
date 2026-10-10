#!/usr/bin/env python3
"""
Annotate the Kinibi MCLF loader (0x5eac4..0x5ef98) with the driver-command
IDs each call targets, so the exact position and failure-handling of cmd 0xad
(the presumed verify step, checked at 0x5ebf0) can be read off.

Usage:
  uv run --with capstone --no-project python analysis/annotate_loader.py
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

K12 = os.path.join(HERE, "kinibi_core.bin")
LOADER_LO, LOADER_HI = 0x5EAC4, 0x5F000
KINIBI_BASE = 0x08000000


def main() -> int:
    data = open(K12, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True

    # 1) wrapper map: for known wrapper entries, extract the cmd id (movz w0,#imm)
    wrappers = {}
    known = [0x65998, 0x659B0, 0x65AB0, 0x65AC8, 0x65AE0, 0x65B04, 0x65B3C, 0x65B60,
             0x65BC0, 0x65BE0, 0x65C88, 0x65CC8, 0x65D00, 0x65D18, 0x65D34, 0x65D58,
             0x65D70, 0x65D94, 0x65DBC, 0x65DE4, 0x65E0C, 0x65E4C, 0x65E94, 0x65EDC,
             0x65F24, 0x65F4C]
    for w in known:
        for insn in md.disasm(data[w : w + 0x40], w):
            if insn.mnemonic in ("mov", "movz") and re.match(r"^w0, #0x[0-9a-f]+$", insn.op_str):
                wrappers[w] = int(insn.op_str.split("#")[1], 16)
                break
            if insn.mnemonic in ("blr", "br", "ret"):
                break
    print("wrapper cmd map:")
    for w in sorted(wrappers):
        print(f"  0x{w:06x} -> cmd 0x{wrappers[w]:x}")

    # 2) annotated loader disassembly
    print(f"\nloader 0x{LOADER_LO:x}..0x{LOADER_HI:x} (bl targets annotated):")
    for insn in md.disasm(data[LOADER_LO:LOADER_HI], LOADER_LO):
        note = ""
        if insn.mnemonic == "bl":
            tgt = int(insn.op_str.strip("#"), 16)
            if tgt in wrappers:
                note = f"   ; <<< driver cmd 0x{wrappers[tgt]:x}"
        print(f"  0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
