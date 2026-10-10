#!/usr/bin/env python3
"""
D: who writes the KeyMint trustlet's is_locked() global?

is_locked() (trustlet 0x19ec0) reads [0x73000 + 8]:
    adrp x0, #0x73000 ; ldr w0, [x0, #8] ; cmp w0,#0 ; cset w0, ne ; ret

This sweep finds every access to the 0x73000 page in the trustlet and marks
reads vs WRITES, with context, to determine whether the global is:
  - written from a TCI (HAL/normal-world input buffer)  -> LK/REE spoofable
  - written from an RTM/driver API result               -> deeper TEE state
  - written at load time from a constant

Usage:
  uv run --with capstone --no-project python analysis/trace_rot_input.py
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

STOCK = os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet_20_5_14.tlbin")
TEXT_START = 0x80
WATCH_LO, WATCH_HI = 0x73000, 0x74000


def main() -> int:
    data = open(STOCK, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True

    insns = list(md.disasm(data[TEXT_START:], TEXT_START))
    print(f"decoded {len(insns)} instructions from {STOCK}")

    regs: dict[str, tuple[str, int]] = {}
    hits = []
    for idx, insn in enumerate(insns):
        m, ops = insn.mnemonic, insn.op_str
        try:
            if m == "adrp" and "," in ops:
                reg, target = ops.split(",", 1)
                regs[reg.strip()] = ("page", int(target.strip().strip("#"), 16))
            elif m == "adr" and "," in ops:
                reg, target = ops.split(",", 1)
                regs[reg.strip()] = ("addr", int(target.strip().strip("#"), 16))
            elif m == "add" and ops.count(",") == 2:
                dst, src, imm = [s.strip() for s in ops.split(",")]
                if src in regs and imm.startswith("#"):
                    kind, val = regs[src]
                    regs[dst] = (kind, val + int(imm[1:], 16))
                elif dst != src:
                    regs.pop(dst, None)
            elif m in ("ldr", "ldrb", "ldrh", "str", "strb", "strh", "ldp", "stp") and "[" in ops:
                inner = ops[ops.index("[") + 1 : ops.index("]")]
                parts = [p.strip() for p in inner.split(",")]
                if len(parts) == 1:
                    breg, imm = parts[0], 0
                elif len(parts) == 2 and parts[1].startswith("#"):
                    breg = parts[0]
                    s = parts[1][1:]
                    imm = int(s, 16) if s.startswith("0x") else int(s)
                else:
                    breg, imm = None, 0
                if breg in regs:
                    kind, val = regs[breg]
                    eff = val + imm
                    if WATCH_LO <= eff < WATCH_HI:
                        hits.append((idx, insn, eff))
                if m in ("ldr", "ldrb", "ldr", "ldp") and "," in ops:
                    regs.pop(ops.split(",", 1)[0].strip(), None)
            elif m.startswith("mov") and "," in ops and "[" not in ops:
                dst, src = [s.strip() for s in ops.split(",", 1)]
                if src in regs:
                    regs[dst] = regs[src]
                else:
                    regs.pop(dst, None)
            elif m == "bl":
                regs.clear()
        except (ValueError, IndexError):
            continue

    print(f"accesses to [0x{WATCH_LO:x}, 0x{WATCH_HI:x}): {len(hits)}")
    writes = [(i, insn, eff) for i, insn, eff in hits if insn.mnemonic.startswith("st")]
    reads = [(i, insn, eff) for i, insn, eff in hits if not insn.mnemonic.startswith("st")]
    print(f"  reads : {len(reads)}")
    print(f"  writes: {len(writes)}")

    def show(idx, insn, eff, tag):
        print(f"\n  {tag} eff=0x{eff:x} @0x{insn.address:x}:")
        for j in range(max(0, idx - 8), min(idx + 6, len(insns))):
            mark = "  <==" if j == idx else ""
            print(f"    0x{insns[j].address:06x}  {insns[j].bytes.hex(' '):<14} {insns[j].mnemonic:<8} {insns[j].op_str}{mark}")

    for i, insn, eff in writes:
        show(i, insn, eff, "WRITE")
    # show the is_locked reader for orientation
    for i, insn, eff in reads:
        if eff == 0x73008:
            show(i, insn, eff, "READ(is_locked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
