#!/usr/bin/env python3
"""
C (proper): who writes Kinibi's dispatch pointer [0x54000+0x8c]?

Linear capstone sweep with light register tracking:
  - adrp xN, <page>   -> reg page
  - add  xN, xN, #imm -> reg exact address
  - adr  xN, #target  -> reg exact address (function pointer materialization)
  - ldr/str [xN, #imm]-> report if the effective address lands in the target page

Runs over the Kinibi core (own VA space, base 0x08000000) looking for the
page 0x54000, and over ATF using two candidate code bases while watching
0x08540000. This heuristic is not control-flow/data-flow analysis: indirect
writes and untracked instructions can be missed. It cannot establish which
side initializes the dispatcher or prove that no writer exists.

Usage:
  uv run --with capstone --no-project python analysis/find_handler3.py
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
K12 = os.path.join(HERE, "kinibi_core.bin")

KINIBI_BASE = 0x08000000
PAGE = 0x54000            # kinibi-internal VA page of the dispatch table
WATCH_LO, WATCH_HI = KINIBI_BASE + PAGE, KINIBI_BASE + PAGE + 0x100


class Sweep:
    def __init__(self, data: bytes, base: int, label: str, start: int = 0):
        self.data, self.base, self.label, self.start = data, base, label, start
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.skipdata = True  # chew through headers/data islands

    def run(self):
        regs = {}   # xN -> ('page', addr) | ('addr', addr)
        hits = []
        insns = list(self.md.disasm(self.data[self.start:], self.base + self.start))
        # index by address for context
        by_addr = {i.address: i for i in insns}
        seq = [i.address for i in insns]
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
                    if src in regs and imm.startswith("#0x"):
                        kind, val = regs[src]
                        v = int(imm[1:], 16)
                        regs[dst] = (kind, val + v)
                    elif dst != src:
                        regs.pop(dst, None)
                elif m in ("ldr", "str", "ldp", "stp") and "[" in ops:
                    # ops like: w1, [x0, #0x8c]  /  x2, [x1]
                    br = ops[ops.index("[") : ops.index("]") + 1]
                    inner = br[1:-1]
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
                        if kind == "page":
                            eff = val + imm  # page base + imm
                        if WATCH_LO <= eff < WATCH_HI:
                            hits.append((idx, insn, eff))
                    # invalidate dst on loads
                    if m in ("ldr", "ldp"):
                        dst = ops.split(",", 1)[0].strip()
                        regs.pop(dst, None)
                elif m.startswith("mov") and "," in ops and "[" not in ops:
                    dst, src = [s.strip() for s in ops.split(",", 1)]
                    if src in regs:
                        regs[dst] = regs[src]
                    else:
                        regs.pop(dst, None)
                elif m == "bl":
                    regs.clear()  # conservative: calls clobber
            except (ValueError, IndexError):
                continue
        return hits, insns


def main() -> int:
    kinibi = open(K12, "rb").read()
    sw = Sweep(kinibi, KINIBI_BASE, "kinibi", start=0x240)  # code starts at file 0x240 per KINIBI_MCLF_KEY.md
    hits, insns = sw.run()
    print(f"kinibi: {len(insns)} decoded instructions")
    print(f"accesses to [0x{WATCH_LO:08x}, 0x{WATCH_HI:08x}): {len(hits)}")
    for idx, insn, eff in hits:
        kind = "WRITE" if insn.mnemonic.startswith("st") else "READ "
        ctx_lo = max(0, idx - 3)
        print(f"\n  {kind} eff=0x{eff:08x} via:")
        for j in range(ctx_lo, min(idx + 2, len(insns))):
            mark = "  <==" if j == idx else ""
            print(f"    0x{insns[j].address:08x}  {insns[j].bytes.hex(' '):<14} {insns[j].mnemonic:<8} {insns[j].op_str}{mark}")

    # Same watched Kinibi page, with two candidate ATF code bases.
    data = open(T12, "rb").read()
    parts = mtk_cert.parse_parts(data)
    atf = next(p for p in parts if p.name == "atf")
    atfdata = bytes(data[atf.data_off : atf.data_off + atf.dsize])
    for base in (0x48200000, 0x08000000):
        globals()["WATCH_LO"], globals()["WATCH_HI"] = 0x08000000 + PAGE, 0x08000000 + PAGE + 0x100
        sw = Sweep(atfdata, base, f"atf(base 0x{base:08x})")
        h2, i2 = sw.run()
        print(f"\natf @0x{base:08x}: {len(i2)} decoded, {len(h2)} accesses to kinibi page")
        for idx, insn, eff in h2[:20]:
            kind = "WRITE" if insn.mnemonic.startswith("st") else "READ "
            print(f"  {kind} eff=0x{eff:08x} @0x{insn.address:08x} ({insn.mnemonic} {insn.op_str})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
