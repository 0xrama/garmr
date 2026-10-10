#!/usr/bin/env python3
"""
A+B: cert-bypass viability of the 20-5-14 tee.img, and Kinibi-core 12->14
comparison with a re-pin of the MCLF verify-branch bypass.

Usage:
  uv run --with capstone --no-project python analysis/check_tee_14.py
"""
from __future__ import annotations

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))

import mtk_cert  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

T12 = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "tee.img")
T14 = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "tee.img")
K12_PATH = os.path.join(HERE, "kinibi_core.bin")  # 20-5-12 Kinibi core (reference)

# 20-5-12 pinned bypass site (bypass/patch_verify.py)
VERIFY_BRANCH_OFF_12 = 0x5EBF0
ORIG_12 = bytes.fromhex("a0 06 00 34")  # cbz w0, #0x5ecc4


def parts_of(path):
    data = open(path, "rb").read()
    return data, mtk_cert.parse_parts(data)


def find_all(data, needle, start=0):
    out, s = [], start
    while True:
        i = data.find(needle, s)
        if i < 0:
            return out
        out.append(i)
        s = i + 1


def main() -> int:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    d12, p12 = parts_of(T12)
    d14, p14 = parts_of(T14)
    print(f"12 tee.img: {len(d12)} parts {[p.name for p in p12]}")
    print(f"14 tee.img: {len(d14)} parts {[p.name for p in p14]}")

    print("\n=== A: cert verification of 20-5-14 tee.img ===")
    ok = mtk_cert.verify(d14)
    print(f"cert bypass preconditions: {'HOLD' if ok else 'CHANGED'}")

    print("\n=== B: Kinibi core comparison ===")
    k12_ref = open(K12_PATH, "rb").read()
    tee12 = next(p for p in p12 if p.name == "tee")
    tee14 = next(p for p in p14 if p.name == "tee")
    k12 = bytes(d12[tee12.data_off : tee12.data_off + tee12.dsize])
    k14 = bytes(d14[tee14.data_off : tee14.data_off + tee14.dsize])
    print(f"12 kinibi: {len(k12)} sha {hashlib.sha256(k12).hexdigest()[:16]} (ref match: {k12 == k12_ref})")
    print(f"14 kinibi: {len(k14)} sha {hashlib.sha256(k14).hexdigest()[:16]}")
    same = sum(1 for a, b in zip(k12, k14) if a == b)
    print(f"byte identity: {100 * same // max(len(k12), len(k14))}%")

    # show the 12 reference window
    print(f"\n12 bypass window @0x{VERIFY_BRANCH_OFF_12:x}:")
    for insn in md.disasm(k12[VERIFY_BRANCH_OFF_12 - 8 : VERIFY_BRANCH_OFF_12 + 12], VERIFY_BRANCH_OFF_12 - 8):
        print(f"  0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")

    # hunt the equivalent in 14: mov w19,w0 ; cbz w0,#imm  (relaxed imm)
    print("\n14 candidates (mov wN,w0 ; cbz w0,...):")
    for i in find_all(k14, bytes.fromhex("00 34")):
        lo = i - 6
        if lo < 0:
            continue
        w = k14[lo : i + 2]
        insns = list(md.disasm(w, lo))
        if len(insns) != 2:
            continue
        if insns[0].mnemonic == "mov" and insns[0].op_str.endswith(", w0") and insns[1].mnemonic == "cbz" and insns[1].op_str.startswith("w0,"):
            print(f"  @0x{lo:06x}:")
            # widen the window for context
            for insn in md.disasm(k14[lo - 16 : lo + 16], lo - 16):
                print(f"    0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
