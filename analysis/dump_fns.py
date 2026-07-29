#!/usr/bin/env python3
"""dump_fns.py — disassembler for ad-hoc file-offset windows in lk.img."""
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

IMG = "firmware/V1TDS35H.83-20-5-12/lk.img"
BASE = 0xFFFF000050F00000


def dis(buf, off, length):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    for ins in md.disasm(buf[off : off + length], BASE + off):
        print(f"{ins.address:#x}  {ins.mnemonic:9}{ins.op_str}")


def main():
    off = int(sys.argv[1], 16)
    length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x100
    with open(IMG, "rb") as f:
        buf = f.read()
    dis(buf, off, length)


if __name__ == "__main__":
    main()
