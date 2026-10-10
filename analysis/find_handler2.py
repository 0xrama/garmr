#!/usr/bin/env python3
"""Broader hunt for any reference to the Kinibi 0x54000 page in tee.img."""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))
import mtk_cert  # noqa: E402

T12 = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "tee.img")
T14 = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "tee.img")


def find_all(data, needle):
    out, s = [], 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            return out
        out.append(i)
        s = i + 1


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def main():
    for label, path in (("12", T12), ("14", T14)):
        data = open(path, "rb").read()
        parts = mtk_cert.parse_parts(data)
        atf = next(p for p in parts if p.name == "atf")
        tee = next(p for p in parts if p.name == "tee")
        print(f"\n===== tee.img {label}: atf@0x{atf.data_off:x} tee@0x{tee.data_off:x} =====")

        # 1) unaligned LE u32 in 0x08540000..0x08540fff, anywhere in file
        print("-- unaligned u32 0x0854xxxx (whole file) --")
        n = 0
        for i in range(0, len(data) - 4):
            v = u32(data, i)
            if 0x08540000 <= v < 0x08541000:
                where = "atf" if atf.data_off <= i < atf.data_off + atf.dsize else ("tee" if tee.data_off <= i < tee.data_off + tee.dsize else "other")
                print(f"  0x{i:06x} ({where}): 0x{v:08x}")
                n += 1
                if n > 40:
                    print("  ...")
                    break
        if not n:
            print("  none")

        # 2) u64 form 0x0000000008540xxx
        print("-- u64 0x0000000008540xxx --")
        n = 0
        for i in range(0, len(data) - 8):
            v = struct.unpack_from("<Q", data, i)[0]
            if 0x08540000 <= v < 0x08541000:
                print(f"  0x{i:06x}: 0x{v:016x}")
                n += 1
                if n > 40:
                    break
        if not n:
            print("  none")

        # 3) 0x4854xxxx alias
        print("-- unaligned u32 0x4854xxxx --")
        n = 0
        for i in range(0, len(data) - 4):
            v = u32(data, i)
            if 0x48540000 <= v < 0x48541000:
                print(f"  0x{i:06x}: 0x{v:08x}")
                n += 1
                if n > 40:
                    break
        if not n:
            print("  none")

        # 4) as a cross-check: does the KINIBI part itself reference 0x54000+0x8c?
        kdata = bytes(data[tee.data_off:tee.data_off + tee.dsize])
        needle = struct.pack("<I", 0x0854008C)
        print(f"-- exact 0x0854008c in kinibi data: {[hex(x) for x in find_all(kdata, needle)] or 'none'} --")


if __name__ == "__main__":
    main()
