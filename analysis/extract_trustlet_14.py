#!/usr/bin/env python3
"""
Extract the 20-5-14 KeyMint trustlet from the sparse super via LP metadata +
EROFS, then locate its is_locked() equivalent and compare to the 20-5-12
stock trustlet.

Usage:
  uv run --with capstone --no-project python analysis/extract_trustlet_14.py
"""
from __future__ import annotations

import glob
import os
import re
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from find_trustlet import sparse_runs  # noqa: E402
from carve_trustlet_14 import build_map, read_logical  # noqa: E402
from erofs_reader import Erofs  # noqa: E402

FW = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14")
STOCK_PATH = os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet.tlbin")
OUT = os.path.join(ROOT, "analysis", "trustlet_20_5_14.tlbin")

LP_HDR = 0x3000
TARGET_NAME = "0706000000000000000000000000004d.tlbin"


def chunkkey(fn: str) -> int:
    return int(fn.rsplit(".", 1)[-1])


def lp_partitions(runs):
    hdr = read_logical(runs, LP_HDR, 0x100)
    magic = struct.unpack_from("<I", hdr, 0)[0]
    assert magic == 0x414C5030, hex(magic)
    descs = {}
    for i, name in enumerate(("partitions", "extents", "groups", "block_devices")):
        off, num, esz = struct.unpack_from("<III", hdr, 0x50 + i * 12)
        descs[name] = (LP_HDR + 0x100 + off, num, esz)
    base, num, esz = descs["partitions"]
    tab = read_logical(runs, base, num * esz)
    parts = []
    for i in range(num):
        e = tab[i * esz : (i + 1) * esz]
        pname = e[:36].split(b"\0")[0].decode()
        attr, first, nex, _grp = struct.unpack_from("<IIII", e, 36)
        parts.append((pname, first, nex))
    base, num, esz = descs["extents"]
    tab = read_logical(runs, base, num * esz)
    extents = []
    for i in range(num):
        ns, stype, _tt = struct.unpack_from("<III", tab[i * esz :], 0)
        (tdata,) = struct.unpack_from("<Q", tab[i * esz :], 12)
        extents.append((ns, stype, tdata))
    return parts, extents


def carve_partition(runs, parts, extents, name, out_path):
    for pname, first, num in parts:
        if pname != name:
            continue
        with open(out_path, "wb") as out:
            for i in range(first, first + num):
                ns, _st, tdata = extents[i]
                out.write(read_logical(runs, tdata * 512, ns * 512))
                print(f"  extent {i}: {ns} sectors from super+{tdata * 512:#x}", flush=True)
        return True
    return False


def main() -> int:
    files = sorted(glob.glob(os.path.join(FW, "super.img_sparsechunk.*")), key=chunkkey)
    print(f"building run map for {len(files)} files...", flush=True)
    runs = build_map(files)

    parts, extents = lp_partitions(runs)
    print("logical partitions:")
    for pname, first, nex in parts:
        total = sum(extents[i][0] for i in range(first, first + nex))
        print(f"  {pname:16} extents[{first}..{first + nex})  {total // 2048} MiB")

    tmp_base = os.path.join(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "Temp", "opencode")
    os.makedirs(tmp_base, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tmp_base) as td:
        vendor = os.path.join(td, "vendor.img")
        target = next((p for p, _f, _n in parts if p.startswith("vendor") and not p.endswith("_b")), None)
        if target is None or not carve_partition(runs, parts, extents, target, vendor):
            sys.exit("vendor partition not found")
        print(f"carved vendor -> {vendor} ({os.path.getsize(vendor)} bytes)")

        fs = Erofs(vendor)
        print(f"erofs root nid {fs.rootnid}, incompat 0x{fs.feature_incompat:x}")
        hit = None
        for path, nid, ftype in fs.walk(fs.rootnid):
            if TARGET_NAME in path:
                hit = (path, nid)
                break
        if not hit:
            print(f"{TARGET_NAME} not found in walk; mcRegistry paths seen:")
            for path, nid, ftype in fs.walk(fs.rootnid):
                if "mcRegistry" in path:
                    print(f"  {path}")
            return 1
        path, nid = hit
        print(f"found {path} (nid {nid})")
        ino = fs.inode(nid)
        print(f"inode: size={ino['size']} layout={ino['layout']} version={ino['version']}")
        data = fs.read_data(ino)
        with open(OUT, "wb") as f:
            f.write(data)
        print(f"wrote {OUT} ({len(data)} bytes)")

    stock = open(STOCK_PATH, "rb").read()
    same = sum(1 for a, b in zip(stock, data) if a == b)
    print(f"\nvs 20-5-12 stock: {len(stock)} vs {len(data)} bytes, "
          f"{100 * same // max(len(stock), len(data))}% identical")

    for s in (b"red\x00", b"orange\x00", b"yellow\x00", b"green\x00", b"locked\x00", b"open\x00", b"unlocked\x00"):
        print(f"  {s[:-1].decode():<10} @0x{data.find(s):x}")

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    pat = re.compile(rb"\x00\x08\x40\xb9\x1f\x00\x00\x71.{1,12}?\xc0\x03\x5f\xd6", re.DOTALL)
    print("\nis_locked() candidates (ldr w0,[x0,#8]; cmp w0,#0; ...; ret):")
    for m in pat.finditer(data):
        off = m.start()
        print(f"  @0x{off:x} (stock: 0x19ec0)")
        for insn in md.disasm(data[off - 4 : off + 24], off - 4):
            print(f"    0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
