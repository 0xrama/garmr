#!/usr/bin/env python3
"""LP metadata reader and entry point for the build-specific compact extractor.

Requires the matching super.img_sparsechunk.* files, not included in this tree.
Use: python3 analysis/extract_trustlet_14.py
"""
from __future__ import annotations

import struct

from carve_trustlet_14 import read_logical

LP_HDR = 0x3000


def lp_partitions(runs):
    hdr = read_logical(runs, LP_HDR, 0x100)
    magic = struct.unpack_from("<I", hdr, 0)[0]
    if magic != 0x414C5030:
        raise ValueError("LP metadata header not found in supplied super chunks")
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


if __name__ == "__main__":
    from erofs_compact import main
    raise SystemExit(main())
