#!/usr/bin/env python3
"""
Faithful port of the kernel's EROFS compact-index decode (zmap.c) for the
20-5-14 KeyMint trustlet, followed by LZ4 extent extraction.

Usage:
  uv run --with capstone --no-project python analysis/erofs_compact.py
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)


def lz4_decompress_win(src: bytes, max_out: int, win: bytes) -> bytes:
    """LZ4 block decode with a dictionary prefix (EROFS 64KB cross-pcluster
    window: matches may reference output of previous clusters of the file)."""
    out = bytearray()
    base = len(win)
    p, n = 0, len(src)
    while p < n and len(out) < max_out:
        token = src[p]
        p += 1
        lit_len = token >> 4
        if lit_len == 0xF:
            while True:
                b = src[p]
                p += 1
                lit_len += b
                if b != 0xFF:
                    break
        take = min(lit_len, max_out - len(out))
        out += src[p : p + take]
        p += lit_len
        if p >= n or len(out) >= max_out:
            break
        off = src[p] | (src[p + 1] << 8)
        p += 2
        mlen = token & 0xF
        if mlen == 0xF:
            while True:
                b = src[p]
                p += 1
                mlen += b
                if b != 0xFF:
                    break
        mlen += 4
        for _ in range(mlen):
            gpos = base + len(out) - off
            if gpos < 0:
                raise IndexError(f"match before 64K window (off={off})")
            out.append(win[gpos] if gpos < base else out[gpos - base])
    return bytes(out[:max_out])

VENDOR = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp", "opencode", "vendor_20_5_14.img")
STOCK_PATH = os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet.tlbin")
OUT = os.path.join(ROOT, "analysis", "trustlet_20_5_14.tlbin")

BLK = 4096
NID = 147668


def ensure_vendor():
    """Carve vendor_a to a stable temp path if not already present."""
    if os.path.exists(VENDOR) and os.path.getsize(VENDOR) > 800_000_000:
        return
    import glob

    from carve_trustlet_14 import build_map, read_logical  # noqa: E402
    from extract_trustlet_14 import lp_partitions  # noqa: E402

    files = sorted(
        glob.glob(os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "super.img_sparsechunk.*")),
        key=lambda f: int(f.rsplit(".", 1)[-1]),
    )
    runs = build_map(files)
    parts, extents = lp_partitions(runs)
    target = next(p for p, _f, _n in parts if p.startswith("vendor") and not p.endswith("_b"))
    os.makedirs(os.path.dirname(VENDOR), exist_ok=True)
    with open(VENDOR, "wb") as out:
        for pname, first, num in parts:
            if pname != target:
                continue
            for i in range(first, first + num):
                ns, _st, tdata = extents[i]
                out.write(read_logical(runs, tdata * 512, ns * 512))
    print(f"carved {target} -> {VENDOR} ({os.path.getsize(VENDOR)} bytes)")

Z_NONHEAD = 2
Z_HEAD1 = 1
Z_PLAIN = 0
D0_CBLKCNT = 1 << 11


class Img:
    def __init__(self, path):
        self.f = open(path, "rb")

    def rd(self, off, n):
        self.f.seek(off)
        return self.f.read(n)


def decode_entry(pack: bytes, encodebits: int, lobits: int, i: int):
    """Return (lo, type) for entry i inside an 8/32-byte pack."""
    bit = encodebits * i
    v = int.from_bytes(pack[bit // 8 : bit // 8 + 4], "little") >> (bit % 8)
    return v & ((1 << lobits) - 1), (v >> lobits) & 3


class CompactIndex:
    def __init__(self, img: Img, nid: int, size: int, h_advise: int):
        self.img = img
        ino = img.rd(nid * 32, 32)
        xattr_ic = struct.unpack_from("<H", ino, 2)[0]
        xsz = 0 if not xattr_ic else 12 + 4 * (xattr_ic - 1)
        end = nid * 32 + 32 + xsz
        self.ebase = ((end + 7) & ~7) + 8  # map header end
        self.size = size
        self.totalidx = (size + BLK - 1) // BLK
        self.c4i = ((32 - self.ebase % 32) // 4) & 7
        self.c2b = 0
        if (h_advise & 0x0001) and self.c4i < self.totalidx:
            self.c2b = ((self.totalidx - self.c4i) // 16) * 16
        self.lobits = 12  # max(lclusterbits=12, ilog2(D0_CBLKCNT)+1=12)
        print(f"  ebase=0x{self.ebase:x} totalidx={self.totalidx} c4i={self.c4i} c2b={self.c2b}")

    def entry_pos(self, lcn):
        pos = self.ebase
        shift = 2
        if lcn >= self.c4i:
            pos += self.c4i * 4
            lcn -= self.c4i
            if lcn < self.c2b:
                shift = 1
            else:
                pos += self.c2b * 2
                lcn -= self.c2b
        pos += lcn * (1 << shift)
        vcnt = 2 if shift == 2 else 16
        encodebits = ((vcnt << shift) - 4) * 8 // vcnt
        return pos, vcnt, shift, encodebits

    def load(self, lcn):
        """Return dict(type, lo, pack, i, encodebits)."""
        pos, vcnt, shift, encodebits = self.entry_pos(lcn)
        packbytes = vcnt << shift
        packstart = pos - (pos & (packbytes - 1))
        i = (pos - packstart) >> shift
        pack = self.img.rd(packstart, packbytes)
        lo, t = decode_entry(pack, encodebits, self.lobits, i)
        return {"type": t, "lo": lo, "pack": pack, "i": i, "encodebits": encodebits, "vcnt": vcnt, "shift": shift}

    def pblk_of_head(self, e):
        """pblk = trailing base u32 + nblk (kernel walk)."""
        pack, i, encodebits = e["pack"], e["i"], e["encodebits"]
        nblk = 1
        while i > 0:
            i -= 1
            lo, t = decode_entry(pack, encodebits, self.lobits, i)
            if t == Z_NONHEAD:
                i -= lo
            if i >= 0:
                nblk += 1
        base = int.from_bytes(pack[-4:], "little")
        return base + nblk


def main() -> int:
    ensure_vendor()
    img = Img(VENDOR)
    ino = img.rd(NID * 32, 32)
    ifmt, xattr_ic = struct.unpack_from("<HH", ino, 0)
    size = struct.unpack_from("<I", ino, 8)[0]
    assert ifmt & 1 == 0 and ((ifmt >> 1) & 7) == 3, bin(ifmt)

    map_hdr = img.rd((((NID * 32 + 32 + (12 + 4 * (xattr_ic - 1))) + 7) & ~7), 8)
    h_advise = struct.unpack_from("<H", map_hdr, 4)[0]
    h_alg, h_clusterbits = map_hdr[6], map_hdr[7]
    print(f"size={size} h_advise={h_advise:#x} alg={h_alg} clusterbits={h_clusterbits}")
    assert h_advise & ~0x0001 == 0, "unexpected advise bits (fragment/inline/bigpcluster)"
    assert h_clusterbits == 0

    idx = CompactIndex(img, NID, size, h_advise)

    print("\nlcluster table:")
    table = []
    for lcn in range(idx.totalidx):
        e = idx.load(lcn)
        if e["type"] == Z_NONHEAD:
            table.append((lcn, "NONHEAD", e["lo"]))
            print(f"  lcn {lcn:>3}: NONHEAD lo={e['lo']}")
        else:
            pblk = idx.pblk_of_head(e)
            tname = "PLAIN" if e["type"] == Z_PLAIN else f"HEAD{e['type']}"
            table.append((lcn, tname, e["lo"], pblk))
            print(f"  lcn {lcn:>3}: {tname:<7} clusterofs={e['lo']:#x} pblk={pblk:#x}")

    # build extents: HEAD k covers [la_k, la_{k+1}) where la = (lcn<<12)|clusterofs
    heads = [(r[0], r[1], r[2], r[3]) for r in table if r[1] != "NONHEAD"]
    out = bytearray()
    for k, (lcn, tname, clusterofs, pblk) in enumerate(heads):
        la = (lcn << 12) + clusterofs
        if k + 1 < len(heads):
            nlcn, _nt, nclusterofs, npblk = heads[k + 1]
            next_la = (nlcn << 12) + nclusterofs
            cblks = max(1, npblk - pblk)
        else:
            next_la = size
            cblks = 1
        llen = next_la - la
        plen = cblks * BLK
        if tname == "PLAIN":
            chunk = img.rd(pblk * BLK, llen)
        else:
            win = bytes(out[-65536:])
            chunk = lz4_decompress_win(img.rd(pblk * BLK, plen), llen, win)
        print(f"extent {k}: lcn={lcn} la={la:#x} llen={llen} pblk={pblk:#x} cblks={cblks} -> {len(chunk)} bytes")
        if len(chunk) < llen:
            print(f"  !! short decompress ({len(chunk)}/{llen})")
        out += chunk[:llen]

    print(f"\ntotal extracted: {len(out)} / expected {size}")
    if len(out) >= 4 and out[:4] == b"MCLF":
        print("MCLF magic: OK")
        data = bytes(out[:size])
        with open(OUT, "wb") as f:
            f.write(data)
        print(f"wrote {OUT}")
        stock = open(STOCK_PATH, "rb").read()
        same = sum(1 for a, b in zip(stock, data) if a == b)
        print(f"vs stock: {len(stock)} vs {len(data)} bytes; {100 * same // max(len(stock), len(data))}% byte-identical")
        import hashlib

        print(f"sha256 stock={hashlib.sha256(stock).hexdigest()[:16]} new={hashlib.sha256(data).hexdigest()[:16]}")
        print(f"is_locked @0x19ec0 new: {data[0x19ec0:0x19ed8].hex(' ')}")
        print(f"is_locked @0x19ec0 old: {stock[0x19ec0:0x19ed8].hex(' ')}")
        return 0
    print("MCLF magic MISSING — extraction wrong")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
