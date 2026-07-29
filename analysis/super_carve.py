#!/usr/bin/env python3
"""super_carve.py — Motorola sparsechunk[] -> raw super -> carve a logical partition.

Usage:
  python3 super_carve.py desparse            # super.img_sparsechunk.* -> super.raw
  python3 super_carve.py meta                # dump lpmetadata partitions/extents
  python3 super_carve.py carve vendor_b      # carve logical partition to vendor_b.img
"""
import glob
import struct
import sys

D = "/var/folders/kh/0_12wyvd5m94dtwmp2nnxcsh0000gn/T/opencode/fw"
SIMG_HDR = 0x3AFF26ED
CHUNK_RAW, CHUNK_FILL, CHUNK_DONT_CARE, CHUNK_CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
BLK = 4096


def _chunkkey(fn):
    return int(fn.rsplit(".", 1)[-1])


def desparse():
    with open(f"{D}/super.raw", "wb") as raw:
        for fn in sorted(glob.glob(f"{D}/super.img_sparsechunk.*"), key=_chunkkey):
            out_off = 0  # each sparsechunk is a FULL sparse stream; only its segment has RAW data
            with open(fn, "rb") as f:
                data = f.read()
            (magic, _maj, _minor, hs, chs, bsz, _tb, _tc, _c) = struct.unpack_from("<IHHHHIIII", data, 0)
            if magic != SIMG_HDR and struct.unpack_from(">I", data, 0)[0] != SIMG_HDR:
                raise ValueError(f"{fn}: bad simg magic {data[0:4].hex()}")
            pos = hs
            n_raw = 0
            while pos < len(data):
                ctype, _r, csz_blks, csz_total = struct.unpack_from("<HHII", data, pos)
                body = data[pos + chs : pos + csz_total]
                if ctype == CHUNK_RAW:
                    raw.seek(out_off)
                    raw.write(body)
                    n_raw += 1
                elif ctype == CHUNK_FILL:
                    raw.seek(out_off)
                    fill = body[:4] * (csz_blks * bsz // 4)
                    raw.write(fill)
                pos += csz_total
                out_off += csz_blks * bsz
            print(f"{fn.split('/')[-1]}: image blocks {out_off//BLK:#x} (raw chunks: {n_raw})", flush=True)


# ---------- minimal protobuf ----------
def varint(buf, p):
    v = 0
    s = 0
    while True:
        b = buf[p]
        p += 1
        v |= (b & 0x7F) << s
        if not (b & 0x80):
            return v, p
        s += 7


def fields(buf):
    p = 0
    while p < len(buf):
        key, p = varint(buf, p)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, p = varint(buf, p)
            yield fn, wt, v
        elif wt == 2:
            ln, p = varint(buf, p)
            yield fn, wt, buf[p : p + ln]
            p += ln
        elif wt == 5:
            yield fn, wt, struct.unpack_from("<I", buf, p)[0]
            p += 4
        else:
            raise ValueError(f"wire type {wt}")


HDR = 0x3000  # LP metadata header offset in carved super.raw ("LP0A")


def read_tables():
    """Parse the fixed-size LP tables at HDR. Returns (parts, extents, groups)."""
    with open(f"{D}/super.raw", "rb") as f:
        f.seek(HDR)
        hdr = f.read(0x100)
    magic = struct.unpack_from("<I", hdr, 0)[0]
    assert magic == 0x414C5030, hex(magic)
    descs = {}
    for i, name in enumerate(("partitions", "extents", "groups", "block_devices")):
        off, num, esz = struct.unpack_from("<III", hdr, 0x50 + i * 12)
        descs[name] = (HDR + 0x100 + off, num, esz)
    parts = []
    with open(f"{D}/super.raw", "rb") as f:
        base, num, esz = descs["partitions"]
        f.seek(base)
        tab = f.read(num * esz)
        for i in range(num):
            e = tab[i * esz : (i + 1) * esz]
            pname = e[:36].split(b"\0")[0].decode()
            attr, first, nex, _grp = struct.unpack_from("<IIII", e, 36)
            parts.append((pname, first, nex))
        base, num, esz = descs["extents"]
        f.seek(base)
        tab = f.read(num * esz)
        extents = []
        for i in range(num):
            # LpMetadataExtent (packed, 24B): u32 num_sectors, u32 sector_type,
            #   u32 target_type, u64 target_data(sectors), u32 target_source, u32 pad
            ns, stype, _ttype = struct.unpack_from("<III", tab[i * esz :], 0)
            (tdata,) = struct.unpack_from("<Q", tab[i * esz :], 12)
            extents.append((ns, stype, 0, tdata))
        base, num, esz = descs["groups"]
        f.seek(base)
        tab = f.read(num * esz)
        groups = []
        for i in range(num):
            e = tab[i * esz : (i + 1) * esz]
            gname = e[:36].split(b"\0")[0].decode()
            groups.append(gname)
    return parts, extents, groups
    with open(f"{D}/super.raw", "rb") as f:
        f.seek(md_off)
        meta = f.read(msz)
    print(f"lp metadata: {msz} bytes @ {md_off:#x}")
    return meta


def dump_meta():
    parts, extents, groups = read_tables()
    print(f"{len(parts)} partitions, {len(extents)} extents, groups {groups}")
    for pname, first, nex in parts:
        total = sum(extents[i][0] for i in range(first, first + nex))
        print(f"  {pname:16} extents[{first}..{first+nex})  {total//2048} MiB")
    for i, (ns, st, tt, td) in enumerate(extents):
        print(f"  extent {i}: {ns} sectors, type {st}/{tt}, super+{td*512:#x}")


def carve(name):
    parts, extents, _ = read_tables()
    for pname, first, num in parts:
        if pname != name:
            continue
        with open(f"{D}/super.raw", "rb") as src, open(f"{D}/{name}.img", "wb") as out:
            for i in range(first, first + num):
                ns, _st, _tt, tdata = extents[i]
                src.seek(tdata * 512)
                out.write(src.read(ns * 512))
                print(f"  extent {i}: {ns} sectors from super+{tdata*512:#x}")
        print(f"wrote {D}/{name}.img")
        return
    raise SystemExit(f"partition {name} not found; available: {[p[0] for p in parts]}")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "desparse":
        desparse()
    elif cmd == "meta":
        dump_meta()
    elif cmd == "carve":
        carve(sys.argv[2])
