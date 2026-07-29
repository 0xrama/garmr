#!/usr/bin/env python3
"""erofs_reader.py — minimal EROFS (uncompressed/flat) directory lister + extractor.

Usage:
  python3 erofs_reader.py <img> ls [path]
  python3 erofs_reader.py <img> extract <path> <out>
  python3 erofs_reader.py <img> find <substr>        # walk whole tree printing matches
"""
import struct
import sys

BLK = 4096


class Erofs:
    def __init__(self, path):
        self.f = open(path, "rb")
        sb = self._rd(0x400, 128)
        magic = struct.unpack_from("<I", sb, 0)[0]
        assert magic == 0xE0F5E1E2, hex(magic)
        self.blkszbits = sb[0x0C]
        assert self.blkszbits == 12
        self.rootnid = struct.unpack_from("<H", sb, 0x0E)[0]
        self.feature_incompat = struct.unpack_from("<I", sb, 0x44)[0]
        if self.feature_incompat != 0:
            print(f"warn: feature_incompat={self.feature_incompat:#x} (compression may be present)", file=sys.stderr)

    def _rd(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def inode(self, nid):
        off = nid * 32
        raw = self._rd(off, 32)
        ifmt = struct.unpack_from("<H", raw, 0)[0]
        version = ifmt & 1
        layout = (ifmt >> 1) & 7  # 0=FLAT_PLAIN 1=COMPR_FULL 2=FLAT_INLINE 3=COMPR_LEGACY
        mode = struct.unpack_from("<H", raw, 4)[0]
        size = struct.unpack_from("<I", raw, 8)[0]
        raw_blk = struct.unpack_from("<I", raw, 12)[0]
        data_off = off + (64 if version == 1 else 32)
        return {
            "nid": nid, "mode": mode, "size": size, "blk": raw_blk,
            "layout": layout, "version": version, "data_off": data_off,
        }

    def is_dir(self, ino):
        return (ino["mode"] & 0o170000) == 0o040000

    def read_data(self, ino):
        if ino["layout"] in (1, 3):
            return self._read_compressed(ino)
        off = ino["blk"] * BLK if ino["layout"] == 0 else ino["data_off"]
        return self._rd(off, ino["size"])

    def _read_compressed(self, ino):
        """COMPRESSED_LEGACY (layout 3 / 1): VLE legacy index + per-lcluster LZ4."""
        istart = ino["nid"] * 32
        isize = 64 if ino["version"] == 1 else 32
        xattr_ic = struct.unpack_from("<H", self._rd(istart + 2, 2))[0]
        pos = istart + isize + xattr_ic * 4
        if pos % 8 == 4:
            pos += 4
        pos += 8  # z_erofs_map_header (8 bytes)
        pos += 8  # Z_EROFS_VLE_LEGACY_HEADER_PADDING
        nlb = (ino["size"] + BLK - 1) // BLK
        out = bytearray()
        prev_blk = None
        for di in range(nlb):
            advise, clusterofs, blk = struct.unpack_from("<HHI", self._rd(pos + di * 8, 8))
            tp = advise & 3
            if tp == 3:  # RESERVED: same blkaddr as prev => NONHEAD (skip)
                if blk == prev_blk:
                    continue
                tp = 1
            prev_blk = blk
            if tp == 0:  # PLAIN: raw 4096 block
                out += self._rd(blk * BLK, BLK)
            elif tp == 1:  # HEAD: lz4 stream at blk*4096
                need = min(ino["size"] - len(out), BLK)
                out += lz4_block_decompress(self._rd(blk * BLK, BLK), need)
            else:  # NONHEAD: shares previous head's stream (rare)
                continue
        return bytes(out[: ino["size"]])

    def _parse_dirent_region(self, data, base_desc, max_entries=10000):
        """data = region starting at a dirent table; nameoffs relative to region start."""
        if len(data) < 12:
            return []
        nameoff0 = struct.unpack_from("<H", data, 8)[0]
        if nameoff0 == 0 or nameoff0 % 12 != 0:
            raise NotImplementedError(f"bad dir region at {base_desc}")
        nents = min(nameoff0 // 12, max_entries)
        ents = []
        for i in range(nents):
            enid, nameoff, ftype, _r = struct.unpack_from("<QHBB", data, i * 12)
            ents.append((enid, nameoff, ftype))
        out = []
        for i, (enid, nameoff, ftype) in enumerate(ents):
            next_off = ents[i + 1][1] if i + 1 < len(ents) else len(data)
            name = data[nameoff:next_off].split(b"\0")[0].decode(errors="replace")
            out.append((name, enid, ftype))
        return out

    def listdir(self, nid, max_entries=10000):
        ino = self.inode(nid)
        assert self.is_dir(ino), f"nid {nid} not dir (mode {ino['mode']:#o})"
        if ino["layout"] == 0:  # FLAT_PLAIN: per-block tables
            data = self.read_data(ino)
            out = []
            for b in range(0, len(data), BLK):
                try:
                    out.extend(self._parse_dirent_region(data[b : b + BLK], f"nid{nid} blk{b}"))
                except NotImplementedError:
                    pass
            return out
        if ino["layout"] == 2:  # FLAT_INLINE: inode + inline xattrs + table + names
            istart = nid * 32
            isize = 64 if ino["version"] == 1 else 32
            region = self._rd(istart + isize, ino["size"])
            for s in range(0, 96, 4):
                if s + 12 > len(region):
                    break
                try:
                    return self._parse_dirent_region(region[s:], f"nid{nid}+inline")
                except NotImplementedError:
                    continue
            raise NotImplementedError(f"cannot locate inline dirent table for nid {nid}")
        raise NotImplementedError(f"compressed dir inode layout {ino['layout']}")

    def walk(self, nid, prefix=""):
        try:
            ents = self.listdir(nid)
        except Exception as ex:
            print(f"warn: listdir failed for {prefix or '/'}: {ex}", file=sys.stderr)
            return
        for name, enid, ftype in ents:
            if name in (".", ".."):
                continue
            path = f"{prefix}/{name}"
            yield path, enid, ftype
            ino = self.inode(enid)
            if self.is_dir(ino):
                yield from self.walk(enid, path)


def lz4_block_decompress(src, max_out):
    """Minimal raw LZ4 block decompressor (no frame header)."""
    out = bytearray()
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
        out += src[p : p + lit_len]
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
        start = len(out) - off
        for i in range(mlen):
            out.append(out[start + i])
            if len(out) >= max_out:
                break
    return bytes(out)



    img = sys.argv[1]
    cmd = sys.argv[2]
    e = Erofs(img)
    if cmd == "ls":
        path = sys.argv[3] if len(sys.argv) > 3 else ""
        nid = e.rootnid
        if path.strip("/"):
            for part in path.strip("/").split("/"):
                ent = {n: (i, t) for n, i, t in e.listdir(nid)}
                nid, _ = ent[part]
        for name, enid, ftype in e.listdir(nid):
            print(f"{ftype} {enid:>8} {name}")
    elif cmd == "find":
        needle = sys.argv[3].lower()
        for path, enid, ftype in e.walk(e.rootnid):
            if needle in path.lower():
                print(path)
    elif cmd == "extract":
        path, outp = sys.argv[3], sys.argv[4]
        nid = e.rootnid
        for part in path.strip("/").split("/"):
            ent = {n: (i, t) for n, i, t in e.listdir(nid)}
            nid, _ = ent[part]
        data = e.read_data(e.inode(nid))
        open(outp, "wb").write(data)
        print(f"wrote {outp} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
