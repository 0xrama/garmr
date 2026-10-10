#!/usr/bin/env python3
"""
Carve the 20-5-14 KeyMint trustlet (mcRegistry 0706...4d.tlbin) out of the
sparse super and locate its is_locked() equivalent.

Usage:
  uv run --with capstone --no-project python analysis/carve_trustlet_14.py
"""
from __future__ import annotations

import glob
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from find_trustlet import sparse_runs  # noqa: E402

FW = os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14")
STOCK = open(os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet.tlbin"), "rb").read()
UUID = bytes.fromhex("0706000000000000000000000000004d")
OUT = os.path.join(ROOT, "analysis", "trustlet_20_5_14.tlbin")


def chunkkey(fn: str) -> int:
    return int(fn.rsplit(".", 1)[-1])


def build_map(files):
    """Return sorted [(logical_start, logical_end, file_idx, run_bytes)] for RAW runs."""
    runs = []
    for i, fn in enumerate(files):
        for start, blob in sparse_runs(fn):
            runs.append((start, start + len(blob), i, blob))
    runs.sort()
    return runs


def read_logical(runs, start, size):
    """Read [start, start+size) from the logical image; sparse holes read as zeros."""
    import bisect

    starts = [r[0] for r in runs]
    out = bytearray()
    pos = start
    while len(out) < size:
        idx = bisect.bisect_right(starts, pos) - 1
        if idx >= 0:
            s, e, _i, blob = runs[idx]
            if s <= pos < e:
                take = min(size - len(out), e - pos)
                out += blob[pos - s : pos - s + take]
                pos += take
                continue
        # pos is in a hole: zero-fill up to the next run (or the request end)
        nxt = starts[idx + 1] if 0 <= idx + 1 < len(runs) else pos
        # if idx<0 (before first run) bisect_right-1 == -1; next run is starts[0]
        if idx < 0 and runs:
            nxt = runs[0][0]
        take = min(size - len(out), max(0, nxt - pos))
        out += b"\0" * take
        pos += take
        if take == 0:  # request end inside the hole
            out += b"\0" * (size - len(out))
    return bytes(out)


def main() -> int:
    files = sorted(glob.glob(os.path.join(FW, "super.img_sparsechunk.*")), key=chunkkey)
    print(f"building run map for {len(files)} files...", flush=True)
    runs = build_map(files)
    total_raw = sum(e - s for s, e, _i, _b in runs)
    print(f"raw coverage: {len(runs)} runs, {total_raw / 2**30:.2f} GiB")

    # find every MCLF magic and keep those whose first 0x200 bytes hold the UUID
    mclf_offs = []
    for s, e, _i, blob in runs:
        j = blob.find(b"MCLF")
        while j >= 0:
            mclf_offs.append(s + j)
            j = blob.find(b"MCLF", j + 1)
    print(f"MCLF candidates: {len(mclf_offs)}")

    tl_start = None
    for off in mclf_offs:
        head = read_logical(runs, off, 0x200)
        if UUID in head:
            aligned = off % 4096 == 0
            print(f"  UUID match @0x{off:x} (4k-aligned={aligned})")
            if aligned:
                tl_start = off
                break
    if tl_start is None:
        print("no aligned MCLF with our UUID; falling back to string-table backtrack")
        # loose strtab: yellow\0 then green\0 within 0x20 bytes
        pat = re.compile(rb"yellow\x00.{0,18}?green\x00.{0,18}?locked\x00", re.DOTALL)
        for s, e, _i, blob in runs:
            for m in pat.finditer(blob):
                hit = s + m.start()
                print(f"  strtab cluster @0x{hit:x}")
                # backtrack to the nearest 4k-aligned MCLF within 0x80000
                base = hit & ~0xFFF
                for back in range(0, 0x80000, 0x1000):
                    cand = base - back
                    if cand < 0:
                        break
                    for ms, me, _mi, mblob in runs:
                        if ms <= cand < me:
                            if mblob[cand - ms : cand - ms + 4] == b"MCLF":
                                head = read_logical(runs, cand, 0x10)
                                print(f"    MCLF @0x{cand:x} head={head.hex(' ')}")
                                if head[4:8] == STOCK[4:8] or head[4] == STOCK[4]:
                                    tl_start = cand
                                    break
                            break
                    if tl_start is not None:
                        break
                if tl_start is not None:
                    break
            if tl_start is not None:
                break
    if tl_start is None:
        print("no aligned MCLF with our UUID found")
        return 1

    # carve generously, then trim: find the MCLF-declared or content end
    blob = read_logical(runs, tl_start, 0x60000)
    # trailing zeros of >= 4 consecutive 4K blocks mark end of file content
    end = len(blob)
    zero = b"\0" * 0x4000
    k = blob.rfind(zero)
    # walk back from the big zero tail to last non-zero
    tail = blob.rstrip(b"\0")
    print(f"carved 0x{len(blob):x}, last non-zero at 0x{len(tail):x}")
    carved = blob[: len(tail)]
    with open(OUT, "wb") as f:
        f.write(carved)
    print(f"wrote {OUT} ({len(carved)} bytes; stock was {len(STOCK)})")

    # compare against stock
    import hashlib

    print(f"stock sha256 {hashlib.sha256(STOCK).hexdigest()[:16]}  new sha256 {hashlib.sha256(carved).hexdigest()[:16]}")

    # string table
    st = carved.find(b"red\x00")
    print(f"strtab 'red' @0x{st:x} (stock 0x3b370)")
    for s in (b"green\x00", b"locked\x00", b"open\x00", b"unlocked\x00"):
        print(f"  {s[:-1].decode():<10} @0x{carved.find(s):x}")

    # hunt is_locked(): adrp x0; ldr w0,[x0,#8]; cmp w0,#0; cset w0,ne; ret
    pat = re.compile(rb"\x00\x08\x40\xb9\x1f\x00\x00\x71.{1,12}?\xc0\x03\x5f\xd6", re.DOTALL)
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for m in pat.finditer(carved):
        off = m.start()
        # back up to the adrp (4 bytes before ldr)
        fn_start = off - 4
        print(f"\nis_locked candidate @0x{off:x}:")
        for insn in md.disasm(carved[fn_start : fn_start + 28], fn_start):
            print(f"  0x{insn.address:06x}  {insn.bytes.hex(' '):<14} {insn.mnemonic:<8} {insn.op_str}")

    # diff hotspots vs stock for context
    same = sum(1 for a, b in zip(STOCK, carved) if a == b)
    print(f"\nbyte identity vs stock: {same}/{min(len(STOCK), len(carved))} ({100 * same // min(len(STOCK), len(carved))}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
