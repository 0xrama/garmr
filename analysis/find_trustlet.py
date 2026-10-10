#!/usr/bin/env python3
"""
Search the 20-5-14 super image (sparsechunk[]) for the KeyMint trustlet.

Memory-safe scan: parses each sparsechunk (LE or BE simg header), merges
contiguous RAW chunk bodies into runs, and searches each run with a carry
buffer across logically contiguous runs. DONT_CARE and FILL runs are treated
as discontinuities (none of the needles are all-zero, so a straddle is
impossible).

Needles:
  - the full 20-5-12 stock trustlet (byte-identical copy?)
  - the is_locked() neighborhood (stock encoding)
  - the trustlet string-table marker (red/orange/yellow/green/...)
  - the patched is_locked() encoding (sanity: must not be in stock fw)

Usage:
  uv run --no-project python analysis/find_trustlet.py [super_dir]
"""
from __future__ import annotations

import glob
import hashlib
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SUPER_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    ROOT, "firmware", "V1TDS35H.83-20-5-14"
)
STOCK_TLBIN = os.path.join(ROOT, "poc", "trustlet_patch", "stock_trustlet.tlbin")

SIMG_HDR = 0x3AFF26ED
CHUNK_RAW, CHUNK_FILL, CHUNK_DONT_CARE, CHUNK_CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4


def chunkkey(fn: str) -> int:
    return int(fn.rsplit(".", 1)[-1])


def build_needles() -> list[tuple[str, bytes]]:
    stock = open(STOCK_TLBIN, "rb").read()
    return [
        ("stock trustlet (full file)", stock),
        ("is_locked() neighborhood", stock[0x19EC0:0x19ED8]),
        ("string-table marker", stock[0x3B370:0x3B3A8]),
        ("patched is_locked() bytes", bytes.fromhex("20 00 80 D2 C0 03 5F D6")),
    ]


def search_runs(runs: list[tuple[int, bytes]], needles) -> dict[str, list[int]]:
    """runs: [(logical_start, data)] sorted, non-overlapping."""
    maxlen = max(len(n) for _, n in needles)
    hits: dict[str, list[int]] = {name: [] for name, _ in needles}
    carry = b""
    carry_start = 0
    prev_end = None
    for start, blob in runs:
        if prev_end == start:
            data = carry + blob
            base = carry_start
        else:
            data = blob
            base = start
        for name, needle in needles:
            i = data.find(needle)
            while i >= 0:
                hits[name].append(base + i)
                i = data.find(needle, i + 1)
        keep = min(len(data), maxlen)
        carry = data[-keep:]
        carry_start = base + len(data) - keep
        prev_end = start + len(blob)
    return hits


def sparse_runs(fn: str) -> list[tuple[int, bytes]]:
    """Return [(logical_start, merged_raw_bytes)] for one sparsechunk file."""
    with open(fn, "rb") as f:
        data = f.read()
    endian = "<"
    if struct.unpack_from("<I", data, 0)[0] != SIMG_HDR:
        if struct.unpack_from(">I", data, 0)[0] != SIMG_HDR:
            raise ValueError(f"{os.path.basename(fn)}: bad simg magic")
        # Motorola quirk: byte-swapped magic, but all other fields stay
        # little-endian (same treatment as analysis/super_carve.py).
    (_m, _maj, _min, hs, chs, bsz, _tb, _tc, _cc) = struct.unpack_from(
        "<IHHHHIIII", data, 0
    )
    runs: list[tuple[int, bytes]] = []
    pos = hs
    out_off = 0
    cur_start = None
    cur = bytearray()
    while pos + chs <= len(data):
        ctype, _res, csz_blks, csz_total = struct.unpack_from("<HHII", data, pos)
        size = csz_blks * bsz
        if ctype == CHUNK_RAW:
            body = data[pos + chs:pos + csz_total]
            if cur_start is None:
                cur_start = out_off
            elif out_off != cur_start + len(cur):
                runs.append((cur_start, bytes(cur)))
                cur = bytearray()
                cur_start = out_off
            cur += body
        else:
            if cur_start is not None and len(cur):
                runs.append((cur_start, bytes(cur)))
            cur, cur_start = bytearray(), None
        pos += csz_total
        out_off += size
    if cur_start is not None and len(cur):
        runs.append((cur_start, bytes(cur)))
    return runs


def main() -> int:
    files = sorted(glob.glob(os.path.join(SUPER_DIR, "super.img_sparsechunk.*")), key=chunkkey)
    if not files:
        sys.exit(f"no sparsechunks in {SUPER_DIR}")
    print(f"scanning {len(files)} sparsechunk files from {SUPER_DIR}", flush=True)

    needles = build_needles()
    stock = open(STOCK_TLBIN, "rb").read()
    all_hits: dict[str, list[int]] = {name: [] for name, _ in needles}

    t0 = time.time()
    for fn in files:
        runs = sparse_runs(fn)
        hits = search_runs(runs, needles)
        for name, offs in hits.items():
            all_hits[name].extend(offs)
        print(
            f"  {os.path.basename(fn):<28} runs={len(runs):<4} "
            f"hits={sum(len(v) for v in hits.values()):<3} {time.time() - t0:6.1f}s",
            flush=True,
        )

    print("\n=== results ===")
    for name, offs in all_hits.items():
        pretty = [f"0x{o:x}" for o in offs[:6]]
        print(f"  {name:<30} {len(offs)} hit(s) {pretty}{' ...' if len(offs) > 6 else ''}")

    full = all_hits["stock trustlet (full file)"]
    if full:
        print("\nStock trustlet present VERBATIM in 20-5-14 super (byte-identical).")
        print(f"  logical offset: 0x{full[0]:x}")
    else:
        fn_hits = all_hits["is_locked() neighborhood"]
        st_hits = all_hits["string-table marker"]
        print("\nStock trustlet NOT found verbatim.")
        print(f"  is_locked() neighborhood: {len(fn_hits)} hit(s)")
        print(f"  string-table marker     : {len(st_hits)} hit(s)")
        if fn_hits and st_hits:
            delta = st_hits[0] - fn_hits[0]
            print(f"  strtab - is_locked delta: 0x{delta:x} (stock: 0x{0x3b370 - 0x19ec0:x})")
    print(f"\nreference stock sha256: {hashlib.sha256(stock).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
