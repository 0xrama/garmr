#!/usr/bin/env python3
"""
Deep-dive on the patch sites that did not survive 20-5-12 -> 20-5-14.

For each vanished pattern this script:
  - relocates it in the old image and dumps context,
  - searches the new image for relaxed variants (masked registers, any-bl,
    prefix windows) to decide "code rebuilt" vs "site deliberately changed",
  - prints a region-level byte diff of the lk sub-image between builds.

Usage:
  uv run --no-project python analysis/diff_sites.py <old lk.img> <new lk.img>
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))

import mtk_cert  # noqa: E402
from build_native_20_5_12 import PATCHES  # noqa: E402


def hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def find_all(data: bytes, needle: bytes) -> list[int]:
    out, s = [], 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            return out
        out.append(i)
        s = i + 1


def load(path: str):
    data = open(path, "rb").read()
    parts = mtk_cert.parse_parts(data)
    img = next(p for p in parts if p.name == "lk")
    return data, bytes(data[img.data_off:img.data_off + img.dsize])


def hexdump(data: bytes, off: int, before: int = 32, after: int = 32) -> None:
    lo = max(0, off - before)
    hi = min(len(data), off + after)
    for row in range(lo, hi, 16):
        chunk = data[row:row + 16]
        mark = " <-- site" if row <= off < row + 16 else ""
        print(f"    0x{row:06x}  {chunk.hex(' '):<47}{mark}")


def regex_hunt(data: bytes, pattern: str, label: str) -> list[int]:
    hits = [m.start() for m in re.finditer(pattern, data, re.DOTALL)]
    print(f"  {label}: {len(hits)} hit(s) @ lk+{[hex(h) for h in hits[:8]]}")
    return hits


def diff_regions(old: bytes, new: bytes, pad: int = 64):
    """Yield (start, end) maximal regions where old/new differ, merged within pad."""
    n = min(len(old), len(new))
    regions = []
    i = 0
    while i < n:
        if old[i] != new[i]:
            j = i
            last = i
            while j < n and (old[j] != new[j] or j - last <= pad):
                if old[j] != new[j]:
                    last = j
                j += 1
            regions.append((i, last + 1))
            i = j
        else:
            i += 1
    if len(old) != len(new):
        regions.append((n, max(len(old), len(new))))
    return regions


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    old_raw, old = load(sys.argv[1])
    new_raw, new = load(sys.argv[2])
    print(f"old lk sub-image: {len(old)} bytes")
    print(f"new lk sub-image: {len(new)} bytes")

    vanished = ["force_green_state", "bypass_security_control", "vbmeta_device_state_locked"]
    survived = [n for n in PATCHES if n not in vanished]

    print("\n=== control: survived sites (old flat -> new flat, lk-relative) ===")
    for name in survived:
        orig = PATCHES[name][0]
        if "lk" not in PATCHES[name][2]:
            continue
        oh = find_all(old, orig)
        nh = find_all(new, orig)
        print(f"  {name:<30} old={[hex(h) for h in oh]} new={[hex(h) for h in nh]}")

    print("\n=== vanished sites: old context ===")
    for name in vanished:
        orig = PATCHES[name][0]
        for h in find_all(old, orig):
            print(f"\n[{name}] old @ lk+0x{h:x}")
            hexdump(old, h, 16, 48)

    print("\n=== vanished sites: relaxed hunts in new image ===")

    # force_green_state: adrp x8 ; str w?, [x8, #0x268] ; ret  (mask the str register)
    hits = regex_hunt(new, rb"\x69\x02\xb9\xc0\x03\x5f\xd6", "any `str w?,[x?,#0x268]; ret`")
    for h in hits[:4]:
        hexdump(new, h - 8, 0, 24)
    # also check whether the store was already replaced by a zero store
    hits = find_all(new, hx("1f 69 02 b9 c0 03 5f d6"))
    print(f"  `str wzr,[x?,#0x268]; ret` (pre-zeroed store): {len(hits)} hit(s)")

    # bypass_security_control: any `bl` followed by tbz w0,#0 (bypassable gate shape)
    hits = regex_hunt(new, rb"\x94.{4}\x20\x01\x00\x36", "any `bl X; tbz w0,#0,#imm` (4-byte window)")
    hits6 = regex_hunt(new, rb"\x94.{6}\x20\x01\x00\x36", "any `bl X,Y; tbz w0,#0` (6-byte window)")
    for h in (hits + hits6)[:6]:
        hexdump(new, h - 8, 0, 24)
    # the exact old bl target still callable?
    bl_old = find_all(old, PATCHES["bypass_security_control"][0])
    if bl_old:
        import struct
        word = struct.unpack_from("<I", old, bl_old[0])[0]
        tgt = bl_old[0] + ((word & 0x03FFFFFF) << 2)
        print(f"  old bl target (callee) @ lk+0x{tgt:x}; same bytes in new: {old[tgt:tgt+16] == new[tgt:tgt+16] if tgt < len(new) else 'oob'}")

    # vbmeta_device_state_locked: keep the cmp/branch prefix, mask the csel+mov
    hits = regex_hunt(new, re.escape(PATCHES["vbmeta_device_state_locked"][0][:8]) + rb".{8}", "cmp/branch prefix + any 8 bytes")
    for h in hits[:4]:
        hexdump(new, h, 0, 32)
    hits = regex_hunt(new, re.escape(PATCHES["vbmeta_device_state_locked"][0][:12]) + rb".{4}", "12-byte prefix + any 4")

    print("\n=== lk sub-image byte diff (regions merged within 64 bytes) ===")
    regions = diff_regions(old, new)
    print(f"  {len(regions)} differing region(s), {sum(e - s for s, e in regions)} bytes total")
    for s, e in regions[:40]:
        print(f"    0x{s:06x} - 0x{e:06x}  ({e - s} bytes)")
    if len(regions) > 40:
        print(f"    ... {len(regions) - 40} more")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
