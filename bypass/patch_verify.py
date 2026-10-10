#!/usr/bin/env python3
"""
Patch Kinibi's MCLF trustlet signature-verification gates so a modified
trustlet is accepted, then re-sign tee.img with the CERT2 cert bypass.

UPGRADED (see analysis/annotate_loader.py for the disassembly evidence):
the loader checks the cmd-0xad verdict at TWO sites, and both must be
forced to the success path:

    gate 1  kinibi 0x5ebf0:  cbz w0, #0x5ecc4  ->  b #0x5ecc4
            bytes           a0 06 00 34        ->  35 00 00 14
    gate 2  kinibi 0x5eca4:  cbz w0, #0x5ed40  ->  b #0x5ed40
            bytes           e0 04 00 34        ->  27 00 00 14

Loader flow (annotated):
    cmd 0xa9  open handle
    cmd 0xac  read properties/size
    cmd 0xad  verdict -> gate 1 -> cmd 0x32 reads 0x30-byte header
    ...
    cmd 0xad  verdict -> gate 2 -> cmd 0x32 reads the full image -> map

Notes:
  - Do NOT neutralize the 0xad wrapper (0x65b60) itself: its call sites
    consume outputs produced alongside the verdict, and skipping the call
    leaves them zero.
  - The failure path already tolerates the special code 0xf0100001.
  - The 20-5-12 and 20-5-14 Kinibi cores are byte-identical in both windows
    (99% overall), so the same offsets apply; the tee partition data offset
    is resolved dynamically from the container.

Usage:
    python3 bypass/patch_verify.py --tee-img firmware/<build>/tee.img -o out.img
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "poc"))
import mtk_cert  # noqa: E402


# (label, kinibi offset, anchor window, patch) — offsets inside the tee sub-image.
# The bare cbz bytes are NOT unique in the image; each gate is pinned by its
# bl/mov preamble, and only the final 4 bytes (the cbz) are replaced.
GATES = [
    ("verify gate 1 (loader 0x5ebf0)", 0x5EBF0,
     bytes.fromhex("de 1b 00 94 f3 03 00 2a a0 06 00 34"),  # bl 0x65b60; mov w19,w0; cbz w0,#0x5ecc4
     bytes.fromhex("35 00 00 14")),                        # b   #0x5ecc4
    ("verify gate 2 (loader 0x5eca4)", 0x5ECA4,
     bytes.fromhex("b0 1b 00 94 e0 04 00 34"),             # bl 0x65b60; cbz w0,#0x5ed40
     bytes.fromhex("27 00 00 14")),                        # b   #0x5ed40
]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tee-img", required=True, type=Path)
    p.add_argument("-o", "--output", required=True, type=Path)
    args = p.parse_args()

    raw = args.tee_img.read_bytes()
    parts = mtk_cert.parse_parts(raw)
    tee = next((x for x in parts if x.name == "tee"), None)
    if tee is None:
        raise SystemExit("no 'tee' sub-image found in tee.img")
    print(f"tee sub-image data @ tee.img 0x{tee.data_off:x} ({tee.dsize} bytes)")

    img = bytearray(raw)
    for label, off, anchor, patch in GATES:
        # gate offset points at the cbz (last 4 bytes of the anchor)
        anchor_off = tee.data_off + off - (len(anchor) - 4)
        window = bytes(img[anchor_off : anchor_off + len(anchor)])
        if window != anchor:
            print(f"ERROR: {label}: expected anchor {anchor.hex()} at 0x{anchor_off:x}, "
                  f"found {window.hex()} — aborting.", file=sys.stderr)
            return 1
        # uniqueness of the anchor window inside the tee sub-image
        region = bytes(img[tee.data_off : tee.data_off + tee.dsize])
        hits, s = [], 0
        while True:
            i = region.find(anchor, s)
            if i < 0:
                break
            hits.append(i)
            s = i + 1
        if len(hits) != 1:
            print(f"ERROR: {label}: {len(hits)} occurrences of anchor in tee "
                  f"sub-image (want exactly 1) — aborting.", file=sys.stderr)
            return 1
        # only the final 4 bytes of the anchor (the cbz) are replaced
        cbz_abs = anchor_off + len(anchor) - 4
        img[cbz_abs : cbz_abs + 4] = patch
        print(f"{label}: {anchor[-4:].hex()} -> {patch.hex()} @ tee.img 0x{cbz_abs:x} (anchor unique)")

    signed = mtk_cert.apply_cert_bypass(bytes(img), {"tee"})
    args.output.write_bytes(signed)

    print(f"\nwrote {args.output} ({len(raw)} -> {len(signed)} bytes)")
    print("--- verification ---")
    ok = mtk_cert.verify(signed)
    print(f"\n{'OK' if ok else 'FAIL'}")
    print("\nNOTE: high-confidence static patch (both 0xad verdict gates in the "
          "MCLF loader; disassembly evidence in analysis/annotate_loader.py), "
          "but still hardware-unvalidated. Flash only on a sacrificial device "
          "with a recovery path.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
