#!/usr/bin/env python3
"""
Stock-firmware survey for the Garmr patch set (stdlib only, no liblk).

Answers "did the OEM change anything the seven patches depend on?" for a new
stock lk.img:

  1. parses the MTK part_hdr_t container (via poc/mtk_cert.py),
  2. counts every original/patched pattern from poc/build_native_20_5_12.py
     in the target sub-images and reports flat offsets,
  3. re-checks the anchors documented in notes/STATUS.md
     (preflash string, sboot global, MBM string),
  4. runs the full CERT1/CERT2 verification, proving the hash-override
     cert-bypass preconditions still hold for the new image,
  5. optionally diffs sub-image digests against a reference build.

Usage:
  uv run --no-project python analysis/check_fw.py <stock lk.img> [reference lk.img]

Exit code 0 = every pattern still present at the expected count and the cert
layout is unchanged; anything else prints what moved.
"""
from __future__ import annotations

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "poc"))

import mtk_cert  # noqa: E402
from build_native_20_5_12 import PATCHES  # noqa: E402  (single source of truth)

# Informational only: the sboot getter neighborhood that was removed from the
# builder (see notes/STATUS.md "The sboot patch was a trap"). 20-5-12 had 2
# hits per partition (getter + X.509 OID handler).
SBOOT_INFO = "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52"
SBOOT_GLOBAL_OFF = 0x12EE2C  # lk+ offset of the stock sboot global (0x11)


def hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return out
        out.append(idx)
        start = idx + 1


def sha_short(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def main() -> int:
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    stock_path = sys.argv[1]
    ref_path = sys.argv[2] if len(sys.argv) == 3 else None

    data = open(stock_path, "rb").read()
    parts = mtk_cert.parse_parts(data)
    print(f"image      : {stock_path}")
    print(f"size       : {len(data)} (0x{len(data):x})")
    print(f"sub-images : {[p.name for p in parts]}")

    ref_parts = None
    if ref_path:
        ref = open(ref_path, "rb").read()
        ref_parts = {p.name: p for p in mtk_cert.parse_parts(ref)}

    print("\n=== sub-image comparison vs reference (data digests) ===")
    for p in parts:
        line = f"  {p.name:<10} dsize=0x{p.dsize:<7x} sha256={sha_short(bytes(data[p.data_off:p.data_off + p.dsize]))}"
        if ref_parts is not None:
            r = ref_parts.get(p.name)
            if r is None:
                line += "  (absent in reference)"
            elif sha_short(bytes(ref[r.data_off:r.data_off + r.dsize])) != sha_short(bytes(data[p.data_off:p.data_off + p.dsize])):
                line += "  CHANGED"
            else:
                line += "  identical"
        print(line)

    print("\n=== patch pattern survey ===")
    by_name = {p.name: p for p in parts}
    all_ok = True
    for name, (orig, patched, want) in PATCHES.items():
        print(f"\n[{name}]")
        for pname, expected in want.items():
            p = by_name.get(pname)
            if p is None:
                print(f"  {pname:<8} SUB-IMAGE MISSING FROM CONTAINER")
                all_ok = False
                continue
            region = bytes(data[p.data_off:p.data_off + p.dsize])
            oh = find_all(region, orig)
            ph = find_all(region, patched)
            flat = ", ".join(f"0x{p.data_off + o:x}" for o in oh) or "-"
            good = len(oh) == expected and not ph
            all_ok &= good
            print(
                f"  {pname:<8} orig={len(oh)} patched={len(ph)} expected={expected}"
                f" {'OK' if good else 'CHANGED'}  flat: {flat}"
            )

    print("\n=== anchors from notes/STATUS.md ===")
    lk = by_name.get("lk")
    if lk is not None:
        lkdata = bytes(data[lk.data_off:lk.data_off + lk.dsize])
        s = lkdata.find(b"Preflash validation failed")
        print(f"  'Preflash validation failed' @lk+0x{s:x}" if s >= 0 else "  'Preflash validation failed' MISSING")
        if SBOOT_GLOBAL_OFF < len(lkdata):
            v = lkdata[SBOOT_GLOBAL_OFF]
            print(f"  sboot global @lk+0x{SBOOT_GLOBAL_OFF:x} = 0x{v:02x} (reference stock: 0x11)")
        n = find_all(lkdata, hx(SBOOT_INFO))
        print(f"  sboot getter neighborhood hits: {len(n)} (reference stock: 2; informational only)")
    mbm = data.find(b"MBM-3.1-cancunf")
    if mbm >= 0:
        end = data.find(b"\0", mbm)
        print(f"  MBM string @0x{mbm:x}: {bytes(data[mbm:end]).decode('latin-1')}")

    print("\n=== cert bypass preconditions (full CERT1/CERT2 verify) ===")
    cert_ok = True
    try:
        # mtk_cert.verify re-hashes every sub-image and checks both RSA-PSS
        # signatures; VALID == the hash-override bypass can be re-applied.
        cert_ok = mtk_cert.verify(data)
    except Exception as exc:  # noqa: BLE001
        cert_ok = False
        print(f"  verify raised: {exc}")

    verdict = all_ok and cert_ok
    print(
        f"\n=== RESULT: patterns {'ALL PRESENT AT EXPECTED COUNTS' if all_ok else 'SOME PATTERNS CHANGED'}"
        f" / certs {'BYPASS PRECONDITIONS HOLD' if cert_ok else 'CERT LAYOUT CHANGED'} ==="
    )
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
