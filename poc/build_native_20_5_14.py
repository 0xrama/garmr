#!/usr/bin/env python3
"""
Fenrir-free Cancunf 20-5-14 build.

Same seven-patch set as build_native_20_5_12.py, re-pinned for stock firmware
V1TDS35H.83-20-5-14 (see notes/STATUS.md, "20-5-14 survey"). Motorola did not
harden any of the seven sites in this build; three patterns changed only
because PC-relative immediates moved (routine recompile):

  force_green_state            adrp x8 page immediate d0 -> f0
  bypass_security_control      bl callee moved 0xa2948 -> 0xa2b30
  vbmeta_device_state_locked   adrp x1 page immediate (data page +0x1000)

Patch list (spoof_sboot_state intentionally omitted — see notes/STATUS.md):
  1. sec_get_vfy_policy            bl2_ext/lk/aee (core EL3 chain bypass)   [unchanged]
  2. spoof_lock_state              bl2_ext/lk/aee (force LKS_LOCK)          [unchanged]
  3. force_green_state             lk (boot state global -> green)          [re-pinned]
  4. avb_allow_verification_error  lk (allow AVB verification errors)       [unchanged]
  5. bypass_security_control       lk (skip lock/security error branch)     [re-pinned]
  6. preflash_validation_bypass    lk (skip preflash validation failure)    [unchanged]
  7. vbmeta_device_state_locked    lk (force androidboot.vbmeta.device_state=locked) [re-pinned]

Usage:
    python3 poc/build_native_20_5_14.py

Env overrides:
    CANCUNF_STOCK  path to stock lk.img
    CANCUNF_OUT    output path (default: poc/cancunf-native-full-20-5-14.img)
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import mtk_cert as cert  # noqa: E402


STOCK = os.environ.get(
    "CANCUNF_STOCK",
    os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-14", "lk.img"),
)
OUT = os.environ.get(
    "CANCUNF_OUT",
    os.path.join(HERE, "cancunf-native-full-20-5-14.img"),
)

CERT_TARGETS = {"lk", "bl2_ext", "aee"}


def hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# (original, patched, {partition: expected_hit_count})
# Keep in sync with analysis/confirm_repin.py evidence.
PATCHES = {
    "sec_get_vfy_policy": (
        hx("00 01 00 b4 fd 7b bf a9"),
        hx("00 00 80 52 c0 03 5f d6"),
        {"bl2_ext": 1, "lk": 1, "aee": 1},
    ),
    "spoof_lock_state": (
        hx("20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91"),
        hx("88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6"),
        {"bl2_ext": 1, "lk": 1, "aee": 1},
    ),
    # 20-5-14: adrp x8 immediate d0 -> f0 (site verified at lk+0x736ec)
    "force_green_state": (
        hx("88 05 00 f0 00 69 02 b9 c0 03 5f d6"),
        hx("88 05 00 f0 1f 69 02 b9 c0 03 5f d6"),
        {"lk": 1},
    ),
    "avb_allow_verification_error": (
        hx("e3 03 17 2a 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
        hx("e3 02 00 32 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
        {"lk": 1},
    ),
    # 20-5-14: bl immediate 53 54 01 94 -> cd 54 01 94 (callee at 0xa2b30)
    "bypass_security_control": (
        hx("cd 54 01 94 20 01 00 36"),
        hx("cd 54 01 94 1f 20 03 d5"),
        {"lk": 1},
    ),
    "preflash_validation_bypass": (
        hx("42 41 02 94 80 00 00 36"),
        hx("42 41 02 94 1f 20 03 d5"),
        {"lk": 1},
    ),
    # 20-5-14: adrp x1 immediate 41 04 00 f0 -> 61 04 00 90 (page 0x108000)
    "vbmeta_device_state_locked": (
        hx("1f 01 00 71 61 04 00 90 42 01 89 9a 21 a8 29 91"),
        hx("1f 01 00 71 61 04 00 90 e2 03 0a aa 21 a8 29 91"),
        {"lk": 1},
    ),
}


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            return out
        out.append(idx)
        start = idx + 1


def apply_patches(data: bytes) -> bytes:
    out = bytearray(data)
    for part in cert.parse_parts(data):
        if part.is_cert:
            continue
        for name, (orig, patched, expected_by_part) in PATCHES.items():
            if part.name not in expected_by_part:
                continue
            region = out[part.data_off : part.data_off + part.dsize]
            hits = find_all(bytes(region), orig)
            expected = expected_by_part[part.name]
            if len(hits) != expected:
                raise SystemExit(
                    f"{name}: {part.name} has {len(hits)} hits, expected {expected}"
                )
            for h in hits:
                start = part.data_off + h
                out[start : start + len(patched)] = patched
    return bytes(out)


def verify_patches(artifact: bytes) -> bool:
    """Re-parse the signed artifact: originals gone, patched present, once each."""
    ok = True
    for part in cert.parse_parts(artifact):
        if part.is_cert:
            continue
        region = bytes(artifact[part.data_off : part.data_off + part.dsize])
        for name, (orig, patched, expected_by_part) in PATCHES.items():
            if part.name not in expected_by_part:
                continue
            expected = expected_by_part[part.name]
            n_orig = len(find_all(region, orig))
            n_patched = len(find_all(region, patched))
            # spoof_lock_state's replacement ends with the same 8 bytes as
            # sec_get_vfy_policy's, so partitions carrying both show one
            # extra hit. verify_poc.py uses the same ">=" for this reason.
            good = n_orig == 0 and n_patched >= expected
            ok &= good
            print(
                f"  {name:<30} {part.name:<8} orig={n_orig} patched={n_patched} {'OK' if good else 'FAIL'}"
            )
    return ok


def main() -> int:
    if not os.path.exists(STOCK):
        raise SystemExit(f"stock not found: {STOCK}")

    print(f"stock   : {STOCK}")
    print(f"output  : {OUT}")
    print(f"patches : {len(PATCHES)}")

    data = open(STOCK, "rb").read()
    patched = apply_patches(data)
    signed = cert.apply_cert_bypass(patched, CERT_TARGETS)

    with open(OUT, "wb") as fh:
        fh.write(signed)

    print(f"\nwrote {OUT} ({len(data)} -> {len(signed)} bytes)")
    print("\n--- patch verification ---")
    ok = verify_patches(signed)
    print("\n--- cert verification ---")
    ok &= cert.verify(signed)
    print(f"\n{'OK' if ok else 'FAIL'} -> {OUT}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
