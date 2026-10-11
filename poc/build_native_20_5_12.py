#!/usr/bin/env python3
"""
Fenrir-free Cancunf 20-5-12 build.

Applies the same seven pinned LK patches as build_full_20_5_12.py and signs
the container with the MTK CERT2 hash-override cert bypass implemented in
mtk_cert.py. The output is byte-for-byte identical to the fenrir
`CertBypass.OVERRIDE` artifact (cancunf-fenrir-full-20-5-12.img), but this
script has no fenrir-injector and no liblk dependency (stdlib only).

Patch list (spoof_sboot_state intentionally omitted — see notes/STATUS.md):
  1. sec_get_vfy_policy            bl2_ext/lk/aee (core EL3 chain bypass)
  2. spoof_lock_state              bl2_ext/lk/aee (force LKS_LOCK)
  3. force_green_state             lk (boot state global -> green)
  4. avb_allow_verification_error  lk (allow AVB verification errors)
  5. bypass_security_control       lk (skip lock/security error branch)
  6. preflash_validation_bypass    lk (skip preflash validation failure branch)
  7. vbmeta_device_state_locked    lk (force androidboot.vbmeta.device_state=locked)

Usage:
    python3 poc/build_native_20_5_12.py

Env overrides:
    CANCUNF_STOCK  path to stock lk.img
    CANCUNF_OUT    output path (default: poc/cancunf-native-full-20-5-12.img)
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
    os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "lk.img"),
)
OUT = os.environ.get(
    "CANCUNF_OUT",
    os.path.join(HERE, "cancunf-native-full-20-5-12.img"),
)

CERT_TARGETS = {"lk", "bl2_ext", "aee"}


def hx(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# (original, patched, {partition: expected_hit_count})
# Canonical definitions; native14 overrides only the three changed patterns.
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
    "force_green_state": (
        hx("88 05 00 d0 00 69 02 b9 c0 03 5f d6"),
        hx("88 05 00 d0 1f 69 02 b9 c0 03 5f d6"),
        {"lk": 1},
    ),
    "avb_allow_verification_error": (
        hx("e3 03 17 2a 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
        hx("e3 02 00 32 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
        {"lk": 1},
    ),
    "bypass_security_control": (
        hx("53 54 01 94 20 01 00 36"),
        hx("53 54 01 94 1f 20 03 d5"),
        {"lk": 1},
    ),
    "preflash_validation_bypass": (
        hx("42 41 02 94 80 00 00 36"),
        hx("42 41 02 94 1f 20 03 d5"),
        {"lk": 1},
    ),
    "vbmeta_device_state_locked": (
        hx("1f 01 00 71 41 04 00 f0 42 01 89 9a 21 a8 29 91"),
        hx("1f 01 00 71 41 04 00 f0 e2 03 0a aa 21 a8 29 91"),
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


def apply_patches(data: bytes, patches: dict = PATCHES) -> bytes:
    parts = cert.parse_parts(data)
    triples = cert.signed_triples(parts)
    required = {part for _orig, _patched, targets in patches.values() for part in targets}
    if required - {img.name for img, _c1, _c2 in triples}:
        raise ValueError("missing required patch partitions")
    out = bytearray(data)
    for part in parts:
        if part.is_cert:
            continue
        for name, (orig, patched, expected_by_part) in patches.items():
            if part.name not in expected_by_part:
                continue
            region = out[part.data_off : part.data_off + part.dsize]
            hits = find_all(bytes(region), orig)
            expected = expected_by_part[part.name]
            if len(hits) != expected:
                raise ValueError(
                    f"{name}: {part.name} has {len(hits)} hits, expected {expected}"
                )
            for h in hits:
                start = part.data_off + h
                out[start : start + len(patched)] = patched
    return bytes(out)


def verify_patches(stock: bytes, artifact: bytes, patches: dict = PATCHES) -> bool:
    """Compare every payload against the exact stock-site replacements."""
    expected = apply_patches(stock, patches)
    wanted = cert.signed_triples(cert.parse_parts(expected))
    actual = cert.signed_triples(cert.parse_parts(artifact))
    if [p.name for p, _c1, _c2 in wanted] != [p.name for p, _c1, _c2 in actual]:
        return False
    ok = True
    for (before, _c1, _c2), (after, _a1, _a2) in zip(wanted, actual):
        good = (expected[before.off : before.data_off] == artifact[after.off : after.data_off]
                and expected[before.data_off : before.end] == artifact[after.data_off : after.end])
        print(f"  {before.name:<12} exact payload: {'OK' if good else 'FAIL'}")
        ok &= good
    return ok


def main(stock: str = STOCK, out: str = OUT, patches: dict = PATCHES) -> int:
    print(f"stock   : {stock}")
    print(f"output  : {out}")
    print(f"patches : {len(patches)}")

    try:
        with open(stock, "rb") as fh:
            data = fh.read()
        if not cert.verify(data):
            return 1
        patched = apply_patches(data, patches)
        signed = cert.apply_cert_bypass(patched, CERT_TARGETS)

        print("\n--- patch verification ---")
        ok = verify_patches(data, signed, patches)
        print("\n--- certificate/hash consistency ---")
        ok &= cert.verify(signed)
        if not ok:
            return 1
        with open(out, "wb") as fh:
            fh.write(signed)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"\nwrote {out} ({len(data)} -> {len(signed)} bytes)")
    print("OFFLINE VERIFIED — not a boot test or a Strong Integrity result")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
