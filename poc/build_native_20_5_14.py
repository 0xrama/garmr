#!/usr/bin/env python3
"""Build the seven-patch 20-5-14 artifact with the shared native pipeline.

Only three patterns differ from 20-5-12, through PC-relative immediates.
This build has not been hardware-validated. See notes/STATUS.md.
Environment: CANCUNF_STOCK and CANCUNF_OUT override the build-specific paths.
"""
from __future__ import annotations

import os

import build_native_20_5_12 as native
from build_native_20_5_12 import CERT_TARGETS, find_all, hx

STOCK = os.environ.get(
    "CANCUNF_STOCK",
    os.path.join(native.ROOT, "firmware", "V1TDS35H.83-20-5-14", "lk.img"),
)
OUT = os.environ.get(
    "CANCUNF_OUT", os.path.join(native.HERE, "cancunf-native-full-20-5-14.img"),
)

# Re-pinned sites: see analysis/confirm_repin.py. All other definitions are shared.
PATCHES = {
    **native.PATCHES,
    "force_green_state": (
        hx("88 05 00 f0 00 69 02 b9 c0 03 5f d6"),
        hx("88 05 00 f0 1f 69 02 b9 c0 03 5f d6"),
        {"lk": 1},
    ),
    "bypass_security_control": (
        hx("cd 54 01 94 20 01 00 36"),
        hx("cd 54 01 94 1f 20 03 d5"),
        {"lk": 1},
    ),
    "vbmeta_device_state_locked": (
        hx("1f 01 00 71 61 04 00 90 42 01 89 9a 21 a8 29 91"),
        hx("1f 01 00 71 61 04 00 90 e2 03 0a aa 21 a8 29 91"),
        {"lk": 1},
    ),
}


def apply_patches(data: bytes) -> bytes:
    return native.apply_patches(data, PATCHES)


def verify_patches(stock: bytes, artifact: bytes) -> bool:
    return native.verify_patches(stock, artifact, PATCHES)


def main() -> int:
    return native.main(STOCK, OUT, PATCHES)


if __name__ == "__main__":
    raise SystemExit(main())
