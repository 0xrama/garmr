#!/usr/bin/env python3
"""
Build the full Cancunf 20-5-12 LK artifact — every applicable pinned patch.

7 patches (spoof_sboot_state intentionally omitted — see notes/STATUS.md):
  1. sec_get_vfy_policy          — bl2_ext/lk/aee (core EL3 chain bypass)
  2. spoof_lock_state            — bl2_ext/lk/aee (force LKS_LOCK)
  3. force_green_state           — lk (boot state global -> green)
  4. avb_allow_verification_error— lk (allow AVB verification errors)
  5. bypass_security_control     — lk (skip lock/security error branch)
  6. preflash_validation_bypass  — lk (skip preflash validation failure branch)
  7. vbmeta_device_state_locked  — lk (force androidboot.vbmeta.device_state=locked)

spoof_sboot_state was removed after hardware testing proved it is both
unnecessary (sboot global = 0x11, getter already returns 1 = enabled) and
harmful (the fenrir replacement decodes as eor w8,w2,#0x3ffff — XOR with an
uninitialized register — writing garbage that breaks dm-verity →
"Cannot load Android system").

Usage:
  LIBLK_PATH=/Users/sriram/code/rom/liblk \
  FENRIR_INJECTOR_PATH=/Users/sriram/code/rom/fenrir/injector \
  python3 poc/build_full_20_5_12.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIBLK = os.environ.get("LIBLK_PATH", "/Users/sriram/code/rom/liblk")
FENRIR_INJECTOR = os.environ.get("FENRIR_INJECTOR_PATH", "/Users/sriram/code/rom/fenrir/injector")
for path in (LIBLK, FENRIR_INJECTOR):
    if path not in sys.path:
        sys.path.insert(0, path)

from liblk import LkImage  # noqa: E402
from cert_bypass import CertBypass  # noqa: E402
from injector import BootloaderInjector  # noqa: E402
from patch_utils import MatchMode  # noqa: E402
from stage import PatchStage  # noqa: E402

STOCK = os.environ.get("CANCUNF_STOCK", os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "lk.img"))
OUT = os.environ.get("CANCUNF_OUT", os.path.join(HERE, "cancunf-fenrir-full-20-5-12.img"))


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


# (original, patched, {partition: expected_hit_count})
# expected counts verified against firmware/V1TDS35H.83-20-5-12/lk.img
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

STAGES = {
    name: PatchStage(
        name,
        pattern=orig.hex(" "),
        replacement=patched.hex(" "),
        match_mode=MatchMode.ALL,
        description=name,
    )
    for name, (orig, patched, _parts) in PATCHES.items()
}


def verify(stock_path: str, out_path: str) -> None:
    stock = LkImage(stock_path)
    poc = LkImage(out_path)
    assert set(stock.partitions) == set(poc.partitions), "partition set changed"

    print("\n--- patch verification ---")
    for name, (orig, patched, expected_by_part) in PATCHES.items():
        print(f"[{name}]")
        for pname, expected in expected_by_part.items():
            sdata = bytes(stock.partitions[pname].data)
            pdata = bytes(poc.partitions[pname].data)
            stock_orig = len(find_all(sdata, orig))
            poc_orig = len(find_all(pdata, orig))
            poc_patched = len(find_all(pdata, patched))
            ok = stock_orig == expected and poc_orig == 0 and poc_patched >= expected
            print(
                f"  {pname:<8} stock_orig={stock_orig} poc_orig={poc_orig} "
                f"poc_patched={poc_patched} expected={expected} {'OK' if ok else 'FAIL'}"
            )
            assert ok, f"{name} failed verification in {pname}"


def main() -> int:
    if not os.path.exists(STOCK):
        sys.exit(f"stock not found: {STOCK}")

    print(f"stock : {STOCK}")
    print(f"output: {OUT}")
    print(f"patches: {len(PATCHES)}")

    inj = BootloaderInjector(STOCK, 'payload/build', device_name='Cancunf')
    inj.stages = STAGES
    if not inj.inject_all_stages():
        sys.exit("injection failed")
    signed = inj.apply_cert_bypass(CertBypass.OVERRIDE)
    print(f"cert_bypass signed: {signed}")
    inj.save_patched_bootloader(OUT)

    verify(STOCK, OUT)

    stock_size = os.path.getsize(STOCK)
    poc_size = os.path.getsize(OUT)
    print(f"\nOK -> {OUT}")
    print(f"stock {stock_size} -> patched {poc_size} bytes")
    chk = LkImage(OUT)
    print(f"re-parsed: {len(chk.partitions)} partitions: {list(chk.partitions.keys())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
