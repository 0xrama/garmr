#!/usr/bin/env python3
"""
Build the minimal Cancunf 20-5-7 LK artifact for first hardware trial.

Included patches:
  1. sec_get_vfy_policy across bl2_ext/lk/aee
  2. avb_allow_verification_error in lk
  3. force_green_state in lk

Explicitly skipped:
  - spoof_lock_state
  - spoof_sboot_state (unsafe: 2 matches per partition)
  - bypass_security_control
  - preflash_validation_bypass

Usage:
  LIBLK_PATH=/Users/sriram/code/rom/liblk \
  FENRIR_INJECTOR_PATH=/Users/sriram/code/rom/fenrir/injector \
  python3 poc/build_minimal_20_5_7.py
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIBLK = os.environ.get("LIBLK_PATH", "/Users/sriram/code/rom/liblk")
FENRIR_INJECTOR = os.environ.get(
    "FENRIR_INJECTOR_PATH", "/Users/sriram/code/rom/fenrir/injector"
)
for path in (LIBLK, FENRIR_INJECTOR):
    if path not in sys.path:
        sys.path.insert(0, path)

from liblk import LkImage  # noqa: E402
from cert_bypass import CertBypass  # noqa: E402
from injector import BootloaderInjector  # noqa: E402
from patch_utils import MatchMode  # noqa: E402
from stage import PatchStage  # noqa: E402

STOCK = os.environ.get(
    "CANCUNF_STOCK", os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-7", "lk.img")
)
OUT = os.environ.get(
    "CANCUNF_OUT", os.path.join(HERE, "cancunf-fenrir-minimal-20-5-7.img")
)


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


PATCHES = {
    "sec_get_vfy_policy": (
        hx("00 01 00 b4 fd 7b bf a9"),
        hx("00 00 80 52 c0 03 5f d6"),
        {"bl2_ext": 1, "lk": 1, "aee": 1},
    ),
    "avb_allow_verification_error": (
        hx("e3 03 17 2a 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
        hx("e3 02 00 32 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
        {"lk": 1},
    ),
    "force_green_state": (
        hx("88 05 00 d0 00 69 02 b9 c0 03 5f d6"),
        hx("88 05 00 d0 1f 69 02 b9 c0 03 5f d6"),
        {"lk": 1},
    ),
}

SKIPPED_MUST_REMAIN_ORIGINAL = {
    "spoof_lock_state": (
        hx("20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91"),
        hx("88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6"),
        {"bl2_ext": 1, "lk": 1, "aee": 1},
    ),
    "spoof_sboot_state": (
        hx("fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52"),
        hx("48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5"),
        {"bl2_ext": 2, "lk": 2, "aee": 2},
    ),
}

STAGES = {
    "sec_get_vfy_policy": PatchStage(
        "sec_get_vfy_policy",
        pattern=PATCHES["sec_get_vfy_policy"][0].hex(" "),
        replacement=PATCHES["sec_get_vfy_policy"][1].hex(" "),
        match_mode=MatchMode.ALL,
        description="Disable internal LK verification policy",
    ),
    "avb_allow_verification_error": PatchStage(
        "avb_allow_verification_error",
        pattern=PATCHES["avb_allow_verification_error"][0].hex(" "),
        replacement=PATCHES["avb_allow_verification_error"][1].hex(" "),
        match_mode=MatchMode.ALL,
        description="Force AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR",
    ),
    "force_green_state": PatchStage(
        "force_green_state",
        pattern=PATCHES["force_green_state"][0].hex(" "),
        replacement=PATCHES["force_green_state"][1].hex(" "),
        match_mode=MatchMode.ALL,
        description="Force reported boot state to green",
    ),
}


def verify(stock_path: str, out_path: str) -> None:
    stock = LkImage(stock_path)
    poc = LkImage(out_path)
    assert set(stock.partitions) == set(poc.partitions), "partition set changed"

    print("\n--- included patches ---")
    for name, (orig, patched, expected_by_part) in PATCHES.items():
        print(f"[{name}]")
        for pname, expected in expected_by_part.items():
            sdata = bytes(stock.partitions[pname].data)
            pdata = bytes(poc.partitions[pname].data)
            stock_orig = len(find_all(sdata, orig))
            poc_orig = len(find_all(pdata, orig))
            poc_patched = len(find_all(pdata, patched))
            ok = stock_orig == expected and poc_orig == 0 and poc_patched == expected
            print(
                f"  {pname:<8} stock_orig={stock_orig} poc_orig={poc_orig} "
                f"poc_patched={poc_patched} expected={expected} {'OK' if ok else 'FAIL'}"
            )
            assert ok, f"{name} failed verification in {pname}"

    print("\n--- explicitly skipped patches remain unmodified ---")
    for name, (orig, patched, expected_by_part) in SKIPPED_MUST_REMAIN_ORIGINAL.items():
        print(f"[{name}]")
        for pname, expected in expected_by_part.items():
            sdata = bytes(stock.partitions[pname].data)
            pdata = bytes(poc.partitions[pname].data)
            stock_orig = len(find_all(sdata, orig))
            poc_orig = len(find_all(pdata, orig))
            poc_patched = len(find_all(pdata, patched))
            ok = stock_orig == expected and poc_orig == expected and poc_patched == 0
            print(
                f"  {pname:<8} stock_orig={stock_orig} poc_orig={poc_orig} "
                f"poc_patched={poc_patched} expected_orig={expected} {'OK' if ok else 'FAIL'}"
            )
            assert ok, f"skipped patch {name} was unexpectedly modified in {pname}"


def main() -> int:
    if not os.path.exists(STOCK):
        sys.exit(f"stock image not found: {STOCK}")

    inj = BootloaderInjector(STOCK, "payload/build", device_name="CancunfMinimal2057")
    inj.stages = STAGES
    if not inj.inject_all_stages():
        sys.exit("injection failed")
    signed = inj.apply_cert_bypass(CertBypass.OVERRIDE)
    print(f"cert_bypass signed: {signed}")
    inj.save_patched_bootloader(OUT)

    verify(STOCK, OUT)
    chk = LkImage(OUT)
    print(f"\nOK -> {OUT}")
    print(f"  stock   {os.path.getsize(STOCK)} bytes")
    print(f"  patched {os.path.getsize(OUT)} bytes")
    print(f"  re-parsed partitions: {list(chk.partitions.keys())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
