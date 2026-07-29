#!/usr/bin/env python3
"""
Cancunf LK patch-analysis harness.

Reproduces byte-level findings for the cancunf LK image and prints the exact
Ghidra-pinned patch sites discovered for V1TDS35H.83-20-5-7.

Usage:
  LIBLK_PATH=/path/to/liblk CANCUNF_STOCK=firmware/V1TDS35H.83-20-5-7/lk.img \
    python3 analysis/find_patches.py
"""
import os
import sys

sys.path.insert(0, os.environ.get("LIBLK_PATH", "/Users/sriram/code/rom/liblk"))
from liblk import LkImage  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOCK = os.environ.get("CANCUNF_STOCK", os.path.join(ROOT, "firmware", "V1TDS35H.83-20-5-12", "lk.img"))
BASE = 0xFFFF000050F00000  # cancunf LK partition load address used in notes


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


def part_bytes(img: LkImage, name: str) -> bytes:
    return bytes(img.partitions[name].data)


def print_pattern(name: str, data: bytes, pattern: bytes, replacement: bytes | None = None) -> None:
    hits = find_all(data, pattern)
    print(f"{name:<34} hits={len(hits)} offsets={[hex(x) for x in hits]}")
    if replacement is not None:
        print(f"  original   : {pattern.hex(' ')}")
        print(f"  replacement: {replacement.hex(' ')}")


def main() -> int:
    img = LkImage(STOCK)
    raw = open(STOCK, "rb").read()
    lk = part_bytes(img, "lk")

    # liblk partition data excludes the 0x200-byte flat container header before lk.
    lk_flat_start = raw.find(lk[:4096])
    print(f"stock image : {STOCK}")
    print(f"partitions  : {list(img.partitions.keys())}")
    print(f"load base   : 0x{BASE:x}")
    print(f"lk flat start: 0x{lk_flat_start:x}")

    print("\n--- CONFIRMED in current PoC artifact (hit count per partition) ---")
    confirmed = {
        "sec_get_vfy_policy": hx("00 01 00 b4 fd 7b bf a9"),
        "spoof_lock_state": hx("20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91"),
        "spoof_sboot_state": hx("fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52"),
    }
    for name, pat in confirmed.items():
        counts = {p: len(find_all(bytes(part.data), pat)) for p, part in img.partitions.items()}
        print(f"{name:<20} {counts}")

    print("\n--- PINNED LK-only patches (20-5-7 flat offsets) ---")
    pinned = {
        "force_green_state": (
            hx("88 05 00 d0 00 69 02 b9 c0 03 5f d6"),
            hx("88 05 00 d0 1f 69 02 b9 c0 03 5f d6"),
            "FUN_000738ec: str w0,[x8,#0x268] -> str wzr,[x8,#0x268]",
        ),
        "avb_allow_verification_error": (
            hx("e3 03 17 2a 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
            hx("e3 02 00 32 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35"),
            "FUN_00073078: mov w3,w23 -> orr w3,w23,#1 before AVB slot verify",
        ),
        "bypass_security_control": (
            hx("53 54 01 94 20 01 00 36"),
            hx("53 54 01 94 1f 20 03 d5"),
            "FUN_0004d9e0 path: bl FUN_000a2b48 (lock/security state); tbz w0,#0 -> nop",
        ),
        "preflash_validation_bypass": (
            hx("42 41 02 94 80 00 00 36"),
            hx("42 41 02 94 1f 20 03 d5"),
            "Preflash validation caller: bl check; tbz w0,#0 -> nop",
        ),
    }
    for name, (pat, rep, desc) in pinned.items():
        print_pattern(name, raw, pat, rep)
        print(f"  {desc}")
        for off in find_all(raw, pat):
            if lk_flat_start >= 0 and off >= lk_flat_start:
                print(f"  flat=0x{off:x} lk+0x{off - lk_flat_start:x} vaddr=0x{BASE + off - lk_flat_start:x}")

    print("\n--- Boot-state / AVB / preflash strings (flat offsets) ---")
    strings = [
        b"androidboot.verifiedbootstate=orange",
        b"boot state: green\n",
        b"Boot state: %s",
        b"boot_state %d avb_ret = %d\n",
        b"AVB_SLOT_VERIFY",
        b"Verification failed\n",
        b"Verified boot signature",
        b"Preflash validation failed",
        b"MBM-3.1-cancunf",
    ]
    for needle in strings:
        hits = find_all(raw, needle)
        printable = needle.decode("ascii", "replace")
        print(f"{printable:<42} {[hex(x) for x in hits[:5]]}{' ...' if len(hits) > 5 else ''}")

    print("\n--- Legacy structural search counts (not enough to patch alone) ---")
    tbz_hits = find_all(lk, hx("20 01 00 36"))
    tecno_hits = find_all(lk, hx("1f 0d 00 71 21 01 00 54"))
    print(f"<bl>; tbz w0,#0 family discriminator: {len(tbz_hits)} hits in lk")
    print(f"cmp w8,#3 ; b.ne Tecno-family cluster : {len(tecno_hits)} hits in lk")

    required_singletons = [
        "force_green_state",
        "avb_allow_verification_error",
        "bypass_security_control",
        "preflash_validation_bypass",
    ]
    ok = True
    for name in required_singletons:
        pat = pinned[name][0]
        hits = find_all(raw, pat)
        if len(hits) != 1:
            print(f"ERROR: {name} expected exactly 1 hit, got {len(hits)}")
            ok = False
    print("\n=== RESULT: %s ===" % ("PINNED PATTERNS VERIFIED" if ok else "CHECK FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
