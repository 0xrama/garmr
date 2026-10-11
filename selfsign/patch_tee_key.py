#!/usr/bin/env python3
"""
Replace a candidate Kinibi RSA public key with our own, then apply CERT2 hash
overrides. This key's role is unknown; neither boot-chain authorization nor
trustlet acceptance is established by local certificate verification.

The candidate key is in the `tee` partition payload (Kinibi core):
    tee.img offset = 0x3d150 + 0x88000 = 0xc5150   (256-byte modulus)
    exponent stays 0x10001 at 0x3d150 + 0x88100.

Usage:
    python3 selfsign/patch_tee_key.py \
        --modulus selfsign/modulus.bin \
        --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
        -o selfsign/tee_selfsigned.img
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "poc"))
import mtk_cert  # noqa: E402


KEY_OFF = 0x88000        # modulus offset inside the tee payload (kinibi_core.bin)
MODULUS_SIZE = 256


def main() -> int:
    p = argparse.ArgumentParser(description="Replace a candidate Kinibi RSA key (experimental)")
    p.add_argument("--modulus", required=True, type=Path)
    p.add_argument("--tee-img", required=True, type=Path)
    p.add_argument("-o", "--output", required=True, type=Path)
    args = p.parse_args()

    modulus = args.modulus.read_bytes()
    if len(modulus) != MODULUS_SIZE:
        raise SystemExit(f"modulus must be {MODULUS_SIZE} bytes, got {len(modulus)}")

    img = bytearray(args.tee_img.read_bytes())
    if not mtk_cert.verify(bytes(img)):
        return 1
    tee = next(p for p in mtk_cert.parse_parts(bytes(img)) if p.name == "tee")
    key_img_off = tee.data_off + KEY_OFF

    if KEY_OFF + MODULUS_SIZE + 4 > tee.dsize:
        raise SystemExit(f"tee.img too small for key offset 0x{key_img_off:x}")
    if img[key_img_off + MODULUS_SIZE : key_img_off + MODULUS_SIZE + 4] != b"\x01\x00\x01\x00":
        raise SystemExit("candidate key exponent anchor does not match")

    old = bytes(img[key_img_off : key_img_off + MODULUS_SIZE])
    print(f"old modulus: {old.hex()[:32]}...")
    print(f"new modulus: {modulus.hex()[:32]}...")

    img[key_img_off : key_img_off + MODULUS_SIZE] = modulus

    # cert bypass only the `tee` partition (atf is untouched)
    signed = mtk_cert.apply_cert_bypass(bytes(img), {"tee"})
    print("\n--- certificate/hash consistency ---")
    ok = mtk_cert.verify(signed)
    if not ok:
        return 1
    args.output.write_bytes(signed)
    print(f"\nwrote {args.output} ({len(img)} -> {len(signed)} bytes)")
    print("Experimental candidate key replacement; device acceptance unknown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
