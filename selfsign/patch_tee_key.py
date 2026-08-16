#!/usr/bin/env python3
"""
Patch the Kinibi trustlet-verification RSA public key inside tee.img to our own
key, then re-sign the tee.img container with the MTK CERT2 hash-override cert
bypass (so the boot chain accepts the modified image).

The key lives in the `tee` partition payload (Kinibi core):
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


TEE_DATA_OFF = 0x3D150   # tee partition data offset inside tee.img
KEY_OFF = 0x88000        # modulus offset inside the tee payload (kinibi_core.bin)
MODULUS_SIZE = 256


def main() -> int:
    p = argparse.ArgumentParser(description="Patch Kinibi MCLF verification key in tee.img")
    p.add_argument("--modulus", required=True, type=Path)
    p.add_argument("--tee-img", required=True, type=Path)
    p.add_argument("-o", "--output", required=True, type=Path)
    args = p.parse_args()

    modulus = args.modulus.read_bytes()
    if len(modulus) != MODULUS_SIZE:
        raise SystemExit(f"modulus must be {MODULUS_SIZE} bytes, got {len(modulus)}")

    img = bytearray(args.tee_img.read_bytes())
    key_img_off = TEE_DATA_OFF + KEY_OFF

    if key_img_off + MODULUS_SIZE > len(img):
        raise SystemExit(f"tee.img too small for key offset 0x{key_img_off:x}")

    old = bytes(img[key_img_off : key_img_off + MODULUS_SIZE])
    print(f"old modulus: {old.hex()[:32]}...")
    print(f"new modulus: {modulus.hex()[:32]}...")

    img[key_img_off : key_img_off + MODULUS_SIZE] = modulus

    # cert bypass only the `tee` partition (atf is untouched)
    signed = mtk_cert.apply_cert_bypass(bytes(img), {"tee"})
    args.output.write_bytes(signed)

    print(f"\nwrote {args.output} ({len(img)} -> {len(signed)} bytes)")
    print("\n--- verification ---")
    ok = mtk_cert.verify(signed)
    print(f"\n{'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
