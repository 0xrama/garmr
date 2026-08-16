#!/usr/bin/env python3
"""
Patch Kinibi's MCLF trustlet signature-verification check so a modified
trustlet is accepted, then re-sign tee.img with the CERT2 cert bypass.

Status: BEST-GUESS (medium confidence). The self-sign route was disproved by
the parallel investigation — the real trustlet verification key is not the
in-flash RSA key (kinibi 0x88000); it is likely efuse/hardware-backed via the
MTK crypto SMC path. So bypass is the correct primary route.

The patched point is the loader's post-intro check of driver command 0xad,
which sits exactly where a verify/open-trustlet step runs (right after the MCLF
intro is read, before segment mapping):

    0x5ebe8: bl     #0x65b60      ; cmd 0xad (verify/load step)
    0x5ebec: mov    w19, w0
    0x5ebf0: cbz    w0, #0x5ecc4  ; success -> continue
    0x5ebf4: ...                   ; failure path

Patch (force the 0xad result to look successful):
    file 0x5ebf0:  cbz w0, #0x5ecc4   ->   b #0x5ecc4
    bytes:         a0 06 00 34        ->   35 00 00 14

tee.img offset for the same instruction = 0x3d150 + 0x5ebf0 = 0x9bd40.

Usage:
    python3 bypass/patch_verify.py \
        --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
        -o bypass/tee_bypassed.img
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "poc"))
import mtk_cert  # noqa: E402


TEE_DATA_OFF = 0x3D150    # tee partition data offset inside tee.img

# Best-guess bypass (medium confidence) — see docstring / bypass/README.md.
VERIFY_BRANCH_OFF = 0x5EBF0               # kinibi_core.bin offset
ORIGINAL = bytes.fromhex("a0 06 00 34")    # cbz w0, #0x5ecc4
PATCH = bytes.fromhex("35 00 00 14")       # b   #0x5ecc4  (unconditional continue)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tee-img", required=True, type=Path)
    p.add_argument("-o", "--output", required=True, type=Path)
    args = p.parse_args()

    img = bytearray(args.tee_img.read_bytes())
    off = TEE_DATA_OFF + VERIFY_BRANCH_OFF

    if off + len(PATCH) > len(img):
        raise SystemExit(f"tee.img too small for branch offset 0x{off:x}")

    old = bytes(img[off : off + len(PATCH)])
    if old != ORIGINAL:
        print(f"WARNING: expected {ORIGINAL.hex()} at 0x{off:x}, found {old.hex()} — "
              "aborting to avoid a bad patch. Recheck VERIFY_BRANCH_OFF.", file=sys.stderr)
        return 1

    print(f"branch @ tee.img 0x{off:x}: {old.hex()} -> {PATCH.hex()}")
    img[off : off + len(PATCH)] = PATCH

    signed = mtk_cert.apply_cert_bypass(bytes(img), {"tee"})
    args.output.write_bytes(signed)

    print(f"\nwrote {args.output} ({len(img)} -> {len(signed)} bytes)")
    print("\n--- verification ---")
    ok = mtk_cert.verify(signed)
    print(f"\n{'OK' if ok else 'FAIL'}")
    print("\nNOTE: this is a MEDIUM-CONFIDENCE patch. The definitive verify branch "
          "lives behind the runtime-initialized handler at [0x54000+0x8c]. "
          "Hardware-test on a sacrificial device with a recovery path.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
