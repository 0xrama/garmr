#!/usr/bin/env python3
"""
Re-sign an MCLF v2.5 trustlet with an RSA-2048 private key.

WARNING: this produces a CORRECT-FORMAT signature block, but the cancunf
device's actual trustlet verification key appears to be efuse/hardware-backed
(see notes in selfsign/README.md and the self-sign investigation). Use this
only once the correct signing key is known, or for format research.

Default scheme: SHA-256 + PKCS#1 v1.5 over region [0, 0x403f8) (header + text +
data). Override with flags if the real scheme differs.

Usage:
    python3 selfsign/sign_trustlet.py \
        --key selfsign/key.pem \
        --trustlet poc/trustlet_patch/0706000000000000000000000000004d.tlbin \
        -o selfsign/trustlet_selfsigned.tlbin
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

MCLF_MAGIC = b"MCLF"
V25_HEADER_SIZE = 0x80
TEXT_LEN = 0x3FAC8
DATA_LEN = 0x8B0
SEGMENTS_END = V25_HEADER_SIZE + TEXT_LEN + DATA_LEN  # 0x403f8

SIG_TYPE_RSA = 3
EXP = b"\x01\x00\x01"  # 0x10001 big-endian, 3 bytes


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def sign_v15(key, data: bytes, sha: int) -> bytes:
    h = hashes.SHA256() if sha == 256 else hashes.SHA384()
    return key.sign(data, padding.PKCS1v15(), h)


def sign_pss(key, data: bytes, sha: int, salt_len: int) -> bytes:
    h = hashes.SHA256() if sha == 256 else hashes.SHA384()
    return key.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=salt_len), h)


def main() -> int:
    p = argparse.ArgumentParser(description="Re-sign an MCLF v2.5 trustlet (RSA-2048)")
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--trustlet", required=True, type=Path)
    p.add_argument("-o", "--output", required=True, type=Path)
    p.add_argument("--sha", choices=["256", "384"], default="256")
    p.add_argument("--pss", action="store_true", help="use RSA-PSS instead of PKCS#1 v1.5")
    p.add_argument("--salt-len", type=int, default=32, help="PSS salt length")
    p.add_argument("--zero-blob", action="store_true",
                   help="zero the 132-byte pre-signature blob instead of copying it")
    args = p.parse_args()

    tl = bytearray(args.trustlet.read_bytes())
    if tl[:4] != MCLF_MAGIC:
        raise SystemExit("not an MCLF trustlet (bad magic)")

    # Verify the segment layout matches what we expect for this build
    text_start = struct.unpack_from("<I", tl, 0x30)[0]
    text_len = struct.unpack_from("<I", tl, 0x34)[0]
    data_len = struct.unpack_from("<I", tl, 0x3C)[0]
    if text_len != TEXT_LEN or data_len != DATA_LEN:
        raise SystemExit(
            f"unexpected segment sizes (text={text_len:#x}, data={data_len:#x}); "
            "this signer is build-specific"
        )
    if len(tl) < SEGMENTS_END + 256:
        raise SystemExit("trustlet too short")

    signed = bytes(tl[:SEGMENTS_END])
    key = load_private_key(args.key)
    sha = int(args.sha)

    sig = sign_pss(key, signed, sha, args.salt_len) if args.pss else sign_v15(key, signed, sha)
    if len(sig) != 256:
        raise SystemExit(f"expected 256-byte RSA-2048 signature, got {len(sig)}")

    blob = bytes(132) if args.zero_blob else bytes(tl[SEGMENTS_END : SEGMENTS_END + 132])

    out = bytearray(tl[:SEGMENTS_END])
    out += blob
    out += struct.pack("<I", SIG_TYPE_RSA)
    out += EXP
    out += sig

    args.output.write_bytes(out)
    print(f"wrote {args.output} ({len(tl)} -> {len(out)} bytes)")
    print(f"signed region: [0x00000, 0x{SEGMENTS_END:x}) ({SEGMENTS_END} bytes)")
    print(f"scheme: {'RSA-PSS' if args.pss else 'PKCS#1 v1.5'} SHA-{sha}")
    print("NOTE: device verification key is likely efuse-backed; this output is format-correct only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
