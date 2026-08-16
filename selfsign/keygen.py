#!/usr/bin/env python3
"""
Generate an RSA-2048 keypair for re-signing the KeyMint trustlet, and emit the
public modulus in the raw 256-byte big-endian form that Kinibi stores at
tee.img offset 0xc5150 (== kinibi_core.bin offset 0x88000).

Usage:
    python3 selfsign/keygen.py            # writes key.pem, pub.pem, modulus.bin
    python3 selfsign/keygen.py --out DIR

No Python crypto deps needed (shells out to openssl).
"""

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def main() -> int:
    p = argparse.ArgumentParser(description="RSA-2048 keygen for trustlet re-sign")
    p.add_argument("--out", default=".", help="output directory")
    args = p.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    key = out / "key.pem"
    pub = out / "pub.pem"
    mod = out / "modulus.bin"

    run(["openssl", "genrsa", "-out", str(key), "2048"])
    run(["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(pub)])

    modhex = run(["openssl", "rsa", "-in", str(key), "-noout", "-modulus"]).strip()
    modhex = modhex.removeprefix("Modulus=")
    modbytes = bytes.fromhex(modhex)
    assert len(modbytes) == 256, f"unexpected modulus size {len(modbytes)}"

    mod.write_bytes(modbytes)

    print(f"private key : {key}")
    print(f"public key  : {pub}")
    print(f"modulus     : {mod} ({len(modbytes)} bytes)")
    print(f"modulus hex : {modhex}")
    print(f"\nPatch target: tee.img offset 0xc5150 (kinibi_core.bin offset 0x88000)")
    print("  python3 selfsign/patch_tee_key.py --modulus modulus.bin --tee-img firmware/V1TDS35H.83-20-5-12/tee.img -o selfsign/tee_selfsigned.img")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
