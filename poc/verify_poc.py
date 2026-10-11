#!/usr/bin/env python3
"""Verify the exact canonical artifact against matching stock, stdlib only.

Usage: python3 poc/verify_poc.py stock.img artifact.img --build 20-5-14
This is offline consistency verification, not hardware authorization or safety.
"""
import argparse
import sys
from pathlib import Path

import build_native_20_5_12 as native12
import build_native_20_5_14 as native14
import mtk_cert as cert

BUILDERS = {"20-5-12": native12, "20-5-14": native14}


def verify(stock: bytes, artifact: bytes, build: str = "20-5-12") -> bool:
    try:
        builder = BUILDERS[build]
        if not cert.verify(stock):
            return False
        expected = cert.apply_cert_bypass(builder.apply_patches(stock), builder.CERT_TARGETS)
        if artifact != expected:
            print("FAIL: artifact differs from the exact canonical stock-to-build result")
            return False
        return cert.verify(artifact)
    except (ValueError, KeyError) as exc:
        print(f"FAIL: {exc}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock", type=Path)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--build", choices=BUILDERS, default="20-5-12")
    args = parser.parse_args()
    try:
        ok = verify(args.stock.read_bytes(), args.artifact.read_bytes(), args.build)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("OFFLINE VERIFIED" if ok else "VERIFICATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
