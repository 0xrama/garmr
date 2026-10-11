#!/usr/bin/env python3
"""Deprecated command alias; use build_native_20_5_12.py directly."""
import sys

from build_native_20_5_12 import main


if __name__ == "__main__":
    print("Deprecated: use poc/build_native_20_5_12.py (no fenrir/liblk needed).",
          file=sys.stderr)
    raise SystemExit(main())
