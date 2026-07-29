#!/usr/bin/env python3
"""
Build Cancunf 20-5-12 LK artifact with vbmeta.device_state forced to locked.

Includes all patches from build_lockspoof_20_5_12.py plus:
  - vbmeta_device_state_locked in lk libavb cmdline builder

Still skips spoof_sboot_state.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import build_lockspoof_20_5_12 as base  # noqa: E402

base.OUT = os.environ.get(
    "CANCUNF_OUT",
    os.path.join(HERE, "cancunf-fenrir-vbmeta-locked-20-5-12.img"),
)

orig = base.hx("1f 01 00 71 41 04 00 f0 42 01 89 9a 21 a8 29 91")
patched = base.hx("1f 01 00 71 41 04 00 f0 e2 03 0a aa 21 a8 29 91")
base.PATCHES["vbmeta_device_state_locked"] = (orig, patched, {"lk": 1})
base.STAGES["vbmeta_device_state_locked"] = base.PatchStage(
    "vbmeta_device_state_locked",
    pattern=orig.hex(" "),
    replacement=patched.hex(" "),
    match_mode=base.MatchMode.ALL,
    description="Force androidboot.vbmeta.device_state to locked",
)

if __name__ == "__main__":
    raise SystemExit(base.main())
