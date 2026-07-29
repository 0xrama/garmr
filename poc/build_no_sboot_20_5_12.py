#!/usr/bin/env python3
"""
Cancunf 20-5-12 LK artifact — 7 patches, DROPS spoof_sboot_state.

The 8-patch full build (with sboot) produces "Cannot load Android system" on
hardware. sboot changes the TEE's sboot state, likely altering dm-verity key
derivation and breaking verification of the stock system partition.

This variant includes everything EXCEPT sboot:
  1. sec_get_vfy_policy          — bl2_ext/lk/aee
  2. spoof_lock_state            — bl2_ext/lk/aee
  3. force_green_state           — lk
  4. avb_allow_verification_error— lk
  5. bypass_security_control     — lk
  6. preflash_validation_bypass  — lk
  7. vbmeta_device_state_locked  — lk
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (os.environ.get("LIBLK_PATH", "/Users/sriram/code/rom/liblk"),
             os.environ.get("FENRIR_INJECTOR_PATH", "/Users/sriram/code/rom/fenrir/injector")):
    if path not in sys.path:
        sys.path.insert(0, path)

# Import the full builder and strip sboot
import build_full_20_5_12 as base

base.OUT = os.environ.get("CANCUNF_OUT", os.path.join(HERE, "cancunf-fenrir-no-sboot-20-5-12.img"))
for key in ("spoof_sboot_state",):
    base.PATCHES.pop(key, None)
    base.STAGES.pop(key, None)

if __name__ == "__main__":
    raise SystemExit(base.main())
