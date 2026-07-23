"""
Cancunf (Motorola Moto G54 5G / G64 5G, MT6855 / Dimensity 7025) device entry
for the fenrir exploit framework.

CONFIRMED against firmware: V1TDS35H.83-20-5-5 RETIN (Android 15)

How to use:
  Drop this file into fenrir/injector/, add an import + append Cancunf to the
  DEVICES list in devices.py, place firmware/lk.img as bin/cancunf.bin, then:
      ./build.sh Cancunf /path/to/lk.img

STATUS:
  [x] sec_get_vfy_policy  -- confirmed 1x in bl2_ext/lk/aee (the core bypass)
  [x] spoof_lock_state    -- confirmed 1x in bl2_ext/lk/aee
  [~] spoof_sboot_state   -- 2x per partition; needs per-instance validation
  [ ] force_green_state   -- NOT YET PINNED (13 structural candidates, see notes/STATUS.md)
  [ ] preflash bypass     -- NOT YET PINNED (xref hunt needs Ghidra, see notes/STATUS.md)

WARNING: This is offline-verified at the byte level only. Boots/integrity/brick
safety are NOT verified. Firmware-build-specific: V1TDS35H.83-20-5-5 ONLY.
"""

from cert_bypass import CertBypass
from device import Device
from stage import PatchStage
from patch_utils import MatchMode


Cancunf = Device(
    'Cancunf',
    'Motorola Moto G54/G64 5G (MT6855)',
    {
        # ---- CORE: disable secure-boot verification at EL3 ----
        # Confirmed present (1 hit each) in bl2_ext, lk, aee.
        # Original:  cbz x0, ... ; stp x29, x30, [sp, #-0x10]!   (function prologue)
        # Patched:   mov w0, #0 ; ret                            (always "no verification needed")
        'sec_get_vfy_policy': PatchStage(
            'sec_get_vfy_policy',
            pattern='00 01 00 b4 fd 7b bf a9',
            replacement='00 00 80 52 c0 03 5f d6',
            match_mode=MatchMode.ALL,
            description='Disable secure boot policy enforcement (EL3)',
        ),

        # ---- Spoof lock state to LKS_LOCK ----
        # Confirmed present (1 hit each).
        'spoof_lock_state': PatchStage(
            'spoof_lock_state',
            pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
            replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
            match_mode=MatchMode.ALL,
            description='Force lock state to always be LKS_LOCK',
        ),

        # ---- Spoof sboot state ----
        # CAUTION: matches 2x per partition on cancunf (6 total). On other devices
        # this common-A variant matches 1x. Per-instance validation recommended
        # before flashing -- see notes/STATUS.md.
        'spoof_sboot_state': PatchStage(
            'spoof_sboot_state',
            pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
            replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
            match_mode=MatchMode.ALL,
            description='Force sboot state to ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP',
        ),
    },
    cert_bypass=CertBypass.OVERRIDE,
)
