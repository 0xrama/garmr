#!/usr/bin/env python3
"""
Reproducible builder for the cancunf fenrir PoC.

Produces poc/cancunf-fenrir-poc.img from firmware/lk.img.
Requires: liblk (https://github.com/R0rt1z2/liblk) on PYTHONPATH or installed,
          and fenrir's injector/ package on PYTHONPATH.

Usage:
  PYTHONPATH=/path/to/liblk:/path/to/fenrir/injector python3 build_poc.py
"""
import sys, os

# Resolve helper paths (edit if your layout differs)
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIBLK = os.environ.get('LIBLK_PATH', '/tmp/liblk')
FENRIR_INJECTOR = os.environ.get('FENRIR_INJECTOR_PATH',
                                 '/Users/sriram/code/rom/fenrir/injector')
for p in (LIBLK, FENRIR_INJECTOR):
    if p not in sys.path:
        sys.path.insert(0, p)

from liblk import LkImage                                          # noqa: E402
from cert_bypass import CertBypass                                 # noqa: E402
from stage import PatchStage                                       # noqa: E402
from patch_utils import MatchMode                                  # noqa: E402
from injector import BootloaderInjector                            # noqa: E402

# Stock input and PoC output are env-configurable so the same builder targets
# any firmware build. Defaults preserve the original 20-5-5 reference target.
STOCK = os.environ.get('CANCUNF_STOCK',
                       os.path.join(ROOT, 'firmware', 'lk.img'))
OUT = os.environ.get('CANCUNF_OUT',
                     os.path.join(HERE, 'cancunf-fenrir-poc.img'))

# --- patches (mirror devices/cancunf.py) ---
STAGES = {
    'sec_get_vfy_policy': PatchStage(
        'sec_get_vfy_policy',
        pattern='00 01 00 b4 fd 7b bf a9',
        replacement='00 00 80 52 c0 03 5f d6',
        match_mode=MatchMode.ALL,
        description='Disable secure boot policy enforcement (EL3)'),
    'spoof_lock_state': PatchStage(
        'spoof_lock_state',
        pattern='20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91',
        replacement='88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6',
        match_mode=MatchMode.ALL,
        description='Force lock state to LKS_LOCK'),
    'spoof_sboot_state': PatchStage(
        'spoof_sboot_state',
        pattern='fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52',
        replacement='48 44 00 52 08 00 00 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
        match_mode=MatchMode.ALL,
        description='Force sboot state to ATTR_SBOOT_ONLY_ENABLE_ON_SCHIP'),
}


def main():
    if not os.path.exists(STOCK):
        sys.exit(f'stock image not found: {STOCK}')
    inj = BootloaderInjector(STOCK, 'payload/build', device_name='Cancunf')
    inj.stages = STAGES
    if not inj.inject_all_stages():
        sys.exit('injection failed')
    signed = inj.apply_cert_bypass(CertBypass.OVERRIDE)
    print(f'cert_bypass signed: {signed}')
    inj.save_patched_bootloader(OUT)
    # verify
    chk = LkImage(OUT)
    b = bytes(chk.partitions['bl2_ext'].data)
    assert bytes.fromhex('00010 0b4fd7bbfa9'.replace(' ', '')) not in b
    assert bytes.fromhex('000080 52c0035fd6'.replace(' ', '')) in b
    print(f'\nOK -> {OUT}')
    print(f'  stock {os.path.getsize(STOCK)} -> patched {os.path.getsize(OUT)} bytes')
    print(f'  re-parsed: {len(chk.partitions)} partitions: {list(chk.partitions.keys())}')


if __name__ == '__main__':
    main()
