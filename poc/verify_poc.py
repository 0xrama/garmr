#!/usr/bin/env python3
"""
Per-partition verification of a built PoC image against its stock source.
Confirms every patch landed in the right partition and no originals survive.

Usage:
  PYTHONPATH=/path/to/liblk \\
  python poc/verify_poc.py <stock_lk.img> <poc.img>

The PATCHES dict below mirrors poc/build_full_20_5_12.py. If you add or remove
a patch in the builder, update it here too.
"""
import sys
from liblk import LkImage

def hx(s): return bytes.fromhex(s.replace(' ', ''))
def find_all(data, needle):
    out, s = [], 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            break
        out.append(i); s = i + 1
    return out

# (name, original_pattern, patched_pattern, {partition: expected_hits})
# spoof_sboot_state has 2 legit hits per partition (both are sboot getters).
PATCHES = {
    'sec_get_vfy_policy': (
        hx('00 01 00 b4 fd 7b bf a9'),
        hx('00 00 80 52 c0 03 5f d6'),
        {'bl2_ext': 1, 'lk': 1, 'aee': 1},
    ),
    'spoof_lock_state': (
        hx('20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91'),
        hx('88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6'),
        {'bl2_ext': 1, 'lk': 1, 'aee': 1},
    ),
    'force_green_state': (
        hx('88 05 00 d0 00 69 02 b9 c0 03 5f d6'),
        hx('88 05 00 d0 1f 69 02 b9 c0 03 5f d6'),
        {'lk': 1},
    ),
    'avb_allow_verification_error': (
        hx('e3 03 17 2a 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35'),
        hx('e3 02 00 32 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35'),
        {'lk': 1},
    ),
    'bypass_security_control': (
        hx('53 54 01 94 20 01 00 36'),
        hx('53 54 01 94 1f 20 03 d5'),
        {'lk': 1},
    ),
    'preflash_validation_bypass': (
        hx('42 41 02 94 80 00 00 36'),
        hx('42 41 02 94 1f 20 03 d5'),
        {'lk': 1},
    ),
    'vbmeta_device_state_locked': (
        hx('1f 01 00 71 41 04 00 f0 42 01 89 9a 21 a8 29 91'),
        hx('1f 01 00 71 41 04 00 f0 e2 03 0a aa 21 a8 29 91'),
        {'lk': 1},
    ),
}


def main():
    if len(sys.argv) != 3:
        sys.exit('usage: verify_poc.py <stock.img> <poc.img>')
    stock_path, poc_path = sys.argv[1], sys.argv[2]
    stock = LkImage(stock_path)
    poc = LkImage(poc_path)

    print('stock partitions: %s' % list(stock.partitions.keys()))
    print('poc   partitions: %s' % list(poc.partitions.keys()))
    assert set(stock.partitions) == set(poc.partitions), 'partition set changed!'

    ok = True
    for name, (orig, patched, per_part) in PATCHES.items():
        print('\n[%s]' % name)
        for pname, expected in per_part.items():
            sdata = bytes(stock.partitions[pname].data)
            pdata = bytes(poc.partitions[pname].data)
            orig_in_stock = len(find_all(sdata, orig))
            orig_in_poc = len(find_all(pdata, orig))
            patched_in_poc = len(find_all(pdata, patched))
            good = (orig_in_stock == expected and orig_in_poc == 0
                    and patched_in_poc >= expected)
            ok &= good
            print('  %-8s stock_orig=%d  poc_orig=%d  poc_patched=%d  expected=%d  %s'
                  % (pname, orig_in_stock, orig_in_poc, patched_in_poc,
                     expected, 'OK' if good else 'FAIL'))

    print('\n=== RESULT: %s ===' % ('ALL PATCHES VERIFIED' if ok else 'VERIFICATION FAILED'))
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
