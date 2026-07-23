#!/usr/bin/env python3
"""
Pattern-analysis harness for the cancunf LK image.
Reproduces every finding and prints candidate locations for the open patches.

Usage: PYTHONPATH=/tmp/liblk python3 analysis/find_patches.py
"""
import sys, os
sys.path.insert(0, '/tmp/liblk')
from liblk import LkImage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
img = LkImage(os.path.join(ROOT, 'firmware', 'lk.img'))
BASE = 0xffff000050f00000  # cancunf lk load address (from liblk parse)

def hx(s): return bytes.fromhex(s.replace(' ', ''))
def count(data, needle):
    n, s = 0, 0
    while True:
        i = data.find(needle, s)
        if i < 0: break
        n += 1; s = i + 1
    return n

print(f'partitions: {list(img.partitions.keys())}')
print(f'load base : 0x{BASE:x}')

CONFIRMED = {
    'sec_get_vfy_policy': hx('00 01 00 b4 fd 7b bf a9'),
    'spoof_lock_state'  : hx('20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91'),
    'spoof_sboot_state' : hx('fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52'),
}
print('\n--- CONFIRMED patches (hit count per partition) ---')
for name, pat in CONFIRMED.items():
    parts = {p: count(bytes(part.data), pat) for p, part in img.partitions.items()}
    print(f'  {name:<20} {parts}')

print('\n--- OPEN 1: force_green_state structural candidates ---')
print('  (adrp x8,page ; str wN,[x8,#imm] ; ret)  -- 13 hits, need Ghidra xref to boot-state logic')
lk = bytes(img.partitions['lk'].data)
for i in range(0, len(lk) - 12):
    if lk[i+8:i+12] != hx('c0 03 5f d6'): continue
    strw = int.from_bytes(lk[i+4:i+8], 'little')
    if (strw & 0xffc003ff) != 0xb9000000 + (8 << 5): continue
    adrp = int.from_bytes(lk[i:i+4], 'little')
    if (adrp & 0x9f00001f) != 0x90000008: continue
    imm = ((strw >> 10) & 0xfff) << 2
    print(f'  lk+0x{i:x} (vaddr 0x{BASE+i:x}): {lk[i:i+12].hex(" ")}  str w{strw&0x1f},[x8,#0x{imm:x}]')

print('\n--- OPEN 2: preflash validation string + neighborhood ---')
s = lk.find(b'Preflash validation failed')
print(f'  string @ lk+0x{s:x} (vaddr 0x{BASE+s:x})')
print(f'  page 0x{(BASE+s)&~0xfff:x}  off-in-page 0x{(BASE+s)&0xfff:x}')
print('  => no clean adrp+add xref via byte scan; resolve xrefs in Ghidra')
print('     (string may be reached via adrp+ldr literal pool or adr)')

print('\n--- sanity: device fingerprint strings ---')
for needle in (b'MBM-3.1-cancunf', b'k6855v1_64_cancun', b'img_auth_required'):
    i = lk.find(needle)
    print(f'  {needle.decode():24} {"found @0x{:x}".format(i) if i>=0 else "MISSING"}')
