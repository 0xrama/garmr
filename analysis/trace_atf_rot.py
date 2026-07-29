#!/usr/bin/env python3
"""
trace_atf_rot.py — find ATF's ROOT_OF_TRUST service handler inside tee.img/atf.

The cancunf ATF runtime (tee.img partition 'atf') exposes MTKSIP services
including MTK_SIP_GET_ROOT_OF_TRUST and MTK_SIP_LK_ROOT_OF_TRUST.
If that service hands boot/lock state to the TEE or kernel, it is the
patchable channel (tee.img is unverified in fenrir mode) that makes
deviceLocked/verifiedBootState spoofable — the "fenrir on pacman" equivalent.

Steps:
  1. disassemble atf, reconstruct absolute targets of adrp+add pairs
  2. infer atf's runtime load base from string offsets (consensus)
  3. locate svc-name table entries for the ROT strings
  4. locate the adjacent handler function pointer, disassemble the handler
"""
import re
import struct
import sys
from collections import Counter

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TEE_IMG = sys.argv[1] if len(sys.argv) > 1 else "tee.img"

buf = open(TEE_IMG, "rb").read()
ATF_OFF, ATF_SIZE = 0x200, 0x3BE78
atf = buf[ATF_OFF : ATF_OFF + ATF_SIZE]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.skipdata = True
insns = list(md.disasm(atf, 0x0))  # addresses relative to atf start for now


def pimm(s):
    s = s.strip().lstrip("#").rstrip("]").split("!")[0].split(",")[0].strip()
    return int(s, 16)


# 1. build map: register -> absolute page from adrp; resolve add xD, xS, #imm
computed = []  # (site_addr_in_atf, absolute_target)
regs = {}
for ins in insns:
    if ins.mnemonic == "adrp":
        p = ins.op_str.split(", ")
        try:
            regs[p[0]] = pimm(p[1])
        except Exception:
            pass
    elif ins.mnemonic == "add":
        p = ins.op_str.split(", ")
        if len(p) == 3 and p[1] in regs and p[2].startswith("#"):
            try:
                computed.append((ins.address, regs[p[1]] + pimm(p[2])))
            except Exception:
                pass
    else:
        # simple clobber tracking
        dst = ins.op_str.split(", ")[0]
        if dst in regs and ins.mnemonic not in ("add",):
            regs.pop(dst, None)

# 2. candidate bases from string consensus
strings = {}
for m in re.finditer(rb'[\x20-\x7e]{8,}', atf):
    s = m.group(0)
    if any(k in s for k in (b"MTK_SIP_", b"PL2TFA", b"ufs_ctrl", b"ERROR", b"error")):
        strings[m.start()] = s.decode(errors="replace")

counts = Counter()
cset = set(c for _, c in computed)
for s_off in strings:
    for c in cset:
        counts[c - s_off] += 1
base, hits = counts.most_common(1)[0]
print(f"consensus ATF load base candidate: {base:#x} (supported by {hits} string refs)")

# NOTE: disassembly is 0-based relative to atf start, so all 'computed' values
# are already RELATIVE to atf start → use base = 0 for direct comparison with
# string offsets. (The -1 consensus above is regex off-by-one noise.)
base = 0

# 3. validate: how many strings are referenced under this base
refd = [(s_off, s) for s_off, s in strings.items() if base + s_off in cset]
print(f"{len(refd)}/{len(strings)} probed strings are referenced under base {base:#x}")

# 4. exact offsets of the ROT strings inside atf (relative == absolute here)
targets = {}
for m in re.finditer(rb'MTK_SIP_[A-Z0-9_]+', atf):
    if b"ROOT_OF_TRUST" in m.group(0):
        targets[m.group(0).decode()] = m.start()
print("\nROT string offsets (atf-relative):")
for n, a in targets.items():
    print(f"  {n}: {a:#x}")

# 5. find CODE sites computing those string addresses (adrp+add)
by_addr = {i.address: i for i in insns}
for name, soff in targets.items():
    print(f"\ncode sites computing {name} @{soff:#x}:")
    for site, val in computed:
        if val == soff:
            print(f"  site {site:#x}: {by_addr[site].mnemonic} {by_addr[site].op_str}")
            # dump the surrounding function window
            lo = site - 0x80
            hi = site + 0x40
            md2 = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            md2.skipdata = True
            for ins in md2.disasm(atf[lo:hi], lo):
                marker = ">>" if ins.address == site else "  "
                print(f"   {marker} {ins.address:#x}: {ins.mnemonic:8} {ins.op_str}")
EOF_MARKER = None
