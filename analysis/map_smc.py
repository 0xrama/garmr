#!/usr/bin/env python3
"""
map_smc.py — map the lk -> EL3 (bl2_ext) SMC call surface.

Finds the SMC trampoline function(s) in each partition, then finds every bl
caller of those trampolines and reconstructs the SMC function id in w0/x0 by
tracking movz/movk backwards from each callsite.

This answers: "what services does LK request from EL3 at runtime?" — if a
service is 'get lock/boot state', that's the live channel fenrir-style patches
need to influence (and the one the cancunf attestation ultimately consumes).
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

IMG = sys.argv[1] if len(sys.argv) > 1 else "firmware/V1TDS35H.83-20-5-12/lk.img"
BASE = 0xFFFF000050F00000
PARTITIONS = {
    "lk": (0x200, 0x12F4B8),
    "bl2_ext": (0x130790, 0xBCA98),
    "aee": (0x1EE300, 0xFDCB8),
}

SMC_WORD = struct.pack("<I", 0xD4000003)


def pimm(s):
    s = s.strip().lstrip("#").rstrip("]").split("!")[0].split(",")[0].strip()
    return int(s, 16)


def main():
    buf = open(IMG, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True

    for name, (start, size) in PARTITIONS.items():
        insns = list(md.disasm(buf[start : start + size], BASE + start))
        by_addr = {i.address: i for i in insns}
        bl_targets = {}
        for i in insns:
            if i.mnemonic == "bl":
                try:
                    bl_targets.setdefault(pimm(i.op_str), []).append(i.address)
                except ValueError:
                    pass

        print(f"\n===== [{name}] =====")
        # find smc sites
        sites = []
        off = start
        while True:
            j = buf.find(SMC_WORD, off, start + size)
            if j == -1:
                break
            sites.append(BASE + j)
            off = j + 4
        for smc_rt in sites:
            # find function start: walk back to previous 'stp x29, x30' prologue
            idx = [k for k, i in enumerate(insns) if i.address == smc_rt][0]
            fstart = None
            for k in range(idx, max(0, idx - 2000), -1):
                i = insns[k]
                if i.mnemonic == "ret" and k < idx - 1:
                    fstart = insns[k + 1].address
                    break
            fstr = f"{fstart:#x}" if fstart else "UNKNOWN"
            print(f"\nsmc @ {smc_rt:#x}, function starts ~{fstr}")
            callers = bl_targets.get(fstart, []) if fstart else []
            print(f"  {len(callers)} bl-callers:")
            for c in callers:
                # reconstruct w0 from ~12 insns before the call
                cidx = [k for k, i in enumerate(insns) if i.address == c][0]
                regs = {}
                for ins in insns[max(0, cidx - 12) : cidx + 1]:
                    if ins.mnemonic in ("movz", "movk"):
                        dst, imm = ins.op_str.split(", ")[0], ins.op_str.split(", ")[1]
                        try:
                            v = pimm(imm)
                        except ValueError:
                            continue
                        shift = 0
                        if "lsl" in ins.op_str:
                            shift = int(ins.op_str.split("lsl #")[-1])
                        cur = regs.get(dst, 0)
                        if ins.mnemonic == "movz":
                            cur = 0
                        mask = 0xFFFF << shift
                        regs[dst] = (cur & ~mask) | ((v << shift) & mask)
                    elif ins.mnemonic == "mov" and ", #" in ins.op_str:
                        dst, imm = ins.op_str.split(", ")
                        try:
                            regs[dst] = pimm(imm)
                        except ValueError:
                            pass
                w0 = regs.get("w0", regs.get("x0"))
                print(f"  call from {c:#x}: w0 = {w0 if w0 is None else hex(w0)}")


if __name__ == "__main__":
    main()
