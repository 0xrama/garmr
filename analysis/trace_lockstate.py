#!/usr/bin/env python3
"""
trace_lockstate.py — second-pass audit of the "attestation boundary" conclusion.

The 2026-07-26 Ghidra analysis concluded that cancunf's lock-state code is
write-only/dead and that the TEE reads deviceLocked from RPMB directly, so LK
patching can't touch attestation. Ghidra xrefs miss three things:

  1. absolute function pointers in dispatch tables (SMC handler tables),
  2. references where the adrp pairing was broken across basic blocks,
  3. additional readers of the sec_update partition (seccfg) beyond the two
     known sec_get_seccfg functions.

This script re-checks all three with a raw capstone sweep of lk.img and answers:
  - Are there readers of the lock-state globals beyond the known wrapper?
  - Do any function-pointer tables reference the known seccfg/lock functions?
  - Which functions reference the "sec_update" partition name string?
  - What SMC surface do lk/bl2_ext expose (smc issuers + SiP-id immediates)?

Usage: python3 analysis/trace_lockstate.py [path/to/lk.img]
"""

import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

IMG_PATH = sys.argv[1] if len(sys.argv) > 1 else "firmware/V1TDS35H.83-20-5-12/lk.img"
BASE = 0xFFFF000050F00000  # runtime base == ghidra addr of file offset 0

PARTITIONS = {
    "lk": (0x200, 0x12F4B8),
    "bl2_ext": (0x130790, 0xBCA98),
    "aee": (0x1EE300, 0xFDCB8),
}

# Known points of interest (Ghidra / file offsets)
POI = {
    "lk.sec_get_seccfg": 0xC2CEC,
    "lk.sec_query_device_lock(dEAD wrapper)": 0xC2FE4,
    "bl2_ext.sec_query_device_lock_twin": 0x1AA2AC,
    "lk.sboot_getter_callee": 0xBED50,
    "lk.cert_processing_fn": 0xBFF28,
    "bl2_ext.sec_get_seccfg": 0x1A9FB4,
    # functions itself called right after seccfg refresh in the orchestrators
    "bl2_ext.sec_update_orchestrator_followup_1": 0x1A4684,
    "bl2_ext.sec_update_orchestrator_followup_2": 0x1A4F2C,
    "lk.sec_update_orchestrator_followup_1": 0xBC738,
    "lk.sec_update_orchestrator_followup_2": 0xBD014,
}


def load():
    with open(IMG_PATH, "rb") as f:
        return f.read()


def rt(off):
    return BASE + off


def pimm(s):
    """parse a capstone immediate like '#0xffff000051109000' or '#0xe48]' -> int"""
    s = s.strip().lstrip("#").rstrip("]").split("!")[0].split(",")[0].strip()
    return int(s, 16)


def disasm_partition(buf, start, size):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True  # keep scanning through data blobs
    code = buf[start : start + size]
    return list(md.disasm(code, rt(start)))


def disasm_window(buf, off, before, after):
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.skipdata = True
    s = max(0, off - before * 4) & ~3
    code = buf[s : off + after * 4]
    return list(md.disasm(code, rt(s)))


def find_adrp_pairs(insns, target_addr):
    """Find adrp+{add|ldr|str} pairs that compute target_addr."""
    hits = []
    target_page = target_addr & ~0xFFF
    target_off = target_addr & 0xFFF
    regs = {}  # reg -> page value
    for i, ins in enumerate(insns):
        if ins.mnemonic == "adrp":
            parts = ins.op_str.split(", ")
            reg = parts[0]
            try:
                imm = pimm(parts[1])
            except (IndexError, ValueError):
                regs.pop(reg, None)
                continue
            if imm == target_page:
                regs[reg] = imm
        elif ins.mnemonic in ("add", "ldr", "str", "ldrsw", "ldrb", "ldrh", "strb", "strh") and regs:
            parts = ins.op_str.split(", ")
            for reg, page in list(regs.items()):
                used = any(p == reg or p.startswith(reg + "]") or p.endswith("[" + reg) or ("[" + reg + "]") in p or ("[" + reg + ",") in ins.op_str for p in parts[1:])
                if not used:
                    continue
                if "#" not in ins.op_str:
                    imm = 0
                else:
                    try:
                        imm = pimm(ins.op_str.split("#")[-1])
                    except ValueError:
                        continue
                if page + imm == target_addr:
                    hits.append((ins.address, f"{ins.mnemonic} {ins.op_str}"))
        # drop tracking when a tracked reg is clobbered by something else
        for reg in list(regs):
            if ins.mnemonic != "adrp" and ins.op_str.split(", ")[0].rstrip("]") == reg and ins.mnemonic not in ("ldr", "str", "ldrb", "ldrh", "strb", "strh", "add", "ldrsw"):
                regs.pop(reg, None)
    return hits


def find_bl_targets(insns):
    bls = {}
    for ins in insns:
        if ins.mnemonic == "bl":
            try:
                tgt = pimm(ins.op_str)
            except ValueError:
                continue
            bls.setdefault(tgt, []).append(ins.address)
    return bls


def scan_qword_tables(buf, start, size):
    """scan data-ish regions for qword pointers into the image runtime range."""
    hits = []
    end = start + size
    lo, hi = BASE, BASE + len(buf)
    for off in range(start, end - 8, 8):
        (val,) = struct.unpack_from("<Q", buf, off)
        if lo <= val < hi:
            hits.append((off, val))
    return hits


def find_string(buf, s):
    out = []
    needle = s.encode()
    i = buf.find(needle)
    while i != -1:
        out.append(i)
        i = buf.find(needle, i + 1)
    return out


def main():
    buf = load()
    print(f"image: {IMG_PATH} ({len(buf)} bytes), base {BASE:#x}\n")

    # sanity: first lk insn
    first = struct.unpack_from("<I", buf, 0x200)[0]
    print(f"[sanity] lk first insn word @0x200: {first:#010x} (expect bl 0xb2a0 = 0x9400xxxx)\n")

    dis = {}
    for name, (start, size) in PARTITIONS.items():
        print(f"disassembling {name} ...", flush=True)
        dis[name] = disasm_partition(buf, start, size)
        print(f"  {len(dis[name])} insns")

    # 1. readers of ANY seccfg struct field + sboot global
    #    lk seccfg struct: page 0x51109000, imm 0xe40..0xec0 (file 0x209e40..)
    #    bl2ext seccfg struct: page 0x511be000, imm 0xd80..0xe00 (file 0x2bed80..)
    #    sboot global: page 0x5102e000, imm 0xe2c (file 0x12ee2c)
    print("\n== 1. ALL references into the seccfg state structs + sboot global ==")
    RANGES = [
        ("lk.seccfg_struct", 0xFFFF000051109000, 0xE40, 0xEC0),
        ("bl2ext.seccfg_struct", 0xFFFF0000511BE000, 0xD80, 0xE00),
        ("lk.sboot_global", 0xFFFF00005102E000, 0xE28, 0xE30),
    ]
    for label, page, imm_lo, imm_hi in RANGES:
        print(f"\n-- {label}: page {page:#x} imm {imm_lo:#x}..{imm_hi:#x}")
        for pname in PARTITIONS:
            for ins in dis[pname]:
                if ins.mnemonic != "adrp":
                    continue
                parts = ins.op_str.split(", ")
                if len(parts) != 2:
                    continue
                try:
                    if pimm(parts[1]) != page:
                        continue
                except ValueError:
                    continue
                reg = parts[0]
                # look at following insns for use with imm in range
                idx = dis[pname].index(ins)
                for ins2 in dis[pname][idx + 1 : idx + 9]:
                    if ins2.address >= ins.address + 0x24:
                        break
                    if reg + "," in ins2.op_str or f"[{reg}" in ins2.op_str:
                        if "#" in ins2.op_str:
                            try:
                                imm = pimm(ins2.op_str.split("#")[-1])
                            except ValueError:
                                imm = None
                            if imm is not None and imm_lo <= imm <= imm_hi:
                                print(
                                    f"   [{pname}] {ins2.address:#x}  {ins2.mnemonic:8}{ins2.op_str}"
                                    f"   -> {label}+{(imm - imm_lo) & ~3:#x}"
                                )
                        break

    # 2. direct calls (bl) to known functions
    print("\n== 2. bl-callers of known functions ==")
    for poi_name in [
        "lk.sec_get_seccfg",
        "lk.sec_query_device_lock(dEAD wrapper)",
        "bl2_ext.sec_query_device_lock_twin",
        "lk.sboot_getter_callee",
        "bl2_ext.sec_get_seccfg",
        "bl2_ext.sec_update_orchestrator_followup_1",
        "bl2_ext.sec_update_orchestrator_followup_2",
        "lk.sec_update_orchestrator_followup_1",
        "lk.sec_update_orchestrator_followup_2",
    ]:
        target = rt(POI[poi_name])
        print(f"\n-- {poi_name} @ {target:#x}")
        for name in PARTITIONS:
            bls = find_bl_targets(dis[name])
            callers = bls.get(target, [])
            for c in callers:
                print(f"   [{name}] called from {c:#x}")
            if not callers:
                print(f"   [{name}] none")

    # 3. absolute qword tables (dispatch tables) referencing POI functions
    print("\n== 3. qword function-pointer tables referencing known functions ==")
    poi_funcs = {k: rt(v) for k, v in POI.items() if "GLOBAL" not in k}
    found_any = False
    for name, (start, size) in PARTITIONS.items():
        for off, val in scan_qword_tables(buf, start, size):
            for poi_name, addr in poi_funcs.items():
                if val == addr:
                    print(f"   [{name}] @{off:#x} -> {poi_name} ({val:#x})")
                    found_any = True
    if not found_any:
        print("   none — no dispatch-table references to any known seccfg/lock fn")

    # 4. strings: sec_update / seccfg / lock related, and their xrefs
    print("\n== 4. interesting strings ==")
    for s in ["sec_update", "seccfg", "device_lock", "lock_state", "LKS_LOCK", "mtk_smc", "sip"]:
        locs = find_string(buf, s)
        print(f"   {s!r}: {[hex(x) for x in locs][:8]}")

    # 5. SMC issuers (smc #0) per partition
    print("\n== 5. `smc #0` instruction sites ==")
    S = struct.pack("<I", 0xD4000003)
    for name, (start, size) in PARTITIONS.items():
        i = buf.find(S, start, start + size)
        sites = []
        while i != -1:
            sites.append(i)
            i = buf.find(S, i + 4, start + size)
        print(f"   [{name}] {len(sites)} smc sites: {[hex(x) for x in sites][:16]}")

    # 6. SiP SMC id immediates (movz/movk with 0x8xxx / 0xC2xx hi halves) in code
    print("\n== 6. candidate SMC-id immediates (0x82xxxxxx / 0xC2xxxxxx) ==")
    for name, (start, size) in PARTITIONS.items():
        seen = set()
        for ins in dis[name]:
            if ins.mnemonic in ("mov", "movz", "movk") and ("#0xc2" in ins.op_str.lower() or "#0x82" in ins.op_str.lower()):
                seen.add(ins.op_str)
        for s in sorted(seen):
            print(f"   [{name}] {s}")

    # 7. context around each smc site + reconstruct w0 via movz/movk tracking
    print("\n== 7. smc site context (reconstructing w0 SMC id) ==")
    for name, (start, size) in PARTITIONS.items():
        S = struct.pack("<I", 0xD4000003)
        i = buf.find(S, start, start + size)
        while i != -1:
            wins = disasm_window(buf, i, 40, 2)
            regs = {}
            for ins in wins:
                if ins.address > rt(i):
                    continue
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
                if ins.address == rt(i):
                    w0 = regs.get("w0", regs.get("x0"))
                    print(f"\n   [{name}] smc @ file {i:#x}: w0 = {w0 if w0 is None else hex(w0)}")
            i = buf.find(S, i + 4, start + size)

    # 8. xrefs to sec_update / seccfg strings (find adrp+add referencing each)
    print("\n== 8. references to 'sec_update' string offsets ==")
    for off in find_string(buf, "sec_update"):
        target = rt(off)
        print(f"\n-- 'sec_update' @{off:#x} (rt {target:#x})")
        for name in PARTITIONS:
            for addr, ctx in find_adrp_pairs(dis[name], target):
                print(f"   [{name}] {addr:#x}  {ctx}")


if __name__ == "__main__":
    main()
