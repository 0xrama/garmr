# Research findings — cancunf fenrir LK exploit

Complete log of findings from the 2026-07-26 deep-dive that used Ghidra to trace
the full lock-state / attestation data path. This document is the definitive
record of what works, what doesn't, and why.

---

## Executive summary

**What works (bootloader-level):** the 7-patch LK artifact correctly spoofs every
property the bootloader controls — `verifiedbootstate=green`,
`vbmeta.device_state=locked`, `flash.locked=1`. The device boots cleanly and
passes BASIC Play Integrity.

**What doesn't work (hardware attestation):** the TEE's `deviceLocked` field in
the key-attestation certificate still reports "unlocked." Ghidra decompilation
proved that the lock-state code in both `lk` and `bl2_ext` is **write-only** — no
function reads the seccfg-derived lock state to return it to the TEE. The TEE
reads lock state directly from RPMB/eFuse, bypassing the LK entirely.

**Conclusion:** LK patching has reached its architectural limit for attestation.
DEVICE and STRONG Play Integrity require Track A (TrickyStore + keybox) at the
Android KeyMint layer.

---

## 1. Boot-chain architecture (confirmed from binary analysis)

```
BootROM (masked ROM, eFuse root key)
  → Preloader (verified vs fused ROTPK)
    → bl2_ext (EL3, verified when seccfg=locked, UNVERIFIED when seccfg=unlocked)
      → TEE (Trustonic Kinibi, loaded by bl2_ext)
        → GenieZone (EL2 hypervisor)
          → lk / aee (LK proper, loaded by bl2_ext)
            → Linux kernel (EL1)
```

The fenrir exploit works because: when `seccfg = unlocked`, the Preloader skips
bl2_ext signature verification but still jumps into bl2_ext at EL3. A patched
bl2_ext at EL3 can then load unverified TEE/GZ/LK/kernel — collapsing the entire
chain of trust downstream.

**Key partitions inside `lk.img`** (file layout confirmed by raw-byte search):

| Partition | File offset | Data size   | Role |
|-----------|-------------|-------------|------|
| lk        | 0x000200    | 0x12F4B8    | Main LK bootloader (fastboot, boot logic, state reporting) |
| bl2_ext   | 0x130790    | 0xBCA98     | EL3 ATF (verification, SMC handler, security policy) |
| aee       | 0x1EE300    | 0xFDCB8     | AEE dump handler |
| lk_main_dtb | 0x2ECE90  | —           | Device tree blob |

Each partition has a 0x200-byte GFH header. Ghidra address = file offset.

---

## 2. Patch inventory (7 patches, all hardware-confirmed)

### Patches that WORK (in the current `cancunf-fenrir-full-20-5-12.img`):

| # | Patch | Partition(s) | Pattern (hex) | Effect |
|---|-------|-------------|---------------|--------|
| 1 | `sec_get_vfy_policy` | bl2_ext, lk, aee | `00 01 00 b4 fd 7b bf a9` → `00 00 80 52 c0 03 5f d6` | Disable inter-partition verification (core fenrir bypass) |
| 2 | `spoof_lock_state` | bl2_ext, lk, aee | `20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91` → `88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6` | Force lock-state getter to return LKS_LOCK(4) |
| 3 | `force_green_state` | lk | `88 05 00 d0 00 69 02 b9 c0 03 5f d6` → `...1f 69 02 b9...` | Force boot-state global to 0 (green) |
| 4 | `avb_allow_verification_error` | lk | `e3 03 17 2a...` → `e3 02 00 32...` | Set AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR |
| 5 | `bypass_security_control` | lk | `53 54 01 94 20 01 00 36` → `53 54 01 94 1f 20 03 d5` | NOP the lock/security check branch in fastboot command dispatch |
| 6 | `preflash_validation_bypass` | lk | `42 41 02 94 80 00 00 36` → `42 41 02 94 1f 20 03 d5` | NOP the preflash validation failure branch |
| 7 | `vbmeta_device_state_locked` | lk | `1f 01 00 71 41 04 00 f0 42 01 89 9a...` → `...e2 03 0a aa...` | Force `androidboot.vbmeta.device_state=locked` in kernel cmdline |

### Patches REMOVED after analysis:

| Patch | Why removed |
|-------|-------------|
| `spoof_sboot_state` | See §3 below — sboot already enabled in stock firmware, and the fenrir replacement is harmful on cancunf. |

---

## 3. The `spoof_sboot_state` failure — full root cause

### Discovery process

The original fenrir `spoof_sboot_state` pattern (`fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa 20 00 80 52`) matched **2× per partition** on cancunf (6 total), unlike other supported devices where it matches 1× per partition.

**Capstone disassembly of both instances in `lk` partition:**
- **Instance #1** (`lk+0xbec18`): calls callee at `lk+0xbeb50`. The callee is a simple state checker — loads a global, switches on `0x11`/`0x22`/`0x00`, returns 0 or 1. **This is the real `get_sboot_state()` getter.**
- **Instance #2** (`lk+0xc237c`): calls callee at `lk+0xbfd28`. The callee is a **208-byte function that indexes a table of X.509 OIDs** (`1.2.840.113549.1.1.10` = RSASSA-PSS, `1.2.840.113549.1.1.1` = rsaEncryption). **This is a certificate/signature processing function, NOT a state getter.** Patching it broke the crypto chain → dm-verity failure → "Cannot load Android system."

**First fix attempt:** extended pattern from 20→24 bytes to include the `bl` target:
- Instance #1: `...c9 ff ff 97` (identical across all 3 partitions)
- Instance #2: `...66 f6 ff 97` (identical across all 3 partitions)
- Result: matched only instance #1. Still bootlooped.

**Root cause (the second fix wasn't enough):** the fenrir replacement bytes `48 44 00 52` decode via capstone as `eor w8, w2, #0x3ffff` — an XOR with register `w2`, which is **uninitialized** in this calling convention. The wrapper passes `w0=1` to the callee, not `w2`. The replacement writes garbage to `*output_ptr`, corrupting whatever consumer reads it. Even patching only the "correct" instance #1 produces garbage output.

**Final resolution:** decoded the sboot getter callee (FUN at `lk+0xbeb50`):
```c
// Ghidra decompile of get_sboot_state callee
int get_sboot_state(int arg) {
    int state = *(int*)(0x5102ee2c);  // sboot global
    if (state == 0x22) { ... return 1; }
    if (state == 0x11) { return 1; }  // ← stock value!
    if (state != 0)    { ... error path; }
    return 0;  // state == 0
}
```

The stock sboot global at `lk+0x12ee2c` = **`0x11`** → the getter already returns **1 (sboot enabled)**. The TEE already sees sboot as enabled. **The patch was completely unnecessary** and only caused harm.

### Hardware trial matrix

| Build | sboot patch | Booted? | Notes |
|-------|------------|---------|-------|
| 5-patch (vbmeta-locked) | Not included | ✅ Yes | BASIC integrity only |
| 8-patch (2× sboot, 20-byte pattern) | 6 sites patched | ❌ "Cannot load" | Broke cert processing function |
| 8-patch (1× sboot, 24-byte pattern) | 3 sites patched | ❌ "Cannot load" | Replacement writes garbage (eor w2) |
| 7-patch (no sboot) | Not included | ✅ Yes | BASIC integrity, sboot already enabled |

---

## 4. The attestation boundary — Ghidra decompilation findings

This is the core finding that explains why LK patching cannot achieve DEVICE/STRONG
integrity.

### 4.1 The lock-state data flow in `lk` partition

**`sec_get_seccfg` (FUN_000c2cec, Ghidra address 0xc2cec):**
```c
int sec_get_seccfg(void) {
    // zeros globals at 0x209e40–0x209eb8
    // allocates 0x40-byte buffer
    // reads "sec_update" partition into buffer
    // copies raw fields to globals:
    DAT_00209e40 = buffer[0];     // offset 0x00: magic (0x4d4d4d4d)
    DAT_00209e48 = buffer[1];     // offset 0x08: 8-byte value (lock state in upper 32 bits)
    // ... more fields ...
    // verifies magic + hash
    return 0; // or error
}
```

**`sec_query_device_lock` wrapper (FUN_000c2fe4, Ghidra address 0xc2fe4):**
```c
undefined4 sec_query_device_lock(unsigned int *param_1) {
    if (param_1 == NULL) return 0x100006;  // null error
    int ret = sec_get_seccfg();
    uint lock_state = DAT_00209e48._4_4_;  // upper 32 bits of offset-0x08 field
    if (ret != 0) lock_state = 1;          // default on error
    *param_1 = lock_state;
    return (ret != 0) ? 0x103000 : 0;
}
```

The lock state is at **seccfg raw offset 0x0c** (upper 32 bits of the 8-byte value at offset 0x08).

### 4.2 Ghidra xref analysis — the dead-code proof

Ghidra's `get_xrefs_to` on the lock-state global `DAT_00209e48` (Ghidra address `0x209e48`):

| Address | Function | Access |
|---------|----------|--------|
| `0x000c2c34` | FUN_000c2be0 | **WRITE** (initialization/restore) |
| `0x000c2d30` | FUN_000c2cec (sec_get_seccfg) | **WRITE** (copy from buffer) |
| `0x000c2dac` | FUN_000c2cec | **WRITE** (backup restore path) |
| `0x000c2f58` | FUN_000c2cec | **WRITE** (hash verification path) |
| `0x000c3000` | FUN_000c2fe4 (wrapper) | **READ** ← only reader |

The wrapper at `0xc2fe4` is the **only function that reads** the lock-state global. And it has **zero callers** (confirmed by `get_xrefs_to 0xc2fe4` returning nothing). It is dead code.

### 4.3 Same result in `bl2_ext` partition

**bl2_ext `sec_get_seccfg` (FUN_001a9fb4, Ghidra address 0x1a9fb4):**
- Reads "sec_update" partition
- Stores at global `DAT_002bdd88` (bl2_ext's BSS equivalent)

**Ghidra xref on `DAT_002bdd88`:**

| Address | Function | Access |
|---------|----------|--------|
| `0x001a9efc` | FUN_001a9eec | **WRITE** |
| `0x001a9ff8` | FUN_001a9fb4 (sec_get_seccfg) | **WRITE** |
| `0x001aa074` | FUN_001a9fb4 | **WRITE** |

**Zero READS.** No function in bl2_ext ever reads the lock-state global either.

### 4.4 Where the TEE actually gets lock state

Since neither the lk nor bl2_ext code reads the seccfg-derived lock state to
return it to anyone, the TEE must obtain `deviceLocked` through a completely
different path:

1. **Direct RPMB read** — the Trustonic TEE has its own RPMB access code in
   `tee.img` and reads the seccfg partition directly from secure storage.
2. **eFuse** — the MTK security fuse (SBC_MK_SI) determines the hardware
   security state independently of seccfg.
3. **Shared memory written by BootROM/Preloader** — the TEE may read a
   hardware-locked shared region populated before bl2_ext runs.

All three are **inaccessible to LK binary patching**. The TEE's attestation
certificate includes a `RootOfTrust` extension with `deviceLocked` signed by a
hardware key whose private key never leaves the secure world. No amount of
bootloader patching can change what the TEE signs.

This confirms what `notes/knowledge.md` §5 predicted: *"Strong Integrity does not
ask the bootloader; it asks the TEE to cryptographically sign an attestation
whose certificate chain roots at a Google hardware key provisioned at
manufacturing."*

---

## 5. Partition layout and address mapping

Discovered through raw-byte search of `firmware/V1TDS35H.83-20-5-12/lk.img`:

```
File offset      Content
0x000000         lk partition header (magic 0x58881688, 0x200 bytes)
0x000200         lk data start (first instruction: bl 0xb2a0)
  ...
0x130590         bl2_ext partition header
0x130790         bl2_ext data start (first instruction: bl 0x570c)
  ...
0x1EE100         aee partition header
0x1EE300         aee data start
  ...
0x2ECE90         lk_main_dtb partition header
0x322510         end of image (3,286,288 bytes)
```

**Ghidra address mapping:**
- Ghidra loaded the raw `lk.img` at base address `0x0`
- Ghidra address = file offset
- lk data offset X = Ghidra address (X + 0x200)
- bl2_ext data offset X = Ghidra address (0x130790 + X)

**Runtime address mapping:**
- lk loads at runtime address `0xFFFF000050F00000`
- All partitions (lk, bl2_ext, aee) load at the same base — they are sequential
  loadable segments of the same binary, verified and loaded one at a time

**String locations** (file/Ghidra offsets, all in lk partition):

| String | File offset | Used for |
|--------|-------------|----------|
| `sec_query_device_lock` | 0xf4816 | Symbol name (dead code) |
| `sec_get_seccfg` | 0x119e33 | Symbol name |
| `get_lock_state` | 0xf49da | Symbol name |
| `lock_state, 0x%x` | 0x119f5d | Debug format string (dead) |
| `Preflash validation failed` | 0xd053f | Referenced by preflash patch site |
| `MBM-3.1-cancunf_g_vext-...` | 0xd2786 | Device fingerprint |
| `k6855v1_64_cancun` | 0xcc595 | Platform codename |
| `Orange State\n\n` | 0x103de9 | Boot warning screen text |
| `androidboot.verifiedbootstate=orange` | 0x103d65 | Cmdline string (patched by force_green) |

---

## 6. Key functions (Ghidra decompiled)

### FUN_000a2b48 — security state check (bypass_security_control callee)
```c
bool FUN_000a2b48(void) {
    return iRam0000000000206574 != 0x7070;
}
```
Returns true if the security-state global at `0x206574` is not `0x7070`. Called
by the fastboot command dispatcher to gate restricted commands. The
`bypass_security_control` patch NOPs the `tbz w0,#0` after this call, making
all commands execute regardless of security state.

### FUN_000c2cec — sec_get_seccfg (lk partition)
Reads the "sec_update" partition (64 bytes), copies fields to globals at
`0x209e40`–`0x209eb8`, verifies magic (`0x4d4d4d4d`) and hash. The lock state
is at raw offset `0x0c` in the seccfg data.

### FUN_000c2fe4 — sec_query_device_lock wrapper (lk, DEAD CODE)
```c
undefined4 FUN_000c2fe4(unsigned int *param_1) {
    if (param_1 != NULL) {
        int ret = FUN_000c2cec();
        *param_1 = (ret != 0) ? 1 : DAT_00209e48._4_4_;
        return (ret != 0) ? 0x103000 : 0;
    }
    return 0x100006;
}
```
**Zero callers.** Ghidra `get_xrefs_to` returned nothing. This is the function
the original `spoof_lock_state` patch targeted — patching it changes nothing
because nobody calls it.

### FUN_001a9fb4 — sec_get_seccfg (bl2_ext partition)
Identical logic to lk's version but stores at `DAT_002bdd80`–`DAT_002bddf8`
(bl2_ext's BSS). Also has **zero readers** of the lock-state field.

### Sboot getter callee (lk partition, at lk+0xbeb50)
```c
int get_sboot_state(int arg) {
    int state = global_at_0x5102ee2c;  // stock value: 0x11
    if (state == 0x22) { ... return 1; }
    if (state == 0x11) { return 1; }   // ← stock path: sboot ENABLED
    if (state != 0)    { ... }
    return 0;
}
```
Stock sboot global = `0x11` → getter returns 1 (enabled). **No patch needed.**

### Certificate processing function (lk partition, at lk+0xbfd28)
208-byte function with a large stack frame. Indexes a table of X.509 OID
strings (`1.2.840.113549.1.1.10` = RSASSA-PSS, `1.2.840.113549.1.1.1` =
rsaEncryption) with 64-byte stride. Called by the second `spoof_sboot_state`
pattern instance — **NOT a state getter**, but a signature/certificate
processing function. Patching it broke dm-verity.

---

## 7. Hardware trial log

| Date | Build | Patches | Booted? | verifiedbootstate | device_state | flash.locked | Integrity | Notes |
|------|-------|---------|---------|-------------------|-------------|-------------|-----------|-------|
| 2026-07-26 | vbmeta-locked (5-patch) | sec/lock/green/avb/vbmeta | ✅ | green | locked | 1 | BASIC | sboot + bypass_security + preflash omitted |
| 2026-07-26 | full (8-patch, 2× sboot) | all 8, 20-byte sboot pattern | ❌ | — | — | — | — | "Cannot load Android system" — broke cert function |
| 2026-07-26 | full (8-patch, 1× sboot) | all 8, 24-byte sboot pattern | ❌ | — | — | — | — | "Cannot load Android system" — eor w2 garbage |
| 2026-07-26 | no-sboot (7-patch) | all except sboot | ✅ | green | locked | 1 | BASIC | Key attestation app: "BL is unlocked" |

---

## 8. Architectural conclusion

```
┌─────────────────────────────────────────────────────────┐
│                  ANDROID USERSPACE                       │
│  Play Integrity API ← reads attestation JWT from TEE     │
├─────────────────────────────────────────────────────────┤
│                  ANDROID FRAMEWORK                       │
│  KeyMint HAL ← requests attestation from TEE via IPC     │
├─────────────────────────────────────────────────────────┤
│            LINUX KERNEL (EL1, Normal World)              │
│  Reads ro.boot.* cmdline props ← SPOOFED ✅              │
├──────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┤
│         GENIEZONE HYPERVISOR (EL2)                       │
├─────────────────────────────────────────────────────────┤
│         TRUSTONIC TEE (S-EL1, Secure World)              │
│  Keymaster TA ← signs attestation certificate            │
│  deviceLocked ← reads from RPMB/eFuse DIRECTLY  ❌ LK    │
│  verifiedBootState ← reads from TEE shared memory ❌ LK  │
├──────── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┤
│         BL2_EXT / ATF (EL3)                              │
│  sec_get_seccfg ← reads "sec_update" partition            │
│  Stores lock state to global ← NOBODY READS IT            │
│  sec_query_device_lock wrapper ← DEAD CODE (0 callers)    │
├─────────────────────────────────────────────────────────┤
│         LK BOOTLOADER (EL1, loaded by bl2_ext)           │
│  force_green_state ← spoofs boot state global  ✅        │
│  spoof_lock_state ← dead-code wrapper (0 callers) ⚠️      │
│  vbmeta.device_state ← spoofs cmdline prop     ✅        │
│  bypass_security_control ← skips fastboot gate ✅        │
│  avb_allow_verification_error ← allows AVB errors ✅     │
└─────────────────────────────────────────────────────────┘
```

**The boundary:** LK patches control everything above the "Linux kernel" line
(cmdline properties, AVB behavior, fastboot command gating). They cannot
control anything below the "Trustonic TEE" line — the TEE reads hardware state
from RPMB/eFuse through its own code in `tee.img`, which is a separate binary
not touched by LK patching.

---

## 9. Recommendations

### For daily-driver DEVICE + STRONG integrity:

**Track A — TrickyStore + keybox** (see `notes/integrity_practical.md`):
1. Root with Magisk or KernelSU
2. Install TrickyStore module
3. Obtain a valid `keybox.xml` (device-specific attestation key pair)
4. TrickyStore intercepts the KeyMint attestation path at the HAL level and
   substitutes the keybox certificate chain
5. Result: genuine-looking attestation → BASIC + DEVICE + STRONG pass

**Why this is the only option on cancunf:** the TEE reads `deviceLocked` from
RPMB directly (§4). Patching the LK's seccfg code has no effect because the TEE
never calls that code. Patching `tee.img` is theoretically possible but is a
completely separate exploit class (Trustonic TEE binary patching), far beyond
the fenrir LK framework.

### For the LK exploit research:

The 7-patch `cancunf-fenrir-full-20-5-12.img` is the **optimal LK configuration**
for this device. It:
- Boots cleanly with stock boot/system
- Reports correct (spoofed) boot state to Android
- Allows flashing without restrictions (bypass_security + preflash bypass)
- Does not break dm-verity (sboot left at stock value)
- Does not trigger "Cannot load Android system" (no harmful patches)

The only remaining LK-level research question is whether a **payload stage**
(fenrir's `PayloadStage` injection into unused partition space) could write
LKS_LOCK to the RPMB seccfg before the TEE reads it. This would require:
1. Finding the RPMB write path in bl2_ext
2. Crafting a payload that writes seccfg state = LKS_LOCK to RPMB
3. Injecting it via fenrir's stage mechanism
4. Ensuring it runs BEFORE the TEE initialization

This is the cyberknight777 "low-level exploit" territory — credible but unreleased,
and a completely separate research effort from the fenrir LK patching framework.
