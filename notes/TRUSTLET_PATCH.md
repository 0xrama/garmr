# Trustlet is_locked() patch — the STRONG integrity patch point

**Date:** 2026-07-29
**Firmware:** V1TDS35H.83-20-5-12 RETIN

## The finding

The Trustonic KeyMint trustlet (`0706000000000000000000000000004d.tlbin`, 263KB,
in `/vendor/app/mcRegistry/`) composes the attestation RootOfTrust extension.
The `deviceLocked` / `bootloader_state` field is determined by a single function:

### `is_locked()` at trustlet offset `0x19ec0`

```asm
0x19ec0: adrp x0, #0x73000       ; global variable page
0x19ec4: ldr  w0, [x0, #8]       ; read u32 at vaddr 0x73008
0x19ec8: cmp  w0, #0
0x19ecc: cset w0, ne             ; return (global != 0) = locked?
0x19ed0: ret
```

It reads **one global u32** — no SMC, no RPMB, no tlApi platform query. When the
device is unlocked, this global is 0 → `is_locked()` returns false → the
attestation cert's RootOfTrust says `"open"` / `"unlocked"`.

### The attestation string table (trustlet offset 0x3b370+)

```
0x3b370: "red"       (bootState=3+, len=3)
0x3b378: "orange"    (bootState=2,   len=6)
0x3b380: "yellow"    (bootState=1,   len=6)
0x3b388: "green"     (bootState=0,   len=5)  ← our LK patch sends this via cmdline
0x3b390: "locked"    (is_locked()=1, len=6)
0x3b398: "open"      (is_locked()=0, len=4)
0x3b3a0: "unlocked"  (sp+0x2c8=0,    len=8)
```

### bootState source

`bootState` (green/yellow/orange/red) comes from **HAL-supplied TCI parameters**
(`sp+0x2c4`). The HAL reads `ro.boot.verifiedbootstate` from the kernel cmdline.
Our 7-patch LK already sets `verifiedbootstate=green` → HAL sends bootState=0 →
TA writes "green". **This part already works** (hardware-confirmed: green in cmdline).

### deviceLocked source — TWO checks

1. **At 0x1cc44:** `bl #0x19ec0` (`is_locked()`) → selects "locked" vs "open" for
   the `bootloader_state` attestation field. This is the TA-internal override that
   reports unlocked even when the HAL sends locked=1.
2. **At 0x1cd5c:** `ldrb w0, [sp, #0x2c8]` → selects "locked" vs "unlocked". This
   byte is HAL-supplied (from `ro.boot.vbmeta.device_state=locked` via TCI). Our
   LK patch sets this → should already be 1 (locked).

**Check #1 is the blocker.** Patching it to always return 1 (locked) makes the TA
unable to override the HAL-supplied locked state.

## The patch — 8 bytes

```
offset 0x19ec0: C0 02 00 D0 00 08 40 B9  →  20 00 80 D2 C0 03 5F D6
                 (adrp x0, #0x73000)        (mov x0, #1)
                 (ldr  w0, [x0, #8])        (ret)
```

After patching, `is_locked()` unconditionally returns 1 (locked).

Built artifact: `poc/trustlet_patch/0706000000000000000000000000004d.tlbin`
Module: `poc/cancunf-km-islocked-patch.zip`

## Deployment paths

### Path A — root module (fastest test, needs existing root)

The user's custom ROM already has root (KernelSU/Magisk). Flash the module
`cancunf-km-islocked-patch.zip` → it bind-mounts the patched trustlet over
`/vendor/app/mcRegistry/0706...4d.tlbin`.

**Risk:** Kinibi may verify the MCLF trustlet signature before loading. If so,
the patched trustlet is rejected → no KeyMint → must add MCLF auth bypass.

### Path B — fenrir mode (permanent, no root dependency)

In fenrir mode (bl2_ext patched → tee.img unverified), the full chain:
1. `lk.img` — 7 patches (existing, hardware-confirmed)
2. `tee.img` — disable Kinibi MCLF signature verification (TO FIND)
3. trustlet `0706...4d.tlbin` — is_locked() patch (this doc)

This yields genuine STRONG integrity with the stock keybox — no rotation,
no root, no zygisk. The same property fenrir has on pacman-class devices.

### Path C — TrickyStore (works today, no firmware patching)

Unchanged from earlier analysis. TrickyStore + keybox works regardless.
The trustlet patch removes the keybox dependency.

## What remains

1. **MCLF auth bypass in tee.img** — needed only if Kinibi verifies trustlet
   signatures at load time. Search the Kinibi core (tee partition) or the CMS
   driver for MCLF signature verification code. If not found, Kinibi may not
   verify (Path A works directly).

2. **Verify sp+0x2c8 is correct** — the second deviceLocked check. If it reads
   from the HAL-supplied TCI (likely), it's already correct from cmdline patches.
   If not, trace the setter and patch if needed.

3. **verifiedBootKey consistency** — if running a custom boot.img signed by a
   different key, the vbmeta_digest in the cert won't match stock → may fail
   STRONG's "recent patches + consistent key" rule. Solution: run stock-signed
   boot/system (only the LK is patched), OR patch the vbmeta_digest field too.
