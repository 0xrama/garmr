# Patch status — Cancunf (V1TDS35H.83-20-5-5)

Honest per-patch status. "Confirmed" = byte pattern located + replacement lands at
the right offset + patched image re-parses. "Open" = needs interactive RE.

## ✅ Confirmed (in the PoC)

### sec_get_vfy_policy — THE core bypass
- **Pattern:** `00 01 00 b4 fd 7b bf a9` (`cbz x0,… ; stp x29,x30,[sp,#-0x10]!`)
- **Replacement:** `00 00 80 52 c0 03 5f d6` (`mov w0,#0 ; ret`)
- **Hits:** exactly 1 in each of `bl2_ext`, `lk`, `aee` (matches supported devices)
- **Effect:** every verification-policy query in the chain returns "no auth needed".
  This is what collapses secure-boot enforcement downstream of bl2_ext.

### spoof_lock_state
- **Pattern:** `20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91`
- **Hits:** 1 per partition — clean, matches supported devices.

## ⚠️ Present but needs validation

### spoof_sboot_state (common-A variant)
- **Pattern:** `fd 7b be a9 … 20 00 80 52`
- **Hits:** **2 per partition** on cancunf (6 total). Other supported devices match
  1 per partition.
- **Risk:** patching both instances may touch an unrelated similar function. Validate
  each instance in Ghidra before relying on this. If only one is the real
  `get_sboot_state`, restrict to `MatchMode.FIRST` or split into two targeted patches.

## ❌ Open — needs Ghidra (cannot resolve by blind byte scan)

### force_green_state
- 13 structural candidates match `adrp x8,page ; str wN,[x8,#imm] ; ret` in `lk`.
- The real one is the boot-state *setter* referenced by the boot-state-determination
  logic. Disambiguation needs cross-references.
- **Ghidra task:** load `firmware/lk.img` → find the function that writes the global
  consumed by `androidboot.verifiedbootstate=` cmdline construction (search xrefs to
  the `green`/`yellow`/`orange`/`red` strings, or to `set_dm_verity_status`). The
  writer is the target; patch its stored value to 0 (green) like pacman's
  `00 21 01 b9 → 1f 21 01 b9` (str w1 → str wzr).

### preflash-validation bypass
- "Preflash validation failed" string located at `lk+0xd053f`.
- Byte-scan for `adrp+add` xrefs returned 0 — the reference uses `adr` or a literal
  pool/GOT indirection.
- **Ghidra task:** find xrefs to the string at `0xffff000050fd053f`. The caller is
  the preflash check; the conditional branch (`cbz`/`cbnz`/`b.ne`) deciding
  pass/fail before it is what you NOP (`1f 20 03 d5`). This is the
  "Preflash validation failed" wall that forces cancunf into fastbootd for every
  flash.

## Not in scope of this PoC

- **Payload stages** (custom fastboot commands / runtime calls): need `payload/devices/cancunf.h`
  with STAGE*_BASE + function addresses from Ghidra. Template: see fenrir's
  `payload/devices/q25.h` and Shirayuki39's `s666ln.h`.
- **Deep attestation control** (the Strong-Integrity frontier): that's the
  GZ/TEE/cert layer, separate from these LK patches. See `notes/integrity_practical.md`.
