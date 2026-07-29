# Patch status — Cancunf (V1TDS35H.83-20-5-12)

Honest per-patch status. "Confirmed" = byte pattern located + replacement lands at
the right offset + patched image re-parses. "Pinned" = Ghidra/manual RE identified
the exact patch site and bytes. All patterns below are re-verified against the
20-5-12 LK (the 5-7 → 5-12 firmware shift did not move any patch site).

## Hardware trial results (2026-07-26)

Full trial matrix across 4 builds:

| Build | sboot? | Booted? | verifiedbootstate | Integrity |
---|---|---|---|---|
| vbmeta-locked (5-patch) | no | ✅ | green | BASIC |
| full (8-patch, 2× sboot) | yes (2×) | ❌ "Cannot load" | — | — |
| full (8-patch, 1× sboot) | yes (1×) | ❌ "Cannot load" | — | — |
| no-sboot (7-patch) | no | ✅ | green | BASIC |

All booting builds report `vbmeta.device_state=locked`, `flash.locked=1`,
`verifiedbootstate=green`. But Play Integrity caps at BASIC — hardware
attestation still reports "BL is unlocked" because the TEE reads lock state
from RPMB directly, not from LK code. See `notes/RESEARCH_FINDINGS.md` §4.

## Current artifact

`poc/cancunf-fenrir-full-20-5-12.img` — 7 patches (no sboot), byte-verified,
re-parses cleanly, cert-bypass (OVERRIDE) signed across lk/bl2_ext/aee. This is
the optimal LK configuration — boot state fully spoofed, dm-verity intact, no
harmful patches. Build with `python3 poc/build_full_20_5_12.py`; verify with
`poc/verify_poc.py`.

## ✅ Confirmed in the current PoC artifact — chain + reported state

These three stages land cleanly in `bl2_ext`, `lk`, and `aee` at the expected
per-partition offsets on both `20-5-5` and `20-5-7`. The `20-5-7` LK is a
re-sign/re-version rebuild; its patch neighborhoods match `20-5-5`.

### sec_get_vfy_policy — inter-partition verification policy
- **Pattern:** `00 01 00 b4 fd 7b bf a9`
- **Replacement:** `00 00 80 52 c0 03 5f d6`
- **Hits:** exactly 1 in each of `bl2_ext`, `lk`, `aee`.
- **Effect:** every partition-to-partition verification-policy query in the LK
  container returns "no auth needed". This affects the internal LK chain
  (`bl2_ext → lk → aee`). It does **not** disable Android Verified Boot.

### spoof_lock_state — LKS_LOCK
- **Pattern:** `20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91`
- **Hits:** 1 per partition — clean, matches supported devices.

### spoof_sboot_state — NOT NEEDED on cancunf (sboot already enabled)
- **Stock global** at `lk+0x12ee2c` = `0x11`. The getter's switch treats `0x11`
  as `return 1` (sboot enabled). The TEE already sees sboot as enabled — no
  patch needed.
- **The fenrir replacement is harmful on cancunf:** it decodes as
  `eor w8, w2, #0x3ffff` (XOR with `w2`, which is uninitialized in this
  calling convention — the wrapper passes `w0=1`, not `w2`). It writes garbage
  to `*output_ptr` instead of the expected `0`/`1` boolean, breaking the
  caller's downstream logic → dm-verity failure → "Cannot load Android system."
- **Hardware proof (2026-07-26):** every build containing `spoof_sboot_state`
  (2× match, 1× match, narrowed pattern) failed to boot with
  "Cannot load Android system." Dropping the patch entirely resolves the issue.
- **Decision:** `spoof_sboot_state` is removed from all cancunf builds. The
  stock getter already returns the correct value.

## 🟡 Pinned by RE, not yet in the current PoC artifact

These are the missing boot-image / flashing blockers from the earlier assessment.
They now have exact `20-5-7` byte patches, but they have not been applied to a
signed artifact or tested on hardware.

### force_green_state — pinned
- **Function:** `FUN_000738ec`
- **Decompile:** `DAT_00125268 = param_1; return;`
- **Caller evidence:** `FUN_00073078` computes boot-state `2`/`3` from AVB result and
  calls `FUN_000738ec(uVar2)`; this is the global consumed by the boot-state
  reporting path.
- **Offset:** flat `0x738ec` (`lk+0x736ec`).
- **Original:** `88 05 00 d0 00 69 02 b9 c0 03 5f d6`
- **Replacement:** `88 05 00 d0 1f 69 02 b9 c0 03 5f d6`
- **Instruction changed:** `str w0,[x8,#0x268]` → `str wzr,[x8,#0x268]`.
- **Effect:** store boot state `0` (green) regardless of caller input.
- **Uniqueness:** original context occurs exactly once in `20-5-7/lk.img`.

### avb_allow_verification_error — pinned
- **AVB function:** `FUN_0007e508`.
- **Caller:** `FUN_00073078`; it passes `w23` as AVB `param_4` flags, then treats a
  non-zero AVB return as allowed only when bit 0 is set:
  `cbz w0, success; cbnz w23, success; else failure`.
- **Offset:** flat `0x73298`.
- **Original context:** `e3 03 17 2a 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35`
- **Replacement context:** `e3 02 00 32 9b 2c 00 94 f7 02 00 12 a0 00 00 34 97 00 00 35`
- **Instruction changed:** `mov w3,w23` → `orr w3,w23,#1` before `bl FUN_0007e508`.
- **Effect:** sets `AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR` in the flags
  passed into AVB slot verification.
- **Uniqueness:** original context occurs exactly once in `20-5-7/lk.img`.

### bypass_security_control / bypass_lock_control — pinned
- **Region:** flat `0x4da00` / `lk+0x4d800`, in `FUN_0004d9e0` thunk path to
  `FUN_000bb168`.
- **Check callee:** `FUN_000a2b48`.
- **Callee decompile:** `return iRam0000000000206574 != 0x7070;`.
- **State evidence:** `FUN_000a2e14` writes `iRam0000000000206574` from OEM
  unlock / security state; `FUN_000a3ec0` uses the same global while printing
  `"Already unlocked"`, `"Unsupported on engineering phone"`, and
  `"Check Allow OEM Unlock in Android..."`.
- **Disassembly:**
  - `0x4d9fc: bl 0xa2b48` — lock/security state check.
  - `0x4da00: tbz w0,#0,0x4da24` — failure path if bit 0 is clear.
  - `0x4da04: orr w8,w20,#1`
  - `0x4da08: cmp w8,#3`
  - `0x4da0c: b.ne 0x4da30`
- **NOP patch:** `20 01 00 36` → `1f 20 03 d5` at flat `0x4da00`.
- **Larger Tecno-style context:** `53 54 01 94 20 01 00 36` →
  `53 54 01 94 1f 20 03 d5`.
- **Effect:** skip the lock/security error branch so the command path continues.
- **Confidence:** high; the branch, callee, and state global all match the intended
  `bypass_security_control` / `bypass_lock_control` role.

### preflash-validation bypass — pinned
- **String:** `Preflash validation failed` @ flat `0xd073f` (`lk+0xd053f`).
- **Reference:** direct `adrp/add` around flat `0x11d04` / `0x11d0c`.
- **Branch:** `0x11cec: bl 0xa21f4; 0x11cf0: tbz w0,#0,0x11cfc`.
- **Patch:** `42 41 02 94 80 00 00 36` → `42 41 02 94 1f 20 03 d5`.
- **Effect:** skip the branch that routes into the preflash-validation failure path.
## Conclusion — LK patching limit reached

The 7-patch build is the **optimal LK configuration**. It correctly spoofs all
bootloader-controlled properties. But Play Integrity cannot exceed BASIC via LK
patching alone. Verified three independent ways (see
`notes/ATTESTATION_CHANNEL.md`, 2026-07-29):

1. The lock-state code in both `lk` and `bl2_ext` is write-only — the only
   readers (lock wrappers 0xc2fe4 / 0x1aa2ac) have zero callers, no
   dispatch-table references exist, and LK's whole SMC surface is power/RTC-only.
2. `tee.img` (atf @ 0x48200000 + Kinibi) contains **no keymaster/attestation
   logic at all** — its only state channel is an ATF ROT mailbox used for
   utag/UFS-RPMB handover, not attestation. The RoT extension is composed by a
   **dynamic KM trustlet in the vendor image**, above a TEE that self-sources
   platform state (eFuse/lifecycle/RPMB), bypassing LK entirely.
3. Therefore no LK patch can change what the TEE signs. The patch point for
   "fenrir-class" STRONG on cancunf is the **vendor KM trustlet** (plus possibly
   Kinibi's TA-signature check in `tee.img`) — both load-time-unverified in
   fenrir mode — or Track A (TrickyStore+keybox) which needs neither.

Next actions and the exact dumps needed are in `notes/ATTESTATION_CHANNEL.md` §4–§5.

## Not in scope of this LK PoC

- **Payload stages** (`payload/devices/cancunf.h`): need STAGE*_BASE + function
  addresses from Ghidra. Template: fenrir's `q25.h`, Shirayuki39's `s666ln.h`.
- **Deep attestation control** (Strong Integrity frontier): GZ/TEE/cert/keybox layer,
  separate from LK patching. See `notes/integrity_practical.md`.
