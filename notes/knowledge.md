# Knowledge base — cancunf secure-boot exploit research

Complete context from the investigation, so anyone picking this up cold can get
back up to speed. Last updated at the point the workspace was created.

---

## 1. Device under test

- **Device:** Motorola Moto G64 5G (also covers Moto G54 5G — same codename)
- **Codename:** `cancunf`
- **SoC:** MediaTek Dimensity 7025 → **MT6855V/AZA**
- **CPU:** ARM64 (AArch64) — 2× Cortex-A78 + 6× Cortex-A55
- **Bootloader architecture:** MTK LK v2 (contains `lk`, `bl2_ext`, `aee`, `lk_main_dtb`)
- **Stock firmware tested:** `V1TDS35H.83-20-5-5 RETIN` (Android 15), India channel
- **MBM version string:** `MBM-3.1-cancunf_g_vext-5cbf37-V1TDS35H.83-20-5-5-a8c92`
- **TEE:** Trustonic (Kinibi/MobiCore lineage) — confirmed via `com.trustonic.*` strings
- **Hypervisor:** GenieZone (GZ) at EL2
- Bootloader is **legitimately unlockable** via Motorola's unlock-key tool (easy).
  This matters: the fenrir flaw *requires* seccfg unlocked; it is NOT a way to
  unlock a locked phone.

---

## 2. The vulnerability class (fenrir)

**Name:** fenrir — MediaTek `bl2_ext` secure-boot bypass.
**Author:** R0rt1z2. Repo: github.com/R0rt1z2/fenrir. Shared lib: github.com/R0rt1z2/liblk.

**Normal MTK boot chain:**
```
BootROM (masked ROM, eFuse root key)
  → Preloader (verified vs fused ROTPK)
    → bl2_ext (EL3, verified)        ← verifies everything below
      → TEE → GenieZone (EL2) → LK/AEE → Linux kernel (EL1)
```

**The flaw:** when `seccfg` = **unlocked**, the Preloader **skips verification of
`bl2_ext`**. Preloader still *jumps into* bl2_ext at EL3. An unverified bl2_ext
running at EL3 can then load unverified TEE/GZ/LK/kernel — the whole chain of
trust collapses.

**Exploit mechanic:** patch `sec_get_vfy_policy()` to always return 0
(`mov w0,#0 ; ret` = `00 00 80 52 c0 03 5f d6`). Every downstream verification
query then returns "no auth required."

**Prerequisite:** bootloader must be unlocked (seccfg). fenrir is a *post-unlock*
power-up, not an unlock bypass.

**One exception:** the Vivo X80 Pro reportedly skips bl2_ext verification even when
*locked*. No evidence cancunf does this. Assume cancunf needs unlock.

---

## 3. Confirmed: cancunf IS vulnerable to this class

Parsed `firmware/lk.img` with liblk and byte-compared against the supported
reference device (Nothing Phone 2a, `pacman`). Every precondition matches:

| Check | cancunf | pacman (supported) |
|---|---|---|
| LK header magic `88 16 88 58 …lk` | ✓ identical | ✓ |
| LK version | 2 | 2 |
| Partitions | `lk, bl2_ext, aee, lk_main_dtb` | `lk, bl2_ext, aee, lk_main_dtb, lk_dtbo` |
| `sec_get_vfy_policy` pattern `00 01 00 b4 fd 7b bf a9` | 1× in bl2_ext/lk/aee | 1× in bl2_ext/lk/aee |
| Function-context bytes around the pattern | near-identical | — |
| `img_auth_required` log string | present (`0x1153b7`) | — |
| MT6855 sboot source paths | `platform/mediatek/mt6855/sboot/...` | — |

**Conclusion:** a fenrir port for cancunf is technically feasible at the
pattern level. The unreleased maintainer work (cyberknight777 teaser — see §6)
is real and reproducible against this firmware.

---

## 4. signing-info.txt — the boot architecture confirmation

The firmware's `signing-info.txt` was the decisive artifact. It enumerates
sub-partitions inside `lk.img`:
```
lk.img__bl2_ext=0x01   ← the EL3 verifier, fenrir's target
lk.img__aee=0x01
lk.img__lk=0x01
```
Plus `BOOTLOADER_ANTIROLLBACK_VER_SUM=014`, `enforce_anti_rollback_check_in_ota=true`.
This confirms the standard MTK LK-container layout (bl2_ext inside lk) that fenrir
attacks. Anti-rollback is eFuse/RPMB-backed — not bypassable by LK patching.

---

## 5. The hard part: Play Integrity & attestation (calibrated, honest)

This is the most contested area; positions here were calibrated against real-world
evidence and corrected mid-investigation. Read carefully.

### What the spoofing actually achieves
fenrir's lock-state/boot-state patches make the **bootloader report** locked/green
to anything that trusts it — i.e. the `androidboot.verifiedbootstate=` cmdline and
userspace reads. That satisfies **software-level** checks and most app-level
checks.

### The layer software can't reach: hardware key attestation
Strong Integrity does not ask the bootloader; it asks the **TEE** to
*cryptographically sign* an attestation whose certificate chain roots at a
**Google hardware key** provisioned at manufacturing. The private key never leaves
the secure world.

### Architecture on cancunf (confirmed from `tee.img`)
- TEE is **Trustonic** (`com.trustonic.trustedStorage`, `McLib`, `drApiPlatformControl`).
- Direct evidence the TEE **defers to ATF (EL3) for security policy** — strings:
  `[SFSRP]ATF reports RPMB disabled : No Downgrade protection` and
  `[SFSRP]drApiPlatformControl failed(%d). act as downgrade protection active`.
- SMC path confirmed: `mtk_smc_handler`, `MTK_SIP_HYP_SMC_TO_EL2_TEE`, `EL3_SMC_ID`.

### The honest claim and its limits
- **Theory:** because fenrir patches policy *at EL3* (above the TEE), and the TEE
  queries that layer via SMC, the genuine hardware key could sign attestations
  reporting green/locked with no key extraction needed.
- **Calibrated reality:** real-world evidence (fenrir issue #15, MT6897) shows
  lock-state spoofing works *but verification enforcement is a separate code path*
  that still kicks in unless *every* enforcement point is patched. The community
  (issue #11) recognizes full attestation control likely requires neutering GZ/TZ,
  not just LK.
- **`verifiedBootKey` field:** even with state=green, attestation includes the hash
  of the key that signed boot.img. A custom boot image → non-matching hash →
  effectively yellow regardless of state. To keep green, run official-signed
  boot/system (modify only the LK).
- **No one has publicly demonstrated** fenrir-alone → green Strong Integrity.
  cyberknight777 *claims* "permanent strong integrity" with his separate (deeper)
  exploit; credible given his expertise and concrete teaser results, but the
  mechanism is unreleased and unverified by us.

### The pragmatic path (Track A) — what solves daily-use integrity NOW
**TrickyStore + keybox.xml** (Magisk/KSU module). Replaces the attestation
certificate chain at the KeyMint HAL level. Needs root, not a bootloader exploit.
Passes BASIC + DEVICE + STRONG today. Google revokes abused keyboxes periodically.
**This is the recommended daily-driver solution**, independent of this workspace.

See `notes/integrity_practical.md`.

---

## 6. Key actors and their repos

| Actor | Role | Repo(s) | What's there |
|---|---|---|---|
| R0rt1z2 | fenrir/liblk/lkpatcher author | R0rt1z2/fenrir, R0rt1z2/liblk, R0rt1z2/lkpatcher | the exploit + parsing libs; lkpatcher is the older general tool (32-bit-Thumb-oriented defaults) |
| cyberknight777 | cancunf maintainer; has unreleased low-level exploit | cyberknight777/{hacc,mtklogo,dragonheart_kernel_motorola_cancunf,fenrir}, shomykohai/hacc PR#1 | fenrir fork is an *empty reference copy*; real work is in hacc (BromSecCfg parsing) + private. Claims permanent Strong Integrity via a cert/low-level exploit distinct from fenrir |
| Shirayuki39 | active fenrir contributor | Shirayuki39/fenrir | **best learning reference** — added itel RS4 (S666LN) + payloads, iterated Tetris patches. Shows the device-porting process end-to-end |
| shomykohai | hacc author | shomykohai/hacc | MTK structure parser (LK image, seccfg, GFH, certs) |

### cyberknight777 chat-log position (the framing that organized our work)
He dismissed an "inferior exploit only good for rooting, patched in newer kernels"
(kernel-level), positioned fenrir as niche-for-devices-that-can't-unlock (e.g. Xiaomi),
and claimed his own work is a **low-level** exploit giving **permanent Strong
Integrity** across most MTK chips. Consistent with the empty fenrir fork + hacc
BromSecCfg work. His exploit is unreleased.

---

## 7. fenrir vs lkpatcher vs hacc vs mtklogo — what each is

- **fenrir** — the bl2_ext exploit *framework*: device-specific ARM64 patch set
  (devices.py), payload injection stages, cert_bypass. Built on liblk.
- **liblk** — shared Python parser for MTK LK images (partitions, GFH headers,
  certs). Used by both fenrir and lkpatcher.
- **lkpatcher** — R0rt1z2's older (2023) general-purpose LK patcher. JSON-defined
  patches, policy-table analyzer, partition management. **Default patches are
  32-bit-Thumb** (`00207047` = `bx lr`); cancunf is ARM64 → lkpatcher defaults
  do NOT apply to cancunf. Its policy-table heuristic found 0 tables on cancunf.
  Useful as a framework/concept, not out-of-the-box here.
- **hacc** — Rust no-std MTK structure parser (shomykohai; cyberknight contributed
  BromSecCfg parsing). The foundation for cyberknight's deeper exploit work.
- **mtklogo** — Rust tool to edit the MTK logo partition (cyberknight). **Not an
  exploit** — it's the content tool; the exploit is what lets a modified logo boot.
- **mtkclient** (bkerler) — open MTK BROM/flashing tool. Use for seccfg unlock +
  partition readback. Essential for getting dumps and triggering the unlock state.

---

## 8. Current PoC status (this workspace)

Built and **byte-verified offline** against **both** `V1TDS35H.83-20-5-5` and
`V1TDS35H.83-20-5-7`. The two LK images are byte-identical in the old patch
neighborhoods; `20-5-7` is mainly a re-sign/re-version rebuild. See
`notes/STATUS.md` for the exact patch table.

### What the patches actually do (final, post-hardware-trial 2026-07-26)

The 7-patch build (`poc/cancunf-fenrir-full-20-5-12.img`) is the optimal LK
configuration. All patches are hardware-confirmed. `spoof_sboot_state` was removed
after Ghidra proved it was both unnecessary (stock sboot global = 0x11 → getter
already returns 1 = enabled) and harmful (replacement decodes as `eor w8,w2,#0x3ffff`
with uninitialized w2, writing garbage that breaks dm-verity).

| Patch | Layer | Status | Evidence |
|---|---|---|---|
| `sec_get_vfy_policy` | chain | ✅ hardware-confirmed | 1× bl2_ext/lk/aee |
| `spoof_lock_state` | state | ✅ in artifact, but wrapper is DEAD CODE (0 callers) | Ghidra xref proof in RESEARCH_FINDINGS §4 |
| `force_green_state` | state | ✅ hardware-confirmed | `verifiedbootstate=green` |
| `avb_allow_verification_error` | boot-img | ✅ in artifact | `FUN_00073078` caller flags |
| `bypass_security_control` | fastboot gate | ✅ in artifact | `FUN_000a2b48`, NOPs security check |
| `preflash_validation_bypass` | flash | ✅ in artifact | NOPs preflash failure branch |
| `vbmeta_device_state_locked` | cmdline | ✅ hardware-confirmed | `device_state=locked` |
| `spoof_sboot_state` | — | ❌ REMOVED | Stock sboot=0x11 already enabled; replacement is harmful |

### The attestation boundary (the definitive finding)

Ghidra decompilation traced the full lock-state data flow. The lock-state code in
both `lk` and `bl2_ext` is **write-only**: `sec_get_seccfg` writes the lock state
to a global, but **no function reads it** to return to the TEE. The
`sec_query_device_lock` wrapper has zero callers — it's dead code.

The TEE reads `deviceLocked` from RPMB/eFuse directly, through its own code in
`tee.img`. No LK patch can change what the TEE signs in the attestation
certificate. This is why Play Integrity caps at BASIC despite all cmdline
properties being correctly spoofed.

**For DEVICE + STRONG:** use Track A (TrickyStore + keybox). See
`notes/RESEARCH_FINDINGS.md` for the full Ghidra decompilation and data-flow proof.

## 10. Reproduce / toolchain

```bash
# deps
git clone https://github.com/R0rt1z2/liblk      # parsing
# fenrir injector at /path/to/fenrir/injector   # patch engine
pip install pyasn1                              # liblk cert dep

# rebuild PoC
PYTHONPATH=/path/to/liblk:/path/to/fenrir/injector \
  python3 poc/build_poc.py

# re-run analysis
PYTHONPATH=/path/to/liblk python3 analysis/find_patches.py
```

cancunf load address (from liblk): `0xffff000050f00000`.

---

## 11. Critical constraints (do not forget)

- **Firmware-build-specific.** This PoC targets `V1TDS35H.83-20-5-5 RETIN` only.
  Different build/region = different offsets = brick.
- **Unlock first.** `mtkclient da seccfg unlock` — the flaw only triggers unlocked.
- **No proven Strong Integrity.** Don't assume the bootloader PoC passes Play
  Integrity. Use TrickyStore+keybox (Track A) for daily-use integrity.
- **Brick risk is real.** EL3 patches can hard-brick; keep full dumps + EDL/DA
  recovery. Do not test on a daily driver without a spare.

---

## 12. Key reference URLs

- fenrir: https://github.com/R0rt1z2/fenrir (issues #8, #11, #15 are essential reading)
- liblk: https://github.com/R0rt1z2/liblk
- lkpatcher: https://github.com/R0rt1z2/lkpatcher (+ blog guide, currently 404)
- hacc: https://github.com/shomykohai/hacc
- Shirayuki39 active fork: https://github.com/Shirayuki39/fenrir
- mtkclient: https://github.com/bkerler/mtkclient
- HackTricks MTK bl2_ext: https://hacktricks.wiki/en/hardware-physical-access/firmware-analysis/android-mediatek-secure-boot-bl2_ext-bypass-el3.html
- HackTricks Play Integrity bypass: https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/play-integrity-attestation-bypass.html
- Android Verified Boot: https://source.android.com/docs/security/features/verifiedboot
- Play Integrity verdicts: https://developer.android.com/google/play/integrity/verdicts
- Copperhead verified boot (best TEE/attestation explainer): https://copperhead.co/android/docs/verified_boot
- MediaTek Genio Secure Boot (rare public MTK doc): https://genio.mediatek.com/doc/iot-yocto/latest/sw/yocto/secure-boot.html
- cancunf custom-ROM guide (cyberknight): https://cyberknight777.dev/instructions/cancunf/
- cancunf guides (rvsmooth): https://rvsmooth.github.io/cancunfdocs/

---

## 13. Learning path (if continuing dev)

To go from "running the PoC" to "writing/extending it," in order:
1. **ARM64 assembly (reading):** Azeria Labs tutorials; Maria Markstedter's
   *Arm Assembly Internals & Reverse Engineering*.
2. **Ghidra:** load `firmware/lk.img`, find `sec_get_vfy_policy` at the offset
   `analysis/find_patches.py` reports. That single exercise is worth a week of theory.
3. **Android boot chain + TrustZone:** source.android.com verifiedboot docs;
   Copperhead verified boot docs; ARM TF-A docs.
4. **MTK-specific:** bkerler/mtkclient source; liblk/hacc/mtklogo sources
   (these *are* the format docs); HackTricks MTK page.
5. **Practice ladder:** read fenrir injector → re-run our analysis → port a
   patch to a new device using Shirayuki39's S666LN work as template.
6. **Community:** fenrir/liblk/hacc GitHub issues; XDA MTK subforums.

Highest-leverage first action: **install Ghidra and load `firmware/lk.img`.**
