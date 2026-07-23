# Play Integrity on unlocked cancunf — the honest options

Your actual pain is "custom ROM works great, apps fail integrity." There are two
parallel tracks. Read both before committing time to the bootloader exploit.

## Track A — Software (TrickyStore + keybox)  ← solves your pain NOW

This is what the rooting community actually uses today to pass
`MEETS_STRONG_INTEGRITY` on unlocked devices. It needs **root, not a bootloader
exploit.** You already have/need root for a custom-ROM daily driver anyway.

**Stack:**
- KernelSU or Magisk (root)
- **TrickyStore** (Magisk/KSU module) — intercepts the KeyMint attestation path and
  substitutes a genuine-device certificate chain (`keybox.xml`).
- A valid `keybox.xml` (extracted from a genuinely-locked device — these circulate
  in the rooting community; Google revokes abused ones, so they rotate).
- Optional: spoof the security-patch date so `MEETS_STRONG_INTEGRITY`'s
  "recent patches on all partitions" rule is satisfied.

**Result:** `MEETS_BASIC` + `MEETS_DEVICE` + `MEETS_STRONG` pass. Google's JWT is
genuine (Play Services generated it from the spoofed inputs).

**Cost:** finding/keeping an unrevoked keybox; periodic rotation when Google blocks one.

**Why this is the pragmatic answer:** zero brick risk, no firmware-build-matching,
works the day you set it up, independent of whether the fenrir PoC ever fully works.

## Track B — Bootloader exploit (this workspace)  ← research/deeper goal

The fenrir PoC in `poc/` aims to make the *genuine* hardware attestation key sign
green/locked state with no keybox needed. That's a stronger, more durable result
*if* it works — but as of now:

- Core verification-bypass + lock/sboot spoof: built and byte-verified ✅
- `force_green_state` + preflash bypass: open, need Ghidra ❌
- Whether it actually passes Strong Integrity: **unproven**, needs a real Play
  Integrity request on a booted+patched device. Could pass cleanly, could pass
  DEVICE-but-not-STRONG (the `verifiedBootKey` consistency issue), or could fail.

**Recommendation:** run Track A for your daily-driver integrity today. Keep this
workspace as the Track B research project. They aren't mutually exclusive — if Track B
matures, it removes the keybox-rotation dependency Track A carries.

## Quick decision

| If you want… | Do this |
|---|---|
| Banking/apps working this week | Track A (TrickyStore + keybox) |
| To understand/contribute to the exploit | Track B (this workspace) + learn Ghidra/ARM64 |
| The "permanent, no keybox" endgame | Track B, but it's unproven and months of work |
