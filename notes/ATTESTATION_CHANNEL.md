# Attestation channel investigation — where cancunf's `deviceLocked` comes from

**Question:** fenrir passes STRONG integrity on pacman-class devices "just" by
spoofing lock/boot state in LK. Why doesn't the same work on cancunf, and where
is the real patch point?

**Short answer:** on cancunf, no code in the whole `lk.img` container
(`lk`, `bl2_ext`, `aee`) ever forwards lock/boot state to the TEE, and the
keymaster/KeyMint logical content does not live in `tee.img` at all. The
attestation RootOfTrust is composed by a **dynamically-loaded Kinibi Keymaster
trustlet shipped in the vendor image**, above a TEE that self-sources platform
state. That trustlet (+ optionally the Kinibi core in `tee.img`) is the patch
point — both are load-time-unverified in fenrir mode.

---

## 1. The fenrir STRONG claim is real — and device-specific

R0rt1z2/fenrir README (main branch, fetched 2026-07-29):

> "In addition to patching `sec_get_vfy_policy()`, the included PoC also spoofs
> the device's lock state as locked so you can pass strong integrity checks
> anywhere while being unlocked."

Patch comment in `injector/devices.py` (pacman entry):

> "...spoof the boot state to always be set to green and thus trick **TEE** and
> Android into thinking that the device hasn't been tampered with so we can
> pass STRONG, DEVICE and BASIC Play Store Integrity checks."

So on pacman-class devices the KM attestation visibly consumes LK-produced
state. cancunf is wired differently (below).

## 2. Three independent proofs that cancunf's LK never forwards lock state

(a) **Dead wrappers.** `lk` partition: `sec_get_seccfg` (0xc2cec) maintains a
seccfg shadow struct (base 0x209e40); the lock word at 0x209e4c is read ONLY
by `sec_query_device_lock` (0xc2fe4) which has **zero callers**. Same story in
`bl2_ext` (lock word 0x2bed8c, wrapper 0x1aa2ac, zero callers). Extra callers
of `sec_get_seccfg` (0xb68b4, 0xc3034, 0xc30ac) are the
sec_update/refresh+debug-print utilities; none export the lock word anywhere.

(b) **No dispatch-table references.** Full qword sweep of all three partitions:
no pointer table (SMC handlers, fastboot tables, etc.) references any of the
seccfg/lock functions. So it's not an indirect call that Ghidra xrefs missed.

(c) **LK's SMC surface is power/RTC only.** All `smc #0` sites mapped
(trampoline at 0x1b214 generic; 0x3b6fc called with ids 0x84000002 = PSCI
CPU_OFF, 0x820000c8). No lock/boot-state service is ever requested by LK.

Tools: `analysis/trace_lockstate.py`, `analysis/map_smc.py`, `analysis/dump_fns.py`.
All reproducible on `firmware/V1TDS35H.83-20-5-12/lk.img`.

## 3. What `tee.img` actually contains (build V1TDS35H.83-20-5-12)

Partition table (0x58881688 headers):

| partition | file range | content |
|---|---|---|
| `atf` | 0x200..0x3c078 | ARM TF-A runtime (BL31 resident @ **0x48200000**) — SMC dispatch |
| `cert1`,`cert2` | — | image signing certs |
| `tee` | 0x3d150..0xc6550 | Trustonic Kinibi core (MCLF blobs @ 0x68240/0x70240/0x83240/0x84240 in-partition) |

Findings:

- ATF publishes an MTK SiP service table (descriptor = 0x20 bytes:
  `{u64 handler, u64 (end_id<<32|start_id), u64 name, u64 sub}`). Full service
  list: storage control (MMC/UFS), MPU/DAPC, crypto engine, GET_RND,
  **`MTK_SIP_GET_ROOT_OF_TRUST` (0x82000020/0xc2000020)** and
  **`MTK_SIP_LK_ROOT_OF_TRUST` (0x82000120/0xc2000120)**. No lock/boot-state/AVB
  service exists anywhere in ATF. (Tool: `analysis/trace_atf_rot.py`.)
- The ROT service is an **ATF-side mailbox**: `LK_ROOT_OF_TRUST` handler
  (atf+0x1dfa0) pushes the four SMC args into a DRAM ring (max 4 slots);
  `GET_ROOT_OF_TRUST` handler (atf+0x1d264) pops them for later consumers.
- **`lk` calls `LK_ROOT_OF_TRUST` 5×** from `lk+0x3875c` (called from 0x734a8),
  pushing Motorola **utag** data + UFS/RPMB geometry (struct at rt
  0x51066898 — filled by storage-detect code at 0x6b380; the `mul/lsr #3`
  arithmetic is bits→bytes of RPMB geometry). This is the TEE RPMB/storage
  handover path, **not** attestation content.
- **Zero keymaster/attestation strings in tee.img** (`keymaster`,
  `deviceLocked`, `verifiedBoot*`, `rootOfTrust`, `attest`, `LOCKED`,
  `verifiedBootKey` — all absent). Kinibi ships only generic services
  (SFS/storage, TUI flags, gpd properties).

**Conclusion:** the RootOfTrust extension in key-attestation certs is composed
by the **dynamic KM trustlet** (in vendor image: `/vendor/tee`,
`/vendor/firmware`, `/system/tee`, or the *hbp*/trustlet partitions — Kinibi
UUID-named `.tlbin` files), not by anything in lk.img/tee.img that we can see.
Its lock/boot-state input comes from either (i) Kinibi platform state
(eFuse/lifecycle via tlApi), (ii) a GZ/RKP-fed channel, or (iii) the RPMB
conduit (ATF-mediated) — NOT from LK.

## 4. Implications — the actual ways to "locked + STRONG" on cancunf

**Path 1 — patch the KM trustlet (+ Kinibi TA check) [the fenrir-equivalent].**
In fenrir mode `bl2_ext` loads `tee.img` unverified, and Kinibi then loads
vendor trustlets unverified. So:
1. Dump the vendor Keymaster trustlet (see §5).
2. Find its RootOfTrust composition (`swd_key_attest` equivalent — keybuster's
   Samsung writeup documents the exact internal format: ASN.1 `km_indata`
   `swd_*` handlers; Kinibi variant too).
3. Patch `deviceLocked→true`, `verifiedBootState→VERIFIED` (and if CrossChecked
   / consistent: `verifiedBootKey`) at its source, **or** patch its platform
   state query to return locked.
4. If Kinibi enforces trustlet signature (MCLF auth), patch `tee.img`'s TA
   authentication check as well — tee.img is unverified in fenrir mode.
This yields genuine-looking STRONG certs **with the stock keybox intact**, the
exact property fenrir has on pacman.

**Path 2 — GZ/RKP channel [if KeyMint lives there].** signing-info lists
`gz.img__mkp_service`, `gz.img__rkp`. If the KM implementation is under
GenieZone/RKP on this build, same analysis applies to gz.img. Need the dump.

**Path 3 — TrickyStore + keybox [works TODAY, unprivileged-firmware].**
TrickyStore hacks the leaf attestation certificate at the KeyMint HAL level and
re-signs with a leaked keybox chain; it substitutes RoT fields
(locked/VERIFIED) regardless of TA's inputs, so cancunf's TEE autonomy doesn't
matter. Needs root + a surviving keybox (rotation). This is the only option
that does not depend on further RE.

**Discriminator experiment (cheap, device only):** on the current 7-patch
build, run a Key Attestation app and read the FULL RoT extension fields:
`verifiedBootKey`, `verifiedBootState`, `vbmetaDigest`, `deviceLocked`.
- If `verifiedBootState`==VERIFIED / `verifiedBootKey`==stock while only
  `deviceLocked`==false → the TA partially consumes LK state and a narrow LK
  patch may suffice (recheck channel).
- If ALL fields report hardware truth (orange/UNVERIFIED + stock key +
  unlocked) → Path 1/2/3 as above; no LK patch can help. (Current
  "BL is unlocked" reading suggests the latter.)

## 5. Dumps needed to execute Path 1/2

1. **KM trustlet binary** — on the booted device: `su -c 'ls -la /vendor/tee
   /system/tee /vendor/firmware /vendor/tee 2>/dev/null'` + `logcat -d | grep
   -i -E "trustonic|keymaster|kmta"` right after boot to learn the TA uuid/path;
   or extract `vendor_b` from the OTA: `super.img` → `lpunpack` → mount/read.
   Kinibi trustlets are UUID-named MCLF `tlbin` files. Suspect name pattern:
   `ffffffff-0000-0000-0000-4b45594d5354`-ish ("KEYMST" tails) or vendor-specific.
2. **gz.img** (same build) — to rule in/out a GZ-RKP KeyMint.
3. (Optional for the Preloader gate) `preloader.img`.

## 6. References gathered this session

- fenrir README + `injector/devices.py` (pacman) — the STRONG claim + mechanism.
- shakevsky/keybuster `writeup.md` — Kinibi/TEEGRIS Keymaster TA internals,
  HAL↔TA ASN.1 `km_indata/km_outdata` formats, `swd_key_attest`.
- 5ec1cff/TrickyStore README + SECURITY.md — hack (leaf re-sign) vs generate
  mode; keybox.xml; target.txt `!` suffix for TEE-broken devices.
