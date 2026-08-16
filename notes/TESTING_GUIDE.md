# Garmr hardware-testing guide

Read this fully before flashing anything. This is a **research** procedure for a
device you own, tied to one firmware build, with a real brick risk.

**Target:** Moto G54 5G / G64 5G (`cancunf`, MT6855 / Dimensity 7025)
**Firmware:** `V1TDS35H.83-20-5-12 RETIN` (Android 15) — do not mix builds.
**Prereq:** bootloader already unlocked (`seccfg` unlocked). Garmr is *not* an
unlock bypass.

---

## 0. Before you start

1. **Back up every partition** you will touch. Minimum:
   ```bash
   # via mtkclient (EDL) or a rooted shell
   dd if=/dev/block/by-name/lk        of=/sdcard/backup/lk.img
   dd if=/dev/block/by-name/tee       of=/sdcard/backup/tee.img
   ```
   Better: back up `lk`, `tee`, `preloader`, `boot`, `vbmeta`, `gz` and keep a
   full stock firmware archive.
2. **Have a recovery path** before you start: a known-good `mtkclient` EDL/DA
   setup and the stock images ready to re-flash. A wrong `tee.img` can leave
   the phone unable to reach fastboot.
3. Use a **sacrificial device** if possible. The failed `sboot` variants in this
   repo produced the "Cannot load Android system" screen — that's the class of
   failure you should expect if a patch is wrong.
4. Confirm root (Magisk/KernelSU) for the trustlet steps (options B and C).

---

## 1. Build the artifacts (do this on a PC first)

```bash
cd /path/to/garmr

# (a) LK image — 7 patches + cert bypass (byte-identical to fenrir artifact)
python3 poc/build_native_20_5_12.py
# -> poc/cancunf-native-full-20-5-12.img

# (b) tee.img with the MCLF-verify bypass (best-guess @ tee.img 0x9bd40)
python3 bypass/patch_verify.py \
    --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
    -o bypass/tee_bypassed.img

# (c) self-signed tee.img + trustlet (negative control)
python3 selfsign/keygen.py --out selfsign
python3 selfsign/patch_tee_key.py \
    --modulus selfsign/modulus.bin \
    --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
    -o selfsign/tee_selfsigned.img
python3 selfsign/sign_trustlet.py \
    --key selfsign/key.pem \
    --trustlet poc/trustlet_patch/0706000000000000000000000000004d.tlbin \
    -o selfsign/trustlet_selfsigned.tlbin
```

Sanity check every image **before** flashing — it must print `Result: VALID`:

```bash
python3 poc/mtk_cert.py verify poc/cancunf-native-full-20-5-12.img --all
python3 poc/mtk_cert.py verify bypass/tee_bypassed.img --all
python3 poc/mtk_cert.py verify selfsign/tee_selfsigned.img --all
```

---

## 2. Option A — LK only (baseline, lowest risk)

Flash the patched LK, keep everything else stock.

```bash
# fastboot
fastboot flash lk poc/cancunf-native-full-20-5-12.img
fastboot reboot
```

**Check:**

```bash
adb shell getprop ro.boot.verifiedbootstate   # expect: green
adb shell getprop ro.boot.vbmeta.device_state # expect: locked
adb shell getprop ro.boot.flash.locked        # expect: 1
adb shell getprop ro.boot.verifiedbootstate   # and vbmeta digest if present
```

Play Integrity (any checker app / `playintegrity` API): expect **BASIC**, not
DEVICE/STRONG. This is the proven baseline — if it does not boot or does not
report green/locked, stop and re-check the build.

---

## 3. Option B — trustlet bind-mount only (answers the #1 unknown)

Keep stock `tee.img`. Only install the trustlet patch module. This tells us
whether **Kinibi rejects the modified MCLF** (the single biggest unknown).

1. Copy `poc/cancunf-km-trustlet-patch-v2.zip` to the phone.
2. Install as a Magisk/KernelSU module.
3. Reboot.

**Check (the whole point of this step):**

```bash
adb logcat -d | grep -iE 'trustonic|keymaster|kmta|mobicore|mcRegistry' | tail -100
adb shell su -c 'ls -la /vendor/app/mcRegistry /vendor/tee /vendor/firmware 2>/dev/null'
```

- If KeyMint starts and attestation still says `unlocked` → the trustlet patch
  itself is wrong or the bind mount is not taking effect.
- If KeyMint **fails to start** / loader logs a signature rejection → **Kinibi
  verifies the MCLF**, and we proceed to Option C.
- If attestation now reports `locked` → done (unlikely, but then stop here).

---

## 4. Option C — trustlet + tee.img bypass (the main attempt)

Flash the bypassed TEE and install the trustlet module together.

```bash
fastboot flash tee bypass/tee_bypassed.img
fastboot reboot
# install poc/cancunf-km-trustlet-patch-v2.zip module, reboot again
```

**Check:**

```bash
adb logcat -d | grep -iE 'trustonic|keymaster|kmta|mobicore' | tail -100
```

Then dump a full attestation certificate (Key Attestation / `keymint` tester or
`adb shell` through a rooted helper) and look at:

- `deviceLocked` (want `true`)
- `verifiedBootState` (want `VERIFIED`)
- `verifiedBootKey` + `vbmetaDigest` (STRONG needs these to be sane)
- `bootState` (want `GREEN`)

Play Integrity: expect **DEVICE or STRONG** if the bypass + trustlet patch both
hold. If it stays BASIC, one of the two assumptions is wrong — report back the
attestation fields and the mobicore log.

---

## 5. Option D — self-sign (negative control)

Expected to **fail** — this confirms the efuse-key finding rather than trusting
it on paper.

```bash
fastboot flash tee selfsign/tee_selfsigned.img
# replace the trustlet with the self-signed one (same bind-mount approach,
# pointing at selfsign/trustlet_selfsigned.tlbin)
fastboot reboot
```

**Check:** KeyMint should either fail to start (signature/key rejection) or
still report `unlocked`. A **failure here is the expected, correct result** —
it validates that the verification key is not in flash.

---

## 6. Recovery

If any step fails to boot:

```bash
fastboot flash lk  backup/lk.img
fastboot flash tee backup/tee.img
# or full EDL re-flash of the stock firmware via mtkclient
```

If fastboot is unreachable, use the EDL/DA recovery path you prepared in step 0.

---

## 7. Decision table (fill in while testing)

| Option | Booted? | verifiedbootstate | deviceLocked | Play Integrity | Notes |
| --- | --- | --- | --- | --- | --- |
| A (LK only) | | green | ? | BASIC (expected) | |
| B (trustlet only) | | | | | did mobicore reject MCLF? |
| C (trustlet + tee bypass) | | | | | |
| D (self-sign) | | | | | expected FAIL |

---

## 8. Hard rules

- **One change at a time.** Don't flash LK + TEE + trustlet together on the
  first try; you won't know which one broke boot.
- **Match the firmware build.** Every offset in this repo is for
  `V1TDS35H.83-20-5-12`. A different build needs a fresh `find_patches.py` run
  and fresh offsets.
- **A green Android property is not a green attestation.** Only the attestation
  certificate + Play Integrity verdict count.
- **Log everything.** `logcat`, the full attestation cert, and which image you
  flashed — these are what let us fix the next step.
