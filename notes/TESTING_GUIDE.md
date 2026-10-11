# Garmr hardware-testing guide

Read this fully before flashing anything. This is a **research** procedure for a
device you own, tied to one firmware build, with a real brick risk.

**Target:** Moto G54 5G / G64 5G (`cancunf`, MT6855 / Dimensity 7025)
**Firmware:** `V1TDS35H.83-20-5-12 RETIN` (Android 15) — do not mix builds.
**Prereq:** bootloader already unlocked (`seccfg` unlocked). Garmr is *not* an
unlock bypass.

The examples below use 20-5-12. Separate 20-5-14 artifacts exist; substitute
all LK/TEE inputs/outputs consistently. The module ZIP is 12-only and refuses
14; the separate 14 trustlet binary is not a supported module package.
No TEE/trustlet hardware result or DEVICE/STRONG solution is
established. LK success is a historical report without captured supporting
logs/certificates/integrity responses in the audited tree.

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

# (b) experimental two-consumer bypass (Kinibi 0x5ebf0 and 0x5eca4)
python3 bypass/patch_verify.py \
    --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
    -o bypass/tee_bypassed.img

# (c) candidate self-signed tee.img + trustlet (exploratory, not an efuse test)
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

Python 3 stdlib suffices for native builders/verification; self-signing requires
`cryptography`, key generation uses OpenSSL, disassembly requires Capstone, older analysis may need
liblk. Vendor extraction cannot be rerun without matching super sparsechunks,
absent from the supplied firmware directories.

Check every image **before** flashing:

```bash
python3 poc/mtk_cert.py verify poc/cancunf-native-full-20-5-12.img --all
python3 poc/mtk_cert.py verify bypass/tee_bypassed.img --all
python3 poc/mtk_cert.py verify selfsign/tee_selfsigned.img --all
python3 poc/verify_poc.py --build 20-5-12 \
    firmware/V1TDS35H.83-20-5-12/lk.img \
    poc/cancunf-native-full-20-5-12.img
python3 -m unittest discover -s tests -v
```

Full parsing rejects truncation/trailing bytes; verification requires all four
LK signed components or both TEE components. `VALID` establishes internal
signature/hash consistency with embedded keys, not device authorization or
boot safety. Exact stock-to-artifact verification is stdlib-only; its build
selector defaults to 20-5-12 and also accepts 20-5-14. Builders verify before
writing. Passing offline CI/tests is not a hardware test.

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
DEVICE/STRONG. This is the historically reported baseline — if it does not boot or does not
report green/locked, stop and re-check the build.

---

## 3. Option B — trustlet bind-mount only (answers the #1 unknown)

Keep stock `tee.img`. Only install the trustlet patch module. This probes
acceptance, but a mount or service restart alone does not establish execution.

1. Copy `poc/cancunf-km-trustlet-patch-v2.zip` to the phone.
2. Install as a Magisk/KernelSU module.
3. Reboot.

**Check (the whole point of this step):**

```bash
adb logcat -d | grep -iE 'trustonic|keymaster|kmta|mobicore|mcRegistry' | tail -100
adb shell su -c 'ls -la /vendor/app/mcRegistry /vendor/tee /vendor/firmware 2>/dev/null'
```

- Verify matching firmware, mounted file hashes and installed `module.log`.
  Logs record restart requests for discovered services, not proof of restarts.
  Independently check actual restarts and fresh secure-world session evidence.
- If KeyMint starts but attestation stays unlocked, possible causes include an
  old cached session, wrong file/path, patch semantics or another state source.
- KeyMint startup failure alone does not prove signature enforcement. Preserve
  explicit loader rejection evidence and distinguish it from mount/service errors.
- If a fresh signed certificate changes to locked, preserve the complete chain
  and parsed fields; this is not by itself a DEVICE/STRONG result.

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
- `verifiedBootKey` + `vbmetaDigest` (compare against build-matched baseline)
- `bootState` (want `GREEN`)

Record the actual Play Integrity response; **no DEVICE/STRONG verdict is
promised or expected from these patches alone**. Even locked/green signed
fields do not establish chain trust, provisioning, revocation status, freshness,
security-patch requirements or verifier policy. BASIC does not uniquely diagnose
either patch. Preserve image hashes, full certificates and loader/session logs.

---

## 5. Option D — self-sign (exploratory candidate)

Acceptance is unknown. Failure cannot confirm efuse provenance: wrong metadata,
signed region, algorithm, key selection or other enforcement can explain it.

```bash
fastboot flash tee selfsign/tee_selfsigned.img
# replace the trustlet with the self-signed one (same bind-mount approach,
# pointing at selfsign/trustlet_selfsigned.tlbin)
fastboot reboot
```

**Check:** collect startup, loader and fresh-session evidence and a full signed
certificate if available. Do not interpret rejection or unchanged state as
proof that a verification key is absent from flash.

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
| D (self-sign) | | | | | candidate scheme; key provenance unresolved |

---

## 8. Hard rules

- **One change at a time.** Don't flash LK + TEE + trustlet together on the
  first try; you won't know which one broke boot.
- **Match the firmware build.** This guide uses 20-5-12 examples; 20-5-14 has
  separately re-pinned patterns and matching artifacts. Other builds need
  fresh analysis, not merely a pattern match.
- **A green Android property is not a green attestation.** Only the attestation
  certificate + Play Integrity verdict count.
- **Log everything.** `logcat`, the full attestation cert, and which image you
  flashed — these are what let us fix the next step.
