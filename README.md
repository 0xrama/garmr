# Garmr

Garmr is a fenrir-inspired secure-boot-bypass PoC for Motorola's `cancunf`
platform: the Moto G54 5G and Moto G64 5G (MediaTek MT6855 / Dimensity 7025).

I built this to answer a narrow question: does cancunf's MTK LK container have
the same EL3 verification-policy weakness used by fenrir? Yes. The current LK
artifact boots on tested hardware and makes Android report a locked, green boot
state. It does **not**, by itself, make hardware attestation report a locked
bootloader.

This is a research tree, not a one-click unlock tool. The phone must already be
bootloader-unlocked, and every patch is tied to a firmware build.

## Current result

Tested against stock firmware `V1TDS35H.83-20-5-12 RETIN` (Android 15):

- `poc/cancunf-fenrir-full-20-5-12.img` boots with stock system images.
- Android reports `verifiedbootstate=green`,
  `vbmeta.device_state=locked`, and `flash.locked=1`.
- Play Integrity reaches **BASIC**, not DEVICE or STRONG. The Trustonic
  KeyMint trustlet still has an independent bootloader-state input.
- The artifact parses cleanly and is cert-bypass signed for the LK container.

The name `full` is historical. It contains seven patches; the dangerous
`sboot` patch is deliberately absent. The output filenames retain `fenrir`
because Garmr uses the fenrir injector and liblk tooling.

### Patch status

| Patch | Result |
| --- | --- |
| `sec_get_vfy_policy` | Hardware-confirmed EL3 chain bypass in `bl2_ext`, `lk`, and `aee` |
| `spoof_lock_state` | Present, but the seccfg reader it targets is dead code for attestation |
| `force_green_state` | Hardware-confirmed |
| `avb_allow_verification_error` | Included and byte-verified |
| `bypass_security_control` | Included; skips the fastboot lock/security gate |
| `preflash_validation_bypass` | Included; skips the preflash failure branch |
| `vbmeta_device_state_locked` | Hardware-confirmed |
| `spoof_sboot_state` | Removed: stock sboot is already enabled, and the replacement breaks boot |

The exact bytes, offsets, and Ghidra evidence are in [`notes/STATUS.md`](notes/STATUS.md).

## Why Strong Integrity is a separate problem

On cancunf, LK's seccfg lock-state code writes a shadow global, but the only
reader has no callers. The TEE does not get its attestation state from that LK
path; the Trustonic KeyMint trustlet composes the RootOfTrust separately.
That is why spoofing LK properties works for Android's boot-state reporting but
hardware attestation still says the bootloader is unlocked.

A three-patch KeyMint trustlet module is included as an unvalidated research
artifact:

```text
poc/cancunf-km-trustlet-patch-v2.zip
```

It targets the exact trustlet from this firmware and forces the relevant
locked/green fields. It is intended for a rooted Magisk/KernelSU environment,
and its bind mount may be rejected if Kinibi verifies the trustlet signature.
Do not treat it as tested just because the binary patch is present. See
[`notes/TRUSTLET_PATCH.md`](notes/TRUSTLET_PATCH.md).

For a daily driver, the practical alternative is TrickyStore plus a valid
keybox. That route needs root and has keybox-rotation/revocation costs; see
[`notes/integrity_practical.md`](notes/integrity_practical.md).

## Build and verify

The builder uses [liblk](https://github.com/R0rt1z2/liblk) and the
[fenrir injector](https://github.com/R0rt1z2/fenrir/tree/main/injector):

```bash
LIBLK_PATH=/path/to/liblk \
FENRIR_INJECTOR_PATH=/path/to/fenrir/injector \
python3 poc/build_full_20_5_12.py
```

A fenrir-free, liblk-free build path is also available. It applies the same
seven patches and signs with the native CERT2 hash-override cert bypass, and
produces a byte-identical image to the fenrir path:

```bash
python3 poc/build_native_20_5_12.py
```

The cert bypass lives in [`poc/mtk_cert.py`](poc/mtk_cert.py) (sign + verify,
stdlib only). See [`notes/CERT_BYPASS.md`](notes/CERT_BYPASS.md) for the
mechanism and the byte-for-byte equivalence to fenrir's `CertBypass.OVERRIDE`.

The stock input defaults to:

```text
firmware/V1TDS35H.83-20-5-12/lk.img
```

Override it with `CANCUNF_STOCK` and the output with `CANCUNF_OUT` if needed.
The builder checks hit counts, removes every original pattern, reapplies the
cert-bypass override, and reparses the resulting image.

To verify an existing artifact against its stock input:

```bash
PYTHONPATH=/path/to/liblk \
python3 poc/verify_poc.py \
  firmware/V1TDS35H.83-20-5-12/lk.img \
  poc/cancunf-fenrir-full-20-5-12.img
```

To rerun the byte-level analysis:

```bash
LIBLK_PATH=/path/to/liblk \
CANCUNF_STOCK=firmware/V1TDS35H.83-20-5-12/lk.img \
python3 analysis/find_patches.py
```

## Repository layout

```text
firmware/                 Stock LK, TEE, and related firmware components
poc/build_full_20_5_12.py Canonical seven-patch builder
poc/build_native_20_5_12.py Fenrir-free seven-patch builder (native cert bypass)
poc/mtk_cert.py          MTK CERT2 hash-override cert bypass + verifier
poc/verify_poc.py         Per-partition patch verification
poc/cancunf-fenrir-full-20-5-12.img Latest built LK artifact
poc/cancunf-km-trustlet-patch-v2.zip Root-module trustlet patch package
poc/trustlet_patch/       Trustlet binaries and Magisk module scripts
analysis/                 Pattern searches and binary-analysis helpers
devices/cancunf.py        Initial drop-in fenrir device entry
notes/STATUS.md           Current patch and hardware-trial status
notes/CERT_BYPASS.md      CERT2 cert-bypass mechanism and equivalence to fenrir
notes/KINIBI_MCLF_KEY.md  Kinibi trustlet verification key location (flash vs efuse)
notes/RESEARCH_COMPLETE.md  Full attack-surface map and test plan
notes/TESTING_GUIDE.md      Hardware test procedure (review before flashing)
notes/ATTESTATION_CHANNEL.md  TEE/KeyMint data-flow investigation
notes/TRUSTLET_PATCH.md   Trustlet patch point and remaining risks
```

`devices/cancunf.py` is the original framework entry and still contains the
old sboot stage. Use `poc/build_full_20_5_12.py` for the current artifact.

## Hardware warnings

- Garmr's fenrir-derived path requires `seccfg` unlocked; it is not an unlock bypass.
- Back up every partition and keep a working EDL/DA recovery path before
  touching `lk.img`.
- Flash only the matching firmware build. A pattern match is not proof that a
  different build is safe.
- Use a sacrificial device if you are testing modified boot-chain images. The
  failed sboot variants produced the Android “Cannot load” screen; removing
  that patch restored boot.

## Credits

- [R0rt1z2/fenrir](https://github.com/R0rt1z2/fenrir), [liblk](https://github.com/R0rt1z2/liblk)
- [Shirayuki39/fenrir](https://github.com/Shirayuki39/fenrir) for device-porting references
- [shomykohai/hacc](https://github.com/shomykohai/hacc) for MTK structure parsing
- The cancunf kernel/ROM and low-level research community
