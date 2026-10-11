# Garmr

Garmr is a fenrir-inspired secure-boot-bypass PoC for Motorola's `cancunf`
platform: the Moto G54 5G and Moto G64 5G (MediaTek MT6855 / Dimensity 7025).

I built this to answer a narrow question: does cancunf's MTK LK container have
the same EL3 verification-policy weakness used by fenrir? Yes. The current LK
artifact reportedly booted in historical trials and made Android report a locked,
green boot state. It does **not**, by itself, make hardware attestation report a locked
bootloader.

This is a research tree, not a one-click unlock tool. The phone must already be
bootloader-unlocked, and every patch is tied to a firmware build.

## Current result

Historical reports for `V1TDS35H.83-20-5-12 RETIN` (Android 15):

- `poc/cancunf-fenrir-full-20-5-12.img` boots with stock system images.
- Android reports `verifiedbootstate=green`,
  `vbmeta.device_state=locked`, and `flash.locked=1`.
- Play Integrity reaches **BASIC**, not DEVICE or STRONG. The Trustonic
  KeyMint trustlet still has an independent bootloader-state input.
- The artifact parses cleanly and is cert-bypass signed for the LK container.

The newer `V1TDS35H.83-20-5-14` build was surveyed in October 2026: no patch
site was hardened, three patterns were re-pinned, and
`poc/cancunf-native-full-20-5-14.img` builds and verifies cleanly but has
not been flashed. Details in [`notes/STATUS.md`](notes/STATUS.md).

These hardware reports are not independently reproduced by this checkout:
no captured boot-property logs, signed before/after attestation chains or
Play Integrity responses supporting them were identified in the audit.
Offline reconstruction matches both checked-in LK artifacts exactly.

The name `full` is historical. It contains seven patch types (eleven placements,
82 changed payload bytes per build); the dangerous
`sboot` patch is deliberately absent. The output filenames retain `fenrir`
as provenance of the original artifact, not a current dependency.

### Patch status

| Patch | Result |
| --- | --- |
| `sec_get_vfy_policy` | Byte-verified in `bl2_ext`, `lk`, and `aee`; historical boot success reported |
| `spoof_lock_state` | Present, but the seccfg reader it targets is dead code for attestation |
| `force_green_state` | Byte-verified; historical green properties reported |
| `avb_allow_verification_error` | Included and byte-verified |
| `bypass_security_control` | Included; skips the fastboot lock/security gate |
| `preflash_validation_bypass` | Included; skips the preflash failure branch |
| `vbmeta_device_state_locked` | Byte-verified; historical locked properties reported |
| `spoof_sboot_state` | Removed: stock sboot is already enabled, and the replacement breaks boot |

The exact bytes, offsets, and Ghidra evidence are in [`notes/STATUS.md`](notes/STATUS.md).

## Why Strong Integrity is a separate problem

The identified LK seccfg reader has no detected callers. Static searches found
no forwarding path to the TEE, not an exhaustive proof that none exists.
Trustlet state selectors provide a separate research target; their HAL inputs
and mapping into the signed RootOfTrust serializer remain to be traced.

A three-patch KeyMint trustlet module is included as an unvalidated research
artifact:

```text
poc/cancunf-km-trustlet-patch-v2.zip
```

It targets the 20-5-12 trustlet and changes three candidate state selectors;
their mapping into signed standard attestation fields remains unvalidated.
It is intended for a rooted Magisk/KernelSU environment,
and Kinibi may reject the modified binary even if the bind mount succeeds.
Do not treat it as tested just because the binary patch is present. See
[`notes/TRUSTLET_PATCH.md`](notes/TRUSTLET_PATCH.md).

For a daily driver, the practical alternative is TrickyStore plus a valid
keybox. That route needs root and has keybox-rotation/revocation costs; see
[`notes/integrity_practical.md`](notes/integrity_practical.md).

## Build and verify

The canonical builders require Python 3's standard library only. They apply
the seven patch types and native CERT2 hash overrides, verifying the complete
result before writing it. Native12 owns shared patch operations; native14
supplies build-specific pattern overrides.

```bash
python3 poc/build_native_20_5_12.py
```

The same seven-patch set is available for the newer `V1TDS35H.83-20-5-14`
build (three patterns re-pinned after a routine Motorola recompile; no site
was actually hardened — see [`notes/STATUS.md`](notes/STATUS.md)):

```bash
python3 poc/build_native_20_5_14.py
```

The cert bypass lives in [`poc/mtk_cert.py`](poc/mtk_cert.py) (sign + verify,
stdlib only). See [`notes/CERT_BYPASS.md`](notes/CERT_BYPASS.md) for the
mechanism and the byte-for-byte equivalence to fenrir's `CertBypass.OVERRIDE`.

The stock input defaults to:

```text
firmware/V1TDS35H.83-20-5-12/lk.img
```

Override it with `CANCUNF_STOCK` and the output with `CANCUNF_OUT` if needed.
The deprecated `poc/build_full_20_5_12.py` entry delegates to native12.
The unsafe legacy `devices/cancunf.py` entry is removed; do not use old copies.
Parsing rejects truncation and trailing bytes; full signed inventories are
LK = `lk`, `bl2_ext`, `aee`, `lk_main_dtb`, and TEE = `atf`, `tee`.
Certificate verification establishes internal consistency using keys embedded
in the image, not hardware authorization, boot safety or trustlet acceptance.

To verify an existing artifact against its stock input:

```bash
python3 poc/verify_poc.py \
  --build 20-5-12 \
  firmware/V1TDS35H.83-20-5-12/lk.img \
  poc/cancunf-fenrir-full-20-5-12.img
```

`verify_poc.py` is the stdlib canonical stock-to-artifact verifier: it checks
the exact expected artifact and certificates, not merely pattern counts.
`--build` accepts `20-5-12` (default) and `20-5-14`; use matching stock/artifact
paths for 14. Run offline regression tests with:

```bash
python3 -m unittest discover -s tests -v
```

CI runs offline tests, not hardware tests. Analysis helpers are separate:
`find_patches.py` requires liblk; disassembly helpers require Capstone;
self-signing requires cryptography, and key generation uses OpenSSL. Install these in your
Python environment only if using those paths. Vendor extraction requires the
matching firmware super sparsechunks, which are absent from the supplied
firmware directories. The old EROFS reader does not support the 14 compact
layout; `extract_trustlet_14.py` now delegates to the build/inode-specific
`erofs_compact.py` decoder. Missing inputs prevent an end-to-end extraction
retest; do not mistake input validation for proven extraction correctness.

To rerun the byte-level analysis:

```bash
LIBLK_PATH=/path/to/liblk \
CANCUNF_STOCK=firmware/V1TDS35H.83-20-5-12/lk.img \
python3 analysis/find_patches.py
```

## Repository layout

```text
firmware/                 Stock LK, TEE, and related firmware components
poc/build_full_20_5_12.py Deprecated compatibility entry for native12
poc/build_native_20_5_12.py Canonical seven-patch builder (native cert bypass)
poc/build_native_20_5_14.py Seven-patch builder for the 20-5-14 build (re-pinned)
poc/mtk_cert.py          MTK CERT2 hash-override cert bypass + verifier
poc/verify_poc.py         Exact stock-to-artifact and certificate verification
poc/cancunf-fenrir-full-20-5-12.img Historically reported booting LK artifact
poc/cancunf-native-full-20-5-14.img Newer-build artifact (not hardware-validated)
poc/cancunf-km-trustlet-patch-v2.zip Root-module trustlet patch package
poc/trustlet_patch/       Trustlet binaries and Magisk module scripts
analysis/                 Pattern searches and binary-analysis helpers
analysis/check_fw.py      Stock-firmware survey for the whole patch set
analysis/diff_sites.py   Old-vs-new LK byte diff and relaxed pattern hunts
analysis/repin_20_5_14.py / confirm_repin.py  Capstone re-pinning evidence
analysis/find_trustlet.py  Sparse-aware super scan for the KeyMint trustlet
notes/STATUS.md           Current patch and hardware-trial status
notes/CERT_BYPASS.md      CERT2 cert-bypass mechanism and equivalence to fenrir
notes/KINIBI_MCLF_KEY.md  Candidate key evidence and unresolved provenance
notes/RESEARCH_COMPLETE.md  Provisional attack-surface map and test plan
notes/TESTING_GUIDE.md      Hardware test procedure (review before flashing)
notes/ATTESTATION_CHANNEL.md  TEE/KeyMint data-flow investigation
notes/TRUSTLET_PATCH.md   Trustlet patch point and remaining risks
```

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
