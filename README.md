# cancunf-exploit

Fenrir-class secure-boot-bypass PoC work for the **Motorola Moto G54/G64 5G**
(codename `cancunf`, MediaTek MT6855 / Dimensity 7025).

Personal device, legitimate research. Built against stock firmware
**`V1TDS35H.83-20-5-5 RETIN` (Android 15)** — patches are build-specific.

## What this is

An offline-constructed PoC that patches the cancunf `lk.img` to:
- disable the MTK secure-boot verification policy at EL3 (`sec_get_vfy_policy` → return 0),
- spoof lock state to `LKS_LOCK`,
- spoof sboot state,

then re-signs modified partitions via cert-bypass (override). The patched image
parses cleanly and the core patch is byte-verified present in `bl2_ext`.

## What this is NOT (yet)

- **Not proven to boot.** Runtime MMU faults / over-broad patch matches can bootloop
  or brick. Needs a sacrificial device.
- **Not complete.** `force_green_state` and the preflash-validation bypass are open
  (need Ghidra xref analysis — see `notes/STATUS.md`).
- **Not a guaranteed Strong-Integrity bypass.** On cancunf the attestation RoT
  is composed by a vendor-loaded Kinibi KM trustlet outside the LK container —
  see `notes/ATTESTATION_CHANNEL.md` for the proven boundary, the patch point
  that could still yield "fenrir-class" STRONG (vendor KM trustlet / tee.img),
  and the pragmatic Track A (TrickyStore+keybox).

## Layout

```
firmware/         extracted stock components (lk.img, preloader, tee, gz, vbmeta, …)
devices/cancunf.py    drop-in fenrir device entry (confirmed patches)
poc/build_poc.py      reproducible builder -> poc/cancunf-fenrir-poc.img
poc/cancunf-fenrir-poc.img   the built PoC (core patches only)
analysis/find_patches.py     reproduces all findings + lists open-patch candidates
notes/STATUS.md              per-patch status + exact Ghidra tasks for the open ones
notes/integrity_practical.md the two integrity tracks (honest)
```

## Reproduce

```bash
# deps: liblk (github.com/R0rt1z2/liblk) on PYTHONPATH
PYTHONPATH=/path/to/liblk:/path/to/fenrir/injector \
  python3 poc/build_poc.py
# -> poc/cancunf-fenrir-poc.img

# re-run the analysis any time:
PYTHONPATH=/path/to/liblk python3 analysis/find_patches.py
```

## Flashing prerequisites (if/when you test on hardware)

1. Unlock seccfg with `mtkclient` (`python mtk da seccfg unlock`) — the fenrir
   flaw only triggers in the unlocked state.
2. Keep a full partition backup + recovery path (EDL/DA) before flashing anything.
3. Flash only the matching firmware build. Wrong build = brick.

## Credits / references

- fenrir + liblk + lkpatcher — R0rt1z2 (NEE PA1.0)
- device-porting patterns — Shirayuki39/fenrir (S666LN, LG8n payloads)
- MTK struct parsing — shomykohai/hacc (+ cyberknight777 BromSecCfg work)
- cancunf ecosystem — cyberknight777 (kernel/ROM maintainership, mtklogo, unreleased low-level exploit)
