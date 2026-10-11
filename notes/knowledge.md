# Garmr research notebook

This is the short version of the facts gathered while porting the fenrir idea to
Motorola's `cancunf` platform. The device is the Moto G54/G64 5G, built around
the MediaTek MT6855 / Dimensity 7025.

## Device and firmware

- Codename: `cancunf`
- CPU: ARM64, MT6855V/AZA
- Bootloader: MTK LK v2 with `lk`, `bl2_ext`, `aee`, and `lk_main_dtb`
- Historically reported tested firmware: `V1TDS35H.83-20-5-12 RETIN`, Android 15
- Earlier comparison images: 20-5-5 and 20-5-7
- TEE: Trustonic Kinibi/MobiCore
- Hypervisor: GenieZone at EL2

The Motorola bootloader can be unlocked through the normal unlock-key process.
That matters: Garmr requires the device to be unlocked. It is not a way to
unlock a locked phone.

## What Garmr exploits

The normal chain is:

```text
BootROM -> preloader -> bl2_ext (EL3) -> TEE -> GZ -> LK -> Linux
```

With `seccfg` unlocked, the preloader skips verification of `bl2_ext` but still
executes it. Garmr patches `sec_get_vfy_policy()` so the running EL3 code stops
requiring authentication for the downstream LK-container components.

The core replacement is:

```text
00 01 00 b4 fd 7b bf a9
  -> 00 00 80 52 c0 03 5f d6
```

The match appears once in each of `bl2_ext`, `lk`, and `aee` in the reference
firmware.

## What the current image does

`poc/cancunf-fenrir-full-20-5-12.img` is the current seven-patch artifact. The
filename comes from the fenrir tooling; the port itself is called Garmr.

Historical trials report booting with the stock system and these properties;
captured logs, signed before/after certificates and integrity responses were
not found in the audited checkout. Offline artifacts reproduce exactly.
The reported properties are:

```text
verifiedbootstate=green
vbmeta.device_state=locked
flash.locked=1
```

The image reaches BASIC Play Integrity. It does not make the hardware-backed
certificate say that the bootloader is locked.

The seven patches are:

- internal verification-policy bypass in `bl2_ext`, `lk`, and `aee`;
- the original lock-state wrapper replacement in those partitions;
- green boot-state storage;
- AVB allow-verification-error flag;
- fastboot security-branch bypass;
- preflash-validation branch bypass;
- locked `vbmeta.device_state` command-line value.

The sboot patch was removed. Cancunf already has sboot enabled (`0x11`), and
the generic replacement corrupts either the getter output or a certificate
processing function depending on which match is selected.

## The attestation result

The LK lock-state wrapper has no callers. The LK SMC surface also has no
lock-state service. `tee.img` contains ATF and Kinibi, including an ATF mailbox
for RPMB/utag handoff, but no KeyMint implementation.

The RootOfTrust fields are composed by this vendor trustlet:

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

Its `is_locked()` function is at offset `0x19ec0`. A three-site patch is in
`poc/cancunf-km-trustlet-patch-v2.zip`. It has not been validated on hardware,
and Kinibi signature enforcement is still unknown.

That is the current boundary: LK patching controls what Linux and Android read
from the boot command line; the trustlet controls the relevant attestation
fields.

## Tools and useful files

- `poc/build_native_20_5_12.py` / `build_native_20_5_14.py`: canonical builders
- `poc/build_full_20_5_12.py`: deprecated compatibility entry for native12
- `poc/verify_poc.py`: stdlib exact stock-to-artifact/cert verifier;
  `--build {20-5-12,20-5-14}`, default 12
- `analysis/find_patches.py`: reproduce the LK pattern search
- `analysis/trace_lockstate.py`: follow LK seccfg references
- `analysis/trace_atf_rot.py`: map the ATF root-of-trust mailbox
- `analysis/map_smc.py`: map LK SMC calls
- `analysis/dump_fns.py`: dump function neighborhoods
- `notes/STATUS.md`: exact current patch status
- `notes/ATTESTATION_CHANNEL.md`: attestation data-flow investigation
- `notes/TRUSTLET_PATCH.md`: trustlet patch details

Canonical builds and certificate verification are stdlib-only and verify before
writing. Older analysis uses [liblk](https://github.com/R0rt1z2/liblk), disassembly
requires Capstone; signing requires cryptography and key generation uses OpenSSL. Matching super
sparsechunks needed for vendor extraction are absent from supplied inputs.
`mtkclient` is useful for reading
partitions and changing seccfg, but keep a complete backup and an EDL/DA
recovery path before testing.

## People and projects worth reading

- R0rt1z2: fenrir, liblk, and lkpatcher
- Shirayuki39: practical fenrir device ports and payload work
- shomykohai: hacc, an MTK structure parser
- cyberknight777: cancunf kernel/ROM work and deeper unreleased MTK research
- bkerler: mtkclient

## Things not to assume

- A clean byte patch is not a boot test.
- A green Android property is not a green hardware attestation certificate.
- A patch found in one firmware build is not safe on another.
- Garmr is not an unlock bypass.
- The trustlet module is not a confirmed Strong Integrity solution yet.

The next useful work is straightforward: test the trustlet package on the exact
vendor image, collect the complete attestation certificate, and find out whether
Kinibi accepts or rejects the modified MCLF binary.
