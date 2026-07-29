# Garmr research notes: what the cancunf trial proved

This is the investigation log for the Motorola Moto G54/G64 5G, codename
`cancunf`. Garmr is inspired by fenrir and uses the same general idea: patch the
MediaTek LK container so an unlocked device will execute modified boot-chain
components.

The useful result is narrower than the original hope:

- The LK bypass works.
- The patched phone boots and reports a green/locked state to Android.
- LK patching alone does not change the hardware-backed attestation result.
- The real attestation patch point is a vendor Trustonic KeyMint trustlet. A
  binary patch exists, but it has not yet been tested on hardware.

## 1. Boot chain

The relevant chain on this phone is:

```text
BootROM
  -> preloader
  -> bl2_ext / ATF (EL3)
  -> Trustonic TEE
  -> GenieZone (EL2)
  -> lk and aee
  -> Linux
```

When `seccfg` is unlocked, the preloader skips signature verification for
`bl2_ext` but still jumps into it. That is the opening used by Garmr. Once a
patched `bl2_ext` is running at EL3, it can load the downstream components
without enforcing their normal signatures.

Inside the stock `lk.img` used here:

| Partition | File offset | Role |
| --- | ---:| --- |
| `lk` | `0x000200` | Fastboot, boot logic, and state reporting |
| `bl2_ext` | `0x130790` | EL3 verification and security policy |
| `aee` | `0x1ee300` | AEE dump handler |
| `lk_main_dtb` | `0x2ece90` | Device tree |

Each sub-partition has a `0x200`-byte GFH header. Ghidra was loaded with the
raw image at address zero, so file offsets and Ghidra addresses line up.

## 2. What boots

The current artifact is:

```text
poc/cancunf-fenrir-full-20-5-12.img
```

It contains seven LK-container patches. The sboot patch is intentionally not
one of them; it caused every tested image that contained it to fail during boot.
The working image reports:

```text
verifiedbootstate=green
vbmeta.device_state=locked
flash.locked=1
```

It boots with the stock system image and reaches BASIC Play Integrity. The
attestation certificate still reports the bootloader as unlocked.

### Patch inventory

| Patch | Where | What it does |
| --- | --- | --- |
| `sec_get_vfy_policy` | `bl2_ext`, `lk`, `aee` | Makes internal verification-policy queries return no auth required |
| `spoof_lock_state` | `bl2_ext`, `lk`, `aee` | Replaces a lock-state wrapper; later shown to be dead code for attestation |
| `force_green_state` | `lk` | Stores boot state zero/green |
| `avb_allow_verification_error` | `lk` | Sets the AVB allow-verification-error flag |
| `bypass_security_control` | `lk` | Skips the fastboot security branch |
| `preflash_validation_bypass` | `lk` | Skips the preflash validation failure branch |
| `vbmeta_device_state_locked` | `lk` | Forces the cmdline device state to locked |

All seven are checked by the builder and verifier. The exact bytes are in
[`STATUS.md`](STATUS.md).

## 3. What went wrong with sboot

The common fenrir sboot pattern matched twice per partition on cancunf. That was
the first warning sign.

In `lk`, the occurrence at `lk+0xbec18` calls the actual sboot getter at
`lk+0xbeb50`. The occurrence at `lk+0xc237c` calls a 208-byte certificate
routine that indexes X.509 OIDs such as `1.2.840.113549.1.1.10` and
`1.2.840.113549.1.1.1`. Patching both occurrences damaged the crypto path.

Narrowing the pattern to the getter did not help. The replacement itself uses
`w2` in an `eor` instruction even though this call path passes its argument in
`w0`. The output pointer consequently receives garbage.

The stock global at `lk+0x12ee2c` is `0x11`. The getter treats that value as
“sboot enabled” and returns one. There was nothing to fix. The sboot stage has
been removed from every current Garmr build.

## 4. The LK lock-state code is not the attestation path

The first theory was that `spoof_lock_state` would make the TEE see `LKS_LOCK`.
The disassembly does not support that.

In `lk`, `sec_get_seccfg` (`FUN_000c2cec`) reads the 64-byte `sec_update`
partition and copies its fields to globals around `0x209e40`. The lock state is
the upper half of the value at raw seccfg offset `0x08`, or raw offset `0x0c`.

The only function that reads that field is `sec_query_device_lock`
(`FUN_000c2fe4`). Its callers are empty: Ghidra finds no direct caller and no
pointer-table reference. The same pattern appears in `bl2_ext`; its lock-state
global is written but never read.

The LK SMC calls do not fill the gap. The mapped SMC surface is power/RTC
service code, not a lock-state or boot-state service. In other words, patching
this LK wrapper changes bytes in the image but does not change the value that
KeyMint signs.

## 5. The actual attestation route

`tee.img` contains the ATF runtime and the Trustonic Kinibi core. It contains
storage, crypto, and MTK SiP services, including the two root-of-trust mailbox
services:

```text
MTK_SIP_GET_ROOT_OF_TRUST  0x82000020 / 0xc2000020
MTK_SIP_LK_ROOT_OF_TRUST   0x82000120 / 0xc2000120
```

The LK calls `LK_ROOT_OF_TRUST` to pass Motorola `utag` data and UFS/RPMB
geometry to the secure side. That is a storage handoff, not the attestation
certificate itself. A string search of the Kinibi image found no Keymaster or
RootOfTrust implementation.

The KeyMint logic is in a dynamically loaded vendor trustlet:

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

Disassembly of that trustlet found the `is_locked()` function at offset
`0x19ec0`. It reads one global and returns whether it is nonzero. The current
three-site patch forces that return value to one and also forces the two related
attestation fields to the locked/green values.

The patch is in `poc/cancunf-km-trustlet-patch-v2.zip`. It is an experiment,
not a hardware result. Kinibi may reject the modified MCLF trustlet before
KeyMint can load it.

## 6. Partition and address notes

For `V1TDS35H.83-20-5-12/lk.img`:

```text
0x000000  lk header
0x000200  lk data
0x130590  bl2_ext header
0x130790  bl2_ext data
0x1ee100  aee header
0x1ee300  aee data
0x2ece90  lk_main_dtb header
0x322510  end of image
```

The LK load base used in the notes is:

```text
0xffff000050f00000
```

Useful strings in the LK partition include:

| String | Flat offset |
| --- | ---: |
| `sec_query_device_lock` | `0xf4816` |
| `sec_get_seccfg` | `0x119e33` |
| `Preflash validation failed` | `0xd053f` |
| `k6855v1_64_cancun` | `0xcc595` |
| `androidboot.verifiedbootstate=orange` | `0x103d65` |

## 7. Hardware log

| Build | Result |
| --- | --- |
| 5-patch vbmeta-locked | Booted; green; device state locked; BASIC |
| 8-patch, sboot patched at all six matches | “Cannot load Android system” |
| 8-patch, sboot narrowed to three matches | “Cannot load Android system” |
| 7-patch, no sboot patch | Booted; green; device state locked; BASIC |

The failed images were enough to identify the sboot replacement as harmful. The
working image leaves the stock sboot value alone.

## 8. What remains

1. Test the KeyMint trustlet module on the exact firmware build.
2. If Kinibi checks MCLF signatures, locate and bypass that check in `tee.img`.
3. Verify the trustlet's second device-locked input and the reported
   `verifiedBootKey`/vbmeta digest on a real attestation certificate.
4. Keep payload-stage work separate. No cancunf payload has been built here.

For daily use, TrickyStore plus a valid keybox is still the practical route.
It does not depend on the Garmr LK path, but keyboxes can be revoked and need
replacement.
