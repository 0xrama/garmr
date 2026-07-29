# Garmr patch status

This is the working status for the Motorola `cancunf` port. It records what was
actually checked, what booted, and which ideas turned out to be wrong.

`Confirmed` means the pattern was found at the expected count, the replacement
landed in the intended partition, and the resulting LK image parsed again.
`Hardware-confirmed` means the patched image was also booted on the test phone.

The current reference build is `V1TDS35H.83-20-5-12 RETIN` (Android 15). The
same patch neighborhoods were checked on 20-5-5 and 20-5-7; the later images
are mostly re-signed/re-versioned copies in the areas that matter here.

## Hardware trial

| Build | sboot patch | Booted? | `verifiedbootstate` | Play Integrity |
| --- | --- | --- | --- | --- |
| vbmeta-locked, 5 patches | no | yes | green | BASIC |
| full, 8 patches | 2 matches | no — “Cannot load Android system” | — | — |
| full, 8 patches | 1 narrowed match | no — “Cannot load Android system” | — | — |
| no-sboot, 7 patches | no | yes | green | BASIC |

Both booting images reported:

```text
vbmeta.device_state=locked
flash.locked=1
verifiedbootstate=green
```

That is as far as LK-only patching got. The attestation certificate still said
that the bootloader was unlocked, so Play Integrity stopped at BASIC. The TEE
and KeyMint path is covered in [`ATTESTATION_CHANNEL.md`](ATTESTATION_CHANNEL.md).

## Current artifact

```text
poc/cancunf-fenrir-full-20-5-12.img
```

The filename is inherited from the fenrir-based tooling; Garmr is the name of
this port. The image contains seven patches, is cert-bypass signed with the
`OVERRIDE` mode, reparses cleanly, and keeps dm-verity working on the tested
stock system image.

Build it with `poc/build_full_20_5_12.py` and check it with
`poc/verify_poc.py`.

## The seven patches in the image

### `sec_get_vfy_policy`

```text
00 01 00 b4 fd 7b bf a9
  -> 00 00 80 52 c0 03 5f d6
```

There is one hit in each of `bl2_ext`, `lk`, and `aee`. This makes the internal
LK-container verification-policy query return “no authentication required”.
It is the core Garmr bypass. It does not disable Android Verified Boot by
itself.

### `spoof_lock_state`

```text
20 02 00 b4 fd 7b be a9 f3 0b 00 f9 fd 03 00 91
  -> 88 00 80 52 08 00 00 b9 00 00 80 52 c0 03 5f d6
```

There is one hit in each of `bl2_ext`, `lk`, and `aee`. The bytes are clean and
the patch remains in the artifact for compatibility with the original port.
Ghidra later showed that the LK wrapper this targets has no callers, so it is
not the thing that controls the KeyMint attestation result.

### `force_green_state`

At flat offset `0x738ec` (`lk+0x736ec`):

```text
88 05 00 d0 00 69 02 b9 c0 03 5f d6
  -> 88 05 00 d0 1f 69 02 b9 c0 03 5f d6
```

This changes `str w0,[x8,#0x268]` to `str wzr,[x8,#0x268]`. The boot-state
global is therefore stored as zero, which produces the green boot state seen by
Android.

### `avb_allow_verification_error`

At flat offset `0x73298`, the patch changes:

```text
mov w3,w23
  -> orr w3,w23,#1
```

The extra bit is `AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR`. The full
match is unique in the 20-5-7 LK and is also present in the current builder.

### `bypass_security_control`

At flat offset `0x4da00`, the branch after the lock/security check is replaced:

```text
20 01 00 36 -> 1f 20 03 d5
```

That is a `tbz` replaced with a NOP. Fastboot continues instead of taking the
restricted-command error path.

### `preflash_validation_bypass`

The preflash failure branch is replaced in the LK:

```text
42 41 02 94 80 00 00 36
  -> 42 41 02 94 1f 20 03 d5
```

The string `Preflash validation failed` is at flat offset `0xd073f`; the caller
and branch are at `0x11cec` and `0x11cf0`.

### `vbmeta_device_state_locked`

This changes the LK's construction of the kernel command line so Android sees
`androidboot.vbmeta.device_state=locked`. The current builder expects exactly
one match in `lk`.

## The sboot patch was a trap

Cancunf's stock sboot global is `0x11` at `lk+0x12ee2c`, and the real getter
already treats `0x11` as enabled. The common fenrir pattern occurs twice per
partition here, not once. One occurrence is the getter; the other is a
certificate-processing routine that handles X.509 OIDs.

The original replacement also decodes to:

```text
eor w8, w2, #0x3ffff
```

`w2` is not initialized by this calling convention. The patched getter writes
garbage through its output pointer, and the certificate occurrence damages the
crypto path. Every tested image containing the sboot patch failed to boot.

The decision is simple: do not apply `spoof_sboot_state` to cancunf.

## Attestation boundary

The LK and `bl2_ext` seccfg routines write a lock-state shadow global, but the
only LK reader (`sec_query_device_lock`, at `0xc2fe4`) has no callers. There is
no LK SMC service forwarding that value to the TEE. The KeyMint RootOfTrust is
composed by a vendor Trustonic trustlet instead.

The trustlet was later located and its `is_locked()` function was pinned at
offset `0x19ec0`. A three-site trustlet patch is packaged in
`poc/cancunf-km-trustlet-patch-v2.zip`, but it has not been hardware-validated.
Kinibi trustlet signature enforcement is still an open question. See
[`TRUSTLET_PATCH.md`](TRUSTLET_PATCH.md).

## Still out of scope

- Payload stages. Garmr does not currently include a cancunf payload header.
- A tested permanent attestation fix. The trustlet patch is the next experiment,
  not a result.
- Portability to another firmware build. Recheck every pattern before using a
  different image.
