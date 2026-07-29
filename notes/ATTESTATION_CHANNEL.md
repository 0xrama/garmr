# Where cancunf's attestation state comes from

This investigation started with a simple question: why does Garmr make Android
say “green” and “locked” while Play Integrity still says the bootloader is
unlocked?

The answer is that cancunf does not use the LK lock-state path that fenrir uses
on some other devices. The LK patch controls normal-world boot reporting. The
KeyMint trustlet has its own state inputs.

## Short version

- `lk` and `bl2_ext` contain seccfg readers, but their lock-state result is not
  forwarded to the TEE.
- `tee.img` contains ATF and Kinibi, not the actual KeyMint attestation logic.
- The RootOfTrust fields are composed by a vendor Trustonic trustlet.
- That trustlet was found at:

```text
/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin
```

- Its `is_locked()` function is at trustlet offset `0x19ec0`.
- A three-site patch exists, but has not been tested on a phone yet.

## 1. What we checked in LK

In the `lk` partition, `sec_get_seccfg` (`FUN_000c2cec`) reads the 64-byte
`sec_update` partition and stores the fields in a shadow structure around
`0x209e40`. The lock word is at raw seccfg offset `0x0c`.

`sec_query_device_lock` (`FUN_000c2fe4`) is the only function that reads that
word. Ghidra finds no callers for it. A sweep for function pointers and dispatch
tables found no indirect reference either.

`bl2_ext` has the same shape: it writes its own shadow state and never reads the
lock word in a live path. The SMC calls in LK are power/RTC calls; none is a
lock-state service.

That makes the original `spoof_lock_state` patch a byte-valid patch to dead code
for this particular attestation question. It is not the source of the
certificate's `deviceLocked` value.

## 2. What we checked in `tee.img`

For firmware `V1TDS35H.83-20-5-12`, the image contains:

| Area | Contents |
| --- | --- |
| `atf` | ARM TF-A runtime, resident at `0x48200000` |
| `cert1`, `cert2` | Image certificates |
| `tee` | Trustonic Kinibi core |

ATF exposes MTK services for storage, MPU/DAPC, crypto, random data, and two
root-of-trust mailbox calls:

```text
MTK_SIP_GET_ROOT_OF_TRUST  0x82000020 / 0xc2000020
MTK_SIP_LK_ROOT_OF_TRUST   0x82000120 / 0xc2000120
```

LK calls the second service five times to pass Motorola `utag` data and
UFS/RPMB geometry into the secure side. That is the storage handoff. It is not
the code that builds the KeyMint certificate.

There are no useful `keymaster`, `deviceLocked`, `verifiedBoot*`, or
`RootOfTrust` strings in the Kinibi image. The actual KeyMint logic is loaded
from the vendor trustlet directory.

The relevant analysis helpers are:

```text
analysis/trace_lockstate.py
analysis/map_smc.py
analysis/trace_atf_rot.py
analysis/dump_fns.py
```

## 3. The trustlet patch point

The vendor trustlet is a 263 KB ARM64 MCLF binary. At offset `0x19ec0` it has:

```asm
adrp x0, #0x73000
ldr  w0, [x0, #8]
cmp  w0, #0
cset w0, ne
ret
```

This is `is_locked()`. On the unlocked phone the global is zero, so the
function returns false and the attestation path selects `open`/`unlocked`.

The trustlet also contains these strings:

```text
red       bootState 3+
orange    bootState 2
yellow    bootState 1
green     bootState 0
locked    is_locked() == 1
open      is_locked() == 0
unlocked  second deviceLocked check == 0
```

The green boot-state value already comes from the Garmr LK patch. The HAL reads
`ro.boot.verifiedbootstate=green` and supplies bootState zero to the trustlet.

There are two device-locked checks in the attestation routine:

1. At `0x1cc44`, a call to `is_locked()` selects `locked` or `open`.
2. At `0x1cd5c`, a byte from the HAL-supplied TCI selects `locked` or
   `unlocked`.

The first one was the confirmed blocker. The current trustlet package forces
both paths to the locked value and forces the related boot-state field green.
Details and exact bytes are in [`TRUSTLET_PATCH.md`](TRUSTLET_PATCH.md).

## 4. What this means for Garmr

Garmr can control:

- the LK container's internal verification policy;
- LK's boot-state global;
- AVB error handling and fastboot gates;
- the `ro.boot.*` values passed to Linux and Android.

Garmr LK patches cannot directly change a value that is computed inside the
vendor KeyMint trustlet. The trustlet is the cancunf equivalent of the deeper
attestation patch point used by fenrir on devices whose TEE consumes LK state.

There are two practical ways forward:

### Trustlet route

Patch the vendor trustlet and, if necessary, patch Kinibi's MCLF authentication
check. In Garmr mode the downstream image is already outside the original
verification chain, but the trustlet loader can still enforce its own signature
rules. That behavior has not been tested yet.

### TrickyStore route

Use TrickyStore with a valid keybox at the Android KeyMint layer. This avoids
firmware changes and is the practical daily-driver option, although keyboxes
can be revoked and replaced.

## 5. Useful next dumps

For the trustlet route, the most useful evidence is:

1. A full attestation certificate from the seven-patch LK build, including
   `verifiedBootKey`, `verifiedBootState`, `vbmetaDigest`, and `deviceLocked`.
2. The exact vendor trustlet from the same firmware build.
3. `gz.img`, to rule out a GZ/RKP KeyMint implementation.
4. `preloader.img`, if the preloader-side verification path needs to be mapped.
5. Logs from the Trustonic/MobiCore loader showing whether the patched MCLF is
   accepted or rejected.

On a rooted phone, the trustlet location and loader messages can be checked with:

```bash
su -c 'ls -la /vendor/app/mcRegistry /vendor/tee /vendor/firmware 2>/dev/null'
logcat -d | grep -i -E 'trustonic|keymaster|kmta|mobicore'
```
