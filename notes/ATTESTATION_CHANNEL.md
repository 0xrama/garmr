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

> **Updated (offline re-analysis, Oct 2026):** the source of `is_locked()`'s
> global is now pinned. It is **not** the TCI and **not** the ATF ROT
> mailbox — see the "Where the lock byte really comes from" section below.
> The practical consequence: no LK-side spoof can reach it, and the trustlet
> patch is the correct (and necessary) layer.

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

## 6. Where the lock byte really comes from (Oct 2026)

`analysis/trace_rot_input.py` / `trace_rot_input2.py` sweep the whole
trustlet for accesses to the `0x73000` page. `[0x73000+8]` — the
`is_locked()` global — has exactly two writers:

1. **Reset** (`0x19c9c`): `str wzr` — a clear-state path that also closes the
   cached session at `[0x72000+0xff8]`.
2. **Load** (`0x19fa4`, inside the function at `0x19ed8`):
   opens a storage session (`bl 0x13200`), **reads a 4-byte value through
   the storage API (`bl 0x1d980`)** into `[sp+0x40]`, caches the session,
   then stores `(u64)value / 9` (magic `0xE38E38E38E38E38F`, `umulh`+`lsr #5`)
   into `[0x73000+8]`.

So the bootloader-lock input to attestation is a **persisted trustlet
storage value** (Kinibi secure storage, session-cached), decoded from an
encoded integer. Consequences:

- The **ATF ROT-mailbox SMCs are not the source** — an LK-side spoof of the
  `MTK_SIP_LK_ROOT_OF_TRUST` handoff cannot change attestation. That
  shortcut is disproved; the three-site trustlet patch remains the layer to
  patch.
- The second device-locked selector at `0x1cd5c` reads `ldrb w0, [sp,#0x2c8]`
  (HAL-supplied TCI byte), consistent with the original findings: one
  secure-side gate (`is_locked`), one REE-fed gate.
- Callers of the loader function: `0x1a0d0`, `0x1a19c`, `0x1a77c` (init /
  provisioning paths).

For the 20-5-14 trustlet the same layout holds: the writer, the reset, the
selection tree at `0x1cc00..0x1cd9c`, and the string table are byte-identical;
the two rebuilt regions (`0x1a848..0x1bad5`, `0x33417..0x34c0e`) sit in bulk
code away from every pinned site (`analysis/diff_trustlet_fns2.py`; the old
region-A profile — 8 string-emitter calls, RoT-struct references, 2 storage
opens — marks it as certificate-assembly code, and value *selection* happens
in the unchanged region).

