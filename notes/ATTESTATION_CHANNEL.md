# Where cancunf's attestation state comes from

This investigation started with a simple question: why does Garmr make Android
say “green” and “locked” while Play Integrity still says the bootloader is
unlocked?

The working explanation is that the identified LK lock-state wrapper is not
the relevant attestation source. LK controls normal-world reporting; the
KeyMint trustlet has separate observed selectors. Historical hardware outcomes
are reported, not independently captured here; full HAL/serializer provenance
and signed before/after certificates remain missing.

## Short version

- `lk` and `bl2_ext` contain seccfg readers, but no forwarding path from the
  identified lock-state result to the TEE was found.
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

`bl2_ext` has a similar shadow state with no live reader identified. The
mapped LK SMC calls are power/RTC calls, not an identified lock-state service.
Static searches do not exclude all indirect/runtime paths.

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

> **Offline re-analysis, Oct 2026:** a storage-load path into `is_locked()`'s
> global was identified. This does not trace upstream producers or exclude
> mailbox influence on persisted state. See the storage section below.

The vendor trustlet is a 263 KB ARM64 MCLF binary. At offset `0x19ec0` it has:

```asm
adrp x0, #0x73000
ldr  w0, [x0, #8]
cmp  w0, #0
cset w0, ne
ret
```

This is the function called `is_locked()` here. A zero global returns false
and selects `open`; the actual runtime value needs captured evidence.

The trustlet also contains these strings:

```text
red       bootState 3+
orange    bootState 2
yellow    bootState 1
green     bootState 0
locked    is_locked() == 1
open      is_locked() == 0
unlocked  stack-byte selector == 0 (standard field mapping unresolved)
```

LK reports green through the boot properties. HAL propagation of that property
as trustlet bootState zero is a hypothesis requiring a matching HAL trace.

There are two candidate lock-related selectors in the apparent attestation routine:

1. At `0x1cc44`, a call to `is_locked()` selects `locked` or `open`.
2. At `0x1cd5c`, a stack byte selects `locked` or `unlocked`; HAL/TCI origin
   is not established by that load alone.

Standard RootOfTrust has one `deviceLocked` member. These string selectors
must be traced into serialization before assigning standard field semantics.
The current package changes three candidate state-selection sites; effects
on signed certificates and integrity verdicts are not established.
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

## 6. Observed storage-load path (Oct 2026)

`analysis/trace_rot_input.py` / `trace_rot_input2.py` sweep the whole
trustlet for accesses to the `0x73000` page. `[0x73000+8]` — the
`is_locked()` global — has two detected writers in these heuristic sweeps:

1. **Reset** (`0x19c9c`): `str wzr` — a clear-state path that also closes the
   cached session at `[0x72000+0xff8]`.
2. **Load** (`0x19fa4`, inside the function at `0x19ed8`):
   opens a storage session (`bl 0x13200`), **reads a 4-byte value through
   the storage API (`bl 0x1d980`)** into `[sp+0x40]`, caches the session,
   then stores a decoded value into `[0x73000+8]`. The described magic
   `0xE38E38E38E38E38F`, `umulh` + `lsr #5` implements unsigned division
   by **36**, not 9 (inputs 9, 36, 72 yield 0, 1, 2). A Capstone rerun
   confirmed the constant construction at `0x19f84..0x19f98`, followed by
   `umulh x1,x1,x3` at `0x19f9c` and `lsr x1,x1,#5` at `0x19fa0`.
   This establishes the local arithmetic, not the upstream value's meaning.

This supports a persisted/session-cached storage input, not a complete causal
trace of bootloader state. Producers and update paths remain unresolved:

- No direct mailbox-to-global path was identified. Storage reads do not
  exclude upstream influence via `MTK_SIP_LK_ROOT_OF_TRUST` or other paths.
- The second device-locked selector at `0x1cd5c` reads `ldrb w0, [sp,#0x2c8]`
  (origin unresolved), alongside the global-fed `is_locked` selector.
- Callers of the loader function: `0x1a0d0`, `0x1a19c`, `0x1a77c` (init /
  provisioning paths).

Linear sweeps and register tracking are heuristic, not exhaustive proofs of
all writers or runtime data flow.

For the 20-5-14 trustlet the same observed layout holds: the writer, the reset, the
selection tree at `0x1cc00..0x1cd9c`, and the string table are byte-identical;
the two rebuilt regions (`0x1a848..0x1bad5`, `0x33417..0x34c0e`) sit in bulk
code away from every pinned site (`analysis/diff_trustlet_fns2.py`; the old
region-A profile — 8 string-emitter calls, RoT-struct references, 2 storage
opens — marks it as certificate-assembly code, and value *selection* happens
in the unchanged region).
