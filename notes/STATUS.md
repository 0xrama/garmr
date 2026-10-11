# Garmr patch status

This is the working status for the Motorola `cancunf` port. It records what was
actually checked, what booted, and which ideas turned out to be wrong.

`Confirmed` means the pattern was found at the expected count, the replacement
landed in the intended partition, and the resulting LK image parsed again.
Hardware entries below are historical reports, not independently captured
evidence. The audit found no supporting adb property logs, signed before/after
attestation chains or Play Integrity response artifacts. Both LK artifacts
reproduce offline exactly; no new hardware test is claimed.

The current reference build is `V1TDS35H.83-20-5-12 RETIN` (Android 15). The
same patch neighborhoods were checked on 20-5-5 and 20-5-7; the later images
are mostly re-signed/re-versioned copies in the areas that matter here.

## Reported historical hardware trial

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

Build with `poc/build_native_20_5_12.py`; native14 uses shared native12
operations with build-specific overrides. `build_full_20_5_12.py` is a
deprecated compatibility entry. Check exact output with the stdlib
`poc/verify_poc.py --build 20-5-12 STOCK ARTIFACT` (default 12; 14 supported).
Builders verify before writing. Full parsing rejects truncation/trailing bytes;
signed inventories are LK `(lk, bl2_ext, aee, lk_main_dtb)` and TEE `(atf, tee)`.
Certificate checks prove internal consistency, not hardware authorization.
Offline CI runs `python3 -m unittest discover -s tests -v`, not device tests.

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

## 20-5-14 survey (October 2026)

`V1TDS35H.83-20-5-14 RETIN` (full extracted flash bundle, now under
`firmware/V1TDS35H.83-20-5-14/`) was checked against the seven-patch set with
`analysis/check_fw.py`, then the three missing sites were re-pinned with
`analysis/diff_sites.py`, `analysis/repin_20_5_14.py`, and
`analysis/confirm_repin.py` (capstone disassembly evidence).

**Motorola did not harden any of the seven sites.** The LK sub-image was
recompiled (it grew 0x1000 bytes and ~60% of bytes differ), which broke three
patterns purely through PC-relative immediates:

| Patch | What changed in 20-5-14 | New lk offset |
| --- | --- | --- |
| `sec_get_vfy_policy` | nothing (relocated) | `0xb660c` (was `0xb6424`) |
| `spoof_lock_state` | nothing (relocated) | `0xc336c` (was `0xc2de4`) |
| `force_green_state` | `adrp x8` page immediate `d0 -> f0`; the `str w0,[x8,#0x268]; ret` is untouched | `0x736ec` (unchanged) |
| `avb_allow_verification_error` | nothing at all | `0x73098` (unchanged) |
| `bypass_security_control` | callee moved `0xa2948 -> 0xa2b30`, so the `bl` immediate changed; the `tbz w0,#0` gate is byte-identical | `0x4d800` (unchanged) |
| `preflash_validation_bypass` | nothing at all | `0x11aec` (unchanged) |
| `vbmeta_device_state_locked` | `adrp x1` data page `0x107000 -> 0x108000`; the `csel x2,x10,x9` still selects between `locked`/`unlocked` at the same site | `0x7c1ec` (unchanged) |

The sboot-global anchor `lk+0x12ee2c = 0x11` is stale in 20-5-14 (the data
section moved); the getter neighborhood still occurs twice. Informational
only, since `spoof_sboot_state` remains deliberately omitted.

The CERT2 hash-override preconditions fully hold: all four signed sub-images
(`lk`, `bl2_ext`, `aee`, `lk_main_dtb`) pass `poc/mtk_cert.py` verification,
so the cert bypass re-applies unchanged.

The rebuilt artifact is:

```text
poc/cancunf-native-full-20-5-14.img
```

built by `poc/build_native_20_5_14.py` (same seven patches, three re-pinned
patterns, native cert bypass, self-verifying). It parses, patches, and signs
cleanly, but — like the trustlet package — has not been hardware-validated
yet. Treat `notes/TESTING_GUIDE.md` as mandatory reading before flashing it.

### Trustlet in 20-5-14

The 20-5-14 vendor image moved to **EROFS with LZ4 compact indexes and a
64 KB cross-cluster window** (`h_advise = COMPACTED_2B`,
`feature_incompat = LZ4_0PADDING`), so the raw needle scans that worked for
the 20-5-12 tree find nothing. The trustlet was carved with
`analysis/extract_trustlet_14.py` / `analysis/erofs_compact.py`. Extraction
cannot currently be replayed from supplied inputs: matching super sparsechunks
are absent. The extraction entry now delegates to the build/inode-specific
compact decoder instead of the incompatible old EROFS data reader. Missing
inputs and short extraction results fail without writing a trustlet. Full
extraction correctness has not been retested. Capstone is required for
disassembly; older analysis uses liblk; signing uses cryptography and key
generation uses OpenSSL.

The result (`poc/trustlet_patch/stock_trustlet_20_5_14.tlbin`) is 263,555
bytes — the same size as 20-5-12 — and 95% byte-identical. The differences
are two rebuilt functions (`0x1a848` and `0x33417` regions), a build-time
string (`5:24:46` -> `6:14:11` at `0x3ae09`), and the re-signed MCLF tail.
All three v2 patch sites are byte-identical:

| Site | Offset | Status |
| --- | --- | --- |
| `is_locked()` | `0x19ec0` | unchanged |
| boot-state selector (stack word) | `0x1cbbc` | unchanged |
| device-locked path | `0x1cd5c` | unchanged |

A 20-5-14 patched binary was generated the same way as v2
(`poc/trustlet_patch/0706000000000000000000000000004d_20_5_14.tlbin`,
sha256 `7626f446f501826bce37545a38e09b55d77f20c2d5a265b1b3b2d05ba20c62b7`).
The Kinibi signature question from `TRUSTLET_PATCH.md` is still open, and
nothing here has been hardware-validated.

### TEE side in 20-5-14

The 20-5-14 `tee.img` passes the full CERT1/CERT2 verification
(`analysis/check_tee_14.py`), and its Kinibi core is 99% byte-identical to
20-5-12 — both cmd `0xad` status consumers are byte-identical at the same offsets.
Signature-specific semantics and dispatcher provenance remain unresolved. The
two-gate bypass is built for both builds:

```text
bypass/tee_bypassed_20_5_12.img
bypass/tee_bypassed_20_5_14.img
```

See `bypass/README.md` for the loader-flow evidence.

Upstream context (checked October 2026): fenrir was archived by its author on
2026-09-20; its final releases (Nothing Phone 2a/2a+, NothingOS 4) document an
OEM that *did* patch the weakness at the preloader stage. The ARMv8 successor
is `sprig` (an EL3 `bl2_ext` replacement payload that disables SBC/SLA/DAA in
the Preloader for unsigned-DA flashing, not boot-state spoofing), and
`lkpatcher` is the maintained generic fenrir-style patcher. `kaeru`'s
`fastboot oem bldr_spoof` route to Strong Integrity is ARMv7-only. No public
cancunf-specific PoC newer than this repo's method exists.
