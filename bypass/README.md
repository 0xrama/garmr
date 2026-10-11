# Experimental two-consumer bypass

Force two Kinibi loader status consumers down their zero-status branches,
leaving cmd `0xad` calls intact. Signature-verification semantics are inferred,
not established: the dispatcher and actual key provenance remain unresolved.
The self-sign calculation excludes one candidate interpretation, not all
in-flash keys; efuse/hardware backing remains a hypothesis.

## Status

| Piece | Status |
| --- | --- |
| cert bypass for tee.img (both builds) | Offline internal signature/hash consistency (`VALID`), not hardware authorization |
| MCLF parser / loader / wrappers | Statically mapped; runtime dispatcher unresolved |
| status consumer branches | Two anchored sites reproduced; signature-specific meaning unproved |
| artifacts | ✅ `tee_bypassed_20_5_12.img`, `tee_bypassed_20_5_14.img` |
| hardware validation | ⬜ not yet flashed |

## What the loader actually does (evidence)

`analysis/annotate_loader.py` disassembles the MCLF loader
(`kinibi 0x5eac4..0x5ef98`) with every driver-wrapper call annotated by its
command id. The load sequence is:

```text
cmd 0xa9   open handle
cmd 0xac   read properties/size
cmd 0xad   presumed status/verification step -> gate 1 @0x5ebf0 (cbz w0,#0x5ecc4)
cmd 0x32   read 0x30-byte header
   ...     segment setup
cmd 0xad   presumed status/verification step -> gate 2 @0x5eca4 (cbz w0,#0x5ed40)
cmd 0x32   read the full trustlet image
   ...     map segments, install
```

Findings that shaped the patch:

1. Cmd `0xad` has status consumers at **two** sites. Wrapper annotation does
   not establish its cryptographic implementation or return semantics. The old single-site
   patch at `0x5ebf0` alone would leave the second gate live.
2. Do **not** neutralize the `0xad` wrapper (`0x65b60`): the code after each
   gate appears to consume outputs produced around the call. Skipping it may
   break loading; its outputs and side effects require runtime confirmation.
3. The failure path already tolerates the special code `0xf0100001`
   (meaning unknown). An "already verified/loaded" interpretation is only a
   hypothesis, not proof of a pure verdict gate.
4. The `20-5-14` Kinibi core is 99% byte-identical to `20-5-12`, and both
   gate windows are byte-identical — the same offsets apply to both builds.
   The 20-5-14 `tee.img` container also passes the full CERT1/CERT2
   verification (`analysis/check_tee_14.py`), so the cert bypass re-applies.

## Patch

Both consumers force the zero-status branch (`cbz` -> unconditional `b`); each is
pinned by a unique `bl`-preamble anchor:

```text
gate 1  kinibi 0x5ebf0:  de 1b 00 94 f3 03 00 2a | a0 06 00 34 -> 35 00 00 14   (b #0x5ecc4)
gate 2  kinibi 0x5eca4:  b0 1b 00 94             | e0 04 00 34 -> 27 00 00 14   (b #0x5ed40)
```

The bare `cbz` bytes are not unique in the image (3 occurrences for gate 1);
the script aborts unless the full anchor matches exactly once.

## Pipeline

```bash
python3 bypass/patch_verify.py \
    --tee-img firmware/V1TDS35H.83-20-5-14/tee.img \
    -o bypass/tee_bypassed_20_5_14.img
```

Before any hardware experiment, follow `notes/TESTING_GUIDE.md`, with stock
backups and a tested recovery path; change one layer at a time. Use the
matching patched trustlet from `poc/trustlet_patch/` (use the
`_20_5_14` binary on the 14 build) at
`/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin`.

## Unresolved dispatcher provenance

`analysis/find_handler3.py` reports 34 dispatch-page accesses in Kinibi, all
reads, and no detected ATF code references. This linear register-tracking sweep
is heuristic, not exhaustive control/data-flow proof. The earlier ATF literal
theory was unaligned-scan noise; ATF handoff, preloader copy and runtime driver
registration remain unproved initializer theories. The handler behind
`[0x54000+0x8c]` is unresolved, not moot: it could enforce authentication or
produce security-relevant side effects beyond these consumers.

## Remaining unknowns

1. Hardware behavior: whether forcing both gates is sufficient for a patched
   trustlet to load and run (watch `logcat -d | grep -iE 'mobicore|trustonic|kmta'`).
2. The cmd `0xad` implementation, key selection, return meanings and any
   additional enforcement. A locally consistent container cannot answer these.

Python 3 stdlib suffices for patching/container checks; reproducing annotated
disassembly requires Capstone. No modified-trustlet execution or DEVICE/STRONG
result is demonstrated by these artifacts.
