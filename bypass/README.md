# Bypass route (recommended)

Force Kinibi's MCLF trustlet signature-verification gates to "success" by
patching the loader's result checks, leaving the key and the verify call
itself untouched. This is the primary route because the self-sign
investigation proved the trustlet verification key is **not** in flash
(likely efuse/hardware via MTK crypto SMC).

## Status

| Piece | Status |
| --- | --- |
| cert bypass for tee.img (both builds) | ✅ working (`poc/mtk_cert.py`, `VALID` on 12 and 14) |
| MCLF parser / loader / dispatch | ✅ mapped (high confidence) |
| verify-result branches | ✅ **pinned: two gates, disassembly-proven** (was: single best-guess) |
| artifacts | ✅ `tee_bypassed_20_5_12.img`, `tee_bypassed_20_5_14.img` |
| hardware validation | ⬜ not yet flashed |

## What the loader actually does (evidence)

`analysis/annotate_loader.py` disassembles the MCLF loader
(`kinibi 0x5eac4..0x5ef98`) with every driver-wrapper call annotated by its
command id. The load sequence is:

```text
cmd 0xa9   open handle
cmd 0xac   read properties/size
cmd 0xad   VERDICT -> gate 1 @0x5ebf0 (cbz w0,#0x5ecc4)
cmd 0x32   read 0x30-byte header
   ...     segment setup
cmd 0xad   VERDICT -> gate 2 @0x5eca4 (cbz w0,#0x5ed40)
cmd 0x32   read the full trustlet image
   ...     map segments, install
```

Findings that shaped the patch:

1. **cmd `0xad` is the verify verdict** (open question #2 from
   `notes/KINIBI_MCLF_KEY.md`), checked at **two** sites. The old single-site
   patch at `0x5ebf0` alone would leave the second gate live.
2. Do **not** neutralize the `0xad` wrapper (`0x65b60`): the code after each
   gate consumes outputs produced around the verdict, and skipping the call
   leaves them zero (the load would abort with `-0xfffb`).
3. The failure path already tolerates the special code `0xf0100001`
   ("already verified/loaded"-style), which is consistent with `0xad` being
   a pure verdict gate.
4. The `20-5-14` Kinibi core is 99% byte-identical to `20-5-12`, and both
   gate windows are byte-identical — the same offsets apply to both builds.
   The 20-5-14 `tee.img` container also passes the full CERT1/CERT2
   verification (`analysis/check_tee_14.py`), so the cert bypass re-applies.

## Patch

Both gates force the success branch (`cbz` -> unconditional `b`); each is
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

Then flash the bypassed `tee.img` together with the Garmr LK artifact, and
install the patched trustlet from `poc/trustlet_patch/` (use the
`_20_5_14` binary on the 14 build) at
`/vendor/app/mcRegistry/0706000000000000000000000000004d.tlbin`.

## Resolved and mooted unknowns

- ~~Who initializes `[0x54000+0x8c]`~~ — a full disassembly sweep
  (`analysis/find_handler3.py`) found **34 accesses** to the dispatch page in
  Kinibi, **all reads**, and **zero** code references in ATF. The earlier
  "ATF data literal" theory was unaligned-scan noise (`find_handler2.py`);
  `adrp` targets are not raw literals. The pointer is written indirectly at
  runtime (driver registration), but its provenance is now **moot**: the
  patch targets the consumer branches in the loader, not the handler.
- ~~Which cmd id returns the verify result~~ — `0xad`, at two gates (above).

## Remaining unknowns

1. Hardware behavior: whether forcing both gates is sufficient for a patched
   trustlet to load and run (watch `logcat -d | grep -iE 'mobicore|trustonic|kmta'`).
2. Whether anything *inside* the 0xad flow is needed beyond the verdict
   (the annotated flow suggests not: all data reads go through 0xac/0x32).
