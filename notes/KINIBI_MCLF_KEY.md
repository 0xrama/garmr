# Kinibi trustlet verification: key location (corrected)

Goal: determine whether the MCLF trustlet signature check uses a key stored in
**flash** (patchable `tee.img`) or **efuse/hardware** (not patchable).

**Result: the trustlet verification key is NOT the in-flash key — it is almost
certainly efuse/hardware-backed.** Self-signing by patching the flash key is
therefore expected to fail on hardware; the **bypass** route is the viable
one (`bypass/patch_verify.py`).

## tee.img layout

`tee.img` (816160 bytes) is a two-part MTK container:

| part | data offset | size | content |
| --- | ---: | ---: | --- |
| `atf` | `0x000200` | 245368 | ARM TF-A runtime (MTK SiP / crypto SMC services) |
| `tee` | `0x03d150` | 562176 | Trustonic Kinibi core (= `analysis/kinibi_core.bin`) |

Kinibi load base: file offset `X` = runtime `0x08000000 + X` (the `tee` part
header `maddr` is `0x08000240` for entry/code at file `0x240`). tee.img offset
for a kinibi file offset `X` = `0x3d150 + X`.

## MCLF verification surface (mapped)

- MCLF parser `0x5c738`: builds magic `0x464C434D` and compares the first word.
- Trustlet loader `0x5eac4..0x5ef98`: reads MCLF intro, calls parser, maps
  segments (`0x5c5b8`, `0x5c6cc`).
- Driver dispatch: wrappers `0x65b60` (cmd `0xad`), `0x65c88` (cmd `0xac`),
  `0x65ae0` (cmd `0x32`), etc. tail-call a runtime-initialized handler at BSS
  `[0x54000 + 0x8c]` (not statically pinned).
- No SHA-256 constants and no inline RSA in the image → hashing + RSA go
  through MTK hardware crypto (ATF SMC), using a key outside the flash image.

## The in-flash RSA key does NOT verify trustlets

A single RSA-2048 public key exists in the image: modulus @ kinibi `0x88000`
(tee.img `0xc5150`), exponent `0x10001` @ `0x88100`.

`pow(sig, 0x10001, n)` against the stock trustlet signature yields random bytes
(`em[0:2]=2d33`, `em[-1]=0x20`) — not PKCS#1 v1.5, not PSS — over every
plausible signed region, SHA-256/384/1, and modulus endianness. No other RSA
key exists in tee.img (ATF sweep included). So `0x88000` is **not** the
trustlet verifier; the real key is likely provisioned in efuse and used via
the MTK crypto SMC path.

## Trustlet signature layout (confirmed)

`0706000000000000000000000000004d.tlbin` (0x40583 bytes), MCLF v2.5:

| region | offset | size |
| --- | ---: | ---: |
| header | `0x00000` | `0x80` |
| text | `0x00080` | `0x3fac8` |
| data | `0x3fb48` | `0x8b0` |
| sig block | `0x403f8` | `0x18b` (395) |

Signature block = `[132-byte blob][03 00 00 00][01 00 01][256-byte RSA sig]`.
Signature = last 256 bytes (`0x40483`); `03 00 00 00` = type 3 (RSA);
`01 00 01` = exponent 65537. The 132-byte blob's purpose is unknown (not a
hash of any region, not DER).

## Conclusion and routes

- **Self-sign**: `selfsign/` is format-correct (round-trip verified) but will
  only produce a device-accepted trustlet if the efuse verification key is
  recovered. Not the practical path.
- **Bypass**: `bypass/` patches the loader's post-intro check of cmd `0xad` at
  `0x5ebf0` (`cbz` → `b`, tee.img `0x9bd40`). Medium confidence — the
  definitive branch is behind `[0x54000+0x8c]`.

## Final hop: who initializes [0x54000+0x8c]

> **Correction (offline re-analysis, Oct 2026):** the "23 references" to the
> Kinibi BSS page in the `atf` partition were **unaligned byte-scan noise** —
> `adrp` targets are encoded relative to PC and never appear as raw literals.
> A full capstone sweep with register tracking (`analysis/find_handler3.py`)
> found 34 accesses to the dispatch page inside Kinibi, **all reads**, and
> zero code references in ATF. The pointer is written indirectly at runtime
> (driver registration), so its static provenance stays unresolved.
>
> **This hop is now moot for the bypass.** `analysis/annotate_loader.py`
> mapped the whole MCLF loader with wrapper command ids: cmd `0xad` is the
> verify verdict, gated at exactly two `cbz` sites (`0x5ebf0`, `0x5eca4`),
> and `bypass/patch_verify.py` now patches both. See `bypass/README.md`.

Original investigation (superseded, kept for the record):

Traced (Kinibi side):

- `[0x54000+0x8c]` (runtime `0x0854008c`) is BSS in kinibi_core.bin (all zero
  on disk).
- The dispatch wrappers (`0x65b60` cmd `0xad`, `0x65c88` cmd `0xac`, `0x65ae0`
  cmd `0x32`, `0x65cc8` cmd `0xa9`, ...) all `ldr wN, [0x54000+0x8c]` then
  `blr xN`. So it is a 32-bit function pointer to a single handler/dispatcher.
- **Kinibi's own code never writes this pointer** — an exhaustive sweep of
  adrp/str/stp/movz/literal-pool accesses to page `0x54000` finds only reads,
  no writes. The write is therefore performed by the **ATF (secure monitor)**
  during the Kinibi boot handoff.
- Corroborating: the `atf` partition of tee.img references the Kinibi BSS page
  `0x08540000` 23 times (as 32-bit data literals in its boot descriptor
  tables), consistent with ATF initializing Kinibi's BSS structures before
  jumping to it.

Remaining (scoped, not completed): disassemble the `atf` partition (load base
~`0x48200000`) and find the store to `0x0854008c` to recover the handler
address, then disassemble that handler and locate its signature-failure
return. This is the only way to upgrade `0x5ebf0` from best-guess to a
100%-pinned branch.
