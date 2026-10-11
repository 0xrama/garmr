# Kinibi MCLF verification: candidate key and unresolved provenance

The trustlet verification key has **not been located**. Efuse/hardware backing
is a hypothesis, not a result. Failure of the candidate calculation below does
not exclude runtime-loaded keys, other images, key hierarchies, alternative
trailer encodings or a different signing algorithm/region.

## 20-5-12 layout and evidence

`tee.img` is 816160 bytes, with signed `atf` and `tee` components:

| part | data offset | size |
| --- | ---: | ---: |
| `atf` | `0x200` | 245368 |
| `tee` (Kinibi) | `0x3d150` | 562176 |

Kinibi file offset `X` corresponds to runtime `0x08000000 + X` and container
offset `0x3d150 + X`; header `maddr=0x08000240` points to code at file `0x240`.
The MCLF parser is at `0x5c738`; the loader is at `0x5eac4..0x5ef98`.

A candidate RSA-2048 modulus is at Kinibi `0x88000` (container `0xc5150`),
with exponent 65537 at `0x88100`. For the stock trustlet's final 256 bytes,
`pow(sig, 65537, n)` with this big-endian modulus starts `2d33` and ends `20`.
This is inconsistent with conventional PKCS#1 v1.5/PSS for that interpretation.
It does not prove that no verification key exists in flash. Searches for
recognized SHA constants/inline RSA do not prove a particular hardware path.
Recovering a public key would not supply the private key needed to sign.

## Observed trustlet trailer

`0706000000000000000000000000004d.tlbin` is `0x40583` bytes (MCLF v2.5):

| region | offset | size |
| --- | ---: | ---: |
| header | `0` | `0x80` |
| text | `0x80` | `0x3fac8` |
| data | `0x3fb48` | `0x8b0` |
| trailer | `0x403f8` | `0x18b` |

Trailer: `[132-byte blob][03 00 00 00][01 00 01][256-byte candidate RSA signature]`.
The final 256 bytes start at `0x40483`. Type-3/RSA and exponent interpretations
are candidates; the 132-byte blob and actual authenticated region remain unknown.
`selfsign/` implements a candidate scheme, not a stock-validated accepted format.
Self-sign failure can have many causes and cannot confirm efuse provenance.

## Dispatcher and two consumer sites

Wrappers at `0x65b60` (cmd `0xad`), `0x65c88` (`0xac`), `0x65ae0` (`0x32`)
and `0x65cc8` (`0xa9`) call through `[0x54000+0x8c]` (runtime `0x0854008c`),
zero on disk. Its initializer, handler implementation, key selection and return
semantics remain unresolved. Neither ATF handoff, preloader PIC copy nor runtime
driver registration is established as its provenance.

`analysis/find_handler3.py` reports 34 dispatch-page accesses in Kinibi, all
reads, and no detected ATF code references. This linear register-tracking sweep
is heuristic, not exhaustive control/data-flow proof; indirect writers may be
missed. The older 23 ATF raw-literal matches were unaligned-scan noise and do
not support an ATF initializer claim.

The original single-site candidate was incomplete: `bypass/patch_verify.py`
changes **two** anchored `cbz` consumers after cmd `0xad`, at `0x5ebf0` and
`0x5eca4`, in both builds. Cmd `0xad` is a presumed verification/status step;
its signature-specific semantics are not proved by wrapper annotation.
Consumer patches do not make handler provenance moot: authentication may
have other checks or side effects. See [bypass evidence](../bypass/README.md).
