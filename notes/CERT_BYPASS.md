# The CERT2 hash-override cert bypass

This is the one piece of the `val-protocol` project that maps onto fenrir's
`CertBypass.OVERRIDE`, extracted into a self-contained, dependency-free module:
[`poc/mtk_cert.py`](../poc/mtk_cert.py). It has nothing to do with
val-protocol's unlock/FRP presets.

## What the exploit is

Every sub-image in a Motorola MTK LK container (`lk`, `bl2_ext`, `aee`,
`lk_main_dtb`) is followed by `cert1` + `cert2` part entries. `cert2` is an
X.509 certificate whose signed content embeds two MTK-specific OIDs:

```text
2.16.886.2454.2.4   image header hash   (SHA-256 / SHA-384)
2.16.886.2454.2.1   image hash          (SHA-256 / SHA-384)
```

After you patch a payload those hashes no longer match, and you cannot re-sign
`cert2` because you do not have the OEM RSA key. The bypass prepends a fresh
context-specific TLV before the original `cert2` DER:

```text
a0 58
  06 07 60 86 76 93 16 02 04      OID 2.16.886.2454.2.4
  03 21 00 <32-byte header hash>  BIT STRING
  06 07 60 86 76 93 16 02 01      OID 2.16.886.2454.2.1
  03 21 00 <32-byte image hash>   BIT STRING
<original 0x30 ... CERT2 SEQUENCE, untouched>
```

MTK libsec scans for the first occurrence of each hash OID and accepts the
prepended values. The original certificate and its RSA-PSS signatures are left
untouched, so the signature check still passes while the hash check now matches
the patched bytes. SHA-384 builds use a 48-byte BIT STRING (`03 31 00`).

This is exactly what fenrir's `CertBypass.OVERRIDE` does. `poc/mtk_cert.py`
reproduces it byte-for-byte: building with `poc/build_native_20_5_12.py`
produces an image identical to `poc/cancunf-fenrir-full-20-5-12.img`.

## What `--legacy` in val-protocol adds (and fenrir does not)

val-protocol's `tools/sign_mtk_cert.py --legacy` additionally wraps the original
`cert2` DER in a BIT STRING before the hash-override block, for "old libsec
`bypass_mode=1`" parsers. Garmr's cancunf build does not need it. Without
`--legacy`, that script is equivalent to `poc/mtk_cert.py` and to fenrir's
`OVERRIDE`.

## Files

- [`poc/mtk_cert.py`](../poc/mtk_cert.py) — `sign` (prepend CERT2 overrides)
  and `verify` (RSA-PSS + hash check) for a whole container. Stdlib only.
- [`poc/build_native_20_5_12.py`](../poc/build_native_20_5_12.py) — the seven
  pinned cancunf patches + native cert bypass. No fenrir, no liblk.

## Usage

```bash
# sign a patched container (overrides lk, bl2_ext, aee by default)
python3 poc/mtk_cert.py sign patched_lk.img -o signed_lk.img

# verify signatures + hashes across every signed sub-image
python3 poc/mtk_cert.py verify signed_lk.img --all

# full fenrir-free build of the seven-patch artifact
python3 poc/build_native_20_5_12.py
```

## Verification status

- `verify` reports `VALID` on the stock `V1TDS35H.83-20-5-12` image.
- `verify` reports `VALID` on `poc/cancunf-fenrir-full-20-5-12.img`.
- `poc/build_native_20_5_12.py` output is byte-identical to
  `poc/cancunf-fenrir-full-20-5-12.img` (`cmp` clean).

This is still an offline cert/hash result. A clean cert bypass is not a boot
test; flash only a matching firmware build on a sacrificial device with a
recovery path.
