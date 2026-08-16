# Self-sign route

Replace Kinibi's MCLF trustlet-verification RSA key with our own, and re-sign

the patched KeyMint trustlet so Kinibi accepts it *without* touching the
verification logic.

## Status

| Piece | Status |
| --- | --- |
| cert bypass for tee.img | ✅ working (`poc/mtk_cert.py`, verified `VALID`) |
| key location | ❌ `0x88000` key does NOT verify the trustlet (see below) |
| key generation | ✅ `keygen.py` |
| key patching + tee.img re-sign | ✅ `patch_tee_key.py` |
| trustlet re-sign (format) | ✅ `sign_trustlet.py` (format-correct, round-trip verified) |
| trustlet re-sign (device-accepted) | ❌ blocked on unknown efuse key |

## ⚠️ Critical finding

The only RSA-2048 key in `tee.img` is at `0x88000` (tee.img `0xc5150`), but
computing `sig^e mod n` against the stock trustlet's 256-byte signature does
**not** yield PKCS#1 v1.5 or PSS for any plausible signed region or hash.
That means the real trustlet verification key is **not** the in-flash key — it
is most likely **efuse/hardware-backed** (read via the MTK crypto SMC path).

This is exactly the "device rejects the new key" scenario: patching the key in
flash will not help, because the verifier does not use that key. **The bypass
route is the viable one**; self-sign is a research fallback only if the efuse
key is ever recovered.

## Pipeline (format-correct, not device-accepted)

```bash
# 1. generate our RSA-2048 keypair
python3 selfsign/keygen.py --out selfsign

# 2. patch tee.img's verification key to ours + cert-bypass re-sign
python3 selfsign/patch_tee_key.py \
    --modulus selfsign/modulus.bin \
    --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
    -o selfsign/tee_selfsigned.img

# 3. re-sign the patched trustlet (format-correct; round-trip verified)
python3 selfsign/sign_trustlet.py \
    --key selfsign/key.pem \
    --trustlet poc/trustlet_patch/0706000000000000000000000000004d.tlbin \
    -o selfsign/trustlet_selfsigned.tlbin

# 4. flash tee_selfsigned.img + trustlet_selfsigned.tlbin (EXPECTED TO FAIL
#    unless the real verification key is known)
```

## MCLF trustlet signature format (determined)

MCLF v2.5: header `0x80` + text `0x3fac8` + data `0x8b0` = `0x403f8`, then a
395-byte signature block:

```text
[132-byte blob][03 00 00 00][01 00 01][256-byte RSA-2048 sig]
```

- signature = last 256 bytes (offset `0x40483`);
- `03 00 00 00` = sig type 3 (RSA), `01 00 01` = exponent 65537;
- 132-byte blob purpose still unknown (not a hash of any region, not DER).

