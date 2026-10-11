# Experimental self-sign route

This pipeline replaces a candidate in-flash RSA modulus and signs a patched
trustlet under a newly generated key. It does **not** establish that Kinibi uses
that key or accepts the signing scheme. No hardware acceptance is demonstrated.

The candidate modulus at Kinibi `0x88000` (20-5-12 tee.img `0xc5150`) fails
the conventional stock-signature interpretation: the RSA encoded message starts
`2d33` and ends `20`, not conventional PKCS#1 v1.5/PSS. This narrows one
key/signature interpretation only. Efuse/hardware provenance remains a
hypothesis; other images, runtime keys and encodings are unexcluded. Obtaining
a public verification key would not provide the private signing key.

## Pipeline (candidate format, not device authorization)

Requires Python 3, OpenSSL for key generation, and `cryptography` for signing; native MTK
container certificate operations use the standard library. Use matching firmware
and preserve stock images and a recovery path before any hardware experiment.

```bash
python3 selfsign/keygen.py --out selfsign
python3 selfsign/patch_tee_key.py \
    --modulus selfsign/modulus.bin \
    --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
    -o selfsign/tee_selfsigned.img
python3 selfsign/sign_trustlet.py \
    --key selfsign/key.pem \
    --trustlet poc/trustlet_patch/0706000000000000000000000000004d.tlbin \
    -o selfsign/trustlet_selfsigned.tlbin
python3 poc/mtk_cert.py verify selfsign/tee_selfsigned.img --all
```

`VALID` means internal container certificate/hash consistency, not hardware
trust anchoring or accepted MCLF signing. The signer verifies its newly generated
signature with the supplied public key before writing; that round trip validates
only the chosen candidate scheme, not the actual accepted trustlet format.
There is no stock-signature validation establishing the scheme or signed region.

## Observed trailer, unresolved semantics

MCLF v2.5: `0x80` header + `0x3fac8` text + `0x8b0` data = `0x403f8`, then:

```text
[132-byte blob][03 00 00 00][01 00 01][256-byte candidate RSA signature]
```

The final 256 bytes start at `0x40483`. Type 3/RSA and exponent 65537 are
candidate interpretations; the blob and authenticated region are unknown.
The signer retains or zeroes this blob without establishing its meaning.

Failure on hardware could reflect wrong metadata, signed region, algorithm,
key selection, mounting/session state or other enforcement. It cannot prove
efuses or that the key is absent from flash. See
[candidate-key evidence](../notes/KINIBI_MCLF_KEY.md) and
[testing guide](../notes/TESTING_GUIDE.md).
