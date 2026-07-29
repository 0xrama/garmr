# Trustonic KeyMint trustlet patch

This is the current attestation experiment for Garmr. It is not a claim that
Strong Integrity already works.

**Firmware:** `V1TDS35H.83-20-5-12 RETIN`

**Trustlet:**

```text
0706000000000000000000000000004d.tlbin
/vendor/app/mcRegistry/
```

The binary is an ARM64 Trustonic MCLF trustlet, 263 KB in this build. It
composes the RootOfTrust-related strings used by the KeyMint attestation
certificate.

## Finding `is_locked()`

At trustlet offset `0x19ec0`:

```asm
0x19ec0: adrp x0, #0x73000
0x19ec4: ldr  w0, [x0, #8]
0x19ec8: cmp  w0, #0
0x19ecc: cset w0, ne
0x19ed0: ret
```

The function reads one global u32 and returns whether it is nonzero. On the
unlocked phone the value is zero, so this path selects `open` instead of
`locked` in the attestation data.

The replacement is eight bytes of ARM64:

```text
C0 02 00 D0 00 08 40 B9
  -> 20 00 80 D2 C0 03 5F D6
```

That changes the function to `mov w0,#1; ret`.

## The other two fields

The trustlet has two related device-state checks:

- `0x1cc44` calls `is_locked()` for the `locked`/`open` bootloader-state field.
- `0x1cd5c` reads the HAL-supplied device-state byte for the `locked`/`unlocked`
  field.

The current v2 binary patches all three relevant sites: `is_locked()`, the
bootloader-state path, and the second device-locked path. The green boot state
comes from Garmr's LK patch through `ro.boot.verifiedbootstate=green`.

The string table around trustlet offset `0x3b370` is useful when checking a
future build:

```text
0x3b370  red
0x3b378  orange
0x3b380  yellow
0x3b388  green
0x3b390  locked
0x3b398  open
0x3b3a0  unlocked
```

## Artifacts

The older single-site experiment is:

```text
poc/cancunf-km-islocked-patch.zip
```

The current three-site package is:

```text
poc/cancunf-km-trustlet-patch-v2.zip
```

It is packaged as a Magisk/KernelSU-style module. The scripts bind-mount the
patched trustlet over the stock path before restarting the Trustonic and
KeyMint services.

## What has not been proven

The module has not been validated on hardware. In particular:

1. Kinibi may check the MCLF signature before loading the trustlet. If it does,
   the patched binary will be rejected and KeyMint may fail to start.
2. The second device-state input needs to be confirmed from a full certificate.
3. `verifiedBootKey` and the vbmeta digest still need to be checked against
   the Strong Integrity requirements.
4. The trustlet must match the firmware build. Do not reuse this binary on a
   different vendor image.

The next useful test is a rooted boot with a recovery path, followed by a full
Key Attestation dump and the Trustonic loader log. A successful bind mount alone
is not enough; the certificate fields are the result that matters.
