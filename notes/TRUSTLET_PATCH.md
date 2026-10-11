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

The function reads one global u32 and returns whether it is nonzero. A zero
value selects `open`; a captured runtime value and signed certificate trace
are still needed to establish actual device behavior.

The replacement is eight bytes of ARM64:

```text
C0 02 00 D0 00 08 40 B9
  -> 20 00 80 D2 C0 03 5F D6
```

That changes the function to `mov x0,#1; ret` (also sets w0 to 1).

## The other two candidate selectors

The trustlet has two related device-state checks:

- `0x1cc44` calls `is_locked()` for the `locked`/`open` bootloader-state field.
- `0x1cd5c` reads a stack byte selecting `locked`/`unlocked`; HAL/TCI origin
  remains a hypothesis, not a fact established by the load.

The current v2 binary patches all three relevant sites: `is_locked()`, the
boot-state stack word at `0x1cbbc` (`ldr w0,[sp,#0x2c4]` replaced by
`mov w0,#0`), and the second lock-related selector. Standard
RootOfTrust has one `deviceLocked` field; mapping these selectors into signed
fields requires serializer tracing. LK reports `ro.boot.verifiedbootstate=green`,
but matching HAL propagation to this trustlet remains unvalidated.

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

The current three-site package is:

```text
poc/cancunf-km-trustlet-patch-v2.zip
```

It is packaged as a Magisk/KernelSU-style module with the same patched 12
binary and updated scripts. They validate matching firmware and mounted
contents and log restart **requests** for discovered running init services to
`module.log` in the installed module directory. A successful request is not
proof of a restart or a fresh secure-world session loading/executing the file.
The guard requires the vendor fingerprint to contain the exact build ID and
the stock/patched trustlet SHA-256 to match; absent evidence causes refusal.

## What has not been proven

The module has not been validated on hardware. In particular:

1. Kinibi may check the MCLF signature before loading the trustlet. If it does,
   the patched binary will be rejected and KeyMint may fail to start.
2. The second device-state input needs to be confirmed from a full certificate.
3. Full chain trust, `verifiedBootKey`, vbmeta digest, provisioning, revocation,
   freshness and verifier policy remain to be checked. Locked/green fields
   alone cannot guarantee DEVICE/STRONG.
4. The trustlet must match the firmware build. Do not reuse this binary on a
   different vendor image.

The next useful test is a rooted boot with a recovery path, followed by a full
Key Attestation dump and the Trustonic loader log. A successful bind mount alone
is not enough; the certificate fields are the result that matters.

## 20-5-14 status

The `V1TDS35H.83-20-5-14` trustlet was carved from the new EROFS vendor image
(see `notes/STATUS.md` for the extraction path). It is the same size and 95%
byte-identical to the 20-5-12 binary; only two functions, a build-time string,
and the signature block changed. All three patch offsets above are unchanged,
so the v2 sites carry over directly:

```text
poc/trustlet_patch/stock_trustlet_20_5_14.tlbin                            carved stock
poc/trustlet_patch/0706000000000000000000000004d_20_5_14.tlbin             3-site patched
```

The v2 Magisk/KernelSU package itself is still built around the 20-5-12
binary and now deliberately refuses 20-5-14. Simply replacing its binary will
not pass the firmware/hash guards. The separate `_20_5_14` binary remains an
offline research artifact, not a supported module package.
All hardware/attestation caveats above still apply unchanged.
