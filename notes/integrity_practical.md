# Play Integrity on an unlocked cancunf

The short version: historical reports say Garmr changes bootloader-facing
properties but reaches BASIC only. Supporting captured hardware artifacts were
not found in the audit; no new hardware result or DEVICE/STRONG solution is
claimed here. If the immediate goal is a daily driver with
banking and Play Integrity-dependent apps, the software route is less risky.

## Track A: TrickyStore and a keybox

This does not require the Garmr boot-chain patch. It requires root:

- Magisk or KernelSU
- TrickyStore
- a working `keybox.xml`
- optionally, a security-patch-date setup if the current Strong verdict requires it

TrickyStore operates at the Android KeyMint/attestation boundary and can replace
the certificate chain and RootOfTrust values supplied to Google. On a working,
unrevoked keybox this is the route people use to obtain BASIC, DEVICE, and
STRONG verdicts on unlocked phones.

There are real drawbacks:

- leaked keyboxes get revoked;
- a replacement keybox may be needed later;
- this is not a permanent firmware fix;
- the result depends on the module stack and the exact device state.

It avoids LK flashing, but compatibility and verifier policy still matter;
no module/keybox combination here is verified to guarantee an integrity verdict.

## Track B: Garmr and the genuine key

The Garmr LK artifact is the research route. It makes the normal-world boot
chain report:

```text
verifiedbootstate=green
vbmeta.device_state=locked
flash.locked=1
```

The phone boots and reaches BASIC. It does not change the `deviceLocked` value
that the vendor Trustonic KeyMint trustlet uses for hardware attestation.

That trustlet has now been located and a three-site patch has been built:

```text
poc/cancunf-km-trustlet-patch-v2.zip
```

The package is still an experiment. It may be rejected by Kinibi's MCLF loader,
and no hardware test has established a DEVICE or STRONG result. The remaining
checks are documented in [`TRUSTLET_PATCH.md`](TRUSTLET_PATCH.md).

## Which track makes sense?

| Goal | Practical choice |
| --- | --- |
| Apps working soon | Track A, with a valid unrevoked keybox |
| Learn the boot chain and ARM64 patching | Track B, on a spare device |
| Remove the keybox dependency | Continue the trustlet/TEE work; it is not finished |

The two tracks are independent. Using Track A does not prevent continuing Garmr
research later.
