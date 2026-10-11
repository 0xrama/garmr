# Garmr: provisional attack-surface map and test plan

This is an offline research map, not a complete proof of the secure-world
implementation or an attestation solution. Historical LK trials report booting,
green/locked Android properties and BASIC integrity. Captured boot logs, signed
before/after certificates and Play Integrity responses supporting those trials
were not identified in the audited checkout. No new hardware tests are claimed.

## 1. Boot chain and image layout

```text
BootROM -> preloader (BL2) -> ATF (BL31, EL3) -> Kinibi TEE (EL1)
        -> GenieZone (EL2) -> LK -> Linux
```

For 20-5-12, `tee.img` contains signed `atf` (245368 bytes, data `0x200`,
runtime `0x48200000`) and `tee` (562176 bytes, data `0x3d150`, Kinibi base
`0x08000000`). The Kinibi header is `0x240` bytes with `EET KTM` magic;
its signature/key interpretations need further validation.

## 2. Evidence by layer

| Layer | Offline evidence | Boundary |
| --- | --- | --- |
| LK | Seven patch types, eleven placements, 82 changed payload bytes per build; both artifacts reproduced exactly | Historical boot reports, not independently captured here |
| CERT2 overrides | Internal CERT1/CERT2 signatures and hashes pass on stock and modified LK/TEE | Embedded keys do not establish hardware authorization |
| Kinibi loader | Two anchored consumers after cmd `0xad` patched in both builds | Signature-specific semantics/acceptance unknown |
| KeyMint trustlet | Three sites change 16 bytes per build, final 256-byte signature unchanged | Execution and signed certificate effects unknown |

Canonical build/verification commands and dependency requirements are in
[README](../README.md). Parsing rejects truncation/trailing bytes and full
verification requires LK inventory `(lk, bl2_ext, aee, lk_main_dtb)` or TEE
inventory `(atf, tee)`. This is not a boot-safety guarantee.

## 3. Candidate attestation inputs

`is_locked()` at trustlet `0x19ec0` reads global `0x73008`. Analysis detects
reset and storage-load writers (`0x19c9c`, `0x19fa4`), but upstream producers
and update paths remain untraced. The described `umulh` with magic
`0xE38E38E38E38E38F` followed by `lsr #5` implements unsigned division by
36, not 9; a Capstone rerun confirmed this local instruction sequence.

Selectors at `0x1cc44` and `0x1cd5c` use the global and a stack byte
respectively. A stack load does not prove HAL/TCI provenance. LK/property to
trustlet boot-state propagation is a working hypothesis without the matching
HAL/serializer trace and signed certificate evidence. Standard RootOfTrust has
one `deviceLocked` field, not two; multiple string selectors are not proof of
multiple standard fields. See [data-flow notes](ATTESTATION_CHANNEL.md).

## 4. Key and handler unknowns

The stock trailer has a 132-byte unknown blob, `03 00 00 00`, `01 00 01`
and final 256-byte candidate RSA signature at `0x40483`. The candidate modulus
at Kinibi `0x88000` yields encoded-message prefix `2d33`, suffix `20`,
inconsistent with conventional PKCS#1 v1.5/PSS under that interpretation.
It does not locate the real key, exclude all in-flash keys or prove efuses.
Self-sign failure cannot resolve key provenance or validate the chosen format.

Wrappers call through `[0x54000+0x8c]`; initializer and handler remain unresolved.
ATF handoff, preloader PIC-copy and runtime registration are theories, not facts.
Linear register-tracking sweeps are heuristic, not exhaustive proofs of no
writer. See [key evidence](KINIBI_MCLF_KEY.md).

## 5. Experiments and required evidence

1. Build-matched LK baseline: collect image hashes, properties, complete signed
   attestation chains and actual integrity responses; do not substitute narrative.
2. Trustlet mount only: verify mounted bytes and logged restart requests for
   discovered running services, then independently establish actual restarts
   and whether a fresh secure-world session executed it.
3. Trustlet plus experimental TEE consumers: both `0x5ebf0` and `0x5eca4`
   are changed, not only the old first-site candidate. Additional authentication
   and side effects may remain behind cmd `0xad`.
4. Self-sign: exploratory alternative, not a negative control proving efuses.

Follow [testing guide](TESTING_GUIDE.md), one layer at a time with backups and
a recovery path. Neither successful mounts nor locked/green certificate fields
guarantee DEVICE/STRONG: chain trust, revocation, provisioning, freshness,
security-patch requirements and verifier policy can still matter. No such
result is demonstrated here. Missing super sparsechunks also prevent replaying
vendor extraction from the supplied firmware inputs.
