# Garmr: complete attack-surface map and test plan

This consolidates everything established across the LK, TEE (Kinibi), trustlet,
and preloader analysis. It is the reference for the "sit and try all options"
session.

## 1. Boot chain (cancunf, MT6855)

```
BootROM -> preloader (BL2) -> ATF (BL31, EL3) -> Kinibi TEE (EL1)
        -> GenieZone (EL2) -> LK -> Linux
```

- `preloader.img` loads ATF + TEE; it holds the Kinibi memory-map / MMU tables
  (references `0x08000000` base and `0x08540000` BSS page).
- `tee.img` = `atf` (245368 B @ data 0x200, runtime 0x48200000) + `tee`
  (Kinibi core 562176 B @ data 0x3d150, runtime base 0x08000000).
- Kinibi image format: `"EET KTM"` header (0x240 B) = magic + sizes + a
  256-byte RSA-2048 self-signature + load base `0x08000000`.

## 2. What each layer controls

| Layer | Controls | Garmr status |
| --- | --- | --- |
| LK (normal world) | cmdline: `verifiedbootstate`, `vbmeta.device_state`, `flash.locked`, AVB flags | ✅ 7 patches, hardware-proven → Android reports green/locked |
| CERT2 cert bypass | accepts modified `lk.img`/`tee.img` | ✅ `poc/mtk_cert.py`, byte-identical to fenrir OVERRIDE |
| Kinibi (TEE) | trustlet loading + MCLF signature verification | ⚠️ mapped, key is efuse-backed |
| KeyMint trustlet | composes RootOfTrust / attestation | ⚠️ patch exists, unvalidated |

## 3. Attestation inputs (trustlet `07060000...004d.tlbin`)

| Field | Trustlet source | Controllable? |
| --- | --- | --- |
| `bootState` (green) | HAL reads `ro.boot.verifiedbootstate` | ✅ LK patch |
| `deviceLocked` #1 | `is_locked()` @ `0x19ec0` → global `0x73008` | ❌ TEE-internal (set via trustlet cmd `0xa`, from secure storage) |
| `deviceLocked` #2 | TCI byte @ `0x1cd5c` (HAL-supplied) | ✅ patch Android KeyMint HAL |

So two of three are normal-world winnable; `is_locked()` is the TEE-side wall.
The v2 trustlet patch (`poc/cancunf-km-trustlet-patch-v2.zip`) forces all three.

## 4. Trustlet MCLF signature

- MCLF v2.5: header `0x80` + text `0x3fac8` + data `0x8b0` + sig block.
- Sig block = `[132-byte blob][03 00 00 00][01 00 01][256-byte RSA-2048 sig]`,
  signature = last 256 bytes @ `0x40483`.
- **Verification key is NOT the in-flash RSA key** (kinibi `0x88000` = tee.img
  `0xc5150`): `sig^e mod n` is random under PKCS#1 v1.5/PSS over all regions.
  The real key is efuse/hardware, used via MTK crypto SMC. **Self-sign is dead.**

## 5. Kinibi MCLF verification surface

- Parser `0x5c738` (magic `0x464C434D`), loader `0x5eac4..0x5ef98`.
- Driver dispatch: wrappers (`0x65b60` cmd `0xad`, `0x65c88` cmd `0xac`,
  `0x65ae0` cmd `0x32`, `0x65cc8` cmd `0xa9`, ...) do
  `ldr wN,[0x54000+0x8c]; blr xN` → a single runtime-initialized handler.
- **`[0x54000+0x8c]` (runtime `0x0854008c`) is never written by Kinibi code**
  (exhaustive adrp/str/stp/movz scan = zero writes). It is initialized during
  the preloader→Kinibi handoff via Kinibi's early-boot PIC copy at
  `0x2b94..0x2bbc` (source data passed in by the preloader). The handler's
  address is therefore not statically resolvable from the images alone.
- The handler's signature-failure return was therefore **not pinned to 100%**.

## 6. Bypass candidates (test order)

1. **`0x5ebf0` (recommended first)**: loader's `cbz w0,#0x5ecc4` after the
   cmd `0xad` call → patch to `b #0x5ecc4`
   (`a0 06 00 34` → `35 00 00 14`) at tee.img `0x9bd40`. Medium confidence
   (cmd `0xad` runs right after the MCLF intro read = most likely verify step).
   → `python3 bypass/patch_verify.py ...`
2. **Trustlet bind-mount only** (`poc/trustlet_patch` module) — tests whether
   Kinibi rejects the modified MCLF (the #1 unknown).
3. **Trustlet + tee.img bypass** — the full TEE-side experiment.
4. **Self-sign** (`selfsign/`) — expected to FAIL (efuse key), kept as a
   negative control to confirm the efuse finding.

## 7. What a full win requires (unvalidated)

```text
unlock -> LK patches + cert bypass (done)
       -> patched tee.img to make Kinibi accept the modified MCLF (candidate 1)
       -> patched trustlet forcing is_locked()/deviceLocked#2 (exists)
       -> trustlet signs genuine device key with locked/green claims
       -> DEVICE, maybe STRONG
```

The one hard blocker that remains unproven is whether Kinibi's MCLF signature
check can be neutralized (candidate 1) — the verification key is efuse-backed,
so the only route is bypassing the *result check*, whose definitive branch is
behind the preloader-initialized handler.
