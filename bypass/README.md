# Bypass route (recommended)

Force Kinibi's MCLF trustlet signature verification to "valid" by patching the
loader's result check, leaving the key untouched. This is now the **primary**
route because the parallel self-sign investigation proved the real trustlet
verification key is **not** in flash (likely efuse/hardware via MTK crypto SMC).

## Status

| Piece | Status |
| --- | --- |
| cert bypass for tee.img | ✅ working (`poc/mtk_cert.py`, verified `VALID`) |
| MCLF parser / loader / dispatch | ✅ mapped (high confidence) |
| verify-result branch | ⚠️ best-guess `0x5ebf0` (medium confidence) |

## What was found

- Load base: kinibi file offset `X` = runtime `0x08000000 + X`; tee.img offset = `0x3d150 + X`.
- MCLF parser `0x5c738` (checks magic `0x464C434D`), loader `0x5eac4..0x5ef98`.
- Verification is **indirect**: loader calls driver wrappers (`0x65b60` cmd `0xad`,
  `0x65c88` cmd `0xac`, `0x65ae0` cmd `0x32`, etc.) that dispatch through a
  runtime-initialized handler at BSS `[0x54000 + 0x8c]` (not statically pinned).
- No SHA-256 constants and no inline RSA in the image → hashing/RSA go through
  MTK hardware crypto (ATF SMC).
- The in-flash RSA key (`0x88000`) does **not** verify the trustlet signature
  (proved mathematically), so the real key is outside the flashable image.

## Patch

Best-guess: the loader's check of the post-intro driver call (cmd `0xad`) at
`0x5ebf0`, right after the MCLF intro is read and before segment mapping:

```asm
0x5ebe8: bl     #0x65b60      ; cmd 0xad (verify/load step)
0x5ebec: mov    w19, w0
0x5ebf0: cbz    w0, #0x5ecc4  ; success -> continue
0x5ebf4: ...                   ; failure path
```

`patch_verify.py` changes `cbz w0, #0x5ecc4` → `b #0x5ecc4`
(`a0 06 00 34` → `35 00 00 14`) at tee.img `0x9bd40`.

## Pipeline

```bash
python3 bypass/patch_verify.py \
    --tee-img firmware/V1TDS35H.83-20-5-12/tee.img \
    -o bypass/tee_bypassed.img
```

Use the stock patched trustlet as-is (no re-signing needed):
`poc/trustlet_patch/0706000000000000000000000000004d.tlbin`.

## Remaining unknowns (to reach 100% confidence)

1. The handler behind `[0x54000+0x8c]` (find the boot code that initializes it,
   disassemble it, and locate its signature-failure return).
2. Which command id (`0xad`? `0x32`? `0x35`?) actually returns the verify result.
3. The ATF crypto SMC id and the real verification key (efuse).
