# OxyJWT 0.7.0

**Beta** performance release — single-pass verified decode, a Python fast path for plain `decode` / `decode_complete`, fat-LTO wheels, and PyJWT-aligned `require` claim handling. No intentional breaking changes to the public `__all__` API.

## Highlights

### Performance

- **Single-pass verified decode** — parse header once, payload once, verify once (no second pass through `jsonwebtoken::decode`)
- **Fast path** when only `algorithms` is supplied — skip options dict build/copy across the FFI boundary
- **Release profile** — fat LTO, `codegen-units = 1`, stripped symbols
- HS256 microbench vs 0.6.0 (CPython 3.14, Linux/x86-64): decode **~2.3×**, encode **~1.2×**
- Full library comparison (1000 iter × 3 rounds): HS256 decode **~450k** ops/s, encode **~714k** ops/s

### Fixes

- `MissingRequiredClaimError` names a **deterministic** claim when several required claims are absent
- `options["require"]` treats JSON `null` as absent (matches Python layer and PyJWT)
- `encode` avoids copying the payload when no `datetime` rewrite is needed

### Behaviour change

- A claim in `options["require"]` that is **present but unparseable** (e.g. `{"exp": "not-a-number"}`) now raises `DecodeError` instead of `MissingRequiredClaimError`, matching PyJWT

## Install

```bash
pip install oxyjwt==0.7.0
```

## Upgrade from 0.6.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to public symbols.
- Successful encode/decode results are unchanged; only the edge-case `require` + malformed claim error class differs (see above).

See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/CHANGELOG.md#070--2026-08-26).
