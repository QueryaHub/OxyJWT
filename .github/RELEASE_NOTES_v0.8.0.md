# OxyJWT 0.8.0

**Beta** performance release — cached RSA signing keys, borrowed (no longer cloned) key material, a lighter Python decode fast path, interned claim/header names, and skipped GIL release on the HMAC hot path. No intentional breaking changes to the public `__all__` API.

## Highlights

### Performance

- **Cached RSA signing key** — `EncodingKey.from_rsa_pem` parses the DER key into an `aws_lc_rs::RsaKeyPair` once, at construction time; RS256 `encode` dropped from ~526 µs to ~201 µs (2.6× faster) with a pre-built key
- **No more per-call key cloning** — `EncodingKey` / `DecodingKey` are `frozen` pyclasses now; native `encode`/`decode` borrow the key material instead of cloning it
- **Lighter Python decode fast path** — inlined argument checks, and `exp` is only re-checked in Python when it isn't a plain `int`: wrapper overhead dropped from ~0.85 µs to ~0.57 µs (with `iat`) or ~0.37 µs (no time claims)
- **Interned claim/header names** (`exp`, `iat`, `nbf`, `sub`, `aud`, `iss`, `jti`, `alg`, `typ`, `kid`) — native `decode` on an 8-claim payload dropped from ~2.05 µs to ~1.92 µs
- **HMAC no longer releases the GIL** — HS256 decode throughput under 8-thread contention went from ~410k to ~790k decodes/sec; RSA/EC/EdDSA are unaffected and keep releasing the GIL
- Removed several redundant allocations/re-parses on secondary paths (`get_unverified_header`, `decode_unverified`, the unverified branch of `decode_complete`, `encode_json` token assembly)

### Behaviour change

- `decode_unverified` now accepts a header that is valid JSON but not a recognized `alg` name (e.g. `{"alg": "made-up"}`), matching `get_unverified_header`'s own check. Unverified decode was never a security boundary.

## Install

```bash
pip install oxyjwt==0.8.0
```

## Upgrade from 0.7.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to public symbols.
- Successful encode/decode results are unchanged; only the `decode_unverified` edge case above differs.

See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/CHANGELOG.md#080--2026-09-28).
