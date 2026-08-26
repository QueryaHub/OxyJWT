# OxyJWT 0.6.0

**Beta** security and JWKS hardening release — RFC 8725 token-type validation, JWKS refresh throttling, stricter RFC 7797 `crit` handling, thread-safe JWK materialization, and encode/decode hot-path improvements. No intentional breaking changes to the public `__all__` API.

## Highlights

### Security

- **`typ`** parameter on `decode` / `decode_complete` for explicit token type validation (RFC 8725 §3.11)
- **`InsecureJWKSUriWarning`** when JWKS URI uses unencrypted HTTP (RFC 8725 §3.10)
- **`refresh_cooldown`** on `PyJWKClient` to mitigate kid-flooding DoS
- RFC 7797: reject unsupported parameters in `crit` for detached JWS

### JWKS

- Single-flight coalescing and fine-grained locking for concurrent JWKS fetches
- Thread-safe lazy key materialization in `PyJWK` and `PyJWKSet`
- `PyJWKSet` kid index excludes `use: enc` encryption keys

### Fixes

- `exp` expiration boundary synchronized between Rust and Python
- Recursion depth / cycle limit in native `py_to_json` conversion

### Performance

- Avoid `serde_json::Value` DOM allocation in `encode_json`
- Pre-allocate `PyList` during claim conversion; fewer allocations in JWS signing input parsing

## Install

```bash
pip install oxyjwt==0.6.0
```

## Upgrade from 0.5.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to public symbols.
- Optional `typ` on decode for token type checks; optional `refresh_cooldown` on `PyJWKClient`.
- HTTP JWKS URIs now emit a warning; RFC 7797 `crit` validation is stricter.

See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/CHANGELOG.md#060--2026-08-26).
