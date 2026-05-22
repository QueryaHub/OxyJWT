# OxyJWT 0.4.0

**Beta** production-hardening release — security, performance, PyJWT/JWKS parity, and typing. No intentional breaking changes to the public `__all__` API beyond stricter defaults and new warnings.

## Highlights

### Security

- JWKS: `max_bytes`, optional `require_https`, `algorithms` checked before HTTP, refresh-on-miss `kid`, `lifespan` TTL
- Reject JWKs with `use: enc`; `PyJWKSetSkipWarning` for skipped keys
- `InsecureDecodeWarning` for unverified decode paths
- `strict_aud`, `verify_sub`, issuer list validation, fractional `leeway` alignment
- Max compact JWT size (256 KiB) before parse; HMAC secret buffers zeroized after use

### Features & parity

- `PyJWKClient`: `headers`, `ssl_context`, `cache_keys` (default off), `lifespan`
- RFC 7797 detached payload decode (`detached_payload` + `b64: false`)
- Custom string JWT header parameters on `encode`
- Public `.pyi` stubs + `py.typed`; mypy CI job

### Performance

- Single-parse verified `decode_complete`; fewer orjson round-trips on encode/decode
- O(1) JWKS `kid` index; lazy `PyJWK.key`; GIL release on unverified parse

### Testing & docs

- `tests/test_security_regression.py`; RSA/EC JWK parity tests
- Stricter benchmark CI gates (≥75% vs PyJWT); expanded API/security docs

## Install

```bash
pip install oxyjwt==0.4.0
```

## Upgrade from 0.3.0

```bash
pip install -U oxyjwt
```

Review new warnings and stricter JWKS/JWT limits. See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/docs-site/docs/changelog.md#040--2026-05-22).
