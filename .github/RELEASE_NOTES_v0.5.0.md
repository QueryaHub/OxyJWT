# OxyJWT 0.5.0

**Beta** performance and hardening release — faster encode/decode hot paths, JWKS concurrency fixes, stricter compact JWT handling, and expanded security regression coverage. No intentional breaking changes to the public `__all__` API.

## Highlights

### Performance

- Verified decode avoids unconditional header parse unless RFC 7797 detached form (`b64: false`, empty payload segment)
- Single-parse unverified decode; native encode when no custom `json_encoder`
- Rust `decode_verified_complete`: fewer key clones, one detach path; RFC 7797 claims validated in Rust
- Skip redundant Python `aud` / `iss` / `sub` checks after Rust validation
- Lazy `PyJWK` / `DecodingKey` materialization for large JWKS sets

### Security

- `detached_payload` capped at 256 KiB (RFC 7797)
- Unified strict compact JWT segment validation before decode
- Thread-safe `PyJWKClient` cache under concurrent `get_signing_key`
- Expanded `tests/test_security_regression.py` contract (always-on in CI)

### Fixes

- `issuer=` now always validates `iss`; missing `iss` raises `InvalidIssuerError` (PyJWT parity)

### CI & benchmarks

- Full CI on pushes to `dev`; PyPI release workflow gated on passing CI
- HS256 smoke benchmark: 3 rounds, median ratio vs PyJWT (≥75% gate)
- Docs: PEM vs cached competitor key modes for fair asymmetric comparisons

## Install

```bash
pip install oxyjwt==0.5.0
```

## Upgrade from 0.4.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to public symbols.
- Stricter validation on malformed compact JWTs and oversized detached payloads.
- When passing `issuer=`, a token without `iss` now fails with `InvalidIssuerError` (was inconsistent before).

See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/docs-site/docs/changelog.md#050--2026-05-22).
