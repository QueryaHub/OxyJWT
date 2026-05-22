# Changelog

## Unreleased (0.4.0)

### Added

- Public `.pyi` stubs for `api_jwt`, `jwk`, `jwks_client`, `jwk_exc`, and `warnings`; `py.typed` marker for PEP 561.
- Mypy CI job and `tests/typing/` smoke checks for the public API surface.

### Fixed

- `PyJWKClient.get_signing_key` refetches JWKS once when `kid` is missing from the cached set (key rotation).
- `decode` / `decode_complete` accept `issuer` as a string or iterable (aligned with docs and Rust validation).

### Security

- HMAC secret buffers copied from Python are held in `Zeroizing<Vec<u8>>` and cleared after `EncodingKey` / `DecodingKey` construction and ephemeral `from_secret` decode paths.
- Compact JWT strings larger than 256 KiB are rejected with `DecodeError` before base64/JSON parsing (all decode and unverified entry points).
- `InsecureDecodeWarning` when `verify_signature` is `False`; additional warnings when `subject` or `require` are used without signature verification.
- `verify_sub` option (PyJWT-aligned); Python-side `sub` validation on the unverified decode path when enabled.
- `PyJWKClient` `max_bytes` (default 256 KiB) and optional `require_https` for JWKS fetches.
- `PyJWKClient.get_signing_key_from_jwt` optional `algorithms` allow-list: rejects disallowed header `alg` before JWKS lookup.
- `PyJWK` rejects JWKs with `use: enc` (encryption keys) for signature verification paths.
- `PyJWKSet` emits `PyJWKSetSkipWarning` when unusable JWK entries are skipped (index and `kid` in message).
- Claim validation split documented: Rust validates `exp`/`nbf` on verified decode; Python validates `iat` and PyJWT-style audience/issuer/sub rules. `verify_sub=False` no longer validates `sub` in Rust when `subject` is passed.
- Fractional `leeway` on verified decode: Python validates `exp`/`nbf` with float semantics; Rust uses rounded whole seconds when `leeway` is an integer.
- `PyJWKSet` O(1) lookup by `kid`; `PyJWK.key` parses `DecodingKey` lazily on first access.
- `decode_unverified`, `get_unverified_header`, and `jws_parse_compact` release the GIL during native JWS/JWT parsing.
- `PyJWKClient` accepts optional `headers` and `ssl_context` (PyJWT 2.8 subset).
- `PyJWKClient` `lifespan` TTL (default 300s) for cached JWKS when `cache_jwk_set=True`.
- `strict_aud` decode option for exact string audience matching (PyJWT parity).
- `PyJWKClient` `cache_keys` parameter (default `False`, PyJWT parity); per-`kid` LRU is opt-in.
- `tests/test_security_regression.py` — dedicated 0.4.0 security regression suite (always run in CI).
- Benchmark CI smoke: HS256 OxyJWT vs PyJWT ratio gates tightened to ≥75% (was 25%); decode checked too. Docs describe smoke / extended / full workflows.
- Expanded `PyJWKClient` API reference; JWKS security notes cross-linked from `SECURITY.md` and `security.md`.

### Performance

- Encode path passes `orjson` output as bytes into Rust (`serde_json::from_slice`), removing an extra UTF-8 decode and `from_str` parse.
- Verified `decode_complete` uses `decode_verified_complete` in Rust (one `jwt_decode` parse) instead of `jws_parse_compact` plus a second full decode.
- Removed `orjson` dumps/loads round-trip when normalizing decode claims and headers (`_as_plain_dict`).

## 0.3.0

Documentation, PyJWT parity, and operational polish. PyPI classifiers now mark the project as **Beta**; the API remains pre-1.0. See [Versioning](versioning.md). Security reporting is described in [`SECURITY.md` on GitHub](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md).

### Upgrading from 0.2.0

- `pip install -U oxyjwt` pulls the new runtime dependency **[orjson](https://github.com/ijl/orjson)** automatically; no code changes required for typical `encode` / `decode` usage.
- New optional `subject` argument on `decode` / `decode_complete` (PyJWT-compatible order: `audience`, `subject`, `issuer`).
- No further breaking API changes beyond the **0.2.0** exception hierarchy; update `except` clauses if you have not already (see [Migration from PyJWT](usage/migration-pyjwt.md)).

Added:

- `subject` parameter on `PyJWT.decode` / `decode_complete` (and module helpers), wired through to native verification.
- LRU cache for `PyJWKClient` signing keys keyed by `kid`, bounded by `max_cached_keys`.
- Expanded optional PyJWT parity tests (`tests/test_parity_pyjwt.py`).
- `pytest-cov` coverage report (XML + terminal) in CI.
- `SECURITY.md`, `CONTRIBUTING.md`, docs for [versioning](versioning.md), [benchmarks](benchmarks.md), and a [FastAPI cookbook](cookbooks/fastapi-jwt.md).
- Scheduled benchmark workflow producing a Markdown artifact.
- Runtime dependency on **[orjson](https://github.com/ijl/orjson)** for JSON in the Python API layer (payload serialization for `encode`, JWK/JWKS parsing, claim/header normalization).
- Pytest benchmark smoke test (`tests/test_benchmark_jwt_libraries.py`) that reuses `scripts/compare_jwt_libraries.py` for HS256 throughput vs competitors.

Changed:

- API reference and decoding guides now match `verify_signature` / `options` behavior from 0.2.0.
- Exception hierarchy diagrams in docs corrected to match runtime (`InvalidTokenError` above `DecodeError`).
- Pytest `pythonpath = ["python"]` so local runs resolve the mixed-layout package consistently.

## 0.2.0

PyJWT compatibility release (API shape, JWK, JWKS client, and documentation). **Breaking change:** the exception class hierarchy is aligned with PyJWT (`InvalidTokenError` as the common base for most token and claim errors; `DecodeError` and `InvalidSignatureError` nest under it). Code that relied on the previous nesting order may need to update `except` clauses. See the [Migration from PyJWT](usage/migration-pyjwt.md) page for details.

Added:

- Module-level `PyJWT`, `encode`, `decode`, and `decode_complete` matching common PyJWT usage, including `json_encoder`, `sort_headers`, and `leeway` / `timedelta` handling.
- `PyJWK` and `PyJWKSet` built on `DecodingKey::from_jwk`, plus `PyJWKClient` (JWKS over HTTP via the standard library).
- `InvalidIssuedAtError` and claim validation for `iat` in the Python layer when enabled.
- `encode_json` and `jws_parse_compact` in the native module for the Python JWT layer.
- Parity and regression tests; optional comparison tests against the `jwt` package when installed.
- Python 3.14 Trove classifier and CI job.

Changed:

- `decode` with `options["verify_signature"] = False` skips JWS verification and no longer requires an `algorithms` list for that path (treat unverified tokens as untrusted). Default remains signature verification on.
- Native `leeway` is expressed in seconds as a float, consistent with PyJWT.
- Stubs (`_oxyjwt.pyi`) updated for the new symbols and exception layout.

## 0.1.0

Initial alpha release.

Added:

- PyJWT-like `encode` and `decode` API.
- Explicit `algorithms` allow-list for decoding.
- HMAC, RSA, RSA-PSS, ECDSA, and EdDSA algorithm support.
- Typed `EncodingKey` and `DecodingKey` constructors.
- Unverified inspection helpers.
- OxyJWT exception hierarchy.
- Rust unit tests and Python pytest coverage.
- MkDocs documentation.

Security defaults (0.1.0; see 0.2.0 for unverified decode):

- `alg="none"` is rejected.
- Raw `str` and `bytes` keys are accepted only for HMAC algorithms.
- Mixed algorithm families are rejected for one decode call.
- In 0.1.0, `verify_signature=False` was rejected in `decode` (0.2.0 allows an explicit unverified path; still unsafe for trusted claims without a verified signature).
