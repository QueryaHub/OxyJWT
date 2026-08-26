# Changelog

## Unreleased

(No changes yet.)

## 0.7.0 — 2026-08-26

Performance release. Verified `decode` is about **2.3× faster** and `encode` about
**1.2× faster** than 0.6.0 on the HS256 hot path, with no change to any successful
decode or encode result. Measured locally with CPython 3.14 on Linux/x86-64;
absolute numbers vary by machine. The API remains pre-1.0 (Beta). See
[Versioning](versioning.md) and [`SECURITY.md` on GitHub](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md).

### Upgrading from 0.6.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to the public `__all__` surface.
- One edge-case behaviour change: a **present but unparseable** claim listed in
  `options["require"]` (for example `{"exp": "not-a-number"}`) now raises
  `DecodeError` instead of `MissingRequiredClaimError`, matching PyJWT.
- Absent and JSON `null` required claims still raise `MissingRequiredClaimError`.

| Operation | 0.6.0 | 0.7.0 | Change |
| --- | --- | --- | --- |
| `decode` | 6.08 µs | 2.64 µs | 2.30× faster |
| `decode_complete` | 5.90 µs | 2.98 µs | 1.98× faster |
| `decode` (large claims) | 15.18 µs | 9.60 µs | 1.58× faster |
| `decode` (`audience` + `issuer`) | 7.12 µs | 5.50 µs | 1.29× faster |
| `encode` | 1.68 µs | 1.44 µs | 1.17× faster |

### Changed

- **Single-pass verified decode.** The native decode path now parses the header
  once, parses the payload once and verifies the signature once. Previously the
  underlying `jsonwebtoken::decode` parsed both segments a second time for its
  internal validation struct, and the returned header had to be re-serialized
  before it could be handed to Python.
- **Fast path for plain `decode` / `decode_complete`.** When nothing but
  `algorithms` is supplied, the options dictionary is no longer built, copied or
  re-read on either side of the FFI boundary, and Python runs only the claim
  checks that Rust does not already cover. Calls that pass `options`,
  `audience`, `issuer`, `subject`, a non-zero `leeway`, `typ` or
  `detached_payload`, or that use a `PyJWT` instance with non-default options,
  behave exactly as before.
- **Release profile.** Wheels are now built with fat LTO, a single codegen unit
  and stripped symbols.
- RFC 7797 detached-JWS decoding no longer selects its exception type by matching
  on error message text.
- Header parse failures now report the same message as `get_unverified_header`
  for the same token. The exception classes are unchanged.

### Fixed

- **`MissingRequiredClaimError` now names a deterministic claim.** When several
  claims listed in `options["require"]` were absent, the one reported differed
  between processes.
- **`options["require"]` treats a JSON `null` as an absent claim**, matching
  PyJWT.
- `encode` no longer copies the payload when no `datetime` claim needs
  rewriting, and never mutates the caller's dictionary.

### Behaviour change

- A claim listed in `options["require"]` that is **present but unparseable** (for
  example `{"exp": "not-a-number"}` with `require=["exp"]`) now raises
  `DecodeError` instead of `MissingRequiredClaimError`, matching PyJWT. Absent and
  `null` claims continue to raise `MissingRequiredClaimError`.

### Notes

- `sort_headers` on `encode` has never affected the emitted token: claim keys are
  serialized in sorted order either way. The flag is still accepted for PyJWT
  compatibility.

## 0.6.0 — 2026-08-26

Security, JWKS hardening, and performance release: RFC 8725 token-type validation, JWKS refresh throttling, stricter RFC 7797 `crit` handling, thread-safe JWK materialization, and encode/decode hot-path improvements. The API remains pre-1.0 (Beta). See [Versioning](versioning.md) and [`SECURITY.md` on GitHub](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md).

### Upgrading from 0.5.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to the public `__all__` surface.
- New optional **`typ`** parameter on `decode` / `decode_complete` for explicit token type validation (RFC 8725 §3.11).
- New optional **`refresh_cooldown`** on `PyJWKClient` (default `0.0`; opt in to rate-limit JWKS refresh).
- **`InsecureJWKSUriWarning`** when a JWKS URI uses unencrypted HTTP (RFC 8725 §3.10).
- Stricter RFC 7797 validation: unsupported parameters in `crit` are rejected for detached JWS.
- `PyJWKSet` kid index no longer includes keys with `use: enc`.

### Added

- **`typ`** parameter on `decode` / `decode_complete` — validates the JWT header `typ` claim to prevent token type confusion (RFC 8725 §3.11).
- **`PyJWKClient.refresh_cooldown`** — cooldown window between JWKS refreshes to mitigate kid-flooding DoS.
- Single-flight coalescing and fine-grained locking in `PyJWKClient` for concurrent JWKS fetches.

### Fixed

- Thread-safe lazy key materialization in `PyJWK` and `PyJWKSet`.
- `PyJWKSet` kid index excludes `use: enc` encryption keys.
- `exp` expiration boundary synchronized between Rust and Python validation.
- Recursion depth / cycle limit in native `py_to_json` conversion during encode.

### Security

- `InsecureJWKSUriWarning` when JWKS URI uses unencrypted HTTP (RFC 8725 §3.10).
- JWKS refresh cooldown mitigates repeated refresh under kid-flooding attacks.
- RFC 7797: reject unsupported parameters listed in `crit` for detached JWS.

### Performance

- Avoid `serde_json::Value` DOM tree allocation in `encode_json`.
- Pre-allocate `PyList` during `json_to_bound` claim conversion.
- Eliminate intermediate string allocation in JWS signing input parsing.

## 0.5.0 — 2026-05-22

Performance and hardening release: faster encode/decode hot paths, JWKS concurrency fixes, stricter compact JWT validation, PyJWT-aligned issuer errors, and expanded security regression tests. The API remains pre-1.0 (Beta). See [Versioning](versioning.md) and [`SECURITY.md` on GitHub](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md).

### Upgrading from 0.4.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to the public `__all__` surface.
- Malformed compact JWTs (wrong segment count) are rejected consistently in Rust before decode.
- `detached_payload` is capped at **256 KiB** (RFC 7797).
- When `issuer=` is passed, a token **without** `iss` now raises **`InvalidIssuerError`** (PyJWT parity; previously could slip through on some paths).

### Fixed

- `issuer=` always runs issuer validation in Python; missing `iss` raises `InvalidIssuerError` instead of being skipped.
- `PyJWKClient` JWKS / signing-key cache is thread-safe under concurrent `get_signing_key` (lock around cache mutations).

### Security

- `detached_payload` size capped at 256 KiB before attach (RFC 7797).
- Compact JWT segment validation unified in Rust (reject extra/missing segments before `jwt` parse).
- Expanded `tests/test_security_regression.py` — oversized JWT, detached cap, `none` alg, concurrent JWKS client, issuer-without-iss.

### Performance

- Verified decode: skip `get_unverified_header` unless empty payload segment (RFC 7797 detached form).
- Unverified decode / `get_unverified_header`: single native parse path (no double segment split).
- `encode`: use Rust `encode` directly when no custom `json_encoder` (no `encode_json` round-trip).
- `decode_verified_complete`: hold decoding key by reference; combine detach + verify in one Rust path.
- Skip redundant Python `aud` / `iss` / `sub` validation when Rust already validated on verified decode.
- RFC 7797 verified path: `exp` / `nbf` / `iat` validated in Rust for detached tokens.
- `PyJWK` / `PyJWKSet`: lazy `DecodingKey` materialization; large JWKS sets avoid upfront parse of every key.

### CI & documentation

- Full CI runs on pushes to `dev` (same gates as PRs).
- PyPI [Release workflow](https://github.com/QueryaHub/OxyJWT/blob/main/.github/workflows/release.yml) runs CI via `workflow_call` before publishing.
- HS256 smoke benchmark: 3 rounds, **median** ops/s vs PyJWT; gate remains ≥75%.
- [Benchmarks](benchmarks.md): document smoke / extended / full tiers and PEM vs `cached` competitor key modes.

## 0.4.0 — 2026-05-22

Production hardening release: security fixes, performance improvements, expanded PyJWT/JWKS parity, public typing stubs, and stricter CI. The API remains pre-1.0 (Beta). See [Versioning](versioning.md) and [`SECURITY.md` on GitHub](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md).

### Upgrading from 0.3.0

```bash
pip install -U oxyjwt
```

- No intentional breaking changes to the public `__all__` surface; behavior is stricter in several security-sensitive paths (see **Security** below).
- New warnings: `InsecureDecodeWarning` when `verify_signature=False`; `PyJWKSetSkipWarning` when JWKS entries are skipped.
- `PyJWKClient.cache_keys` defaults to **`False`** (PyJWT parity); opt in for per-`kid` LRU caching.
- `decode` / `decode_complete` accept **`issuer`** as a string or iterable.
- **`strict_aud`**, **`detached_payload`** (RFC 7797 when `b64: false`), and custom string JWT header fields on `encode`.
- Public **`.pyi`** stubs and `py.typed` for IDE/mypy users.

### Added

- `tests/test_jwk_rsa_ec.py` — RSA and EC JWK/JWKS parity tests with real `n`/`e` and `crv`/`x`/`y` shapes.
- RFC 7797 detached payload decode via `detached_payload` when the protected header sets `b64` to `false`.
- `encode` accepts custom string JWT header parameters beyond `alg` / `typ` / `cty` / `kid`, plus optional standard string JWS fields (`jku`, `x5u`, `x5t`, `x5t#S256`, `url`, `nonce`).
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
