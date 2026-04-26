# Changelog

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
