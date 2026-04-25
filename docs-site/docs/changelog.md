# Changelog

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

Security defaults:

- `alg="none"` is rejected.
- Raw `str` and `bytes` keys are accepted only for HMAC algorithms.
- Mixed algorithm families are rejected for one decode call.
- `verify_signature=False` is rejected in `decode`.
