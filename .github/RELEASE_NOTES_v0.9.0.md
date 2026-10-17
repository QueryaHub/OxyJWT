# OxyJWT 0.9.0

**Beta** performance and security release — zero-copy streaming claims deserialization, pre-encoded static headers, native fast-path claim validation in Rust, zero-copy header algorithm extraction, direct JWK deserialization, RFC 7515/7797 strict `crit` header enforcement, and public top-level `encode_json` export.

## Highlights

### Security

- **Strict rejection of unrecognized `crit` (Critical) header parameters** — Under RFC 7515 §4.1.11 and RFC 7797, any critical header extensions that are unrecognized, malformed, empty, or targeting reserved claims are rejected immediately on both verified and unverified decode paths (#132).

### Performance

- **Pre-encoded static headers and native claim validation** — Standard default headers (`{"typ":"JWT","alg":"..."}`) use pre-encoded immutable base64 slices in `encode` and `encode_json`, eliminating header JSON serialization and base64 allocation. Fast-path `decode` now validates `iat`, unrequested `aud`, and `sub` entirely in Rust, eliminating secondary Python validation passes. HS256 encode benchmark reached **~895,000 ops/s** (#150).
- **Direct JWK deserialization** — Materializing a decoding key from a JWK dictionary now avoids intermediate `serde_json::Value` DOM trees; parsed in a single pass via `orjson.dumps` and streaming `jsonwebtoken::jwk::Jwk` parsing. Speedup: 10× for octet/HMAC keys (0.97 µs vs 9.66 µs) and 21× for RSA keys (1.21 µs vs 25.48 µs) (#140).
- **Zero-copy header algorithm resolution** — Standard compact headers are resolved via static string matching without base64 or JSON decoding; non-standard headers extract `alg` via a streaming serde visitor without allocating map structures (#138).
- **Streaming claims deserialization into `PyDict`** — Deserialization in `decode_complete` directly streams serde JSON tokens into Python `PyDict` without building intermediate Rust DOM trees (#137).
- **In-Rust validation for `aud`, `iss`, and `sub`** — Standard claim checks execute natively during fast-path decoding (#136).
- **Payload borrowing in `encode_json` and GIL optimization** — JWS signing inputs are built directly from borrowed slices; non-cryptographic sub-microsecond helpers run attached to the GIL to eliminate `py.detach` thread context switching overhead (#139).

### Added

- **Top-level `encode_json` export** — `encode_json` is exported directly on `oxyjwt.encode_json` and `PyJWT.encode_json` with complete typing and parity tests (#148).
- `DecodingKey.from_jwk`, `PyJWK`, and `PyJWKSet.from_json` now accept raw UTF-8 `bytes` directly in addition to `str` and `Mapping[str, Any]` (#140).

## Install

```bash
pip install oxyjwt==0.9.0
```

## Upgrade from 0.8.0

```bash
pip install -U oxyjwt
```

- No breaking changes to public APIs.
- Full parity with PyJWT 2.x maintained across all algorithms and options.

See the full [changelog](https://github.com/QueryaHub/OxyJWT/blob/main/CHANGELOG.md#090--2026-10-17).
