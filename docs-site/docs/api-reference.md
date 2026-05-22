# API Reference

This is a hand-written reference for the public Python API.

## `encode`

```python
def encode(
    payload: Mapping[str, Any],
    key: str | bytes | EncodingKey,
    algorithm: str = "HS256",
    headers: Mapping[str, Any] | None = None,
) -> str: ...
```

Signs `payload` and returns a compact JWT string.

Parameters:

- `payload`: JSON-compatible mapping to place in the token claims.
- `key`: raw HMAC secret or an `EncodingKey`.
- `algorithm`: signing algorithm. Defaults to `HS256`.
- `headers`: optional JWT header values such as `kid` and `typ`.

Raises:

- `EncodeError` for invalid payloads or unsupported headers.
- `InvalidAlgorithmError` for unsupported algorithms or `alg` header overrides.
- `InvalidKeyError` for invalid key material.

## `decode`

```python
def decode(
    jwt: str | bytes,
    key: str | bytes | DecodingKey = "",
    algorithms: list[str] | None = None,
    options: Mapping[str, Any] | None = None,
    verify: bool | None = None,
    detached_payload: bytes | None = None,
    audience: str | Iterable[str] | None = None,
    subject: str | None = None,
    issuer: str | None = None,
    leeway: float | timedelta = 0,
) -> dict[str, Any]: ...
```

Verifies the JWT and returns its claims as a Python dict (via `decode_complete`).

When `options["verify_signature"]` is true (the default), `algorithms` is required and the JWS signature is verified in the Rust core.

Parameters:

- `jwt`: compact JWT string or UTF-8 bytes.
- `key`: raw HMAC secret or a `DecodingKey`.
- `algorithms`: required server-side allow-list when signature verification is on.
- `audience`: expected `aud` value or values.
- `subject`: expected `sub` value (passed to the native decoder when signature verification is on).
- `issuer`: expected `iss` value.
- `leeway`: clock tolerance in seconds or as a `timedelta`.
- `options`: validation switches (see below). Values from a `PyJWT(..., options=...)` instance are merged with per-call `options`.
- `detached_payload`: not supported; raises `NotImplementedError` if set.

Supported `options` keys (booleans unless noted):

- `verify_signature` — verify the JWS signature (default `True`).
- `verify_exp`, `verify_nbf`, `verify_iat`, `verify_aud`, `verify_iss`
- `require_exp` — require an `exp` claim in the token
- `require` — list of claim names that must be present (may also be passed on the `PyJWT` instance)

When `verify_signature` is `False`, OxyJWT skips signature verification and does not require `algorithms`. Claim checks follow the merged `options` (defaults turn off time and issuer/audience checks unless you set them back to `True`). Treat the payload as **untrusted** unless you have another integrity layer.

Raises:

- `InvalidSignatureError`
- `ExpiredSignatureError`
- `ImmatureSignatureError`
- `InvalidAudienceError`
- `InvalidIssuerError`
- `InvalidSubjectError`
- `InvalidAlgorithmError`
- `MissingRequiredClaimError`
- `InvalidTokenError`
- `DecodeError`
- `InvalidKeyError`

## `decode_complete`

Same parameters as `decode`, but returns a dict with `payload`, `header`, and `signature` (bytes), matching common PyJWT usage.

## `get_unverified_header`

```python
def get_unverified_header(token: str) -> dict[str, Any]: ...
```

Returns the JWT header without verifying the token. Use this for inspection or key lookup only.

## `decode_unverified`

```python
def decode_unverified(token: str) -> dict[str, Any]: ...
```

Returns claims without verifying the signature or validating registered claims. Do not use this for authentication or authorization.

## `EncodingKey`

```python
class EncodingKey:
    @staticmethod
    def from_secret(secret: str | bytes) -> EncodingKey: ...

    @staticmethod
    def from_rsa_pem(pem: str | bytes) -> EncodingKey: ...

    @staticmethod
    def from_ec_pem(pem: str | bytes) -> EncodingKey: ...

    @staticmethod
    def from_ed_pem(pem: str | bytes) -> EncodingKey: ...
```

Use `EncodingKey` for signing tokens.

## `DecodingKey`

```python
class DecodingKey:
    @staticmethod
    def from_secret(secret: str | bytes) -> DecodingKey: ...

    @staticmethod
    def from_rsa_pem(pem: str | bytes) -> DecodingKey: ...

    @staticmethod
    def from_ec_pem(pem: str | bytes) -> DecodingKey: ...

    @staticmethod
    def from_ed_pem(pem: str | bytes) -> DecodingKey: ...

    @staticmethod
    def from_jwk(jwk: str | Mapping[str, Any]) -> DecodingKey: ...
```

Use `DecodingKey` for verifying tokens.

## Exceptions

All OxyJWT exceptions inherit from `OxyJWTError`. The layout matches PyJWT: `InvalidTokenError` is the common base for most decode-time errors; `DecodeError` and `InvalidSignatureError` nest under it.

```text
OxyJWTError
├── EncodeError
├── InvalidKeyError
└── InvalidTokenError
    ├── DecodeError
    │   └── InvalidSignatureError
    ├── ExpiredSignatureError
    ├── ImmatureSignatureError
    ├── InvalidAudienceError
    ├── InvalidIssuerError
    ├── InvalidIssuedAtError
    ├── InvalidSubjectError
    ├── InvalidAlgorithmError
    └── MissingRequiredClaimError
```
