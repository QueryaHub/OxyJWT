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
    token: str,
    key: str | bytes | DecodingKey,
    algorithms: Sequence[str],
    *,
    audience: str | Sequence[str] | None = None,
    issuer: str | Sequence[str] | None = None,
    subject: str | None = None,
    leeway: int = 0,
    options: Mapping[str, bool] | None = None,
    require: Sequence[str] | None = None,
) -> dict[str, Any]: ...
```

Verifies `token` and returns its claims as a Python dict.

Parameters:

- `token`: compact JWT string.
- `key`: raw HMAC secret or a `DecodingKey`.
- `algorithms`: required server-side allow-list.
- `audience`: expected `aud` value or values.
- `issuer`: expected `iss` value or values.
- `subject`: expected `sub` value.
- `leeway`: clock tolerance in seconds.
- `options`: validation switches.
- `require`: claims that must be present.

Supported `options` keys:

- `verify_exp`
- `verify_nbf`
- `verify_aud`
- `require_exp`

`verify_signature=False` is intentionally rejected by `decode`.

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
- `InvalidKeyError`

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

All OxyJWT exceptions inherit from `OxyJWTError`.

```text
OxyJWTError
├── EncodeError
├── DecodeError
│   └── InvalidTokenError
│       ├── InvalidSignatureError
│       ├── ExpiredSignatureError
│       ├── ImmatureSignatureError
│       ├── InvalidAudienceError
│       ├── InvalidIssuerError
│       ├── InvalidSubjectError
│       ├── InvalidAlgorithmError
│       └── MissingRequiredClaimError
└── InvalidKeyError
```
