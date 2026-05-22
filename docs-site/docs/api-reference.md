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
    issuer: str | Iterable[str] | None = None,
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
- `issuer`: expected `iss` value, or an iterable of allowed issuers (token `iss` must match one).
- `leeway`: clock tolerance in seconds or as a `timedelta`.
- `options`: validation switches (see below). Values from a `PyJWT(..., options=...)` instance are merged with per-call `options`.
- `detached_payload`: not supported; raises `NotImplementedError` if set.

Supported `options` keys (booleans unless noted):

- `verify_signature` — verify the JWS signature (default `True`).
- `verify_exp`, `verify_nbf`, `verify_iat`, `verify_aud`, `verify_iss`, `verify_sub`, `strict_aud`
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

## `PyJWKClient`

HTTP client for fetching a [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) document and resolving signing keys by `kid`. Uses the Python standard library (`urllib`) only — no extra HTTP dependencies.

Typical flow with an identity provider that publishes rotating RSA/EC keys:

```python
import oxyjwt

client = oxyjwt.PyJWKClient(
    "https://auth.example.com/.well-known/jwks.json",
    require_https=True,
    headers={"Authorization": "Bearer <service-token>"},
)

token = "<compact-jwt-from-client>"
signing_key = client.get_signing_key_from_jwt(
    token,
    algorithms=["RS256"],  # server-side allow-list; checked before HTTP
)
claims = oxyjwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="api",
    issuer="https://auth.example.com",
)
```

See also the [FastAPI cookbook](cookbooks/fastapi-jwt.md) and [Security — JWKS](security.md#jwks-pyjwkclient).

### Two-tier caching

| Tier | Option | Default | Behavior |
|------|--------|---------|----------|
| **1 — JWK Set** | `cache_jwk_set`, `lifespan` | on, 300s | Caches the parsed JWKS JSON. Refetch when TTL expires or `get_jwk_set(refresh=True)`. |
| **2 — signing keys** | `cache_keys`, `max_cached_keys` | off, 16 | LRU of `PyJWK` objects by `kid` (no time expiry). Opt-in; matches PyJWT default. |

On `get_signing_key`, if `kid` is missing from the current set, the client refetches JWKS **once** and retries (key rotation). A second miss raises `KeyError` (no further HTTP retries in that call).

### Constructor

```python
class PyJWKClient:
    def __init__(
        self,
        uri: str,
        *,
        cache_jwk_set: bool = True,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        timeout: float = 30.0,
        max_bytes: int = 262_144,
        require_https: bool = False,
        headers: Mapping[str, Any] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        lifespan: float = 300.0,
    ) -> None: ...
```

| Parameter | Description |
|-----------|-------------|
| `uri` | JWKS endpoint URL (`http://` or `https://`). |
| `cache_jwk_set` | Cache the fetched JWKS document (tier 1). |
| `lifespan` | Seconds before tier-1 cache expires; must be &gt; 0 when `cache_jwk_set=True`. |
| `cache_keys` | Enable per-`kid` signing-key LRU (tier 2). Default `False` (PyJWT parity). |
| `max_cached_keys` | Max LRU entries when `cache_keys=True`. |
| `timeout` | HTTP GET timeout in seconds. |
| `max_bytes` | Max JWKS response size (default 256 KiB). Larger bodies raise `PyJWKClientError`. |
| `require_https` | When `True`, reject non-HTTPS `uri` values. |
| `headers` | Extra request headers merged with `User-Agent` and `Accept: application/json`. |
| `ssl_context` | `ssl.SSLContext` for HTTPS (default `ssl.create_default_context()`). |

Raises `ValueError` for invalid `uri` / `max_bytes`; `TypeError` for invalid `ssl_context`; `PyJWKClientError` when `require_https` blocks the URI or `lifespan` is invalid.

### `get_jwk_set`

```python
def get_jwk_set(self, refresh: bool = False) -> PyJWKSet: ...
```

Returns a `PyJWKSet` parsed from the endpoint. When `refresh=False` and tier-1 cache is valid, returns the cached set without HTTP. When `refresh=True`, always fetches a new document and updates the cache (clears tier-2 LRU entries).

Raises `PyJWKClientConnectionError` on network/timeout failures; `PyJWKClientError` on oversized body or invalid JSON shape.

### `get_signing_key`

```python
def get_signing_key(self, kid: str) -> PyJWK: ...
```

Returns the `PyJWK` for `kid`. Uses tier-1 cache, then tier-2 LRU if enabled. Refetches JWKS once on `KeyError` (rotation). Empty `kid` raises `PyJWKClientError`.

### `get_signing_key_from_jwt`

```python
def get_signing_key_from_jwt(
    self,
    jwt: str | bytes,
    algorithms: list[str] | None = None,
) -> PyJWK: ...
```

Reads `kid` (and optionally `alg`) from the token header via `get_unverified_header`, then calls `get_signing_key`.

When `algorithms` is provided:

- empty list → `InvalidAlgorithmError`;
- header `alg` not in the list → `InvalidAlgorithmError` **before** any JWKS HTTP request;
- `none` → `InvalidAlgorithmError`.

Missing or empty `kid` → `PyJWKClientError`.

### Security notes

- Pass your server-side **`algorithms`** allow-list to `get_signing_key_from_jwt` and again to `decode` — do not trust the header `alg` alone. See [Security](security.md).
- Prefer **`require_https=True`** in production.
- Use **`max_bytes`** to limit denial-of-service from huge JWKS responses.
- `get_unverified_header` inside `get_signing_key_from_jwt` does not verify the signature; only use the returned `PyJWK.key` with verified `decode`. Details: [SECURITY.md](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md) and [Security — unverified helpers](security.md#treat-unverified-helpers-as-inspection-only).
- Encryption keys (`use: enc`) in the JWKS are rejected when building `PyJWK`; skipped entries emit `PyJWKSetSkipWarning`.

### Related exceptions

- `PyJWKClientError` — invalid client configuration, JWKS shape, size limits, missing `kid`.
- `PyJWKClientConnectionError` — HTTP/URL errors (subclass of `PyJWKClientError`).
- `KeyError` — `kid` not found after one refresh attempt.
- `InvalidAlgorithmError` — disallowed `alg` when `algorithms` is passed to `get_signing_key_from_jwt`.

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
