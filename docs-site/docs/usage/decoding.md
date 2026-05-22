# Decoding Tokens

Use `oxyjwt.decode` when you want to verify a token and return its claims.

```python
claims = oxyjwt.decode(token, key, algorithms=["HS256"])
```

## Algorithms Are Required

`algorithms` is required on purpose:

```python
claims = oxyjwt.decode(
    token,
    "super-secret",
    algorithms=["HS256"],
)
```

Do not read the algorithm from the token header and pass it back into `decode`. The allowed algorithms must come from your server-side configuration.

## Audience And Issuer

Validate `aud` and `iss` whenever your tokens include those claims:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["RS256"],
    audience="api",
    issuer="https://auth.example.com",
)
```

You can pass one value or multiple values:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["RS256"],
    audience=["api", "mobile-api"],
    issuer=["https://auth.example.com", "https://backup-auth.example.com"],
)
```

## Subject

Use `subject` when the token must belong to one known subject:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["HS256"],
    subject="user-123",
)
```

## Leeway

`leeway` allows small clock differences between systems. It is measured in seconds.

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["HS256"],
    leeway=30,
)
```

Keep leeway small. Large values make expired or not-yet-valid tokens valid for longer than intended.

## Required Claims

Use `require` when a claim must be present:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["HS256"],
    require=["exp", "sub"],
)
```

Presence is not the same as business validation. For example, requiring `sub` only means the claim exists; your app still decides which subjects are allowed.

## Options

`options` controls validation switches. Values set on a `PyJWT(options={...})` instance are merged with the dict passed to each `decode` call.

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["HS256"],
    options={
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_iat": True,
        "verify_aud": True,
        "verify_iss": True,
    },
)
```

Supported options:

- `verify_signature` — verify the JWS signature (default `True`). When `False`, `algorithms` is not required; treat claims as untrusted.
- `verify_exp` — validate `exp` (Rust/jsonwebtoken on verified decode; Python on unverified decode).
- `verify_nbf` — validate `nbf` (Rust on verified decode; Python on unverified decode).
- `verify_iat` — validate `iat` (always Python; jsonwebtoken does not implement `iat` checks).
- `verify_aud` — validate `aud` when `audience` is provided.
- `verify_iss` — validate `iss` when `issuer` is provided.
- `verify_sub` — validate `sub` when `subject` is provided (defaults to `False` when `verify_signature` is `False`).
- `require_exp` — require the `exp` claim.
- `require` — list of claim names that must be present.

### Where claims are validated

| Claim / check | Verified decode (`verify_signature=True`) | Unverified decode |
|---------------|-------------------------------------------|-------------------|
| Signature, `alg` | Rust (jsonwebtoken) | Skipped |
| `exp`, `nbf` | Rust | Python |
| `iat` | Python | Python |
| `aud`, `iss`, `sub` | Rust when parameters/options enable it; Python also enforces PyJWT-style rules (e.g. `aud` present without an `audience` argument) | Python |

Use integer-second `leeway` for consistent `exp`/`nbf` behavior on verified decode (Rust uses whole seconds). Fractional leeway applies fully to `iat` (Python).

!!! warning "`verify_signature=False` is not the same as `decode_unverified`"

    With `verify_signature=False`, OxyJWT still parses the compact JWT and can run claim checks according to your `options`. OxyJWT emits `InsecureDecodeWarning` when signature verification is disabled.

    The `subject` argument is **ignored** unless you set `options["verify_sub"]` to `True` (off by default when `verify_signature` is `False`). Even then, subject matching does not prove the token was signed by your issuer—use verified decode in production.

    `options["require"]` only checks that claims are **present**, not authentic, when the signature is not verified.

    You still must not trust `sub`, roles, or other claims for authorization unless you have another integrity guarantee.

    `decode_unverified` and `get_unverified_header` are for inspection and debugging only; they skip cryptographic verification entirely.

## Unverified Helpers

These helpers do not authenticate a token:

```python
header = oxyjwt.get_unverified_header(token)
claims = oxyjwt.decode_unverified(token)
```

Use them for debugging, key lookup, or inspection flows. Never use their output to authorize a request.
