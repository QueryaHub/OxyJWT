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

`options` controls a small set of validation switches:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["HS256"],
    options={"verify_exp": True, "verify_nbf": True, "verify_aud": True},
)
```

Supported options:

- `verify_exp`: validate `exp`.
- `verify_nbf`: validate `nbf`.
- `verify_aud`: validate `aud` when `audience` is provided.
- `require_exp`: require the `exp` claim.

`verify_signature=False` is not supported in `decode`. Use `decode_unverified` only when you intentionally need unauthenticated inspection.

## Unverified Helpers

These helpers do not authenticate a token:

```python
header = oxyjwt.get_unverified_header(token)
claims = oxyjwt.decode_unverified(token)
```

Use them for debugging, key lookup, or inspection flows. Never use their output to authorize a request.
