# OxyJWT

OxyJWT is a Python JWT/JWS library with a Rust implementation underneath. It gives Python code a **PyJWT-compatible** `encode` / `decode` / `decode_complete` API (plus JWK helpers) while keeping verified decoding tied to an explicit `algorithms` list by default. See [Migration from PyJWT](usage/migration-pyjwt.md) for exception hierarchy changes in **0.2.0**.

The short version:

```python
import time

import oxyjwt

secret = "super-secret"

token = oxyjwt.encode(
    {
        "sub": "user-123",
        "role": "admin",
        "aud": "api",
        "iss": "auth-service",
        "exp": int(time.time()) + 3600,
    },
    secret,
    algorithm="HS256",
)

claims = oxyjwt.decode(
    token,
    secret,
    algorithms=["HS256"],
    audience="api",
    issuer="auth-service",
)
```

!!! warning "Always pass `algorithms`"
    OxyJWT intentionally requires an allowed algorithm list when decoding. Do not read the algorithm from the token header and feed it back into verification.

## What OxyJWT Does

OxyJWT signs and verifies JWT/JWS tokens. It supports:

- HMAC: `HS256`, `HS384`, `HS512`
- RSA: `RS256`, `RS384`, `RS512`
- RSA-PSS: `PS256`, `PS384`, `PS512`
- ECDSA: `ES256`, `ES384`
- EdDSA: `EdDSA`

It does not implement JWE encryption in the first version.

## Where To Go Next

- Start with [Getting Started](getting-started.md) if you want the first working token.
- Read [Security](security.md) before using JWTs for authentication or authorization.
- Use [API Reference](api-reference.md) when you need exact function signatures.
