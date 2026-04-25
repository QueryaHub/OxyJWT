# Getting Started

This page gets you from an empty Python file to a signed and verified JWT.

## Install

```bash
pip install oxyjwt
```

OxyJWT requires Python 3.10 or newer.

## Create A Token

JWT payloads are ordinary JSON-compatible Python mappings. Registered claims such as `sub`, `aud`, `iss`, and `exp` are not required for signing, but they are what make verification meaningful.

```python
import time

import oxyjwt

secret = "change-me"
payload = {
    "sub": "user-123",
    "role": "admin",
    "aud": "api",
    "iss": "auth-service",
    "exp": int(time.time()) + 3600,
}

token = oxyjwt.encode(payload, secret, algorithm="HS256")
print(token)
```

## Verify A Token

Verification is where most JWT bugs happen. OxyJWT makes the algorithm allow-list explicit:

```python
claims = oxyjwt.decode(
    token,
    secret,
    algorithms=["HS256"],
    audience="api",
    issuer="auth-service",
)

print(claims["sub"])
```

If the token is expired, signed with the wrong key, or has the wrong audience or issuer, `decode` raises an OxyJWT exception.

## Handle Errors

Catch specific errors when your application needs different behavior, and catch `InvalidTokenError` for a general authentication failure:

```python
try:
    claims = oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience="api",
        issuer="auth-service",
    )
except oxyjwt.ExpiredSignatureError:
    print("Please sign in again.")
except oxyjwt.InvalidTokenError:
    print("The token is not valid.")
```

## Next Steps

- Learn signing options in [Encoding tokens](usage/encoding.md).
- Learn validation controls in [Decoding tokens](usage/decoding.md).
- Review the security checklist in [Security](security.md).
