# Handling Errors

OxyJWT raises package-specific exceptions so application code can distinguish expired tokens, bad signatures, invalid keys, and malformed input.

## Basic Pattern

```python
try:
    claims = oxyjwt.decode(
        token,
        key,
        algorithms=["HS256"],
        audience="api",
        issuer="auth-service",
    )
except oxyjwt.ExpiredSignatureError:
    print("Token expired.")
except oxyjwt.InvalidTokenError:
    print("Token is invalid.")
```

## Exception Hierarchy

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

## Common Errors

| Exception | Typical cause |
| --- | --- |
| `ExpiredSignatureError` | `exp` is in the past. |
| `ImmatureSignatureError` | `nbf` is in the future. |
| `InvalidSignatureError` | Token signature does not match the key. |
| `InvalidAudienceError` | Token `aud` does not match `audience`. |
| `InvalidIssuerError` | Token `iss` does not match `issuer`. |
| `InvalidAlgorithmError` | Unsupported algorithm, `none`, empty allow-list, or mismatched key family. |
| `MissingRequiredClaimError` | A claim listed in `require` is missing. |
| `InvalidKeyError` | Key material cannot be parsed or is used with the wrong API. |

## Authentication Failures

For login/session middleware, it is often enough to treat all invalid tokens the same:

```python
try:
    claims = oxyjwt.decode(token, key, algorithms=["RS256"], audience="api")
except oxyjwt.InvalidTokenError:
    return unauthorized()
```

Avoid returning detailed token validation errors to untrusted clients. Detailed errors are useful in logs and tests, but they can leak information about your validation setup.
