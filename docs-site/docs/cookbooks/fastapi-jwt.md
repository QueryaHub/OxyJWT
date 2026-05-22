# FastAPI: verify JWT access tokens

This recipe shows a minimal dependency that decodes a bearer JWT with OxyJWT. Adjust `algorithms`, `audience`, and `issuer` to match your identity provider.

```python
from typing import Annotated, Any

import oxyjwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer(auto_error=False)

# Load verification key from config / env in real apps.
VERIFICATION_KEY = oxyjwt.DecodingKey.from_rsa_pem(
    """-----BEGIN PUBLIC KEY-----
... paste your JWKS-derived or PEM public key ...
-----END PUBLIC KEY-----"""
)
ALLOWED_ALGORITHMS = ["RS256"]
AUDIENCE = "api"
ISSUER = "https://auth.example.com"


async def current_subject(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> dict[str, Any]:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )
    try:
        return oxyjwt.decode(
            creds.credentials,
            VERIFICATION_KEY,
            algorithms=ALLOWED_ALGORITHMS,
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except oxyjwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except oxyjwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


# Example route:
# @app.get("/me")
# async def me(claims: Annotated[dict, Depends(current_subject)]):
#     return {"sub": claims.get("sub")}
```

## JWKS rotation

If your provider publishes rotating keys, use `oxyjwt.PyJWKClient` to resolve `kid` from the token header, then pass the resulting `PyJWK.key` into `decode`. Cache behavior is described on the [API reference](../api-reference.md) page for `PyJWKClient`.

## Security reminders

- Never build the `algorithms` list from unverified token headers.
- Keep leeway small (seconds), not hours.
- Log generic authentication failures; avoid echoing token parsing details to clients.

See the main [Security](../security.md) page for the full checklist.
