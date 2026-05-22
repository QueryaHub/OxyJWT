"""Typing smoke checks for the public API (run under mypy in CI)."""
from __future__ import annotations

import ssl
from datetime import timedelta

import oxyjwt
from oxyjwt import DecodingKey, EncodingKey, PyJWK, PyJWKClient, PyJWKSet, PyJWT


def exercise_public_api() -> None:
    tok: str = oxyjwt.encode(
        {"sub": "user", "exp": 9_999_999_999},
        "secret",
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    claims: dict[str, object] = oxyjwt.decode(
        tok,
        "secret",
        algorithms=["HS256"],
        audience="api",
        issuer="issuer",
        subject="user",
        leeway=timedelta(seconds=5),
        options={"strict_aud": False},
    )
    _ = claims["sub"]

    complete = oxyjwt.decode_complete(tok, "secret", algorithms=["HS256"])
    header: dict[str, object] = complete["header"]
    _ = complete["signature"]

    inst = PyJWT(options={"verify_exp": False})
    _ = inst.encode({"a": 1}, "secret")
    _ = inst.decode(tok, "secret", algorithms=["HS256"])

    enc = EncodingKey.from_secret(b"secret")
    dec = DecodingKey.from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n")
    _ = oxyjwt.encode({"x": 1}, enc, algorithm="HS256")

    jwk = PyJWK.from_dict({"kty": "oct", "k": "c2VjcmV0", "kid": "k1"})
    _ = jwk.key_id
    jwks = PyJWKSet.from_dict({"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "k1"}]})
    _ = jwks["k1"].key

    client = PyJWKClient(
        "https://example.invalid/jwks.json",
        require_https=True,
        cache_keys=True,
        headers={"X-Custom": "1"},
        ssl_context=ssl.create_default_context(),
    )
    _ = client.get_jwk_set(refresh=False)

    _ = oxyjwt.get_unverified_header(tok)
    _ = oxyjwt.decode_unverified(tok)
