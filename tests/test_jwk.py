from __future__ import annotations

import base64
import json

import pytest

import oxyjwt
from oxyjwt.jwk import PyJWK, PyJWKSet
from oxyjwt.jwk_exc import PyJWKSetError


def _oct_jwk_for_secret(secret: bytes) -> str:
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    return json.dumps({"kty": "oct", "k": k, "kid": "k1"})


def test_pyjwk_from_json_hs256() -> None:
    jw = _oct_jwk_for_secret(b"my-secret")
    a = PyJWK(jw)
    t = oxyjwt.encode({"exp": 9_999_999_999}, b"my-secret", algorithm="HS256")
    oxyjwt.decode(
        t,
        a.key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )


def test_pyjwkset_from_dict() -> None:
    jw = json.loads(_oct_jwk_for_secret(b"x"))
    s = PyJWKSet.from_dict({"keys": [jw]})
    key = s["k1"]
    tok = oxyjwt.encode({"x": 1, "exp": 9_999_999_999}, b"x", algorithm="HS256")
    oxyjwt.decode(
        tok,
        key.key,
        algorithms=["HS256"],
    )


def test_pyjwkset_empty_keys_raises() -> None:
    with pytest.raises(PyJWKSetError):
        PyJWKSet.from_dict({"keys": []})
