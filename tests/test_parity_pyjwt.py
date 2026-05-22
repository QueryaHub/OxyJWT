from __future__ import annotations

import base64
import json
import time
from datetime import timedelta

import jwt
import pytest

import oxyjwt


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def test_hs256_encode_decode_parity() -> None:
    payload = {
        "sub": "1",
        "exp": int(time.time()) + 300,
    }
    k = "s3cr3t"
    t_j = jwt.encode(payload, k, algorithm="HS256")
    t_o = oxyjwt.encode(payload, k, algorithm="HS256")
    o_j = jwt.decode(
        t_j,
        k,
        algorithms=["HS256"],
        options={"verify_signature": True},
    )
    o_o = oxyjwt.decode(
        t_j,
        k,
        algorithms=["HS256"],
    )
    assert o_j == o_o
    oxyjwt.decode(t_o, k, algorithms=["HS256"])  # must round-trip oxy token


def test_decode_unverified_parity() -> None:
    payload = {"a": 1, "exp": 9_999_999_999}
    t = oxyjwt.encode(payload, "k", algorithm="HS256")
    assert jwt.decode(
        t,
        options={"verify_signature": False},
    ) == oxyjwt.decode(
        t,
        "k",
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_iat": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )


def test_exception_hierarchy_matches_pyjwt_names() -> None:
    import jwt.exceptions as je

    assert issubclass(oxyjwt.InvalidSignatureError, oxyjwt.DecodeError)
    assert issubclass(oxyjwt.DecodeError, oxyjwt.InvalidTokenError)
    assert issubclass(oxyjwt.ExpiredSignatureError, oxyjwt.InvalidTokenError)
    # Same general shape as PyJWT (names differ: PyJWTError vs OxyJWTError).
    assert issubclass(oxyjwt.InvalidTokenError, oxyjwt.PyJWTError)
    assert issubclass(je.InvalidTokenError, je.PyJWTError)
    assert issubclass(je.DecodeError, je.InvalidTokenError)
    assert issubclass(je.InvalidSignatureError, je.DecodeError)


def test_audience_decode_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {
        "sub": "u",
        "aud": "api",
        "exp": int(time.time()) + 600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    opts: dict = {}
    assert jwt.decode(
        token, secret, algorithms=["HS256"], audience="api", options=opts
    ) == oxyjwt.decode(
        token, secret, algorithms=["HS256"], audience="api", options=opts
    )


def test_strict_aud_decode_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {
        "sub": "u",
        "aud": "api",
        "exp": int(time.time()) + 600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    opts = {"strict_aud": True}
    assert jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience="api",
        options=opts,
    ) == oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience="api",
        options=opts,
    )

    list_aud_token = jwt.encode(
        {**payload, "aud": ["api", "other"]},
        secret,
        algorithm="HS256",
    )
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            list_aud_token,
            secret,
            algorithms=["HS256"],
            audience="api",
            options=opts,
        )
    with pytest.raises(oxyjwt.InvalidAudienceError):
        oxyjwt.decode(
            list_aud_token,
            secret,
            algorithms=["HS256"],
            audience="api",
            options=opts,
        )


def test_issuer_decode_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {
        "sub": "u",
        "iss": "https://issuer.example",
        "exp": int(time.time()) + 600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer="https://issuer.example",
    ) == oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer="https://issuer.example",
    )


def test_issuer_list_decode_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {
        "sub": "u",
        "iss": "https://issuer.example",
        "exp": int(time.time()) + 600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    issuers = ["https://issuer.example", "https://backup.example"]
    assert jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuers,
    ) == oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuers,
    )


def test_subject_decode_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {
        "sub": "user-42",
        "exp": int(time.time()) + 600,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        subject="user-42",
    ) == oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        subject="user-42",
    )


def test_require_claim_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {
        "sub": "u",
        "custom": 1,
        "exp": 9_999_999_999,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    options = {
        "verify_signature": True,
        "verify_exp": False,
        "verify_nbf": False,
        "verify_iat": False,
        "require": ["sub", "custom"],
    }
    assert jwt.decode(
        token, secret, algorithms=["HS256"], options=options
    ) == oxyjwt.decode(token, secret, algorithms=["HS256"], options=options)


def test_fractional_leeway_exp_boundary_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    now = int(time.time())
    # exp must be strictly after int(now): PyJWT compares exp to float time.time(),
    # so exp==now fails for most of each second (parity flake on CI).
    payload = {"sub": "u", "exp": now + 1}
    token = jwt.encode(payload, secret, algorithm="HS256")
    assert jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        leeway=0.9,
    ) == oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        leeway=0.9,
    )


def test_leeway_timedelta_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    now = int(time.time())
    payload = {"sub": "u", "exp": now + 2}
    token = jwt.encode(payload, secret, algorithm="HS256")
    leeway = timedelta(seconds=10)
    assert jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        leeway=leeway,
    ) == oxyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        leeway=leeway,
    )


def test_decode_complete_shape_parity() -> None:
    secret = "hmac-secret-32-bytes-long-ok!!!"
    payload = {"sub": "1", "exp": int(time.time()) + 300}
    token = jwt.encode(payload, secret, algorithm="HS256")
    cj = jwt.decode_complete(token, secret, algorithms=["HS256"])
    co = oxyjwt.decode_complete(token, secret, algorithms=["HS256"])
    assert cj["payload"] == co["payload"]
    assert json.loads(json.dumps(cj["header"])) == json.loads(
        json.dumps(co["header"])
    )
    assert cj["signature"] == co["signature"]


def test_symmetric_jwk_decode_parity() -> None:
    secret = b"symmetric-key-32-bytes-long-ok"
    jwk_dict = {"kty": "oct", "k": _b64u(secret)}
    payload = {"sub": "1", "exp": int(time.time()) + 300}
    token = jwt.encode(payload, secret, algorithm="HS256")
    j_jwk = jwt.PyJWK.from_dict(jwk_dict)
    o_jwk = oxyjwt.PyJWK.from_dict(jwk_dict)
    assert jwt.decode(token, j_jwk.key, algorithms=["HS256"]) == oxyjwt.decode(
        token, o_jwk.key, algorithms=["HS256"]
    )


def test_jwks_set_decode_parity() -> None:
    secret = b"symmetric-key-32-bytes-long-ok"
    jwks_dict = {
        "keys": [{"kty": "oct", "kid": "k1", "k": _b64u(secret)}],
    }
    j_set = jwt.PyJWKSet.from_dict(jwks_dict)
    o_set = oxyjwt.PyJWKSet.from_dict(jwks_dict)
    token = oxyjwt.encode(
        {"sub": "1", "exp": 9_999_999_999},
        secret,
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    kj = j_set["k1"].key
    ko = o_set["k1"].key
    opts = {"verify_exp": False}
    assert jwt.decode(token, kj, algorithms=["HS256"], options=opts) == oxyjwt.decode(
        token, ko, algorithms=["HS256"], options=opts
    )
