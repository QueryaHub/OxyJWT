from __future__ import annotations

import time

import jwt
import pytest

import oxyjwt


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
        options={"verify_signature": False, "verify_exp": False, "verify_nbf": False, "verify_iat": False, "verify_aud": False, "verify_iss": False},
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
