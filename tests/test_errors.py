from __future__ import annotations

import time

import pytest

import oxyjwt


def test_invalid_signature_error() -> None:
    token = oxyjwt.encode({"exp": int(time.time()) + 60}, "secret")

    with pytest.raises(oxyjwt.InvalidSignatureError):
        oxyjwt.decode(token, "wrong-secret", algorithms=["HS256"])


def test_malformed_token_error() -> None:
    with pytest.raises(oxyjwt.InvalidTokenError):
        oxyjwt.decode("not-a-jwt", "secret", algorithms=["HS256"])


def test_raw_key_is_rejected_for_asymmetric_algorithms() -> None:
    with pytest.raises(oxyjwt.InvalidKeyError):
        oxyjwt.encode(
            {"exp": int(time.time()) + 60},
            "not-a-pem",
            algorithm="RS256",
        )


def test_header_alg_cannot_override_algorithm() -> None:
    with pytest.raises(oxyjwt.InvalidAlgorithmError):
        oxyjwt.encode(
            {"exp": int(time.time()) + 60},
            "secret",
            algorithm="HS256",
            headers={"alg": "RS256"},
        )


def test_payload_must_be_object() -> None:
    with pytest.raises(TypeError):
        oxyjwt.encode(["not", "an", "object"], "secret")


def test_exception_hierarchy_pyjwt_shape() -> None:
    assert issubclass(oxyjwt.DecodeError, oxyjwt.InvalidTokenError)
    assert issubclass(oxyjwt.InvalidSignatureError, oxyjwt.DecodeError)
    assert issubclass(oxyjwt.ExpiredSignatureError, oxyjwt.InvalidTokenError)
    assert oxyjwt.PyJWTError is oxyjwt.OxyJWTError
