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


def test_too_many_compact_segments_rejected_consistently() -> None:
    token = oxyjwt.encode({"exp": int(time.time()) + 60}, "secret", algorithm="HS256")
    extra = f"{token}.extra"
    with pytest.raises(oxyjwt.DecodeError, match="Too many segments"):
        oxyjwt.decode(extra, "secret", algorithms=["HS256"])
    with pytest.raises(oxyjwt.DecodeError, match="Too many segments"):
        oxyjwt.decode_unverified(extra)
    with pytest.raises(oxyjwt.DecodeError, match="Too many segments"):
        oxyjwt.get_unverified_header(extra)


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


def test_decode_rejects_missing_or_non_string_alg_in_header() -> None:
    # {"typ": "JWT"}
    t1 = "eyJ0eXAiOiJKV1QifQ.e30.sig"
    with pytest.raises(oxyjwt.DecodeError, match="missing field `alg` in JWT header"):
        oxyjwt.decode(t1, "secret", algorithms=["HS256"])

    # {"alg": 123}
    t2 = "eyJhbGciOjEyM30.e30.sig"
    with pytest.raises(oxyjwt.DecodeError, match="missing field `alg` in JWT header"):
        oxyjwt.decode(t2, "secret", algorithms=["HS256"])

    # {"alg": null}
    t3 = "eyJhbGciOm51bGx9.e30.sig"
    with pytest.raises(oxyjwt.DecodeError, match="missing field `alg` in JWT header"):
        oxyjwt.decode(t3, "secret", algorithms=["HS256"])


def test_decode_rejects_non_object_header() -> None:
    # [1, 2]
    t1 = "WzEsMl0.e30.sig"
    with pytest.raises(oxyjwt.DecodeError, match="Invalid header string: must be a json object"):
        oxyjwt.decode(t1, "secret", algorithms=["HS256"])

    # "string"
    t2 = "InN0cmluZyI.e30.sig"
    with pytest.raises(oxyjwt.DecodeError, match="Invalid header string: must be a json object"):
        oxyjwt.decode(t2, "secret", algorithms=["HS256"])


def test_decode_rejects_malformed_header_json() -> None:
    # {"alg":
    t = "eyJhbGciOi.e30.sig"
    with pytest.raises(oxyjwt.DecodeError):
        oxyjwt.decode(t, "secret", algorithms=["HS256"])


def test_decode_with_custom_header_fields() -> None:
    token = oxyjwt.encode(
        {"sub": "user42"},
        "a-very-long-secret-key-that-is-secure-32b",
        algorithm="HS256",
        headers={"kid": "my-key-1", "custom": "some-value"},
    )
    claims = oxyjwt.decode(
        token,
        "a-very-long-secret-key-that-is-secure-32b",
        algorithms=["HS256"],
    )
    assert claims == {"sub": "user42"}
