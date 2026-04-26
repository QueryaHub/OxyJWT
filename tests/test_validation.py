from __future__ import annotations

import time

import pytest

import oxyjwt


def test_decode_requires_algorithms() -> None:
    token = oxyjwt.encode({"exp": int(time.time()) + 60}, "secret")

    with pytest.raises(oxyjwt.DecodeError):
        oxyjwt.decode(token, "secret", algorithms=[])


def test_none_algorithm_is_rejected() -> None:
    with pytest.raises(oxyjwt.InvalidAlgorithmError):
        oxyjwt.encode({"sub": "user"}, "secret", algorithm="none")


def test_expired_token_raises_specific_error() -> None:
    token = oxyjwt.encode({"exp": int(time.time()) - 1}, "secret")

    with pytest.raises(oxyjwt.ExpiredSignatureError):
        oxyjwt.decode(token, "secret", algorithms=["HS256"])


def test_immature_token_raises_specific_error() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "nbf": int(time.time()) + 3600},
        "secret",
    )

    with pytest.raises(oxyjwt.ImmatureSignatureError):
        oxyjwt.decode(token, "secret", algorithms=["HS256"])


def test_audience_validation() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "aud": "api"},
        "secret",
    )

    with pytest.raises(oxyjwt.InvalidAudienceError):
        oxyjwt.decode(token, "secret", algorithms=["HS256"], audience="other")


def test_issuer_validation() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "iss": "issuer"},
        "secret",
    )

    with pytest.raises(oxyjwt.InvalidIssuerError):
        oxyjwt.decode(token, "secret", algorithms=["HS256"], issuer="other")


def test_required_claim_validation() -> None:
    token = oxyjwt.encode({"sub": "user"}, "secret")

    with pytest.raises(oxyjwt.MissingRequiredClaimError):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            options={"verify_exp": False, "require": ["exp"]},
        )


def test_mixed_algorithm_families_are_rejected() -> None:
    token = oxyjwt.encode({"exp": int(time.time()) + 60}, "secret")

    with pytest.raises(oxyjwt.InvalidAlgorithmError):
        oxyjwt.decode(token, "secret", algorithms=["HS256", "RS256"])


def test_verify_signature_false_skips_signature() -> None:
    token = oxyjwt.encode({"sub": "u", "exp": int(time.time()) + 60}, "secret")
    out = oxyjwt.decode(
        token,
        "wrong-secret",
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_iat": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
    assert out["sub"] == "u"
