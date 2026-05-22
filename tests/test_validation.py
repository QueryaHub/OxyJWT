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


def test_strict_aud_rejects_list_audience_claim() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "aud": ["api", "other"]},
        "secret",
    )
    with pytest.raises(oxyjwt.InvalidAudienceError, match="strict"):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            audience="api",
            options={"strict_aud": True},
        )


def test_strict_aud_rejects_iterable_audience_argument() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "aud": "api"},
        "secret",
    )
    with pytest.raises(oxyjwt.InvalidAudienceError, match="strict"):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            audience=["api"],
            options={"strict_aud": True},
        )


def test_strict_aud_accepts_exact_string_match() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "aud": "api"},
        "secret",
    )
    out = oxyjwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        audience="api",
        options={"strict_aud": True},
    )
    assert out["aud"] == "api"


def test_issuer_validation() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "iss": "issuer"},
        "secret",
    )

    with pytest.raises(oxyjwt.InvalidIssuerError):
        oxyjwt.decode(token, "secret", algorithms=["HS256"], issuer="other")


def test_issuer_list_validation() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "iss": "https://primary.example"},
        "secret",
    )
    allowed = ["https://primary.example", "https://backup.example"]

    out = oxyjwt.decode(
        token, "secret", algorithms=["HS256"], issuer=allowed
    )
    assert out["iss"] == "https://primary.example"

    with pytest.raises(oxyjwt.InvalidIssuerError):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            issuer=["https://backup.example"],
        )


def test_issuer_list_unverified_decode() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "iss": "https://primary.example"},
        "secret",
    )
    with pytest.warns(oxyjwt.InsecureDecodeWarning):
        out = oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            options={"verify_signature": False},
            issuer=["https://primary.example", "https://backup.example"],
        )
    assert out["iss"] == "https://primary.example"


def test_subject_validation() -> None:
    token = oxyjwt.encode(
        {
            "sub": "user-a",
            "exp": int(time.time()) + 3600,
        },
        "secret",
    )

    with pytest.raises(oxyjwt.InvalidSubjectError):
        oxyjwt.decode(token, "secret", algorithms=["HS256"], subject="user-b")


def test_missing_iss_with_issuer_uses_invalid_issuer_error() -> None:
    token = oxyjwt.encode(
        {"sub": "user", "exp": int(time.time()) + 3600},
        "secret",
    )
    with pytest.raises(oxyjwt.InvalidIssuerError, match="Invalid issuer"):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            issuer="https://issuer.example",
        )


def test_issuer_bytes_rejected() -> None:
    token = oxyjwt.encode(
        {"sub": "user", "exp": int(time.time()) + 3600},
        "secret",
    )
    with pytest.raises(TypeError, match="issuer must be a string"):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            issuer=b"https://issuer.example",  # type: ignore[arg-type]
        )


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
    with pytest.warns(oxyjwt.InsecureDecodeWarning, match="signature verification"):
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


def test_unverified_decode_warns_when_subject_ignored() -> None:
    token = oxyjwt.encode(
        {"sub": "attacker", "exp": int(time.time()) + 3600},
        "secret",
    )
    with pytest.warns(oxyjwt.InsecureDecodeWarning) as records:
        out = oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            options={"verify_signature": False},
            subject="victim",
        )
    assert out["sub"] == "attacker"
    messages = [str(w.message) for w in records.list]
    assert any("subject argument is ignored" in m for m in messages)


def test_unverified_decode_subject_with_verify_sub() -> None:
    token = oxyjwt.encode(
        {"sub": "user-a", "exp": int(time.time()) + 3600},
        "secret",
    )
    with pytest.warns(oxyjwt.InsecureDecodeWarning):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            options={"verify_signature": False, "verify_sub": True},
            subject="user-a",
        )

    with pytest.warns(oxyjwt.InsecureDecodeWarning):
        with pytest.raises(oxyjwt.InvalidSubjectError):
            oxyjwt.decode(
                token,
                "secret",
                algorithms=["HS256"],
                options={"verify_signature": False, "verify_sub": True},
                subject="user-b",
            )


def test_verify_sub_false_ignores_subject_on_verified_decode() -> None:
    token = oxyjwt.encode(
        {"sub": "user-a", "exp": int(time.time()) + 3600},
        "secret",
    )
    out = oxyjwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        subject="user-b",
        options={"verify_sub": False},
    )
    assert out["sub"] == "user-a"


def test_iat_future_rejects_on_verified_decode() -> None:
    token = oxyjwt.encode(
        {
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) + 120,
        },
        "secret",
    )
    with pytest.raises(oxyjwt.ImmatureSignatureError, match="iat"):
        oxyjwt.decode(token, "secret", algorithms=["HS256"], leeway=0)


def test_iat_leeway_allows_recent_future_iat() -> None:
    token = oxyjwt.encode(
        {
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) + 30,
        },
        "secret",
    )
    out = oxyjwt.decode(
        token, "secret", algorithms=["HS256"], leeway=60
    )
    assert "iat" in out


def test_verify_iat_false_skips_iat_check() -> None:
    token = oxyjwt.encode(
        {
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()) + 120,
        },
        "secret",
    )
    out = oxyjwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        options={"verify_iat": False},
    )
    assert "iat" in out


def test_fractional_leeway_allows_slightly_future_exp() -> None:
    now = int(time.time())
    token = oxyjwt.encode({"exp": now + 1}, "secret")
    out = oxyjwt.decode(
        token, "secret", algorithms=["HS256"], leeway=0.9
    )
    assert out["exp"] == now + 1


def test_fractional_leeway_still_rejects_clearly_expired_token() -> None:
    now = int(time.time())
    token = oxyjwt.encode({"exp": now - 1}, "secret")
    with pytest.raises(oxyjwt.ExpiredSignatureError):
        oxyjwt.decode(
            token, "secret", algorithms=["HS256"], leeway=0.5
        )


def test_missing_iat_does_not_fail_when_verify_iat_enabled() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600},
        "secret",
    )
    out = oxyjwt.decode(token, "secret", algorithms=["HS256"])
    assert "iat" not in out


def test_unverified_decode_warns_on_require() -> None:
    token = oxyjwt.encode(
        {"sub": "u", "exp": int(time.time()) + 3600},
        "secret",
    )
    with pytest.warns(oxyjwt.InsecureDecodeWarning) as records:
        oxyjwt.decode(
            token,
            "secret",
            options={
                "verify_signature": False,
                "verify_exp": False,
                "require": ["sub"],
            },
        )
    assert any(
        "require" in str(w.message) and "presence" in str(w.message)
        for w in records.list
    )
