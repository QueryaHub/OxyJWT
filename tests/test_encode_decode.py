from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest

import oxyjwt


def _payload() -> dict[str, object]:
    return {
        "sub": "user-123",
        "role": "admin",
        "iss": "issuer",
        "aud": "api",
        "exp": int(time.time()) + 3600,
        "nbf": int(time.time()) - 1,
    }


def test_encode_datetime_claim_roundtrip() -> None:
    exp = datetime.now(timezone.utc)
    token = oxyjwt.encode(
        {"sub": "u", "exp": exp},
        "secret",
        algorithm="HS256",
    )
    decoded = oxyjwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert decoded["sub"] == "u"
    assert isinstance(decoded["exp"], int)


def test_decode_complete_returns_header_and_signature() -> None:
    token = oxyjwt.encode(_payload(), "secret", algorithm="HS256", headers={"kid": "k1"})
    out = oxyjwt.decode_complete(
        token,
        "secret",
        algorithms=["HS256"],
        audience="api",
        issuer="issuer",
    )
    assert out["payload"]["sub"] == "user-123"
    assert out["header"]["alg"] == "HS256"
    assert out["header"]["kid"] == "k1"
    assert isinstance(out["signature"], (bytes, bytearray, memoryview))
    assert len(out["signature"]) > 0


def test_hs256_roundtrip_with_raw_secret() -> None:
    token = oxyjwt.encode(_payload(), "secret", algorithm="HS256", headers={"kid": "key-1"})

    assert oxyjwt.get_unverified_header(token)["kid"] == "key-1"
    assert oxyjwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        audience="api",
        issuer="issuer",
    )["sub"] == "user-123"


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_hmac_key_objects_roundtrip(algorithm: str) -> None:
    token = oxyjwt.encode(
        _payload(),
        oxyjwt.EncodingKey.from_secret("secret"),
        algorithm=algorithm,
    )

    decoded = oxyjwt.decode(
        token,
        oxyjwt.DecodingKey.from_secret("secret"),
        algorithms=[algorithm],
        audience="api",
        issuer="issuer",
    )

    assert decoded["role"] == "admin"


@pytest.mark.parametrize("algorithm", ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
def test_rsa_and_pss_roundtrip(algorithm: str, rsa_pair: object) -> None:
    token = oxyjwt.encode(_payload(), rsa_pair.encoding_key, algorithm=algorithm)
    decoded = oxyjwt.decode(
        token,
        rsa_pair.decoding_key,
        algorithms=[algorithm],
        audience="api",
        issuer="issuer",
    )

    assert decoded["sub"] == "user-123"


def test_es256_roundtrip(ec256_pair: object) -> None:
    token = oxyjwt.encode(_payload(), ec256_pair.encoding_key, algorithm="ES256")
    decoded = oxyjwt.decode(
        token,
        ec256_pair.decoding_key,
        algorithms=["ES256"],
        audience="api",
        issuer="issuer",
    )

    assert decoded["aud"] == "api"


def test_es384_roundtrip(ec384_pair: object) -> None:
    token = oxyjwt.encode(_payload(), ec384_pair.encoding_key, algorithm="ES384")
    decoded = oxyjwt.decode(
        token,
        ec384_pair.decoding_key,
        algorithms=["ES384"],
        audience="api",
        issuer="issuer",
    )

    assert decoded["iss"] == "issuer"


def test_eddsa_roundtrip(ed_pair: object) -> None:
    token = oxyjwt.encode(_payload(), ed_pair.encoding_key, algorithm="EdDSA")
    decoded = oxyjwt.decode(
        token,
        ed_pair.decoding_key,
        algorithms=["EdDSA"],
        audience="api",
        issuer="issuer",
    )

    assert decoded["role"] == "admin"


def test_decode_unverified_is_explicit() -> None:
    token = oxyjwt.encode(_payload(), "secret", algorithm="HS256")

    assert oxyjwt.decode_unverified(token)["sub"] == "user-123"
