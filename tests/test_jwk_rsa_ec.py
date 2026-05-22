"""RSA and EC JWK / JWKS parity with PyJWT (issue #27)."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import oxyjwt
from oxyjwt.jwk import PyJWK, PyJWKSet


def _b64u_int(value: int) -> str:
    length = (value.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode().rstrip("=")


def _private_pem(key: object) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def rsa_jwk_dict(key: rsa.RSAPrivateKey, *, kid: str = "rsa-k1") -> dict[str, Any]:
    pub = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u_int(pub.n),
        "e": _b64u_int(pub.e),
    }


def ec_jwk_dict(
    key: ec.EllipticCurvePrivateKey,
    *,
    crv: str,
    alg: str,
    kid: str,
) -> dict[str, Any]:
    pub = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "crv": crv,
        "x": _b64u_int(pub.x),
        "y": _b64u_int(pub.y),
    }


@dataclass(frozen=True)
class _AsymmetricFixture:
    private_key: object
    algorithm: str
    jwk: dict[str, Any]
    encoding_key: object


@pytest.fixture(scope="module")
def rsa_material() -> _AsymmetricFixture:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _AsymmetricFixture(
        private_key=key,
        algorithm="RS256",
        jwk=rsa_jwk_dict(key, kid="issuer-rsa-2024"),
        encoding_key=oxyjwt.EncodingKey.from_rsa_pem(_private_pem(key)),
    )


@pytest.fixture(scope="module")
def ec256_material() -> _AsymmetricFixture:
    key = ec.generate_private_key(ec.SECP256R1())
    return _AsymmetricFixture(
        private_key=key,
        algorithm="ES256",
        jwk=ec_jwk_dict(key, crv="P-256", alg="ES256", kid="issuer-ec-p256"),
        encoding_key=oxyjwt.EncodingKey.from_ec_pem(_private_pem(key)),
    )


@pytest.fixture(scope="module")
def ec384_material() -> _AsymmetricFixture:
    key = ec.generate_private_key(ec.SECP384R1())
    return _AsymmetricFixture(
        private_key=key,
        algorithm="ES384",
        jwk=ec_jwk_dict(key, crv="P-384", alg="ES384", kid="issuer-ec-p384"),
        encoding_key=oxyjwt.EncodingKey.from_ec_pem(_private_pem(key)),
    )


def _payload() -> dict[str, int | str]:
    return {"sub": "user-42", "exp": 9_999_999_999}


def _decode_opts() -> dict[str, bool]:
    return {"verify_exp": False}


@pytest.mark.parametrize(
    "fixture_name",
    ["rsa_material", "ec256_material", "ec384_material"],
)
def test_pyjwk_asymmetric_decode_parity(
    fixture_name: str, request: pytest.FixtureRequest
) -> None:
    material: _AsymmetricFixture = request.getfixturevalue(fixture_name)
    token = oxyjwt.encode(
        _payload(),
        material.encoding_key,
        algorithm=material.algorithm,
        headers={"kid": material.jwk["kid"]},
    )
    j_jwk = jwt.PyJWK.from_dict(material.jwk)
    o_jwk = PyJWK.from_dict(material.jwk)
    assert jwt.decode(
        token,
        j_jwk.key,
        algorithms=[material.algorithm],
        options=_decode_opts(),
    ) == oxyjwt.decode(
        token,
        o_jwk.key,
        algorithms=[material.algorithm],
        options=_decode_opts(),
    )


def test_pyjwk_rsa_metadata() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = PyJWK(rsa_jwk_dict(key, kid="meta-rsa"))
    assert jwk.key_type == "RSA"
    assert jwk.key_id == "meta-rsa"
    assert jwk.public_key_use == "sig"


def test_pyjwk_ec_metadata() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = PyJWK(ec_jwk_dict(key, crv="P-256", alg="ES256", kid="meta-ec"))
    assert jwk.key_type == "EC"
    assert jwk.key_id == "meta-ec"
    assert jwk.public_key_use == "sig"


def test_jwks_set_rsa_and_ec_shapes_parity(
    rsa_material: _AsymmetricFixture,
    ec256_material: _AsymmetricFixture,
) -> None:
    """JWKS document with multiple asymmetric keys (typical IdP shape)."""
    jwks_dict = {
        "keys": [rsa_material.jwk, ec256_material.jwk],
    }
    j_set = jwt.PyJWKSet.from_dict(jwks_dict)
    o_set = PyJWKSet.from_dict(jwks_dict)

    rsa_token = oxyjwt.encode(
        _payload(),
        rsa_material.encoding_key,
        algorithm="RS256",
        headers={"kid": rsa_material.jwk["kid"]},
    )
    ec_token = oxyjwt.encode(
        _payload(),
        ec256_material.encoding_key,
        algorithm="ES256",
        headers={"kid": ec256_material.jwk["kid"]},
    )

    opts = _decode_opts()
    assert jwt.decode(
        rsa_token,
        j_set[rsa_material.jwk["kid"]].key,
        algorithms=["RS256"],
        options=opts,
    ) == oxyjwt.decode(
        rsa_token,
        o_set[rsa_material.jwk["kid"]].key,
        algorithms=["RS256"],
        options=opts,
    )
    assert jwt.decode(
        ec_token,
        j_set[ec256_material.jwk["kid"]].key,
        algorithms=["ES256"],
        options=opts,
    ) == oxyjwt.decode(
        ec_token,
        o_set[ec256_material.jwk["kid"]].key,
        algorithms=["ES256"],
        options=opts,
    )
