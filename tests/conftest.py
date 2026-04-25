from __future__ import annotations

from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import oxyjwt


@dataclass(frozen=True)
class KeyPair:
    encoding_key: object
    decoding_key: object


def _private_pem(key: object) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _public_pem(key: object) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="session")
def rsa_pair() -> KeyPair:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return KeyPair(
        oxyjwt.EncodingKey.from_rsa_pem(_private_pem(key)),
        oxyjwt.DecodingKey.from_rsa_pem(_public_pem(key)),
    )


@pytest.fixture(scope="session")
def ec256_pair() -> KeyPair:
    key = ec.generate_private_key(ec.SECP256R1())
    return KeyPair(
        oxyjwt.EncodingKey.from_ec_pem(_private_pem(key)),
        oxyjwt.DecodingKey.from_ec_pem(_public_pem(key)),
    )


@pytest.fixture(scope="session")
def ec384_pair() -> KeyPair:
    key = ec.generate_private_key(ec.SECP384R1())
    return KeyPair(
        oxyjwt.EncodingKey.from_ec_pem(_private_pem(key)),
        oxyjwt.DecodingKey.from_ec_pem(_public_pem(key)),
    )


@pytest.fixture(scope="session")
def ed_pair() -> KeyPair:
    key = ed25519.Ed25519PrivateKey.generate()
    return KeyPair(
        oxyjwt.EncodingKey.from_ed_pem(_private_pem(key)),
        oxyjwt.DecodingKey.from_ed_pem(_public_pem(key)),
    )
