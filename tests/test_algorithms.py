from __future__ import annotations

import time

import pytest

import oxyjwt


@pytest.mark.parametrize(
    "algorithm",
    [
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "EdDSA",
    ],
)
def test_supported_algorithm_names_are_recognized(
    algorithm: str,
    rsa_pair: object,
    ec256_pair: object,
    ec384_pair: object,
    ed_pair: object,
) -> None:
    payload = {"exp": int(time.time()) + 60}
    if algorithm.startswith("HS"):
        token = oxyjwt.encode(payload, "secret", algorithm=algorithm)
        decoded = oxyjwt.decode(token, "secret", algorithms=[algorithm])
    elif algorithm.startswith(("RS", "PS")):
        token = oxyjwt.encode(payload, rsa_pair.encoding_key, algorithm=algorithm)
        decoded = oxyjwt.decode(token, rsa_pair.decoding_key, algorithms=[algorithm])
    elif algorithm == "ES256":
        token = oxyjwt.encode(payload, ec256_pair.encoding_key, algorithm=algorithm)
        decoded = oxyjwt.decode(token, ec256_pair.decoding_key, algorithms=[algorithm])
    elif algorithm == "ES384":
        token = oxyjwt.encode(payload, ec384_pair.encoding_key, algorithm=algorithm)
        decoded = oxyjwt.decode(token, ec384_pair.decoding_key, algorithms=[algorithm])
    else:
        token = oxyjwt.encode(payload, ed_pair.encoding_key, algorithm=algorithm)
        decoded = oxyjwt.decode(token, ed_pair.decoding_key, algorithms=[algorithm])

    assert decoded["exp"] == payload["exp"]


@pytest.mark.parametrize("algorithm", ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
def test_rsa_encoding_key_signs_correctly_across_repeated_calls(
    algorithm: str, rsa_pair: object
) -> None:
    """`EncodingKey.from_rsa_pem` parses the private key once; every `encode`
    call re-signs through the cached parsed key rather than re-parsing the PEM
    (see issue #120), so the same `EncodingKey` object must keep producing
    signatures that verify correctly across many calls, not just the first.
    """
    for i in range(20):
        payload = {"sub": f"user-{i}", "exp": int(time.time()) + 60}
        token = oxyjwt.encode(payload, rsa_pair.encoding_key, algorithm=algorithm)
        decoded = oxyjwt.decode(token, rsa_pair.decoding_key, algorithms=[algorithm])
        assert decoded == payload


def test_rsa_encoding_key_rejects_malformed_pem_at_construction() -> None:
    with pytest.raises(oxyjwt.InvalidKeyError):
        oxyjwt.EncodingKey.from_rsa_pem(b"not a pem encoded key")
