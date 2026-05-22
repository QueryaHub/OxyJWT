from __future__ import annotations

import time

import oxyjwt


def test_get_unverified_header() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 60},
        "secret",
        headers={"kid": "key-1", "typ": "JWT"},
    )

    header = oxyjwt.get_unverified_header(token)

    assert header["alg"] == "HS256"
    assert header["kid"] == "key-1"
    assert header["typ"] == "JWT"


def test_encode_custom_string_header() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 60},
        "secret",
        headers={"kid": "k1", "X-Custom": "trace-9", "tenant": "acme"},
    )
    header = oxyjwt.get_unverified_header(token)
    assert header["kid"] == "k1"
    assert header["X-Custom"] == "trace-9"
    assert header["tenant"] == "acme"
