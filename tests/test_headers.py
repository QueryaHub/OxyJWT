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
