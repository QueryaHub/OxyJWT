"""RFC 7797 detached payload decode (issue #26)."""
from __future__ import annotations

import json
import time

import jwt
import pytest
from jwt.api_jws import PyJWS

import oxyjwt


def _make_rfc7797_token(
    payload: dict[str, object] | None = None,
    secret: bytes = b"secret",
) -> tuple[str, bytes]:
    body = json.dumps(
        payload or {"sub": "u", "exp": int(time.time()) + 300},
        separators=(",", ":"),
    ).encode()
    jws = PyJWS()
    token = jws.encode(
        body,
        secret,
        algorithm="HS256",
        headers={"b64": False},
        is_payload_detached=True,
    )
    return token, body


def test_detached_decode_parity_with_pyjwt() -> None:
    token, payload = _make_rfc7797_token()
    expected = jwt.decode(
        token, "secret", algorithms=["HS256"], detached_payload=payload
    )
    assert (
        oxyjwt.decode(
            token, "secret", algorithms=["HS256"], detached_payload=payload
        )
        == expected
    )


def test_detached_decode_complete_shape() -> None:
    token, payload = _make_rfc7797_token()
    out = oxyjwt.decode_complete(
        token, "secret", algorithms=["HS256"], detached_payload=payload
    )
    assert out["payload"]["sub"] == "u"
    assert out["header"]["b64"] is False
    assert "b64" in out["header"]["crit"]
    assert isinstance(out["signature"], (bytes, bytearray))


def test_detached_requires_payload_when_b64_false() -> None:
    token, _ = _make_rfc7797_token()
    with pytest.raises(oxyjwt.DecodeError, match="detached_payload"):
        oxyjwt.decode(token, "secret", algorithms=["HS256"])


def test_detached_wrong_payload_fails_verification() -> None:
    token, payload = _make_rfc7797_token()
    tampered = json.dumps({"sub": "other", "exp": 9_999_999_999}).encode()
    with pytest.raises(oxyjwt.InvalidSignatureError):
        oxyjwt.decode(
            token, "secret", algorithms=["HS256"], detached_payload=tampered
        )


def test_get_unverified_header_rfc7797() -> None:
    token, _ = _make_rfc7797_token()
    header = oxyjwt.get_unverified_header(token)
    assert header["alg"] == "HS256"
    assert header["b64"] is False
