"""Security regression tests for OxyJWT 0.4.0.

Covers the main 0.4.0 security fixes in one module so CI always exercises them
without extra env flags. See milestone 0.4.0 issues #1–#12 and related JWKS/API work.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import oxyjwt
from oxyjwt.exceptions import DecodeError
from oxyjwt.jwk_exc import PyJWKClientError
from oxyjwt.jwks_client import PyJWKClient

_MAX_COMPACT_JWT_BYTES = 256 * 1024

pytestmark = pytest.mark.security


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _JWKHandler(BaseHTTPRequestHandler):
    jwks_json: ClassVar[bytes] = b"{}"
    request_count: ClassVar[int] = 0

    def do_GET(self) -> None:  # noqa: N802
        type(self).request_count += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.jwks_json)

    def log_message(self, *args: object) -> None:  # noqa: D102
        return


class _RotatingJWKHandler(BaseHTTPRequestHandler):
    jwks_first: ClassVar[bytes] = b"{}"
    jwks_second: ClassVar[bytes] = b"{}"
    request_count: ClassVar[int] = 0

    def do_GET(self) -> None:  # noqa: N802
        type(self).request_count += 1
        body = (
            self.jwks_first
            if type(self).request_count == 1
            else self.jwks_second
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # noqa: D102
        return


class _LargeJWKHandler(BaseHTTPRequestHandler):
    body: ClassVar[bytes] = b"x" * 4096

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: object) -> None:  # noqa: D102
        return


def _serve_jwks(jw: dict) -> str:
    _JWKHandler.jwks_json = json.dumps(jw).encode("utf-8")
    _JWKHandler.request_count = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _JWKHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


def _serve_rotating_jwks(first: dict, second: dict) -> str:
    _RotatingJWKHandler.jwks_first = json.dumps(first).encode("utf-8")
    _RotatingJWKHandler.jwks_second = json.dumps(second).encode("utf-8")
    _RotatingJWKHandler.request_count = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RotatingJWKHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


def _serve_large_jwks(body: bytes) -> str:
    _LargeJWKHandler.body = body
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _LargeJWKHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


# --- JWKS rotation (issue #1) ---


def test_security_jwks_refresh_on_unknown_kid_after_rotation() -> None:
    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {"kty": "oct", "k": _b64u(secret_old), "kid": "old-key"}
    jw_new = {"kty": "oct", "k": _b64u(secret_new), "kid": "new-key"}
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    client = PyJWKClient(uri, cache_jwk_set=True, timeout=5.0)

    tok_old = oxyjwt.encode(
        {"sub": "old", "exp": 9_999_999_999},
        secret_old,
        algorithm="HS256",
        headers={"kid": "old-key"},
    )
    client.get_signing_key_from_jwt(tok_old)
    assert _RotatingJWKHandler.request_count == 1

    tok_new = oxyjwt.encode(
        {"sub": "new", "exp": 9_999_999_999},
        secret_new,
        algorithm="HS256",
        headers={"kid": "new-key"},
    )
    jwk = client.get_signing_key_from_jwt(tok_new)
    payload = oxyjwt.decode(
        tok_new,
        jwk.key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert payload["sub"] == "new"
    assert _RotatingJWKHandler.request_count == 2


# --- Unverified decode footgun (issue #2) ---


def test_security_unverified_decode_warns_and_ignores_subject_by_default() -> None:
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
    assert any(
        "subject argument is ignored" in str(w.message) for w in records.list
    )


# --- Multi-issuer (issue #3) ---


def test_security_multi_issuer_list_validation() -> None:
    token = oxyjwt.encode(
        {"exp": int(time.time()) + 3600, "iss": "https://primary.example"},
        "secret",
    )
    out = oxyjwt.decode(
        token,
        "secret",
        algorithms=["HS256"],
        issuer=["https://primary.example", "https://backup.example"],
    )
    assert out["iss"] == "https://primary.example"

    with pytest.raises(oxyjwt.InvalidIssuerError):
        oxyjwt.decode(
            token,
            "secret",
            algorithms=["HS256"],
            issuer=["https://backup.example"],
        )


# --- Oversized JWKS (issue #7) ---


def test_security_oversized_jwks_response_rejected() -> None:
    uri = _serve_large_jwks(b"x" * 2048)
    client = PyJWKClient(uri, max_bytes=1024, timeout=5.0)
    with pytest.raises(PyJWKClientError, match="max_bytes"):
        client.get_jwk_set()


# --- Oversized compact JWT (issue #24) ---


def test_security_oversized_compact_jwt_rejected_before_parse() -> None:
    token = "a" * (_MAX_COMPACT_JWT_BYTES + 1)
    with pytest.raises(DecodeError, match="maximum compact token size"):
        oxyjwt.decode_unverified(token)
    with pytest.raises(DecodeError, match="maximum compact token size"):
        oxyjwt.get_unverified_header(token)


# --- Algorithm confusion before JWKS fetch (issue #8) ---


def test_security_disallowed_alg_rejected_before_jwks_http() -> None:
    jw = {"kty": "oct", "k": _b64u(b"the-shared-secret-xy"), "kid": "alpha"}
    uri = _serve_jwks({"keys": [jw]})
    client = PyJWKClient(uri, cache_jwk_set=False, timeout=5.0)
    token = oxyjwt.encode(
        {"sub": "1", "exp": 9_999_999_999},
        b"the-shared-secret-xy",
        algorithm="HS256",
        headers={"kid": "alpha"},
    )
    with pytest.raises(oxyjwt.InvalidAlgorithmError, match="not allowed"):
        client.get_signing_key_from_jwt(token, algorithms=["RS256"])
    assert _JWKHandler.request_count == 0
