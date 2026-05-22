from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import oxyjwt
from oxyjwt.jwks_client import PyJWKClient


def _b64u(b: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


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


def _serve_jwks(jw: dict) -> str:
    _JWKHandler.jwks_json = json.dumps(jw).encode("utf-8")
    _JWKHandler.request_count = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _JWKHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


def test_jwks_client_fetches_key_by_kid() -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    c = PyJWKClient(uri, cache_jwk_set=False, timeout=5.0)
    tok = oxyjwt.encode(
        {"sub": "1", "exp": 9_999_999_999},
        b"the-shared-secret-xy",
        algorithm="HS256",
        headers={"kid": "alpha"},
    )
    jwk = c.get_signing_key_from_jwt(tok)
    out = oxyjwt.decode(
        tok,
        jwk.key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert out["sub"] == "1"


def test_jwks_client_lru_limits_keys_without_extra_http() -> None:
    jw_a = {
        "kty": "oct",
        "k": _b64u(b"secret-a-32-bytes-long-ok!!!!"),
        "kid": "a",
    }
    jw_b = {
        "kty": "oct",
        "k": _b64u(b"secret-b-32-bytes-long-ok!!!!"),
        "kid": "b",
    }
    uri = _serve_jwks({"keys": [jw_a, jw_b]})
    c = PyJWKClient(uri, cache_jwk_set=True, max_cached_keys=1, timeout=5.0)

    tok_a = oxyjwt.encode(
        {"sub": "1", "exp": 9_999_999_999},
        b"secret-a-32-bytes-long-ok!!!!",
        algorithm="HS256",
        headers={"kid": "a"},
    )
    tok_b = oxyjwt.encode(
        {"sub": "2", "exp": 9_999_999_999},
        b"secret-b-32-bytes-long-ok!!!!",
        algorithm="HS256",
        headers={"kid": "b"},
    )

    c.get_signing_key_from_jwt(tok_a)
    c.get_signing_key_from_jwt(tok_b)
    c.get_signing_key_from_jwt(tok_a)

    assert _JWKHandler.request_count == 1
    assert len(c._kid_lru) == 1  # noqa: SLF001
