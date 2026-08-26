from __future__ import annotations

import json
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest

import oxyjwt
from oxyjwt.jwk_exc import PyJWKClientError
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
    c = PyJWKClient(
        uri, cache_jwk_set=True, cache_keys=True, max_cached_keys=1, timeout=5.0
    )

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


def _serve_rotating_jwks(first: dict, second: dict) -> str:
    _RotatingJWKHandler.jwks_first = json.dumps(first).encode("utf-8")
    _RotatingJWKHandler.jwks_second = json.dumps(second).encode("utf-8")
    _RotatingJWKHandler.request_count = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _RotatingJWKHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


def test_jwks_client_refreshes_jwks_when_kid_missing_after_rotation() -> None:
    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {
        "kty": "oct",
        "k": _b64u(secret_old),
        "kid": "old-key",
    }
    jw_new = {
        "kty": "oct",
        "k": _b64u(secret_new),
        "kid": "new-key",
    }
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    c = PyJWKClient(uri, cache_jwk_set=True, timeout=5.0)

    tok_old = oxyjwt.encode(
        {"sub": "old", "exp": 9_999_999_999},
        secret_old,
        algorithm="HS256",
        headers={"kid": "old-key"},
    )
    c.get_signing_key_from_jwt(tok_old)
    assert _RotatingJWKHandler.request_count == 1

    tok_new = oxyjwt.encode(
        {"sub": "new", "exp": 9_999_999_999},
        secret_new,
        algorithm="HS256",
        headers={"kid": "new-key"},
    )
    jwk = c.get_signing_key_from_jwt(tok_new)
    out = oxyjwt.decode(
        tok_new,
        jwk.key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert out["sub"] == "new"
    assert _RotatingJWKHandler.request_count == 2


def test_jwks_client_refresh_on_miss_does_not_loop() -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    c = PyJWKClient(uri, cache_jwk_set=True, timeout=5.0)
    c.get_jwk_set()

    with pytest.raises(KeyError, match="missing-kid"):
        c.get_signing_key("missing-kid")

    assert _JWKHandler.request_count == 2


def test_jwks_client_get_signing_key_rejects_empty_kid() -> None:
    c = PyJWKClient("https://example.invalid/jwks", timeout=5.0)
    with pytest.raises(PyJWKClientError, match="kid must be a non-empty string"):
        c.get_signing_key("")


def test_jwks_client_refresh_on_miss_when_cache_jwk_set_disabled() -> None:
    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {"kty": "oct", "k": _b64u(secret_old), "kid": "old-key"}
    jw_new = {"kty": "oct", "k": _b64u(secret_new), "kid": "new-key"}
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    c = PyJWKClient(uri, cache_jwk_set=False, timeout=5.0)

    c.get_signing_key("old-key")
    assert _RotatingJWKHandler.request_count == 1

    jwk = c.get_signing_key("new-key")
    assert jwk.key_id == "new-key"
    assert _RotatingJWKHandler.request_count == 2


def test_jwks_client_refreshed_kid_hits_lru_without_extra_http() -> None:
    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {"kty": "oct", "k": _b64u(secret_old), "kid": "old-key"}
    jw_new = {"kty": "oct", "k": _b64u(secret_new), "kid": "new-key"}
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    c = PyJWKClient(uri, cache_jwk_set=True, timeout=5.0)

    c.get_signing_key("old-key")
    c.get_signing_key("new-key")
    assert _RotatingJWKHandler.request_count == 2

    again = c.get_signing_key("new-key")
    assert again.key_id == "new-key"
    assert _RotatingJWKHandler.request_count == 2


def test_jwks_client_explicit_refresh_loads_rotated_keys() -> None:
    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {"kty": "oct", "k": _b64u(secret_old), "kid": "old-key"}
    jw_new = {"kty": "oct", "k": _b64u(secret_new), "kid": "new-key"}
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    c = PyJWKClient(uri, cache_jwk_set=True, timeout=5.0)

    c.get_jwk_set()
    assert _RotatingJWKHandler.request_count == 1

    jwks = c.get_jwk_set(refresh=True)
    assert "new-key" in {k.key_id for k in jwks.keys}
    assert _RotatingJWKHandler.request_count == 2

    jwk = c.get_signing_key("new-key")
    assert jwk.key_id == "new-key"
    assert _RotatingJWKHandler.request_count == 2


class _LargeJWKHandler(BaseHTTPRequestHandler):
    body: ClassVar[bytes] = b"x" * 4096

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: object) -> None:  # noqa: D102
        return


def _serve_large_jwks(body: bytes) -> str:
    _LargeJWKHandler.body = body
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _LargeJWKHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


def test_jwks_client_rejects_oversized_jwks_response() -> None:
    uri = _serve_large_jwks(b"x" * 2048)
    c = PyJWKClient(uri, max_bytes=1024, timeout=5.0)
    with pytest.raises(PyJWKClientError, match="max_bytes"):
        c.get_jwk_set()


def test_jwks_client_require_https_rejects_http_uri() -> None:
    uri = _serve_jwks(
        {
            "keys": [
                {
                    "kty": "oct",
                    "k": _b64u(b"the-shared-secret-xy"),
                    "kid": "alpha",
                }
            ]
        }
    )
    with pytest.raises(PyJWKClientError, match="require_https"):
        PyJWKClient(uri, require_https=True, timeout=5.0)


def test_jwks_client_rejects_disallowed_alg_before_jwks_fetch() -> None:
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
    with pytest.raises(oxyjwt.InvalidAlgorithmError, match="not allowed"):
        c.get_signing_key_from_jwt(tok, algorithms=["RS256"])
    assert _JWKHandler.request_count == 0


def test_jwks_client_allowed_alg_still_fetches_key() -> None:
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
    jwk = c.get_signing_key_from_jwt(tok, algorithms=["HS256"])
    assert jwk.key_id == "alpha"
    assert _JWKHandler.request_count == 1


def test_jwks_client_empty_algorithms_allow_list_before_fetch() -> None:
    uri = _serve_jwks(
        {
            "keys": [
                {
                    "kty": "oct",
                    "k": _b64u(b"the-shared-secret-xy"),
                    "kid": "alpha",
                }
            ]
        }
    )
    c = PyJWKClient(uri, timeout=5.0)
    tok = oxyjwt.encode(
        {"sub": "1", "exp": 9_999_999_999},
        b"the-shared-secret-xy",
        algorithm="HS256",
        headers={"kid": "alpha"},
    )
    with pytest.raises(oxyjwt.InvalidAlgorithmError, match="at least one"):
        c.get_signing_key_from_jwt(tok, algorithms=[])
    assert _JWKHandler.request_count == 0


def test_jwks_client_get_signing_key_from_jwt_missing_kid_raises() -> None:
    uri = _serve_jwks(
        {
            "keys": [
                {
                    "kty": "oct",
                    "k": _b64u(b"the-shared-secret-xy"),
                    "kid": "alpha",
                }
            ]
        }
    )
    c = PyJWKClient(uri, timeout=5.0)
    tok = oxyjwt.encode(
        {"sub": "1", "exp": 9_999_999_999},
        b"the-shared-secret-xy",
        algorithm="HS256",
    )
    with pytest.raises(PyJWKClientError, match="missing a key id"):
        c.get_signing_key_from_jwt(tok)


class _HeaderEchoHandler(BaseHTTPRequestHandler):
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


def _serve_jwks_with_headers(jw: dict) -> str:
    _HeaderEchoHandler.jwks_json = json.dumps(jw).encode("utf-8")
    _HeaderEchoHandler.request_count = 0
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderEchoHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return f"http://{host}:{port}/jwks.json"


def test_jwks_client_sends_custom_headers() -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks_with_headers({"keys": [jw]})
    seen: dict[str, str] = {}

    orig_request = urllib.request.Request

    def capture_request(
        url: str,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: object,
    ) -> urllib.request.Request:
        del data, kwargs
        if headers:
            seen.update(headers)
        return orig_request(url, headers=headers)

    urllib.request.Request = capture_request  # type: ignore[misc, assignment]
    try:
        c = PyJWKClient(
            uri,
            cache_jwk_set=False,
            timeout=5.0,
            headers={"Authorization": "Bearer test-token", "X-Custom": "1"},
        )
        c.get_jwk_set()
    finally:
        urllib.request.Request = orig_request  # type: ignore[misc]

    assert seen.get("Authorization") == "Bearer test-token"
    assert seen.get("X-Custom") == "1"
    assert "application/json" in seen.get("Accept", "")
    assert _HeaderEchoHandler.request_count == 1


def test_jwks_client_uses_provided_ssl_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    ctx = ssl.create_default_context()
    seen: dict[str, ssl.SSLContext] = {}

    orig_urlopen = urllib.request.urlopen

    def capture_urlopen(
        req: object,
        timeout: float | None = None,
        context: ssl.SSLContext | None = None,
    ) -> object:
        if context is not None:
            seen["context"] = context
        return orig_urlopen(req, timeout=timeout, context=context)

    monkeypatch.setattr(urllib.request, "urlopen", capture_urlopen)
    c = PyJWKClient(uri, cache_jwk_set=False, timeout=5.0, ssl_context=ctx)
    c.get_jwk_set()
    assert seen["context"] is ctx


def test_jwks_client_rejects_invalid_ssl_context_type() -> None:
    with pytest.raises(TypeError, match="ssl.SSLContext"):
        PyJWKClient("https://example.invalid/jwks", ssl_context=object())  # type: ignore[arg-type]


def test_jwks_client_cache_keys_false_keeps_no_kid_lru() -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    c = PyJWKClient(uri, cache_jwk_set=True, cache_keys=False, timeout=5.0)
    c.get_signing_key("alpha")
    c.get_signing_key("alpha")
    assert len(c._kid_lru) == 0  # noqa: SLF001
    assert _JWKHandler.request_count == 1


def test_jwks_client_cache_keys_true_uses_kid_lru() -> None:
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
    c = PyJWKClient(
        uri, cache_jwk_set=True, cache_keys=True, max_cached_keys=2, timeout=5.0
    )
    c.get_signing_key("a")
    c.get_signing_key("b")
    assert len(c._kid_lru) == 2  # noqa: SLF001
    again = c.get_signing_key("a")
    assert again.key_id == "a"
    assert _JWKHandler.request_count == 1


def test_jwks_client_rejects_non_positive_lifespan_when_caching() -> None:
    with pytest.raises(PyJWKClientError, match="lifespan must be greater than 0"):
        PyJWKClient("https://example.invalid/jwks", cache_jwk_set=True, lifespan=0)


def test_jwks_client_lifespan_refetches_after_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import oxyjwt.jwks_client as jwks_client_mod

    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    clock = [0.0]

    monkeypatch.setattr(
        jwks_client_mod.time,
        "monotonic",
        lambda: clock[0],
    )
    c = PyJWKClient(uri, cache_jwk_set=True, lifespan=300.0, timeout=5.0)
    c.get_jwk_set()
    assert _JWKHandler.request_count == 1

    clock[0] = 301.0
    c.get_jwk_set()
    assert _JWKHandler.request_count == 2


def test_jwks_client_expired_lifespan_refetches_rotated_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import oxyjwt.jwks_client as jwks_client_mod

    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {"kty": "oct", "k": _b64u(secret_old), "kid": "old-key"}
    jw_new = {"kty": "oct", "k": _b64u(secret_new), "kid": "new-key"}
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    clock = [0.0]
    monkeypatch.setattr(
        jwks_client_mod.time,
        "monotonic",
        lambda: clock[0],
    )
    c = PyJWKClient(uri, cache_jwk_set=True, lifespan=60.0, timeout=5.0)
    c.get_signing_key("old-key")
    assert _RotatingJWKHandler.request_count == 1

    clock[0] = 120.0
    jwk = c.get_signing_key("new-key")
    assert jwk.key_id == "new-key"
    assert _RotatingJWKHandler.request_count == 2


def test_jwks_client_refresh_on_miss_within_lifespan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import oxyjwt.jwks_client as jwks_client_mod

    secret_old = b"secret-old-32-bytes-long-ok!!!"
    secret_new = b"secret-new-32-bytes-long-ok!!!"
    jw_old = {"kty": "oct", "k": _b64u(secret_old), "kid": "old-key"}
    jw_new = {"kty": "oct", "k": _b64u(secret_new), "kid": "new-key"}
    uri = _serve_rotating_jwks({"keys": [jw_old]}, {"keys": [jw_new]})
    clock = [0.0]
    monkeypatch.setattr(
        jwks_client_mod.time,
        "monotonic",
        lambda: clock[0],
    )
    c = PyJWKClient(uri, cache_jwk_set=True, lifespan=300.0, timeout=5.0)
    c.get_signing_key("old-key")
    assert _RotatingJWKHandler.request_count == 1

    jwk = c.get_signing_key("new-key")
    assert jwk.key_id == "new-key"
    assert _RotatingJWKHandler.request_count == 2


def test_jwks_client_concurrent_get_signing_key() -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    c = PyJWKClient(uri, cache_jwk_set=True, cache_keys=True, timeout=5.0)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            jwk = c.get_signing_key("alpha")
            assert jwk.key_id == "alpha"
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert _JWKHandler.request_count <= 2


def test_jwks_client_refresh_cooldown_throttles_rapid_refreshes() -> None:
    jw = {
        "kty": "oct",
        "k": _b64u(b"the-shared-secret-xy"),
        "kid": "alpha",
    }
    uri = _serve_jwks({"keys": [jw]})
    c = PyJWKClient(uri, cache_jwk_set=True, refresh_cooldown=1.0, timeout=5.0)
    c.get_jwk_set()
    assert _JWKHandler.request_count == 1

    # Immediate lookups for non-existent keys within cooldown window shouldn't hammer the endpoint
    for _ in range(5):
        with pytest.raises(KeyError):
            c.get_signing_key("non-existent-kid")
    assert _JWKHandler.request_count == 1


def test_jwks_client_http_uri_emits_insecure_warning() -> None:
    with pytest.warns(oxyjwt.InsecureJWKSUriWarning, match="unencrypted HTTP"):
        PyJWKClient("http://example.invalid/jwks.json")


