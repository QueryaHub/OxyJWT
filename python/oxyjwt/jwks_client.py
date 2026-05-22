"""PyJWKClient — fetch JWKS over HTTP (stdlib urllib only)."""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from typing import Any, Mapping
from urllib.parse import urlparse

import orjson

from oxyjwt import _oxyjwt
from oxyjwt.exceptions import InvalidAlgorithmError
from oxyjwt.jwk import PyJWK, PyJWKSet
from oxyjwt.jwk_exc import PyJWKClientConnectionError, PyJWKClientError

_DEFAULT_UA = "OxyJWT-PyJWKClient/0.4 (+https://github.com/QueryaHub/OxyJWT)"
_DEFAULT_MAX_JWKS_BYTES = 256 * 1024


def _read_limited_body(resp: Any, max_bytes: int) -> bytes:
    data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise PyJWKClientError(
            f"JWKS response exceeds max_bytes limit ({max_bytes} bytes)"
        )
    return data


def _merge_request_headers(extra: Mapping[str, Any] | None) -> dict[str, str]:
    headers = {
        "User-Agent": _DEFAULT_UA,
        "Accept": "application/json",
    }
    if extra is not None:
        for key, value in extra.items():
            headers[str(key)] = str(value)
    return headers


def _header_to_plain_dict(obj: Any) -> dict[str, Any]:
    raw = orjson.dumps(obj, default=str)
    out = orjson.loads(raw)
    if not isinstance(out, dict):
        raise TypeError("expected JSON object for JWT header")
    return out


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        *,
        cache_jwk_set: bool = True,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        timeout: float = 30.0,
        max_bytes: int = _DEFAULT_MAX_JWKS_BYTES,
        require_https: bool = False,
        headers: Mapping[str, Any] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        lifespan: float = 300.0,
    ) -> None:
        if not uri or not str(uri).strip():
            raise ValueError("uri must be a non-empty string")
        self.uri: str = str(uri).strip()
        parsed = urlparse(self.uri)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("uri must use http or https scheme")
        if require_https and parsed.scheme != "https":
            raise PyJWKClientError("JWKS uri must use https when require_https is enabled")
        self._cache_jwk_set = bool(cache_jwk_set)
        if self._cache_jwk_set and float(lifespan) <= 0:
            raise PyJWKClientError(
                f'lifespan must be greater than 0, the input is "{lifespan}"'
            )
        self._lifespan = float(lifespan)
        self._cache_keys = bool(cache_keys)
        self._max_cached_keys = max(1, int(max_cached_keys))
        self.timeout = float(timeout)
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        self._max_bytes = int(max_bytes)
        self._require_https = bool(require_https)
        if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
            raise TypeError("ssl_context must be an ssl.SSLContext or None")
        self._headers = _merge_request_headers(headers)
        self._ssl_context = (
            ssl_context if ssl_context is not None else ssl.create_default_context()
        )
        self._jwk_set: PyJWKSet | None = None
        self._jwk_set_fetched_at: float | None = None
        self._kid_lru: OrderedDict[str, PyJWK] = OrderedDict()

    def _jwk_set_cache_valid(self) -> bool:
        if self._jwk_set is None or self._jwk_set_fetched_at is None:
            return False
        return time.monotonic() <= self._jwk_set_fetched_at + self._lifespan

    def _fetch_raw(self) -> bytes:
        req = urllib.request.Request(
            self.uri,
            headers=self._headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self._ssl_context
            ) as resp:
                return _read_limited_body(resp, self._max_bytes)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise PyJWKClientConnectionError(str(e) or type(e).__name__) from e

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        if self._cache_jwk_set and not refresh and self._jwk_set_cache_valid():
            return self._jwk_set
        data = self._fetch_raw()
        try:
            obj: dict[str, Any] = orjson.loads(data)
        except orjson.JSONDecodeError as e:
            raise PyJWKClientError("JWKS response is not valid JSON") from e
        if not isinstance(obj, dict) or "keys" not in obj:
            raise PyJWKClientError("JWKS response must be a JSON object with a 'keys' field")
        jwks = PyJWKSet.from_dict(obj)
        self._kid_lru.clear()
        if self._cache_jwk_set:
            self._jwk_set = jwks
            self._jwk_set_fetched_at = time.monotonic()
        return jwks

    def get_signing_key(self, kid: str) -> PyJWK:
        if not kid:
            raise PyJWKClientError("kid must be a non-empty string")
        if self._cache_keys:
            cached = self._kid_lru.get(kid)
            if cached is not None:
                self._kid_lru.move_to_end(kid)
                return cached
        jwks = self.get_jwk_set()
        try:
            jwk = jwks[kid]
        except KeyError:
            jwks = self.get_jwk_set(refresh=True)
            jwk = jwks[kid]
        if self._cache_keys:
            self._kid_lru[kid] = jwk
            while len(self._kid_lru) > self._max_cached_keys:
                self._kid_lru.popitem(last=False)
        return jwk

    def get_signing_key_from_jwt(
        self,
        jwt: str | bytes,
        algorithms: list[str] | None = None,
    ) -> PyJWK:
        token = jwt if isinstance(jwt, str) else jwt.decode("utf-8")
        header: dict[str, Any] = _oxyjwt.get_unverified_header(token)  # type: ignore[assignment]
        if not isinstance(header, dict):
            header = _header_to_plain_dict(header)
        if algorithms is not None:
            if not algorithms:
                raise InvalidAlgorithmError(
                    "decode requires at least one allowed algorithm"
                )
            alg = header.get("alg")
            if alg is None or str(alg) not in algorithms:
                raise InvalidAlgorithmError("The specified alg value is not allowed")
            if str(alg).lower() == "none":
                raise InvalidAlgorithmError("the 'none' algorithm is not supported")
        kid = header.get("kid")
        if kid is None or kid == "":
            raise PyJWKClientError("token header is missing a key id (kid)")
        return self.get_signing_key(str(kid))


__all__ = ["PyJWKClient"]
