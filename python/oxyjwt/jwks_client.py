"""PyJWKClient — fetch JWKS over HTTP (stdlib urllib only)."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from oxyjwt import _oxyjwt
from oxyjwt.jwk import PyJWKSet
from oxyjwt.jwk_exc import PyJWKClientConnectionError, PyJWKClientError

_DEFAULT_UA = "OxyJWT-PyJWKClient/0.2 (+https://github.com/QueryaHub/OxyJWT)"


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        *,
        cache_jwk_set: bool = True,
        max_cached_keys: int = 16,
        timeout: float = 30.0,
    ) -> None:
        if not uri or not str(uri).strip():
            raise ValueError("uri must be a non-empty string")
        self.uri: str = str(uri).strip()
        self._cache_jwk_set = bool(cache_jwk_set)
        self._max_cached_keys = max(1, int(max_cached_keys))
        self.timeout = float(timeout)
        self._jwk_set: PyJWKSet | None = None
        # Simple LRU not implemented: cache is replace-on-fetch when enabled.

    def _fetch_raw(self) -> bytes:
        req = urllib.request.Request(
            self.uri,
            headers={"User-Agent": _DEFAULT_UA, "Accept": "application/json"},
            method="GET",
        )
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise PyJWKClientConnectionError(str(e) or type(e).__name__) from e

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        if self._cache_jwk_set and not refresh and self._jwk_set is not None:
            return self._jwk_set
        data = self._fetch_raw()
        try:
            obj: dict[str, Any] = json.loads(data)
        except json.JSONDecodeError as e:
            raise PyJWKClientError("JWKS response is not valid JSON") from e
        if not isinstance(obj, dict) or "keys" not in obj:
            raise PyJWKClientError("JWKS response must be a JSON object with a 'keys' field")
        jwks = PyJWKSet.from_dict(obj)
        if self._cache_jwk_set:
            self._jwk_set = jwks
        return jwks

    def get_signing_key(self, kid: str) -> PyJWK:
        if not kid:
            raise PyJWKClientError("kid must be a non-empty string")
        jwks = self.get_jwk_set()
        return jwks[kid]

    def get_signing_key_from_jwt(self, jwt: str | bytes) -> PyJWK:
        token = jwt if isinstance(jwt, str) else jwt.decode("utf-8")
        header: dict[str, Any] = _oxyjwt.get_unverified_header(token)  # type: ignore[assignment]
        if not isinstance(header, dict):
            header = json.loads(json.dumps(header))
        kid = header.get("kid")
        if kid is None or kid == "":
            raise PyJWKClientError("token header is missing a key id (kid)")
        return self.get_signing_key(str(kid))


__all__ = ["PyJWKClient"]
