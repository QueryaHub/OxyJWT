from __future__ import annotations

import ssl
from collections.abc import Mapping
from typing import Any

from oxyjwt.jwk import PyJWK, PyJWKSet

class PyJWKClient:
    uri: str
    timeout: float
    def __init__(
        self,
        uri: str,
        *,
        cache_jwk_set: bool = True,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        timeout: float = 30.0,
        max_bytes: int = 262_144,
        require_https: bool = False,
        headers: Mapping[str, Any] | None = None,
        ssl_context: ssl.SSLContext | None = None,
        lifespan: float = 300.0,
    ) -> None: ...
    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet: ...
    def get_signing_key(self, kid: str) -> PyJWK: ...
    def get_signing_key_from_jwt(
        self,
        jwt: str | bytes,
        algorithms: list[str] | None = None,
    ) -> PyJWK: ...
