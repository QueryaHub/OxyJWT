"""PyJWK / PyJWKSet — minimal PyJWT-compatible facades on DecodingKey.from_jwk."""
from __future__ import annotations

import json
from typing import Any, Mapping, cast

from oxyjwt import _oxyjwt
from oxyjwt.exceptions import (
    InvalidKeyError,
    OxyJWTError,
    PyJWKError,
    PyJWKSetError,
)


def _as_dict(jwk: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(jwk, str):
        return cast("dict[str, Any]", json.loads(jwk))
    return dict(jwk)


class PyJWK:
    def __init__(self, jwk: Mapping[str, Any] | str, algorithm: str | None = None) -> None:
        data = _as_dict(jwk)
        if not data.get("kty"):
            raise InvalidKeyError(f"kty is not found: {data!r}")
        # algorithm hint only for error messages; verification uses the JWK as-is
        self._jwk = data
        _ = algorithm
        try:
            self.key: _oxyjwt.DecodingKey = _oxyjwt.DecodingKey.from_jwk(self._jwk)
        except Exception as e:  # noqa: BLE001
            msg = str(e) or type(e).__name__
            raise PyJWKError(f"Unable to build key from JWK: {msg}") from e

    @staticmethod
    def from_dict(obj: Mapping[str, Any], algorithm: str | None = None) -> PyJWK:
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: str | None = None) -> PyJWK:
        return PyJWK.from_dict(json.loads(data), algorithm)

    @property
    def key_type(self) -> str | None:
        return self._jwk.get("kty")

    @property
    def key_id(self) -> str | None:
        return self._jwk.get("kid")

    @property
    def public_key_use(self) -> str | None:
        return self._jwk.get("use")


class PyJWKSet:
    def __init__(self, keys: list[dict[str, Any]]) -> None:
        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")
        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")
        self.keys: list[PyJWK] = []
        for k in keys:
            try:
                self.keys.append(PyJWK(k))
            except (OxyJWTError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                continue
        if not self.keys:
            raise PyJWKSetError(
                "The JWK Set did not contain any usable keys."
            )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> PyJWKSet:
        ks = obj.get("keys", [])
        if not isinstance(ks, list):
            raise PyJWKSetError("Invalid JWK Set value")
        return PyJWKSet([x for x in ks if isinstance(x, dict)])

    @staticmethod
    def from_json(data: str) -> PyJWKSet:
        return PyJWKSet.from_dict(json.loads(data))

    def __getitem__(self, kid: str) -> PyJWK:
        for j in self.keys:
            if j.key_id == kid:
                return j
        raise KeyError(f"keyset has no key for kid: {kid!r}")


__all__ = ["PyJWK", "PyJWKSet"]
