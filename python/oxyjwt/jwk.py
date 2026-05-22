"""PyJWK / PyJWKSet — minimal PyJWT-compatible facades on DecodingKey.from_jwk."""
from __future__ import annotations

import warnings
from typing import Any, Mapping, cast

import orjson

from oxyjwt import _oxyjwt
from oxyjwt.exceptions import (
    InvalidKeyError,
    OxyJWTError,
    PyJWKError,
    PyJWKSetError,
)
from oxyjwt.warnings import PyJWKSetSkipWarning


def _as_dict(jwk: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(jwk, str):
        return cast("dict[str, Any]", orjson.loads(jwk.encode("utf-8")))
    return dict(jwk)


def _reject_encryption_jwk(data: dict[str, Any]) -> None:
    use = data.get("use")
    if use is not None and str(use).lower() == "enc":
        raise PyJWKError(
            "JWK with use=enc cannot be used for signature verification"
        )


class PyJWK:
    def __init__(self, jwk: Mapping[str, Any] | str, algorithm: str | None = None) -> None:
        data = _as_dict(jwk)
        if not data.get("kty"):
            raise InvalidKeyError(f"kty is not found: {data!r}")
        _reject_encryption_jwk(data)
        # algorithm hint only for error messages; verification uses the JWK as-is
        self._jwk = data
        self._key: _oxyjwt.DecodingKey | None = None
        _ = algorithm

    @property
    def key(self) -> _oxyjwt.DecodingKey:
        if self._key is None:
            try:
                self._key = _oxyjwt.DecodingKey.from_jwk(self._jwk)
            except Exception as e:  # noqa: BLE001
                msg = str(e) or type(e).__name__
                raise PyJWKError(f"Unable to build key from JWK: {msg}") from e
        return self._key

    @staticmethod
    def from_dict(obj: Mapping[str, Any], algorithm: str | None = None) -> PyJWK:
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: str | None = None) -> PyJWK:
        return PyJWK.from_dict(orjson.loads(data.encode("utf-8")), algorithm)

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
        self._by_kid: dict[str, PyJWK] = {}
        for index, k in enumerate(keys):
            try:
                jwk = PyJWK(k)
            except OxyJWTError as error:
                kid = k.get("kid") if isinstance(k, dict) else None
                kid_label = f"kid={kid!r}" if kid is not None else "no kid"
                warnings.warn(
                    f"Skipped JWK at index {index} ({kid_label}): {error}",
                    PyJWKSetSkipWarning,
                    stacklevel=2,
                )
                continue
            self.keys.append(jwk)
            kid = jwk.key_id
            if kid is not None and kid not in self._by_kid:
                self._by_kid[kid] = jwk
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
        return PyJWKSet.from_dict(orjson.loads(data.encode("utf-8")))

    def __getitem__(self, kid: str) -> PyJWK:
        try:
            return self._by_kid[kid]
        except KeyError as e:
            raise KeyError(f"keyset has no key for kid: {kid!r}") from e


__all__ = ["PyJWK", "PyJWKSet"]
