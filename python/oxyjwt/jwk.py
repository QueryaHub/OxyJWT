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
        kid = self._jwk.get("kid")
        return str(kid) if kid is not None else None

    @property
    def public_key_use(self) -> str | None:
        return self._jwk.get("use")


class PyJWKSet:
    def __init__(self, keys: list[dict[str, Any]]) -> None:
        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")
        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")
        self._raw_keys: list[dict[str, Any]] = [
            k for k in keys if isinstance(k, dict)
        ]
        if not self._raw_keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")
        self._by_kid_raw: dict[str, dict[str, Any]] = {}
        for raw in self._raw_keys:
            use = raw.get("use")
            if use is not None and str(use).lower() == "enc":
                continue
            kid = raw.get("kid")
            if kid is not None and str(kid) not in self._by_kid_raw:
                self._by_kid_raw[str(kid)] = raw
        # Fallback for kids that only have enc keys to retain proper error reporting on lookup
        for raw in self._raw_keys:
            kid = raw.get("kid")
            if kid is not None and str(kid) not in self._by_kid_raw:
                self._by_kid_raw[str(kid)] = raw
        self._materialized: dict[str, PyJWK] = {}
        self._keys_cache: list[PyJWK] | None = None

    def _materialize(self, raw: dict[str, Any], index: int) -> PyJWK | None:
        try:
            return PyJWK(raw)
        except OxyJWTError as error:
            kid = raw.get("kid")
            kid_label = f"kid={kid!r}" if kid is not None else "no kid"
            warnings.warn(
                f"Skipped JWK at index {index} ({kid_label}): {error}",
                PyJWKSetSkipWarning,
                stacklevel=3,
            )
            return None

    @property
    def keys(self) -> list[PyJWK]:
        if self._keys_cache is None:
            built: list[PyJWK] = []
            for index, raw in enumerate(self._raw_keys):
                jwk = self._materialize(raw, index)
                if jwk is None:
                    continue
                built.append(jwk)
                kid = jwk.key_id
                if kid is not None:
                    self._materialized[kid] = jwk
            if not built:
                raise PyJWKSetError(
                    "The JWK Set did not contain any usable keys."
                )
            self._keys_cache = built
        return self._keys_cache

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
        if kid in self._materialized:
            return self._materialized[kid]
        try:
            raw = self._by_kid_raw[kid]
        except KeyError as e:
            raise KeyError(f"keyset has no key for kid: {kid!r}") from e
        jwk = PyJWK(raw)
        self._materialized[kid] = jwk
        return jwk

    @property
    def _by_kid(self) -> dict[str, PyJWK]:
        """Materialized kid index (compat for tests and introspection)."""
        for kid in self._by_kid_raw:
            if kid not in self._materialized:
                self[kid]
        return self._materialized


__all__ = ["PyJWK", "PyJWKSet"]
