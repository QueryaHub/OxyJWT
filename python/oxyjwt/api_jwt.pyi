from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import timedelta
from json import JSONEncoder
from typing import Any

from oxyjwt._oxyjwt import DecodingKey, EncodingKey

class PyJWT:
    def __init__(self, options: dict[str, Any] | None = None) -> None: ...
    @staticmethod
    def _get_default_options() -> dict[str, Any]: ...
    def encode(
        self,
        payload: dict[str, Any],
        key: object,
        algorithm: str | None = "HS256",
        headers: dict[str, Any] | None = None,
        json_encoder: type[JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str: ...
    def decode(
        self,
        jwt: str | bytes,
        key: object = "",
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        subject: str | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
        **kwargs: Any,
    ) -> Any: ...
    def decode_complete(
        self,
        jwt: str | bytes,
        key: object = "",
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        subject: str | None = None,
        issuer: str | Iterable[str] | None = None,
        leeway: float | timedelta = 0,
        **kwargs: Any,
    ) -> dict[str, Any]: ...

def encode(
    payload: dict[str, Any],
    key: object,
    algorithm: str | None = "HS256",
    headers: dict[str, Any] | None = None,
    json_encoder: type[JSONEncoder] | None = None,
    sort_headers: bool = True,
) -> str: ...
def decode(
    jwt: str | bytes,
    key: object = "",
    algorithms: list[str] | None = None,
    options: dict[str, Any] | None = None,
    verify: bool | None = None,
    detached_payload: bytes | None = None,
    audience: str | Iterable[str] | None = None,
    subject: str | None = None,
    issuer: str | Iterable[str] | None = None,
    leeway: float | timedelta = 0,
    **kwargs: Any,
) -> Any: ...
def decode_complete(
    jwt: str | bytes,
    key: object = "",
    algorithms: list[str] | None = None,
    options: dict[str, Any] | None = None,
    verify: bool | None = None,
    detached_payload: bytes | None = None,
    audience: str | Iterable[str] | None = None,
    subject: str | None = None,
    issuer: str | Iterable[str] | None = None,
    leeway: float | timedelta = 0,
    **kwargs: Any,
) -> dict[str, Any]: ...
