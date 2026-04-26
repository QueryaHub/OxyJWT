from __future__ import annotations

from oxyjwt import _oxyjwt


class PyJWKError(_oxyjwt.OxyJWTError):
    pass


class PyJWKSetError(_oxyjwt.OxyJWTError):
    pass


class PyJWKClientError(_oxyjwt.OxyJWTError):
    pass


class PyJWKClientConnectionError(PyJWKClientError):
    pass


__all__ = [
    "PyJWKError",
    "PyJWKSetError",
    "PyJWKClientError",
    "PyJWKClientConnectionError",
]
