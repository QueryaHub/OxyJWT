"""Warnings for PyJWT-compatible API."""

from __future__ import annotations


class RemovedInPyJWT3Warning(DeprecationWarning):
    """Mirror of PyJWT's warning for kwargs and future removals."""


class InsecureDecodeWarning(UserWarning):
    """Emitted when decoding without signature verification or related footguns."""


class PyJWKSetSkipWarning(UserWarning):
    """Emitted when a JWK entry in a set cannot be used and is skipped."""
