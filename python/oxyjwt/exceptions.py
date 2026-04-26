"""Exception hierarchy (PyJWT-compatible)."""

from __future__ import annotations

from ._oxyjwt import (
    DecodeError,
    EncodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidSubjectError,
    InvalidTokenError,
    MissingRequiredClaimError,
    OxyJWTError,
)

# PyJWT names this class PyJWTError; we keep the Rust type as OxyJWTError.
PyJWTError = OxyJWTError

from oxyjwt.jwk_exc import (
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
)

__all__ = [
    "DecodeError",
    "EncodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAlgorithmError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidSubjectError",
    "InvalidTokenError",
    "MissingRequiredClaimError",
    "OxyJWTError",
    "PyJWTError",
    "PyJWKError",
    "PyJWKSetError",
    "PyJWKClientError",
    "PyJWKClientConnectionError",
]
