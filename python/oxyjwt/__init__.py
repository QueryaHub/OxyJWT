"""OxyJWT public API (PyJWT-shaped module surface)."""

__version__ = "0.2.0"

from ._oxyjwt import (
    DecodingKey,
    EncodingKey,
    decode_unverified,
    get_unverified_header,
)
from .api_jwt import PyJWT, decode, decode_complete, encode
from .exceptions import (
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
    PyJWTError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
)
from .jwk import PyJWK, PyJWKSet
from .jwks_client import PyJWKClient

__all__ = [
    "__version__",
    "DecodingKey",
    "EncodeError",
    "EncodingKey",
    "PyJWK",
    "PyJWKClient",
    "PyJWKClientConnectionError",
    "PyJWKClientError",
    "PyJWKError",
    "PyJWKSet",
    "PyJWKSetError",
    "PyJWT",
    "DecodeError",
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
    "decode",
    "decode_complete",
    "decode_unverified",
    "encode",
    "get_unverified_header",
]
