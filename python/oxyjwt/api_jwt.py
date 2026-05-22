"""PyJWT-compatible JWT API (encode / decode / decode_complete)."""
from __future__ import annotations

import time
import warnings
from calendar import timegm
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from json import JSONEncoder
from typing import Any, Callable, cast

import orjson

from oxyjwt import _oxyjwt
from oxyjwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidSubjectError,
    MissingRequiredClaimError,
)
from oxyjwt.warnings import InsecureDecodeWarning, RemovedInPyJWT3Warning

_DEFAULT_DECODE_OPTIONS: dict[str, Any] = {
    "verify_signature": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_iat": True,
    "verify_aud": True,
    "verify_iss": True,
    "verify_sub": True,
    "require": [],
}

_UNVERIFIED_DECODE_WARNING = (
    "Unverified JWT decoding is insecure. The token was parsed without "
    "signature verification; claims must not be used for authorization."
)


def _sig_as_bytes(sig: object) -> bytes:
    if isinstance(sig, (bytes, bytearray, memoryview)):
        return bytes(sig)
    tob = getattr(sig, "tobytes", None)
    if callable(tob):
        return bytes(tob())
    return bytes(sig)  # type: ignore[call-overload]


def _leeway_seconds(leeway: float | timedelta) -> float:
    if isinstance(leeway, timedelta):
        return leeway.total_seconds()
    return float(leeway)


def _as_plain_dict(obj: Any) -> dict[str, Any]:
    """Normalize claims/header to a plain dict without JSON round-trip."""
    if isinstance(obj, dict):
        return cast("dict[str, Any]", obj)
    if isinstance(obj, Mapping):
        return {str(k): v for k, v in obj.items()}
    raise TypeError("expected JSON object for JWT claims or header")


def _json_default_from_encoder(encoder_cls: type[JSONEncoder]) -> Callable[[Any], Any]:
    enc = encoder_cls()

    def default(obj: Any) -> Any:
        return enc.default(obj)

    return default


class PyJWT:
    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self._options: dict[str, Any] = {**_DEFAULT_DECODE_OPTIONS, **(options or {})}

    @staticmethod
    def _get_default_options() -> dict[str, Any]:
        return dict(_DEFAULT_DECODE_OPTIONS)

    def encode(
        self,
        payload: dict[str, Any],
        key: object,
        algorithm: str | None = "HS256",
        headers: dict[str, Any] | None = None,
        json_encoder: type[JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        if not isinstance(payload, dict):
            raise TypeError(
                "Expecting a dict object, as JWT only supports JSON objects as payloads."
            )
        pl = dict(payload)
        for time_claim in ("exp", "iat", "nbf"):
            v = pl.get(time_claim)
            if isinstance(v, datetime):
                pl[time_claim] = timegm(v.utctimetuple())
        opts = orjson.OPT_SORT_KEYS if sort_headers else 0
        if json_encoder is None:
            body_b = orjson.dumps(pl, option=opts)
        else:
            body_b = orjson.dumps(
                pl,
                option=opts,
                default=_json_default_from_encoder(json_encoder),
            )
        alg = algorithm if algorithm is not None else "HS256"
        return _oxyjwt.encode_json(body_b, key, alg, headers)

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
    ) -> Any:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyJWT3Warning,
                stacklevel=2,
            )
        if detached_payload is not None:
            raise NotImplementedError(
                "detached JWS payload is not supported in this OxyJWT release"
            )
        return self.decode_complete(
            jwt,
            key,
            algorithms=algorithms,
            options=options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            subject=subject,
            issuer=issuer,
            leeway=leeway,
        )["payload"]

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
    ) -> dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyJWT3Warning,
                stacklevel=2,
            )
        if detached_payload is not None:
            raise NotImplementedError(
                "detached JWS payload is not supported in this OxyJWT release"
            )
        token = jwt if isinstance(jwt, str) else jwt.decode("utf-8")
        # Match PyJWT: JWS/algorithm gating uses call-only `options` + setdefault, then merge for claims
        co: dict[str, Any] = dict(options or {})
        co.setdefault("verify_signature", True)
        if verify is not None and verify != co["verify_signature"]:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                DeprecationWarning,
                stacklevel=2,
            )
        if not co.get("verify_signature", True):
            warnings.warn(
                _UNVERIFIED_DECODE_WARNING,
                InsecureDecodeWarning,
                stacklevel=2,
            )
            co.setdefault("verify_exp", False)
            co.setdefault("verify_nbf", False)
            co.setdefault("verify_iat", False)
            co.setdefault("verify_aud", False)
            co.setdefault("verify_iss", False)
            co.setdefault("verify_sub", False)
        if co.get("verify_signature", True) and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )
        merged = {**self._options, **co}
        if not co.get("verify_signature", True):
            if subject is not None and not merged.get("verify_sub", False):
                warnings.warn(
                    "The subject argument is ignored when verify_sub is False "
                    "(the default when verify_signature is False).",
                    InsecureDecodeWarning,
                    stacklevel=2,
                )
            elif subject is not None and merged.get("verify_sub", False):
                warnings.warn(
                    "Checking subject with verify_signature=False does not prove "
                    "the token was issued for that subject; use signature "
                    "verification in production.",
                    InsecureDecodeWarning,
                    stacklevel=2,
                )
            if merged.get("require"):
                warnings.warn(
                    "options['require'] only checks claim presence when "
                    "verify_signature is False, not authenticity.",
                    InsecureDecodeWarning,
                    stacklevel=2,
                )
        if audience is not None and not isinstance(
            audience, (str, Iterable, type(None))
        ):
            raise TypeError("audience must be a string, iterable or None")
        if audience is not None and isinstance(audience, (bytes, bytearray, memoryview)):
            raise TypeError("audience must be a string, iterable or None")
        if issuer is not None and not isinstance(
            issuer, (str, Iterable, type(None))
        ):
            raise TypeError("issuer must be a string, iterable or None")
        if issuer is not None and isinstance(issuer, (bytes, bytearray, memoryview)):
            raise TypeError("issuer must be a string, iterable or None")

        lwf = _leeway_seconds(leeway)
        if not co.get("verify_signature", True):
            _s, header_obj, _pld, sigb = _oxyjwt.jws_parse_compact(token)
            header = _as_plain_dict(header_obj)
            pl_d = _as_plain_dict(_oxyjwt.decode_unverified(token))
            self._validate_claims(
                pl_d, merged, audience, issuer, subject, lwf
            )
            return {
                "payload": pl_d,
                "header": header,
                "signature": _sig_as_bytes(sigb),
            }
        assert algorithms is not None
        req = [str(x) for x in (merged.get("require") or []) if x is not None]
        dec, header_obj, sigb = _oxyjwt.decode_verified_complete(
            token,
            key,
            list(algorithms),
            audience=audience,
            issuer=issuer,
            subject=subject,
            leeway=lwf,
            options=merged,
            require=req,
        )
        header = _as_plain_dict(header_obj)
        pl_out = _as_plain_dict(dec)
        self._validate_claims(
            pl_out,
            merged,
            audience,
            issuer,
            subject,
            lwf,
            rust_time_claims=True,
        )
        return {
            "payload": pl_out,
            "header": header,
            "signature": _sig_as_bytes(sigb),
        }

    def _validate_claims(
        self,
        payload: dict[str, Any],
        options: dict[str, Any],
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        subject: str | None = None,
        leeway: float = 0,
        *,
        rust_time_claims: bool = False,
    ) -> None:
        """Validate claims after decode.

        Verified decode (`rust_time_claims=True`): ``exp`` and ``nbf`` are checked in
        Rust (jsonwebtoken); this layer handles ``iat`` plus audience/issuer/sub
        rules that depend on call-time parameters.
        """
        self._validate_required(payload, options)
        now = time.time()
        if "iat" in payload and options.get("verify_iat", True):
            self._validate_iat_fields(payload, now, leeway)
        if not rust_time_claims:
            if "nbf" in payload and options.get("verify_nbf", True):
                self._validate_nbf_fields(payload, now, leeway)
            if "exp" in payload and options.get("verify_exp", True):
                self._validate_exp_fields(payload, now, leeway)
        if options.get("verify_iss", True):
            self._validate_iss_field(payload, issuer)
        if options.get("verify_aud", True):
            self._validate_aud_field(payload, audience)
        if options.get("verify_sub", True):
            self._validate_sub_field(payload, subject)

    @staticmethod
    def _validate_required(
        payload: dict[str, Any], options: dict[str, Any]
    ) -> None:
        for claim in options.get("require", []) or []:
            if payload.get(claim) is None:
                raise MissingRequiredClaimError(claim)

    @staticmethod
    def _validate_iat_fields(
        payload: dict[str, Any], now: float, leeway: float
    ) -> None:
        try:
            iat = int(payload["iat"])
        except (ValueError, TypeError) as e:
            raise InvalidIssuedAtError(
                "Issued At claim (iat) must be an integer."
            ) from e
        if iat > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (iat)")

    @staticmethod
    def _validate_nbf_fields(
        payload: dict[str, Any], now: float, leeway: float
    ) -> None:
        try:
            nbf = int(payload["nbf"])
        except (ValueError, TypeError) as e:
            raise DecodeError("Not Before claim (nbf) must be an integer.") from e
        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    @staticmethod
    def _validate_exp_fields(
        payload: dict[str, Any], now: float, leeway: float
    ) -> None:
        try:
            exp = int(payload["exp"])
        except (ValueError, TypeError) as e:
            raise DecodeError(
                "Expiration Time claim (exp) must be an integer."
            ) from e
        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    @staticmethod
    def _validate_sub_field(
        payload: dict[str, Any], subject: str | None
    ) -> None:
        if "sub" not in payload:
            return
        if not isinstance(payload["sub"], str):
            raise InvalidSubjectError("Subject must be a string")
        if subject is not None and payload.get("sub") != subject:
            raise InvalidSubjectError("Invalid subject")

    @staticmethod
    def _validate_iss_field(
        payload: dict[str, Any], issuer: str | Iterable[str] | None
    ) -> None:
        if issuer is None:
            return
        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")
        issuers = [issuer] if isinstance(issuer, str) else list(issuer)
        if payload["iss"] not in issuers:
            raise InvalidIssuerError("Invalid issuer")

    @staticmethod
    def _validate_aud_field(
        payload: dict[str, Any], audience: str | Iterable[str] | None
    ) -> None:
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            raise InvalidAudienceError("Invalid audience")
        if "aud" not in payload or not payload["aud"]:
            raise MissingRequiredClaimError("aud")
        audience_claims = payload["aud"]
        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")
        auds = [audience] if isinstance(audience, str) else list(audience)
        if all(a not in audience_claims for a in auds):
            raise InvalidAudienceError("Audience doesn't match")

_jwt = PyJWT()
encode = _jwt.encode
decode = _jwt.decode
decode_complete = _jwt.decode_complete
