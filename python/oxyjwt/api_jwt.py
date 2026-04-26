"""PyJWT-compatible JWT API (encode / decode / decode_complete)."""
from __future__ import annotations

import json
import time
import warnings
from calendar import timegm
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any, cast

from oxyjwt import _oxyjwt
from oxyjwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    MissingRequiredClaimError,
)
from oxyjwt.warnings import RemovedInPyJWT3Warning

_DEFAULT_DECODE_OPTIONS: dict[str, Any] = {
    "verify_signature": True,
    "verify_exp": True,
    "verify_nbf": True,
    "verify_iat": True,
    "verify_aud": True,
    "verify_iss": True,
    "require": [],
}


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
        json_encoder: type[json.JSONEncoder] | None = None,
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
        body = json.dumps(
            pl, separators=(",", ":"), cls=json_encoder, sort_keys=sort_headers
        )
        alg = algorithm if algorithm is not None else "HS256"
        return _oxyjwt.encode_json(body, key, alg, headers)

    def decode(
        self,
        jwt: str | bytes,
        key: object = "",
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | None = None,
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
        issuer: str | None = None,
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
            co.setdefault("verify_exp", False)
            co.setdefault("verify_nbf", False)
            co.setdefault("verify_iat", False)
            co.setdefault("verify_aud", False)
            co.setdefault("verify_iss", False)
        if co.get("verify_signature", True) and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )
        merged = {**self._options, **co}
        if audience is not None and not isinstance(
            audience, (str, Iterable, type(None))
        ):
            raise TypeError("audience must be a string, iterable or None")
        if audience is not None and isinstance(audience, (bytes, bytearray, memoryview)):
            raise TypeError("audience must be a string, iterable or None")

        _s, header_obj, _pld, sigb = _oxyjwt.jws_parse_compact(token)
        header: dict[str, Any] = (
            header_obj
            if isinstance(header_obj, dict)
            else json.loads(json.dumps(header_obj))
        )
        lwf = _leeway_seconds(leeway)
        if not co.get("verify_signature", True):
            pl_d = _oxyjwt.decode_unverified(token)
            if not isinstance(pl_d, dict):
                pl_d = cast(
                    "dict[str, Any]", json.loads(json.dumps(pl_d, default=str))
                )
            self._validate_claims(pl_d, merged, audience, issuer, lwf)
            return {
                "payload": pl_d,
                "header": header,
                "signature": _sig_as_bytes(sigb),
            }
        assert algorithms is not None
        req = [str(x) for x in (merged.get("require") or []) if x is not None]
        dec = _oxyjwt.decode(
            token,
            key,
            list(algorithms),
            audience=audience,
            issuer=issuer,
            subject=None,
            leeway=lwf,
            options=merged,
            require=req,
        )
        pl_out: dict[str, Any]
        if not isinstance(dec, dict):
            pl_out = json.loads(json.dumps(dec, default=str))
        else:
            pl_out = dec
        self._validate_claims(pl_out, merged, audience, issuer, lwf)
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
        issuer: str | None = None,
        leeway: float = 0,
    ) -> None:
        self._validate_required(payload, options)
        now = time.time()
        if "iat" in payload and options.get("verify_iat", True):
            self._validate_iat_fields(payload, now, leeway)
        if "nbf" in payload and options.get("verify_nbf", True):
            self._validate_nbf_fields(payload, now, leeway)
        if "exp" in payload and options.get("verify_exp", True):
            self._validate_exp_fields(payload, now, leeway)
        if options.get("verify_iss", True):
            self._validate_iss_field(payload, issuer)
        if options.get("verify_aud", True):
            self._validate_aud_field(payload, audience)

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
    def _validate_iss_field(
        payload: dict[str, Any], issuer: str | None
    ) -> None:
        if issuer is None:
            return
        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")
        if payload["iss"] != issuer:
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
