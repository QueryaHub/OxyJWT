"""PyJWT-compatible JWT API (encode / decode / decode_complete)."""
from __future__ import annotations

import math
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
    InvalidTokenError,
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
    "strict_aud": False,
    "require": [],
}

_UNVERIFIED_DECODE_WARNING = (
    "Unverified JWT decoding is insecure. The token was parsed without "
    "signature verification; claims must not be used for authorization."
)

# Distinguishes "claim absent" from "claim present but null", which must still
# be rejected as a malformed value.
_MISSING: Any = object()


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


def _leeway_is_whole_seconds(leeway: float) -> bool:
    """True when leeway is an integer number of seconds (Rust jsonwebtoken path)."""
    rounded = round(leeway)
    return math.isclose(leeway, rounded, rel_tol=0.0, abs_tol=1e-9)


def _as_plain_dict(obj: Any) -> dict[str, Any]:
    """Normalize claims/header to a plain dict without JSON round-trip."""
    if isinstance(obj, dict):
        return cast("dict[str, Any]", obj)
    if isinstance(obj, Mapping):
        return {str(k): v for k, v in obj.items()}
    raise TypeError("expected JSON object for JWT claims or header")


def _require_detached_payload_for_rfc7797(
    token: str,
    *,
    detached_payload: bytes | None,
    verify_signature: bool,
) -> None:
    """Raise when verified decode needs RFC 7797 detached_payload (b64: false)."""
    if detached_payload is not None or not verify_signature:
        return
    # The b64:false form has an empty payload segment, and base64url never
    # contains a dot, so ".." is the only way it can appear. Checking for it
    # first keeps ordinary tokens off the split/header-parse path.
    if ".." not in token:
        return
    segments = token.split(".", 2)
    if len(segments) < 3 or segments[1] != "":
        return
    header_peek = _as_plain_dict(_oxyjwt.get_unverified_header(token))
    if header_peek.get("b64") is False:
        raise DecodeError(
            'It is required that you pass in a value for the "detached_payload" '
            "argument to decode a message having the b64 header set to false."
        )


def _check_string_or_iterable(value: object, name: str) -> None:
    """Reject values that cannot name an audience or issuer.

    Bytes-like objects are iterable but would compare per-byte, so they are
    excluded even though they satisfy the ``Iterable`` check.
    """
    if isinstance(value, (bytes, bytearray, memoryview)) or not isinstance(
        value, (str, Iterable)
    ):
        raise TypeError(f"{name} must be a string, iterable or None")


def _is_plain_decode(
    options: dict[str, Any] | None,
    verify: bool | None,
    detached_payload: bytes | None,
    audience: object,
    issuer: object,
    subject: str | None,
    leeway: float | timedelta,
    typ: str | None,
    algorithms: list[str] | None,
) -> bool:
    """True when no argument changes the default verified-decode behaviour.

    With nothing but ``algorithms`` supplied, Rust validates ``exp``/``nbf``
    and has no audience/issuer/subject to check, so the remaining claim rules
    reduce to :meth:`PyJWT._validate_claims_default`. A ``timedelta`` leeway
    never compares equal to ``0`` and therefore takes the general path, as do
    algorithm containers the native module cannot read directly (a set or an
    iterator), which the general path normalises with ``list()``.
    """
    return (
        options is None
        and audience is None
        and issuer is None
        and subject is None
        and typ is None
        and detached_payload is None
        and verify is None
        and leeway == 0
        and bool(algorithms)
        and isinstance(algorithms, (list, tuple))
    )


def _json_default_from_encoder(encoder_cls: type[JSONEncoder]) -> Callable[[Any], Any]:
    enc = encoder_cls()

    def default(obj: Any) -> Any:
        return enc.default(obj)

    return default


class PyJWT:
    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self._options: dict[str, Any] = {**_DEFAULT_DECODE_OPTIONS, **(options or {})}
        # Instance options can switch individual checks off, so the fast decode
        # path is only equivalent while every default is still in place.
        self._default_options: bool = self._options == _DEFAULT_DECODE_OPTIONS

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
        # Copy only when a datetime actually has to be rewritten, so the common
        # case of integer time claims does not pay for a dict copy.
        pl = payload
        for time_claim in ("exp", "iat", "nbf"):
            v = payload.get(time_claim)
            if isinstance(v, datetime):
                if pl is payload:
                    pl = dict(payload)
                pl[time_claim] = timegm(v.utctimetuple())
        alg = algorithm if algorithm is not None else "HS256"
        # `sort_headers` does not affect the output: claim keys come out sorted
        # either way, because the native `encode` entry point backs JSON objects
        # with serde_json's BTreeMap. Serializing once with orjson and handing
        # the bytes to Rust is the cheaper of the two equivalent routes.
        _ = sort_headers
        if json_encoder is None:
            body_b = orjson.dumps(pl, option=orjson.OPT_SORT_KEYS)
        else:
            body_b = orjson.dumps(
                pl,
                option=orjson.OPT_SORT_KEYS,
                default=_json_default_from_encoder(json_encoder),
            )
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
        typ: str | None = None,
        **kwargs: Any,
    ) -> Any:
        if (
            self._default_options
            and not kwargs
            and _is_plain_decode(
                options, verify, detached_payload, audience, issuer, subject, leeway,
                typ, algorithms,
            )
        ):
            token = jwt if isinstance(jwt, str) else jwt.decode("utf-8")
            _require_detached_payload_for_rfc7797(
                token, detached_payload=None, verify_signature=True
            )
            payload = _oxyjwt.decode(token, key, algorithms)
            self._validate_claims_default(payload)
            return payload
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyJWT3Warning,
                stacklevel=2,
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
            typ=typ,
        )["payload"]

    def decode_complete(
        self,
        jwt: str | bytes,
        key: object = "",
        algorithms: list[str] | None = None,
        options: dict[str, Any] | None = None,
        *,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Iterable[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
        typ: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if (
            self._default_options
            and not kwargs
            and _is_plain_decode(
                options, verify, detached_payload, audience, issuer, subject, leeway,
                typ, algorithms,
            )
        ):
            token = jwt if isinstance(jwt, str) else jwt.decode("utf-8")
            _require_detached_payload_for_rfc7797(
                token, detached_payload=None, verify_signature=True
            )
            payload, header, signature = _oxyjwt.decode_verified_complete(
                token, key, algorithms
            )
            self._validate_claims_default(payload)
            return {"payload": payload, "header": header, "signature": signature}
        if kwargs:
            first = next(iter(kwargs))
            warnings.warn(
                f"passing {first!r} to decode() is deprecated and will be removed in PyJWT 3.0.0",
                RemovedInPyJWT3Warning,
                stacklevel=2,
            )
        token = jwt if isinstance(jwt, str) else jwt.decode("utf-8")
        if detached_payload is not None and not isinstance(
            detached_payload, (bytes, bytearray, memoryview)
        ):
            raise TypeError("detached_payload must be bytes")
        # Match PyJWT: JWS/algorithm gating uses call-only `options` + setdefault, then merge for claims
        co: dict[str, Any] = dict(options) if options else {}
        co.setdefault("verify_signature", True)
        verify_signature = bool(co["verify_signature"])
        if typ is not None:
            co["typ"] = typ
            co["verify_typ"] = True
        if verify is not None and verify != co["verify_signature"]:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                DeprecationWarning,
                stacklevel=2,
            )
        if not verify_signature:
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
        if verify_signature and not algorithms:
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )
        _require_detached_payload_for_rfc7797(
            token,
            detached_payload=detached_payload,
            verify_signature=verify_signature,
        )
        if len(co) == 1 and verify_signature and self._default_options:
            # `co` holds nothing but the implied verify_signature=True, so the
            # merge would reproduce the instance options exactly. Nothing below
            # mutates `merged`, so it is safe to alias.
            merged = self._options
        else:
            merged = {**self._options, **co}
        if not verify_signature:
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
        if audience is not None:
            _check_string_or_iterable(audience, "audience")
        if issuer is not None:
            _check_string_or_iterable(issuer, "issuer")

        lwf = _leeway_seconds(leeway)
        if not verify_signature:
            _s, header_obj, pld_bytes, sigb = _oxyjwt.jws_parse_compact(token)
            header = _as_plain_dict(header_obj)
            if detached_payload is not None:
                pld_bytes = bytes(detached_payload)
            pl_out = _as_plain_dict(
                orjson.loads(pld_bytes)
                if pld_bytes
                else {}
            )
            self._validate_headers(header, merged)
            self._validate_claims(
                pl_out,
                merged,
                audience,
                issuer,
                subject,
                lwf,
                rust_time_claims=False,
                rust_standard_claims=False,
            )
            return {
                "payload": pl_out,
                "header": header,
                "signature": _sig_as_bytes(sigb),
            }
        assert algorithms is not None
        req = merged.get("require", [])
        if req is not None and not isinstance(req, (list, tuple)):
            req = list(req)
        whole_leeway = _leeway_is_whole_seconds(lwf)
        if whole_leeway:
            rust_options: dict[str, Any] = merged
        else:
            # Fractional leeway cannot be expressed in jsonwebtoken's
            # whole-second validation, so Python takes over exp/nbf.
            rust_options = {**merged, "verify_exp": False, "verify_nbf": False}
        dec, header_obj, sigb = _oxyjwt.decode_verified_complete(
            token,
            key,
            algorithms if isinstance(algorithms, (list, tuple)) else list(algorithms),
            audience=audience,
            issuer=issuer,
            subject=subject,
            leeway=lwf,
            options=rust_options,
            require=req,
            detached_payload=bytes(detached_payload)
            if detached_payload is not None
            else None,
        )
        header = _as_plain_dict(header_obj)
        pl_out = _as_plain_dict(dec)
        self._validate_headers(header, merged)
        self._validate_claims(
            pl_out,
            merged,
            audience,
            issuer,
            subject,
            lwf,
            rust_time_claims=whole_leeway,
            rust_standard_claims=whole_leeway and detached_payload is None,
        )
        return {
            "payload": pl_out,
            "header": header,
            "signature": _sig_as_bytes(sigb),
        }

    def _validate_claims_default(self, payload: dict[str, Any]) -> None:
        """Claim checks left to Python after a plain verified decode.

        Equivalent to :meth:`_validate_claims` with default options, no
        ``require`` list, zero leeway and both ``rust_time_claims`` and
        ``rust_standard_claims`` true: Rust already validated ``exp``/``nbf``,
        so only ``iat``, the Python ``exp`` boundary, the "no audience
        expected" rule and the ``sub`` type check remain.
        """
        now = time.time()

        iat = payload.get("iat", _MISSING)
        if iat is not _MISSING:
            try:
                iat_value = int(iat)
            except (ValueError, TypeError) as e:
                raise InvalidIssuedAtError(
                    "Issued At claim (iat) must be an integer."
                ) from e
            if iat_value > now:
                raise ImmatureSignatureError("The token is not yet valid (iat)")

        exp = payload.get("exp", _MISSING)
        if exp is not _MISSING:
            try:
                exp_value = int(exp)
            except (ValueError, TypeError) as e:
                raise DecodeError(
                    "Expiration Time claim (exp) must be an integer."
                ) from e
            if exp_value <= now:
                raise ExpiredSignatureError("Signature has expired")

        if payload.get("aud"):
            raise InvalidAudienceError("Invalid audience")

        sub = payload.get("sub", _MISSING)
        if sub is not _MISSING and not isinstance(sub, str):
            raise InvalidSubjectError("Subject must be a string")

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
        rust_standard_claims: bool = False,
    ) -> None:
        """Validate claims after decode.

        Verified decode (`rust_time_claims=True`): ``exp`` and ``nbf`` are checked in
        Rust (jsonwebtoken); this layer handles ``iat`` plus audience/issuer/sub
        rules that depend on call-time parameters.

        When ``rust_standard_claims=True``, aud/iss/sub checks already run in Rust
        for call-time ``audience`` / ``issuer`` / ``subject``; Python still runs
        ``strict_aud`` and claim checks Rust does not cover.
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
        strict_aud = bool(options.get("strict_aud", False))
        if options.get("verify_aud", True):
            if strict_aud or not (
                rust_standard_claims and audience is not None
            ):
                self._validate_aud_field(
                    payload,
                    audience,
                    strict=strict_aud,
                )
        if options.get("verify_iss", True) and (
            issuer is not None or not rust_standard_claims
        ):
            self._validate_iss_field(payload, issuer)
        if options.get("verify_sub", True) and not (
            rust_standard_claims and subject is not None
        ):
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
            raise InvalidIssuerError("Invalid issuer")
        issuers = [issuer] if isinstance(issuer, str) else list(issuer)
        if payload["iss"] not in issuers:
            raise InvalidIssuerError("Invalid issuer")

    @staticmethod
    def _validate_aud_field(
        payload: dict[str, Any],
        audience: str | Iterable[str] | None,
        *,
        strict: bool = False,
    ) -> None:
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            raise InvalidAudienceError("Invalid audience")
        if "aud" not in payload or not payload["aud"]:
            raise MissingRequiredClaimError("aud")
        audience_claims = payload["aud"]
        if strict:
            if not isinstance(audience, str):
                raise InvalidAudienceError("Invalid audience (strict)")
            if not isinstance(audience_claims, str):
                raise InvalidAudienceError(
                    "Invalid claim format in token (strict)"
                )
            if audience != audience_claims:
                raise InvalidAudienceError("Audience doesn't match (strict)")
            return
        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")
        auds = [audience] if isinstance(audience, str) else list(audience)
        if all(a not in audience_claims for a in auds):
            raise InvalidAudienceError("Audience doesn't match")

    @staticmethod
    def _validate_headers(
        header: dict[str, Any], options: dict[str, Any]
    ) -> None:
        if options.get("verify_typ", False) or "typ" in options:
            expected_typ = options.get("typ")
            actual_typ = header.get("typ")
            if expected_typ is not None:
                if actual_typ is None or str(actual_typ).lower() != str(expected_typ).lower():
                    raise InvalidTokenError(
                        f"Invalid token type: expected {expected_typ!r}, got {actual_typ!r}"
                    )
            elif actual_typ is None:
                raise InvalidTokenError("Header is missing 'typ' parameter")


_jwt = PyJWT()
encode = _jwt.encode
decode = _jwt.decode
decode_complete = _jwt.decode_complete
