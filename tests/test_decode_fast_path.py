"""Regression tests for the fast decode path and its equivalence guarantees.

`decode` and `decode_complete` take a shortened route when nothing but
``algorithms`` is supplied: Rust validates ``exp``/``nbf``, the options dict is
not built at all, and Python only runs the checks that are left. Because
``options={}`` merges to exactly the default options, the general path is a
behavioural oracle for that shortcut, and most tests here assert the two agree.
"""
from __future__ import annotations

import datetime
import itertools
import time
from typing import Any

import pytest

import oxyjwt
from oxyjwt.api_jwt import PyJWT

SECRET = "fast-path-secret-with-more-than-enough-length-for-hs256"
NOW = int(time.time())


def _outcome(fn: Any) -> Any:
    """Result or (exception type, message), so both can be compared."""
    try:
        return ("ok", fn())
    except Exception as e:  # noqa: BLE001 - the failure mode is what we compare
        return ("err", type(e), str(e))


def _fast_and_general(payload: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    token = oxyjwt.encode(payload, SECRET, "HS256")
    return (
        _outcome(lambda: oxyjwt.decode(token, SECRET, algorithms=["HS256"])),
        _outcome(lambda: oxyjwt.decode(token, SECRET, algorithms=["HS256"], options={})),
        _outcome(lambda: oxyjwt.decode_complete(token, SECRET, algorithms=["HS256"])),
        _outcome(
            lambda: oxyjwt.decode_complete(
                token, SECRET, algorithms=["HS256"], options={}
            )
        ),
    )


CLAIM_VALUES: list[Any] = [
    None, 0, 1, "text", "", [], ["a"], {}, True, 1.5, NOW + 3600, NOW - 3600,
]


@pytest.mark.parametrize("claim", ["exp", "iat", "nbf", "aud", "sub", "iss"])
@pytest.mark.parametrize("value", CLAIM_VALUES)
def test_fast_path_matches_general_path_for_single_claim(claim: str, value: Any) -> None:
    fast, general, fast_complete, general_complete = _fast_and_general({claim: value})
    assert fast == general
    assert fast_complete == general_complete


@pytest.mark.parametrize(
    ("first", "second"),
    list(itertools.combinations(["exp", "nbf", "aud", "sub"], 2)),
)
def test_fast_path_matches_general_path_for_claim_pairs(first: str, second: str) -> None:
    for a, b in itertools.product([None, 1, "x", NOW + 60], repeat=2):
        fast, general, fast_complete, general_complete = _fast_and_general(
            {first: a, second: b}
        )
        assert fast == general, f"{first}={a!r} {second}={b!r}"
        assert fast_complete == general_complete, f"{first}={a!r} {second}={b!r}"


def test_fast_path_returns_same_payload_header_and_signature() -> None:
    payload = {"sub": "u", "exp": NOW + 600, "data": {"z": 1, "a": [1, 2]}}
    token = oxyjwt.encode(payload, SECRET, "HS256")
    fast = oxyjwt.decode_complete(token, SECRET, algorithms=["HS256"])
    general = oxyjwt.decode_complete(token, SECRET, algorithms=["HS256"], options={})
    assert fast == general
    assert fast["payload"] == payload
    assert fast["header"] == {"typ": "JWT", "alg": "HS256"}
    assert isinstance(fast["signature"], bytes)


def test_fast_path_rejects_bad_signature() -> None:
    token = oxyjwt.encode({"sub": "u"}, SECRET, "HS256")
    with pytest.raises(oxyjwt.InvalidSignatureError):
        oxyjwt.decode(token, "a-different-secret-of-similar-size", algorithms=["HS256"])


def test_fast_path_rejects_disallowed_algorithm() -> None:
    token = oxyjwt.encode({"sub": "u"}, SECRET, "HS384")
    with pytest.raises(oxyjwt.InvalidTokenError):
        oxyjwt.decode(token, SECRET, algorithms=["HS256"])


@pytest.mark.parametrize(
    "algorithms",
    [["HS256"], ("HS256",), {"HS256"}, ["HS256", "HS384"], frozenset({"HS256"})],
)
def test_algorithms_accepts_any_container(algorithms: Any) -> None:
    """A set or other non-sequence must not be rejected by the fast path."""
    token = oxyjwt.encode({"sub": "u"}, SECRET, "HS256")
    assert oxyjwt.decode(token, SECRET, algorithms=algorithms) == {"sub": "u"}


def test_algorithms_accepts_iterator() -> None:
    token = oxyjwt.encode({"sub": "u"}, SECRET, "HS256")
    algorithms: Any = iter(["HS256"])
    assert oxyjwt.decode(token, SECRET, algorithms=algorithms) == {"sub": "u"}


def test_instance_options_disable_fast_path() -> None:
    """Options set on the instance must still switch checks off."""
    token = oxyjwt.encode({"sub": "u", "exp": NOW - 10}, SECRET, "HS256")
    lenient = PyJWT(options={"verify_exp": False})
    assert lenient.decode(token, SECRET, algorithms=["HS256"])["sub"] == "u"
    with pytest.raises(oxyjwt.ExpiredSignatureError):
        PyJWT().decode(token, SECRET, algorithms=["HS256"])


def test_detached_payload_token_still_rejected_without_payload() -> None:
    """A b64:false token must not slip through the fast path unverified."""
    import base64
    import json as json_mod

    header = base64.urlsafe_b64encode(
        json_mod.dumps({"alg": "HS256", "b64": False, "crit": ["b64"]}).encode()
    ).decode().rstrip("=")
    token = f"{header}..c2ln"
    with pytest.raises(oxyjwt.DecodeError):
        oxyjwt.decode(token, SECRET, algorithms=["HS256"])


@pytest.mark.parametrize("leeway", [0, 0.0])
def test_zero_leeway_uses_fast_path_and_matches(leeway: float) -> None:
    token = oxyjwt.encode({"sub": "u", "exp": NOW + 60}, SECRET, "HS256")
    assert oxyjwt.decode(token, SECRET, algorithms=["HS256"], leeway=leeway) == (
        oxyjwt.decode(token, SECRET, algorithms=["HS256"], options={})
    )


def test_timedelta_leeway_still_honoured() -> None:
    token = oxyjwt.encode({"sub": "u", "exp": NOW - 5}, SECRET, "HS256")
    assert oxyjwt.decode(
        token, SECRET, algorithms=["HS256"], leeway=datetime.timedelta(seconds=60)
    )["sub"] == "u"


class TestRequiredClaims:
    """`require` follows PyJWT: a JSON null counts as an absent claim."""

    @staticmethod
    def _decode(payload: dict[str, Any], require: list[str]) -> Any:
        token = oxyjwt.encode(payload, SECRET, "HS256")
        return oxyjwt.decode(
            token, SECRET, algorithms=["HS256"], options={"require": require}
        )

    def test_null_claim_counts_as_missing(self) -> None:
        with pytest.raises(oxyjwt.MissingRequiredClaimError):
            self._decode({"sub": "u", "exp": None}, ["exp"])

    def test_null_subject_counts_as_missing(self) -> None:
        with pytest.raises(oxyjwt.MissingRequiredClaimError):
            self._decode({"sub": None, "exp": NOW + 60}, ["sub"])

    def test_absent_claim_reported_as_missing(self) -> None:
        with pytest.raises(oxyjwt.MissingRequiredClaimError):
            self._decode({"sub": "u"}, ["exp"])

    def test_malformed_claim_reported_as_bad_format(self) -> None:
        """Present but unparseable is a decode failure, not a missing claim."""
        with pytest.raises(oxyjwt.DecodeError):
            self._decode({"sub": "u", "exp": "not-a-number"}, ["exp"])

    def test_missing_claim_message_is_deterministic(self) -> None:
        """The named claim must not depend on hash-set iteration order."""
        messages = set()
        for _ in range(20):
            with pytest.raises(oxyjwt.MissingRequiredClaimError) as excinfo:
                self._decode({"name": "n"}, ["exp", "sub", "aud", "iss", "nbf"])
            messages.add(str(excinfo.value))
        assert len(messages) == 1


class TestEncodeInvariants:
    def test_caller_payload_is_not_mutated(self) -> None:
        payload = {
            "exp": datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc),
            "sub": "u",
        }
        before = dict(payload)
        oxyjwt.encode(payload, SECRET, "HS256")
        assert payload == before

    @pytest.mark.parametrize(
        "payload",
        [
            {"zeta": 1, "alpha": 2, "mid": 3},
            {"sub": "u", "exp": NOW + 60},
            {"nested": {"z": 1, "a": [1, 2, {"q": None}]}},
        ],
    )
    def test_sort_headers_does_not_change_output(self, payload: dict[str, Any]) -> None:
        """Claim keys are emitted sorted either way; the flag is output-neutral."""
        assert oxyjwt.encode(payload, SECRET, "HS256", sort_headers=True) == (
            oxyjwt.encode(payload, SECRET, "HS256", sort_headers=False)
        )
