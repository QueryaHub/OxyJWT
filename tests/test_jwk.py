from __future__ import annotations

import base64
import json
import warnings

import pytest

import oxyjwt
from oxyjwt.jwk import PyJWK, PyJWKSet
from oxyjwt.jwk_exc import PyJWKError, PyJWKSetError


def _oct_jwk_for_secret(secret: bytes) -> str:
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    return json.dumps({"kty": "oct", "k": k, "kid": "k1"})


def test_pyjwk_from_json_hs256() -> None:
    jw = _oct_jwk_for_secret(b"my-secret")
    a = PyJWK(jw)
    t = oxyjwt.encode({"exp": 9_999_999_999}, b"my-secret", algorithm="HS256")
    oxyjwt.decode(
        t,
        a.key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )


def test_pyjwkset_from_dict() -> None:
    jw = json.loads(_oct_jwk_for_secret(b"x"))
    s = PyJWKSet.from_dict({"keys": [jw]})
    key = s["k1"]
    tok = oxyjwt.encode({"x": 1, "exp": 9_999_999_999}, b"x", algorithm="HS256")
    oxyjwt.decode(
        tok,
        key.key,
        algorithms=["HS256"],
    )


def test_pyjwkset_empty_keys_raises() -> None:
    with pytest.raises(PyJWKSetError):
        PyJWKSet.from_dict({"keys": []})


def test_pyjwk_rejects_encryption_use() -> None:
    secret = b"my-secret-32-bytes-long-ok!!!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    enc_jwk = {"kty": "oct", "k": k, "kid": "enc-k", "use": "enc"}
    with pytest.raises(PyJWKError, match="use=enc"):
        PyJWK(enc_jwk)


def test_pyjwkset_warns_when_skipping_invalid_key() -> None:
    secret = b"good-secret-32-bytes-long-ok!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    bad_jwk = {"kid": "bad-k"}
    good_jwk = {"kty": "oct", "k": k, "kid": "good-k"}
    s = PyJWKSet.from_dict({"keys": [bad_jwk, good_jwk]})
    with pytest.warns(oxyjwt.PyJWKSetSkipWarning, match="index 0") as records:
        assert len(s.keys) == 1
    assert len(records) == 1
    assert "bad-k" in str(records[0].message)
    assert len(s.keys) == 1
    assert s["good-k"].key_id == "good-k"


def test_pyjwkset_skips_enc_keys_keeps_signing_keys() -> None:
    secret = b"signing-key-32-bytes-long-ok!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    enc_jwk = {"kty": "oct", "k": k, "kid": "enc-k", "use": "enc"}
    sig_jwk = {"kty": "oct", "k": k, "kid": "sig-k", "use": "sig"}
    s = PyJWKSet.from_dict({"keys": [enc_jwk, sig_jwk]})
    with pytest.warns(oxyjwt.PyJWKSetSkipWarning, match="enc-k"):
        assert len(s.keys) == 1
    assert s["sig-k"].key_id == "sig-k"
    tok = oxyjwt.encode(
        {"x": 1, "exp": 9_999_999_999},
        secret,
        algorithm="HS256",
        headers={"kid": "sig-k"},
    )
    oxyjwt.decode(
        tok,
        s["sig-k"].key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )


def test_pyjwkset_only_encryption_keys_raises() -> None:
    secret = b"my-secret-32-bytes-long-ok!!!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    enc_jwk = {"kty": "oct", "k": k, "kid": "enc-k", "use": "enc"}
    s = PyJWKSet.from_dict({"keys": [enc_jwk]})
    with pytest.warns(oxyjwt.PyJWKSetSkipWarning):
        with pytest.raises(PyJWKSetError, match="usable keys"):
            _ = s.keys


def test_pyjwkset_getitem_uses_kid_index() -> None:
    secret = b"signing-key-32-bytes-long-ok!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    s = PyJWKSet.from_dict(
        {
            "keys": [
                {"kty": "oct", "k": k, "kid": "a"},
                {"kty": "oct", "k": k, "kid": "b"},
            ]
        }
    )
    assert s["b"] is s._by_kid["b"]  # noqa: SLF001


def test_pyjwk_lazy_decoding_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import oxyjwt

    calls: list[int] = []
    orig = oxyjwt._oxyjwt.DecodingKey.from_jwk

    def counting(jwk: object) -> object:
        calls.append(1)
        return orig(jwk)

    monkeypatch.setattr(oxyjwt._oxyjwt.DecodingKey, "from_jwk", counting)
    secret = b"my-secret-32-bytes-long-ok!!!!"
    kb = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    jwk = PyJWK({"kty": "oct", "k": kb, "kid": "k1"})
    assert calls == []
    _ = jwk.key
    assert len(calls) == 1
    _ = jwk.key
    assert len(calls) == 1


def test_pyjwkset_only_parses_used_key(monkeypatch: pytest.MonkeyPatch) -> None:
    import oxyjwt

    calls: list[str] = []
    orig = oxyjwt._oxyjwt.DecodingKey.from_jwk

    def counting(jwk: dict[str, object]) -> object:
        kid = jwk.get("kid")
        calls.append(str(kid))
        return orig(jwk)

    monkeypatch.setattr(oxyjwt._oxyjwt.DecodingKey, "from_jwk", counting)
    secret = b"signing-key-32-bytes-long-ok!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    s = PyJWKSet.from_dict(
        {
            "keys": [
                {"kty": "oct", "k": k, "kid": "unused"},
                {"kty": "oct", "k": k, "kid": "used"},
            ]
        }
    )
    assert calls == []
    tok = oxyjwt.encode(
        {"x": 1, "exp": 9_999_999_999},
        secret,
        algorithm="HS256",
        headers={"kid": "used"},
    )
    oxyjwt.decode(
        tok,
        s["used"].key,
        algorithms=["HS256"],
        options={"verify_exp": False},
    )
    assert calls == ["used"]


def test_pyjwkset_valid_keys_load_without_warning() -> None:
    jw = json.loads(_oct_jwk_for_secret(b"no-warn-secret-32-bytes-ok!"))
    with warnings.catch_warnings():
        warnings.simplefilter("error", oxyjwt.PyJWKSetSkipWarning)
        s = PyJWKSet.from_dict({"keys": [jw]})
    assert len(s.keys) == 1


def test_pyjwkset_duplicate_kid_enc_before_sig() -> None:
    secret = b"signing-key-32-bytes-long-ok!!"
    k = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    enc_jwk = {"kty": "oct", "k": k, "kid": "k1", "use": "enc"}
    sig_jwk = {"kty": "oct", "k": k, "kid": "k1", "use": "sig"}
    s = PyJWKSet.from_dict({"keys": [enc_jwk, sig_jwk]})
    # Directly looking up k1 should return the signing key, not fail on enc key
    jwk = s["k1"]
    assert jwk.key_id == "k1"
    assert jwk.public_key_use == "sig"
    assert jwk.key is not None

