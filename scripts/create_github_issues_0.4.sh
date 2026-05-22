#!/usr/bin/env bash
# One-time: create 0.4.0 roadmap issues. Requires: gh auth, milestone "0.4.0".
set -euo pipefail
cd "$(dirname "$0")/.."
MILESTONE="0.4.0"

create() {
  local title="$1"
  shift
  gh issue create --title "$title" --body "$1" --label "$2" --milestone "$MILESTONE"
}

# --- P0 Security ---
create "security(jwks): refresh JWKS once when signing key kid is missing" "$(cat <<'EOF'
## Problem
`PyJWKClient.get_signing_key` raises on unknown `kid` but does not refetch JWKS. IdP key rotation breaks verification until manual cache clear.

## Acceptance criteria
- [ ] On `KeyError` for `kid`, call `get_jwk_set(refresh=True)` once and retry lookup
- [ ] No infinite refresh loop (single retry per call)
- [ ] Tests: simulate rotation (two JWKS responses) in `tests/test_jwks_client.py`
- [ ] Document behavior in `docs-site/docs/api-reference.md`

## Files
- `python/oxyjwt/jwks_client.py`
- `tests/test_jwks_client.py`

## Branch
`issue/<N>-jwks-refresh-on-miss` from `dev`
EOF
)" "p0,security"

create "security(api): warn and guard unverified decode (verify_signature=False)" "$(cat <<'EOF'
## Problem
`decode(..., verify_signature=False)` bypasses signature and some claim checks (`subject` etc.). Easy footgun in production.

## Acceptance criteria
- [ ] Emit `warnings.warn` (PyJWT-style) when signature verification is disabled
- [ ] Reject or document `subject` / `require` without verify (align with PyJWT semantics)
- [ ] Tests in `tests/test_validation.py` or dedicated security tests
- [ ] Note in `SECURITY.md` and decoding docs

## Files
- `python/oxyjwt/api_jwt.py`
- `rust/src/api.rs` (if Rust path involved)
- `tests/`, `docs-site/docs/usage/decoding.md`

## Branch
`issue/<N>-unverified-decode-warnings` from `dev`
EOF
)" "p0,security"

create "fix(api): support issuer as list (docs and Rust already allow)" "$(cat <<'EOF'
## Problem
`_validate_iss_field` only accepts `str`, but docs and Rust `Validation` accept a list of issuers. Multi-issuer setups get false `InvalidIssuerError`.

## Acceptance criteria
- [ ] Python validation mirrors `_validate_aud_field` (str or list of str)
- [ ] Parity test vs PyJWT for list issuer
- [ ] Docs already correct — no doc drift

## Files
- `python/oxyjwt/api_jwt.py`
- `tests/test_validation.py`, `tests/test_parity_pyjwt.py`

## Branch
`issue/<N>-issuer-list-validation` from `dev`
EOF
)" "p0,security"

# --- P0 Performance ---
create "perf(encode): remove double JSON serialization on encode path" "$(cat <<'EOF'
## Problem
Encode path: `orjson.dumps` → UTF-8 `str` → `serde_json::from_str` in Rust (`encode_json`). Wastes CPU on hot path.

## Acceptance criteria
- [ ] Single serialization: e.g. `orjson` bytes → `from_slice`, or `_oxyjwt.encode` + `py_to_json`
- [ ] All encode tests and parity tests green
- [ ] Benchmark shows improved HS256 encode ops/s vs 0.3.0 baseline

## Files
- `python/oxyjwt/api_jwt.py`
- `rust/src/api.rs`, `rust/src/claims.rs`
- `tests/test_benchmark_jwt_libraries.py` (optional threshold update)

## Branch
`issue/<N>-encode-single-json` from `dev`
EOF
)" "p0,performance"

create "perf(decode): single-parse decode_complete in Rust" "$(cat <<'EOF'
## Problem
Verified decode parses JWT twice: `jws_parse_compact` then full `jsonwebtoken` decode in `_oxyjwt.decode`.

## Acceptance criteria
- [ ] New or extended Rust API: parse once, verify, return header/payload dicts
- [ ] Python `decode_complete` uses unified path without redundant parse
- [ ] Tests unchanged behavior; benchmark decode mean ms improves

## Files
- `rust/src/jws.rs`, `rust/src/api.rs`
- `python/oxyjwt/api_jwt.py`

## Branch
`issue/<N>-decode-complete-single-parse` from `dev`
EOF
)" "p0,performance"

create "perf(api): drop unnecessary orjson round-trips on claims normalization" "$(cat <<'EOF'
## Problem
`_claims_to_plain_dict` uses orjson dumps+loads to normalize PyO3 objects on hot paths.

## Acceptance criteria
- [ ] Use `json_to_py` / direct dict conversion where sufficient
- [ ] No regression in claim types (int, str, nested dict)
- [ ] Covered by existing decode tests

## Files
- `python/oxyjwt/api_jwt.py`

## Branch
`issue/<N>-claims-no-roundtrip` from `dev`
EOF
)" "p0,performance"

# --- P1 Security ---
create "security(jwks): limit JWKS response size and optional require_https" "$(cat <<'EOF'
## Acceptance criteria
- [ ] `max_bytes` on fetch (default safe, e.g. 256 KiB)
- [ ] Optional `require_https` (opt-in, safe default)
- [ ] Tests: reject oversized body; HTTPS-only when enabled
- [ ] Document in api-reference

## Files
- `python/oxyjwt/jwks_client.py`
- `tests/test_jwks_client.py`
EOF
)" "p1,security"

create "security(jwks): validate JWT alg against allow-list before kid lookup" "$(cat <<'EOF'
## Acceptance criteria
- [ ] In `get_signing_key_from_jwt`, reject alg not in caller's `algorithms` before JWKS lookup
- [ ] Test algorithm confusion / wrong alg header

## Files
- `python/oxyjwt/jwks_client.py`
- `tests/test_jwks_client.py`
EOF
)" "p1,security"

create "security(validation): align claim validation between Rust and Python" "$(cat <<'EOF'
## Problem
Split validation: Rust `Validation` vs Python `_validate_claims` (e.g. `iat` only in Python layer).

## Acceptance criteria
- [ ] Document or unify: single source of truth for time claims
- [ ] Parity tests for edge cases (clock skew, missing iat)

## Files
- `python/oxyjwt/api_jwt.py`
- `rust/src/validation.rs`
- `tests/test_validation.py`
EOF
)" "p1,security"

create "fix(rust): align leeway types (f64 vs u64) between Rust and Python" "$(cat <<'EOF'
## Problem
Sub-second leeway may be truncated in Rust (`u64`) while Python accepts floats.

## Acceptance criteria
- [ ] Consistent leeway semantics across layers
- [ ] Tests for fractional leeway if supported, or explicit doc that only integer seconds apply in Rust path

## Files
- `rust/src/validation.rs`
- `python/oxyjwt/api_jwt.py`
EOF
)" "p1,security"

create "security(jwk): fail-fast or warn when PyJWKSet skips invalid keys" "$(cat <<'EOF'
## Acceptance criteria
- [ ] Invalid JWK entries: warn with kid/index or raise (choose PyJWT-aligned behavior)
- [ ] Test silent-skip vs explicit error

## Files
- `python/oxyjwt/jwk.py`
- `tests/`
EOF
)" "p1,security"

create "security(jwk): reject encryption keys (use: enc) for signature verification" "$(cat <<'EOF'
## Acceptance criteria
- [ ] `PyJWK` / verify path rejects `use: enc` keys
- [ ] Test with enc JWK in set

## Files
- `python/oxyjwt/jwk.py`
- `tests/`
EOF
)" "p1,security"

# --- P1 Performance ---
create "perf(jwks): O(1) kid index and lazy DecodingKey parsing" "$(cat <<'EOF'
## Acceptance criteria
- [ ] `dict[kid]` (or similar) for lookup in `PyJWKSet`
- [ ] Lazy `DecodingKey.from_jwk` until key is used
- [ ] JWKS client tests still pass

## Files
- `python/oxyjwt/jwk.py`
- `python/oxyjwt/jwks_client.py`
EOF
)" "p1,performance"

create "perf(rust): release GIL on decode_unverified and heavy JWS parse" "$(cat <<'EOF'
## Acceptance criteria
- [ ] `py.detach` or equivalent for `decode_unverified` / `jws_parse_compact` where safe
- [ ] No functional regression

## Files
- `rust/src/api.rs`
EOF
)" "p1,performance"

# --- P1 Features ---
create "feat(jwks): PyJWKClient ssl_context and custom headers" "$(cat <<'EOF'
## Acceptance criteria
- [ ] Constructor accepts `ssl_context` and `headers` (PyJWT 2.8 subset)
- [ ] Tests with mock or custom SSL context
- [ ] `docs-site/docs/api-reference.md` updated

## Files
- `python/oxyjwt/jwks_client.py`
EOF
)" "p1,enhancement"

create "feat(jwks): PyJWKClient lifespan TTL for cached JWKS" "$(cat <<'EOF'
## Acceptance criteria
- [ ] Optional `lifespan` seconds; refresh after expiry
- [ ] Works with refresh-on-miss
- [ ] Tests + docs

## Files
- `python/oxyjwt/jwks_client.py`
EOF
)" "p1,enhancement"

create "feat(api): add strict_aud option (PyJWT parity)" "$(cat <<'EOF'
## Acceptance criteria
- [ ] `strict_aud` behavior matches PyJWT when enabled
- [ ] Parity test in `test_parity_pyjwt.py`

## Files
- `python/oxyjwt/api_jwt.py`
- `rust/src/validation.rs` (if needed)
EOF
)" "p1,enhancement"

create "feat(jwks): cache_keys PyJWT parity (default off)" "$(cat <<'EOF'
## Acceptance criteria
- [ ] `cache_keys` parameter on `PyJWKClient` (default False for safe tier-2)
- [ ] Document difference vs PyJWT default

## Files
- `python/oxyjwt/jwks_client.py`
EOF
)" "p1,enhancement"

# --- P1 DX / CI ---
create "test(security): regression suite for 0.4.0 security fixes" "$(cat <<'EOF'
## Scope
- JWKS rotation refresh
- verify_signature=False + subject
- multi-issuer
- oversized JWKS
- algorithm confusion

## Acceptance criteria
- [ ] Dedicated test module or marked section
- [ ] CI always runs (no env flag required)

## Files
- `tests/test_security_regression.py` (new) or extend existing
EOF
)" "p1,testing"

create "ci(bench): stricter benchmark regression gates in CI" "$(cat <<'EOF'
## Acceptance criteria
- [ ] Tighten thresholds after encode/decode perf fixes (not 4× PyJWT slack forever)
- [ ] Separate smoke vs full benchmark workflow documented
- [ ] Baseline artifact or documented ratio in `docs-site/docs/benchmarks.md`

## Files
- `tests/test_benchmark_jwt_libraries.py`
- `.github/workflows/benchmarks.yml`
EOF
)" "p1,testing"

create "docs(api): document PyJWKClient parameters and security options" "$(cat <<'EOF'
## Acceptance criteria
- [ ] Full `PyJWKClient` section in api-reference
- [ ] Cross-link SECURITY.md for JWKS and unverified decode

## Files
- `docs-site/docs/api-reference.md`
- `SECURITY.md`
EOF
)" "p1,documentation"

create "feat(typing): public .pyi stubs for PyJWT, PyJWKClient, JWK" "$(cat <<'EOF'
## Acceptance criteria
- [ ] Stubs for main public API
- [ ] Optional mypy job in CI or documented local check

## Files
- `python/oxyjwt/*.pyi` or `python/oxyjwt-stubs/`
- `pyproject.toml` if package layout changes
EOF
)" "p1,enhancement"

# --- P2 ---
create "security(rust): zeroize HMAC key material after use" "$(cat <<'EOF'
Post-1.0 hardening. `zeroize` in Cargo.toml unused.

## Files
- `rust/src/keys.rs`, `rust/Cargo.toml`
EOF
)" "p2,security"

create "security(api): max JWT token size before parse (DoS mitigation)" "$(cat <<'EOF'
Reject oversized compact JWT before full parse.

## Files
- `rust/src/jws.rs` or `api.rs`
EOF
)" "p2,security"

create "feat(api): custom JWT header extras beyond alg/typ/cty/kid" "$(cat <<'EOF'
Stretch / post-0.4.0 unless time permits.

## Files
- `rust/src/api.rs`
EOF
)" "p2,enhancement"

create "feat(jws): detached JWS decode (RFC 7797)" "$(cat <<'EOF'
Stretch. Currently `NotImplementedError`. Requires Rust verify over external payload.

## Files
- `rust/src/jws.rs`, `python/oxyjwt/api_jwt.py`
EOF
)" "p2,enhancement"

create "test(jwk): RSA and EC JWK parity tests with real JWKS shapes" "$(cat <<'EOF'
Stretch. Beyond oct-only fixtures.

## Files
- `tests/`
EOF
)" "p2,testing"

echo "Done. List issues:"
gh issue list --milestone "$MILESTONE" --limit 50
