# OxyJWT

OxyJWT is a Python JWT/JWS library backed by a Rust core. It exposes a familiar PyJWT-like API while keeping verification explicit: decoding always requires a caller-provided `algorithms` allow-list.

This project is currently alpha software.

## Documentation

The full documentation is written with MkDocs and lives in [`docs/`](docs/):

- [Getting Started](docs/getting-started.md)
- [Security](docs/security.md)
- [API Reference](docs/api-reference.md)

Build it locally with:

```bash
python -m venv .venv
.venv/bin/python -m pip install -U ".[docs]"
.venv/bin/mkdocs serve
```

Or build a static documentation image for deployment:

```bash
docker build -f Dockerfile.docs -t oxyjwt-docs .
docker run --rm -p 8000:80 oxyjwt-docs
```

## Installation

```bash
pip install oxyjwt
```

For local development:

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip maturin pytest cryptography pyjwt
.venv/bin/maturin develop --release
.venv/bin/python -m pytest
```

## HMAC Example

```python
import time

import oxyjwt

secret = "super-secret"
payload = {
    "sub": "user-123",
    "role": "admin",
    "aud": "api",
    "iss": "auth-service",
    "exp": int(time.time()) + 3600,
}

token = oxyjwt.encode(payload, secret, algorithm="HS256", headers={"kid": "key-1"})
claims = oxyjwt.decode(
    token,
    secret,
    algorithms=["HS256"],
    audience="api",
    issuer="auth-service",
)
```

## Asymmetric Keys

Use explicit key constructors for RSA, PSS, ECDSA, and EdDSA:

```python
import oxyjwt

signing_key = oxyjwt.EncodingKey.from_rsa_pem(private_pem)
verification_key = oxyjwt.DecodingKey.from_rsa_pem(public_pem)

token = oxyjwt.encode({"sub": "user-123", "exp": 1893456000}, signing_key, algorithm="RS256")
claims = oxyjwt.decode(token, verification_key, algorithms=["RS256"])
```

Supported algorithms in v1:

- `HS256`, `HS384`, `HS512`
- `RS256`, `RS384`, `RS512`
- `PS256`, `PS384`, `PS512`
- `ES256`, `ES384`
- `EdDSA`

## Exceptions

OxyJWT exposes a stable exception hierarchy:

```python
try:
    claims = oxyjwt.decode(token, key, algorithms=["HS256"])
except oxyjwt.ExpiredSignatureError:
    ...
except oxyjwt.InvalidTokenError:
    ...
```

All package exceptions inherit from `oxyjwt.OxyJWTError`.

## Benchmarks

There is a small comparison script for OxyJWT, PyJWT, python-jose, and Authlib:

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip maturin ".[bench]"
.venv/bin/maturin develop --release
.venv/bin/python scripts/compare_jwt_libraries.py \
  --algorithms all \
  --iterations 1000 \
  --rounds 3 \
  --warmup 100 \
  --json benchmark-results/all-algorithms.bench.json \
  --markdown benchmark-results/all-algorithms.bench.md
```

The script covers HMAC, RSA, RSA-PSS, ECDSA, and EdDSA algorithms. Unsupported library/algorithm combinations are reported as `0` throughput. For a quicker smoke test, pass something like `--algorithms HS256,RS256,EdDSA --iterations 100 --rounds 1`.

Benchmark outputs are ignored by git because results depend on the machine, Python version, compiler flags, and CPU state.

The default Rust crypto backend is `aws_lc_rs`, chosen for stronger performance on RSA and ECDSA in local benchmarks. You can still build with `rust_crypto` for comparison:

```bash
PYO3_BUILD_EXTENSION_MODULE=1 maturin build --release --no-default-features --features rust_crypto
```

## Security Notes

- Always pass a fixed server-side `algorithms` list to `decode`.
- Never build the `algorithms` list from untrusted token headers.
- `alg="none"` is intentionally unsupported.
- Raw `str`/`bytes` keys are accepted only for HMAC algorithms. Use `EncodingKey.from_*` and `DecodingKey.from_*` for RSA, PSS, ECDSA, and EdDSA.
- Validate `audience` and `issuer` for application tokens when those claims are part of your trust model.
- `decode_unverified` and `get_unverified_header` do not authenticate a token. Use them only for inspection/debugging flows, never for authorization.

OxyJWT implements JWT/JWS signing and verification. JWE encryption is not part of the first version.
