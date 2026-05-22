# OxyJWT

OxyJWT is a Python JWT/JWS library backed by a Rust core. The public API follows **PyJWT** for `encode`, `decode`, `decode_complete`, JWK/JWKS helpers, and the `PyJWKClient`. When **signature verification** is enabled (the default), you must pass an `algorithms` allow-list, matching common PyJWT usage. Unverified decode is available only when you explicitly set `options["verify_signature"]` to `False` (treat the payload as untrusted).

This project is **beta** software on the `0.4.x` line; see the [changelog](docs-site/docs/changelog.md) for **0.2.0** breaking changes (exception hierarchy) and **0.4.0** production-hardening notes.

## Documentation

The full documentation is written with MkDocs and lives in [`docs-site/`](docs-site/) as a standalone site:

- [Getting Started](docs-site/docs/getting-started.md)
- [Security](docs-site/docs/security.md)
- [API Reference](docs-site/docs/api-reference.md)

Build it locally with:

```bash
python -m venv .venv
.venv/bin/python -m pip install -U -r docs-site/requirements.txt
.venv/bin/mkdocs serve -f docs-site/mkdocs.yml
```

Or build a static documentation image for deployment:

```bash
docker compose -f docs-site/docker-compose.yml up -d --build
```

The static site is served on **http://127.0.0.1:8001** by default. Point your own reverse proxy at that upstream for HTTPS. Details and `OXYJWT_DOCS_PORT` are in [`docs-site/README.md`](docs-site/README.md).

## Installation

```bash
pip install oxyjwt
```

Requires **Python 3.10+**. The wheel installs **[orjson](https://github.com/ijl/orjson)** as a runtime dependency (JSON serialization in the Python API layer).

For local development:

```bash
python -m venv .venv
.venv/bin/python -m pip install -U pip maturin pytest pytest-cov cryptography pyjwt
.venv/bin/maturin develop --release
.venv/bin/python -m pytest
```

See [RELEASING.md](RELEASING.md) for maintainer release steps.

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

**Benchmark fairness:** the default `--competitor-key-mode pem` keeps pre-parsed `EncodingKey`/`DecodingKey` for OxyJWT while competitors often receive PEM bytes (see [Benchmarks](docs-site/docs/benchmarks.md)). For asymmetric comparisons, also run with `--competitor-key-mode cached`.

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

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and pull request expectations. Report security issues privately via [SECURITY.md](SECURITY.md).

## Performance benchmarks

OxyJWT is optimized for throughput on typical JWT workloads (especially HMAC). See [docs-site/docs/benchmarks.md](docs-site/docs/benchmarks.md) for smoke vs extended vs full workflows and key-preparation modes.

The table below is a **historical snapshot** (default script settings, `pem` competitor keys). RS256 encode numbers are not comparable to `--competitor-key-mode cached`; re-run the script on your hardware before drawing conclusions.

| Algorithm | Operation | OxyJWT | PyJWT | Authlib | python-jose |
| :--- | :--- | ---: | ---: | ---: | ---: |

| **HS256** | Encode | 620,270 | 140,670 | 99,408 | 99,507 |
| **HS256** | Decode | 361,073 | 109,272 | 94,823 | 51,838 |
| **RS256** | Encode | 1,934 | 35 | 35 | 35 |
| **RS256** | Decode | 58,752 | 27,200 | 26,085 | 23,046 |
| **EdDSA** | Encode | 69,105 | 17,518 | 15,014 | N/A |
| **EdDSA** | Decode | 31,666 | 10,741 | 10,317 | N/A |
| **ES256** | Encode | 46,559 | 19,632 | 16,199 | 19,723 |