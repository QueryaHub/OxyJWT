# ⚡ OxyJWT

<div align="center">

**A high-performance Python JWT/JWS library backed by a native Rust core.**  
*Drop-in replacement for PyJWT with up to 4× higher throughput, native security, and full JWKS support.*

[![CI](https://github.com/QueryaHub/OxyJWT/actions/workflows/ci.yml/badge.svg)](https://github.com/QueryaHub/OxyJWT/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/QueryaHub/OxyJWT/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/QueryaHub/OxyJWT/actions/workflows/benchmarks.yml)
[![PyPI version](https://img.shields.io/pypi/v/oxyjwt.svg)](https://pypi.org/project/oxyjwt/)
[![Python versions](https://img.shields.io/pypi/pyversions/oxyjwt.svg)](https://pypi.org/project/oxyjwt/)
[![Rust](https://img.shields.io/badge/rust-2021%20edition-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-oxyjwt.queryahub.com-blue)](https://oxyjwt.queryahub.com/)

[**Documentation**](https://oxyjwt.queryahub.com/) • [**Benchmarks**](#-performance-benchmarks) • [**Quickstart**](#-quick-start) • [**JWKS Client**](#-jwks-client-integration) • [**Security**](#-security-by-default)

</div>

---

## ✨ Features

- 🚀 **Blazing Fast**: Up to **4× faster** encoding and **3.3× faster** decoding than PyJWT for HS256 and EdDSA. Built with a single-pass Rust parser, fast Python dispatch, and fat Link-Time Optimization (LTO).
- 🔄 **Drop-in PyJWT Replacement**: Fully compatible API for `encode`, `decode`, `decode_complete`, `get_unverified_header`, `PyJWKClient`, and standard claim validation options.
- 🛡️ **Secure by Default**: Mandatory server-side algorithm allowlists, strictly rejects `alg: "none"`, constant-time signature comparisons, and SSRF-hardened JWKS client with cache and rate limits.
- 🔑 **Modern Cryptography**: Powered by `aws-lc-rs` (AWS Libcrypto). Supports HMAC, RSA, RSA-PSS, ECDSA, and EdDSA (`Ed25519`).
- ⚡ **High-Speed Serialization**: Deep integration with [`orjson`](https://github.com/ijl/orjson) for ultrafast JSON parsing and serialization.
- 📦 **Batteries Included**: Pre-built binary wheels available for Linux (x86_64, aarch64), macOS (Apple Silicon, Intel), and Windows.

---

## 📊 Performance Benchmarks

Measured on modern Linux hardware comparing median operations per second (`ops/sec`) across libraries (higher is better):

<!-- BENCHMARK_TABLE_START -->
| Algorithm | Operation | OxyJWT | PyJWT | Authlib | python-jose | OxyJWT Speedup |
| :--- | :--- | ---: | ---: | ---: | ---: | :---: |
| **HS256** | **Encode** | **666,018** | 172,057 | 121,276 | 118,782 | **~3.9× faster** 🚀 |
| **HS256** | **Decode** | **421,031** | 131,095 | 118,723 | 63,573 | **~3.2× faster** 🚀 |
| **EdDSA** | **Encode** | **73,626** | 18,551 | 16,443 | *N/A* | **~4.0× faster** 🚀 |
| **EdDSA** | **Decode** | **29,773** | 10,757 | 9,914 | *N/A* | **~2.8× faster** 🚀 |
| **RS256** | **Decode** | **62,634** | 28,565 | 28,727 | 25,335 | **~2.2× faster** 🚀 |
| **ES256** | **Encode** | **47,428** | 22,113 | 16,032 | 21,758 | **~2.1× faster** 🚀 |
<!-- BENCHMARK_TABLE_END -->

> [!NOTE]
> Detailed methodology, key-mode comparisons (`pem` vs `cached`), and reproducible benchmarks are documented in [docs-site/docs/benchmarks.md](docs-site/docs/benchmarks.md). Continuous performance tracking is executed automatically in our [Performance CI workflow](https://github.com/QueryaHub/OxyJWT/actions/workflows/benchmarks.yml).

---

## 📦 Installation

```bash
pip install oxyjwt
```

Requires **Python 3.10+**. Binary wheels include pre-compiled Rust extensions for all major operating systems.

---

## 🚀 Quick Start

### 1. HMAC (Symmetric)

```python
import time
import oxyjwt

secret = "your-256-bit-secret"
payload = {
    "sub": "user_42",
    "role": "admin",
    "iss": "https://auth.example.com",
    "aud": "https://api.example.com",
    "exp": int(time.time()) + 3600,
}

# Encode a token
token = oxyjwt.encode(payload, secret, algorithm="HS256", headers={"kid": "key-2026"})

# Decode and validate claims
claims = oxyjwt.decode(
    token,
    secret,
    algorithms=["HS256"],  # Fixed allow-list is required
    audience="https://api.example.com",
    issuer="https://auth.example.com",
)
print(claims["sub"])  # "user_42"
```

---

### 2. Asymmetric Keys (RSA, ECDSA, EdDSA)

For asymmetric cryptography, parse keys once using explicit constructors:

```python
import oxyjwt

# Load keys
signing_key = oxyjwt.EncodingKey.from_rsa_pem(private_pem_bytes)
verifying_key = oxyjwt.DecodingKey.from_rsa_pem(public_pem_bytes)

# Sign with RS256
token = oxyjwt.encode({"sub": "user_42"}, signing_key, algorithm="RS256")

# Verify with RS256
claims = oxyjwt.decode(token, verifying_key, algorithms=["RS256"])
```

OxyJWT also supports **Ed25519 (EdDSA)**:

```python
signing_key = oxyjwt.EncodingKey.from_ed_pem(ed25519_private_pem)
verifying_key = oxyjwt.DecodingKey.from_ed_pem(ed25519_public_pem)

token = oxyjwt.encode({"sub": "service-worker"}, signing_key, algorithm="EdDSA")
claims = oxyjwt.decode(token, verifying_key, algorithms=["EdDSA"])
```

---

### 3. JWKS Client Integration

Fetch and cache remote JSON Web Key Sets (e.g., Auth0, Keycloak, Cognito, Okta) seamlessly:

```python
from oxyjwt import PyJWKClient
import oxyjwt

jwks_client = PyJWKClient(
    "https://your-domain.auth0.com/.well-known/jwks.json",
    cache_keys=True,
    max_cached_keys=16,
    cache_jwk_set=True,
    lifespan=3600,  # 1 hour cache
)

# Automatically resolve the signing key using the token's header `kid`
signing_key = jwks_client.get_signing_key_from_jwt(token)

claims = oxyjwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="https://api.example.com",
)
```

---

### 4. Complete Inspection & Fast Path

```python
import oxyjwt

# Inspect headers without verifying signature (debugging only)
header = oxyjwt.get_unverified_header(token)

# Retrieve header, claims payload, and raw signature together
token_data = oxyjwt.decode_complete(token, key, algorithms=["HS256"])
print(token_data["header"])
print(token_data["payload"])
print(token_data["signature"])
```

---

## 🛡️ Exception Hierarchy

OxyJWT provides a predictable exception tree that mirrors PyJWT for easy catch blocks:

```python
import oxyjwt

try:
    claims = oxyjwt.decode(token, key, algorithms=["HS256"])
except oxyjwt.ExpiredSignatureError:
    # Token has expired (exp claim)
    ...
except oxyjwt.ImmatureSignatureError:
    # Token is not yet valid (nbf claim)
    ...
except oxyjwt.InvalidAudienceError:
    # Audience claim mismatch (aud claim)
    ...
except oxyjwt.InvalidIssuerError:
    # Issuer mismatch (iss claim)
    ...
except oxyjwt.InvalidSignatureError:
    # Signature verification failed
    ...
except oxyjwt.InvalidTokenError:
    # Malformed token or general decoding error
    ...
except oxyjwt.OxyJWTError:
    # Base class for all OxyJWT exceptions
    ...
```

---

## 🔒 Supported Algorithms

| Family | Algorithms | Key Type |
| :--- | :--- | :--- |
| **HMAC** | `HS256`, `HS384`, `HS512` | `str` or `bytes` (shared secret) |
| **RSA** | `RS256`, `RS384`, `RS512` | `EncodingKey.from_rsa_pem` / `DecodingKey.from_rsa_pem` |
| **RSA-PSS** | `PS256`, `PS384`, `PS512` | `EncodingKey.from_rsa_pem` / `DecodingKey.from_rsa_pem` |
| **ECDSA** | `ES256`, `ES384` | `EncodingKey.from_ec_pem` / `DecodingKey.from_ec_pem` |
| **EdDSA** | `EdDSA` (Ed25519) | `EncodingKey.from_ed_pem` / `DecodingKey.from_ed_pem` |

---

## 🛡️ Security by Default

1. **Fixed Algorithm Allow-List**: Passing an `algorithms` parameter to `decode` is mandatory when signature verification is active.
2. **No `alg: "none"`**: Unsigned tokens are fundamentally disallowed.
3. **Constant-Time Verification**: Cryptographic comparisons are protected against timing attacks.
4. **Hardened JWKS Client**: Protects against SSRF, limits downloaded key sizes, and enforces key rate-limiting.
5. **No Key Confusion**: Asymmetric algorithms require explicit typed `EncodingKey` / `DecodingKey` structures to prevent HMAC key confusion attacks.

---

## 📖 Documentation & Local Development

Full documentation is available at [**oxyjwt.queryahub.com**](https://oxyjwt.queryahub.com/).

### Local Setup & Testing

```bash
# Clone and setup environment
git clone https://github.com/QueryaHub/OxyJWT.git
cd OxyJWT
python -m venv .venv
source .venv/bin/activate

# Install build & test dependencies
pip install -U pip maturin pytest pytest-cov cryptography pyjwt authlib python-jose

# Compile Rust extension and run tests
maturin develop --release
pytest

# Run extended performance benchmarks
OXYJWT_BENCHMARK=1 pytest tests/test_benchmark_jwt_libraries.py -v
```

### Documentation Preview

```bash
pip install -r docs-site/requirements.txt
mkdocs serve -f docs-site/mkdocs.yml
```

---

## 🤝 Contributing & Security

- Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and code standards.
- To report security vulnerabilities, please refer to [SECURITY.md](SECURITY.md).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).