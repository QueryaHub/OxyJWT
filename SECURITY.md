# Security policy

## Supported versions

| Version line | Support |
| --- | --- |
| **0.4.x** (current) | Security fixes and patch releases |
| **0.3.x** | Best-effort backports only for critical issues |
| **0.2.x** and older | Unsupported |

Security fixes target the latest **0.4.x** release. See the [changelog](docs-site/docs/changelog.md) for release history.

## Reporting a vulnerability

Please report security issues **privately** to the maintainers via GitHub Security Advisories for this repository: [https://github.com/QueryaHub/OxyJWT/security/advisories/new](https://github.com/QueryaHub/OxyJWT/security/advisories/new)

Do not open a public issue for undisclosed vulnerabilities.

Include:

- A short description of the impact you believe is possible
- Steps to reproduce (minimal code, token samples if safe, library versions)
- Whether you believe the issue affects signature verification, key handling, or claim validation

We aim to acknowledge reports within a few business days. If you do not receive a response, you may also contact the repository owners listed on the GitHub organization page.

## Scope

This policy covers the `oxyjwt` Python package and its Rust extension (`_oxyjwt`). Documentation site hosting, CI configuration, and third-party benchmark scripts are out of scope unless they directly affect library users.

## JWT usage

OxyJWT implements JWT/JWS signing and verification. Correct use still depends on application choices (algorithm allow-lists, audience/issuer checks, secret management). Read the [Security](docs-site/docs/security.md) documentation before deploying to production.

### JWKS (`PyJWKClient`)

When loading keys from a JWKS URL: use HTTPS (`require_https=True` in production), cap response size (`max_bytes`), pass an explicit `algorithms` list to `get_signing_key_from_jwt` (checked before HTTP), and always verify tokens with `decode` after resolving the key. See [Security — JWKS](docs-site/docs/security.md#jwks-pyjwkclient) and the [API reference](docs-site/docs/api-reference.md#pyjwkclient).

### `verify_signature=False`

Decoding with `options["verify_signature"] = False` skips cryptographic verification. OxyJWT emits `InsecureDecodeWarning` in that case. Do not use unverified payloads for authorization.

- The `subject` parameter is ignored unless `verify_sub` is explicitly `True` (it defaults to `False` when the signature is not verified).
- `require` only checks claim **presence**, not that the token was signed by your trust anchor.
