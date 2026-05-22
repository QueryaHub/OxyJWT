# Security

JWT libraries are easy to use incorrectly. This page is the checklist to read before using OxyJWT for authentication or authorization.

## Choose Algorithms Server-Side

The allowed algorithm list must come from your configuration, not from the token:

```python
claims = oxyjwt.decode(
    token,
    verification_key,
    algorithms=["RS256"],
    audience="api",
    issuer="https://auth.example.com",
)
```

Do not do this:

```python
header = oxyjwt.get_unverified_header(token)
claims = oxyjwt.decode(token, key, algorithms=[header["alg"]])
```

The second example trusts attacker-controlled input before verification.

## `none` Is Not Supported

OxyJWT rejects `alg="none"` in the normal API. Unsecured JWTs are not appropriate for authentication.

## Avoid Algorithm Confusion

A classic JWT vulnerability is accepting an RSA public key as an HMAC secret after an attacker changes the token header from `RS256` to `HS256`.

OxyJWT reduces that risk by:

- requiring `algorithms` in `decode`;
- rejecting mixed key families in one `algorithms` list;
- accepting raw `str` / `bytes` keys only for HMAC;
- requiring explicit key constructors for RSA, PSS, ECDSA, and EdDSA.

## Validate Audience And Issuer

Signature verification only proves that a token was signed by a key. It does not prove that the token was meant for your service.

When your issuer includes `aud` and `iss`, validate both:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["RS256"],
    audience="api",
    issuer="https://auth.example.com",
)
```

## Require Claims That Your App Needs

If your app requires `exp` and `sub`, say so:

```python
claims = oxyjwt.decode(
    token,
    key,
    algorithms=["HS256"],
    require=["exp", "sub"],
)
```

Then validate your own business rules after decoding.

## Keep Secrets Out Of Source Code

Demo examples use short strings because they are readable. Production HMAC secrets should be high entropy and loaded from a secret manager or environment configuration.

Do not print tokens, private keys, or HMAC secrets in logs.

## `verify_signature=False`

`decode` with `options["verify_signature"] = False` parses the token without verifying the JWS signature. OxyJWT warns with `InsecureDecodeWarning`.

- Do not use the returned claims for authentication or authorization.
- `subject` is ignored unless `verify_sub` is `True` (not the default when the signature is off).
- `require` only asserts that named claims exist in the parsed JSON, not that they are authentic.

Prefer verified `decode` with an explicit `algorithms` allow-list in production.

## HMAC key material

When you pass a raw `str` / `bytes` HMAC secret (or use `EncodingKey.from_secret` / `DecodingKey.from_secret`), the Rust core copies the material into a buffer that is **zeroized on drop** after the `jsonwebtoken` key object is built. Long-lived `EncodingKey` / `DecodingKey` instances still hold signing material inside the library as required for operation; prefer short-lived keys and OS secret stores in production.

## Compact JWT size limit

OxyJWT rejects compact JWT strings larger than **256 KiB** (same order of magnitude as the default JWKS `max_bytes` cap) with `DecodeError` before base64 or JSON parsing. This applies to verified `decode`, `decode_unverified`, `get_unverified_header`, and `jws_parse_compact`. RFC 7797 **`detached_payload`** bytes passed to verified decode are capped at the same limit before copy or JSON parsing. Legitimate tokens are far smaller; huge inputs are usually denial-of-service attempts.

## Treat Unverified Helpers As Inspection Only

`get_unverified_header` and `decode_unverified` do not verify the signature and do not validate claims.

Good uses:

- selecting a key by `kid` before verification;
- debugging token shape;
- inspecting tokens in trusted local tooling.

Bad uses:

- deciding whether a request is authenticated;
- trusting `sub`, `role`, `aud`, or `iss`;
- building the allowed algorithm list from the unverified header.

## JWKS (`PyJWKClient`)

When keys rotate at your identity provider, fetch JWKS over HTTPS and resolve keys by `kid`:

```python
client = oxyjwt.PyJWKClient(
    "https://auth.example.com/.well-known/jwks.json",
    require_https=True,
)
signing_key = client.get_signing_key_from_jwt(
    token,
    algorithms=["RS256"],
)
claims = oxyjwt.decode(
    token,
    signing_key.key,
    algorithms=["RS256"],
    audience="api",
    issuer="https://auth.example.com",
)
```

Security practices:

- Pass **`algorithms`** to `get_signing_key_from_jwt` so disallowed header `alg` values are rejected **before** JWKS HTTP I/O.
- Enable **`require_https`** for production JWKS URLs.
- Set **`max_bytes`** (default 256 KiB) to cap oversized responses.
- Do not disable signature verification after resolving a key; `get_signing_key_from_jwt` only inspects the header to find `kid`.
- Tier-2 **`cache_keys`** is off by default; enable only if you understand LRU retention of `PyJWK` material in memory.

Full parameter reference: [API reference — `PyJWKClient`](api-reference.md#pyjwkclient). Reporting vulnerabilities: [SECURITY.md](https://github.com/QueryaHub/OxyJWT/blob/main/SECURITY.md).

## JWS, Not JWE

OxyJWT signs and verifies JWT/JWS tokens. It does not encrypt token contents. Anyone who receives a JWT can read its claims unless you use a separate encryption layer.
