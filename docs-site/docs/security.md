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

## JWS, Not JWE

OxyJWT signs and verifies JWT/JWS tokens. It does not encrypt token contents. Anyone who receives a JWT can read its claims unless you use a separate encryption layer.
