# Encoding Tokens

Use `oxyjwt.encode` when you want to turn a Python mapping into a signed JWT.

```python
token = oxyjwt.encode(payload, key, algorithm="HS256", headers={"kid": "key-1"})
```

## Payloads

Payloads must be JSON objects. In Python terms, pass a mapping with JSON-compatible values:

```python
payload = {
    "sub": "user-123",
    "role": "admin",
    "aud": "api",
    "iss": "auth-service",
    "exp": 1893456000,
}
```

Avoid values that JSON cannot represent, such as arbitrary objects, open files, or `NaN`.

## HMAC Signing

For HMAC algorithms, a raw `str` or `bytes` secret is accepted:

```python
token = oxyjwt.encode(
    {"sub": "user-123", "exp": 1893456000},
    "super-secret",
    algorithm="HS256",
)
```

You can also use an explicit key object:

```python
key = oxyjwt.EncodingKey.from_secret("super-secret")
token = oxyjwt.encode({"sub": "user-123", "exp": 1893456000}, key, algorithm="HS512")
```

## RSA And RSA-PSS Signing

For asymmetric algorithms, use an explicit `EncodingKey`. Raw strings are not accepted for RSA, PSS, ECDSA, or EdDSA signing because that makes algorithm confusion mistakes easier.

```python
signing_key = oxyjwt.EncodingKey.from_rsa_pem(private_pem)

token = oxyjwt.encode(
    {"sub": "user-123", "exp": 1893456000},
    signing_key,
    algorithm="RS256",
)
```

For RSA-PSS, use the same RSA key constructor and a `PS*` algorithm:

```python
token = oxyjwt.encode(
    {"sub": "user-123", "exp": 1893456000},
    signing_key,
    algorithm="PS256",
)
```

## ECDSA And EdDSA Signing

Use the EC constructor for `ES256` and `ES384`:

```python
signing_key = oxyjwt.EncodingKey.from_ec_pem(ec_private_pem)
token = oxyjwt.encode({"sub": "user-123", "exp": 1893456000}, signing_key, algorithm="ES256")
```

Use the EdDSA constructor for `EdDSA`:

```python
signing_key = oxyjwt.EncodingKey.from_ed_pem(ed25519_private_pem)
token = oxyjwt.encode({"sub": "user-123", "exp": 1893456000}, signing_key, algorithm="EdDSA")
```

## Headers

Pass optional JWT headers with `headers`:

```python
token = oxyjwt.encode(
    {"sub": "user-123", "exp": 1893456000},
    "super-secret",
    algorithm="HS256",
    headers={"kid": "key-1", "typ": "JWT"},
)
```

OxyJWT does not allow `headers["alg"]` to override the `algorithm` argument.
