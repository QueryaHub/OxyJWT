# Keys And Algorithms

OxyJWT separates key families so that one key cannot silently be reused with an unrelated algorithm family.

## Supported Algorithms

| Family | Algorithms | Key constructor |
| --- | --- | --- |
| HMAC | `HS256`, `HS384`, `HS512` | `from_secret` or raw `str` / `bytes` |
| RSA | `RS256`, `RS384`, `RS512` | `from_rsa_pem` |
| RSA-PSS | `PS256`, `PS384`, `PS512` | `from_rsa_pem` |
| ECDSA | `ES256`, `ES384` | `from_ec_pem` |
| EdDSA | `EdDSA` | `from_ed_pem` |

## HMAC Secrets

For HMAC, you can pass a raw secret:

```python
token = oxyjwt.encode(payload, "super-secret", algorithm="HS256")
claims = oxyjwt.decode(token, "super-secret", algorithms=["HS256"])
```

Or use explicit key objects:

```python
signing_key = oxyjwt.EncodingKey.from_secret("super-secret")
verification_key = oxyjwt.DecodingKey.from_secret("super-secret")
```

Use high-entropy secrets. Human-readable demo strings are fine in examples, not in production.

## PEM Keys

For RSA, PSS, ECDSA, and EdDSA, pass PEM bytes or text to the matching constructor:

```python
signing_key = oxyjwt.EncodingKey.from_rsa_pem(private_pem)
verification_key = oxyjwt.DecodingKey.from_rsa_pem(public_pem)
```

The signing side usually uses a private key. The verification side usually uses a public key.

## JWK Verification

`DecodingKey.from_jwk` creates a verification key from a JSON Web Key:

```python
verification_key = oxyjwt.DecodingKey.from_jwk(jwk)
claims = oxyjwt.decode(token, verification_key, algorithms=["RS256"])
```

The current API supports JWK for decoding. Encoding uses explicit secret or PEM constructors.

## Why Raw Keys Are HMAC-Only

Algorithm confusion bugs happen when a system accepts one byte string as both an HMAC secret and an asymmetric public key. OxyJWT avoids that shape:

```python
# Allowed: HMAC with raw secret.
oxyjwt.decode(token, "super-secret", algorithms=["HS256"])

# Rejected: asymmetric algorithm with raw string.
oxyjwt.decode(token, "-----BEGIN PUBLIC KEY-----...", algorithms=["RS256"])
```

For asymmetric algorithms, construct a `DecodingKey` explicitly:

```python
verification_key = oxyjwt.DecodingKey.from_rsa_pem(public_pem)
claims = oxyjwt.decode(token, verification_key, algorithms=["RS256"])
```

## Do Not Mix Algorithm Families

Keep each `decode` call to one key family:

```python
claims = oxyjwt.decode(token, verification_key, algorithms=["RS256", "PS256"])
```

Do not combine HMAC and RSA algorithms in the same allowed list.
