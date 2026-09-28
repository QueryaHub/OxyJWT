use jsonwebtoken::{Algorithm, DecodingKey as JwtDecodingKey, EncodingKey as JwtEncodingKey};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

use crate::algorithms::{ensure_algorithm_family, ensure_single_family, KeyFamily};
use crate::claims;
use crate::errors;

#[cfg(feature = "aws_lc_rs")]
use std::sync::Arc;

#[cfg(feature = "aws_lc_rs")]
use aws_lc_rs::signature::RsaKeyPair;

#[derive(Debug)]
struct EncodingKeyMaterial {
    family: KeyFamily,
    key: JwtEncodingKey,
    // Populated only for RSA/RSA-PSS keys when the `aws_lc_rs` crypto backend is in
    // use. `jsonwebtoken::crypto::sign` re-parses (and re-validates, which for RSA
    // is the expensive part) `key.inner()` into an `aws_lc_rs::signature::RsaKeyPair`
    // on every call; parsing it once here and signing through it directly in
    // `api::encode` / `api::encode_json` turns that per-call cost into a one-time
    // cost at key construction. See issue #120.
    #[cfg(feature = "aws_lc_rs")]
    cached_rsa: Option<Arc<RsaKeyPair>>,
}

#[derive(Debug)]
struct DecodingKeyMaterial {
    family: KeyFamily,
    key: JwtDecodingKey,
}

#[pyclass(module = "oxyjwt._oxyjwt")]
pub struct EncodingKey {
    material: EncodingKeyMaterial,
}

#[pyclass(module = "oxyjwt._oxyjwt")]
pub struct DecodingKey {
    material: DecodingKeyMaterial,
}

#[pymethods]
impl EncodingKey {
    #[staticmethod]
    pub fn from_secret(secret: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = secret_bytes_from_py(secret)?;
        Ok(Self {
            material: EncodingKeyMaterial::new(
                KeyFamily::Hmac,
                JwtEncodingKey::from_secret(bytes.as_ref()),
            ),
        })
    }

    #[staticmethod]
    pub fn from_rsa_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        let key = JwtEncodingKey::from_rsa_pem(&bytes).map_err(errors::from_jwt_encode_error)?;
        #[cfg(feature = "aws_lc_rs")]
        let material = {
            let cached_rsa = Arc::new(parse_cached_rsa_key_pair(key.inner())?);
            EncodingKeyMaterial::new_rsa(key, cached_rsa)
        };
        #[cfg(not(feature = "aws_lc_rs"))]
        let material = EncodingKeyMaterial::new(KeyFamily::Rsa, key);
        Ok(Self { material })
    }

    #[staticmethod]
    pub fn from_ec_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        Ok(Self {
            material: EncodingKeyMaterial::new(
                KeyFamily::Ec,
                JwtEncodingKey::from_ec_pem(&bytes).map_err(errors::from_jwt_encode_error)?,
            ),
        })
    }

    #[staticmethod]
    pub fn from_ed_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        Ok(Self {
            material: EncodingKeyMaterial::new(
                KeyFamily::Ed,
                JwtEncodingKey::from_ed_pem(&bytes).map_err(errors::from_jwt_encode_error)?,
            ),
        })
    }

    fn __repr__(&self) -> String {
        format!("<oxyjwt.EncodingKey family={:?}>", self.material.family)
    }
}

#[pymethods]
impl DecodingKey {
    #[staticmethod]
    pub fn from_secret(secret: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = secret_bytes_from_py(secret)?;
        Ok(Self {
            material: DecodingKeyMaterial::new(
                KeyFamily::Hmac,
                JwtDecodingKey::from_secret(bytes.as_ref()),
            ),
        })
    }

    #[staticmethod]
    pub fn from_rsa_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        Ok(Self {
            material: DecodingKeyMaterial::new(
                KeyFamily::Rsa,
                JwtDecodingKey::from_rsa_pem(&bytes).map_err(errors::from_jwt_decode_error)?,
            ),
        })
    }

    #[staticmethod]
    pub fn from_ec_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        Ok(Self {
            material: DecodingKeyMaterial::new(
                KeyFamily::Ec,
                JwtDecodingKey::from_ec_pem(&bytes).map_err(errors::from_jwt_decode_error)?,
            ),
        })
    }

    #[staticmethod]
    pub fn from_ed_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        Ok(Self {
            material: DecodingKeyMaterial::new(
                KeyFamily::Ed,
                JwtDecodingKey::from_ed_pem(&bytes).map_err(errors::from_jwt_decode_error)?,
            ),
        })
    }

    #[staticmethod]
    pub fn from_jwk(jwk: &Bound<'_, PyAny>) -> PyResult<Self> {
        let raw = if let Ok(value) = jwk.extract::<String>() {
            value
        } else {
            let value = claims::py_to_json_for_decode(jwk)?;
            serde_json::to_string(&value)
                .map_err(|err| errors::invalid_key(format!("invalid JWK value: {err}")))?
        };

        let jwk = serde_json::from_str(&raw)
            .map_err(|err| errors::invalid_key(format!("invalid JWK: {err}")))?;

        Ok(Self {
            material: DecodingKeyMaterial::new(
                KeyFamily::Jwk,
                JwtDecodingKey::from_jwk(&jwk).map_err(errors::from_jwt_decode_error)?,
            ),
        })
    }

    fn __repr__(&self) -> String {
        format!("<oxyjwt.DecodingKey family={:?}>", self.material.family)
    }
}

impl EncodingKeyMaterial {
    fn new(family: KeyFamily, key: JwtEncodingKey) -> Self {
        Self {
            family,
            key,
            #[cfg(feature = "aws_lc_rs")]
            cached_rsa: None,
        }
    }

    #[cfg(feature = "aws_lc_rs")]
    fn new_rsa(key: JwtEncodingKey, cached_rsa: Arc<RsaKeyPair>) -> Self {
        Self {
            family: KeyFamily::Rsa,
            key,
            cached_rsa: Some(cached_rsa),
        }
    }

    fn encoding_key(&self, algorithm: Algorithm) -> PyResult<JwtEncodingKey> {
        ensure_algorithm_family(algorithm, self.family)?;
        Ok(self.key.clone())
    }

    /// The pre-parsed RSA signing key, when `key` is an RSA/RSA-PSS `EncodingKey`
    /// and `algorithm` is compatible with it. `None` for every other key family,
    /// in which case the caller falls back to `encoding_key` + `jsonwebtoken::crypto`.
    #[cfg(feature = "aws_lc_rs")]
    fn cached_rsa_signer(&self, algorithm: Algorithm) -> PyResult<Option<Arc<RsaKeyPair>>> {
        ensure_algorithm_family(algorithm, self.family)?;
        Ok(self.cached_rsa.clone())
    }
}

impl DecodingKeyMaterial {
    fn new(family: KeyFamily, key: JwtDecodingKey) -> Self {
        Self { family, key }
    }

    fn validate_for_algorithms(&self, algorithms: &[Algorithm]) -> PyResult<()> {
        if self.family != KeyFamily::Jwk {
            let expected_family = ensure_single_family(algorithms)?;
            if expected_family != self.family {
                return Err(errors::invalid_algorithm(format!(
                    "allowed algorithms cannot be used with a {:?} key",
                    self.family
                )));
            }
        }
        Ok(())
    }

    fn decoding_key(&self, algorithms: &[Algorithm]) -> PyResult<JwtDecodingKey> {
        self.validate_for_algorithms(algorithms)?;
        Ok(self.key.clone())
    }
}

pub fn encoding_key_from_py(
    key: &Bound<'_, PyAny>,
    algorithm: Algorithm,
) -> PyResult<JwtEncodingKey> {
    if let Ok(key_ref) = key.extract::<PyRef<'_, EncodingKey>>() {
        return key_ref.material.encoding_key(algorithm);
    }

    if crate::algorithms::algorithm_family(algorithm) != KeyFamily::Hmac {
        return Err(errors::invalid_key(
            "raw str/bytes keys are only accepted for HMAC algorithms; use EncodingKey.from_*",
        ));
    }

    let bytes = secret_bytes_from_py(key)?;
    Ok(JwtEncodingKey::from_secret(bytes.as_ref()))
}

/// Parse a DER-encoded RSA private key into an `aws_lc_rs` `RsaKeyPair`, mapping
/// failures to the same `InvalidKeyError` that `jsonwebtoken`'s own RSA key
/// rejection produces.
#[cfg(feature = "aws_lc_rs")]
fn parse_cached_rsa_key_pair(der: &[u8]) -> PyResult<RsaKeyPair> {
    RsaKeyPair::from_der(der).map_err(|err| {
        errors::from_jwt_encode_error(jsonwebtoken::errors::new_error(
            jsonwebtoken::errors::ErrorKind::InvalidRsaKey(err.to_string()),
        ))
    })
}

/// The pre-parsed RSA signing key backing `key`, when `key` is an `EncodingKey`
/// built from `EncodingKey.from_rsa_pem` and `algorithm` is an RSA/RSA-PSS
/// algorithm compatible with it. `Ok(None)` when `key` is not an `EncodingKey`
/// object (a raw HMAC secret): the caller falls back to `encoding_key_from_py`,
/// which raises the appropriate error for that case.
#[cfg(feature = "aws_lc_rs")]
pub fn cached_rsa_encoding_key_from_py(
    key: &Bound<'_, PyAny>,
    algorithm: Algorithm,
) -> PyResult<Option<Arc<RsaKeyPair>>> {
    match key.extract::<PyRef<'_, EncodingKey>>() {
        Ok(key_ref) => key_ref.material.cached_rsa_signer(algorithm),
        Err(_) => Ok(None),
    }
}

pub fn decoding_key_from_py(
    key: &Bound<'_, PyAny>,
    algorithms: &[Algorithm],
) -> PyResult<JwtDecodingKey> {
    if let Ok(key_ref) = key.extract::<PyRef<'_, DecodingKey>>() {
        return key_ref.material.decoding_key(algorithms);
    }

    raw_decoding_key_from_py(key, algorithms)
}

fn raw_decoding_key_from_py(
    key: &Bound<'_, PyAny>,
    algorithms: &[Algorithm],
) -> PyResult<JwtDecodingKey> {
    let family = ensure_single_family(algorithms)?;
    if family != KeyFamily::Hmac {
        return Err(errors::invalid_key(
            "raw str/bytes keys are only accepted for HMAC algorithms; use DecodingKey.from_*",
        ));
    }

    let bytes = secret_bytes_from_py(key)?;
    Ok(JwtDecodingKey::from_secret(bytes.as_ref()))
}

/// Copy HMAC secret material from Python; buffer is zeroized on drop.
fn secret_bytes_from_py(value: &Bound<'_, PyAny>) -> PyResult<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(bytes_from_py(value)?))
}

fn bytes_from_py(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return Ok(bytes.as_bytes().to_vec());
    }

    if let Ok(text) = value.extract::<String>() {
        return Ok(text.into_bytes());
    }

    Err(errors::invalid_key("key material must be str or bytes"))
}
