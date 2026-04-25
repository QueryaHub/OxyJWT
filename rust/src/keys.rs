use jsonwebtoken::{Algorithm, DecodingKey as JwtDecodingKey, EncodingKey as JwtEncodingKey};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::algorithms::{ensure_algorithm_family, ensure_single_family, KeyFamily};
use crate::claims;
use crate::errors;

#[derive(Debug)]
struct EncodingKeyMaterial {
    family: KeyFamily,
    key: JwtEncodingKey,
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
        let bytes = bytes_from_py(secret)?;
        Ok(Self {
            material: EncodingKeyMaterial::new(
                KeyFamily::Hmac,
                JwtEncodingKey::from_secret(&bytes),
            ),
        })
    }

    #[staticmethod]
    pub fn from_rsa_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        let bytes = bytes_from_py(pem)?;
        Ok(Self {
            material: EncodingKeyMaterial::new(
                KeyFamily::Rsa,
                JwtEncodingKey::from_rsa_pem(&bytes).map_err(errors::from_jwt_encode_error)?,
            ),
        })
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
        let bytes = bytes_from_py(secret)?;
        Ok(Self {
            material: DecodingKeyMaterial::new(
                KeyFamily::Hmac,
                JwtDecodingKey::from_secret(&bytes),
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
        Self { family, key }
    }

    fn encoding_key(&self, algorithm: Algorithm) -> PyResult<JwtEncodingKey> {
        ensure_algorithm_family(algorithm, self.family)?;
        Ok(self.key.clone())
    }
}

impl DecodingKeyMaterial {
    fn new(family: KeyFamily, key: JwtDecodingKey) -> Self {
        Self { family, key }
    }

    fn decoding_key(&self, algorithms: &[Algorithm]) -> PyResult<JwtDecodingKey> {
        if self.family != KeyFamily::Jwk {
            let expected_family = ensure_single_family(algorithms)?;
            if expected_family != self.family {
                return Err(errors::invalid_algorithm(format!(
                    "allowed algorithms cannot be used with a {:?} key",
                    self.family
                )));
            }
        }

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

    Ok(JwtEncodingKey::from_secret(&bytes_from_py(key)?))
}

pub fn decoding_key_from_py(
    key: &Bound<'_, PyAny>,
    algorithms: &[Algorithm],
) -> PyResult<JwtDecodingKey> {
    if let Ok(key_ref) = key.extract::<PyRef<'_, DecodingKey>>() {
        return key_ref.material.decoding_key(algorithms);
    }

    let family = ensure_single_family(algorithms)?;
    if family != KeyFamily::Hmac {
        return Err(errors::invalid_key(
            "raw str/bytes keys are only accepted for HMAC algorithms; use DecodingKey.from_*",
        ));
    }

    Ok(JwtDecodingKey::from_secret(&bytes_from_py(key)?))
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
