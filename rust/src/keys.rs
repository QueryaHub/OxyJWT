use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey as JwtDecodingKey, EncodingKey as JwtEncodingKey};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

use crate::algorithms::{ensure_algorithm_family, ensure_single_family, KeyFamily};
use crate::claims;
use crate::errors;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyKind {
    Secret,
    RsaPem,
    EcPem,
    EdPem,
    Jwk,
}

#[derive(Debug)]
struct KeyMaterial {
    kind: KeyKind,
    family: KeyFamily,
    bytes: Vec<u8>,
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[pyclass(module = "oxyjwt._oxyjwt")]
pub struct EncodingKey {
    material: KeyMaterial,
}

#[pyclass(module = "oxyjwt._oxyjwt")]
pub struct DecodingKey {
    material: KeyMaterial,
}

#[pymethods]
impl EncodingKey {
    #[staticmethod]
    pub fn from_secret(secret: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::Secret, KeyFamily::Hmac, bytes_from_py(secret)?),
        })
    }

    #[staticmethod]
    pub fn from_rsa_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::RsaPem, KeyFamily::Rsa, bytes_from_py(pem)?),
        })
    }

    #[staticmethod]
    pub fn from_ec_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::EcPem, KeyFamily::Ec, bytes_from_py(pem)?),
        })
    }

    #[staticmethod]
    pub fn from_ed_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::EdPem, KeyFamily::Ed, bytes_from_py(pem)?),
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
        Ok(Self {
            material: KeyMaterial::new(KeyKind::Secret, KeyFamily::Hmac, bytes_from_py(secret)?),
        })
    }

    #[staticmethod]
    pub fn from_rsa_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::RsaPem, KeyFamily::Rsa, bytes_from_py(pem)?),
        })
    }

    #[staticmethod]
    pub fn from_ec_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::EcPem, KeyFamily::Ec, bytes_from_py(pem)?),
        })
    }

    #[staticmethod]
    pub fn from_ed_pem(pem: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            material: KeyMaterial::new(KeyKind::EdPem, KeyFamily::Ed, bytes_from_py(pem)?),
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

        serde_json::from_str::<Jwk>(&raw)
            .map_err(|err| errors::invalid_key(format!("invalid JWK: {err}")))?;

        Ok(Self {
            material: KeyMaterial::new(KeyKind::Jwk, KeyFamily::Jwk, raw.into_bytes()),
        })
    }

    fn __repr__(&self) -> String {
        format!("<oxyjwt.DecodingKey family={:?}>", self.material.family)
    }
}

impl KeyMaterial {
    fn new(kind: KeyKind, family: KeyFamily, bytes: Vec<u8>) -> Self {
        Self {
            kind,
            family,
            bytes,
        }
    }

    fn encoding_key(&self, algorithm: Algorithm) -> PyResult<JwtEncodingKey> {
        ensure_algorithm_family(algorithm, self.family)?;

        match self.kind {
            KeyKind::Secret => Ok(JwtEncodingKey::from_secret(&self.bytes)),
            KeyKind::RsaPem => {
                JwtEncodingKey::from_rsa_pem(&self.bytes).map_err(errors::from_jwt_encode_error)
            }
            KeyKind::EcPem => {
                JwtEncodingKey::from_ec_pem(&self.bytes).map_err(errors::from_jwt_encode_error)
            }
            KeyKind::EdPem => {
                JwtEncodingKey::from_ed_pem(&self.bytes).map_err(errors::from_jwt_encode_error)
            }
            KeyKind::Jwk => Err(errors::invalid_key("JWK cannot be used for encoding")),
        }
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

        match self.kind {
            KeyKind::Secret => Ok(JwtDecodingKey::from_secret(&self.bytes)),
            KeyKind::RsaPem => {
                JwtDecodingKey::from_rsa_pem(&self.bytes).map_err(errors::from_jwt_decode_error)
            }
            KeyKind::EcPem => {
                JwtDecodingKey::from_ec_pem(&self.bytes).map_err(errors::from_jwt_decode_error)
            }
            KeyKind::EdPem => {
                JwtDecodingKey::from_ed_pem(&self.bytes).map_err(errors::from_jwt_decode_error)
            }
            KeyKind::Jwk => {
                let raw = std::str::from_utf8(&self.bytes)
                    .map_err(|err| errors::invalid_key(format!("invalid JWK bytes: {err}")))?;
                let jwk = serde_json::from_str::<Jwk>(raw)
                    .map_err(|err| errors::invalid_key(format!("invalid JWK: {err}")))?;
                JwtDecodingKey::from_jwk(&jwk).map_err(errors::from_jwt_decode_error)
            }
        }
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
