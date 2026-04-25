use jsonwebtoken::{dangerous, decode as jwt_decode, decode_header, encode as jwt_encode, Header};
use pyo3::prelude::*;
use serde_json::Value;

use crate::algorithms::{algorithm_name, parse_algorithm};
use crate::claims::{json_to_py, py_to_json_for_encode};
use crate::errors;
use crate::keys::{decoding_key_from_py, encoding_key_from_py};
use crate::validation;

#[pyfunction]
#[pyo3(signature = (payload, key, algorithm = "HS256", headers = None))]
pub fn encode(
    py: Python<'_>,
    payload: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
    algorithm: &str,
    headers: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let algorithm = parse_algorithm(algorithm)?;
    let claims = py_to_json_for_encode(payload)?;
    if !claims.is_object() {
        return Err(errors::encode_error("payload must be a JSON object"));
    }

    let mut header = Header::new(algorithm);
    apply_headers(&mut header, headers, algorithm)?;
    let encoding_key = encoding_key_from_py(key, algorithm)?;

    py.detach(|| jwt_encode(&header, &claims, &encoding_key))
        .map_err(errors::from_jwt_encode_error)
}

#[pyfunction]
#[pyo3(signature = (
    token,
    key,
    algorithms,
    *,
    audience = None,
    issuer = None,
    subject = None,
    leeway = 0,
    options = None,
    require = None
))]
#[allow(clippy::too_many_arguments)]
pub fn decode(
    py: Python<'_>,
    token: &str,
    key: &Bound<'_, PyAny>,
    algorithms: Vec<String>,
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>,
    subject: Option<String>,
    leeway: u64,
    options: Option<&Bound<'_, PyAny>>,
    require: Option<Vec<String>>,
) -> PyResult<Py<PyAny>> {
    let decode_validation = validation::build_validation(
        algorithms, audience, issuer, subject, leeway, options, require,
    )?;
    let decoding_key = decoding_key_from_py(key, &decode_validation.algorithms)?;

    let token_data = py
        .detach(|| jwt_decode::<Value>(token, &decoding_key, &decode_validation.validation))
        .map_err(errors::from_jwt_decode_error)?;

    json_to_py(py, &token_data.claims)
}

#[pyfunction]
pub fn get_unverified_header(py: Python<'_>, token: &str) -> PyResult<Py<PyAny>> {
    let header = decode_header(token).map_err(errors::from_jwt_decode_error)?;
    let value = serde_json::to_value(header)
        .map_err(|err| errors::decode_error(format!("failed to serialize header: {err}")))?;

    json_to_py(py, &value)
}

#[pyfunction]
pub fn decode_unverified(py: Python<'_>, token: &str) -> PyResult<Py<PyAny>> {
    let token_data =
        dangerous::insecure_decode::<Value>(token).map_err(errors::from_jwt_decode_error)?;

    json_to_py(py, &token_data.claims)
}

fn apply_headers(
    header: &mut Header,
    headers: Option<&Bound<'_, PyAny>>,
    algorithm: jsonwebtoken::Algorithm,
) -> PyResult<()> {
    let Some(headers) = headers else {
        return Ok(());
    };

    if headers.is_none() {
        return Ok(());
    }

    let value = py_to_json_for_encode(headers)?;
    let Some(object) = value.as_object() else {
        return Err(errors::encode_error("headers must be a JSON object"));
    };

    for (key, value) in object {
        match key.as_str() {
            "alg" => {
                let requested = value
                    .as_str()
                    .ok_or_else(|| errors::encode_error("headers['alg'] must be a string"))?;
                if requested != algorithm_name(algorithm) {
                    return Err(errors::invalid_algorithm(
                        "headers['alg'] cannot override the encode algorithm",
                    ));
                }
            }
            "typ" => header.typ = optional_string("typ", value)?,
            "cty" => header.cty = optional_string("cty", value)?,
            "kid" => header.kid = optional_string("kid", value)?,
            other => {
                return Err(errors::encode_error(format!(
                    "unsupported JWT header field: {other}"
                )));
            }
        }
    }

    Ok(())
}

fn optional_string(name: &str, value: &Value) -> PyResult<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }

    value
        .as_str()
        .map(|value| Some(value.to_owned()))
        .ok_or_else(|| errors::encode_error(format!("headers['{name}'] must be a string or None")))
}
