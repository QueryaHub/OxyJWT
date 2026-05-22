use jsonwebtoken::{dangerous, decode as jwt_decode, decode_header, encode as jwt_encode, Header};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;

use crate::algorithms::{algorithm_name, parse_algorithm};
use crate::claims::{json_to_py, py_to_json_for_encode};
use crate::errors;
use crate::jws;
use crate::keys::{decoding_key_from_py, encoding_key_from_py};
use crate::validation;

fn ensure_token_within_limit(token: &str) -> PyResult<()> {
    jws::check_compact_token_size(token).map_err(errors::decode_error)
}

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
    leeway = 0.0,
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
    leeway: f64,
    options: Option<&Bound<'_, PyAny>>,
    require: Option<Vec<String>>,
) -> PyResult<Py<PyAny>> {
    ensure_token_within_limit(token)?;
    let decode_validation = validation::build_validation(
        algorithms, audience, issuer, subject, leeway, options, require,
    )?;
    let decoding_key = decoding_key_from_py(key, &decode_validation.algorithms)?;

    let token_data = py
        .detach(|| jwt_decode::<Value>(token, &decoding_key, &decode_validation.validation))
        .map_err(errors::from_jwt_decode_error)?;

    json_to_py(py, &token_data.claims)
}

type DecodeVerifiedCompleteOutput = (Py<PyAny>, Py<PyAny>, Py<PyBytes>);

/// Verified decode for `decode_complete`: one full JWT parse via jsonwebtoken, plus a cheap
/// signature segment extraction (no duplicate header/payload JSON parse).
#[pyfunction]
#[pyo3(signature = (
    token,
    key,
    algorithms,
    *,
    audience = None,
    issuer = None,
    subject = None,
    leeway = 0.0,
    options = None,
    require = None
))]
#[allow(clippy::too_many_arguments)]
pub fn decode_verified_complete(
    py: Python<'_>,
    token: &str,
    key: &Bound<'_, PyAny>,
    algorithms: Vec<String>,
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>,
    subject: Option<String>,
    leeway: f64,
    options: Option<&Bound<'_, PyAny>>,
    require: Option<Vec<String>>,
) -> PyResult<DecodeVerifiedCompleteOutput> {
    ensure_token_within_limit(token)?;
    let decode_validation = validation::build_validation(
        algorithms, audience, issuer, subject, leeway, options, require,
    )?;
    let decoding_key = decoding_key_from_py(key, &decode_validation.algorithms)?;

    let token_data = py
        .detach(|| jwt_decode::<Value>(token, &decoding_key, &decode_validation.validation))
        .map_err(errors::from_jwt_decode_error)?;

    let header_value = serde_json::to_value(&token_data.header).map_err(|err| {
        errors::decode_error(format!("failed to serialize decoded header: {err}"))
    })?;
    let header_py = json_to_py(py, &header_value)?;
    let claims_py = json_to_py(py, &token_data.claims)?;
    let token_owned = token.to_owned();
    let signature = py
        .detach(move || jws::extract_signature_bytes(&token_owned))
        .map_err(errors::decode_error)?;
    let sig_py = PyBytes::new(py, &signature);
    Ok((claims_py, header_py, sig_py.into()))
}

#[pyfunction]
pub fn get_unverified_header(py: Python<'_>, token: &str) -> PyResult<Py<PyAny>> {
    ensure_token_within_limit(token)?;
    let token = token.to_owned();
    let header = py
        .detach(move || decode_header(&token))
        .map_err(errors::from_jwt_decode_error)?;
    let value = serde_json::to_value(header)
        .map_err(|err| errors::decode_error(format!("failed to serialize header: {err}")))?;

    json_to_py(py, &value)
}

#[pyfunction]
pub fn decode_unverified(py: Python<'_>, token: &str) -> PyResult<Py<PyAny>> {
    ensure_token_within_limit(token)?;
    let token = token.to_owned();
    let token_data = py
        .detach(move || dangerous::insecure_decode::<Value>(&token))
        .map_err(errors::from_jwt_decode_error)?;

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
            "jku" => header.jku = optional_string("jku", value)?,
            "x5u" => header.x5u = optional_string("x5u", value)?,
            "x5t" => header.x5t = optional_string("x5t", value)?,
            "x5t#S256" => header.x5t_s256 = optional_string("x5t#S256", value)?,
            "url" => header.url = optional_string("url", value)?,
            "nonce" => header.nonce = optional_string("nonce", value)?,
            "jwk" | "x5c" | "crit" | "enc" | "zip" => {
                return Err(errors::encode_error(format!(
                    "JWT header field '{key}' is not supported in encode headers (use supported string fields or custom string parameters)"
                )));
            }
            name => {
                header
                    .extras
                    .insert(name.to_owned(), custom_header_string(name, value)?);
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

fn custom_header_string(name: &str, value: &Value) -> PyResult<String> {
    value.as_str().map(|s| s.to_owned()).ok_or_else(|| {
        errors::encode_error(format!(
            "headers['{name}'] must be a string for custom JWT header parameters"
        ))
    })
}

fn parse_payload_json(payload_json: &Bound<'_, PyAny>) -> PyResult<Value> {
    if let Ok(bytes) = payload_json.extract::<&[u8]>() {
        return serde_json::from_slice(bytes)
            .map_err(|e| errors::encode_error(format!("payload_json must be a JSON object: {e}")));
    }
    if let Ok(text) = payload_json.extract::<&str>() {
        return serde_json::from_str(text)
            .map_err(|e| errors::encode_error(format!("payload_json must be a JSON object: {e}")));
    }
    Err(errors::encode_error(
        "payload_json must be a UTF-8 str or bytes containing a JSON object",
    ))
}

/// Encode a JWT from an already-serialized JSON object (str or bytes from Python).
#[pyfunction]
#[pyo3(signature = (payload_json, key, algorithm = "HS256", headers = None))]
pub fn encode_json(
    py: Python<'_>,
    payload_json: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
    algorithm: &str,
    headers: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let claims = parse_payload_json(payload_json)?;
    if !claims.is_object() {
        return Err(errors::encode_error(
            "Expecting a dict object, as JWT only supports JSON objects as payloads.",
        ));
    }
    let algorithm = parse_algorithm(algorithm)?;
    let mut header = Header::new(algorithm);
    apply_headers(&mut header, headers, algorithm)?;
    let encoding_key = encoding_key_from_py(key, algorithm)?;

    py.detach(|| jwt_encode(&header, &claims, &encoding_key))
        .map_err(errors::from_jwt_encode_error)
}
