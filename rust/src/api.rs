use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{
    crypto::verify as jwt_crypto_verify, dangerous, decode as jwt_decode, encode as jwt_encode,
    Header,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;

use crate::algorithms::{algorithm_name, parse_algorithm, parse_algorithm_name};
use crate::claims::{json_to_py, py_to_json_for_encode};
use crate::claims_validate;
use crate::errors;
use crate::jws;
use crate::keys::{decoding_key_from_py, encoding_key_from_py};
use crate::validation;

/// Size limit plus strict three-segment compact JWS check (before jsonwebtoken).
fn ensure_valid_compact_jwt(token: &str) -> PyResult<()> {
    jws::split_compact_segments(token)
        .map(|_| ())
        .map_err(errors::decode_error)
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
    ensure_valid_compact_jwt(token)?;
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
    require = None,
    detached_payload = None
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
    detached_payload: Option<&Bound<'_, PyBytes>>,
) -> PyResult<DecodeVerifiedCompleteOutput> {
    ensure_valid_compact_jwt(token)?;
    let decode_validation = validation::build_validation(
        algorithms, audience, issuer, subject, leeway, options, require,
    )?;
    let decoding_key = decoding_key_from_py(key, &decode_validation.algorithms)?;

    if let Some(payload) = detached_payload {
        return decode_rfc7797_verified_complete(
            py,
            token,
            payload.as_bytes(),
            &decode_validation,
            &decoding_key,
        );
    }

    let token_owned = token.to_owned();
    let validation = decode_validation.validation;
    let (token_data, signature) = py.detach(
        move || -> PyResult<(jsonwebtoken::TokenData<Value>, Vec<u8>)> {
            let token_data = jwt_decode::<Value>(&token_owned, &decoding_key, &validation)
                .map_err(errors::from_jwt_decode_error)?;
            let signature =
                jws::extract_signature_bytes(&token_owned).map_err(errors::decode_error)?;
            Ok((token_data, signature))
        },
    )?;

    let header_value = serde_json::to_value(&token_data.header).map_err(|err| {
        errors::decode_error(format!("failed to serialize decoded header: {err}"))
    })?;
    let header_py = json_to_py(py, &header_value)?;
    let claims_py = json_to_py(py, &token_data.claims)?;
    let sig_py = PyBytes::new(py, &signature);
    Ok((claims_py, header_py, sig_py.into()))
}

fn decode_rfc7797_verified_complete(
    py: Python<'_>,
    token: &str,
    detached_payload: &[u8],
    decode_validation: &validation::DecodeValidation,
    decoding_key: &jsonwebtoken::DecodingKey,
) -> PyResult<DecodeVerifiedCompleteOutput> {
    if detached_payload.len() > jws::MAX_COMPACT_JWT_BYTES {
        return Err(errors::decode_error(format!(
            "Detached payload exceeds maximum size ({} bytes)",
            jws::MAX_COMPACT_JWT_BYTES
        )));
    }
    let token = token.to_owned();
    let payload = detached_payload.to_vec();
    let allowed_algorithms = decode_validation.algorithms.clone();
    let decoding_key = decoding_key.clone();
    let validation = decode_validation.validation.clone();
    let (parts, claims, signature) = py
        .detach(move || {
            let parts = jws::parse_rfc7797_compact(&token)?;
            let claims: Value = serde_json::from_slice(&payload)
                .map_err(|err| format!("Invalid payload string: {err}"))?;
            if !claims.is_object() {
                return Err("Invalid payload string: must be a json object".to_string());
            }
            let alg_name = parts
                .header
                .get("alg")
                .and_then(Value::as_str)
                .ok_or_else(|| "Algorithm not specified".to_string())?;
            let algorithm = parse_algorithm_name(alg_name)?;
            if !allowed_algorithms.contains(&algorithm) {
                return Err("The specified alg value is not allowed".to_string());
            }
            let signing_input = jws::signing_input_rfc7797(&parts.header_segment, &payload);
            let verified = jwt_crypto_verify(
                &parts.signature_segment,
                &signing_input,
                &decoding_key,
                algorithm,
            )
            .map_err(|err| err.to_string())?;
            if !verified {
                return Err("Signature verification failed".to_string());
            }
            claims_validate::validate_claims_value(&claims, &validation)
                .map_err(|err| err.to_string())?;
            let signature = URL_SAFE_NO_PAD
                .decode(&parts.signature_segment)
                .map_err(|e| e.to_string())?;
            Ok((parts, claims, signature))
        })
        .map_err(map_rfc7797_decode_error)?;

    let header_py = json_to_py(py, &parts.header)?;
    let claims_py = json_to_py(py, &claims)?;
    let sig_py = PyBytes::new(py, &signature);
    Ok((claims_py, header_py, sig_py.into()))
}

fn map_rfc7797_decode_error(message: String) -> PyErr {
    if message.contains("Expired") || message.contains("expired") {
        return errors::ExpiredSignatureError::new_err(message);
    }
    if message.contains("Immature") || message.contains("not yet valid") {
        return errors::ImmatureSignatureError::new_err(message);
    }
    if message.contains("Invalid audience") || message.contains("Audience") {
        return errors::InvalidAudienceError::new_err(message);
    }
    if message.contains("Invalid issuer") || message.contains("issuer") {
        return errors::InvalidIssuerError::new_err(message);
    }
    if message.contains("Invalid subject") || message.contains("Subject") {
        return errors::InvalidSubjectError::new_err(message);
    }
    if message.contains("Missing") && message.contains("claim") {
        return errors::MissingRequiredClaimError::new_err(message);
    }
    if message.contains("Signature verification failed") {
        return errors::InvalidSignatureError::new_err(message);
    }
    if message.contains("not allowed") || message.contains("not supported") {
        return errors::InvalidAlgorithmError::new_err(message);
    }
    if message.contains("Invalid payload") {
        return errors::DecodeError::new_err(message);
    }
    if message.contains("b64") || message.contains("Payload segment") {
        return errors::InvalidTokenError::new_err(message);
    }
    errors::decode_error(message)
}

#[pyfunction]
pub fn get_unverified_header(py: Python<'_>, token: &str) -> PyResult<Py<PyAny>> {
    ensure_valid_compact_jwt(token)?;
    let token = token.to_owned();
    let header = py
        .detach(move || jws::parse_compact_header_json(&token))
        .map_err(errors::decode_error)?;

    json_to_py(py, &header)
}

#[pyfunction]
pub fn decode_unverified(py: Python<'_>, token: &str) -> PyResult<Py<PyAny>> {
    ensure_valid_compact_jwt(token)?;
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

fn extract_payload_object_bytes<'a>(payload_json: &'a Bound<'_, PyAny>) -> PyResult<&'a [u8]> {
    let bytes = if let Ok(b) = payload_json.extract::<&'a [u8]>() {
        b
    } else if let Ok(s) = payload_json.extract::<&'a str>() {
        s.as_bytes()
    } else {
        return Err(errors::encode_error(
            "payload_json must be a UTF-8 str or bytes containing a JSON object",
        ));
    };

    let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
    let last = bytes.iter().rfind(|b| !b.is_ascii_whitespace());

    if first != Some(&b'{') || last != Some(&b'}') {
        return Err(errors::encode_error(
            "Expecting a dict object, as JWT only supports JSON objects as payloads.",
        ));
    }

    Ok(bytes)
}

/// Encode a JWT from an already-serialized JSON object (str or bytes from Python) without DOM tree allocation.
#[pyfunction]
#[pyo3(signature = (payload_json, key, algorithm = "HS256", headers = None))]
pub fn encode_json(
    py: Python<'_>,
    payload_json: &Bound<'_, PyAny>,
    key: &Bound<'_, PyAny>,
    algorithm: &str,
    headers: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let payload_bytes = extract_payload_object_bytes(payload_json)?;
    let algorithm = parse_algorithm(algorithm)?;
    let mut header = Header::new(algorithm);
    apply_headers(&mut header, headers, algorithm)?;
    let encoding_key = encoding_key_from_py(key, algorithm)?;

    let header_json = serde_json::to_vec(&header)
        .map_err(|e| errors::encode_error(format!("failed to serialize header: {e}")))?;

    let payload_owned = payload_bytes.to_vec();

    py.detach(move || {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_owned);
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signature =
            jsonwebtoken::crypto::sign(signing_input.as_bytes(), &encoding_key, algorithm)
                .map_err(errors::from_jwt_encode_error)?;

        Ok(format!("{signing_input}.{signature}"))
    })
}
