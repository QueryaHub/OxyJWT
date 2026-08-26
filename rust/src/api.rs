use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::errors::{new_error, ErrorKind};
use jsonwebtoken::{
    crypto::verify as jwt_crypto_verify, dangerous, encode as jwt_encode, DecodingKey, Header,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;

use crate::algorithms::{
    algorithm_name, ensure_single_family, parse_algorithm, parse_algorithm_name,
};
use crate::claims::{json_to_py, py_to_json_for_encode};
use crate::claims_validate;
use crate::errors;
use crate::jws;
use crate::keys::{decoding_key_from_py, encoding_key_from_py};
use crate::validation::{self, DecodeValidation};

/// Size limit plus strict three-segment compact JWS check (before parsing).
fn ensure_valid_compact_jwt(token: &str) -> PyResult<()> {
    jws::split_compact_segments(token)
        .map(|_| ())
        .map_err(errors::decode_error)
}

/// Failure from a decode step that runs with the GIL released.
///
/// Keeping the variants typed (instead of matching on message text) means the
/// Python exception class is chosen from the failure itself.
enum DecodeFail {
    Jwt(jsonwebtoken::errors::Error),
    Decode(String),
    Token(String),
}

impl From<jsonwebtoken::errors::Error> for DecodeFail {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        DecodeFail::Jwt(err)
    }
}

fn decode_fail(kind: ErrorKind) -> DecodeFail {
    DecodeFail::Jwt(new_error(kind))
}

fn map_decode_fail(fail: DecodeFail) -> PyErr {
    match fail {
        DecodeFail::Jwt(err) => errors::from_jwt_decode_error(err),
        DecodeFail::Decode(message) => errors::decode_error(message),
        DecodeFail::Token(message) => errors::invalid_token(message),
    }
}

/// Verified claims plus the protected header, both parsed exactly once.
struct VerifiedToken {
    header: Value,
    claims: Value,
}

/// Verify a compact JWT and parse it in a single pass.
///
/// `jsonwebtoken::decode` parses the header twice and the payload twice (once
/// for the caller's type, once for its internal validation struct) and returns
/// a `Header` struct that we would have to re-serialize to hand back to Python.
/// Doing the steps here keeps it to one header parse, one payload parse and one
/// signature check, and lets us reuse the already-parsed header as the Python
/// header dict.
fn verify_and_parse(
    token: &str,
    decoding_key: &DecodingKey,
    decode_validation: &DecodeValidation,
) -> Result<VerifiedToken, DecodeFail> {
    let (header_segment, payload_segment, signature_segment) =
        jws::split_compact_segments(token).map_err(DecodeFail::Decode)?;

    let header = jws::decode_header_json(header_segment).map_err(DecodeFail::Decode)?;
    let algorithm = header_algorithm(&header)?;
    if !decode_validation.algorithms().contains(&algorithm) {
        return Err(decode_fail(ErrorKind::InvalidAlgorithm));
    }
    // jsonwebtoken rejects an allow-list spanning several key families; keys
    // built from a JWK skip the equivalent check in `keys.rs`.
    ensure_single_family_for_decode(decode_validation.algorithms())?;

    let signing_input = jws::signing_input_of(token, header_segment, payload_segment);
    if !jwt_crypto_verify(signature_segment, signing_input, decoding_key, algorithm)? {
        return Err(decode_fail(ErrorKind::InvalidSignature));
    }

    let payload = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|err| DecodeFail::Decode(err.to_string()))?;
    let claims: Value =
        serde_json::from_slice(&payload).map_err(|err| DecodeFail::Decode(err.to_string()))?;
    if !claims.is_object() {
        return Err(DecodeFail::Decode(
            "Invalid payload string: must be a json object".to_owned(),
        ));
    }

    claims_validate::validate_claims_value(&claims, &decode_validation.validation)?;

    Ok(VerifiedToken { header, claims })
}

fn header_algorithm(header: &Value) -> Result<jsonwebtoken::Algorithm, DecodeFail> {
    let name = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| DecodeFail::Decode("missing field `alg` in JWT header".to_owned()))?;
    // An unusable `alg` has always surfaced as `DecodeError` on this path, and
    // that class is narrower than `InvalidTokenError`, so keep raising it.
    parse_algorithm_name(name).map_err(DecodeFail::Decode)
}

fn ensure_single_family_for_decode(
    algorithms: &[jsonwebtoken::Algorithm],
) -> Result<(), DecodeFail> {
    ensure_single_family(algorithms)
        .map(|_| ())
        .map_err(|_| decode_fail(ErrorKind::InvalidAlgorithm))
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
    let decode_validation = validation::build_validation(
        algorithms, audience, issuer, subject, leeway, options, require,
    )?;
    let decoding_key = decoding_key_from_py(key, decode_validation.algorithms())?;

    let verified = py
        .detach(|| verify_and_parse(token, &decoding_key, &decode_validation))
        .map_err(map_decode_fail)?;

    json_to_py(py, &verified.claims)
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
    let decode_validation = validation::build_validation(
        algorithms, audience, issuer, subject, leeway, options, require,
    )?;
    let decoding_key = decoding_key_from_py(key, decode_validation.algorithms())?;

    if let Some(payload) = detached_payload {
        return decode_rfc7797_verified_complete(
            py,
            token,
            payload.as_bytes(),
            &decode_validation,
            &decoding_key,
        );
    }

    let (verified, signature) = py
        .detach(|| -> Result<(VerifiedToken, Vec<u8>), DecodeFail> {
            let verified = verify_and_parse(token, &decoding_key, &decode_validation)?;
            let signature = jws::extract_signature_bytes(token).map_err(DecodeFail::Decode)?;
            Ok((verified, signature))
        })
        .map_err(map_decode_fail)?;

    let claims_py = json_to_py(py, &verified.claims)?;
    let header_py = json_to_py(py, &verified.header)?;
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

    let (parts, claims, signature) = py
        .detach(|| -> Result<_, DecodeFail> {
            let parts = jws::parse_rfc7797_compact(token).map_err(DecodeFail::Token)?;
            let claims: Value = serde_json::from_slice(detached_payload)
                .map_err(|err| DecodeFail::Decode(format!("Invalid payload string: {err}")))?;
            if !claims.is_object() {
                return Err(DecodeFail::Decode(
                    "Invalid payload string: must be a json object".to_owned(),
                ));
            }

            let algorithm = header_algorithm(&parts.header)?;
            if !decode_validation.algorithms().contains(&algorithm) {
                return Err(decode_fail(ErrorKind::InvalidAlgorithm));
            }
            ensure_single_family_for_decode(decode_validation.algorithms())?;

            let signing_input = jws::signing_input_rfc7797(&parts.header_segment, detached_payload);
            if !jwt_crypto_verify(
                &parts.signature_segment,
                &signing_input,
                decoding_key,
                algorithm,
            )? {
                return Err(decode_fail(ErrorKind::InvalidSignature));
            }

            claims_validate::validate_claims_value(&claims, &decode_validation.validation)?;

            let signature = URL_SAFE_NO_PAD
                .decode(&parts.signature_segment)
                .map_err(|err| DecodeFail::Decode(err.to_string()))?;
            Ok((parts, claims, signature))
        })
        .map_err(map_decode_fail)?;

    let header_py = json_to_py(py, &parts.header)?;
    let claims_py = json_to_py(py, &claims)?;
    let sig_py = PyBytes::new(py, &signature);
    Ok((claims_py, header_py, sig_py.into()))
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
