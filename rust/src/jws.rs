//! Compact JWS parsing (header.payload.signature) for PyJWT-style decode_complete.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;

use crate::errors;

type CompactJwsParts = (Vec<u8>, Value, Vec<u8>, Vec<u8>);

/// Returns `(signing_input bytes, header JSON object, raw payload bytes, signature bytes)`.
pub fn parse_compact_jws(token: &str) -> Result<CompactJwsParts, String> {
    let mut parts = token.split('.');
    let h = parts
        .next()
        .ok_or_else(|| "Not enough segments".to_string())?;
    let p = parts
        .next()
        .ok_or_else(|| "Not enough segments".to_string())?;
    let s = parts
        .next()
        .ok_or_else(|| "Not enough segments".to_string())?;
    if parts.next().is_some() {
        return Err("Too many segments".to_string());
    }
    let signing_input = format!("{h}.{p}").into_bytes();
    let header_bytes = URL_SAFE_NO_PAD.decode(h).map_err(|e| e.to_string())?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    if !header.is_object() {
        return Err("Invalid header string: must be a json object".to_string());
    }
    Ok((signing_input, header, payload_bytes, signature_bytes))
}

/// Extract and decode the JWS signature segment without parsing header or payload JSON.
pub fn extract_signature_bytes(token: &str) -> Result<Vec<u8>, String> {
    let mut parts = token.rsplitn(2, '.');
    let sig_encoded = parts
        .next()
        .ok_or_else(|| "Not enough segments".to_string())?;
    if parts.next().is_none() {
        return Err("Not enough segments".to_string());
    }
    if parts.next().is_some() {
        return Err("Too many segments".to_string());
    }
    URL_SAFE_NO_PAD
        .decode(sig_encoded)
        .map_err(|e| e.to_string())
}

type JwsParseOutput = (Py<PyBytes>, Py<PyAny>, Py<PyBytes>, Py<PyBytes>);

#[pyfunction]
pub fn jws_parse_compact(py: Python<'_>, token: &str) -> PyResult<JwsParseOutput> {
    let (signing_input, header, payload, signature) =
        parse_compact_jws(token).map_err(errors::decode_error)?;
    use crate::claims::json_to_py;
    let header_obj = json_to_py(py, &header)?;
    let signing = PyBytes::new(py, &signing_input);
    let pld = PyBytes::new(py, &payload);
    let sigb = PyBytes::new(py, &signature);
    Ok((signing.into(), header_obj, pld.into(), sigb.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_signature_matches_full_parse() {
        let token =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let (_, _, _, full_sig) = parse_compact_jws(token).expect("parse");
        let extracted = extract_signature_bytes(token).expect("extract");
        assert_eq!(full_sig, extracted);
    }
}
