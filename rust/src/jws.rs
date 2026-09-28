//! Compact JWS parsing (header.payload.signature) for PyJWT-style decode_complete.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;

use crate::errors;

type CompactJwsParts = (Value, Vec<u8>, Vec<u8>);

/// Maximum compact serialization size (`header.payload.signature`) before parsing.
pub const MAX_COMPACT_JWT_BYTES: usize = 256 * 1024;

/// Reject oversized tokens before base64/JSON work (DoS mitigation).
pub fn check_compact_token_size(token: &str) -> Result<(), String> {
    if token.len() > MAX_COMPACT_JWT_BYTES {
        return Err(format!(
            "JWT exceeds maximum compact token size ({MAX_COMPACT_JWT_BYTES} bytes)"
        ));
    }
    Ok(())
}

/// Split a compact JWS/JWT into encoded header, payload, and signature segments.
pub fn split_compact_segments(token: &str) -> Result<(&str, &str, &str), String> {
    check_compact_token_size(token)?;
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
    Ok((h, p, s))
}

pub fn decode_header_json(header_segment: &str) -> Result<Value, String> {
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|e| e.to_string())?;
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;
    if !header.is_object() {
        return Err("Invalid header string: must be a json object".to_string());
    }
    Ok(header)
}

/// Decode the protected header JSON without parsing the payload (RFC 7515 / RFC 7797).
pub fn parse_compact_header_json(token: &str) -> Result<Value, String> {
    let (h, _, _) = split_compact_segments(token)?;
    decode_header_json(h)
}

/// RFC 7797 detached JWS: `b64:false`, empty payload segment, external payload bytes.
pub struct Rfc7797Parts {
    pub header_segment: String,
    pub signature_segment: String,
    pub header: Value,
}

pub fn validate_rfc7797_header(header: &Value) -> Result<(), String> {
    if header.get("b64").and_then(Value::as_bool) != Some(false) {
        return Err(
            "detached_payload requires the JWT header to set b64 to false (RFC 7797)".to_string(),
        );
    }
    let crit = header
        .get("crit")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "The 'b64' header parameter requires 'b64' to be listed in 'crit'.".to_string()
        })?;
    if crit.is_empty() {
        return Err(
            "The 'b64' header parameter requires 'b64' to be listed in 'crit'.".to_string(),
        );
    }
    let mut has_b64 = false;
    for param in crit {
        let Some(param_str) = param.as_str() else {
            return Err("Items in 'crit' header must be strings".to_string());
        };
        match param_str {
            "b64" => has_b64 = true,
            other => {
                return Err(format!(
                    "Unsupported critical header parameter in 'crit': '{other}'"
                ))
            }
        }
    }
    if !has_b64 {
        return Err(
            "The 'b64' header parameter requires 'b64' to be listed in 'crit'.".to_string(),
        );
    }
    Ok(())
}

pub fn parse_rfc7797_compact(token: &str) -> Result<Rfc7797Parts, String> {
    let (h, p, s) = split_compact_segments(token)?;
    if !p.is_empty() {
        return Err("Payload segment must be empty when 'b64' is false.".to_string());
    }
    let header = decode_header_json(h)?;
    validate_rfc7797_header(&header)?;
    Ok(Rfc7797Parts {
        header_segment: h.to_owned(),
        signature_segment: s.to_owned(),
        header,
    })
}

/// JWS signing input (`header.payload`) as a borrowed prefix of the compact token.
///
/// Both segments must come from [`split_compact_segments`] on the same token.
pub fn signing_input_of<'a>(token: &'a str, header: &str, payload: &str) -> &'a [u8] {
    let len = header.len() + 1 + payload.len();
    &token.as_bytes()[..len]
}

pub fn signing_input_rfc7797(header_segment: &str, payload: &[u8]) -> Vec<u8> {
    let mut signing_input =
        Vec::with_capacity(header_segment.len().saturating_add(1) + payload.len());
    signing_input.extend_from_slice(header_segment.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload);
    signing_input
}

/// Returns `(header JSON object, raw payload bytes, signature bytes)`.
///
/// Does not compute the `header.payload` signing input: `jws_parse_compact`'s
/// only Python caller (the `decode_complete(verify_signature=False)` path in
/// `api_jwt.py`) never used it, so returning it was a wasted `Vec<u8>` clone
/// of the token's own bytes on every unverified `decode_complete` call.
pub fn parse_compact_jws(token: &str) -> Result<CompactJwsParts, String> {
    let (h, p, s) = split_compact_segments(token)?;
    let header = decode_header_json(h)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())?;
    Ok((header, payload_bytes, signature_bytes))
}

/// Decode only the claims (payload) segment of a compact JWT, for the
/// module-level `decode_unverified`, which never looks at the header or
/// signature: no reason to spend a JSON parse (or a base64 decode, for the
/// signature) on either. Still runs `split_compact_segments`, so the same
/// size cap and strict three-segment check apply as everywhere else; the
/// header is parsed as JSON only to reject a malformed one, matching
/// `get_unverified_header`'s validation, then discarded.
pub fn parse_compact_claims_unverified(token: &str) -> Result<Value, String> {
    let (header_segment, payload_segment, _) = split_compact_segments(token)?;
    decode_header_json(header_segment)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&payload).map_err(|e| e.to_string())
}

type JwsParseOutput = (Py<PyAny>, Py<PyBytes>, Py<PyBytes>);

#[pyfunction]
pub fn jws_parse_compact(py: Python<'_>, token: &str) -> PyResult<JwsParseOutput> {
    let (header, payload, signature) = py
        .detach(move || parse_compact_jws(token))
        .map_err(errors::decode_error)?;
    use crate::claims::json_to_py;
    let header_obj = json_to_py(py, &header)?;
    let pld = PyBytes::new(py, &payload);
    let sigb = PyBytes::new(py, &signature);
    Ok((header_obj, pld.into(), sigb.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_compact_token() {
        let token = "a".repeat(MAX_COMPACT_JWT_BYTES + 1);
        let err = parse_compact_jws(&token).unwrap_err();
        assert!(err.contains("maximum compact token size"));
    }

    #[test]
    fn rfc7797_signing_input_uses_raw_payload() {
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let payload = br#"{"sub":"u"}"#;
        let input = signing_input_rfc7797(header, payload);
        assert_eq!(
            input,
            format!("{header}.{}", String::from_utf8_lossy(payload)).as_bytes()
        );
    }

    #[test]
    fn rejects_extra_compact_segments() {
        let token = "a.b.c.d";
        assert_eq!(
            split_compact_segments(token).unwrap_err(),
            "Too many segments"
        );
        assert_eq!(parse_compact_jws(token).unwrap_err(), "Too many segments");
        assert_eq!(
            parse_compact_claims_unverified(token).unwrap_err(),
            "Too many segments"
        );
    }

    #[test]
    fn signing_input_of_matches_token_prefix() {
        let token =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let (h, p, _) = split_compact_segments(token).expect("split");
        assert_eq!(
            signing_input_of(token, h, p),
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0".as_slice()
        );
    }

    #[test]
    fn claims_unverified_matches_full_parse_payload() {
        let token =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let (_, payload, _) = parse_compact_jws(token).expect("parse");
        let claims: Value = serde_json::from_slice(&payload).expect("payload is json");
        assert_eq!(
            claims,
            parse_compact_claims_unverified(token).expect("claims")
        );
    }
}
