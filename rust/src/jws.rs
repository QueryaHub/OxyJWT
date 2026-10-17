//! Compact JWS parsing (header.payload.signature) for PyJWT-style decode_complete.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::de::Deserializer;
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

/// Validate the `crit` header parameter value according to RFC 7515 §4.1.11.
///
/// `crit_val` must be a non-empty array of strings, and each named parameter
/// must be present in `understood`. If any named parameter is unrecognized or
/// malformed, an error is returned.
pub fn validate_crit_value(crit_val: &Value, understood: &[&str]) -> Result<(), String> {
    let Some(crit) = crit_val.as_array() else {
        return Err("Items in 'crit' header must be strings".to_string());
    };
    if crit.is_empty() {
        return Err("The 'crit' header parameter must not be empty".to_string());
    }
    for param in crit {
        let Some(param_str) = param.as_str() else {
            return Err("Items in 'crit' header must be strings".to_string());
        };
        if !understood.contains(&param_str) {
            return Err(format!(
                "Unsupported critical header parameter in 'crit': '{param_str}'"
            ));
        }
    }
    Ok(())
}

/// Validate the `crit` header parameter in `header` according to RFC 7515 §4.1.11.
///
/// If `crit` is present in `header`, it must be a non-empty array of strings,
/// and each named parameter must be present in `understood`. If any named parameter
/// is unrecognized, an error is returned.
pub fn validate_crit_header(header: &Value, understood: &[&str]) -> Result<(), String> {
    let Some(crit_val) = header.get("crit") else {
        return Ok(());
    };
    validate_crit_value(crit_val, understood)
}

/// Fast-path match for standard base64url-encoded JWT header segments.
///
/// Standard headers (such as `{"typ":"JWT","alg":"HS256"}` or `{"alg":"HS256","typ":"JWT"}`)
/// account for the vast majority of compact JWTs. Recognizing these static base64
/// slices allows instantaneous algorithm resolution with zero base64 decoding,
/// zero JSON parsing, and zero heap allocations.
#[inline]
pub fn match_standard_header(header_segment: &str) -> Option<jsonwebtoken::Algorithm> {
    use jsonwebtoken::Algorithm;
    match header_segment {
        // Form 1: {"typ":"JWT","alg":"<ALG>"} (standard in jsonwebtoken / OxyJWT)
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" => Some(Algorithm::HS256),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9" => Some(Algorithm::HS384),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9" => Some(Algorithm::HS512),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9" => Some(Algorithm::RS256),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9" => Some(Algorithm::RS384),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9" => Some(Algorithm::RS512),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9" => Some(Algorithm::PS256),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCJ9" => Some(Algorithm::PS384),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9" => Some(Algorithm::PS512),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9" => Some(Algorithm::ES256),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9" => Some(Algorithm::ES384),
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9" => Some(Algorithm::EdDSA),

        // Form 2: {"alg":"<ALG>","typ":"JWT"} (standard in PyJWT and many other libraries)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::HS256),
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9" => Some(Algorithm::HS384),
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::HS512),
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::RS256),
        "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9" => Some(Algorithm::RS384),
        "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::RS512),
        "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::PS256),
        "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9" => Some(Algorithm::PS384),
        "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::PS512),
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9" => Some(Algorithm::ES256),
        "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9" => Some(Algorithm::ES384),
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9" => Some(Algorithm::EdDSA),

        // Form 3: {"alg":"<ALG>"} (minimal header without typ)
        "eyJhbGciOiJIUzI1NiJ9" => Some(Algorithm::HS256),
        "eyJhbGciOiJIUzM4NCJ9" => Some(Algorithm::HS384),
        "eyJhbGciOiJIUzUxMiJ9" => Some(Algorithm::HS512),
        "eyJhbGciOiJSUzI1NiJ9" => Some(Algorithm::RS256),
        "eyJhbGciOiJSUzM4NCJ9" => Some(Algorithm::RS384),
        "eyJhbGciOiJSUzUxMiJ9" => Some(Algorithm::RS512),
        "eyJhbGciOiJQUzI1NiJ9" => Some(Algorithm::PS256),
        "eyJhbGciOiJQUzM4NCJ9" => Some(Algorithm::PS384),
        "eyJhbGciOiJQUzUxMiJ9" => Some(Algorithm::PS512),
        "eyJhbGciOiJFUzI1NiJ9" => Some(Algorithm::ES256),
        "eyJhbGciOiJFUzM4NCJ9" => Some(Algorithm::ES384),
        "eyJhbGciOiJFZERTQSJ9" => Some(Algorithm::EdDSA),

        _ => None,
    }
}

/// Pre-encoded URL-safe unpadded base64 representation of `{"typ":"JWT","alg":"<ALG>"}`.
///
/// For standard encodings with default headers, using this constant slice avoids
/// runtime JSON serialization and base64 encoding on every single `encode` call.
#[inline]
pub fn standard_header_base64(algorithm: jsonwebtoken::Algorithm) -> &'static str {
    use jsonwebtoken::Algorithm;
    match algorithm {
        Algorithm::HS256 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
        Algorithm::HS384 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9",
        Algorithm::HS512 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9",
        Algorithm::RS256 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9",
        Algorithm::RS384 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9",
        Algorithm::RS512 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9",
        Algorithm::PS256 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9",
        Algorithm::PS384 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCJ9",
        Algorithm::PS512 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9",
        Algorithm::ES256 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9",
        Algorithm::ES384 => "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9",
        Algorithm::EdDSA => "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9",
    }
}

#[derive(Debug)]
pub struct FastHeaderSummary {
    pub algorithm: jsonwebtoken::Algorithm,
    pub crit: Option<Value>,
}

#[derive(Debug)]
enum AlgValue<'de> {
    Str(std::borrow::Cow<'de, str>),
    NotAString,
}

struct AlgValueVisitor;

impl<'de> serde::de::Visitor<'de> for AlgValueVisitor {
    type Value = AlgValue<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(AlgValue::Str(std::borrow::Cow::Borrowed(v)))
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(AlgValue::Str(std::borrow::Cow::Owned(v.to_owned())))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(AlgValue::Str(std::borrow::Cow::Owned(v)))
    }

    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E> {
        Ok(AlgValue::NotAString)
    }

    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E> {
        Ok(AlgValue::NotAString)
    }

    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E> {
        Ok(AlgValue::NotAString)
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(AlgValue::NotAString)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(AlgValue::NotAString)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(AlgValue::NotAString)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while let Some(serde::de::IgnoredAny) = seq.next_element()? {}
        Ok(AlgValue::NotAString)
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        while let Some((serde::de::IgnoredAny, serde::de::IgnoredAny)) = map.next_entry()? {}
        Ok(AlgValue::NotAString)
    }
}

impl<'de> serde::Deserialize<'de> for AlgValue<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(AlgValueVisitor)
    }
}

const NON_OBJECT_HEADER_ERR: &str = "Invalid header string: must be a json object";

struct HeaderSummary<'de> {
    alg: Option<AlgValue<'de>>,
    crit: Option<Value>,
}

struct HeaderSummaryVisitor;

impl<'de> serde::de::Visitor<'de> for HeaderSummaryVisitor {
    type Value = HeaderSummary<'de>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a json object")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        let mut alg = None;
        let mut crit = None;

        while let Some(key) = access.next_key::<std::borrow::Cow<'de, str>>()? {
            match key.as_ref() {
                "alg" => {
                    alg = Some(access.next_value::<AlgValue<'de>>()?);
                }
                "crit" => {
                    crit = Some(access.next_value::<Value>()?);
                }
                _ => {
                    let _ = access.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }

        Ok(HeaderSummary { alg, crit })
    }

    fn visit_seq<A>(self, _seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }

    fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }

    fn visit_i64<E>(self, _v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }

    fn visit_u64<E>(self, _v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }

    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(serde::de::Error::custom(NON_OBJECT_HEADER_ERR))
    }
}

fn parse_header_alg_from_slice(
    header_bytes: &[u8],
) -> Result<FastHeaderSummary, errors::DecodeFail> {
    let mut de = serde_json::Deserializer::from_slice(header_bytes);
    let summary = de.deserialize_any(HeaderSummaryVisitor).map_err(|e| {
        let msg = e.to_string();
        if msg.starts_with(NON_OBJECT_HEADER_ERR) {
            errors::DecodeFail::Decode(NON_OBJECT_HEADER_ERR.to_string())
        } else {
            errors::DecodeFail::Decode(msg)
        }
    })?;

    de.end().map_err(|e| {
        let msg = e.to_string();
        if msg.starts_with(NON_OBJECT_HEADER_ERR) {
            errors::DecodeFail::Decode(NON_OBJECT_HEADER_ERR.to_string())
        } else {
            errors::DecodeFail::Decode(msg)
        }
    })?;

    let Some(alg_value) = summary.alg else {
        return Err(errors::DecodeFail::Decode(
            "missing field `alg` in JWT header".to_owned(),
        ));
    };

    let alg_name = match alg_value {
        AlgValue::Str(s) => s,
        AlgValue::NotAString => {
            return Err(errors::DecodeFail::Decode(
                "missing field `alg` in JWT header".to_owned(),
            ));
        }
    };

    let algorithm =
        crate::algorithms::parse_algorithm_name(&alg_name).map_err(errors::DecodeFail::Decode)?;

    Ok(FastHeaderSummary {
        algorithm,
        crit: summary.crit,
    })
}

/// Zero-copy resolution of algorithm and critical header parameters from a protected header segment.
///
/// Tries `match_standard_header` first. On non-standard headers, uses a streaming serde visitor
/// to extract `alg` and `crit` without heap map allocations or unnecessary string cloning.
pub fn resolve_header_alg_and_crit(
    header_segment: &str,
) -> Result<FastHeaderSummary, errors::DecodeFail> {
    if let Some(algorithm) = match_standard_header(header_segment) {
        return Ok(FastHeaderSummary {
            algorithm,
            crit: None,
        });
    }

    let mut stack_buf = [0u8; 512];
    if header_segment.len() <= 512 {
        match URL_SAFE_NO_PAD.decode_slice(header_segment.as_bytes(), &mut stack_buf) {
            Ok(len) => parse_header_alg_from_slice(&stack_buf[..len]),
            Err(_) => {
                let err = URL_SAFE_NO_PAD.decode(header_segment).unwrap_err();
                Err(errors::DecodeFail::Decode(err.to_string()))
            }
        }
    } else {
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_segment)
            .map_err(|e| errors::DecodeFail::Decode(e.to_string()))?;
        parse_header_alg_from_slice(&header_bytes)
    }
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
    validate_crit_header(header, &["b64"])?;
    if !crit.iter().any(|param| param.as_str() == Some("b64")) {
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
#[cfg(test)]
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

    #[test]
    fn validate_crit_header_accepts_no_crit() {
        let header = serde_json::json!({"alg": "HS256"});
        assert!(validate_crit_header(&header, &[]).is_ok());
    }

    #[test]
    fn validate_crit_header_rejects_empty_crit() {
        let header = serde_json::json!({"alg": "HS256", "crit": []});
        let err = validate_crit_header(&header, &[]).unwrap_err();
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn validate_crit_header_rejects_non_array_crit() {
        let header = serde_json::json!({"alg": "HS256", "crit": "b64"});
        let err = validate_crit_header(&header, &[]).unwrap_err();
        assert!(err.contains("must be strings"));
    }

    #[test]
    fn validate_crit_header_rejects_non_string_items() {
        let header = serde_json::json!({"alg": "HS256", "crit": [123]});
        let err = validate_crit_header(&header, &[]).unwrap_err();
        assert!(err.contains("must be strings"));
    }

    #[test]
    fn validate_crit_header_rejects_unsupported_crit() {
        let header = serde_json::json!({"alg": "HS256", "crit": ["exp-strict-mode"]});
        let err = validate_crit_header(&header, &[]).unwrap_err();
        assert!(err.contains("Unsupported critical header parameter in 'crit': 'exp-strict-mode'"));
    }

    #[test]
    fn validate_crit_header_accepts_understood_crit() {
        let header = serde_json::json!({"alg": "HS256", "crit": ["b64"]});
        assert!(validate_crit_header(&header, &["b64"]).is_ok());
    }

    #[test]
    fn match_standard_header_recognizes_forms() {
        use jsonwebtoken::Algorithm;
        assert_eq!(
            match_standard_header("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"),
            Some(Algorithm::HS256)
        );
        assert_eq!(
            match_standard_header("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            Some(Algorithm::HS256)
        );
        assert_eq!(
            match_standard_header("eyJhbGciOiJIUzI1NiJ9"),
            Some(Algorithm::HS256)
        );
        assert_eq!(
            match_standard_header("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"),
            Some(Algorithm::RS256)
        );
        assert_eq!(match_standard_header("non-standard"), None);
    }

    #[test]
    fn resolve_header_alg_extracts_from_custom_header() {
        use jsonwebtoken::Algorithm;
        // {"alg":"HS256","kid":"k1","typ":"JWT"}
        let segment = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0";
        let summary = resolve_header_alg_and_crit(segment).expect("parse");
        assert_eq!(summary.algorithm, Algorithm::HS256);
        assert!(summary.crit.is_none());
    }

    #[test]
    fn resolve_header_alg_extracts_crit_field() {
        use jsonwebtoken::Algorithm;
        // {"alg":"HS256","crit":["unknown"]}
        let segment = "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsidW5rbm93biJdfQ";
        let summary = resolve_header_alg_and_crit(segment).expect("parse");
        assert_eq!(summary.algorithm, Algorithm::HS256);
        assert_eq!(summary.crit, Some(serde_json::json!(["unknown"])));
    }

    #[test]
    fn resolve_header_alg_rejects_missing_or_non_string_alg() {
        // {"typ":"JWT"}
        let missing_alg = "eyJ0eXAiOiJKV1QifQ";
        match resolve_header_alg_and_crit(missing_alg).unwrap_err() {
            errors::DecodeFail::Decode(msg) => {
                assert_eq!(msg, "missing field `alg` in JWT header");
            }
            other => panic!("expected Decode error, got {other:?}"),
        }

        // {"alg":123}
        let int_alg = "eyJhbGciOjEyM30";
        match resolve_header_alg_and_crit(int_alg).unwrap_err() {
            errors::DecodeFail::Decode(msg) => {
                assert_eq!(msg, "missing field `alg` in JWT header");
            }
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_header_alg_rejects_non_object_header() {
        // [1, 2]
        let array_header = "WzEsMl0";
        match resolve_header_alg_and_crit(array_header).unwrap_err() {
            errors::DecodeFail::Decode(msg) => {
                assert_eq!(msg, "Invalid header string: must be a json object");
            }
            other => panic!("expected Decode error, got {other:?}"),
        }

        // "string"
        let str_header = "InN0cmluZyI";
        match resolve_header_alg_and_crit(str_header).unwrap_err() {
            errors::DecodeFail::Decode(msg) => {
                assert_eq!(msg, "Invalid header string: must be a json object");
            }
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn resolve_header_alg_rejects_invalid_base64_or_json() {
        let invalid_b64 = "???";
        assert!(matches!(
            resolve_header_alg_and_crit(invalid_b64),
            Err(errors::DecodeFail::Decode(_))
        ));

        // {"alg":
        let invalid_json = "eyJhbGciOi";
        assert!(matches!(
            resolve_header_alg_and_crit(invalid_json),
            Err(errors::DecodeFail::Decode(_))
        ));
    }

    #[test]
    fn standard_header_base64_matches_header_new() {
        use jsonwebtoken::{Algorithm, Header};

        let algorithms = [
            Algorithm::HS256,
            Algorithm::HS384,
            Algorithm::HS512,
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::EdDSA,
        ];

        for alg in algorithms {
            let header = Header::new(alg);
            let json = serde_json::to_vec(&header).unwrap();
            let b64 = URL_SAFE_NO_PAD.encode(&json);
            assert_eq!(
                standard_header_base64(alg),
                b64,
                "mismatch for algorithm {alg:?}"
            );
        }
    }
}
