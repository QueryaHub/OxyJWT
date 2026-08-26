//! Claim validation for parsed JWT payloads (e.g. RFC 7797 detached), mirroring jsonwebtoken.

use std::collections::HashSet;

use jsonwebtoken::errors::{new_error, Error, ErrorKind};
use jsonwebtoken::{get_current_timestamp, Validation};
use serde_json::Value;

enum NumericClaim {
    Missing,
    Invalid,
    Value(u64),
}

fn parse_numeric_claim(value: Option<&Value>) -> NumericClaim {
    let Some(value) = value else {
        return NumericClaim::Missing;
    };
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                NumericClaim::Value(u)
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() && f >= 0.0 && f < u64::MAX as f64 {
                    NumericClaim::Value(f.round() as u64)
                } else {
                    NumericClaim::Invalid
                }
            } else {
                NumericClaim::Invalid
            }
        }
        _ => NumericClaim::Invalid,
    }
}

fn audience_matches(claim: &Value, expected: &HashSet<String>) -> bool {
    match claim {
        Value::String(s) => expected.contains(s),
        Value::Array(items) => items
            .iter()
            .any(|item| item.as_str().is_some_and(|aud| expected.contains(aud))),
        _ => false,
    }
}

fn issuer_matches(claim: &Value, expected: &HashSet<String>) -> bool {
    match claim {
        Value::String(s) => expected.contains(s),
        Value::Array(items) => items
            .iter()
            .any(|item| item.as_str().is_some_and(|iss| expected.contains(iss))),
        _ => false,
    }
}

/// Validate standard claims on an already-parsed JSON object (post signature verify).
pub fn validate_claims_value(claims: &Value, options: &Validation) -> Result<(), Error> {
    if !claims.is_object() {
        return Err(new_error(ErrorKind::InvalidToken));
    }

    for required in &options.required_spec_claims {
        let present = match required.as_str() {
            "exp" | "nbf" => !matches!(
                parse_numeric_claim(claims.get(required)),
                NumericClaim::Missing
            ),
            "sub" | "iss" | "aud" => claims.get(required).is_some(),
            _ => continue,
        };
        if !present {
            return Err(new_error(ErrorKind::MissingRequiredClaim(required.clone())));
        }
    }

    let now = get_current_timestamp();

    if options.validate_exp || options.validate_nbf {
        if options.validate_exp
            && matches!(
                parse_numeric_claim(claims.get("exp")),
                NumericClaim::Invalid
            )
        {
            return Err(new_error(ErrorKind::InvalidClaimFormat("exp".to_string())));
        }
        if options.validate_nbf
            && matches!(
                parse_numeric_claim(claims.get("nbf")),
                NumericClaim::Invalid
            )
        {
            return Err(new_error(ErrorKind::InvalidClaimFormat("nbf".to_string())));
        }

        if let NumericClaim::Value(exp) = parse_numeric_claim(claims.get("exp")) {
            if exp < options.reject_tokens_expiring_in_less_than {
                return Err(new_error(ErrorKind::InvalidToken));
            }
            if options.validate_exp
                && exp.saturating_sub(options.reject_tokens_expiring_in_less_than)
                    <= now.saturating_sub(options.leeway)
            {
                return Err(new_error(ErrorKind::ExpiredSignature));
            }
        }

        if let NumericClaim::Value(nbf) = parse_numeric_claim(claims.get("nbf")) {
            if options.validate_nbf && nbf > now.saturating_add(options.leeway) {
                return Err(new_error(ErrorKind::ImmatureSignature));
            }
        }
    }

    if let (Some(expected_sub), Some(Value::String(sub))) =
        (options.sub.as_deref(), claims.get("sub"))
    {
        if sub != expected_sub {
            return Err(new_error(ErrorKind::InvalidSubject));
        }
    }

    if let (Some(expected_iss), Some(iss_claim)) = (options.iss.as_ref(), claims.get("iss")) {
        if !issuer_matches(iss_claim, expected_iss) {
            return Err(new_error(ErrorKind::InvalidIssuer));
        }
    }

    if !options.validate_aud {
        return Ok(());
    }

    match (claims.get("aud"), options.aud.as_ref()) {
        (Some(_aud), None) => Err(new_error(ErrorKind::InvalidAudience)),
        (Some(aud), Some(expected)) if !audience_matches(aud, expected) => {
            Err(new_error(ErrorKind::InvalidAudience))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;
    use serde_json::json;

    #[test]
    fn rejects_expired_detached_style_claims() {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        let claims = json!({"sub": "u", "exp": 1});
        let err = validate_claims_value(&claims, &validation).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::ExpiredSignature));
    }
}
