use std::collections::HashSet;

use jsonwebtoken::errors::{new_error, ErrorKind};
use jsonwebtoken::get_current_timestamp;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList, PyString};

use crate::errors;
use crate::validation::DecodeValidation;

/// Spec claims that `required_spec_claims` can hold, in a fixed order.
///
/// `Validation::required_spec_claims` is a `HashSet`, so iterating it directly
/// makes the reported missing claim depend on hash seeding and therefore differ
/// between processes. Walking a constant list instead keeps the error stable and
/// skips the set iteration when nothing is required.
const REQUIRABLE_SPEC_CLAIMS: [&str; 6] = ["aud", "exp", "iat", "iss", "nbf", "sub"];

enum NumericClaim {
    Missing,
    Invalid,
    Value(u64),
}

fn parse_numeric_claim_py(value: Option<Bound<'_, PyAny>>) -> NumericClaim {
    let Some(value) = value else {
        return NumericClaim::Missing;
    };
    if value.is_none() {
        return NumericClaim::Invalid;
    }
    if value.is_instance_of::<PyBool>() {
        return NumericClaim::Invalid;
    }
    if let Ok(u) = value.extract::<u64>() {
        NumericClaim::Value(u)
    } else if let Ok(i) = value.extract::<i64>() {
        if i >= 0 {
            NumericClaim::Value(i as u64)
        } else {
            NumericClaim::Invalid
        }
    } else if let Ok(f) = value.extract::<f64>() {
        if f.is_finite() && f >= 0.0 && f < u64::MAX as f64 {
            NumericClaim::Value(f as u64)
        } else {
            NumericClaim::Invalid
        }
    } else {
        NumericClaim::Invalid
    }
}

fn audience_matches_py(claim: &Bound<'_, PyAny>, expected: &HashSet<String>) -> bool {
    if claim.is_instance_of::<PyString>() {
        if let Ok(s) = claim.extract::<&str>() {
            return !s.is_empty() && expected.contains(s);
        }
    } else if let Ok(items) = claim.cast::<PyList>() {
        if items.is_empty() {
            return false;
        }
        let mut any_match = false;
        for item in items.iter() {
            if item.is_instance_of::<PyString>() {
                if let Ok(s) = item.extract::<&str>() {
                    if !s.is_empty() && expected.contains(s) {
                        any_match = true;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        return any_match;
    }
    false
}

fn issuer_matches_py(claim: &Bound<'_, PyAny>, expected: &HashSet<String>) -> bool {
    if claim.is_instance_of::<PyString>() {
        if let Ok(s) = claim.extract::<&str>() {
            return expected.contains(s);
        }
    } else if let Ok(items) = claim.cast::<PyList>() {
        for item in items.iter() {
            if item.is_instance_of::<PyString>() {
                if let Ok(s) = item.extract::<&str>() {
                    if expected.contains(s) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Validate standard claims directly on a PyDict claims object.
pub fn validate_claims_dict(
    claims: &Bound<'_, PyDict>,
    decode_val: &DecodeValidation,
) -> PyResult<()> {
    let options = &decode_val.validation;
    if !options.required_spec_claims.is_empty() {
        for required in REQUIRABLE_SPEC_CLAIMS {
            if !options.required_spec_claims.contains(required) {
                continue;
            }
            let is_present = match claims.get_item(required) {
                Ok(Some(value)) => !value.is_none(),
                _ => false,
            };
            if !is_present {
                return Err(errors::from_jwt_decode_error(new_error(
                    ErrorKind::MissingRequiredClaim(required.to_owned()),
                )));
            }
        }
    }

    let now = get_current_timestamp();

    if options.validate_exp || options.validate_nbf || decode_val.validate_iat {
        let exp_claim = parse_numeric_claim_py(claims.get_item("exp").ok().flatten());
        let nbf_claim = parse_numeric_claim_py(claims.get_item("nbf").ok().flatten());
        let iat_claim = parse_numeric_claim_py(claims.get_item("iat").ok().flatten());

        if options.validate_exp && matches!(exp_claim, NumericClaim::Invalid) {
            return Err(errors::decode_error(
                "Expiration Time claim (exp) must be an integer.",
            ));
        }
        if options.validate_nbf && matches!(nbf_claim, NumericClaim::Invalid) {
            return Err(errors::decode_error(
                "Not Before claim (nbf) must be an integer.",
            ));
        }
        if decode_val.validate_iat && matches!(iat_claim, NumericClaim::Invalid) {
            return Err(errors::InvalidIssuedAtError::new_err(
                "Issued At claim (iat) must be an integer.",
            ));
        }

        if let NumericClaim::Value(exp) = exp_claim {
            if exp < options.reject_tokens_expiring_in_less_than {
                return Err(errors::invalid_token("Invalid token"));
            }
            if options.validate_exp
                && exp.saturating_sub(options.reject_tokens_expiring_in_less_than)
                    <= now.saturating_sub(options.leeway)
            {
                return Err(errors::ExpiredSignatureError::new_err(
                    "Signature has expired",
                ));
            }
        }

        if let NumericClaim::Value(nbf) = nbf_claim {
            if options.validate_nbf && nbf > now.saturating_add(options.leeway) {
                return Err(errors::ImmatureSignatureError::new_err(
                    "The token is not yet valid (nbf)",
                ));
            }
        }

        if let NumericClaim::Value(iat) = iat_claim {
            if decode_val.validate_iat && iat > now.saturating_add(options.leeway) {
                return Err(errors::ImmatureSignatureError::new_err(
                    "The token is not yet valid (iat)",
                ));
            }
        }
    }

    if decode_val.validate_sub {
        match claims.get_item("sub") {
            Ok(Some(val)) => {
                if !val.is_none() {
                    if val.is_instance_of::<PyString>() {
                        let sub = val
                            .extract::<&str>()
                            .map_err(|_| errors::InvalidSubjectError::new_err("Invalid subject"))?;
                        if let Some(expected_sub) = options.sub.as_deref() {
                            if sub != expected_sub {
                                return Err(errors::InvalidSubjectError::new_err(
                                    "Invalid subject",
                                ));
                            }
                        }
                    } else {
                        return Err(errors::InvalidSubjectError::new_err(
                            "Subject must be a string",
                        ));
                    }
                }
            }
            Ok(None) => (),
            Err(_) => return Err(errors::InvalidSubjectError::new_err("Invalid subject")),
        }
    }

    if let Some(expected_iss) = options.iss.as_ref() {
        match claims.get_item("iss") {
            Ok(None) => return Err(errors::InvalidIssuerError::new_err("Invalid issuer")),
            Ok(Some(val)) if val.is_none() => {
                return Err(errors::InvalidIssuerError::new_err("Invalid issuer"))
            }
            Ok(Some(val)) => {
                if !issuer_matches_py(&val, expected_iss) {
                    return Err(errors::InvalidIssuerError::new_err("Invalid issuer"));
                }
            }
            Err(_) => return Err(errors::InvalidIssuerError::new_err("Invalid issuer")),
        }
    }

    if options.validate_aud {
        let aud_claim = claims.get_item("aud").ok().flatten();
        match (aud_claim, options.aud.as_ref()) {
            (Some(_), None) => {
                return Err(errors::InvalidAudienceError::new_err("Invalid audience"))
            }
            (None, Some(_)) => {
                return Err(errors::from_jwt_decode_error(new_error(
                    ErrorKind::MissingRequiredClaim("aud".to_string()),
                )));
            }
            (Some(val), Some(_)) if val.is_none() => {
                return Err(errors::from_jwt_decode_error(new_error(
                    ErrorKind::MissingRequiredClaim("aud".to_string()),
                )));
            }
            (Some(val), Some(_))
                if val.is_instance_of::<PyString>()
                    && val.extract::<&str>().is_ok_and(|s| s.is_empty()) =>
            {
                return Err(errors::from_jwt_decode_error(new_error(
                    ErrorKind::MissingRequiredClaim("aud".to_string()),
                )));
            }
            (Some(val), Some(_))
                if val.is_instance_of::<PyList>()
                    && val.cast::<PyList>().is_ok_and(|l| l.is_empty()) =>
            {
                return Err(errors::from_jwt_decode_error(new_error(
                    ErrorKind::MissingRequiredClaim("aud".to_string()),
                )));
            }
            (Some(val), Some(expected)) => {
                if !audience_matches_py(&val, expected) {
                    return Err(errors::InvalidAudienceError::new_err("Invalid audience"));
                }
            }
            (None, None) => (),
        }
    }

    Ok(())
}
