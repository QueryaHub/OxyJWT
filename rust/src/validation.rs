use jsonwebtoken::{Algorithm, Validation};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};

use crate::algorithms::parse_algorithm;
use crate::errors;

pub struct DecodeValidation {
    pub algorithms: Vec<Algorithm>,
    pub validation: Validation,
}

#[allow(clippy::too_many_arguments)]
pub fn build_validation(
    algorithms: Vec<String>,
    audience: Option<&Bound<'_, PyAny>>,
    issuer: Option<&Bound<'_, PyAny>>,
    subject: Option<String>,
    leeway: f64,
    options: Option<&Bound<'_, PyAny>>,
    require: Option<Vec<String>>,
) -> PyResult<DecodeValidation> {
    if algorithms.is_empty() {
        return Err(errors::invalid_algorithm(
            "decode requires at least one allowed algorithm",
        ));
    }

    let parsed_algorithms = algorithms
        .iter()
        .map(|algorithm| parse_algorithm(algorithm))
        .collect::<PyResult<Vec<_>>>()?;

    let mut validation = Validation::new(parsed_algorithms[0]);
    validation.algorithms = parsed_algorithms.clone();
    let leeway_u64 = if leeway <= 0.0 {
        0u64
    } else if leeway >= u64::MAX as f64 {
        u64::MAX
    } else {
        leeway as u64
    };
    validation.leeway = leeway_u64;
    validation.validate_exp = option_bool(options, "verify_exp", true)?;
    validation.validate_nbf = option_bool(options, "verify_nbf", true)?;

    if option_bool(options, "require_exp", false)? {
        validation.required_spec_claims.insert("exp".to_owned());
    }

    let mut merged_require = require.unwrap_or_default();
    if let Some(opts) = options {
        if !opts.is_none() {
            if let Ok(dict) = opts.cast::<PyDict>() {
                if let Ok(Some(req)) = dict.get_item("require") {
                    let more: Vec<String> = req.extract().map_err(|_| {
                        errors::decode_error("options['require'] must be a list of strings")
                    })?;
                    merged_require.extend(more);
                }
            }
        }
    }
    for claim in merged_require {
        validation.required_spec_claims.insert(claim);
    }

    let verify_aud = option_bool(options, "verify_aud", true)?;
    if let Some(values) = audience.map(string_or_list).transpose()? {
        if verify_aud {
            validation.validate_aud = true;
            validation.set_audience(&values);
        } else {
            validation.validate_aud = false;
        }
    } else {
        validation.validate_aud = false;
    }

    let verify_iss = option_bool(options, "verify_iss", true)?;
    if verify_iss {
        if let Some(values) = issuer.map(string_or_list).transpose()? {
            if !values.is_empty() {
                validation.set_issuer(&values);
            }
        }
    }

    validation.sub = subject;

    Ok(DecodeValidation {
        algorithms: parsed_algorithms,
        validation,
    })
}

fn option_bool(options: Option<&Bound<'_, PyAny>>, key: &str, default: bool) -> PyResult<bool> {
    let Some(options) = options else {
        return Ok(default);
    };

    if options.is_none() {
        return Ok(default);
    }

    let dict = options
        .cast::<PyDict>()
        .map_err(|_| errors::decode_error("options must be a dict"))?;

    match dict.get_item(key)? {
        Some(value) => value
            .extract::<bool>()
            .map_err(|_| errors::decode_error(format!("options['{key}'] must be a bool"))),
        None => Ok(default),
    }
}

fn string_or_list(value: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    if value.is_none() {
        return Ok(Vec::new());
    }

    if value.cast::<PyString>().is_ok() {
        return Ok(vec![value.extract::<String>()?]);
    }

    if let Ok(list) = value.cast::<PyList>() {
        return list
            .iter()
            .map(|item| item.extract::<String>())
            .collect::<PyResult<Vec<_>>>();
    }

    if let Ok(tuple) = value.cast::<PyTuple>() {
        return tuple
            .iter()
            .map(|item| item.extract::<String>())
            .collect::<PyResult<Vec<_>>>();
    }

    Err(errors::decode_error(
        "expected str, list[str], or tuple[str, ...]",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_algorithms() {
        assert!(build_validation(vec![], None, None, None, 0.0, None, None).is_err());
    }

    #[test]
    fn rejects_none_algorithm() {
        assert!(
            build_validation(vec!["none".to_owned()], None, None, None, 0.0, None, None).is_err()
        );
    }
}
