use jsonwebtoken::{Algorithm, Validation};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};

use crate::algorithms::parse_algorithm;
use crate::errors;

pub struct DecodeValidation {
    pub validation: Validation,
}

impl DecodeValidation {
    /// Algorithms the caller allows, in the order they were supplied.
    pub fn algorithms(&self) -> &[Algorithm] {
        &self.validation.algorithms
    }
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

    // One cast of the options mapping instead of one per key.
    let opts = decode_options(options)?;

    let mut validation = Validation::new(parsed_algorithms[0]);
    validation.algorithms = parsed_algorithms;
    validation.leeway = leeway_as_u64(leeway);
    validation.validate_exp = opts.flag("verify_exp", true)?;
    validation.validate_nbf = opts.flag("verify_nbf", true)?;

    // `Validation::new` pre-seeds `exp`; keep it only if the caller asked for it.
    if !opts.flag("require_exp", false)? {
        validation.required_spec_claims.clear();
    }

    if let Some(claims) = require {
        validation.required_spec_claims.extend(claims);
    }
    if let Some(claims) = opts.require()? {
        validation.required_spec_claims.extend(claims);
    }

    let verify_aud = opts.flag("verify_aud", true)?;
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

    if opts.flag("verify_iss", true)? {
        if let Some(values) = issuer.map(string_or_list).transpose()? {
            if !values.is_empty() {
                validation.set_issuer(&values);
            }
        }
    }

    if opts.flag("verify_sub", true)? {
        validation.sub = subject;
    }

    Ok(DecodeValidation { validation })
}

/// The decode `options` mapping, cast once and then queried by key.
struct DecodeOptions<'py>(Option<Bound<'py, PyDict>>);

fn decode_options<'py>(options: Option<&Bound<'py, PyAny>>) -> PyResult<DecodeOptions<'py>> {
    let Some(options) = options.filter(|value| !value.is_none()) else {
        return Ok(DecodeOptions(None));
    };
    let dict = options
        .cast::<PyDict>()
        .map_err(|_| errors::decode_error("options must be a dict"))?;
    Ok(DecodeOptions(Some(dict.clone())))
}

impl DecodeOptions<'_> {
    fn flag(&self, key: &str, default: bool) -> PyResult<bool> {
        let Some(dict) = self.0.as_ref() else {
            return Ok(default);
        };
        match dict.get_item(key)? {
            Some(value) => value
                .extract::<bool>()
                .map_err(|_| errors::decode_error(format!("options['{key}'] must be a bool"))),
            None => Ok(default),
        }
    }

    fn require(&self) -> PyResult<Option<Vec<String>>> {
        let Some(dict) = self.0.as_ref() else {
            return Ok(None);
        };
        match dict.get_item("require")? {
            Some(value) if !value.is_none() => value
                .extract()
                .map(Some)
                .map_err(|_| errors::decode_error("options['require'] must be a list of strings")),
            _ => Ok(None),
        }
    }
}

/// Map Python `leeway` (float seconds) to jsonwebtoken's whole-second `leeway`.
pub fn leeway_as_u64(leeway: f64) -> u64 {
    if leeway <= 0.0 {
        0
    } else if leeway >= u64::MAX as f64 {
        u64::MAX
    } else {
        leeway.round() as u64
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

    #[test]
    fn leeway_rounds_to_nearest_second() {
        assert_eq!(leeway_as_u64(0.0), 0);
        assert_eq!(leeway_as_u64(0.4), 0);
        assert_eq!(leeway_as_u64(0.9), 1);
        assert_eq!(leeway_as_u64(1.5), 2);
    }
}
