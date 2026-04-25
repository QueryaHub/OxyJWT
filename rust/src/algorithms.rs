use jsonwebtoken::Algorithm;

use crate::errors;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyFamily {
    Hmac,
    Rsa,
    Ec,
    Ed,
    Jwk,
}

pub fn parse_algorithm(name: &str) -> pyo3::PyResult<Algorithm> {
    match name {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        "none" | "None" | "NONE" => Err(errors::invalid_algorithm(
            "the 'none' algorithm is not supported",
        )),
        other => Err(errors::invalid_algorithm(format!(
            "unsupported JWT algorithm: {other}"
        ))),
    }
}

pub fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::EdDSA => "EdDSA",
    }
}

pub fn algorithm_family(algorithm: Algorithm) -> KeyFamily {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => KeyFamily::Hmac,
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => KeyFamily::Rsa,
        Algorithm::ES256 | Algorithm::ES384 => KeyFamily::Ec,
        Algorithm::EdDSA => KeyFamily::Ed,
    }
}

pub fn ensure_algorithm_family(algorithm: Algorithm, family: KeyFamily) -> pyo3::PyResult<()> {
    if family == KeyFamily::Jwk || algorithm_family(algorithm) == family {
        return Ok(());
    }

    Err(errors::invalid_algorithm(format!(
        "algorithm {} cannot be used with a {:?} key",
        algorithm_name(algorithm),
        family
    )))
}

pub fn ensure_single_family(algorithms: &[Algorithm]) -> pyo3::PyResult<KeyFamily> {
    let Some(first) = algorithms.first().copied() else {
        return Err(errors::invalid_algorithm(
            "decode requires at least one allowed algorithm",
        ));
    };

    let family = algorithm_family(first);
    if algorithms
        .iter()
        .copied()
        .all(|algorithm| algorithm_family(algorithm) == family)
    {
        Ok(family)
    } else {
        Err(errors::invalid_algorithm(
            "allowed algorithms must belong to the same key family",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_none_algorithm() {
        assert!(parse_algorithm("none").is_err());
    }

    #[test]
    fn groups_ps_with_rsa() {
        assert_eq!(algorithm_family(Algorithm::PS256), KeyFamily::Rsa);
    }
}
