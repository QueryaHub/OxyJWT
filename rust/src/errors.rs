use jsonwebtoken::errors::Error;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(_oxyjwt, OxyJWTError, PyException);
create_exception!(_oxyjwt, EncodeError, OxyJWTError);
create_exception!(_oxyjwt, DecodeError, OxyJWTError);
create_exception!(_oxyjwt, InvalidTokenError, DecodeError);
create_exception!(_oxyjwt, InvalidSignatureError, InvalidTokenError);
create_exception!(_oxyjwt, ExpiredSignatureError, InvalidTokenError);
create_exception!(_oxyjwt, ImmatureSignatureError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidAudienceError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidIssuerError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidSubjectError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidAlgorithmError, InvalidTokenError);
create_exception!(_oxyjwt, MissingRequiredClaimError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidKeyError, OxyJWTError);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    m.add("OxyJWTError", py.get_type::<OxyJWTError>())?;
    m.add("EncodeError", py.get_type::<EncodeError>())?;
    m.add("DecodeError", py.get_type::<DecodeError>())?;
    m.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
    m.add(
        "InvalidSignatureError",
        py.get_type::<InvalidSignatureError>(),
    )?;
    m.add(
        "ExpiredSignatureError",
        py.get_type::<ExpiredSignatureError>(),
    )?;
    m.add(
        "ImmatureSignatureError",
        py.get_type::<ImmatureSignatureError>(),
    )?;
    m.add(
        "InvalidAudienceError",
        py.get_type::<InvalidAudienceError>(),
    )?;
    m.add("InvalidIssuerError", py.get_type::<InvalidIssuerError>())?;
    m.add("InvalidSubjectError", py.get_type::<InvalidSubjectError>())?;
    m.add(
        "InvalidAlgorithmError",
        py.get_type::<InvalidAlgorithmError>(),
    )?;
    m.add(
        "MissingRequiredClaimError",
        py.get_type::<MissingRequiredClaimError>(),
    )?;
    m.add("InvalidKeyError", py.get_type::<InvalidKeyError>())?;

    Ok(())
}

pub fn encode_error(message: impl Into<String>) -> PyErr {
    EncodeError::new_err(message.into())
}

pub fn decode_error(message: impl Into<String>) -> PyErr {
    DecodeError::new_err(message.into())
}

pub fn invalid_token(message: impl Into<String>) -> PyErr {
    InvalidTokenError::new_err(message.into())
}

pub fn invalid_key(message: impl Into<String>) -> PyErr {
    InvalidKeyError::new_err(message.into())
}

pub fn invalid_algorithm(message: impl Into<String>) -> PyErr {
    InvalidAlgorithmError::new_err(message.into())
}

pub fn from_jwt_decode_error(err: Error) -> PyErr {
    let kind = format!("{:?}", err.kind());
    let message = err.to_string();

    if kind.starts_with("ExpiredSignature") {
        ExpiredSignatureError::new_err(message)
    } else if kind.starts_with("ImmatureSignature") {
        ImmatureSignatureError::new_err(message)
    } else if kind.starts_with("InvalidSignature") {
        InvalidSignatureError::new_err(message)
    } else if kind.starts_with("InvalidAudience") {
        InvalidAudienceError::new_err(message)
    } else if kind.starts_with("InvalidIssuer") {
        InvalidIssuerError::new_err(message)
    } else if kind.starts_with("InvalidSubject") {
        InvalidSubjectError::new_err(message)
    } else if kind.starts_with("MissingRequiredClaim") {
        MissingRequiredClaimError::new_err(message)
    } else if kind.starts_with("InvalidAlgorithm")
        || kind.starts_with("InvalidAlgorithmName")
        || kind.starts_with("MissingAlgorithm")
    {
        InvalidAlgorithmError::new_err(message)
    } else if kind.contains("Key") || kind.contains("Pem") || kind.contains("Rsa") {
        InvalidKeyError::new_err(message)
    } else {
        InvalidTokenError::new_err(message)
    }
}

pub fn from_jwt_encode_error(err: Error) -> PyErr {
    let kind = format!("{:?}", err.kind());
    let message = err.to_string();

    if kind.contains("Key") || kind.contains("Pem") || kind.contains("Rsa") {
        InvalidKeyError::new_err(message)
    } else if kind.starts_with("InvalidAlgorithm") || kind.starts_with("InvalidAlgorithmName") {
        InvalidAlgorithmError::new_err(message)
    } else {
        EncodeError::new_err(message)
    }
}
