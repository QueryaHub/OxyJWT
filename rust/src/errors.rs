use jsonwebtoken::errors::Error;
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// Mirrors PyJWT: InvalidTokenError -> DecodeError -> InvalidSignatureError
create_exception!(_oxyjwt, OxyJWTError, PyException);
create_exception!(_oxyjwt, InvalidTokenError, OxyJWTError);
create_exception!(_oxyjwt, DecodeError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidSignatureError, DecodeError);
create_exception!(_oxyjwt, ExpiredSignatureError, InvalidTokenError);
create_exception!(_oxyjwt, ImmatureSignatureError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidAudienceError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidIssuerError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidIssuedAtError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidSubjectError, InvalidTokenError);
create_exception!(_oxyjwt, InvalidAlgorithmError, InvalidTokenError);
create_exception!(_oxyjwt, MissingRequiredClaimError, InvalidTokenError);
create_exception!(_oxyjwt, EncodeError, OxyJWTError);
create_exception!(_oxyjwt, InvalidKeyError, OxyJWTError);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();

    m.add("OxyJWTError", py.get_type::<OxyJWTError>())?;
    m.add("InvalidTokenError", py.get_type::<InvalidTokenError>())?;
    m.add("DecodeError", py.get_type::<DecodeError>())?;
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
    m.add(
        "InvalidIssuedAtError",
        py.get_type::<InvalidIssuedAtError>(),
    )?;
    m.add("InvalidSubjectError", py.get_type::<InvalidSubjectError>())?;
    m.add(
        "InvalidAlgorithmError",
        py.get_type::<InvalidAlgorithmError>(),
    )?;
    m.add(
        "MissingRequiredClaimError",
        py.get_type::<MissingRequiredClaimError>(),
    )?;
    m.add("EncodeError", py.get_type::<EncodeError>())?;
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
    use jsonwebtoken::errors::ErrorKind;
    let kind = err.kind();
    let message = err.to_string();

    match kind {
        ErrorKind::ExpiredSignature => ExpiredSignatureError::new_err(message),
        ErrorKind::ImmatureSignature => ImmatureSignatureError::new_err(message),
        ErrorKind::InvalidSignature => InvalidSignatureError::new_err(message),
        ErrorKind::InvalidAudience => InvalidAudienceError::new_err(message),
        ErrorKind::InvalidIssuer => InvalidIssuerError::new_err(message),
        ErrorKind::InvalidSubject => InvalidSubjectError::new_err(message),
        ErrorKind::MissingRequiredClaim(_) => MissingRequiredClaimError::new_err(message),
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::MissingAlgorithm => InvalidAlgorithmError::new_err(message),
        ErrorKind::Json(_)
        | ErrorKind::Utf8(_)
        | ErrorKind::Base64(_)
        | ErrorKind::InvalidClaimFormat(_) => DecodeError::new_err(message),
        ErrorKind::InvalidToken => InvalidTokenError::new_err(message),
        ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidEddsaKey
        | ErrorKind::InvalidKeyFormat
        | ErrorKind::InvalidRsaKey(_) => InvalidKeyError::new_err(message),
        _ => InvalidTokenError::new_err(message),
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
