use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::Value;
use serde_json::{Map, Number};

use crate::errors;

pub fn py_to_json_for_encode(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    py_to_json(value).map_err(|err| errors::encode_error(err.to_string()))
}

pub fn py_to_json_for_decode(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    py_to_json(value).map_err(|err| errors::decode_error(err.to_string()))
}

pub fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    json_to_bound(py, value).map(|value| value.unbind())
}

const MAX_RECURSION_DEPTH: usize = 128;

pub fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    py_to_json_depth(value, 0)
}

fn py_to_json_depth(value: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(errors::invalid_token(
            "maximum recursion depth exceeded during claims serialization",
        ));
    }

    if value.is_none() {
        return Ok(Value::Null);
    }

    if let Ok(boolean) = value.cast::<PyBool>() {
        return Ok(Value::Bool(boolean.extract()?));
    }

    if let Ok(integer) = value.cast::<PyInt>() {
        if let Ok(value) = integer.extract::<i64>() {
            return Ok(Value::Number(Number::from(value)));
        }
        if let Ok(value) = integer.extract::<u64>() {
            return Ok(Value::Number(Number::from(value)));
        }
        return Err(errors::invalid_token(
            "integer value is outside JSON number range",
        ));
    }

    if let Ok(float) = value.cast::<PyFloat>() {
        let value = float.value();
        return Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| errors::invalid_token("float values must be finite JSON numbers"));
    }

    if let Ok(string) = value.cast::<PyString>() {
        return Ok(Value::String(string.to_str()?.to_owned()));
    }

    if let Ok(dict) = value.cast::<PyDict>() {
        let mut object = Map::with_capacity(dict.len());
        for (key, value) in dict.iter() {
            let key = key
                .cast::<PyString>()
                .map_err(|_| errors::invalid_token("JSON object keys must be strings"))?
                .to_str()?
                .to_owned();
            object.insert(key, py_to_json_depth(&value, depth + 1)?);
        }
        return Ok(Value::Object(object));
    }

    if let Ok(list) = value.cast::<PyList>() {
        return list
            .iter()
            .map(|item| py_to_json_depth(&item, depth + 1))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }

    if let Ok(tuple) = value.cast::<PyTuple>() {
        return tuple
            .iter()
            .map(|item| py_to_json_depth(&item, depth + 1))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }

    Err(errors::invalid_token(
        "value must be JSON-compatible: dict, list, tuple, str, int, float, bool, or None",
    ))
}

/// Standard JWT claim / header names, interned once per key rather than
/// allocated fresh on every `set_item`. `pyo3::intern!` caches each key in a
/// call-site-local static, both skipping the per-call `PyString` allocation
/// and interning the string in CPython's own intern table, so a subsequent
/// Python-side `dict.get("exp")` (a `str` literal, which CPython also
/// interns) can hit the identity-comparison fast path during dict lookup
/// instead of a full string comparison. Anything outside this list falls
/// back to an ordinary, uninterned `PyString`.
fn claim_key<'py>(py: Python<'py>, key: &str) -> Bound<'py, PyString> {
    match key {
        "exp" => pyo3::intern!(py, "exp").clone(),
        "iat" => pyo3::intern!(py, "iat").clone(),
        "nbf" => pyo3::intern!(py, "nbf").clone(),
        "sub" => pyo3::intern!(py, "sub").clone(),
        "aud" => pyo3::intern!(py, "aud").clone(),
        "iss" => pyo3::intern!(py, "iss").clone(),
        "jti" => pyo3::intern!(py, "jti").clone(),
        "alg" => pyo3::intern!(py, "alg").clone(),
        "typ" => pyo3::intern!(py, "typ").clone(),
        "kid" => pyo3::intern!(py, "kid").clone(),
        _ => PyString::new(py, key),
    }
}

fn json_to_bound<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(value) => Ok(PyBool::new(py, *value).to_owned().into_any()),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.into_pyobject(py)?.into_any())
            } else if let Some(value) = value.as_u64() {
                Ok(value.into_pyobject(py)?.into_any())
            } else if let Some(value) = value.as_f64() {
                Ok(value.into_pyobject(py)?.into_any())
            } else {
                Err(errors::decode_error("invalid JSON number"))
            }
        }
        Value::String(value) => Ok(value.into_pyobject(py)?.into_any()),
        Value::Array(values) => {
            let elements = values
                .iter()
                .map(|value| json_to_bound(py, value))
                .collect::<PyResult<Vec<_>>>()?;
            let list = PyList::new(py, elements)?;
            Ok(list.into_any())
        }
        Value::Object(values) => {
            let dict = PyDict::new(py);
            for (key, value) in values {
                dict.set_item(claim_key(py, key), json_to_bound(py, value)?)?;
            }
            Ok(dict.into_any())
        }
    }
}
