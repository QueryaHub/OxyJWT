use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use serde_json::{Map, Number};
use std::borrow::Cow;

use crate::errors;

pub fn py_to_json_for_encode(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    py_to_json(value).map_err(|err| errors::encode_error(err.to_string()))
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
        "name" => pyo3::intern!(py, "name").clone(),
        "email" => pyo3::intern!(py, "email").clone(),
        "scope" => pyo3::intern!(py, "scope").clone(),
        "scopes" => pyo3::intern!(py, "scopes").clone(),
        "roles" => pyo3::intern!(py, "roles").clone(),
        "permissions" => pyo3::intern!(py, "permissions").clone(),
        "client_id" => pyo3::intern!(py, "client_id").clone(),
        "azp" => pyo3::intern!(py, "azp").clone(),
        "nonce" => pyo3::intern!(py, "nonce").clone(),
        "auth_time" => pyo3::intern!(py, "auth_time").clone(),
        "user_id" => pyo3::intern!(py, "user_id").clone(),
        "metadata" => pyo3::intern!(py, "metadata").clone(),
        "data" => pyo3::intern!(py, "data").clone(),
        "id" => pyo3::intern!(py, "id").clone(),
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

struct PyAnySeed<'py> {
    py: Python<'py>,
}

impl<'de, 'py> DeserializeSeed<'de> for PyAnySeed<'py> {
    type Value = Bound<'py, PyAny>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PyAnyVisitor { py: self.py })
    }
}

struct PyAnyVisitor<'py> {
    py: Python<'py>,
}

impl<'de, 'py> Visitor<'de> for PyAnyVisitor<'py> {
    type Value = Bound<'py, PyAny>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    #[inline]
    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(PyBool::new(self.py, v).to_owned().into_any())
    }

    #[inline]
    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.into_pyobject(self.py)
            .map(|obj| obj.into_any())
            .map_err(de::Error::custom)
    }

    #[inline]
    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.into_pyobject(self.py)
            .map(|obj| obj.into_any())
            .map_err(de::Error::custom)
    }

    #[inline]
    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.into_pyobject(self.py)
            .map(|obj| obj.into_any())
            .map_err(de::Error::custom)
    }

    #[inline]
    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.into_pyobject(self.py)
            .map(|obj| obj.into_any())
            .map_err(de::Error::custom)
    }

    #[inline]
    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        PyFloat::new(self.py, v)
            .into_pyobject(self.py)
            .map(|obj| obj.into_any())
            .map_err(de::Error::custom)
    }

    #[inline]
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(PyString::new(self.py, v).into_any())
    }

    #[inline]
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(PyString::new(self.py, v).into_any())
    }

    #[inline]
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(self.py.None().into_bound(self.py))
    }

    #[inline]
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(self.py.None().into_bound(self.py))
    }

    #[inline]
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut elements = match seq.size_hint() {
            Some(len) => Vec::with_capacity(len),
            None => Vec::new(),
        };
        while let Some(elem) = seq.next_element_seed(PyAnySeed { py: self.py })? {
            elements.push(elem);
        }
        PyList::new(self.py, elements)
            .map(|list| list.into_any())
            .map_err(de::Error::custom)
    }

    #[inline]
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let dict = PyDict::new(self.py);
        while let Some(key) = map.next_key::<Cow<'_, str>>()? {
            let py_key = claim_key(self.py, &key);
            let val = map.next_value_seed(PyAnySeed { py: self.py })?;
            dict.set_item(py_key, val).map_err(de::Error::custom)?;
        }
        Ok(dict.into_any())
    }
}

pub fn deserialize_claims_dict<'py>(
    py: Python<'py>,
    bytes: &[u8],
) -> Result<Bound<'py, PyDict>, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let obj = de
        .deserialize_any(PyAnyVisitor { py })
        .map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    obj.cast_into::<PyDict>()
        .map_err(|_| "Invalid payload string: must be a json object".to_string())
}
