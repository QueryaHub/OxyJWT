use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

use crate::errors;

pub fn py_to_json_for_encode(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    py_to_json(value).map_err(|err| errors::encode_error(err.to_string()))
}

pub fn py_to_json_for_decode(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    py_to_json(value).map_err(|err| errors::decode_error(err.to_string()))
}

pub fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json = py.import("json")?;
    let raw = serde_json::to_string(value)
        .map_err(|err| errors::decode_error(format!("failed to serialize claims: {err}")))?;
    Ok(json.call_method1("loads", (raw,))?.unbind())
}

fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    let py = value.py();
    let json = py.import("json")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("allow_nan", false)?;
    kwargs.set_item("separators", (",", ":"))?;

    let raw: String = json
        .call_method("dumps", (value,), Some(&kwargs))?
        .extract()?;

    serde_json::from_str(&raw).map_err(|err| {
        errors::invalid_token(format!("failed to convert Python value to JSON: {err}"))
    })
}
