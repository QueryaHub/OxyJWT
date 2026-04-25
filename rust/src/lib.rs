mod algorithms;
mod api;
mod claims;
mod errors;
mod keys;
mod validation;

use pyo3::prelude::*;

#[pymodule]
fn _oxyjwt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::register(m)?;

    m.add_class::<keys::EncodingKey>()?;
    m.add_class::<keys::DecodingKey>()?;

    m.add_function(wrap_pyfunction!(api::encode, m)?)?;
    m.add_function(wrap_pyfunction!(api::decode, m)?)?;
    m.add_function(wrap_pyfunction!(api::get_unverified_header, m)?)?;
    m.add_function(wrap_pyfunction!(api::decode_unverified, m)?)?;

    Ok(())
}
