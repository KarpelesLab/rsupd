//! Producer-side upload of a built package to the KLB REST API.
//!
//! [`crate::package::build_package`] turns a project's binaries into a signed
//! zip; this module hands that zip to the platform's upload endpoint
//! ([`UPLOAD_ENDPOINT`]) using the [`klbfw`] client, which negotiates and drives
//! the actual transfer (direct PUT, multipart, or S3) transparently.

use std::collections::HashMap;
use std::io::Cursor;

use klbfw::RestContext;
use serde_json::Value;

use crate::error::{Error, Result};

/// The REST endpoint that negotiates a release upload.
pub const UPLOAD_ENDPOINT: &str = "Cloud/Rust:upload";

/// Uploads a built package zip to [`UPLOAD_ENDPOINT`], returning the endpoint's
/// response data (file metadata such as `Blob__` / `SHA256` / `Size`).
///
/// `filename` is the name advertised to the negotiation endpoint; `bytes` is the
/// complete package zip ([`crate::package::BuiltPackage::bytes`]).
pub fn upload_package(filename: &str, bytes: Vec<u8>) -> Result<Value> {
    let ctx = RestContext::new();

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("filename".into(), Value::String(filename.to_string()));

    let response = klbfw::upload(
        &ctx,
        UPLOAD_ENDPOINT,
        "POST",
        params,
        Cursor::new(bytes),
        "application/zip",
        None,
    )
    .map_err(|e| Error::Other(format!("upload to {UPLOAD_ENDPOINT} failed: {e}")))?;

    response
        .apply::<Value>()
        .map_err(|e| Error::Other(format!("decoding upload response: {e}")))
}
