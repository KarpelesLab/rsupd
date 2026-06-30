//! Producer-side upload of a built package to the KLB REST API.
//!
//! [`crate::package::build_package`] turns a project's binaries into a signed
//! zip; this module hands that zip to the platform's upload endpoint
//! ([`UPLOAD_ENDPOINT`]) using the [`klbfw`] client, which negotiates and drives
//! the actual transfer (direct PUT, multipart, or S3) transparently.

use std::collections::HashMap;
use std::io::Cursor;

use klbfw::{RestContext, RestError};
use serde_json::Value;

use crate::error::{Error, Result};

/// Renders a klbfw error with the platform's request id attached when present,
/// so a server-side failure can be traced in the platform logs. The response
/// token is intentionally omitted — it is a sensitive value and `run_publish`
/// prints this string to stderr (captured in CI logs).
fn rest_detail(e: &RestError) -> String {
    if let RestError::Api {
        message,
        code,
        request_id,
        response: _,
    } = e
    {
        let mut s = message.clone();
        if let Some(c) = code {
            s.push_str(&format!(" (code {c})"));
        }
        if let Some(rid) = request_id {
            s.push_str(&format!(" [X-Request-Id: {rid}]"));
        }
        s
    } else {
        e.to_string()
    }
}

/// The REST endpoint that negotiates a release upload.
pub const UPLOAD_ENDPOINT: &str = "Cloud/Rust:upload";

/// Uploads a built package zip to [`UPLOAD_ENDPOINT`], returning the endpoint's
/// response data (file metadata such as `Blob__` / `SHA256` / `Size`).
///
/// `filename` is the name advertised to the negotiation endpoint; `bytes` is the
/// complete package zip ([`crate::package::BuiltPackage::bytes`]). When `verbose`
/// is set, klbfw traces each REST request (method, path, status) to stderr.
pub fn upload_package(filename: &str, bytes: Vec<u8>, verbose: bool) -> Result<Value> {
    let ctx = RestContext::new().with_debug(verbose);

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
    .map_err(|e| {
        Error::Other(format!(
            "upload to {UPLOAD_ENDPOINT} failed: {}",
            rest_detail(&e)
        ))
    })?;

    response
        .apply::<Value>()
        .map_err(|e| Error::Other(format!("decoding upload response: {e}")))
}
