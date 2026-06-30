//! Producer-side upload of a built package to the KLB REST API.
//!
//! [`crate::package::build_package`] turns a project's binaries into a signed
//! zip; this module hands that zip to the platform's upload endpoint
//! ([`UPLOAD_ENDPOINT`]) using the [`klbfw`] client, which negotiates and drives
//! the actual transfer (direct PUT, multipart, or S3) transparently.
//!
//! Authentication is an API key sourced from the environment; see
//! [`ApiConfig::from_env`].

use std::collections::HashMap;
use std::io::Cursor;

use klbfw::{ApiKey, Config, RestContext};
use serde_json::Value;

use crate::error::{Error, Result};

/// The REST endpoint that negotiates a release upload.
pub const UPLOAD_ENDPOINT: &str = "Cloud/Rest:upload";

/// API credentials and target host for talking to the KLB REST API.
pub struct ApiConfig {
    /// API key identifier.
    pub key_id: String,
    /// Base64-encoded Ed25519 secret for the key.
    pub secret: String,
    /// API host override (`None` uses the klbfw default host).
    pub host: Option<String>,
}

impl ApiConfig {
    /// Loads API config from the environment: `RSUPD_API_KEY` (key id),
    /// `RSUPD_API_SECRET` (base64 secret), and optional `RSUPD_API_HOST`.
    pub fn from_env() -> Result<Self> {
        let key_id = std::env::var("RSUPD_API_KEY")
            .map_err(|_| Error::Other("RSUPD_API_KEY is not set".into()))?;
        let secret = std::env::var("RSUPD_API_SECRET")
            .map_err(|_| Error::Other("RSUPD_API_SECRET is not set".into()))?;
        let host = std::env::var("RSUPD_API_HOST").ok().filter(|h| !h.is_empty());
        Ok(ApiConfig {
            key_id,
            secret,
            host,
        })
    }

    /// Builds an authenticated [`RestContext`] from this config.
    fn context(&self) -> Result<RestContext> {
        let api_key = ApiKey::new(self.key_id.clone(), &self.secret)
            .map_err(|e| Error::Other(format!("invalid API key: {e}")))?;
        let ctx = match &self.host {
            Some(host) => RestContext::with_config(Config::new("https".into(), host.clone())),
            None => RestContext::new(),
        };
        Ok(ctx.with_api_key(api_key))
    }

    /// The API host this config targets, for display.
    pub fn host_label(&self) -> &str {
        self.host.as_deref().unwrap_or("(klbfw default host)")
    }
}

/// Uploads a built package zip to [`UPLOAD_ENDPOINT`], returning the endpoint's
/// response data (file metadata such as `Blob__` / `SHA256` / `Size`).
///
/// `filename` is the name advertised to the negotiation endpoint; `bytes` is the
/// complete package zip ([`crate::package::BuiltPackage::bytes`]).
pub fn upload_package(cfg: &ApiConfig, filename: &str, bytes: Vec<u8>) -> Result<Value> {
    let ctx = cfg.context()?;

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
