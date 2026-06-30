//! The [`Transport`] abstraction over wherever releases are hosted.
//!
//! [`HttpTransport`] fetches releases from the `dist-go` distribution host (the
//! same backing store the producer's `Cloud/Rust:upload` writes to), while
//! [`ZipPackageTransport`] serves a package produced by
//! [`crate::package::build_package`] straight from disk, so the whole
//! check → download → verify → install path can also run offline.

use std::path::Path;

use crate::error::{Error, Result};
use crate::manifest::Artifact;
use crate::package::{MANIFEST_ENTRY, zip::ZipReader};

/// Source of update metadata and artifacts for a project/channel.
///
/// Implementations must be cheap to share across threads (the background updater
/// holds one). They return raw bytes; all verification happens in the updater.
pub trait Transport: Send + Sync {
    /// Fetches the signed manifest bottle for `project` on `channel`.
    fn latest_manifest(&self, project: &str, channel: &str) -> Result<Vec<u8>>;

    /// Fetches the stored (compressed) bytes of `artifact`, which belongs to the
    /// given release `version` of `project` on `channel`.
    fn fetch_artifact(
        &self,
        project: &str,
        channel: &str,
        version: &str,
        artifact: &Artifact,
    ) -> Result<Vec<u8>>;
}

/// A [`Transport`] backed by a single on-disk package zip. Useful for testing and
/// for sideloading a release without a server.
pub struct ZipPackageTransport {
    bytes: Vec<u8>,
}

impl ZipPackageTransport {
    /// Loads a package zip from `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path.as_ref())?;
        Ok(ZipPackageTransport { bytes })
    }

    /// Wraps already-loaded package bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        ZipPackageTransport { bytes }
    }
}

impl Transport for ZipPackageTransport {
    fn latest_manifest(&self, _project: &str, _channel: &str) -> Result<Vec<u8>> {
        ZipReader::new(&self.bytes)?.read(MANIFEST_ENTRY)
    }

    fn fetch_artifact(
        &self,
        _project: &str,
        _channel: &str,
        _version: &str,
        artifact: &Artifact,
    ) -> Result<Vec<u8>> {
        let reader = ZipReader::new(&self.bytes)?;
        reader.read(&artifact.filename).map_err(|_| {
            Error::Malformed(format!(
                "package is missing artifact {:?}",
                artifact.filename
            ))
        })
    }
}

/// A [`Transport`] backed by the `dist-go` HTTP distribution host.
///
/// Layout (mirroring the producer's S3 store), where `name` is the
/// base64url-no-pad encoding of the 32-byte project fingerprint:
///
/// ```text
/// <base>/rust/<name>/MANIFEST-<channel>       moving pointer to the latest manifest
/// <base>/rust/<name>/<version>/<filename>     each immutable artifact
/// ```
pub struct HttpTransport {
    base: String,
    name: String,
}

impl HttpTransport {
    /// The default public distribution host.
    pub const DEFAULT_BASE: &'static str = "https://dist-go.tristandev.net/";

    /// Builds a transport against `base_url` for the project identified by its
    /// 32-byte `fingerprint`. A trailing slash on `base_url` is optional.
    pub fn new(base_url: &str, fingerprint: &[u8]) -> Self {
        use base64::Engine;
        let name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fingerprint);
        let base = if base_url.ends_with('/') {
            base_url.to_string()
        } else {
            format!("{base_url}/")
        };
        HttpTransport { base, name }
    }

    /// Builds a transport against [`DEFAULT_BASE`](Self::DEFAULT_BASE).
    pub fn with_default_base(fingerprint: &[u8]) -> Self {
        Self::new(Self::DEFAULT_BASE, fingerprint)
    }

    /// GETs `url`, returning the body on a 2xx and an error otherwise.
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        let resp =
            rsurl::get(url).map_err(|e| Error::Other(format!("GET {url} failed: {e}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(Error::Other(format!("GET {url} returned HTTP {}", resp.status)));
        }
        Ok(resp.body)
    }
}

impl Transport for HttpTransport {
    fn latest_manifest(&self, _project: &str, channel: &str) -> Result<Vec<u8>> {
        self.get(&format!("{}rust/{}/MANIFEST-{channel}", self.base, self.name))
    }

    fn fetch_artifact(
        &self,
        _project: &str,
        _channel: &str,
        version: &str,
        artifact: &Artifact,
    ) -> Result<Vec<u8>> {
        self.get(&format!(
            "{}rust/{}/{version}/{}",
            self.base, self.name, artifact.filename
        ))
    }
}
