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

/// The distribution host releases are fetched from. Deliberately fixed: there
/// is no way to point the updater at a different origin. Note this is not the
/// security boundary — authenticity comes from the manifest's signature against
/// the embedded fingerprint, so a hostile origin still cannot forge an update.
/// Pinning it just keeps every consumer fetching from the one canonical place.
pub const DIST_HOST: &str = "https://dist-go.tristandev.net/";

/// Sanity cap on the manifest body size. A signed manifest is small; this is a
/// light amplification guard so a hostile origin can't make us buffer a huge
/// response before signature verification. The real backstop is rsurl's own
/// 256 MiB cap — this is just a tighter bound for the manifest specifically.
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

/// A [`Transport`] backed by the fixed [`DIST_HOST`] distribution host.
///
/// Layout (mirroring the producer's S3 store), where `name` is the
/// base64url-no-pad encoding of the 32-byte project fingerprint:
///
/// ```text
/// <DIST_HOST>/rust/<name>/MANIFEST-<channel>     moving pointer to the latest manifest
/// <DIST_HOST>/rust/<name>/<version>/<filename>   each immutable artifact
/// ```
pub struct HttpTransport {
    name: String,
}

impl HttpTransport {
    /// Builds a transport for the project identified by its 32-byte
    /// `fingerprint`. The origin is always [`DIST_HOST`] and cannot be changed.
    pub fn new(fingerprint: &[u8]) -> Self {
        use base64::Engine;
        let name = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fingerprint);
        HttpTransport { name }
    }

    /// GETs `url`, returning the body on a 2xx and an error otherwise.
    fn get(&self, url: &str) -> Result<Vec<u8>> {
        let resp = rsurl::get(url).map_err(|e| Error::Other(format!("GET {url} failed: {e}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(Error::Other(format!(
                "GET {url} returned HTTP {}",
                resp.status
            )));
        }
        Ok(resp.body)
    }
}

impl Transport for HttpTransport {
    fn latest_manifest(&self, _project: &str, channel: &str) -> Result<Vec<u8>> {
        let body = self.get(&format!("{DIST_HOST}rust/{}/MANIFEST-{channel}", self.name))?;
        if body.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Malformed(format!(
                "manifest exceeds sanity cap of {MAX_MANIFEST_BYTES} bytes ({} received)",
                body.len()
            )));
        }
        Ok(body)
    }

    fn fetch_artifact(
        &self,
        _project: &str,
        _channel: &str,
        version: &str,
        artifact: &Artifact,
    ) -> Result<Vec<u8>> {
        self.get(&format!(
            "{DIST_HOST}rust/{}/{version}/{}",
            self.name, artifact.filename
        ))
    }
}
