//! The [`Transport`] abstraction over wherever releases are hosted.
//!
//! The real network protocol is supplied later; until then [`ZipPackageTransport`]
//! serves a package produced by [`crate::package::build_package`] straight from
//! disk, so the whole check → download → verify → install path runs offline.

use std::path::Path;

use crate::error::{Error, Result};
use crate::manifest::Artifact;
use crate::package::{MANIFEST_ENTRY, zip::ZipReader};

/// Source of update metadata and artifacts for a project/channel.
///
/// Implementations must be cheap to share across threads (the background updater
/// holds one). They return raw bytes; all verification happens in the updater.
pub trait Transport: Send + Sync {
    /// Fetches the signed manifest bottle for `project` on `channel`
    /// (`channel` is `""` for the default channel).
    fn latest_manifest(&self, project: &str, channel: &str) -> Result<Vec<u8>>;

    /// Fetches the stored (compressed) bytes of `artifact`.
    fn fetch_artifact(&self, project: &str, channel: &str, artifact: &Artifact) -> Result<Vec<u8>>;
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
