//! Error and result types for rsupd.

use std::fmt;

/// The result type used throughout rsupd.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by rsupd operations.
#[derive(Debug)]
pub enum Error {
    /// An underlying I/O failure.
    Io(std::io::Error),
    /// A failure originating in the `bottlers` crypto/container layer.
    Bottle(bottlers::BottleError),
    /// A CBOR (de)serialization failure.
    Cbor(String),
    /// A compression / decompression failure.
    Compress(String),
    /// The on-disk or in-stream data was not in the expected shape.
    Malformed(String),
    /// A signature, fingerprint, or hash did not verify.
    VerifyFailed(String),
    /// The requested identity / project was not configured.
    NotConfigured(String),
    /// No artifact in the manifest matches the running target.
    NoArtifact(String),
    /// A catch-all for configuration / usage problems.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Bottle(e) => write!(f, "bottle error: {e:?}"),
            Error::Cbor(m) => write!(f, "cbor error: {m}"),
            Error::Compress(m) => write!(f, "compression error: {m}"),
            Error::Malformed(m) => write!(f, "malformed data: {m}"),
            Error::VerifyFailed(m) => write!(f, "verification failed: {m}"),
            Error::NotConfigured(m) => write!(f, "not configured: {m}"),
            Error::NoArtifact(m) => write!(f, "no matching artifact: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<bottlers::BottleError> for Error {
    fn from(e: bottlers::BottleError) -> Self {
        Error::Bottle(e)
    }
}
