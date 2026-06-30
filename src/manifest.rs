//! The release manifest: the signed description of a release.
//!
//! A [`Manifest`] lists, for one project release, every supported target and the
//! hashed, compressed archive that carries that target's binary. It is encoded as
//! an integer-keyed CBOR map (matching the bottlers house style), then sealed
//! into a signed [`bottlers::Bottle`] by the project [`crate::Identity`].
//!
//! A consumer recovers and verifies a manifest with
//! [`Manifest::open_and_verify`], which checks the embedded fingerprint, the
//! IDCard self-signature, and the manifest signature before returning anything.

use bottlers::{IDCard, Opener};
use ciborium::value::Value;

use crate::error::{Error, Result};
use crate::identity::{Identity, fingerprint_of};

/// Current manifest format version.
pub const FORMAT_VERSION: u32 = 1;

/// A hash over an artifact's uncompressed contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hash {
    /// Hash algorithm name (currently always `"sha256"`).
    pub method: String,
    /// Raw digest bytes.
    pub value: Vec<u8>,
}

impl Hash {
    /// Computes a SHA-256 hash over `data`.
    pub fn sha256(data: &[u8]) -> Self {
        Hash {
            method: "sha256".to_string(),
            value: purecrypto::hash::sha256(data).to_vec(),
        }
    }

    /// Verifies `data` matches this hash. Errors on mismatch or unknown method.
    pub fn verify(&self, data: &[u8]) -> Result<()> {
        let got = match self.method.as_str() {
            "sha256" => purecrypto::hash::sha256(data).to_vec(),
            other => {
                return Err(Error::VerifyFailed(format!(
                    "unknown hash method {other:?}"
                )));
            }
        };
        if got == self.value {
            Ok(())
        } else {
            Err(Error::VerifyFailed("artifact hash mismatch".into()))
        }
    }
}

/// One target's downloadable archive within a release.
#[derive(Clone, Debug)]
pub struct Artifact {
    /// Rust target triple, e.g. `x86_64-unknown-linux-gnu`.
    pub target: String,
    /// Path of the archive inside the package zip.
    pub filename: String,
    /// Compression algorithm name (`"zstd"` or `"none"`).
    pub compression: String,
    /// Uncompressed size in bytes.
    pub raw_size: u64,
    /// Stored (compressed) size in bytes.
    pub size: u64,
    /// Hash over the *uncompressed* binary.
    pub hash: Hash,
}

/// A signed release description.
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Format version (see [`FORMAT_VERSION`]).
    pub v: u32,
    /// Project name.
    pub project: String,
    /// Release channel (typically the producer's git branch, e.g. `master`).
    pub channel: String,
    /// Semantic version string (the consumer's `CARGO_PKG_VERSION`).
    pub version: String,
    /// Build stamp in `YYYYMMDDhhmmss` form (newer-build tiebreaker).
    pub date_tag: String,
    /// Short build identity (e.g. git short hash).
    pub git_tag: String,
    /// Release time, Unix seconds.
    pub released: i64,
    /// The project's signed IDCard (public identity).
    pub idcard: Vec<u8>,
    /// Per-target artifacts.
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    /// Returns the artifact whose target equals `target`, if present. `target`
    /// may be a full Rust triple or a compact `os_arch` label, depending on how
    /// the release was named.
    pub fn artifact_for(&self, target: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.target == target)
    }

    /// Returns the artifact matching the running host, accepting either naming
    /// scheme: it prefers an exact full-triple match ([`crate::TARGET`]) and
    /// falls back to the compact `os_arch` label ([`crate::current_label`]). This
    /// lets a producer name artifacts by triple or by `os_arch` and still be
    /// found by the right consumer.
    pub fn artifact_for_host(&self) -> Option<&Artifact> {
        self.artifact_for(crate::TARGET)
            .or_else(|| self.artifact_for(&crate::target::current_label()))
            .or_else(|| self.universal_for_host())
    }

    /// On an Apple host, a single macOS universal (fat) binary covers every
    /// arch; match it by its label or pseudo-triple. `None` off Apple.
    fn universal_for_host(&self) -> Option<&Artifact> {
        if !crate::target::is_apple(crate::TARGET) {
            return None;
        }
        self.artifact_for(crate::target::DARWIN_UNIVERSAL_LABEL)
            .or_else(|| self.artifact_for(crate::target::DARWIN_UNIVERSAL_TRIPLE))
    }

    /// Encodes the manifest as a standalone (unsigned) CBOR document.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&self.to_value(), &mut out)
            .map_err(|e| Error::Cbor(format!("manifest encode: {e}")))?;
        Ok(out)
    }

    /// Decodes an unsigned manifest from CBOR (no signature checking).
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let value: Value = ciborium::de::from_reader(data)
            .map_err(|e| Error::Cbor(format!("manifest decode: {e}")))?;
        Self::from_value(&value)
    }

    /// Signs the manifest with `identity`, returning the signed bottle's CBOR
    /// encoding (what gets stored as `manifest.cbor` in a package).
    pub fn sign(&self, identity: &Identity) -> Result<Vec<u8>> {
        identity.sign_payload(self.to_cbor()?)
    }

    /// Opens and fully verifies a signed manifest bottle against the expected
    /// 32-byte project fingerprint.
    ///
    /// Verification, in order: the bottle opens; the embedded IDCard is validly
    /// self-signed; its primary key fingerprint equals `expected_fingerprint`;
    /// and the manifest bottle is signed by that same primary key. Only then is
    /// the parsed manifest returned.
    pub fn open_and_verify(signed: &[u8], expected_fingerprint: &[u8]) -> Result<Manifest> {
        let (payload, info) = Opener::empty().open_cbor(signed)?;
        let manifest = Manifest::from_cbor(&payload)?;

        // The embedded IDCard must be validly self-signed.
        let card = IDCard::from_signed(&manifest.idcard).map_err(|_| {
            Error::VerifyFailed("embedded IDCard failed self-signature check".into())
        })?;

        // Its primary key must match the embedded trust anchor.
        let fp = fingerprint_of(&card.self_key);
        if fp.as_slice() != expected_fingerprint {
            return Err(Error::VerifyFailed(
                "manifest IDCard fingerprint does not match expected project identity".into(),
            ));
        }

        // The manifest itself must be signed by that primary key.
        if !info.signed_by_pkix(&card.self_key) {
            return Err(Error::VerifyFailed(
                "manifest is not signed by the project identity".into(),
            ));
        }

        Ok(manifest)
    }

    // --- CBOR mapping ----------------------------------------------------

    fn to_value(&self) -> Value {
        let artifacts = Value::Array(self.artifacts.iter().map(artifact_to_value).collect());
        int_map(vec![
            (1, Value::Integer(i64::from(self.v).into())),
            (2, Value::Text(self.project.clone())),
            (3, Value::Text(self.channel.clone())),
            (4, Value::Text(self.version.clone())),
            (5, Value::Text(self.date_tag.clone())),
            (6, Value::Text(self.git_tag.clone())),
            (7, Value::Integer(self.released.into())),
            (8, Value::Bytes(self.idcard.clone())),
            (9, artifacts),
        ])
    }

    fn from_value(v: &Value) -> Result<Self> {
        let map = as_int_map(v)?;
        let artifacts = match get(&map, 9)? {
            Value::Array(items) => items
                .iter()
                .map(artifact_from_value)
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(Error::Malformed("manifest artifacts not an array".into())),
        };
        Ok(Manifest {
            v: u32::try_from(as_i64(get(&map, 1)?)?)
                .map_err(|_| Error::Malformed("manifest version out of range".into()))?,
            project: as_text(get(&map, 2)?)?,
            channel: as_text(get(&map, 3)?)?,
            version: as_text(get(&map, 4)?)?,
            date_tag: as_text(get(&map, 5)?)?,
            git_tag: as_text(get(&map, 6)?)?,
            released: as_i64(get(&map, 7)?)?,
            idcard: as_bytes(get(&map, 8)?)?,
            artifacts,
        })
    }
}

fn artifact_to_value(a: &Artifact) -> Value {
    let hash = Value::Array(vec![
        Value::Text(a.hash.method.clone()),
        Value::Bytes(a.hash.value.clone()),
    ]);
    int_map(vec![
        (1, Value::Text(a.target.clone())),
        (2, Value::Text(a.filename.clone())),
        (3, Value::Text(a.compression.clone())),
        (
            4,
            Value::Integer(i64::try_from(a.raw_size).unwrap_or(i64::MAX).into()),
        ),
        (
            5,
            Value::Integer(i64::try_from(a.size).unwrap_or(i64::MAX).into()),
        ),
        (6, hash),
    ])
}

fn artifact_from_value(v: &Value) -> Result<Artifact> {
    let map = as_int_map(v)?;
    let hash = match get(&map, 6)? {
        Value::Array(a) if a.len() == 2 => Hash {
            method: as_text(&a[0])?,
            value: as_bytes(&a[1])?,
        },
        _ => return Err(Error::Malformed("artifact hash malformed".into())),
    };
    Ok(Artifact {
        target: as_text(get(&map, 1)?)?,
        filename: as_text(get(&map, 2)?)?,
        compression: as_text(get(&map, 3)?)?,
        raw_size: u64::try_from(as_i64(get(&map, 4)?)?)
            .map_err(|_| Error::Malformed("artifact raw_size negative".into()))?,
        size: u64::try_from(as_i64(get(&map, 5)?)?)
            .map_err(|_| Error::Malformed("artifact size negative".into()))?,
        hash,
    })
}

// --- small ciborium helpers ---------------------------------------------

fn int_map(entries: Vec<(i64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect(),
    )
}

fn as_int_map(v: &Value) -> Result<std::collections::BTreeMap<i64, &Value>> {
    match v {
        Value::Map(entries) => {
            let mut m = std::collections::BTreeMap::new();
            for (k, val) in entries {
                let key = k
                    .as_integer()
                    .and_then(|i| i64::try_from(i).ok())
                    .ok_or_else(|| Error::Malformed("non-integer map key".into()))?;
                m.insert(key, val);
            }
            Ok(m)
        }
        _ => Err(Error::Malformed("expected a CBOR map".into())),
    }
}

fn get<'a>(map: &std::collections::BTreeMap<i64, &'a Value>, key: i64) -> Result<&'a Value> {
    map.get(&key)
        .copied()
        .ok_or_else(|| Error::Malformed(format!("missing map key {key}")))
}

fn as_i64(v: &Value) -> Result<i64> {
    v.as_integer()
        .and_then(|i| i64::try_from(i).ok())
        .ok_or_else(|| Error::Malformed("expected an integer".into()))
}

fn as_text(v: &Value) -> Result<String> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(Error::Malformed("expected a text string".into())),
    }
}

fn as_bytes(v: &Value) -> Result<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(Error::Malformed("expected a byte string".into())),
    }
}
