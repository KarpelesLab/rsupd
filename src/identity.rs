//! Project identity: the keypair, IDCard, and keychain that sign releases.
//!
//! An identity is persisted at `~/.config/rsupd/<project>/identity.bin` as a CBOR
//! array `[version, keychain_bytes, signed_idcard_bytes]`:
//!
//! * `keychain_bytes` is a [`bottlers::Keychain`] serialization (optionally
//!   PBES2-encrypted under a password) holding the private signing key.
//! * `signed_idcard_bytes` is the self-signed [`bottlers::IDCard`] — the public
//!   half a consumer can use to verify releases.
//!
//! The signing key is Ed25519. The identity's *fingerprint* — the SHA-256 of the
//! primary public key's PKIX/DER encoding — is the 32-byte trust anchor a
//! consumer embeds in its binary.

use std::path::Path;

use bottlers::{IDCard, Keychain, PrivateKey};
use ciborium::value::Value;
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::rng::OsRng;

use crate::config;
use crate::error::{Error, Result};

/// On-disk format version for `identity.bin`.
const IDENTITY_FORMAT: i64 = 1;

/// Content-type header used on signed rsupd payloads.
pub(crate) const MANIFEST_CT: &str = "rsupd-manifest";

/// A loaded project identity, able to sign releases.
pub struct Identity {
    project: String,
    keychain: Keychain,
    idcard: IDCard,
    signed_idcard: Vec<u8>,
}

impl Identity {
    /// Generates a brand-new identity for `project` (fresh Ed25519 key,
    /// self-signed IDCard) entirely in memory, without touching the filesystem.
    pub fn generate(project: &str) -> Result<Self> {
        let key = PrivateKey::Ed25519(Ed25519PrivateKey::generate(&mut OsRng));
        let idcard = IDCard::new(&key)?;
        let signed_idcard = idcard.sign(&key)?;
        let keychain = Keychain::from_keys([key])?;
        Ok(Identity {
            project: project.to_string(),
            keychain,
            idcard,
            signed_idcard,
        })
    }

    /// Creates a brand-new identity for `project` and writes it to the standard
    /// path. Errors if one already exists.
    ///
    /// When `password` is `Some`, the keychain half is PBES2-encrypted with it.
    pub fn create(project: &str, password: Option<&[u8]>) -> Result<Self> {
        let path = config::identity_path(project)?;
        if path.exists() {
            return Err(Error::Other(format!(
                "identity already exists at {}",
                path.display()
            )));
        }
        let id = Self::generate(project)?;
        id.save(password)?;
        Ok(id)
    }

    /// Loads `project`'s identity from the standard path.
    pub fn load(project: &str, password: Option<&[u8]>) -> Result<Self> {
        let path = config::identity_path(project)?;
        if !path.exists() {
            return Err(Error::NotConfigured(format!(
                "no identity for project {project:?} (expected {})",
                path.display()
            )));
        }
        let data = std::fs::read(&path)?;
        Self::from_bytes(project, &data, password)
    }

    /// Parses an identity from raw `identity.bin` bytes.
    pub fn from_bytes(project: &str, data: &[u8], password: Option<&[u8]>) -> Result<Self> {
        let value: Value = ciborium::de::from_reader(data)
            .map_err(|e| Error::Cbor(format!("identity decode: {e}")))?;
        let arr = match value {
            Value::Array(a) => a,
            _ => return Err(Error::Malformed("identity is not a CBOR array".into())),
        };
        if arr.len() != 3 {
            return Err(Error::Malformed(format!(
                "identity must have 3 fields, got {}",
                arr.len()
            )));
        }
        let version = arr[0]
            .as_integer()
            .and_then(|i| i64::try_from(i).ok())
            .ok_or_else(|| Error::Malformed("identity version not an integer".into()))?;
        if version != IDENTITY_FORMAT {
            return Err(Error::Malformed(format!(
                "unsupported identity version {version}"
            )));
        }
        let keychain_bytes = bytes_field(&arr[1], "keychain")?;
        let signed_idcard = bytes_field(&arr[2], "idcard")?.to_vec();

        let keychain = Keychain::deserialize(keychain_bytes, password)?;
        let idcard = IDCard::from_signed(&signed_idcard)?;

        Ok(Identity {
            project: project.to_string(),
            keychain,
            idcard,
            signed_idcard,
        })
    }

    /// Serializes the identity to `identity.bin` bytes.
    pub fn to_bytes(&self, password: Option<&[u8]>) -> Result<Vec<u8>> {
        let keychain_bytes = self.keychain.serialize(password)?;
        let value = Value::Array(vec![
            Value::Integer(IDENTITY_FORMAT.into()),
            Value::Bytes(keychain_bytes),
            Value::Bytes(self.signed_idcard.clone()),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&value, &mut out)
            .map_err(|e| Error::Cbor(format!("identity encode: {e}")))?;
        Ok(out)
    }

    /// Writes the identity to its standard path, creating the directory tree and
    /// restricting permissions to the owner on Unix.
    pub fn save(&self, password: Option<&[u8]>) -> Result<()> {
        let path = config::identity_path(&self.project)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = self.to_bytes(password)?;
        write_private(&path, &bytes)?;
        Ok(())
    }

    /// The project name this identity belongs to.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The primary (and currently only) signing key.
    pub fn primary_key(&self) -> Result<&PrivateKey> {
        self.keychain
            .first_signer()
            .ok_or_else(|| Error::NotConfigured("keychain has no signing key".into()))
    }

    /// The parsed public IDCard.
    pub fn idcard(&self) -> &IDCard {
        &self.idcard
    }

    /// The self-signed IDCard bottle bytes (the public identity to distribute).
    pub fn signed_idcard(&self) -> &[u8] {
        &self.signed_idcard
    }

    /// The SHA-256 fingerprint of the primary public key (PKIX/DER) — the 32-byte
    /// value a consumer embeds as its trust anchor.
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint_of(&self.idcard.self_key)
    }

    /// Signs `payload` as an rsupd content bottle, returning the signed bottle's
    /// CBOR encoding. Used to seal a serialized manifest.
    pub fn sign_payload(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let key = self.primary_key()?;
        let mut bottle =
            bottlers::Bottle::new(payload).with_header("ct", Value::Text(MANIFEST_CT.to_string()));
        bottle.bottle_up()?;
        bottle.sign(key)?;
        Ok(bottle.to_cbor()?)
    }
}

/// Computes the rsupd fingerprint of a PKIX/DER public key.
pub fn fingerprint_of(pkix: &[u8]) -> [u8; 32] {
    purecrypto::hash::sha256(pkix)
}

fn bytes_field<'a>(v: &'a Value, what: &str) -> Result<&'a [u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(Error::Malformed(format!(
            "identity {what} field is not bytes"
        ))),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}
