//! Project identity: the keypair, IDCard, and keychain that sign releases.
//!
//! An identity is persisted at `~/.config/rsupd/<project>/identity.bin` as a CBOR
//! array `[version, keychain_bytes, signed_idcard_bytes]`:
//!
//! * `keychain_bytes` is a [`bottlers::Keychain`] serialization (optionally
//!   PBES2-encrypted under a password) holding the private keys.
//! * `signed_idcard_bytes` is the self-signed [`bottlers::IDCard`] — the public
//!   half a consumer can use to verify releases.
//!
//! The keychain holds two keys with separated roles: an **Ed25519 signing key**
//! (the primary / self key, purpose `"sign"`) and an **X25519 encryption key**
//! (a subkey, purpose `"decrypt"`). The IDCard advertises both. The identity's
//! *fingerprint* — the SHA-256 of the signing key's PKIX/DER encoding — is the
//! 32-byte trust anchor a consumer embeds in its binary.

use std::path::Path;

use bottlers::{IDCard, Keychain, PrivateKey, PublicKey};
use ciborium::value::Value;
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
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
    /// Generates a brand-new identity for `project` entirely in memory, without
    /// touching the filesystem.
    ///
    /// Two keys are created: an Ed25519 signing key (the self/primary key) and an
    /// X25519 encryption key. The IDCard, self-signed by the signing key, lists
    /// the signing key with purpose `"sign"` and the encryption key with purpose
    /// `"decrypt"`.
    pub fn generate(project: &str) -> Result<Self> {
        let sign_key = PrivateKey::Ed25519(Ed25519PrivateKey::generate(&mut OsRng));
        let enc_key = PrivateKey::X25519(X25519PrivateKey::generate(&mut OsRng));

        // IDCard::new lists the signing key as the self key with purpose "sign".
        let mut idcard = IDCard::new(&sign_key)?;
        idcard.set_key_purposes(enc_key.public_pkix()?, &["decrypt"]);
        // Self-sign the (now two-key) card with the signing key.
        let signed_idcard = idcard.sign(&sign_key)?;

        let keychain = Keychain::from_keys([sign_key, enc_key])?;
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

    /// Name of the environment variable holding a base64-encoded `identity.bin`,
    /// used to supply the signing identity in CI without writing it to disk.
    pub const IDENTITY_ENV: &str = "RSUPD_IDENTITY";

    /// Loads `project`'s identity, preferring the base64 [`Self::IDENTITY_ENV`]
    /// environment variable (the whole `identity.bin`, as set by a CI secret)
    /// over the on-disk file. This lets a publish job supply the signing key via
    /// `RSUPD_IDENTITY` with no filesystem setup.
    pub fn load_env_or_file(project: &str, password: Option<&[u8]>) -> Result<Self> {
        if let Ok(b64) = std::env::var(Self::IDENTITY_ENV) {
            let b64 = b64.trim();
            if !b64.is_empty() {
                use base64::Engine;
                let data = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| {
                        Error::Other(format!("{} base64 decode: {e}", Self::IDENTITY_ENV))
                    })?;
                return Self::from_bytes(project, &data, password);
            }
        }
        Self::load(project, password)
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
        let arr = parse_envelope(data)?;
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

    /// Loads only the public half of `project`'s identity (the IDCard), without
    /// touching the encrypted keychain — so no password is required.
    pub fn load_public(project: &str) -> Result<PublicIdentity> {
        let path = config::identity_path(project)?;
        if !path.exists() {
            return Err(Error::NotConfigured(format!(
                "no identity for project {project:?} (expected {})",
                path.display()
            )));
        }
        let data = std::fs::read(&path)?;
        PublicIdentity::from_identity_bytes(&data)
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

    /// The primary signing key (the IDCard self key, Ed25519).
    pub fn signing_key(&self) -> Result<&PrivateKey> {
        self.keychain
            .get_key(&self.idcard.self_key)
            .ok_or_else(|| Error::NotConfigured("signing key missing from keychain".into()))
    }

    /// The private encryption key (X25519), if one is present in the keychain.
    pub fn encryption_key(&self) -> Option<&PrivateKey> {
        let now = now_unix();
        for sub in &self.idcard.subkeys {
            if !sub.has_purpose("decrypt") {
                continue;
            }
            if let Some(exp) = sub.expires
                && exp <= now
            {
                continue;
            }
            if let Some(key) = self.keychain.get_key(&sub.key) {
                return Some(key);
            }
        }
        None
    }

    /// The public encryption key (X25519) others use to encrypt to this identity.
    pub fn encryption_public(&self) -> Option<PublicKey> {
        self.idcard
            .keys_for("decrypt", now_unix())
            .into_iter()
            .next()
    }

    /// The parsed public IDCard.
    pub fn idcard(&self) -> &IDCard {
        &self.idcard
    }

    /// The self-signed IDCard bottle bytes (the public identity to distribute).
    pub fn signed_idcard(&self) -> &[u8] {
        &self.signed_idcard
    }

    /// The SHA-256 fingerprint of the signing public key (PKIX/DER) — the 32-byte
    /// value a consumer embeds as its trust anchor.
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint_of(&self.idcard.self_key)
    }

    /// Signs `payload` as an rsupd content bottle, returning the signed bottle's
    /// CBOR encoding. Used to seal a serialized manifest.
    pub fn sign_payload(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let key = self.signing_key()?;
        let mut bottle =
            bottlers::Bottle::new(payload).with_header("ct", Value::Text(MANIFEST_CT.to_string()));
        bottle.bottle_up()?;
        bottle.sign(key)?;
        Ok(bottle.to_cbor()?)
    }
}

/// The public half of an identity: the IDCard, with no private key material.
/// Recovered from `identity.bin` without a password.
pub struct PublicIdentity {
    /// The parsed public IDCard.
    pub idcard: IDCard,
    /// The self-signed IDCard bottle bytes.
    pub signed_idcard: Vec<u8>,
}

impl PublicIdentity {
    /// Parses the public IDCard out of raw `identity.bin` bytes, ignoring (and
    /// never decrypting) the keychain field.
    pub fn from_identity_bytes(data: &[u8]) -> Result<Self> {
        let arr = parse_envelope(data)?;
        let signed_idcard = bytes_field(&arr[2], "idcard")?.to_vec();
        let idcard = IDCard::from_signed(&signed_idcard)?;
        Ok(PublicIdentity {
            idcard,
            signed_idcard,
        })
    }

    /// The SHA-256 fingerprint of the signing public key (PKIX/DER).
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint_of(&self.idcard.self_key)
    }

    /// The public encryption key (X25519) advertised by this identity, if any.
    pub fn encryption_public(&self) -> Option<PublicKey> {
        self.idcard
            .keys_for("decrypt", now_unix())
            .into_iter()
            .next()
    }
}

/// Computes the rsupd fingerprint of a PKIX/DER public key.
pub fn fingerprint_of(pkix: &[u8]) -> [u8; 32] {
    purecrypto::hash::sha256(pkix)
}

/// Current Unix time in seconds (used to filter expired subkeys).
fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parses and validates the outer `[version, keychain, idcard]` CBOR envelope,
/// returning the three array elements. Does not interpret the inner fields.
fn parse_envelope(data: &[u8]) -> Result<Vec<Value>> {
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
    Ok(arr)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_key_identity_roundtrips() {
        let id = Identity::generate("demo").unwrap();

        // The IDCard advertises both a sign and a decrypt key.
        let purposes: Vec<String> = id
            .idcard()
            .subkeys
            .iter()
            .flat_map(|s| s.purposes.clone())
            .collect();
        assert!(purposes.iter().any(|p| p == "sign"), "missing sign purpose");
        assert!(
            purposes.iter().any(|p| p == "decrypt"),
            "missing decrypt purpose"
        );

        // Both private keys are present, and they are distinct keys.
        assert!(id.signing_key().is_ok());
        assert!(id.encryption_key().is_some());
        assert!(id.encryption_public().is_some());
        let sign_pkix = id.signing_key().unwrap().public_pkix().unwrap();
        let enc_pkix = id.encryption_key().unwrap().public_pkix().unwrap();
        assert_ne!(sign_pkix, enc_pkix, "sign and encryption keys must differ");
        // The fingerprint anchors to the signing key, not the encryption key.
        assert_eq!(
            id.fingerprint().to_vec(),
            fingerprint_of(&sign_pkix).to_vec()
        );

        // Persisting and reloading preserves both keys.
        let bytes = id.to_bytes(None).unwrap();
        let id2 = Identity::from_bytes("demo", &bytes, None).unwrap();
        assert!(id2.signing_key().is_ok());
        assert!(id2.encryption_key().is_some());
        assert_eq!(id2.fingerprint(), id.fingerprint());

        // The public-only view also exposes the encryption key.
        let pubid = PublicIdentity::from_identity_bytes(&bytes).unwrap();
        assert!(pubid.encryption_public().is_some());
    }
}
