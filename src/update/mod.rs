//! Consumer side: check for, verify, and apply updates to the running program.

pub mod hide;
pub mod install;
pub mod restart;
pub mod selfexe;
pub mod transport;

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::manifest::Manifest;

pub use transport::{HttpTransport, Transport, ZipPackageTransport};

/// How often the background updater checks for a new release.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(3600);

/// A verified, newer release discovered by [`Updater::check`].
pub struct Available {
    /// The verified manifest describing the new release (kept private so the
    /// manifest type stays out of the consumer's public surface).
    manifest: Manifest,
}

impl Available {
    /// The new version string.
    pub fn version(&self) -> &str {
        &self.manifest.version
    }
    /// The new build identity (git short tag).
    pub fn git_tag(&self) -> &str {
        &self.manifest.git_tag
    }
}

/// Drives update checks and installation for one project/channel against a
/// [`Transport`]. Build one with [`Updater::builder`].
pub struct Updater {
    project: String,
    channel: String,
    cur_version: String,
    cur_date_tag: String,
    cur_git_tag: String,
    fingerprint: Vec<u8>,
    transport: Box<dyn Transport>,
    auto_restart: bool,
}

impl Updater {
    /// Starts building an updater for `project` currently at `current_version`
    /// (typically `env!("CARGO_PKG_VERSION")`).
    pub fn builder(
        project: impl Into<String>,
        current_version: impl Into<String>,
    ) -> UpdaterBuilder {
        UpdaterBuilder {
            project: project.into(),
            channel: String::new(),
            cur_version: current_version.into(),
            cur_date_tag: String::new(),
            cur_git_tag: String::new(),
            fingerprint: None,
            fingerprint_err: None,
            transport: None,
            auto_restart: true,
        }
    }

    /// The project name.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Fetches and verifies the latest manifest, returning `Some` only if it is a
    /// genuinely newer release for the running target.
    pub fn check(&self) -> Result<Option<Available>> {
        let signed = self
            .transport
            .latest_manifest(&self.project, &self.channel)?;
        let manifest = Manifest::open_and_verify(&signed, &self.fingerprint)?;

        if manifest.project != self.project {
            return Err(Error::VerifyFailed(format!(
                "manifest is for project {:?}, expected {:?}",
                manifest.project, self.project
            )));
        }
        if manifest.channel != self.channel {
            // Different channel: not an update for us.
            return Ok(None);
        }
        // It must carry an artifact for our host (triple or os_arch), or it is
        // not actionable.
        if manifest.artifact_for_host().is_none() {
            return Ok(None);
        }
        if self.is_newer(&manifest) {
            Ok(Some(Available { manifest }))
        } else {
            Ok(None)
        }
    }

    /// Downloads, verifies, and installs `available`, replacing the running
    /// executable. Does **not** restart. Returns the installed path.
    pub fn install(&self, available: &Available) -> Result<PathBuf> {
        let target = selfexe::self_exe();
        self.install_to(available, &target)?;
        Ok(target)
    }

    /// Like [`install`](Self::install) but writes to an explicit path (used by
    /// tests and for installing somewhere other than the running binary).
    pub fn install_to(&self, available: &Available, target: &Path) -> Result<()> {
        let artifact = available.manifest.artifact_for_host().ok_or_else(|| {
            Error::NoArtifact(format!(
                "no artifact for {} ({})",
                crate::TARGET,
                crate::target::current_label()
            ))
        })?;
        let stored = self.transport.fetch_artifact(
            &self.project,
            &self.channel,
            &available.manifest.version,
            artifact,
        )?;
        let binary = install::decode_and_verify(artifact, &stored)?;
        install::install_bytes(target, &binary)
    }

    /// Runs one full update cycle: check, and if a newer release exists, install
    /// it and (unless disabled) restart into it.
    ///
    /// Returns `Ok(false)` when already up to date. On a successful update with
    /// auto-restart enabled this normally does not return (the process is
    /// replaced); if restart somehow returns, the error is propagated.
    pub fn update(&self) -> Result<bool> {
        let Some(available) = self.check()? else {
            return Ok(false);
        };
        let installed = self.install(&available)?;
        if self.auto_restart {
            restart::restart(&installed)?;
        }
        Ok(true)
    }

    /// Spawns a background thread that runs [`update`](Self::update) immediately
    /// (when `immediate`) and then every [`DEFAULT_INTERVAL`], stopping once an
    /// update has been applied. Returns the thread handle.
    pub fn spawn_auto_update(self, immediate: bool) -> std::thread::JoinHandle<()> {
        self.spawn_auto_update_every(immediate, DEFAULT_INTERVAL)
    }

    /// As [`spawn_auto_update`](Self::spawn_auto_update) with a custom interval.
    pub fn spawn_auto_update_every(
        self,
        immediate: bool,
        interval: Duration,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            if !immediate {
                std::thread::sleep(interval.min(Duration::from_secs(60)));
            }
            loop {
                match self.update() {
                    Ok(true) => return, // updated (and, if restarting, we won't get here)
                    Ok(false) => {}
                    Err(e) => {
                        log_warn(&format!("[rsupd] update check failed: {e}"));
                    }
                }
                std::thread::sleep(interval);
            }
        })
    }

    /// The version-ordering rule (mirrors goupd): an update is newer when its
    /// build identity differs from ours and it sorts strictly after us by
    /// `(semver, date_tag)`.
    fn is_newer(&self, m: &Manifest) -> bool {
        if !m.git_tag.is_empty() && m.git_tag == self.cur_git_tag {
            return false; // same build
        }
        match cmp_semver(&m.version, &self.cur_version) {
            Ordering::Greater => true,
            Ordering::Less => false,
            // Same semantic version: the YYYYMMDDhhmmss stamp breaks the tie, but
            // only when we actually know our own build date. Fixed width means a
            // lexical comparison is chronological.
            Ordering::Equal => {
                !self.cur_date_tag.is_empty()
                    && !m.date_tag.is_empty()
                    && m.date_tag > self.cur_date_tag
            }
        }
    }
}

/// Builder for [`Updater`].
pub struct UpdaterBuilder {
    project: String,
    channel: String,
    cur_version: String,
    cur_date_tag: String,
    cur_git_tag: String,
    fingerprint: Option<Vec<u8>>,
    fingerprint_err: Option<String>,
    transport: Option<Box<dyn Transport>>,
    auto_restart: bool,
}

impl UpdaterBuilder {
    /// Sets the release channel. An empty/unset channel resolves to
    /// [`crate::DEFAULT_CHANNEL`].
    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = channel.into();
        self
    }

    /// Sets the current build's date tag (`YYYYMMDDhhmmss`), used to detect a
    /// newer build of the same semantic version.
    pub fn date_tag(mut self, date_tag: impl Into<String>) -> Self {
        self.cur_date_tag = date_tag.into();
        self
    }

    /// Sets the current build's git short tag (its build identity).
    pub fn git_tag(mut self, git_tag: impl Into<String>) -> Self {
        self.cur_git_tag = git_tag.into();
        self
    }

    /// Sets the 32-byte expected project fingerprint (the trust anchor) from raw
    /// bytes. Most callers want [`fingerprint_hex`](Self::fingerprint_hex)
    /// instead; this is for when you already hold the bytes. Required (or use
    /// `fingerprint_hex`).
    pub fn fingerprint(mut self, fingerprint: impl Into<Vec<u8>>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    /// Sets the trust anchor from its hex form, as printed by `rsupd id export`
    /// (e.g. `.fingerprint_hex("9258…8334")`). The fingerprint is a hash of a
    /// public key, so it is fine to paste straight into source. The hex is
    /// decoded and length-checked when you call [`build`](Self::build).
    pub fn fingerprint_hex(mut self, hex: &str) -> Self {
        match decode_hex(hex) {
            Some(bytes) => self.fingerprint = Some(bytes),
            None => self.fingerprint_err = Some(format!("invalid fingerprint hex: {hex:?}")),
        }
        self
    }

    /// Sets the transport. Optional: when left unset, the updater fetches from
    /// the default [`HttpTransport`] built from the fingerprint (the usual case).
    /// Set it explicitly only for a custom source, e.g. a [`ZipPackageTransport`]
    /// for offline/sideloaded updates or tests.
    pub fn transport(mut self, transport: Box<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Controls whether [`Updater::update`] restarts after installing (default
    /// `true`, matching goupd).
    pub fn auto_restart(mut self, yes: bool) -> Self {
        self.auto_restart = yes;
        self
    }

    /// Finalizes the updater, validating required fields.
    pub fn build(self) -> Result<Updater> {
        if let Some(e) = self.fingerprint_err {
            return Err(Error::Other(e));
        }
        let fingerprint = self
            .fingerprint
            .ok_or_else(|| Error::NotConfigured("updater fingerprint not set".into()))?;
        if fingerprint.len() != 32 {
            return Err(Error::Other(format!(
                "fingerprint must be 32 bytes, got {}",
                fingerprint.len()
            )));
        }
        // Default to the standard dist-go HttpTransport, derived from the
        // fingerprint, so the common case needs no transport line.
        let transport = self
            .transport
            .unwrap_or_else(|| Box::new(HttpTransport::new(&fingerprint)));
        // An unset channel resolves to the default, matching a producer that
        // built with no explicit channel.
        let channel = if self.channel.is_empty() {
            crate::DEFAULT_CHANNEL.to_string()
        } else {
            self.channel
        };
        // Fold the channel into our own version exactly as the producer stamped
        // it into the manifest (1.0.0 -> 1.0.0-beta off master), so same-version
        // comparisons line up and the date_tag tiebreak still fires per channel.
        let cur_version = crate::version_with_channel(&self.cur_version, &channel);
        Ok(Updater {
            project: self.project,
            channel,
            cur_version,
            cur_date_tag: self.cur_date_tag,
            cur_git_tag: self.cur_git_tag,
            fingerprint,
            transport,
            auto_restart: self.auto_restart,
        })
    }
}

fn log_warn(msg: &str) {
    eprintln!("{msg}");
}

/// Decodes an even-length hex string to bytes, or `None` on a bad length or a
/// non-hex character. Surrounding whitespace is trimmed.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Compares two semver-ish version strings: numeric dot-separated core, with a
/// present pre-release sorting before its release. Non-numeric identifiers fall
/// back to lexical comparison.
pub fn cmp_semver(a: &str, b: &str) -> Ordering {
    let (a_core, a_pre) = split_pre(a);
    let (b_core, b_pre) = split_pre(b);

    match cmp_dotted_numeric(a_core, b_core) {
        Ordering::Equal => {}
        other => return other,
    }
    // Equal cores: no pre-release outranks any pre-release.
    match (a_pre, b_pre) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => cmp_pre(x, y),
    }
}

fn split_pre(v: &str) -> (&str, Option<&str>) {
    // Drop build metadata (+...), then split off pre-release (-...).
    let v = v.split('+').next().unwrap_or(v);
    match v.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (v, None),
    }
}

fn cmp_dotted_numeric(a: &str, b: &str) -> Ordering {
    let mut ai = a.split('.');
    let mut bi = b.split('.');
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (Some(x), None) => {
                if x.parse::<u64>().unwrap_or(0) != 0 {
                    return Ordering::Greater;
                }
            }
            (None, Some(y)) => {
                if y.parse::<u64>().unwrap_or(0) != 0 {
                    return Ordering::Less;
                }
            }
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    _ => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

fn cmp_pre(a: &str, b: &str) -> Ordering {
    for (x, y) in a.split('.').zip(b.split('.')) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(xn), Ok(yn)) => xn.cmp(&yn),
            (Ok(_), Err(_)) => Ordering::Less, // numeric < alphanumeric
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.split('.').count().cmp(&b.split('.').count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_ordering() {
        assert_eq!(cmp_semver("1.2.3", "1.2.3"), Ordering::Equal);
        assert_eq!(cmp_semver("1.2.4", "1.2.3"), Ordering::Greater);
        assert_eq!(cmp_semver("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(cmp_semver("2.0.0", "1.99.99"), Ordering::Greater);
        assert_eq!(cmp_semver("1.0.0", "1.0.0-alpha"), Ordering::Greater);
        assert_eq!(cmp_semver("1.0.0-alpha", "1.0.0-beta"), Ordering::Less);
        assert_eq!(cmp_semver("1.0.0-1", "1.0.0-2"), Ordering::Less);
        assert_eq!(cmp_semver("1.0.0+build", "1.0.0"), Ordering::Equal);
    }
}
