//! Producer side: turn a project's compiled binaries into one signed,
//! zipped release package.

pub mod discover;
pub mod zip;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use compcol::vec::compress_to_vec;
use compcol::zstd::Zstd;

use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::manifest::{Artifact, FORMAT_VERSION, Hash, Manifest};

pub use discover::{BinEntry, DiscoveredProject, bin_entries, discover};

// `TargetNaming` is defined below and re-exported at the crate root.

/// The standard archive path inside a package zip.
pub const MANIFEST_ENTRY: &str = "manifest.cbor";

/// How artifacts are identified and named within a package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TargetNaming {
    /// Compact `os_arch` label, e.g. `linux_amd64` (goupd convention). One slot
    /// per OS/arch; cannot distinguish e.g. glibc from musl. The default.
    #[default]
    OsArch,
    /// Full Rust target triple, e.g. `x86_64-unknown-linux-musl`. Use when a
    /// single `os_arch` is not specific enough (multiple libc/ABI variants).
    Triple,
}

impl TargetNaming {
    /// Parses a naming mode from a CLI string (`os_arch` / `osarch` / `triple`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "os_arch" | "osarch" | "os-arch" => Ok(TargetNaming::OsArch),
            "triple" => Ok(TargetNaming::Triple),
            other => Err(Error::Other(format!(
                "unknown target naming {other:?} (use os_arch or triple)"
            ))),
        }
    }

    /// The artifact target identity for a Rust `triple` under this naming.
    pub fn label_for(self, triple: &str) -> String {
        match self {
            TargetNaming::OsArch => crate::target::label_for_triple(triple),
            TargetNaming::Triple => triple.to_string(),
        }
    }
}

/// Options controlling a package build.
pub struct BuildOptions {
    /// Project root holding `Cargo.toml` and `target/`.
    pub project_dir: PathBuf,
    /// Release channel. Empty = derive from the git branch name at build time,
    /// falling back to `"master"` when detached or outside a repo. A non-default
    /// channel is also folded into the version as a SemVer pre-release tag (see
    /// [`version`](Self::version)).
    pub channel: String,
    /// Override the version string. Defaults to the Cargo.toml `[package] version`.
    /// When the resolved channel is not the default (`"master"`), it is appended
    /// as a pre-release tag, so a beta build of `1.0.0` reports `1.0.0-beta`.
    pub version: Option<String>,
    /// Target triples to include. Empty = auto-detect from `target/`.
    pub targets: Vec<String>,
    /// Binary names to include. Empty = from `Cargo.toml`.
    pub bins: Vec<String>,
    /// Compression for artifacts: `"zstd"` (default) or `"none"`.
    pub compression: String,
    /// How to name/identify artifacts (`os_arch` label or full triple).
    pub naming: TargetNaming,
}

impl BuildOptions {
    /// Returns build options for `project_dir` with sensible defaults.
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        BuildOptions {
            project_dir: project_dir.into(),
            channel: String::new(),
            version: None,
            targets: Vec::new(),
            bins: Vec::new(),
            compression: "zstd".to_string(),
            naming: TargetNaming::default(),
        }
    }
}

/// The result of building a package.
pub struct BuiltPackage {
    /// The parsed manifest (also embedded, signed, in `bytes`).
    pub manifest: Manifest,
    /// The signed manifest bottle (the `manifest.cbor` entry of the zip).
    pub signed_manifest: Vec<u8>,
    /// The complete package zip.
    pub bytes: Vec<u8>,
}

/// Builds a signed release package for `identity`'s project.
///
/// Discovers binaries, locates each requested target's compiled binary under
/// `target/`, hashes and (optionally) zstd-compresses each, assembles a signed
/// [`Manifest`], and bundles `manifest.cbor` plus every artifact into a
/// store-mode zip.
pub fn build_package(identity: &Identity, opts: &BuildOptions) -> Result<BuiltPackage> {
    let project = discover::discover(&opts.project_dir)?;
    let bins = if opts.bins.is_empty() {
        project.bins.clone()
    } else {
        opts.bins.clone()
    };

    let targets = if opts.targets.is_empty() {
        discover::detect_targets(&project.root, &bins, crate::TARGET)
    } else {
        opts.targets.clone()
    };
    if targets.is_empty() {
        return Err(Error::Other(
            "no compiled targets found; build the project (cargo build --release) or pass --target"
                .into(),
        ));
    }

    let base_version = opts
        .version
        .clone()
        .or_else(|| project.version.clone())
        .unwrap_or_else(|| "0.0.0".to_string());

    let (git_tag, commit_time) = git_info(&project.root);
    let released = commit_time.unwrap_or_else(now_unix);
    let date_tag = format_date_tag(released);

    // No explicit channel: track the current git branch, falling back to the
    // default channel when detached or outside a repo.
    let channel = if opts.channel.is_empty() {
        git_branch(&project.root).unwrap_or_else(|| crate::DEFAULT_CHANNEL.to_string())
    } else {
        opts.channel.clone()
    };

    // Fold a non-default channel into the version as a SemVer pre-release tag, so
    // a beta build of 1.0.0 reports 1.0.0-beta while master stays 1.0.0. The
    // updater folds its own version the same way, so the two agree.
    let version = crate::version_with_channel(&base_version, &channel);

    let mut zw = zip::ZipWriter::new();
    let mut artifacts = Vec::new();

    // Track which triple produced each artifact label so we can reject two
    // builds (e.g. linux gnu vs musl) that would collide on the same os_arch
    // label. In `triple` naming, labels are unique and this never fires.
    let mut seen_labels: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for triple in &targets {
        let label = opts.naming.label_for(triple);
        for bin in &bins {
            let Some(path) = discover::find_binary(&project.root, triple, bin) else {
                continue;
            };
            if let Some(prev) = seen_labels.insert(format!("{label}/{bin}"), triple.clone())
                && &prev != triple
            {
                return Err(Error::Other(format!(
                    "targets {prev:?} and {triple:?} both map to os_arch label {label:?} for \
                     binary {bin:?}; build only one per os_arch, or use triple naming \
                     (--naming triple) to keep them distinct"
                )));
            }

            let raw = std::fs::read(&path)?;
            let hash = Hash::sha256(&raw);
            let raw_size = raw.len() as u64;

            let (compression, ext, stored) = match opts.compression.as_str() {
                "none" => ("none", "bin", raw.clone()),
                "zstd" => {
                    let z = compress_to_vec::<Zstd>(&raw)
                        .map_err(|e| Error::Compress(format!("zstd: {e:?}")))?;
                    ("zstd", "zst", z)
                }
                other => {
                    return Err(Error::Other(format!(
                        "unsupported compression {other:?} (use zstd or none)"
                    )));
                }
            };

            // Flat, slashless name: <bin>_<os>_<arch>.<ext>, e.g. rsupd_linux_amd64.zst.
            let filename = format!("{bin}_{label}.{ext}");
            zw.add(&filename, &stored)?;
            artifacts.push(Artifact {
                target: label.clone(),
                filename,
                compression: compression.to_string(),
                raw_size,
                size: stored.len() as u64,
                hash,
            });
        }
    }

    if artifacts.is_empty() {
        return Err(Error::Other(format!(
            "found target dirs {targets:?} but none contained binaries {bins:?}"
        )));
    }

    let manifest = Manifest {
        v: FORMAT_VERSION,
        project: identity.project().to_string(),
        channel,
        version,
        date_tag,
        git_tag,
        released,
        idcard: identity.signed_idcard().to_vec(),
        artifacts,
    };

    let signed = manifest.sign(identity)?;
    zw.add(MANIFEST_ENTRY, &signed)?;
    let bytes = zw.finish()?;

    Ok(BuiltPackage {
        manifest,
        signed_manifest: signed,
        bytes,
    })
}

/// Reads `git rev-parse` short hash and the commit's Unix time for `root`.
fn git_info(root: &Path) -> (String, Option<i64>) {
    let git_tag = run_git(root, &["rev-parse", "--short=7", "HEAD"]).unwrap_or_default();
    let commit_time =
        run_git(root, &["log", "-1", "--format=%ct"]).and_then(|s| s.trim().parse::<i64>().ok());
    (git_tag, commit_time)
}

/// Reads the current git branch name for `root`, or `None` when detached
/// (`HEAD`) or outside a repository.
fn git_branch(root: &Path) -> Option<String> {
    match run_git(root, &["rev-parse", "--abbrev-ref", "HEAD"]) {
        Some(b) if b != "HEAD" => Some(b),
        _ => None,
    }
}

fn run_git(root: &Path, args: &[&str]) -> Option<String> {
    // Resolve `git` via PATH so a `git` planted in the project dir can't be run.
    let git = crate::util::resolve_program("git")?;
    let out = std::process::Command::new(&git)
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats a Unix timestamp as a `YYYYMMDDhhmmss` UTC string.
pub fn format_date_tag(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(unix);
    format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}")
}

/// Converts a Unix timestamp to UTC `(year, month, day, hour, min, sec)` using
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_unix(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (hour, min, sec) = (
        (secs / 3600) as u32,
        ((secs % 3600) / 60) as u32,
        (secs % 60) as u32,
    );

    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_tag_known() {
        // 2021-05-18 03:51:12 UTC = 1621309872
        assert_eq!(format_date_tag(1_621_309_872), "20210518035112");
        // Unix epoch.
        assert_eq!(format_date_tag(0), "19700101000000");
    }
}
