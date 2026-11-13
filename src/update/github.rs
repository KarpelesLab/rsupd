//! Updating straight from a project's **GitHub Releases**, without rsupd's
//! signed manifest.
//!
//! This is the alternative to the signed `dist-go` flow, meant for open source
//! projects that already publish their binaries on GitHub. There is no
//! identity, fingerprint or manifest: the updater asks the GitHub API for the
//! channel's newest release, picks the asset built for the running host,
//! downloads it, and checks it against the **SHA-256 digest GitHub itself
//! reports for that asset** before installing.
//!
//! Trust therefore rests on GitHub (and TLS to it): whoever can publish a
//! release on the repository can ship an update. Signing with a key kept in
//! that same repository's CI secrets would add nothing on top of that.
//!
//! Layout, as uploaded by `rsupd publish --github`:
//!
//! ```text
//! release tagged v<version>          (e.g. v1.2.3; v1.2.3-beta on channel "beta")
//!   <bin>_<target>.zst               one zstd-compressed binary per target
//! ```
//!
//! `<target>` is the `os_arch` label (`linux_amd64`), the full Rust triple, or
//! `darwin_universal`. The default channel follows the repository's *latest*
//! release; any other channel follows the newest release whose version carries
//! the channel as its pre-release tag (`1.2.3-beta`), which `rsupd publish`
//! marks as a GitHub pre-release.

use std::cmp::Ordering;

use compcol::vec::decompress_to_vec_capped;
use compcol::zstd::Zstd;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::update::transport::http_get;

/// The GitHub REST API origin.
const API_HOST: &str = "https://api.github.com/";

/// Release assets must be served from here.
const DOWNLOAD_PREFIX: &str = "https://github.com/";

/// Sanity cap on an API response body.
const MAX_API_BYTES: usize = 16 * 1024 * 1024;

/// Floor for the decompression cap; the cap is otherwise a generous multiple of
/// the compressed size (there is no signed `raw_size` to bound it exactly).
const MIN_DECOMPRESS_CAP: u64 = 64 * 1024 * 1024;

/// A GitHub repository whose Releases carry the project's updates.
pub(crate) struct GithubSource {
    repo: String,
}

/// The release asset chosen for the running host.
#[derive(Debug)]
pub(crate) struct GithubRelease {
    /// Release version: the tag without its `v` (or `<project>-v`) prefix.
    pub version: String,
    /// Asset file name.
    name: String,
    /// Asset download URL.
    url: String,
    /// Asset size in bytes, as reported by the API.
    size: u64,
    /// SHA-256 of the asset, as reported by the API.
    sha256: Vec<u8>,
    /// Whether the asset is zstd-compressed (else a raw binary).
    zstd: bool,
}

impl GithubSource {
    /// `repo` is `owner/repo` or the repository URL (so
    /// `env!("CARGO_PKG_REPOSITORY")` works).
    pub fn new(repo: &str) -> Result<Self> {
        let r = repo.trim();
        let r = r
            .strip_prefix("https://github.com/")
            .or_else(|| r.strip_prefix("http://github.com/"))
            .or_else(|| r.strip_prefix("git@github.com:"))
            .unwrap_or(r);
        let r = r.trim_end_matches('/');
        let r = r.strip_suffix(".git").unwrap_or(r);
        match r.split_once('/') {
            Some((owner, name)) if is_safe_segment(owner) && is_safe_segment(name) => {
                Ok(GithubSource {
                    repo: r.to_string(),
                })
            }
            _ => Err(Error::Other(format!(
                "invalid GitHub repository {repo:?}: expected owner/repo"
            ))),
        }
    }

    /// Asks the API for `channel`'s newest release and returns its asset for the
    /// running host, or `None` when there is no such release or asset.
    pub fn latest(&self, project: &str, channel: &str) -> Result<Option<GithubRelease>> {
        // The default channel is the repository's "latest release" (GitHub never
        // gives that title to a draft or pre-release). Other channels are
        // pre-releases, so they are searched for in the recent releases.
        let path = if channel == crate::DEFAULT_CHANNEL {
            "releases/latest"
        } else {
            "releases?per_page=30"
        };
        let url = format!("{API_HOST}repos/{}/{path}", self.repo);
        let body = http_get(
            &url,
            false,
            &[
                ("User-Agent", concat!("rsupd/", env!("CARGO_PKG_VERSION"))),
                ("Accept", "application/vnd.github+json"),
            ],
        )?;
        if body.len() > MAX_API_BYTES {
            return Err(Error::Malformed(format!(
                "GitHub API response too large ({} bytes)",
                body.len()
            )));
        }
        let json: Value = serde_json::from_slice(&body)
            .map_err(|e| Error::Malformed(format!("GitHub API response: {e}")))?;
        pick_release(&json, project, channel, &host_labels())
    }

    /// Downloads `release`'s asset, checks it against the size and SHA-256 the
    /// GitHub API reported, and returns the (decompressed) binary.
    pub fn download(&self, release: &GithubRelease) -> Result<Vec<u8>> {
        let stored = http_get(&release.url, true, &[])?;
        decode_and_verify(release, &stored)
    }
}

/// Verifies downloaded asset bytes against what the API reported and unpacks
/// them into the binary to install.
fn decode_and_verify(release: &GithubRelease, stored: &[u8]) -> Result<Vec<u8>> {
    let name = &release.name;
    if stored.len() as u64 != release.size {
        return Err(Error::VerifyFailed(format!(
            "asset {name:?}: expected {} bytes, got {}",
            release.size,
            stored.len()
        )));
    }
    if purecrypto::hash::sha256(stored).as_slice() != release.sha256.as_slice() {
        return Err(Error::VerifyFailed(format!(
            "asset {name:?} does not match the SHA-256 digest reported by GitHub"
        )));
    }
    if !release.zstd {
        return Ok(stored.to_vec());
    }
    let cap = release.size.saturating_mul(64).max(MIN_DECOMPRESS_CAP);
    decompress_to_vec_capped::<Zstd>(stored, cap)
        .map_err(|e| Error::Compress(format!("zstd decode of {name:?}: {e:?}")))
}

/// The names under which an asset for the running host may be published, most
/// specific first: the exact triple, the `os_arch` label, then (on macOS) the
/// universal binary.
fn host_labels() -> Vec<String> {
    let mut labels = vec![crate::TARGET.to_string(), crate::target::current_label()];
    if crate::target::is_apple(crate::TARGET) {
        labels.push(crate::target::DARWIN_UNIVERSAL_LABEL.to_string());
        labels.push(crate::target::DARWIN_UNIVERSAL_TRIPLE.to_string());
    }
    labels
}

/// Picks `channel`'s newest release out of an API response (one release object,
/// or an array of them) and resolves its asset for a host matching `labels`.
fn pick_release(
    json: &Value,
    project: &str,
    channel: &str,
    labels: &[String],
) -> Result<Option<GithubRelease>> {
    let single = std::slice::from_ref(json);
    let releases = json.as_array().map(Vec::as_slice).unwrap_or(single);

    let mut best: Option<(String, &Value)> = None;
    for rel in releases {
        if rel["draft"].as_bool() == Some(true) {
            continue;
        }
        let Some(version) = rel["tag_name"]
            .as_str()
            .and_then(|tag| version_of_tag(tag, project))
        else {
            continue;
        };
        if !on_channel(version, channel) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(v, _)| super::cmp_semver(version, v) == Ordering::Greater)
        {
            best = Some((version.to_string(), rel));
        }
    }
    let Some((version, rel)) = best else {
        return Ok(None);
    };

    let assets = rel["assets"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let Some((asset, zstd)) = find_asset(assets, project, labels) else {
        return Ok(None);
    };
    let name = asset["name"].as_str().unwrap_or_default().to_string();

    let url = asset["browser_download_url"]
        .as_str()
        .filter(|u| u.starts_with(DOWNLOAD_PREFIX))
        .ok_or_else(|| Error::Malformed(format!("asset {name:?} has no GitHub download URL")))?
        .to_string();
    let size = asset["size"]
        .as_u64()
        .ok_or_else(|| Error::Malformed(format!("asset {name:?} has no size")))?;
    // The digest is the whole integrity check, so an asset without one (GitHub
    // only computes them for assets uploaded since mid-2025) is not installable.
    let sha256 = asset["digest"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .and_then(super::decode_hex)
        .filter(|d| d.len() == 32)
        .ok_or_else(|| {
            Error::VerifyFailed(format!(
                "GitHub reports no SHA-256 digest for asset {name:?}; re-upload it to get one"
            ))
        })?;

    Ok(Some(GithubRelease {
        version,
        name,
        url,
        size,
        sha256,
        zstd,
    }))
}

/// Finds the asset for the first matching label, returning it with whether it
/// is zstd-compressed. An asset named after the project wins over any other
/// binary published for the same target.
fn find_asset<'a>(
    assets: &'a [Value],
    project: &str,
    labels: &[String],
) -> Option<(&'a Value, bool)> {
    let named =
        |pred: &dyn Fn(&str) -> bool| assets.iter().find(|a| a["name"].as_str().is_some_and(pred));
    for label in labels {
        for (ext, zstd) in [("zst", true), ("bin", false)] {
            let exact = format!("{project}_{label}.{ext}");
            let suffix = format!("_{label}.{ext}");
            if let Some(a) =
                named(&|n| n == exact).or_else(|| named(&|n| n.ends_with(suffix.as_str())))
            {
                return Some((a, zstd));
            }
        }
    }
    None
}

/// Extracts the version from a release tag: `v1.2.3`, `1.2.3`, or the
/// `<project>-v1.2.3` form used by multi-crate repositories. `None` for a tag
/// that is not a version (or belongs to another project).
fn version_of_tag<'a>(tag: &'a str, project: &str) -> Option<&'a str> {
    let rest = tag
        .strip_prefix(project)
        .and_then(|r| r.strip_prefix('-'))
        .unwrap_or(tag);
    let version = rest.strip_prefix('v').unwrap_or(rest);
    version
        .starts_with(|c: char| c.is_ascii_digit())
        .then_some(version)
}

/// Whether `version` belongs to `channel`: a non-default channel is folded into
/// the version as its pre-release tag (see [`crate::version_with_channel`]); the
/// default channel takes whatever GitHub calls the latest release.
fn on_channel(version: &str, channel: &str) -> bool {
    channel == crate::DEFAULT_CHANNEL || version.ends_with(&format!("-{channel}"))
}

/// True for a string usable verbatim as one URL path segment.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(['.', '-'])
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn asset(name: &str, data: &[u8]) -> Value {
        json!({
            "name": name,
            "size": data.len(),
            "digest": format!("sha256:{}", hex(&purecrypto::hash::sha256(data))),
            "browser_download_url": format!("https://github.com/o/r/releases/download/t/{name}"),
        })
    }

    fn labels() -> Vec<String> {
        vec!["x86_64-unknown-linux-gnu".into(), "linux_amd64".into()]
    }

    #[test]
    fn repo_forms() {
        for ok in [
            "KarpelesLab/rsupd",
            "https://github.com/KarpelesLab/rsupd",
            "https://github.com/KarpelesLab/rsupd/",
            "https://github.com/KarpelesLab/rsupd.git",
            "git@github.com:KarpelesLab/rsupd.git",
        ] {
            assert_eq!(GithubSource::new(ok).unwrap().repo, "KarpelesLab/rsupd");
        }
        for bad in [
            "",
            "rsupd",
            "a/b/c",
            "a/../b",
            "https://gitlab.com/a/b",
            "a/b?x",
        ] {
            assert!(
                GithubSource::new(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn tag_versions() {
        assert_eq!(version_of_tag("v1.2.3", "app"), Some("1.2.3"));
        assert_eq!(version_of_tag("1.2.3", "app"), Some("1.2.3"));
        assert_eq!(version_of_tag("app-v1.2.3", "app"), Some("1.2.3"));
        assert_eq!(version_of_tag("other-v1.2.3", "app"), None);
        assert_eq!(version_of_tag("nightly", "app"), None);
    }

    #[test]
    fn latest_release_verifies_and_decodes() {
        let binary = b"a freshly released binary".repeat(40);
        let packed = compcol::vec::compress_to_vec::<Zstd>(&binary).unwrap();
        let latest = json!({
            "tag_name": "v1.2.3",
            "draft": false,
            "prerelease": false,
            "assets": [
                asset("app_windows_amd64.zst", b"other platform"),
                asset("app_linux_amd64.zst", &packed),
            ],
        });
        let rel = pick_release(&latest, "app", "master", &labels())
            .unwrap()
            .expect("asset for host");
        assert_eq!(rel.version, "1.2.3");
        assert_eq!(rel.name, "app_linux_amd64.zst");
        assert_eq!(decode_and_verify(&rel, &packed).unwrap(), binary);

        // Anything but the bytes GitHub hashed is refused.
        let mut tampered = packed.clone();
        tampered[10] ^= 1;
        assert!(decode_and_verify(&rel, &tampered).is_err());
        assert!(decode_and_verify(&rel, &packed[..packed.len() - 1]).is_err());
    }

    #[test]
    fn triple_named_and_raw_assets() {
        let latest = json!({
            "tag_name": "v2.0.0",
            "assets": [
                asset("app_linux_amd64.zst", b"generic"),
                asset("app_x86_64-unknown-linux-gnu.bin", b"exact triple"),
            ],
        });
        // The exact triple outranks the os_arch label; `.bin` is stored raw.
        let rel = pick_release(&latest, "app", "master", &labels())
            .unwrap()
            .unwrap();
        assert_eq!(rel.name, "app_x86_64-unknown-linux-gnu.bin");
        assert_eq!(
            decode_and_verify(&rel, b"exact triple").unwrap(),
            b"exact triple"
        );
    }

    #[test]
    fn channel_picks_newest_matching_prerelease() {
        let list = json!([
            { "tag_name": "v1.3.0", "assets": [asset("app_linux_amd64.zst", b"stable")] },
            { "tag_name": "v1.3.0-beta", "prerelease": true,
              "assets": [asset("app_linux_amd64.zst", b"beta 1.3")] },
            { "tag_name": "v1.4.0-beta", "prerelease": true, "draft": true,
              "assets": [asset("app_linux_amd64.zst", b"draft")] },
            { "tag_name": "v1.10.0-beta", "prerelease": true,
              "assets": [asset("app_linux_amd64.zst", b"beta 1.10")] },
            { "tag_name": "v1.2.0-beta", "prerelease": true,
              "assets": [asset("app_linux_amd64.zst", b"beta 1.2")] },
        ]);
        let rel = pick_release(&list, "app", "beta", &labels())
            .unwrap()
            .unwrap();
        assert_eq!(rel.version, "1.10.0-beta");
        assert!(
            pick_release(&list, "app", "nightly", &labels())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn missing_asset_or_digest() {
        // No asset for this host: nothing to do, not an error.
        let other = json!({ "tag_name": "v1.0.0",
            "assets": [asset("app_windows_amd64.zst", b"x")] });
        assert!(
            pick_release(&other, "app", "master", &labels())
                .unwrap()
                .is_none()
        );

        // An asset GitHub has no digest for cannot be verified, so it is refused.
        let mut no_digest = json!({ "tag_name": "v1.0.0",
            "assets": [asset("app_linux_amd64.zst", b"x")] });
        no_digest["assets"][0]["digest"] = Value::Null;
        assert!(pick_release(&no_digest, "app", "master", &labels()).is_err());

        // A download URL off github.com is refused too.
        let mut off_site = json!({ "tag_name": "v1.0.0",
            "assets": [asset("app_linux_amd64.zst", b"x")] });
        off_site["assets"][0]["browser_download_url"] = json!("https://example.com/x");
        assert!(pick_release(&off_site, "app", "master", &labels()).is_err());
    }
}
