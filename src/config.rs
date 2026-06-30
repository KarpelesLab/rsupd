//! Resolution of the per-project configuration directory.
//!
//! Identities live at `<config>/rsupd/<project>/`, where `<config>` follows the
//! platform convention: `$XDG_CONFIG_HOME` (or `~/.config`) on Unix, `%APPDATA%`
//! on Windows, and `~/Library/Application Support` on macOS. The resolver is
//! deliberately dependency-free.

use std::path::PathBuf;

use crate::error::{Error, Result};

/// Returns the base configuration directory for rsupd (the `rsupd` folder under
/// the platform's user config location), creating nothing.
pub fn base_dir() -> Result<PathBuf> {
    let mut dir = platform_config_dir()?;
    dir.push("rsupd");
    Ok(dir)
}

/// Returns the directory holding `project`'s identity and state, e.g.
/// `~/.config/rsupd/<project>`. The directory is not created.
pub fn project_dir(project: &str) -> Result<PathBuf> {
    // Strict allowlist: a project name must be non-empty, contain only ASCII
    // alphanumerics or `._-`, and not be `.` or `..`. This rejects path
    // separators, the current-dir alias `.`, parent-dir `..`, and Windows
    // drive-relative names like `C:foo` (which contain `:` but no slash).
    let valid = !project.is_empty()
        && project
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && project != "."
        && project != "..";
    if !valid {
        return Err(Error::Other(format!("invalid project name: {project:?}")));
    }
    let mut dir = base_dir()?;
    dir.push(project);
    Ok(dir)
}

/// Returns the path to `project`'s `identity.bin`. The directory is not created.
pub fn identity_path(project: &str) -> Result<PathBuf> {
    let mut dir = project_dir(project)?;
    dir.push("identity.bin");
    Ok(dir)
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(windows)]
fn platform_config_dir() -> Result<PathBuf> {
    env_path("APPDATA")
        .or_else(|| {
            env_path("USERPROFILE").map(|mut p| {
                p.push("AppData");
                p.push("Roaming");
                p
            })
        })
        .ok_or_else(|| Error::Other("cannot determine %APPDATA%".into()))
}

#[cfg(target_vendor = "apple")]
fn platform_config_dir() -> Result<PathBuf> {
    env_path("HOME")
        .map(|mut p| {
            p.push("Library");
            p.push("Application Support");
            p
        })
        .ok_or_else(|| Error::Other("cannot determine $HOME".into()))
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn platform_config_dir() -> Result<PathBuf> {
    if let Some(p) = env_path("XDG_CONFIG_HOME") {
        return Ok(p);
    }
    env_path("HOME")
        .map(|mut p| {
            p.push(".config");
            p
        })
        .ok_or_else(|| Error::Other("cannot determine $HOME or $XDG_CONFIG_HOME".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_dir_rejects_unsafe_names() {
        for bad in ["", ".", "..", "C:foo", "a/b", "a\\b", "foo bar", "naïve"] {
            assert!(project_dir(bad).is_err(), "expected {bad:?} to be rejected");
        }
    }

    #[test]
    fn project_dir_accepts_safe_name() {
        let dir = project_dir("my-app_1.0").expect("name should be accepted");
        assert!(dir.ends_with("my-app_1.0"));
    }
}
