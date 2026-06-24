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
    if project.is_empty() || project.contains(['/', '\\']) || project == ".." {
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
