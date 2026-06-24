//! Best-effort "hide" of a leftover file.
//!
//! On Windows a running executable cannot be deleted, so after an update the old
//! binary is renamed aside and hidden. We shell out to `attrib +h` rather than
//! call `SetFileAttributesW` directly, which keeps the crate free of `unsafe`
//! FFI. On every other platform the old file is simply removed, so this is a
//! no-op.

use std::path::Path;

/// Marks `path` hidden where the platform supports it. Errors are non-fatal and
/// swallowed by callers.
#[cfg(windows)]
pub fn hide_file(path: &Path) -> crate::error::Result<()> {
    let status = std::process::Command::new("attrib")
        .arg("+h")
        .arg(path)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(crate::error::Error::Other("attrib +h failed".into()))
    }
}

/// No-op on non-Windows platforms.
#[cfg(not(windows))]
pub fn hide_file(_path: &Path) -> crate::error::Result<()> {
    Ok(())
}
