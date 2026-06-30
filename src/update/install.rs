//! Downloading, verifying, and atomically installing an artifact.

use std::path::{Path, PathBuf};

use compcol::vec::decompress_to_vec_capped;
use compcol::zstd::Zstd;

use crate::error::{Error, Result};
use crate::manifest::Artifact;
use crate::update::hide::hide_file;

/// Upper bound on a decompressed artifact, as a multiple of its declared
/// `raw_size`, to bound work even if a manifest lies. The manifest is signed, so
/// this is belt-and-suspenders.
const DECOMPRESS_SLACK: u64 = 2;

/// Verifies `stored` against `artifact` and returns the decompressed binary.
///
/// Checks the stored size, decompresses according to the artifact's compression,
/// then checks the hash over the decompressed bytes.
pub fn decode_and_verify(artifact: &Artifact, stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() as u64 != artifact.size {
        return Err(Error::VerifyFailed(format!(
            "artifact {:?}: expected {} stored bytes, got {}",
            artifact.filename,
            artifact.size,
            stored.len()
        )));
    }

    let binary = match artifact.compression.as_str() {
        "none" => stored.to_vec(),
        "zstd" => {
            let cap = artifact.raw_size.saturating_mul(DECOMPRESS_SLACK).max(1);
            decompress_to_vec_capped::<Zstd>(stored, cap)
                .map_err(|e| Error::Compress(format!("zstd decode: {e:?}")))?
        }
        other => {
            return Err(Error::Malformed(format!(
                "artifact {:?}: unknown compression {other:?}",
                artifact.filename
            )));
        }
    };

    if binary.len() as u64 != artifact.raw_size {
        return Err(Error::VerifyFailed(format!(
            "artifact {:?}: expected {} raw bytes, got {}",
            artifact.filename,
            artifact.raw_size,
            binary.len()
        )));
    }
    artifact.hash.verify(&binary)?;
    Ok(binary)
}

/// Atomically replaces the file at `target` with `data`.
///
/// Ported from goupd's `SaveAs`: write `.<name>.new` alongside the target, rename
/// the current file to `.<name>.old`, move the new file into place, then try to
/// delete the old file (hiding it if deletion fails, e.g. a running Windows
/// executable). `data` is the final, verified binary.
pub fn install_bytes(target: &Path, data: &[u8]) -> Result<()> {
    let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    let dir = target
        .parent()
        .ok_or_else(|| Error::Other(format!("target has no parent: {}", target.display())))?;
    let name = target
        .file_name()
        .ok_or_else(|| Error::Other(format!("target has no file name: {}", target.display())))?
        .to_string_lossy()
        .to_string();

    let new_path = dir.join(format!(".{name}.new"));
    let old_path = dir.join(format!(".{name}.old"));

    write_executable(&new_path, data).inspect_err(|_| {
        let _ = std::fs::remove_file(&new_path);
    })?;

    let had_old = target.exists();
    if had_old {
        std::fs::rename(&target, &old_path).map_err(|e| {
            let _ = std::fs::remove_file(&new_path);
            Error::Io(e)
        })?;
    }

    if let Err(e) = std::fs::rename(&new_path, &target) {
        // Try to restore the original.
        if had_old {
            let _ = std::fs::rename(&old_path, &target);
        }
        let _ = std::fs::remove_file(&new_path);
        return Err(Error::Io(e));
    }

    if had_old && std::fs::remove_file(&old_path).is_err() {
        // Couldn't delete the prior binary (e.g. a running Windows executable).
        // Before hiding it, best-effort restrict its permissions so a
        // predictable, world-readable copy isn't left behind. Best-effort only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&old_path, std::fs::Permissions::from_mode(0o600));
        }
        let _ = hide_file(&old_path);
    }
    Ok(())
}

/// Returns the conventional sidecar paths for `target` (`.name.new`, `.name.old`),
/// exposed for tests and cleanup.
pub fn sidecar_paths(target: &Path) -> Option<(PathBuf, PathBuf)> {
    let dir = target.parent()?;
    let name = target.file_name()?.to_string_lossy().to_string();
    Some((
        dir.join(format!(".{name}.new")),
        dir.join(format!(".{name}.old")),
    ))
}

#[cfg(unix)]
fn write_executable(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Clear any stale or attacker-planted sidecar first. `remove_file` unlinks a
    // symlink itself rather than following it to its target, so the `create_new`
    // below cannot be redirected through a planted symlink. `create_new` then
    // guarantees we open a freshly created regular file (failing if one
    // reappears), so we never reuse/follow an existing file or inherit its perms.
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    // Force exactly 0o755 regardless of the process umask.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_executable(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    // Clear any stale/planted sidecar, then create a fresh file (failing if one
    // reappears) rather than truncating an existing one.
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}
