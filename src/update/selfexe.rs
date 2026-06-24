//! Locating the currently running executable.

use std::path::PathBuf;

/// Returns the path to the running executable, following symlinks where
/// possible. Falls back to `current_exe` unresolved, then to `argv[0]`.
pub fn self_exe() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        return std::fs::canonicalize(&exe).unwrap_or(exe);
    }
    std::env::args_os()
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
