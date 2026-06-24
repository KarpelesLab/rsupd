//! Restarting the program after an in-place update.
//!
//! Mirrors goupd: re-exec the (now replaced) executable with the same arguments,
//! setting `RSUPD_DELAY=1` so the fresh process pauses briefly before starting —
//! giving the parent time to exit and release resources. On Unix this is an
//! `exec` that never returns on success; on Windows a new process is spawned and
//! the current one exits.

use std::path::Path;

use crate::error::Result;

/// The environment variable a freshly restarted process sees; its value is the
/// number of seconds to sleep before continuing startup.
pub const DELAY_ENV: &str = "RSUPD_DELAY";

/// If `RSUPD_DELAY` is set, sleeps that many seconds. Call once early in `main`
/// so a just-updated process settles before running.
///
/// The variable is intentionally left in place (clearing it would require the
/// `unsafe` `std::env::remove_var`, which this crate forbids); it is only acted
/// on once per process and is harmless to leave set.
pub fn honor_startup_delay() {
    if let Ok(v) = std::env::var(DELAY_ENV)
        && let Ok(secs) = v.parse::<u64>()
    {
        std::thread::sleep(std::time::Duration::from_secs(secs.min(60)));
    }
}

/// Re-executes `self_exe` with the current process arguments.
#[cfg(unix)]
pub fn restart(self_exe: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(self_exe)
        .args(std::env::args_os().skip(1))
        .env(DELAY_ENV, "1")
        .exec();
    // exec only returns on failure.
    Err(crate::error::Error::Io(err))
}

/// Spawns a replacement process and exits the current one.
#[cfg(windows)]
pub fn restart(self_exe: &Path) -> Result<()> {
    std::process::Command::new(self_exe)
        .args(std::env::args_os().skip(1))
        .env(DELAY_ENV, "1")
        .spawn()?;
    std::process::exit(0);
}

#[cfg(not(any(unix, windows)))]
pub fn restart(_self_exe: &Path) -> Result<()> {
    Err(crate::error::Error::Other(
        "restart not supported on this platform".into(),
    ))
}
