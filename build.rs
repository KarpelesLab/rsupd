//! Build script: capture, as compile-time constants, what the running program
//! needs to know about its own build — the Rust target triple, and the git
//! build identity (short hash + commit time) the updater uses to tell a newer
//! build from an older one.

use std::env;
use std::process::Command;

/// Runs `git args...` in the crate dir, returning trimmed stdout on success.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn main() {
    // Cargo sets TARGET for build scripts but not for normal code; re-export it.
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=RSUPD_TARGET={target}");

    // Build identity for the updater's newer-build comparison. Empty when built
    // outside a git checkout (e.g. from a crates.io package); the updater then
    // falls back to a plain semver comparison.
    let git_tag = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_default();
    let build_unix = git(&["log", "-1", "--format=%ct", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=RSUPD_GIT_TAG={git_tag}");
    println!("cargo:rustc-env=RSUPD_BUILD_UNIX={build_unix}");

    println!("cargo:rerun-if-changed=build.rs");
    // Re-stamp when the checked-out commit moves.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = std::fs::read_to_string(".git/HEAD")
        && let Some(reference) = head.strip_prefix("ref:")
    {
        // Only the first line, and only if it looks like a real git ref path
        // (no whitespace or control chars) — otherwise an embedded newline could
        // inject extra `cargo:` directives.
        let reference = reference.lines().next().unwrap_or("").trim();
        if !reference.is_empty()
            && !reference
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            println!("cargo:rerun-if-changed=.git/{reference}");
        }
    }
}
