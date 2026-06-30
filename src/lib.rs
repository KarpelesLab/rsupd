//! # rsupd
//!
//! `rsupd` distributes application releases as **signed manifests** and updates
//! running programs in place. It is the Rust successor to
//! [`goupd`](https://github.com/KarpelesLab/goupd), keeping that project's
//! atomic binary-swap + restart mechanics but replacing the plaintext update
//! files with a cryptographically signed, CBOR manifest built on the
//! [BottleFmt](https://github.com/BottleFmt) stack.
//!
//! There are two sides:
//!
//! * **Producer** (the [`package`] module and the `rsupd` CLI): given a project's
//!   compiled binaries, build a [`manifest::Manifest`] listing every target and
//!   its hashed, zstd-compressed archive, sign it with the project
//!   [`identity::Identity`], and bundle everything into one store-mode zip ready
//!   to upload.
//!
//! * **Consumer** (the [`update`] module): embed the project's public key
//!   fingerprint, ask a [`update::Transport`] for the latest manifest, verify the
//!   signature chain, compare versions, then download / verify / extract / swap
//!   the running executable.
//!
//! The exact upload/download network protocol is intentionally left to the
//! caller via the [`update::Transport`] trait; an offline
//! [`update::ZipPackageTransport`] reads packages produced by this same crate so
//! the whole flow can be exercised without a server.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod doctor;
pub mod error;
pub mod identity;
pub mod manifest;
pub mod package;
pub mod publish;
pub mod target;
pub mod update;

pub use doctor::DoctorReport;
pub use error::{Error, Result};
pub use identity::Identity;
pub use manifest::{Artifact, Hash, Manifest};
pub use package::TargetNaming;
pub use target::{current_label, label_for_triple};
pub use update::restart::honor_startup_delay;
pub use update::{HttpTransport, Transport, Updater, ZipPackageTransport};

/// The Rust target triple this build of rsupd is running on, e.g.
/// `x86_64-unknown-linux-gnu`. Captured at compile time by `build.rs`. It names
/// the directory binaries are read from (`target/<triple>/release`); the compact
/// `os_arch` label that identifies an [`Artifact`] is derived from it by
/// [`current_label`].
pub const TARGET: &str = env!("RSUPD_TARGET");

/// The git short hash this build was compiled from, or `""` when built outside a
/// git checkout. Used as the updater's build identity (an exact match means
/// "same build, no update").
pub const BUILD_GIT_TAG: &str = env!("RSUPD_GIT_TAG");

/// The commit Unix timestamp this build was compiled from, as a decimal string,
/// or `""` when unknown. See [`build_date_tag`] for the formatted form.
const BUILD_UNIX: &str = env!("RSUPD_BUILD_UNIX");

/// This build's commit date as a `YYYYMMDDhhmmss` UTC stamp, or `""` if unknown.
/// Mirrors the producer's manifest `date_tag`, so the updater can tell a newer
/// build of the same version from an older one.
pub fn build_date_tag() -> String {
    match BUILD_UNIX.parse::<i64>() {
        Ok(secs) if secs > 0 => package::format_date_tag(secs),
        _ => String::new(),
    }
}

/// The channel an empty channel string resolves to, on both producer and
/// consumer. A producer with no explicit channel tracks its git branch and
/// falls back to this; a consumer that leaves its channel unset matches it.
pub const DEFAULT_CHANNEL: &str = "master";
