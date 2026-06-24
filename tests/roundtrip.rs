//! End-to-end producer → consumer round trip, exercised entirely offline:
//! generate an identity, stage a fake project, build a signed package, then
//! verify + install it through an [`Updater`] over a [`ZipPackageTransport`].

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rsupd::identity::Identity;
use rsupd::manifest::Manifest;
use rsupd::package::{self, BuildOptions};
use rsupd::update::transport::ZipPackageTransport;
use rsupd::update::{Available, Updater};

/// Creates a unique scratch directory under the system temp dir.
fn scratch(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rsupd-test-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Stages a minimal cargo project whose binary `demo` is already "compiled"
/// at `target/<TARGET>/release/demo` with the given contents.
fn stage_project(root: &Path, binary: &[u8]) {
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let bindir = root.join("target").join(rsupd::TARGET).join("release");
    std::fs::create_dir_all(&bindir).unwrap();
    let exe = if rsupd::TARGET.contains("windows") {
        "demo.exe"
    } else {
        "demo"
    };
    std::fs::write(bindir.join(exe), binary).unwrap();
}

fn build_demo_package(root: &Path, identity: &Identity) -> rsupd::package::BuiltPackage {
    let mut opts = BuildOptions::new(root);
    opts.channel = String::new();
    package::build_package(identity, &opts).expect("build package")
}

#[test]
fn full_roundtrip_install() {
    let root = scratch("roundtrip");
    let binary = b"#!/bin/sh\necho rsupd demo v2\n".repeat(200);
    stage_project(&root, &binary);

    let identity = Identity::generate("demo").unwrap();
    let fingerprint = identity.fingerprint();
    let built = build_demo_package(&root, &identity);

    // The manifest verifies against the right fingerprint.
    let manifest = Manifest::open_and_verify(&built.signed_manifest, &fingerprint)
        .expect("verify with correct fingerprint");
    assert_eq!(manifest.project, "demo");
    assert_eq!(manifest.version, "1.0.0");
    assert!(manifest.artifact_for(rsupd::TARGET).is_some());

    // A wrong fingerprint must fail.
    let wrong = [0u8; 32];
    assert!(Manifest::open_and_verify(&built.signed_manifest, &wrong).is_err());

    // Build an updater whose *current* build is older (0.9.0) than the package.
    let transport = ZipPackageTransport::from_bytes(built.bytes.clone());
    let updater = Updater::builder("demo", "0.9.0")
        .fingerprint(fingerprint)
        .auto_restart(false)
        .transport(Box::new(transport))
        .build()
        .unwrap();

    let available: Available = updater.check().unwrap().expect("an update is available");
    assert_eq!(available.version(), "1.0.0");

    // Install to a temp path and confirm the bytes match the staged binary.
    let dest = root.join("installed-demo");
    std::fs::write(&dest, b"old contents").unwrap();
    updater.install_to(&available, &dest).unwrap();
    let got = std::fs::read(&dest).unwrap();
    assert_eq!(got, binary, "installed binary must match the original");

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn no_update_when_current_is_newer_or_equal() {
    let root = scratch("noupdate");
    stage_project(&root, b"binary bytes here");
    let identity = Identity::generate("demo").unwrap();
    let fingerprint = identity.fingerprint();
    let built = build_demo_package(&root, &identity);

    // Current version equals the package version (1.0.0) and no date_tag set,
    // so there is no update.
    let updater = Updater::builder("demo", "1.0.0")
        .fingerprint(fingerprint)
        .auto_restart(false)
        .transport(Box::new(ZipPackageTransport::from_bytes(
            built.bytes.clone(),
        )))
        .build()
        .unwrap();
    assert!(
        updater.check().unwrap().is_none(),
        "equal version: no update"
    );

    // A newer current version also yields no update.
    let updater2 = Updater::builder("demo", "2.0.0")
        .fingerprint(fingerprint)
        .auto_restart(false)
        .transport(Box::new(ZipPackageTransport::from_bytes(built.bytes)))
        .build()
        .unwrap();
    assert!(
        updater2.check().unwrap().is_none(),
        "newer current: no update"
    );

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn tampered_artifact_is_rejected() {
    let root = scratch("tamper");
    stage_project(&root, &b"abcdefgh".repeat(64));
    let identity = Identity::generate("demo").unwrap();
    let fingerprint = identity.fingerprint();
    let built = build_demo_package(&root, &identity);

    // Corrupt a byte well inside the zip payload (past the headers), then make
    // sure either the CRC/structure check or the hash check rejects it.
    let mut bytes = built.bytes.clone();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;

    let updater = Updater::builder("demo", "0.1.0")
        .fingerprint(fingerprint)
        .auto_restart(false)
        .transport(Box::new(ZipPackageTransport::from_bytes(bytes)))
        .build()
        .unwrap();

    let dest = root.join("installed");
    let result = updater.check().and_then(|maybe| match maybe {
        Some(avail) => updater.install_to(&avail, &dest).map(|_| ()),
        None => Ok(()),
    });
    assert!(result.is_err(), "tampered package must be rejected");

    std::fs::remove_dir_all(&root).ok();
}
