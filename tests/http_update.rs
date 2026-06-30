//! Live end-to-end check of [`rsupd::HttpTransport`] against the public
//! `dist-go` distribution host. Ignored by default since it needs the network;
//! run with `cargo test --test http_update -- --ignored`.

use rsupd::{HttpTransport, Updater};

/// rsupd's own published fingerprint (same anchor the CLI embeds).
const FINGERPRINT: &[u8] = include_bytes!("../rsupd.fpr");

#[test]
#[ignore = "hits the live dist-go.tristandev.net host"]
fn downloads_verifies_and_installs_latest() {
    let transport = HttpTransport::new(FINGERPRINT);

    // Claim an ancient current version so the published release is always newer.
    let updater = Updater::builder("rsupd", "0.0.0")
        .fingerprint(FINGERPRINT)
        .auto_restart(false)
        .transport(Box::new(transport))
        .build()
        .unwrap();

    let available = updater
        .check()
        .expect("manifest fetch/verify should succeed")
        .expect("a newer release than 0.0.0 should exist");

    // install_to downloads the artifact, decompresses it, and checks its hash
    // against the manifest — any tamper or truncation fails here.
    let dir = std::env::temp_dir().join(format!("rsupd-http-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("rsupd-downloaded");
    updater
        .install_to(&available, &dest)
        .expect("download + verify + install should succeed");

    let bytes = std::fs::read(&dest).unwrap();
    assert!(bytes.len() > 1024, "installed binary looks too small");
    if rsupd::TARGET.contains("linux") {
        assert_eq!(&bytes[..4], b"\x7fELF", "expected an ELF binary on linux");
    }

    std::fs::remove_dir_all(&dir).ok();
}
