//! Live end-to-end check of [`rsupd::HttpTransport`] against the public
//! `dist-go` distribution host. Ignored by default since it needs the network;
//! run with `cargo test --test http_update -- --ignored`.

use rsupd::Updater;

/// rsupd's own published fingerprint hex (same anchor the CLI embeds).
const FINGERPRINT_HEX: &str = "925804220841644e23b6c756b2dc3e611374d08eeb24918fcff0161401da8334";

#[test]
#[ignore = "hits the live dist-go.tristandev.net host"]
fn downloads_verifies_and_installs_latest() {
    // Claim an ancient current version so the published release is always newer.
    // No transport set: exercises the default dist-go HttpTransport.
    let updater = Updater::builder("rsupd", "0.0.0")
        .fingerprint_hex(FINGERPRINT_HEX)
        .auto_restart(false)
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
