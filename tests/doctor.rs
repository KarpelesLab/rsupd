//! Static self-check (`rsupd::doctor`) over staged consumer projects.
//! Producer-side test: requires the `_cli` feature.
#![cfg(feature = "_cli")]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rsupd::doctor::{self, FingerprintState};

fn scratch(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("rsupd-doctor-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    dir
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, body).unwrap();
}

#[test]
fn reports_missing_wiring() {
    let root = scratch("missing");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    );
    write(&root.join("src/main.rs"), "fn main() {}\n");

    // No identity exists, so the fingerprint state is Unknown and the single
    // binary is not wired.
    let report = doctor::check(&root, None).unwrap();
    assert_eq!(report.bins.len(), 1);
    assert!(!report.bins[0].wired);
    assert_eq!(report.fingerprint, FingerprintState::Unknown);
    assert!(!report.ok());
    assert!(report.render().contains("--update"));
    assert!(report.render().contains("spawn_auto_update"));

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn detects_updater_wiring() {
    let root = scratch("wired");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    );
    write(
        &root.join("src/main.rs"),
        "fn main() {\n\
         \x20   let _ = rsupd::Updater::builder(\"app\", \"0.1.0\");\n\
         }\n",
    );

    // (No config-dir identity here, so the fingerprint state is Unknown; the
    // hex/.fpr matching paths are covered by the CLI smoke test. This asserts
    // the wiring detection itself.)
    let report = doctor::check(&root, None).unwrap();
    assert!(report.bins[0].wired, "Updater::builder should be detected");
    assert!(report.crate_wired);

    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn detects_multiple_bins() {
    let root = scratch("multi");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
         [[bin]]\nname = \"app\"\npath = \"src/main.rs\"\n\n\
         [[bin]]\nname = \"helper\"\npath = \"src/helper.rs\"\n",
    );
    write(
        &root.join("src/main.rs"),
        "fn main() { let _ = rsupd::Updater::builder(\"app\", \"1\"); }\n",
    );
    write(&root.join("src/helper.rs"), "fn main() {}\n");

    let report = doctor::check(&root, None).unwrap();
    let names: Vec<_> = report.bins.iter().map(|b| b.name.as_str()).collect();
    assert!(names.contains(&"app"));
    assert!(names.contains(&"helper"));
    let app = report.bins.iter().find(|b| b.name == "app").unwrap();
    let helper = report.bins.iter().find(|b| b.name == "helper").unwrap();
    assert!(app.wired, "app/main.rs is wired");
    assert!(!helper.wired, "helper.rs is not wired");

    std::fs::remove_dir_all(&root).ok();
}
