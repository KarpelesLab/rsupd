//! Project discovery: read the package name and binary targets from a
//! `Cargo.toml`, and locate the compiled binaries under `target/`.
//!
//! The TOML reader here is intentionally tiny — it understands the
//! `name = "..."` key inside the `[package]` table and inside each `[[bin]]`
//! table, which covers ordinary manifests. Anything more exotic (workspace
//! inheritance, computed names) should be handled by passing binary names
//! explicitly on the command line.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// What we learned about a project from its `Cargo.toml`.
#[derive(Debug, Clone)]
pub struct DiscoveredProject {
    /// Package name (`[package] name`).
    pub name: String,
    /// Package version (`[package] version`), if present.
    pub version: Option<String>,
    /// Binary names to ship. Defaults to `[name]` when no `[[bin]]` is declared.
    pub bins: Vec<String>,
    /// Project root (the directory holding `Cargo.toml`).
    pub root: PathBuf,
}

/// Reads `<project_dir>/Cargo.toml` and returns the package name and binaries.
pub fn discover(project_dir: &Path) -> Result<DiscoveredProject> {
    let manifest = project_dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", manifest.display())))?;
    let (name, version, bins) = parse_manifest(&text)?;
    let name = name.ok_or_else(|| {
        Error::Other("Cargo.toml has no [package] name (pass binaries explicitly)".into())
    })?;
    let bins = if bins.is_empty() {
        vec![name.clone()]
    } else {
        bins
    };
    Ok(DiscoveredProject {
        name,
        version,
        bins,
        root: project_dir.to_path_buf(),
    })
}

/// Minimal parse: returns `(package_name, package_version, bin_names)`.
fn parse_manifest(text: &str) -> Result<(Option<String>, Option<String>, Vec<String>)> {
    let mut package_name = None;
    let mut package_version = None;
    let mut bins = Vec::new();

    #[derive(PartialEq)]
    enum Section {
        Other,
        Package,
        Bin,
    }
    let mut section = Section::Other;
    let mut current_bin: Option<String> = None;

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            // Flush a finished [[bin]] table.
            if let Some(b) = current_bin.take() {
                bins.push(b);
            }
            let header = header.trim_end_matches(']');
            section = match header.trim_start_matches('[').trim() {
                "package" => Section::Package,
                "bin" if raw.contains("[[bin]]") => Section::Bin,
                _ => Section::Other,
            };
            continue;
        }
        if let Some((key, val)) = split_kv(line) {
            match (key, &section) {
                ("name", Section::Package) => package_name = unquote(val),
                ("name", Section::Bin) => current_bin = unquote(val),
                ("version", Section::Package) => package_version = unquote(val),
                _ => {}
            }
        }
    }
    if let Some(b) = current_bin.take() {
        bins.push(b);
    }
    Ok((package_name, package_version, bins))
}

fn strip_comment(line: &str) -> &str {
    // Naive: a '#' outside quotes starts a comment. Good enough for names.
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => {}
        }
    }
    line
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    Some((line[..eq].trim(), line[eq + 1..].trim()))
}

fn unquote(val: &str) -> Option<String> {
    let v = val.trim();
    let v = v.strip_prefix('"').unwrap_or(v);
    let v = v.strip_suffix('"').unwrap_or(v);
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// Locates the compiled binary `bin` for target triple `triple` under `root`.
///
/// Looks at `target/<triple>/release/<bin>` and, for the host's own native
/// build, `target/release/<bin>`. Tries a `.exe` suffix for Windows triples.
pub fn find_binary(root: &Path, triple: &str, bin: &str) -> Option<PathBuf> {
    let exe = if triple.contains("windows") {
        format!("{bin}.exe")
    } else {
        bin.to_string()
    };
    let candidates = [
        root.join("target").join(triple).join("release").join(&exe),
        root.join("target").join("release").join(&exe),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

/// Heuristic: a Rust target triple is `arch-vendor-os[-abi]`, so it has at least
/// two `-` separators and a recognizable arch prefix. This excludes cargo's
/// `release`/`debug` dirs and tool scratch dirs like `flycheck0`.
fn looks_like_triple(name: &str) -> bool {
    if name.matches('-').count() < 2 {
        return false;
    }
    const ARCHES: &[&str] = &[
        "x86_64",
        "i686",
        "i586",
        "aarch64",
        "arm",
        "armv7",
        "armv6",
        "thumbv7",
        "riscv32",
        "riscv64",
        "powerpc",
        "powerpc64",
        "ppc",
        "mips",
        "mips64",
        "s390x",
        "sparc",
        "sparc64",
        "wasm32",
        "loongarch64",
        "x86",
    ];
    let arch = name.split('-').next().unwrap_or("");
    ARCHES.contains(&arch)
}

/// Auto-detects target triples that have at least one of `bins` built, by
/// scanning `target/<triple>/release/`. The native `target/release` build is
/// reported under `native_triple` when present.
pub fn detect_targets(root: &Path, bins: &[String], native_triple: &str) -> Vec<String> {
    let mut found = Vec::new();
    let target_dir = root.join("target");

    // Cross-compiled triples: subdirectories of target/ with a release/ folder.
    if let Ok(entries) = std::fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let triple = entry.file_name().to_string_lossy().to_string();
            if !looks_like_triple(&triple) {
                // Skip cargo's own dirs (release/, debug/) and tool scratch dirs
                // (e.g. rust-analyzer's flycheck<N>) that are not target triples.
                continue;
            }
            if bins.iter().any(|b| find_binary(root, &triple, b).is_some()) {
                found.push(triple);
            }
        }
    }

    // Native build at target/release counts as the host triple.
    if !found.contains(&native_triple.to_string())
        && bins
            .iter()
            .any(|b| target_dir.join("release").join(b).is_file())
    {
        found.push(native_triple.to_string());
    }

    found.sort();
    found.dedup();
    found
}
