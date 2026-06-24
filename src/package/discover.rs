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

/// A declared `[[bin]]` table: its `name` and optional `path`.
#[derive(Debug, Clone, Default)]
struct BinSpec {
    name: Option<String>,
    path: Option<String>,
}

/// A binary target with its resolved entry-point source file (if found).
#[derive(Debug, Clone)]
pub struct BinEntry {
    /// The binary's name.
    pub name: String,
    /// The entry-point `.rs` file, or `None` if it could not be located.
    pub entry: Option<PathBuf>,
}

/// Reads `<project_dir>/Cargo.toml` and returns the package name and binaries.
pub fn discover(project_dir: &Path) -> Result<DiscoveredProject> {
    let manifest = project_dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", manifest.display())))?;
    let (name, version, specs) = parse_manifest(&text)?;
    let name = name.ok_or_else(|| {
        Error::Other("Cargo.toml has no [package] name (pass binaries explicitly)".into())
    })?;
    let mut bins: Vec<String> = specs.iter().filter_map(|s| s.name.clone()).collect();
    if bins.is_empty() {
        bins.push(name.clone());
    }
    Ok(DiscoveredProject {
        name,
        version,
        bins,
        root: project_dir.to_path_buf(),
    })
}

/// Resolves the entry-point source file of every binary target: declared
/// `[[bin]]` tables, the default `src/main.rs`, and cargo's auto-discovered
/// `src/bin/*.rs` (and `src/bin/*/main.rs`).
pub fn bin_entries(project_dir: &Path) -> Result<Vec<BinEntry>> {
    let manifest = project_dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", manifest.display())))?;
    let (pkg_name, _version, specs) = parse_manifest(&text)?;
    let root = project_dir;

    let mut out: Vec<BinEntry> = Vec::new();
    let mut seen_names = std::collections::HashSet::new();

    // Declared [[bin]] tables.
    for spec in &specs {
        let Some(name) = spec.name.clone() else {
            continue;
        };
        if !seen_names.insert(name.clone()) {
            continue;
        }
        let entry = resolve_entry(root, &name, spec.path.as_deref(), pkg_name.as_deref());
        out.push(BinEntry { name, entry });
    }

    // Default binary: src/main.rs maps to the package name (unless already added).
    if let Some(pkg) = &pkg_name {
        let main_rs = root.join("src").join("main.rs");
        if main_rs.is_file() && seen_names.insert(pkg.clone()) {
            out.push(BinEntry {
                name: pkg.clone(),
                entry: Some(main_rs),
            });
        }
    }

    // Auto-discovered binaries under src/bin/.
    let bindir = root.join("src").join("bin");
    if let Ok(entries) = std::fs::read_dir(&bindir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() && p.extension().is_some_and(|x| x == "rs") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str())
                    && seen_names.insert(stem.to_string())
                {
                    out.push(BinEntry {
                        name: stem.to_string(),
                        entry: Some(p),
                    });
                }
            } else if p.is_dir() {
                let main = p.join("main.rs");
                if let Some(dirname) = p.file_name().and_then(|s| s.to_str())
                    && main.is_file()
                    && seen_names.insert(dirname.to_string())
                {
                    out.push(BinEntry {
                        name: dirname.to_string(),
                        entry: Some(main),
                    });
                }
            }
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Resolves a single binary's entry source file given its name and optional
/// explicit `path`.
fn resolve_entry(
    root: &Path,
    name: &str,
    path: Option<&str>,
    pkg_name: Option<&str>,
) -> Option<PathBuf> {
    if let Some(p) = path {
        let abs = root.join(p);
        return abs.is_file().then_some(abs);
    }
    let candidates = [
        root.join("src").join("bin").join(format!("{name}.rs")),
        root.join("src").join("bin").join(name).join("main.rs"),
    ];
    if let Some(found) = candidates.into_iter().find(|p| p.is_file()) {
        return Some(found);
    }
    // A bin sharing the package name defaults to src/main.rs.
    if pkg_name == Some(name) {
        let main_rs = root.join("src").join("main.rs");
        if main_rs.is_file() {
            return Some(main_rs);
        }
    }
    None
}

/// Minimal parse: returns `(package_name, package_version, bin_specs)`.
fn parse_manifest(text: &str) -> Result<(Option<String>, Option<String>, Vec<BinSpec>)> {
    let mut package_name = None;
    let mut package_version = None;
    let mut bins: Vec<BinSpec> = Vec::new();

    #[derive(PartialEq)]
    enum Section {
        Other,
        Package,
        Bin,
    }
    let mut section = Section::Other;
    let mut current: BinSpec = BinSpec::default();
    let mut in_bin = false;

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            // Flush a finished [[bin]] table.
            if in_bin {
                bins.push(std::mem::take(&mut current));
            }
            in_bin = false;
            let header = header.trim_end_matches(']');
            section = match header.trim_start_matches('[').trim() {
                "package" => Section::Package,
                "bin" if raw.contains("[[bin]]") => {
                    in_bin = true;
                    Section::Bin
                }
                _ => Section::Other,
            };
            continue;
        }
        if let Some((key, val)) = split_kv(line) {
            match (key, &section) {
                ("name", Section::Package) => package_name = unquote(val),
                ("name", Section::Bin) => current.name = unquote(val),
                ("path", Section::Bin) => current.path = unquote(val),
                ("version", Section::Package) => package_version = unquote(val),
                _ => {}
            }
        }
    }
    if in_bin {
        bins.push(current);
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
