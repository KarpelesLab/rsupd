//! A static self-check for consumer projects: does each binary entry point wire
//! up the rsupd updater, and with the project's correct fingerprint?
//!
//! This is a best-effort source scan, not a compiler. It reads each `[[bin]]`
//! entry file plus the rest of `src/`, looks for the updater being constructed,
//! and checks that the project fingerprint is embedded somewhere. When something
//! is missing it produces copy-paste guidance covering both short-running
//! commands (a `--update` flag) and long-running daemons (hourly background
//! checks).

use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::identity::Identity;
use crate::package::{BinEntry, bin_entries, discover};

/// Source markers that indicate the updater is being wired up.
const WIRE_MARKERS: &[&str] = &[
    "Updater::builder",
    "spawn_auto_update",
    "auto_update(",
    "rsupd::Updater",
];

/// Whether (and how correctly) the project fingerprint is embedded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintState {
    /// The project's fingerprint was found embedded (hex literal or `.fpr` file).
    Matches,
    /// A fingerprint/`.fpr` was found but it does not match the project's.
    Mismatch,
    /// The updater is wired but no matching fingerprint was located.
    NotFound,
    /// No identity exists to compare against (run `rsupd id init` first).
    Unknown,
}

/// Per-binary wiring result.
#[derive(Debug, Clone)]
pub struct BinReport {
    /// Binary name.
    pub name: String,
    /// Entry-point source file, if it could be located.
    pub entry: Option<PathBuf>,
    /// Whether the updater appears to be wired up in this entry file.
    pub wired: bool,
}

/// The full self-check result.
#[derive(Debug, Clone)]
pub struct DoctorReport {
    /// Project name.
    pub project: String,
    /// Project fingerprint (hex), or `None` if no identity is configured.
    pub fingerprint_hex: Option<String>,
    /// Crate-wide fingerprint embedding state.
    pub fingerprint: FingerprintState,
    /// Per-binary reports.
    pub bins: Vec<BinReport>,
    /// Whether the updater is wired anywhere in `src/` (even if not in an entry).
    pub crate_wired: bool,
    /// Whether a `build.rs` capturing the build identity is present (so the
    /// updater can detect newer builds of the same version).
    pub build_identity: bool,
    /// Path of a detected CI build config (GitHub/GitLab), if any.
    pub ci_config: Option<String>,
}

impl DoctorReport {
    /// True when every binary is wired and the correct fingerprint is embedded.
    pub fn ok(&self) -> bool {
        !self.bins.is_empty()
            && self.bins.iter().all(|b| b.wired)
            && self.fingerprint == FingerprintState::Matches
    }
}

/// Runs the self-check against `project_dir`. `project_override` names the rsupd
/// identity to compare fingerprints against (defaults to the Cargo package name).
pub fn check(project_dir: &Path, project_override: Option<&str>) -> Result<DoctorReport> {
    let discovered = discover(project_dir)?;
    let project = project_override
        .map(str::to_string)
        .unwrap_or_else(|| discovered.name.clone());

    // The fingerprint to look for (public half only, no password needed).
    let fingerprint = Identity::load_public(&project)
        .ok()
        .map(|p| p.fingerprint());
    let fingerprint_hex = fingerprint.map(|f| hex(&f));

    // Corpus: every .rs file under src/.
    let corpus = read_src_corpus(project_dir);
    let crate_wired = corpus.iter().any(|(_, text)| has_wire_markers(text));

    let bins = bin_entries(project_dir)?
        .into_iter()
        .map(|b: BinEntry| {
            let wired = b
                .entry
                .as_deref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|t| has_wire_markers(&t))
                .unwrap_or(false);
            BinReport {
                name: b.name,
                entry: b.entry,
                wired,
            }
        })
        .collect::<Vec<_>>();

    let fingerprint_state = fingerprint_state(project_dir, fingerprint.as_ref(), &corpus);

    Ok(DoctorReport {
        project,
        fingerprint_hex,
        fingerprint: fingerprint_state,
        bins,
        crate_wired,
        build_identity: has_build_identity(project_dir),
        ci_config: detect_ci_config(project_dir),
    })
}

/// Whether a `build.rs` is present that emits the build identity the updater
/// uses (detected by the `RSUPD_BUILD_UNIX` emit).
fn has_build_identity(project_dir: &Path) -> bool {
    std::fs::read_to_string(project_dir.join("build.rs"))
        .map(|t| t.contains("RSUPD_BUILD_UNIX"))
        .unwrap_or(false)
}

/// Finds a CI build config (`.gitlab-ci.yml` or a `.github/workflows/*.yml`).
fn detect_ci_config(project_dir: &Path) -> Option<String> {
    let gitlab = project_dir.join(".gitlab-ci.yml");
    if gitlab.exists() {
        return Some(gitlab.display().to_string());
    }
    let workflows = project_dir.join(".github").join("workflows");
    let entries = std::fs::read_dir(&workflows).ok()?;
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            return Some(p.display().to_string());
        }
    }
    None
}

fn has_wire_markers(text: &str) -> bool {
    WIRE_MARKERS.iter().any(|m| text.contains(m))
}

/// Determines the crate-wide fingerprint embedding state.
fn fingerprint_state(
    project_dir: &Path,
    fingerprint: Option<&[u8; 32]>,
    corpus: &[(PathBuf, String)],
) -> FingerprintState {
    let Some(fp) = fingerprint else {
        return FingerprintState::Unknown;
    };
    let want_hex = hex(fp);

    // 1. The hex digest appears literally somewhere in the sources.
    if corpus
        .iter()
        .any(|(_, t)| t.to_lowercase().contains(&want_hex))
    {
        return FingerprintState::Matches;
    }

    // 2. A `.fpr` file in the project matches (or mismatches) the fingerprint.
    let mut saw_fpr = false;
    for fpr in find_fpr_files(project_dir) {
        if let Ok(bytes) = std::fs::read(&fpr) {
            saw_fpr = true;
            if bytes == fp.as_slice() {
                return FingerprintState::Matches;
            }
        }
    }

    if saw_fpr {
        // A fingerprint file exists but none matched — likely stale.
        FingerprintState::Mismatch
    } else {
        FingerprintState::NotFound
    }
}

/// Collects `(path, text)` for every `.rs` file under `<dir>/src`.
fn read_src_corpus(project_dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    walk_rs(&project_dir.join("src"), &mut out);
    out
}

/// Largest source file we will read into the corpus; anything bigger is skipped
/// so a hostile/huge file can't blow up memory.
const MAX_RS_BYTES: u64 = 4 * 1024 * 1024;
/// Recursion bound for the source walk (belt-and-suspenders).
const MAX_WALK_DEPTH: usize = 64;

fn walk_rs(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    walk_rs_depth(dir, out, 0);
}

fn walk_rs_depth(dir: &Path, out: &mut Vec<(PathBuf, String)>, depth: usize) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        // Use the entry's own file type (no symlink traversal): a symlink could
        // form a cycle or point outside the tree, so skip symlinks entirely.
        let Ok(ft) = e.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let p = e.path();
        if ft.is_dir() {
            walk_rs_depth(&p, out, depth + 1);
        } else if ft.is_file() && p.extension().is_some_and(|x| x == "rs") {
            if e.metadata().map(|m| m.len()).unwrap_or(u64::MAX) > MAX_RS_BYTES {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                out.push((p, text));
            }
        }
    }
}

/// Finds `.fpr` files in the project root and `src/`.
fn find_fpr_files(project_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in [project_dir.to_path_buf(), project_dir.join("src")] {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "fpr") {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl DoctorReport {
    /// Renders a human-readable report, including remediation guidance when the
    /// project is not fully wired.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let tick = |b: bool| if b { "ok " } else { "MISSING" };

        s.push_str(&format!(
            "rsupd self-check for project {:?}\n",
            self.project
        ));
        match &self.fingerprint_hex {
            Some(h) => s.push_str(&format!("  fingerprint: {h}\n")),
            None => s.push_str("  fingerprint: (no identity — run `rsupd id init`)\n"),
        }
        s.push_str(&format!(
            "  fingerprint embedded: {}\n",
            match self.fingerprint {
                FingerprintState::Matches => "ok",
                FingerprintState::Mismatch => "MISMATCH (a .fpr file does not match this identity)",
                FingerprintState::NotFound => "MISSING",
                FingerprintState::Unknown => "unknown (no identity)",
            }
        ));

        if self.bins.is_empty() {
            s.push_str("  no binaries found to check\n");
        }
        for b in &self.bins {
            let where_ = b
                .entry
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(entry source not found)".into());
            s.push_str(&format!(
                "  [{}] bin {:?}  {}\n",
                tick(b.wired),
                b.name,
                where_
            ));
        }

        // Recommended-but-not-required setup for distribution + self-update.
        // Each line names the flag that sets it up when something is missing.
        s.push_str("\nRecommended for distribution & self-update:\n");
        s.push_str(&format!(
            "  [{}] build identity (build.rs)   {}\n",
            tick(self.build_identity),
            if self.build_identity {
                String::new()
            } else {
                "→ run `rsupd publish --setup-ci`".into()
            }
        ));
        match &self.ci_config {
            Some(path) => s.push_str(&format!("  [ok ] CI build config            {path}\n")),
            None => {
                s.push_str("  [MISSING] CI build config        → run `rsupd publish --setup-ci`\n")
            }
        }

        if self.ok() {
            s.push_str("\nAll binaries wire up the rsupd updater. ✓\n");
            if !self.build_identity || self.ci_config.is_none() {
                s.push_str(
                    "Some recommended items above are missing; see the flag next to each.\n",
                );
            }
            return s;
        }

        s.push_str(&guidance(self));
        s
    }
}

/// Builds the remediation guidance text.
fn guidance(report: &DoctorReport) -> String {
    let p = &report.project;
    let entry = report
        .bins
        .iter()
        .find(|b| !b.wired)
        .and_then(|b| b.entry.as_deref())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "src/main.rs".into());

    let mut g = String::new();
    g.push_str("\n--- How to wire rsupd in ---\n\n");

    if report.fingerprint == FingerprintState::Unknown {
        g.push_str(&format!(
            "0. Create the project identity (one time):\n     rsupd id init --project {p}\n\n"
        ));
    }

    g.push_str(&format!(
        "1. Export the fingerprint next to your crate (re-run if the identity changes):\n\
         \x20    rsupd id export --project {p} -o {p}.fpr\n\n"
    ));

    g.push_str(&format!(
        "2. In {entry}, embed the fingerprint and build an updater:\n\n\
         \x20    // Trust anchor: the 32-byte fingerprint of the project signing key.\n\
         \x20    const RSUPD_FINGERPRINT: &[u8] =\n\
         \x20        include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{p}.fpr\"));\n\n\
         \x20    fn rsupd_updater() -> rsupd::Result<rsupd::Updater> {{\n\
         \x20        rsupd::Updater::builder(env!(\"CARGO_PKG_NAME\"), env!(\"CARGO_PKG_VERSION\"))\n\
         \x20            .fingerprint(RSUPD_FINGERPRINT)\n\
         \x20            .channel(\"stable\")\n\
         \x20            // Build identity (from build.rs) so a same-version rebuild is\n\
         \x20            // still seen as newer; safe to drop if you don't need that.\n\
         \x20            .git_tag(env!(\"RSUPD_GIT_TAG\"))\n\
         \x20            .date_tag(rsupd::date_tag_from_unix(env!(\"RSUPD_BUILD_UNIX\")))\n\
         \x20            .transport(/* your rsupd::Transport */)\n\
         \x20            .build()\n\
         \x20    }}\n\n\
         \x20  (The RSUPD_GIT_TAG / RSUPD_BUILD_UNIX env vars come from a build.rs —\n\
         \x20   run `rsupd publish --setup-ci` to create it.)\n\n"
    ));

    g.push_str(
        "3a. SHORT-RUNNING command — add a `--update` flag that self-updates and exits:\n\n\
         \x20    fn main() {\n\
         \x20        rsupd::honor_startup_delay(); // settle briefly after a self-restart\n\
         \x20        if std::env::args().any(|a| a == \"--update\") {\n\
         \x20            match rsupd_updater().and_then(|u| u.update()) {\n\
         \x20                Ok(true)  => { println!(\"updated\"); return; }\n\
         \x20                Ok(false) => { println!(\"already up to date\"); return; }\n\
         \x20                Err(e)    => { eprintln!(\"update failed: {e}\"); std::process::exit(1); }\n\
         \x20            }\n\
         \x20        }\n\
         \x20        // ... normal command ...\n\
         \x20    }\n\n",
    );

    g.push_str(
        "3b. DAEMON / long-running — check hourly in the background and restart into\n\
         \x20   the new build automatically:\n\n\
         \x20    fn main() {\n\
         \x20        rsupd::honor_startup_delay();\n\
         \x20        if let Ok(updater) = rsupd_updater() {\n\
         \x20            updater.spawn_auto_update(false); // hourly checks; installs + restarts\n\
         \x20        }\n\
         \x20        // ... run the daemon ...\n\
         \x20    }\n\n",
    );

    if report.fingerprint == FingerprintState::Mismatch {
        g.push_str(
            "NOTE: a .fpr file was found that does not match this identity — re-run step 1\n\
             to refresh it (the signing key may have been regenerated).\n",
        );
    }

    g
}
