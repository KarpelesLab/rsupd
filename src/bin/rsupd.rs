//! `rsupd` — command-line tool for managing project identities and building
//! signed release packages.
//!
//! ```text
//! rsupd id init    [--project N] [--password]
//! rsupd id show    [--project N]
//! rsupd id export  [--project N] [-o FILE]
//! rsupd build      [--project-dir DIR] [--channel C] [--target T]... [--bin B]...
//!                  [--naming os_arch|triple] [--no-compress] [-o OUT.zip]
//! rsupd publish    [<build flags>...] [-y] [--ci [--run ID] [--repo R] [--commit SHA]]
//! rsupd version
//! rsupd update     [--channel C]
//! rsupd inspect    PACKAGE.zip [--fingerprint HEX | --project N]
//! rsupd check      [-C DIR] [--project N]
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rsupd::identity::Identity;
use rsupd::manifest::Manifest;
use rsupd::package::{self, BuildOptions};

/// rsupd's own project fingerprint (trust anchor), embedded so `rsupd update`
/// can self-update. Produced by `rsupd id export --project rsupd`.
const FINGERPRINT: &[u8] = include_bytes!("../../rsupd.fpr");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rsupd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> rsupd::Result<()> {
    let mut args = args.iter();
    let cmd = args.next().map(String::as_str);
    let rest: Vec<String> = args.cloned().collect();
    match cmd {
        Some("id") => run_id(&rest),
        Some("build") => run_build(&rest),
        Some("publish") => run_publish(&rest),
        Some("inspect") => run_inspect(&rest),
        Some("check") => run_check(&rest),
        Some("version") | Some("--version") | Some("-V") => run_version(),
        Some("update") => run_update(&rest),
        Some("help") | Some("--help") | Some("-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => Err(err(format!("unknown command {other:?}; try `rsupd help`"))),
    }
}

fn run_id(args: &[String]) -> rsupd::Result<()> {
    let mut it = args.iter();
    let sub = it.next().map(String::as_str);
    let rest: Vec<String> = it.cloned().collect();
    let opts = Flags::parse(&rest);
    let project = opts.project_or_detect()?;

    match sub {
        Some("init") => {
            let password = opts.read_password_if_set("Set a keychain password: ")?;
            let id = Identity::create(&project, password.as_deref())?;
            println!("created identity for project {project:?}");
            println!("fingerprint: {}", hex(&id.fingerprint()));
            println!(
                "stored at:   {}",
                rsupd::config::identity_path(&project)?.display()
            );
            Ok(())
        }
        Some("show") => {
            // Public IDCard only — no keychain decryption, so no password needed.
            let id = Identity::load_public(&project)?;
            let card = &id.idcard;
            println!("project:     {project}");
            println!("fingerprint: {}", hex(&id.fingerprint()));
            println!("self_key:    {} bytes (PKIX)", card.self_key.len());
            println!("issued:      {}", card.issued);
            println!("subkeys:     {}", card.subkeys.len());
            for sub in &card.subkeys {
                let role = if sub.key == card.self_key {
                    " (self)"
                } else {
                    ""
                };
                println!(
                    "  - [{}] {} bytes{role}",
                    sub.purposes.join(","),
                    sub.key.len()
                );
            }
            Ok(())
        }
        Some("export") => {
            // Public fingerprint only — no password needed.
            let id = Identity::load_public(&project)?;
            let fp = id.fingerprint();
            match &opts.output {
                Some(path) => {
                    std::fs::write(path, fp)?;
                    println!("wrote {}-byte fingerprint to {}", fp.len(), path.display());
                }
                None => println!("{}", hex(&fp)),
            }
            Ok(())
        }
        _ => Err(err("usage: rsupd id <init|show|export> [--project N]")),
    }
}

fn run_build(args: &[String]) -> rsupd::Result<()> {
    let opts = Flags::parse(args);
    build_and_write(&opts)?;
    Ok(())
}

/// Builds a package from `opts`, writes the zip to disk, prints a summary, and
/// returns the built package alongside the output path it was written to. Shared
/// by `build` and `publish`.
fn build_and_write(opts: &Flags) -> rsupd::Result<(package::BuiltPackage, PathBuf)> {
    let project_dir = opts
        .project_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let password = opts.read_password_if_set("Keychain password: ")?;

    // The signing identity's project name: explicit --project, else Cargo.toml.
    let discovered = package::discover(&project_dir)?;
    let project = opts
        .project
        .clone()
        .unwrap_or_else(|| discovered.name.clone());
    let identity = Identity::load(&project, password.as_deref())?;

    let mut build = BuildOptions::new(project_dir);
    build.channel = opts.channel.clone().unwrap_or_default();
    build.targets = opts.targets.clone();
    build.bins = opts.bins.clone();
    if let Some(naming) = &opts.naming {
        build.naming = rsupd::TargetNaming::parse(naming)?;
    }
    if opts.no_compress {
        build.compression = "none".to_string();
    }

    let built = package::build_package(&identity, &build)?;
    let out = opts.output.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            "{}_{}.zip",
            built.manifest.project,
            if built.manifest.git_tag.is_empty() {
                built.manifest.date_tag.clone()
            } else {
                built.manifest.git_tag.clone()
            }
        ))
    });
    std::fs::write(&out, &built.bytes)?;

    println!("built package: {}", out.display());
    println!("  project:  {}", built.manifest.project);
    println!("  version:  {}", built.manifest.version);
    println!("  channel:  {:?}", built.manifest.channel);
    println!(
        "  git/date: {}/{}",
        built.manifest.git_tag, built.manifest.date_tag
    );
    for a in &built.manifest.artifacts {
        println!(
            "  artifact: {} ({}, {} -> {} bytes)",
            a.target, a.compression, a.raw_size, a.size
        );
    }
    Ok((built, out))
}

fn run_publish(args: &[String]) -> rsupd::Result<()> {
    let mut opts = Flags::parse(args);

    // --setup-ci: scaffold the CI build config and exit, without publishing.
    if opts.setup_ci {
        let project_dir = opts
            .project_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        return run_setup_ci(&project_dir, &opts);
    }

    // --ci: instead of reading binaries from the local target/ tree, download
    // them from a GitHub Actions run and stage them so the normal build picks
    // them up. Restrict the build to exactly the targets we staged.
    if opts.ci {
        let project_dir = opts
            .project_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        let staged = stage_ci_binaries(&project_dir, &opts)?;
        if staged.is_empty() {
            return Err(err(
                "no binaries matching this project's [[bin]] names were found in the CI artifacts",
            ));
        }
        println!("ci: staged targets: {}", staged.join(", "));
        opts.targets = staged;
    }

    let (built, out) = build_and_write(&opts)?;

    let filename = out
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| format!("{}.zip", built.manifest.project));

    println!();
    println!(
        "About to upload {} ({} bytes) via {}",
        filename,
        built.bytes.len(),
        rsupd::publish::UPLOAD_ENDPOINT,
    );
    if !opts.assume_yes && !confirm("Upload this release? [y/N] ")? {
        println!("aborted; package left at {}", out.display());
        return Ok(());
    }

    let result = rsupd::publish::upload_package(&filename, built.bytes, opts.verbose)?;
    println!("upload complete:");
    println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    Ok(())
}

/// Which CI provider's artifacts to pull from.
enum CiProvider {
    GitHub,
    GitLab,
}

/// Creates/updates the CI build config for the detected provider so it produces
/// one triple-named artifact per target — the layout `--ci` consumes. The build
/// config is generated from the project's own `[[bin]]` names.
fn run_setup_ci(project_dir: &Path, opts: &Flags) -> rsupd::Result<()> {
    let bins = package::discover(project_dir)?.bins;
    if bins.is_empty() {
        return Err(err("no [[bin]] targets found to build"));
    }
    match detect_provider(project_dir, opts)? {
        CiProvider::GitHub => setup_github_ci(project_dir, &bins),
        CiProvider::GitLab => setup_gitlab_ci(project_dir, &bins),
    }
}

/// Writes `.github/workflows/build.yml` (a dedicated file we own).
fn setup_github_ci(project_dir: &Path, bins: &[String]) -> rsupd::Result<()> {
    let mut paths = String::new();
    for b in bins {
        for ext in ["", ".exe"] {
            paths.push_str("            target/${{ matrix.target }}/release/");
            paths.push_str(b);
            paths.push_str(ext);
            paths.push('\n');
        }
    }
    let content = GITHUB_BUILD_YML
        .replace("__ARTIFACT_PATHS__\n", &paths)
        .replace("__BINS__", &bins.join(" "));

    let dir = project_dir.join(".github").join("workflows");
    std::fs::create_dir_all(&dir)?;
    write_ci_file(&dir.join("build.yml"), &content)
}

/// Creates or edits `.gitlab-ci.yml`, managing only an rsupd-marked block so an
/// existing pipeline is preserved.
fn setup_gitlab_ci(project_dir: &Path, bins: &[String]) -> rsupd::Result<()> {
    let mut unix = String::new();
    let mut win = String::new();
    for b in bins {
        unix.push_str("      - target/$RSUPD_TARGET/release/");
        unix.push_str(b);
        unix.push('\n');
        win.push_str("      - target/$RSUPD_TARGET/release/");
        win.push_str(b);
        win.push_str(".exe\n");
    }
    let block = GITLAB_CI_BLOCK
        .replace("__UNIX_PATHS__\n", &unix)
        .replace("__WIN_PATHS__\n", &win);

    let (begin, end) = ("# >>> rsupd-ci >>>", "# <<< rsupd-ci <<<");
    let path = project_dir.join(".gitlab-ci.yml");

    if !path.exists() {
        let content = format!("# GitLab CI generated by `rsupd publish --setup-ci`.\n\n{block}");
        std::fs::write(&path, content)?;
        println!("ci: created {}", path.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&path)?;
    let updated = match (content.find(begin), content.find(end)) {
        (Some(s), Some(e)) if e > s => {
            // Replace the existing managed block in place.
            format!("{}{}{}", &content[..s], block.trim_end(), &content[e + end.len()..])
        }
        _ => {
            // Append a fresh managed block, preserving the rest of the file.
            let sep = if content.ends_with('\n') { "\n" } else { "\n\n" };
            format!("{content}{sep}{block}")
        }
    };
    if updated == content {
        println!("ci: {} already up to date", path.display());
    } else {
        std::fs::write(&path, updated)?;
        println!("ci: updated rsupd jobs in {}", path.display());
    }
    Ok(())
}

/// Writes `content` to `path`, reporting whether it created, updated, or left it.
fn write_ci_file(path: &Path, content: &str) -> rsupd::Result<()> {
    let existed = path.exists();
    if existed && std::fs::read_to_string(path).ok().as_deref() == Some(content) {
        println!("ci: {} already up to date", path.display());
        return Ok(());
    }
    std::fs::write(path, content)?;
    println!(
        "ci: {} {}",
        if existed { "updated" } else { "created" },
        path.display()
    );
    Ok(())
}

/// Detects the CI provider for `project_dir`: an explicit `--provider`, else the
/// CI config file that is present (`.gitlab-ci.yml` / `.github/workflows/`),
/// else the `origin` remote host.
fn detect_provider(project_dir: &Path, opts: &Flags) -> rsupd::Result<CiProvider> {
    if let Some(p) = &opts.provider {
        return match p.to_ascii_lowercase().as_str() {
            "github" | "gh" => Ok(CiProvider::GitHub),
            "gitlab" | "gl" => Ok(CiProvider::GitLab),
            other => Err(err(format!(
                "unknown --provider {other:?} (use github or gitlab)"
            ))),
        };
    }
    if project_dir.join(".gitlab-ci.yml").exists() {
        return Ok(CiProvider::GitLab);
    }
    if project_dir.join(".github").join("workflows").is_dir() {
        return Ok(CiProvider::GitHub);
    }
    if let Ok(url) = run_cmd_in(project_dir, "git", &["remote", "get-url", "origin"]) {
        if url.contains("gitlab") {
            return Ok(CiProvider::GitLab);
        }
        if url.contains("github") {
            return Ok(CiProvider::GitHub);
        }
    }
    Err(err(
        "could not detect a CI provider; pass --provider github|gitlab",
    ))
}

/// Downloads a CI run's artifacts and stages any compiled project binaries into
/// `target/<triple>/release/`, returning the staged target triples.
///
/// Convention (both providers): one artifact / job **named after the Rust
/// target triple**, containing the compiled binary (`<bin>` or `<bin>.exe`).
/// Requires the provider's CLI (`gh` or `glab`), authenticated for the repo.
fn stage_ci_binaries(project_dir: &Path, opts: &Flags) -> rsupd::Result<Vec<String>> {
    let bins = package::discover(project_dir)?.bins;
    let tmp = std::env::temp_dir().join(format!("rsupd-ci-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;

    match detect_provider(project_dir, opts)? {
        CiProvider::GitHub => download_github_artifacts(project_dir, opts, &tmp)?,
        CiProvider::GitLab => download_gitlab_artifacts(project_dir, opts, &tmp)?,
    }

    let staged = stage_from_dir(&tmp, &bins, project_dir)?;
    std::fs::remove_dir_all(&tmp).ok();
    Ok(staged)
}

/// Stages binaries from a download tree whose immediate subdirectories are each
/// named after a target triple. Returns the triples that yielded a binary.
fn stage_from_dir(tmp: &Path, bins: &[String], project_dir: &Path) -> rsupd::Result<Vec<String>> {
    let mut staged = Vec::new();
    for entry in std::fs::read_dir(tmp)? {
        let dir = entry?.path();
        if !dir.is_dir() {
            continue;
        }
        let triple = dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let mut staged_any = false;
        for bin in bins {
            let names = [bin.clone(), format!("{bin}.exe")];
            if let Some(src) = find_file(&dir, &names) {
                let destdir = project_dir.join("target").join(&triple).join("release");
                std::fs::create_dir_all(&destdir)?;
                let fname = src.file_name().unwrap_or_default();
                std::fs::copy(&src, destdir.join(fname))?;
                staged_any = true;
            }
        }
        if staged_any {
            staged.push(triple);
        }
    }
    Ok(staged)
}

/// GitHub: resolve the repo + run, then `gh run download` all artifacts into
/// `tmp` (each extracts to `<tmp>/<artifact-name>/`).
fn download_github_artifacts(project_dir: &Path, opts: &Flags, tmp: &Path) -> rsupd::Result<()> {
    let repo = match &opts.repo {
        Some(r) => r.clone(),
        None => run_cmd_in(
            project_dir,
            "gh",
            &["repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
        )?,
    };
    let run_id = match &opts.run_id {
        Some(r) => r.clone(),
        None => resolve_github_run(project_dir, &repo, opts.commit.as_deref())?,
    };
    println!("ci: downloading GitHub artifacts from {repo} run {run_id}");
    let tmp_str = tmp.to_string_lossy().into_owned();
    run_cmd_in(
        project_dir,
        "gh",
        &["run", "download", &run_id, "-R", &repo, "-D", &tmp_str],
    )?;
    Ok(())
}

/// Picks the newest successful GitHub run for `commit` (default `HEAD`) that
/// actually has artifacts, so an artifact-less run (e.g. a release-only
/// workflow) is skipped. Override with `--run`.
fn resolve_github_run(
    project_dir: &Path,
    repo: &str,
    commit: Option<&str>,
) -> rsupd::Result<String> {
    let sha = match commit {
        Some(c) => c.to_string(),
        None => run_cmd_in(project_dir, "git", &["rev-parse", "HEAD"])?,
    };
    let ids = run_cmd_in(
        project_dir,
        "gh",
        &[
            "api",
            &format!("repos/{repo}/actions/runs?head_sha={sha}&per_page=30"),
            "-q",
            "[.workflow_runs[] | select(.conclusion==\"success\")] | sort_by(.created_at) | reverse | .[].id",
        ],
    )?;
    for id in ids.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let count = run_cmd_in(
            project_dir,
            "gh",
            &[
                "api",
                &format!("repos/{repo}/actions/runs/{id}/artifacts"),
                "-q",
                ".total_count",
            ],
        )?;
        if count.trim().parse::<i64>().unwrap_or(0) > 0 {
            return Ok(id.to_string());
        }
    }
    Err(err(format!(
        "no successful CI run with artifacts found for commit {sha}; pass --run <id>"
    )))
}

/// GitLab: find the newest successful pipeline for the ref, then download each
/// of its artifact-bearing jobs into `<tmp>/<job-name>/` via `glab`. `glab api`
/// has no jq filter, so responses are parsed here.
fn download_gitlab_artifacts(project_dir: &Path, opts: &Flags, tmp: &Path) -> rsupd::Result<()> {
    // `glab job artifact` works on a ref; prefer --commit (a branch or sha),
    // else the current branch.
    let ref_name = match &opts.commit {
        Some(c) => c.clone(),
        None => run_cmd_in(project_dir, "git", &["rev-parse", "--abbrev-ref", "HEAD"])?,
    };

    let pipelines = run_cmd_in(
        project_dir,
        "glab",
        &[
            "api",
            &format!("projects/:id/pipelines?ref={ref_name}&status=success&per_page=20"),
        ],
    )?;
    let pipelines: serde_json::Value = serde_json::from_str(&pipelines)
        .map_err(|e| err(format!("parsing GitLab pipelines: {e}")))?;
    // GitLab returns pipelines newest-first.
    let pid = pipelines
        .as_array()
        .and_then(|a| a.first())
        .and_then(|p| p.get("id"))
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| err(format!("no successful GitLab pipeline for ref {ref_name:?}")))?;

    let jobs = run_cmd_in(
        project_dir,
        "glab",
        &["api", &format!("projects/:id/pipelines/{pid}/jobs?per_page=100")],
    )?;
    let jobs: serde_json::Value =
        serde_json::from_str(&jobs).map_err(|e| err(format!("parsing GitLab jobs: {e}")))?;
    let job_names: Vec<String> = jobs
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|j| j.get("artifacts_file").is_some_and(|v| !v.is_null()))
                .filter_map(|j| j.get("name").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    println!("ci: downloading GitLab artifacts from pipeline {pid} (ref {ref_name})");
    let mut any = false;
    for job in &job_names {
        let dest = tmp.join(job);
        std::fs::create_dir_all(&dest)?;
        let dest_str = dest.to_string_lossy().into_owned();
        let mut args = vec!["job", "artifact", ref_name.as_str(), job.as_str(), "-p", &dest_str];
        if let Some(r) = &opts.repo {
            args.push("-R");
            args.push(r);
        }
        // Best effort: a job whose artifact holds none of our binaries is just
        // skipped later by stage_from_dir.
        if run_cmd_in(project_dir, "glab", &args).is_ok() {
            any = true;
        }
    }
    if !any {
        return Err(err(format!(
            "no artifacts could be downloaded from GitLab pipeline {pid}"
        )));
    }
    Ok(())
}

/// GitHub Actions workflow scaffolded by `--setup-ci`. `__ARTIFACT_PATHS__` is
/// replaced with the project's per-bin artifact paths and `__BINS__` with the
/// space-separated bin names (for the macOS `lipo` loop).
const GITHUB_BUILD_YML: &str = r#"name: Build binaries

# Generated by `rsupd publish --setup-ci`. Each job builds the project for one
# Rust target triple and uploads the compiled binary as an artifact named after
# that triple — the layout `rsupd publish --ci` consumes. macOS is built as a
# single universal (fat) binary and published under both Apple targets.

on:
  push:
    branches: [master]
    tags: ['v*']
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: build-${{ github.ref }}
  cancel-in-progress: true

jobs:
  build:
    name: ${{ matrix.target }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: ubuntu-latest
            target: aarch64-unknown-linux-gnu
            apt: gcc-aarch64-linux-gnu
            linker: aarch64-linux-gnu-gcc
          - os: ubuntu-latest
            target: armv7-unknown-linux-gnueabihf
            apt: gcc-arm-linux-gnueabihf
            linker: arm-linux-gnueabihf-gcc
          - os: windows-latest
            target: x86_64-pc-windows-msvc
          - os: windows-latest
            target: aarch64-pc-windows-msvc

    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Configure cross linker
        if: matrix.linker != ''
        run: |
          sudo apt-get update
          sudo apt-get install -y ${{ matrix.apt }}
          echo "CARGO_TARGET_$(echo ${{ matrix.target }} | tr 'a-z-' 'A-Z_')_LINKER=${{ matrix.linker }}" >> "$GITHUB_ENV"

      - name: Build
        run: cargo build --release --locked --target ${{ matrix.target }}

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.target }}
          # Only one of each pair exists per OS; the other glob matches nothing.
          path: |
__ARTIFACT_PATHS__
          if-no-files-found: error

  # macOS: build both arches and fuse them into one universal binary, published
  # under each Apple target so a consumer matches by its own arch.
  macos-universal:
    name: apple-darwin (universal)
    runs-on: macos-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v6

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-apple-darwin,aarch64-apple-darwin

      - name: Build universal binaries
        run: |
          cargo build --release --locked --target x86_64-apple-darwin
          cargo build --release --locked --target aarch64-apple-darwin
          mkdir -p universal
          for bin in __BINS__; do
            lipo -create -output "universal/$bin" \
              "target/x86_64-apple-darwin/release/$bin" \
              "target/aarch64-apple-darwin/release/$bin"
          done

      - name: Upload x86_64-apple-darwin
        uses: actions/upload-artifact@v4
        with:
          name: x86_64-apple-darwin
          path: universal/
          if-no-files-found: error

      - name: Upload aarch64-apple-darwin
        uses: actions/upload-artifact@v4
        with:
          name: aarch64-apple-darwin
          path: universal/
          if-no-files-found: error
"#;

/// GitLab CI jobs scaffolded by `--setup-ci`, wrapped in markers so the block
/// can be re-edited in place. `__UNIX_PATHS__` / `__WIN_PATHS__` are replaced
/// with per-bin artifact paths. Job name == target triple (what `--ci` expects).
const GITLAB_CI_BLOCK: &str = r#"# >>> rsupd-ci >>> (managed by `rsupd publish --setup-ci`; this block is regenerated)
# Each job builds the project for one Rust target triple; the job is named after
# that triple and its compiled binary is the job artifact, so `rsupd publish
# --ci` can download it. `build` is a default GitLab stage.
.rsupd-build-linux:
  stage: build
  image: rust:latest
  script:
    - rustup target add "$RSUPD_TARGET"
    - cargo build --release --locked --target "$RSUPD_TARGET"
  artifacts:
    expire_in: 1 week
    paths:
__UNIX_PATHS__

x86_64-unknown-linux-gnu:
  extends: .rsupd-build-linux
  variables:
    RSUPD_TARGET: x86_64-unknown-linux-gnu

aarch64-unknown-linux-gnu:
  extends: .rsupd-build-linux
  variables:
    RSUPD_TARGET: aarch64-unknown-linux-gnu
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER: aarch64-linux-gnu-gcc
  before_script:
    - apt-get update && apt-get install -y gcc-aarch64-linux-gnu

# macOS and Windows need GitLab runners for those platforms. The tags below are
# for GitLab.com SaaS runners; change them to match your instance.
aarch64-apple-darwin:
  stage: build
  tags: [saas-macos-medium-m1]
  image: macos-14-xcode-15
  variables:
    RSUPD_TARGET: aarch64-apple-darwin
  script:
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source "$HOME/.cargo/env"
    - rustup target add "$RSUPD_TARGET"
    - cargo build --release --locked --target "$RSUPD_TARGET"
  artifacts:
    expire_in: 1 week
    paths:
__UNIX_PATHS__

x86_64-apple-darwin:
  stage: build
  tags: [saas-macos-medium-m1]
  image: macos-14-xcode-15
  variables:
    RSUPD_TARGET: x86_64-apple-darwin
  script:
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source "$HOME/.cargo/env"
    - rustup target add "$RSUPD_TARGET"
    - cargo build --release --locked --target "$RSUPD_TARGET"
  artifacts:
    expire_in: 1 week
    paths:
__UNIX_PATHS__

x86_64-pc-windows-msvc:
  stage: build
  tags: [saas-windows-medium-amd64]
  variables:
    RSUPD_TARGET: x86_64-pc-windows-msvc
  script:
    - Invoke-WebRequest -Uri https://win.rustup.rs -OutFile rustup-init.exe
    - .\rustup-init.exe -y --default-toolchain stable --profile minimal
    - $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    - cargo build --release --locked --target $env:RSUPD_TARGET
  artifacts:
    expire_in: 1 week
    paths:
__WIN_PATHS__
# <<< rsupd-ci <<<
"#;

/// Recursively finds the first file under `root` whose name matches any of
/// `names`.
fn find_file(root: &Path, names: &[String]) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|s| s.to_str())
                && names.iter().any(|n| n == name)
            {
                return Some(path);
            }
        }
    }
    None
}

/// Runs `program args...` in `dir`, returning trimmed stdout, or an error
/// carrying stderr. Running in `dir` lets `gh`/`glab` auto-resolve the repo.
fn run_cmd_in(dir: &Path, program: &str, args: &[&str]) -> rsupd::Result<String> {
    let out = std::process::Command::new(program)
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| err(format!("running `{program}`: {e}")))?;
    if !out.status.success() {
        return Err(err(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Prompts on stderr and returns true only for an explicit yes.
fn confirm(prompt: &str) -> rsupd::Result<bool> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| err(format!("reading confirmation: {e}")))?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(ans == "y" || ans == "yes")
}

fn run_version() -> rsupd::Result<()> {
    println!("rsupd {}", env!("CARGO_PKG_VERSION"));
    let (git, date) = (rsupd::BUILD_GIT_TAG, rsupd::build_date_tag());
    if !git.is_empty() || !date.is_empty() {
        let git = if git.is_empty() { "unknown" } else { git };
        println!("build:  {git} {date}");
    }
    println!("target: {}", rsupd::TARGET);
    Ok(())
}

fn run_update(args: &[String]) -> rsupd::Result<()> {
    let opts = Flags::parse(args);
    let channel = opts.channel.clone().unwrap_or_default();

    let transport = rsupd::HttpTransport::new(FINGERPRINT);
    let updater = rsupd::Updater::builder("rsupd", env!("CARGO_PKG_VERSION"))
        .fingerprint(FINGERPRINT)
        .channel(channel)
        // Feed in this build's identity so a same-version release only updates
        // when it is a strictly newer build (by git date); an identical build
        // (same git hash) is skipped.
        .date_tag(rsupd::build_date_tag())
        .git_tag(rsupd::BUILD_GIT_TAG)
        // A CLI just swaps its binary in place; the next invocation is the new one.
        .auto_restart(false)
        .transport(Box::new(transport))
        .build()?;

    match updater.check()? {
        None => {
            println!("rsupd is up to date (v{})", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(available) => {
            let version = available.version().to_string();
            println!("updating rsupd {} -> {version} ...", env!("CARGO_PKG_VERSION"));
            let installed = updater.install(&available)?;
            println!("installed v{version} to {}", installed.display());
            Ok(())
        }
    }
}

fn run_inspect(args: &[String]) -> rsupd::Result<()> {
    let opts = Flags::parse(args);
    let pkg = opts
        .positional
        .first()
        .ok_or_else(|| err("usage: rsupd inspect PACKAGE.zip [--fingerprint HEX | --project N]"))?;
    let bytes = std::fs::read(pkg)?;
    let reader = rsupd::package::zip::ZipReader::new(&bytes)?;
    let signed = reader.read(rsupd::package::MANIFEST_ENTRY)?;

    // Determine the fingerprint to verify against.
    let fingerprint = if let Some(hexfp) = &opts.fingerprint {
        unhex(hexfp)?
    } else if let Some(project) = &opts.project {
        Identity::load(project, None)?.fingerprint().to_vec()
    } else {
        // No anchor given: verify self-consistency against the embedded IDCard.
        let manifest = Manifest::from_cbor(&signed_payload(&signed)?)?;
        let card = bottlers::IDCard::from_signed(&manifest.idcard)?;
        rsupd::identity::fingerprint_of(&card.self_key).to_vec()
    };

    let manifest = Manifest::open_and_verify(&signed, &fingerprint)?;
    println!("signature: OK");
    println!("project:   {}", manifest.project);
    println!("version:   {}", manifest.version);
    println!("channel:   {:?}", manifest.channel);
    println!("git/date:  {}/{}", manifest.git_tag, manifest.date_tag);
    println!("released:  {}", manifest.released);
    println!("artifacts:");
    for a in &manifest.artifacts {
        println!(
            "  {:<32} {:<6} {} -> {} bytes  {}:{}",
            a.target,
            a.compression,
            a.raw_size,
            a.size,
            a.hash.method,
            hex(&a.hash.value)
        );
    }
    Ok(())
}

fn run_check(args: &[String]) -> rsupd::Result<()> {
    let opts = Flags::parse(args);
    let project_dir = opts
        .project_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let report = rsupd::doctor::check(&project_dir, opts.project.as_deref())?;
    print!("{}", report.render());
    if report.ok() {
        Ok(())
    } else {
        // Non-zero exit so this is usable as a CI / pre-release gate.
        Err(err("rsupd is not fully wired in (see guidance above)"))
    }
}

/// Opens a signed bottle and returns the raw manifest payload (no verification).
fn signed_payload(signed: &[u8]) -> rsupd::Result<Vec<u8>> {
    let (payload, _info) = bottlers::Opener::empty().open_cbor(signed)?;
    Ok(payload)
}

// --- flag parsing -------------------------------------------------------

#[derive(Default)]
struct Flags {
    project: Option<String>,
    project_dir: Option<PathBuf>,
    channel: Option<String>,
    output: Option<PathBuf>,
    fingerprint: Option<String>,
    naming: Option<String>,
    targets: Vec<String>,
    bins: Vec<String>,
    password: bool,
    no_compress: bool,
    assume_yes: bool,
    verbose: bool,
    ci: bool,
    setup_ci: bool,
    provider: Option<String>,
    run_id: Option<String>,
    repo: Option<String>,
    commit: Option<String>,
    positional: Vec<String>,
}

impl Flags {
    fn parse(args: &[String]) -> Self {
        let mut f = Flags::default();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            let mut take = || {
                i += 1;
                args.get(i).cloned().unwrap_or_default()
            };
            match a {
                "--project" | "-p" => f.project = Some(take()),
                "--project-dir" | "-C" => f.project_dir = Some(PathBuf::from(take())),
                "--channel" | "-c" => f.channel = Some(take()),
                "--output" | "-o" => f.output = Some(PathBuf::from(take())),
                "--fingerprint" => f.fingerprint = Some(take()),
                "--naming" => f.naming = Some(take()),
                "--target" | "-t" => f.targets.push(take()),
                "--bin" | "-b" => f.bins.push(take()),
                "--password" => f.password = true,
                "--no-compress" => f.no_compress = true,
                "--yes" | "-y" => f.assume_yes = true,
                "--verbose" | "-v" => f.verbose = true,
                "--ci" => f.ci = true,
                "--setup-ci" => f.setup_ci = true,
                "--provider" => f.provider = Some(take()),
                "--run" => f.run_id = Some(take()),
                "--repo" => f.repo = Some(take()),
                "--commit" => f.commit = Some(take()),
                other => f.positional.push(other.to_string()),
            }
            i += 1;
        }
        f
    }

    fn project_or_detect(&self) -> rsupd::Result<String> {
        if let Some(p) = &self.project {
            return Ok(p.clone());
        }
        let dir = self
            .project_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        match package::discover(&dir) {
            Ok(d) => Ok(d.name),
            Err(_) => Err(err("could not detect project name; pass --project NAME")),
        }
    }

    fn read_password_if_set(&self, prompt: &str) -> rsupd::Result<Option<Vec<u8>>> {
        if !self.password {
            return Ok(None);
        }
        eprint!("{prompt}");
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| err(format!("reading password: {e}")))?;
        Ok(Some(
            line.trim_end_matches(['\n', '\r']).as_bytes().to_vec(),
        ))
    }
}

fn print_usage() {
    eprintln!(
        "rsupd — signed release distribution

USAGE:
  rsupd id init    [--project N] [--password]
  rsupd id show    [--project N] [--password]
  rsupd id export  [--project N] [--password] [-o FILE]
  rsupd build      [-C DIR] [--channel C] [--target T]... [--bin B]...
                   [--naming os_arch|triple] [--no-compress] [--project N] [-o OUT.zip]
  rsupd publish    [<build flags>...] [-y] [-v]
                   [--ci [--provider github|gitlab] [--run ID]
                         [--repo OWNER/REPO] [--commit SHA|REF]]
                   [--setup-ci [--provider github|gitlab]]
  rsupd version
  rsupd update     [--channel C]
  rsupd inspect    PACKAGE.zip [--fingerprint HEX | --project N]
  rsupd check      [-C DIR] [--project N]

Identities live under the platform config dir, e.g. ~/.config/rsupd/<project>/.

`publish` builds (like `build`), confirms, then uploads to Cloud/Rust:upload.
With `--ci`, binaries are downloaded from a CI run instead of the local target/
tree: each build job must publish one artifact named after its Rust target
triple, containing the compiled binary. The provider is auto-detected from the
CI config file (.github/workflows or .gitlab-ci.yml) and uses `gh` (GitHub) or
`glab` (GitLab); override with --provider. By default the newest successful run
for HEAD that has artifacts is used.

`--setup-ci` instead creates/edits that build config (a GitHub Actions
workflow or .gitlab-ci.yml) for the project's bins, then exits."
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(s: &str) -> rsupd::Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(err("hex string has odd length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| err(format!("bad hex: {e}"))))
        .collect()
}

fn err(msg: impl Into<String>) -> rsupd::Error {
    rsupd::Error::Other(msg.into())
}
