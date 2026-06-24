//! `rsupd` — command-line tool for managing project identities and building
//! signed release packages.
//!
//! ```text
//! rsupd id init    [--project N] [--password]
//! rsupd id show    [--project N]
//! rsupd id export  [--project N] [-o FILE]
//! rsupd build      [--project-dir DIR] [--channel C] [--target T]... [--bin B]...
//!                  [--no-compress] [-o OUT.zip]
//! rsupd inspect    PACKAGE.zip [--fingerprint HEX | --project N]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use rsupd::identity::Identity;
use rsupd::manifest::Manifest;
use rsupd::package::{self, BuildOptions};

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
        Some("inspect") => run_inspect(&rest),
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
    Ok(())
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
    targets: Vec<String>,
    bins: Vec<String>,
    password: bool,
    no_compress: bool,
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
                "--target" | "-t" => f.targets.push(take()),
                "--bin" | "-b" => f.bins.push(take()),
                "--password" => f.password = true,
                "--no-compress" => f.no_compress = true,
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
                   [--no-compress] [--project N] [-o OUT.zip]
  rsupd inspect    PACKAGE.zip [--fingerprint HEX | --project N]

Identities live under the platform config dir, e.g. ~/.config/rsupd/<project>/."
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
