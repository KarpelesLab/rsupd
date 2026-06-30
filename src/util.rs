//! Small internal helpers shared by the producer side.

use std::path::PathBuf;

/// Resolves `program` to an absolute path by searching `PATH` **only** — never
/// the current directory.
///
/// External tools (`git`, `gh`, `glab`) are otherwise spawned by bare name with
/// the working directory set to a possibly-untrusted project dir. On Windows
/// `CreateProcess` searches the current directory before `PATH`, so a binary
/// planted in a cloned repo (`gh.exe`, `git.exe`) could be executed instead of
/// the real tool — and the publish flow pipes the private signing identity to
/// `gh secret set`. Resolving to an absolute `PATH` entry up front removes that
/// search and closes the hijack. Returns `None` if the tool is not on `PATH`.
pub fn resolve_program(program: &str) -> Option<PathBuf> {
    // An explicit path (already contains a separator) is taken as-is.
    if program.contains('/') || program.contains('\\') {
        let p = PathBuf::from(program);
        return p.is_file().then_some(p);
    }

    // On Windows a name is tried against each PATHEXT extension; elsewhere the
    // name is used verbatim.
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        vec![String::new()]
    };

    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        // An empty PATH entry denotes the current directory on some systems —
        // skip it, that is exactly what we must not search.
        if dir.as_os_str().is_empty() {
            continue;
        }
        for ext in &exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}
