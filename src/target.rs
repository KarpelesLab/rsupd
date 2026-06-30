//! Mapping Rust target triples to compact `os_arch` labels (goupd convention).
//!
//! A release artifact is identified and named by an `os_arch` label such as
//! `linux_amd64` or `windows_arm64` — flat (no path separators) and matching the
//! Go/goupd naming the wider toolchain already uses. The producer derives the
//! label from each build's target triple; the consumer derives its own label
//! from [`crate::TARGET`] to pick the matching artifact.

/// Returns the `os_arch` label for a Rust target `triple`, e.g.
/// `x86_64-unknown-linux-gnu` → `linux_amd64`.
pub fn label_for_triple(triple: &str) -> String {
    format!("{}_{}", os_of(triple), arch_of(triple))
}

/// The `os_arch` label of the running build (derived from [`crate::TARGET`]).
pub fn current_label() -> String {
    label_for_triple(crate::TARGET)
}

/// Pseudo-triple under which a single macOS universal (fat) binary is published.
/// Its `os_arch` label is [`DARWIN_UNIVERSAL_LABEL`].
pub const DARWIN_UNIVERSAL_TRIPLE: &str = "universal-apple-darwin";

/// `os_arch` label of a macOS universal (fat) binary — one artifact serving
/// every Apple arch.
pub const DARWIN_UNIVERSAL_LABEL: &str = "darwin_universal";

/// Whether `triple` targets macOS/Apple (so a universal binary applies).
pub fn is_apple(triple: &str) -> bool {
    (triple.contains("apple") || triple.contains("darwin") || triple.contains("macos"))
        && !triple.contains("ios")
}

/// Derives the OS component from a triple. Order matters: `android` and the
/// BSDs must be checked before the generic substrings they may also contain.
fn os_of(triple: &str) -> &'static str {
    let t = triple;
    if t.contains("android") {
        "android"
    } else if t.contains("windows") {
        "windows"
    } else if t.contains("apple") || t.contains("darwin") || t.contains("macos") {
        if t.contains("ios") { "ios" } else { "darwin" }
    } else if t.contains("freebsd") {
        "freebsd"
    } else if t.contains("netbsd") {
        "netbsd"
    } else if t.contains("openbsd") {
        "openbsd"
    } else if t.contains("dragonfly") {
        "dragonfly"
    } else if t.contains("illumos") || t.contains("solaris") {
        "illumos"
    } else if t.contains("wasi") {
        "wasi"
    } else if t.contains("linux") {
        "linux"
    } else {
        // Fall back to the third triple component (the OS), or "unknown".
        match triple.split('-').nth(2) {
            Some(os) if !os.is_empty() => leak_unknown(os),
            _ => "unknown",
        }
    }
}

/// Derives the arch component (Go's GOARCH naming) from a triple's first field.
fn arch_of(triple: &str) -> &'static str {
    let arch = triple.split('-').next().unwrap_or("");
    match arch {
        "x86_64" | "amd64" => "amd64",
        "x86" | "i686" | "i586" | "i386" => "386",
        "aarch64" | "arm64" => "arm64",
        // A macOS universal (fat) binary built with `lipo`; not a real arch.
        "universal" => "universal",
        a if a.starts_with("armv") || a == "arm" || a.starts_with("thumbv") => "arm",
        a if a.starts_with("riscv64") => "riscv64",
        a if a.starts_with("riscv32") => "riscv32",
        a if a.starts_with("powerpc64") || a.starts_with("ppc64") => "ppc64",
        "powerpc" | "ppc" => "ppc",
        "s390x" => "s390x",
        a if a.starts_with("mips64") => "mips64",
        a if a.starts_with("mips") => "mips",
        "loongarch64" => "loong64",
        "wasm32" | "wasm64" => "wasm",
        "sparc64" => "sparc64",
        // Unknown arch: pass through unchanged (leaked to satisfy &'static).
        other => leak_unknown(other),
    }
}

/// Interns an unexpected component string so it can be returned as `&'static`.
/// Only ever hit for target triples we do not explicitly map.
fn leak_unknown(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_triples() {
        assert_eq!(label_for_triple("x86_64-unknown-linux-gnu"), "linux_amd64");
        assert_eq!(label_for_triple("x86_64-unknown-linux-musl"), "linux_amd64");
        assert_eq!(label_for_triple("aarch64-unknown-linux-gnu"), "linux_arm64");
        assert_eq!(label_for_triple("aarch64-apple-darwin"), "darwin_arm64");
        assert_eq!(label_for_triple("x86_64-apple-darwin"), "darwin_amd64");
        assert_eq!(label_for_triple("x86_64-pc-windows-msvc"), "windows_amd64");
        assert_eq!(label_for_triple("aarch64-linux-android"), "android_arm64");
        assert_eq!(
            label_for_triple("armv7-unknown-linux-gnueabihf"),
            "linux_arm"
        );
        assert_eq!(
            label_for_triple("riscv64gc-unknown-linux-gnu"),
            "linux_riscv64"
        );
    }

    #[test]
    fn macos_universal() {
        // The pseudo-triple maps to the documented universal label.
        assert_eq!(label_for_triple(DARWIN_UNIVERSAL_TRIPLE), DARWIN_UNIVERSAL_LABEL);
        assert_eq!(label_for_triple(DARWIN_UNIVERSAL_TRIPLE), "darwin_universal");
        assert!(is_apple("aarch64-apple-darwin"));
        assert!(is_apple(DARWIN_UNIVERSAL_TRIPLE));
        assert!(!is_apple("x86_64-unknown-linux-gnu"));
        assert!(!is_apple("aarch64-apple-ios"));
    }
}
