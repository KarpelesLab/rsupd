//! Build script: expose the exact Rust target triple of the crate being
//! compiled as a runtime constant.
//!
//! Cargo sets `TARGET` for build scripts but does not pass it through to normal
//! code. We re-export it as a `rustc-env` so `rsupd::TARGET` can name the triple
//! the program is running on — which is the same string used to lay binaries
//! out under `target/<triple>/release` on the producer side.

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=RSUPD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
