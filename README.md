# rsupd

Signed release distribution and in-place auto-updates, built on the
[BottleFmt](https://github.com/BottleFmt) stack ([`bottlers`](https://crates.io/crates/bottlers)
for identity/signing, [`purecrypto`](https://crates.io/crates/purecrypto) for hashing,
[`compcol`](https://crates.io/crates/compcol) for compression).

rsupd is the Rust successor to [`goupd`](https://github.com/KarpelesLab/goupd): it keeps
the atomic binary-swap-and-restart mechanics but replaces the plaintext update files with
a **cryptographically signed CBOR manifest**.

It has two sides — a producer (the `rsupd` CLI) that builds a signed release package, and
a consumer library (`rsupd::Updater`) that verifies and applies updates to a running
program.

## Trust model

Each project owns two keys — an **Ed25519 signing key** (the primary/self key) and an
**X25519 encryption key** — stored as an `IDCard` + keychain at
`~/.config/rsupd/<project>/identity.bin`. The IDCard advertises both (purposes `sign` and
`decrypt`). A release **manifest** is sealed in a signed bottle. A consumer binary embeds
only the **32-byte SHA-256 fingerprint** of the project's *signing* key. On update it
checks, in order:

1. the manifest bottle opens,
2. its embedded IDCard is validly self-signed,
3. that IDCard's fingerprint equals the embedded anchor,
4. the manifest is signed by that key,

then compares versions before downloading, hash-checking, and swapping the binary.

## Producer (CLI)

```sh
# one-time: create the project signing identity
rsupd id init --project myapp
rsupd id export --project myapp -o myapp.fpr   # 32-byte anchor to embed in the app

# build a signed package from compiled binaries under target/<triple>/release/
cargo build --release                 # (and any cross targets)
rsupd build -C . --channel stable -o myapp.zip

# verify / inspect a package
rsupd inspect myapp.zip
```

The package is a plain store-mode `.zip` (`unzip`-readable) containing `manifest.cbor`
plus one zstd-compressed archive per target. This is the single file you upload; the
hosting API is pluggable (see below).

## Consumer (library)

```rust
// 32-byte fingerprint produced by `rsupd id export`
const FINGERPRINT: &[u8] = include_bytes!("../myapp.fpr");

let updater = rsupd::Updater::builder(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    .fingerprint(FINGERPRINT)
    .channel("stable")
    .transport(my_transport)   // implements rsupd::Transport
    .build()?;

// spot check:
if let Some(update) = updater.check()? {
    println!("update available: {}", update.version());
    updater.install(&update)?;     // atomic swap of the running binary
}

// or run the background updater (hourly; auto-restarts into the new build):
updater.spawn_auto_update(/* immediate = */ false);
```

`rsupd::TARGET` is the running build's exact target triple (captured by `build.rs`); it
selects the matching artifact from the manifest.

### Transport

The network protocol for fetching manifests/artifacts is intentionally left to the caller
via the [`rsupd::Transport`] trait. `rsupd::ZipPackageTransport` reads a local package zip
and runs the entire check → verify → install path offline — useful for tests and
sideloading until a hosting API is wired in.

## Status

Producer side (identity, manifest, signing, packaging, CLI) and the consumer updater
(verify, download, hash-check, atomic swap, restart) are complete and tested. The remote
upload/download API is the next piece to add behind `Transport`.

## License

MIT
