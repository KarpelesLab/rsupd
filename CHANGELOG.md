# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/KarpelesLab/rsupd/compare/v0.2.0...v0.3.0) - 2026-06-30

### Other

- rename `cli` feature to `_cli` so semver-checks ignores the producer API
- integration fixups for security fixes
- Harden CI input handling in rsupd binary
- Harden manifest and config against untrusted input
- create sidecar with create_new to stop symlink/perm attacks
- render the mental model as a mermaid diagram
- clarify rsupd is the (free) file host; note the cli feature
- Shrink the library API to the updater; gate the producer behind `cli`
- rewrite README around the security/trust model
- enable full release pipeline for rsupd itself
- full CI (--setup-ci --full) + RSUPD_IDENTITY env identity
- full doctor — verify build.rs + CI, point to fix flags
- ship one universal binary (darwin_universal), not two
- make the binary aware of its build identity (git date/hash)
- setup-ci (github): fat macOS binary + more targets
- add --setup-ci to scaffold the CI build config
- publish --ci: support GitLab as well as GitHub
- build rsupd for linux, macOS & windows
- add --ci to source binaries from a GitHub Actions run
- Pin the update origin: HttpTransport host is fixed, not configurable

## [0.2.0](https://github.com/KarpelesLab/rsupd/compare/v0.1.0...v0.2.0) - 2026-06-30

### Other

- Add `rsupd version` and `rsupd update` (self-update over HTTP)
- add -v/--verbose to trace REST requests
- surface request id and token on upload errors
- fix endpoint to Cloud/Rust:upload, drop API env vars
- Add `rsupd publish`: build, confirm, then upload via klbfw
- Default channel to the git branch name (fallback "master")
