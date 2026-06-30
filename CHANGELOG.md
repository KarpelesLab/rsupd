# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/KarpelesLab/rsupd/compare/v0.1.0...v0.2.0) - 2026-06-30

### Other

- Add `rsupd version` and `rsupd update` (self-update over HTTP)
- add -v/--verbose to trace REST requests
- surface request id and token on upload errors
- fix endpoint to Cloud/Rust:upload, drop API env vars
- Add `rsupd publish`: build, confirm, then upload via klbfw
- Default channel to the git branch name (fallback "master")
