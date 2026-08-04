# Changelog — `armature-jwt`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Added

- Adopted the `jwt` criterion benchmark (token signing and verification across algorithms) from the root package's `benches/security_benchmarks.rs`. Run it with `cargo bench -p armature-jwt --bench jwt`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry.
