# Changelog — `armature-jwt`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.6.0] - 2026-10-29

### Changed

- Requires `armature-core` 0.12 (was `0.11`).

## [0.5.0] - 2026-10-17

### Security

- **Breaking:** `JwtConfig::new` now returns `Result<JwtConfig>` and rejects HMAC secrets that are empty, shorter than 32 bytes (`MIN_HMAC_SECRET_LEN`), known placeholders (`change-me-in-production`, `default-secret-change-me`, `CHANGE_ME_IN_PRODUCTION`, `secret`, …) or trivially low-entropy. `JwtService::new`/`verify_only` (and so `JwtManager::new`/`verify_only`) re-validate the config, so a weak secret assigned to the public `secret` field or deserialized from a file is rejected too. New `config::validate_hmac_secret` and `JwtConfig::validate`. Migration: `JwtConfig::new(secret)?` with a ≥ 32-byte random secret (e.g. `openssl rand -base64 48`).
- **Breaking:** removed `impl Default for JwtConfig` (it used the public secret `"change-me-in-production"`) and `impl Default for JwtManager`. Migration: construct from real key material.
- Access and refresh tokens are now distinguishable by header as well as claim: `generate_token_pair` sets `typ: "at+jwt"` on access tokens and `typ: "refresh+jwt"` on refresh tokens. New `JwtManager::verify_access` / `JwtService::verify_access` reject refresh tokens (`token_use` present and ≠ `"access"`, or the refresh `typ`) — use it to authenticate requests. **Breaking:** `refresh_token` now also requires the refresh `typ` header, so refresh tokens minted by earlier versions must be re-issued (users log in again once).
- `JwtConfig.secret` and `JwtConfig.private_key` are redacted from `Debug` and skipped when serializing (still deserialized). `Token` and `TokenPair` redact their tokens from `Debug` (they stay `Serialize`: they are the login response body).
- `jsonwebtoken` now uses the `aws_lc_rs` backend instead of `rust_crypto`, removing the `rsa` crate (RUSTSEC-2023-0071, Marvin timing side channel) from this crate's dependency tree. The provider is installed explicitly, so a build in which another crate enables `rust_crypto` does not panic.

### Changed

- **Breaking:** `decode_unverified` is renamed `decode_unverified_insecure` (on `JwtManager` and `JwtService`), with documentation stating its claims are attacker-controlled. The name makes every call site self-evidently a non-verifying read, the same convention as `jsonwebtoken::dangerous::insecure_decode`. Migration: rename the call, and use `verify`/`verify_access` anywhere the claims drive a decision.

### Added

- `JwtConfig::with_key_pair(private, public, algorithm)`, and support for `PS256`/`PS384`/`PS512` and `EdDSA` keys in `JwtConfig` (previously rejected as unsupported).

## [0.4.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- **`jsonwebtoken` 10.4 → 11.0 (breaking for dependents).** This crate re-exports `Algorithm`, `DecodingKey`, `EncodingKey`, `Header` and `Validation`, and exposes `jsonwebtoken::errors::Error` through `JwtError::EncodingError`, so those types are now the 11.x types. Upstream changes visible through the re-exports: `Algorithm` is `#[non_exhaustive]`; `Header.extras` is an `Extras` struct instead of `HashMap<String, String>`; `Validation::insecure_disable_signature_validation` is gone (use `decode_unverified`); `EncodingKey::inner` is renamed `as_bytes`; `DecodingKey::as_bytes` and both `try_get_hmac_secret` methods are replaced by `DecodingKey::try_get_as_bytes`. Token validation (signature, algorithm allow-list, `exp`/`nbf`/leeway, `iss`/`aud`) behaves as before. HMAC signers and verifiers now also reject non-HMAC keys when they are built.
- `base64` 0.22 → 0.23 (tests and the fuzz harness only).

## [0.3.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.

## [0.2.2] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
