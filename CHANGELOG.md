# Changelog — `armature-siem`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.5.0] - 2026-10-29

### Changed

- Requires `armature-core` 0.12 (was `0.11`).
- Requires `armature-audit` 0.6 (was `0.5`).

## [0.4.0] - 2026-10-17

### Security

- `SiemConfig`'s `Debug` output redacts `token` and `password` as `[REDACTED]`, so a logged configuration no longer leaks the SIEM credential (H27).
- Disabling TLS certificate verification now logs a `warn!` every time a transport is built that way (L17).
- The TLS transport rejects a `ca_cert` file that contains no PEM certificates instead of building an empty root store.

### Changed

- **Breaking:** disabling TLS certificate verification is gated behind the new `dangerous-insecure-tls` cargo feature (not part of `full`). Without it, `tls_verify = false` is rejected by `SiemConfig::validate` and by `HttpTransport::new`/`TcpTransport::new` with `SiemError::Config`, and the `NoServerCertVerification` verifier is not compiled. Migration: trust a private collector with `.ca_cert(path)`; if you really need no verification, enable `dangerous-insecure-tls` and call `.danger_accept_invalid_certs()`.
- CA certificates are parsed with `rustls-pki-types`' `PemObject` (via rustls' re-export) (M32).

### Removed

- **Breaking:** `SiemConfigBuilder::tls_verify(bool)`. Migration: verification is on by default; use `.ca_cert(path)`, or `.danger_accept_invalid_certs()` behind the `dangerous-insecure-tls` feature.
- The `rustls-pemfile` dependency (unmaintained, RUSTSEC-2025-0134) (M32).

## [0.3.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-audit` 0.4 (was `0.3`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.

### Security

- Require `rustls` 0.23.45 or later, which fixes RUSTSEC-2026-0285 (TLS 1.3 handshake messages accepted across encryption-level boundaries).

## [0.2.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.
- Requires `armature-audit` 0.3 (was `0.2`); it moved its minor in the same train for the same reason.

## [0.1.2] - 2026-08-04

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
