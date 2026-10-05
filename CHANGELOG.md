# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Raise the minimum supported Rust version to 1.94 to match Custos.

## [0.1.0] - 2026-07-17

### Added

- Typed, configurable FIRST EPSS and CISA KEV clients over Rustls.
- Bounded default request timeouts with caller-owned HTTP-client overrides.
- Fallible default HTTP-client construction without library panics.
- Sanitized endpoint context on client and response-validation errors.
- Canonical `CveId` parsing and serialization.
- EPSS envelope, score, percentile, date, and time-series models.
- Complete CISA KEV snapshot validation and local CVE lookup.
- Forward-compatible ransomware-use modeling.
- Source-neutral signal joining and cached-catalog enrichment.
- Offline model support through the optional `client` feature.
