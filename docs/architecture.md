# Architecture

## Context

Security products commonly receive CVE-bearing findings without the external
evidence needed to prioritize them. EPSS and KEV are high-value sources, but
their wire contracts, update behavior, and evidence semantics differ. This
crate owns the narrow adapter boundary from those public data sources to typed
Rust facts.

## Boundary

The crate owns:

- CVE normalization and validation;
- provider-specific wire models and schema-tolerant parsing;
- HTTP request construction for the official JSON endpoints;
- source-level integrity checks;
- joining source facts by CVE; and
- source metadata needed to reason about freshness.

The caller owns:

- retries, rate limiting, scheduling, and persistent caching;
- last-known-good snapshot retention and mirror failover;
- telemetry and service-level objectives;
- mapping ASPM or scanner records to CVEs; and
- prioritization policy, persistence, and presentation.

This split keeps the crate reusable in a CLI, batch worker, service, or offline
pipeline without making it own an async runtime or an application architecture.

## Components

| Component | Responsibility |
| --- | --- |
| `CveId` | Canonical, hashable, serializable join key |
| `EpssResponse` / `EpssScore` | Typed FIRST envelope, current score, and optional history |
| `KevCatalog` / `KevEntry` | Validated whole-catalog snapshot and entries |
| `EpssClient` | Character-bounded, de-duplicated per-CVE EPSS requests |
| `KevClient` | Canonical whole-snapshot fetch and validation |
| `join_signals` / `SignalSet` | Deterministic CVE join with KEV snapshot provenance |
| `Enricher` | Convenience orchestration, including caller-cached KEV use |

The provider clients are concrete types. A public async trait would add runtime
and object-safety design commitments without improving the two fixed HTTP
adapters. Callers can wrap the concrete clients behind their own ports when
dependency inversion is needed at an application boundary.

## Invariants

1. A `CveId` has one canonical uppercase representation.
2. Parsed EPSS probability and percentile values are finite and within
   `0.0..=1.0`.
3. A missing EPSS record remains absent; it is never manufactured as zero.
4. A `KevCatalog` is constructed only when its declared count matches the
   decoded entry count.
5. `RansomwareUse::Unknown` never means confirmed non-use.
6. Joined results contain only requested CVEs.
7. No component blends KEV and EPSS into a single numeric score.

## Resilience decisions

- HTTP status is checked before success-body deserialization because provider
  error payloads do not share their success schemas.
- Success bodies are streamed through provider-specific hard size limits, and
  status-error body reads stop after a bounded excerpt.
- EPSS requests honor the documented 2,000-character CVE parameter boundary,
  explicitly select JSON, and set `limit` per batch.
- KEV treats each catalog as a replaceable snapshot, not an append-only feed.
- Unknown JSON fields are allowed, optional KEV fields follow the published
  schema, and the ransomware vocabulary remains open.
- Default requests use a bounded total deadline; native default clients also use
  bounded connect and read-inactivity timeouts. A caller-configured
  `reqwest::Client` replaces those defaults and carries application-specific
  timeout, proxy, TLS, and pool policy. A per-request deadline can be applied
  explicitly when needed. Default transport construction is fallible and returns
  `ClientError::HttpClientBuild` instead of panicking. The crate always disables
  native TLS in favor of Rustls.

## Expected extensions

Likely additive work after v0.1:

- EPSS historical query options and time-series helpers;
- the official EPSS compressed snapshot, including model version retention;
- conditional KEV refresh metadata (`ETag` and `Last-Modified`);
- explicit mirror fallback primitives; and
- streaming decompression and parsing for the EPSS bulk snapshot format.

These should remain provider adapters. Retry/caching frameworks and scoring
policy stay outside unless repeated consumers demonstrate a stable shared
contract.
