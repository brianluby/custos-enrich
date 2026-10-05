# custos-enrich

`custos-enrich` is a small, source-focused Rust library for adding vulnerability
prioritization signals to ASPM, scanner, inventory, and remediation data.

It provides:

- typed clients for the [FIRST EPSS API](https://api.first.org/epss/) and the
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog);
- canonical, case-insensitive CVE identifiers;
- validated EPSS probabilities, percentiles, dates, and optional time series;
- complete-snapshot validation and local lookup for CISA KEV;
- a forward-compatible ransomware-use classification; and
- a source-neutral join that leaves prioritization policy to the caller.

The crate does not assign a severity, risk band, or composite score. A KEV match
is confirmed exploitation evidence; EPSS is an estimate of exploitation
probability. Keeping them separate prevents a product-specific policy from
becoming part of a reusable data client.

## Quick start

Add the crate and an async runtime:

```toml
[dependencies]
custos-enrich = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Fetch and join both sources:

```rust,no_run
use custos_enrich::{CveId, Enricher};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cves = [
        CveId::new("CVE-2021-44228")?,
        CveId::new("CVE-2023-34362")?,
    ];
    let signals = Enricher::try_default()?.enrich(&cves).await?;

    for (cve, signal) in signals {
        println!(
            "{cve}: epss={:?}, kev={}, ransomware={}",
            signal.epss_probability(),
            signal.is_known_exploited(),
            signal.has_known_ransomware_use(),
        );
    }
    Ok(())
}
```

`Enricher::enrich` downloads one complete KEV snapshot per call. Long-running
services should fetch and cache the catalog on their own schedule, then avoid
re-downloading it for each batch:

```rust,no_run
use custos_enrich::{CveId, Enricher, KevClient};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let catalog = KevClient::new()?.catalog().await?;
let cves = [CveId::new("CVE-2021-44228")?];
let signals = Enricher::try_default()?
    .enrich_with_catalog(&cves, &catalog)
    .await?;
# let _ = signals;
# Ok(())
# }
```

## Signal semantics

| Signal | Meaning | Important absence semantics |
| --- | --- | --- |
| EPSS probability | FIRST estimate in `0.0..=1.0` for a dated model output | No returned record is `None`, never zero |
| EPSS percentile | Relative rank in `0.0..=1.0` for the same date | No returned record is `None` |
| KEV entry | CISA has evidence the CVE is exploited in the wild | Absence is trusted only after full-catalog validation |
| Ransomware `Known` | CISA confirms ransomware campaign use | `Unknown` means unconfirmed, not confirmed false |

`join_signals` accepts already-parsed EPSS records and a validated KEV catalog
for offline or caller-managed transport workflows. Its result carries KEV
snapshot provenance plus a deterministic map keyed by canonical CVE ID. Records
not requested by the caller are ignored.

## Provider behavior

### FIRST EPSS

`EpssClient::scores`:

- removes duplicate CVEs before requesting them;
- batches by FIRST's 2,000-character `cve` parameter limit;
- explicitly requests enveloped JSON and sets a sufficient result limit;
- accepts upstream decimal strings and JSON numbers;
- validates scores and percentiles as finite values in `0.0..=1.0`; and
- rejects incomplete pages, duplicate records, and unrequested CVEs.

FIRST currently permits 1,000 public API requests per minute and publishes new
scores daily. Every request made by a client returned by `EpssClient::new`,
`KevClient::new`, or `Enricher::try_default` has a 120-second total deadline. On
native targets, the shared HTTP client also uses a 10-second connect timeout and
a 30-second read-inactivity timeout. These constructors return an error if the
default HTTP transport cannot initialize. The client does not add hidden retries
or concurrency. Use `with_http_client` to supply application-specific proxy,
TLS, pool, or timeout policy; use `with_request_timeout` when a per-request total
deadline should override that client policy. Schedule refreshes and retries
outside this crate.

### CISA KEV

`KevClient::catalog` downloads the whole JSON catalog because CISA does not
publish a lookup or pagination API. Parsing fails when the catalog's declared
`count` differs from the decoded entry count. This prevents a partial download
from being mistaken for evidence that a CVE is not known exploited.

The `catalogVersion` stays opaque, `dateReleased` is parsed as RFC 3339, optional
fields follow CISA's schema, unknown JSON fields are tolerated, and unexpected
ransomware classifications are retained in `RansomwareUse::Other`.

Both clients stream response bodies through provider-specific hard size limits,
and non-success response excerpts are bounded before entering an error.

## Features

The default `client` feature enables asynchronous HTTP clients over reqwest
0.13 and Rustls. Disable it to use only identifiers, models, parsing, validation,
and joining:

```toml
[dependencies]
custos-enrich = { version = "0.1", default-features = false }
```

## Scope and limitations

Version 0.1 intentionally focuses on the current per-CVE EPSS JSON API and the
canonical KEV JSON snapshot. It does not yet provide:

- EPSS bulk CSV download/decompression or model-version metadata;
- historical EPSS query builders;
- conditional KEV requests, persistent caches, retry policy, or rate limiting;
- database or ASPM-specific models; or
- an opinionated prioritization formula.

See [the architecture notes](docs/architecture.md) for the boundary and likely
extension points.

## Data attribution

EPSS scores are provided by the Forum of Incident Response and Security Teams
([FIRST](https://www.first.org/epss/)). FIRST permits public and commercial use
and requests attribution where possible.

CISA's KEV dataset is dedicated to the public domain under
[CC0 1.0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt).
Dataset reuse does not imply CISA or DHS endorsement and does not grant use of
their seals or logos. See [NOTICE](NOTICE) for the compact attribution text.

## Minimum Rust version

The minimum supported Rust version is 1.94. It matches Custos and is raised
together with it.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
