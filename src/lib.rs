//! Typed vulnerability-prioritization signals from FIRST EPSS and CISA KEV.
//!
//! `custos-enrich` keeps source evidence separate from prioritization policy. It
//! normalizes CVE identifiers, parses provider data into typed models, validates
//! complete KEV snapshots, and joins EPSS and KEV facts by CVE. With the default
//! `client` feature it also provides small asynchronous HTTP clients.
//!
//! # Offline example
//!
//! ```
//! use custos_enrich::CveId;
//!
//! let cve: CveId = "cve-2021-44228".parse()?;
//! assert_eq!(cve.as_str(), "CVE-2021-44228");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![forbid(unsafe_code)]

#[cfg(feature = "client")]
mod client;
mod cve;
mod epss;
mod kev;
mod signals;

#[cfg(feature = "client")]
pub use client::{
    CISA_KEV_ENDPOINT, ClientError, DataProvider, Enricher, EpssClient, FIRST_EPSS_ENDPOINT,
    KevClient,
};
pub use cve::{CveId, CveIdError};
pub use epss::{EpssHistoryPoint, EpssResponse, EpssScore, EpssValueError};
pub use kev::{KevCatalog, KevEntry, KevParseError, RansomwareUse};
pub use signals::{KevSnapshotMetadata, SignalSet, SignalsMap, VulnerabilitySignals, join_signals};

// Keep README examples compiled without duplicating the README in rendered API docs.
#[cfg(all(doctest, feature = "client"))]
#[doc = include_str!("../README.md")]
mod readme_doctests {}
