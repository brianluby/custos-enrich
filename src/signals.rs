//! Source-neutral joining of EPSS and KEV facts.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{CveId, EpssScore, KevCatalog, KevEntry, RansomwareUse};

/// Vulnerability signals keyed by canonical CVE identifier.
pub type SignalsMap = BTreeMap<CveId, VulnerabilitySignals>;

/// Metadata identifying the complete KEV snapshot used for a join.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KevSnapshotMetadata {
    catalog_version: String,
    date_released: DateTime<Utc>,
    count: usize,
}

impl KevSnapshotMetadata {
    /// Returns CISA's opaque catalog version string.
    #[must_use]
    pub fn catalog_version(&self) -> &str {
        &self.catalog_version
    }

    /// Returns when CISA released the snapshot.
    #[must_use]
    pub const fn date_released(&self) -> DateTime<Utc> {
        self.date_released
    }

    /// Returns the validated number of entries in the snapshot.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl From<&KevCatalog> for KevSnapshotMetadata {
    fn from(catalog: &KevCatalog) -> Self {
        Self {
            catalog_version: catalog.catalog_version().to_owned(),
            date_released: catalog.date_released(),
            count: catalog.count(),
        }
    }
}

/// Joined vulnerability signals plus the KEV snapshot that established them.
///
/// A set produced without consulting KEV, such as an empty no-network request,
/// has no snapshot metadata. Results produced by [`join_signals`] always retain
/// the validated catalog version, release time, and entry count.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SignalSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    kev_snapshot: Option<KevSnapshotMetadata>,
    signals: SignalsMap,
}

impl SignalSet {
    /// Creates an empty set without source snapshot metadata.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            kev_snapshot: None,
            signals: SignalsMap::new(),
        }
    }

    /// Returns the KEV snapshot metadata when a catalog was consulted.
    #[must_use]
    pub const fn kev_snapshot(&self) -> Option<&KevSnapshotMetadata> {
        self.kev_snapshot.as_ref()
    }

    /// Returns all joined signals keyed by CVE.
    #[must_use]
    pub const fn signals(&self) -> &SignalsMap {
        &self.signals
    }

    /// Returns the signals for one CVE.
    #[must_use]
    pub fn get(&self, cve: &CveId) -> Option<&VulnerabilitySignals> {
        self.signals.get(cve)
    }

    /// Returns the number of distinct CVEs in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signals.len()
    }

    /// Returns whether the set contains no CVEs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    /// Consumes the set and returns the CVE-keyed map.
    #[must_use]
    pub fn into_signals(self) -> SignalsMap {
        self.signals
    }
}

impl Default for SignalSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl IntoIterator for SignalSet {
    type Item = (CveId, VulnerabilitySignals);
    type IntoIter = std::collections::btree_map::IntoIter<CveId, VulnerabilitySignals>;

    fn into_iter(self) -> Self::IntoIter {
        self.signals.into_iter()
    }
}

impl<'a> IntoIterator for &'a SignalSet {
    type Item = (&'a CveId, &'a VulnerabilitySignals);
    type IntoIter = std::collections::btree_map::Iter<'a, CveId, VulnerabilitySignals>;

    fn into_iter(self) -> Self::IntoIter {
        self.signals.iter()
    }
}

/// The available EPSS and KEV facts for one CVE.
///
/// This type deliberately does not assign a severity, risk band, or composite
/// score. Downstream prioritization policy can use the source facts without
/// losing their distinct semantics.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct VulnerabilitySignals {
    cve: CveId,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss: Option<EpssScore>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kev: Option<KevEntry>,
}

impl VulnerabilitySignals {
    /// Returns the CVE identifier.
    #[must_use]
    pub const fn cve(&self) -> &CveId {
        &self.cve
    }

    /// Returns the EPSS record, or `None` when FIRST returned no score.
    ///
    /// Absence is intentionally not represented as a zero probability.
    #[must_use]
    pub const fn epss(&self) -> Option<&EpssScore> {
        self.epss.as_ref()
    }

    /// Returns the KEV entry when CISA lists the CVE.
    #[must_use]
    pub const fn kev(&self) -> Option<&KevEntry> {
        self.kev.as_ref()
    }

    /// Returns whether CISA lists the CVE as known exploited.
    #[must_use]
    pub const fn is_known_exploited(&self) -> bool {
        self.kev.is_some()
    }

    /// Returns the EPSS probability when available.
    #[must_use]
    pub fn epss_probability(&self) -> Option<f64> {
        self.epss.as_ref().map(EpssScore::probability)
    }

    /// Returns whether CISA has confirmed ransomware campaign use.
    #[must_use]
    pub fn has_known_ransomware_use(&self) -> bool {
        self.kev
            .as_ref()
            .and_then(KevEntry::ransomware_use)
            .is_some_and(RansomwareUse::is_known)
    }
}

/// Joins EPSS records and a validated KEV snapshot for the requested CVEs.
///
/// The result has one entry per distinct requested CVE and retains the KEV
/// snapshot metadata needed to interpret negative lookups. Source records for
/// unrequested CVEs are ignored. If a source contains duplicate records, the
/// last record in source order wins deterministically.
#[must_use]
pub fn join_signals(
    cves: &[CveId],
    epss_scores: impl IntoIterator<Item = EpssScore>,
    kev_catalog: &KevCatalog,
) -> SignalSet {
    let mut signals: SignalsMap = cves
        .iter()
        .cloned()
        .map(|cve| {
            (
                cve.clone(),
                VulnerabilitySignals {
                    cve,
                    epss: None,
                    kev: None,
                },
            )
        })
        .collect();

    for score in epss_scores {
        if let Some(entry) = signals.get_mut(score.cve()) {
            entry.epss = Some(score);
        }
    }
    for kev in kev_catalog.entries() {
        if let Some(entry) = signals.get_mut(kev.cve()) {
            entry.kev = Some(kev.clone());
        }
    }

    SignalSet {
        kev_snapshot: Some(kev_catalog.into()),
        signals,
    }
}

#[cfg(test)]
mod tests {
    use crate::{EpssResponse, KevCatalog};

    use super::*;

    #[test]
    fn joining_preserves_missing_epss_as_none() {
        let epss =
            EpssResponse::from_json_slice(include_bytes!("../tests/fixtures/epss_response.json"))
                .expect("valid EPSS fixture");
        let kev = KevCatalog::from_json_slice(include_bytes!("../tests/fixtures/kev_catalog.json"))
            .expect("valid KEV fixture");
        let missing = CveId::new("CVE-2024-3094").expect("valid CVE");
        let cves = [missing.clone()];

        let joined = join_signals(&cves, epss.into_scores(), &kev);

        assert_eq!(
            joined.get(&missing).and_then(VulnerabilitySignals::epss),
            None
        );
    }

    #[test]
    fn joining_retains_kev_snapshot_for_negative_lookups() {
        let kev = KevCatalog::from_json_slice(include_bytes!("../tests/fixtures/kev_catalog.json"))
            .expect("valid KEV fixture");
        let missing = CveId::new("CVE-2024-3094").expect("valid CVE");

        let joined = join_signals(std::slice::from_ref(&missing), [], &kev);

        assert_eq!(
            joined
                .kev_snapshot()
                .map(KevSnapshotMetadata::catalog_version),
            Some("2026.07.16")
        );
    }
}
