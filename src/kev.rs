//! CISA Known Exploited Vulnerabilities catalog models and validation.

use std::fmt;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::CveId;

/// A complete, validated CISA KEV catalog snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KevCatalog {
    catalog_version: String,
    date_released: DateTime<Utc>,
    count: usize,
    vulnerabilities: Vec<KevEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
}

impl KevCatalog {
    /// Parses and validates a CISA KEV JSON catalog.
    ///
    /// Validation rejects a snapshot whose declared count differs from the
    /// number of entries. Without that check, an absent CVE could be the result
    /// of a truncated download rather than evidence that it is absent from KEV.
    ///
    /// # Errors
    ///
    /// Returns [`KevParseError::Json`] for malformed data or
    /// [`KevParseError::CountMismatch`] for an incomplete snapshot.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, KevParseError> {
        let wire: WireKevCatalog = serde_json::from_slice(input)?;
        let actual = wire.vulnerabilities.len();
        if wire.count != actual {
            return Err(KevParseError::CountMismatch {
                declared: wire.count,
                actual,
            });
        }

        Ok(Self {
            catalog_version: wire.catalog_version,
            date_released: wire.date_released,
            count: wire.count,
            vulnerabilities: wire.vulnerabilities,
            title: wire.title,
        })
    }

    /// Returns CISA's opaque catalog version string.
    #[must_use]
    pub fn catalog_version(&self) -> &str {
        &self.catalog_version
    }

    /// Returns when CISA released this snapshot.
    #[must_use]
    pub const fn date_released(&self) -> DateTime<Utc> {
        self.date_released
    }

    /// Returns the validated number of catalog entries.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns the optional catalog title.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Returns all KEV entries in source order.
    #[must_use]
    pub fn entries(&self) -> &[KevEntry] {
        &self.vulnerabilities
    }

    /// Finds a KEV entry by CVE identifier.
    #[must_use]
    pub fn get(&self, cve: &CveId) -> Option<&KevEntry> {
        self.vulnerabilities.iter().find(|entry| entry.cve() == cve)
    }

    /// Returns whether the catalog contains the CVE identifier.
    #[must_use]
    pub fn contains(&self, cve: &CveId) -> bool {
        self.get(cve).is_some()
    }

    /// Consumes the catalog and returns its entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<KevEntry> {
        self.vulnerabilities
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireKevCatalog {
    catalog_version: String,
    date_released: DateTime<Utc>,
    count: usize,
    vulnerabilities: Vec<KevEntry>,
    #[serde(default)]
    title: Option<String>,
}

/// One entry in the CISA KEV catalog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    cve: CveId,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: NaiveDate,
    short_description: String,
    required_action: String,
    due_date: NaiveDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    known_ransomware_campaign_use: Option<RansomwareUse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(default)]
    cwes: Vec<String>,
}

impl KevEntry {
    /// Returns the CVE identifier.
    #[must_use]
    pub const fn cve(&self) -> &CveId {
        &self.cve
    }

    /// Returns the vendor or project named by CISA.
    #[must_use]
    pub fn vendor_project(&self) -> &str {
        &self.vendor_project
    }

    /// Returns the affected product.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Returns CISA's vulnerability name.
    #[must_use]
    pub fn vulnerability_name(&self) -> &str {
        &self.vulnerability_name
    }

    /// Returns the date CISA added this entry to KEV.
    #[must_use]
    pub const fn date_added(&self) -> NaiveDate {
        self.date_added
    }

    /// Returns CISA's short description.
    #[must_use]
    pub fn short_description(&self) -> &str {
        &self.short_description
    }

    /// Returns CISA's required remediation action.
    #[must_use]
    pub fn required_action(&self) -> &str {
        &self.required_action
    }

    /// Returns CISA's remediation due date.
    #[must_use]
    pub const fn due_date(&self) -> NaiveDate {
        self.due_date
    }

    /// Returns CISA's ransomware-use classification when present.
    #[must_use]
    pub const fn ransomware_use(&self) -> Option<&RansomwareUse> {
        self.known_ransomware_campaign_use.as_ref()
    }

    /// Returns CISA's unstructured notes when present.
    #[must_use]
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    /// Returns the CWE identifiers attached by CISA.
    #[must_use]
    pub fn cwes(&self) -> &[String] {
        &self.cwes
    }
}

/// CISA's ransomware-campaign-use classification.
///
/// `Unknown` means CISA has not confirmed ransomware use; it does not mean
/// confirmed absence. The open `Other` variant preserves future source values.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RansomwareUse {
    /// CISA has confirmed ransomware campaign use.
    Known,
    /// CISA has not confirmed ransomware campaign use.
    Unknown,
    /// A source value introduced outside the currently known vocabulary.
    Other(String),
}

impl RansomwareUse {
    /// Returns the exact source representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Known => "Known",
            Self::Unknown => "Unknown",
            Self::Other(value) => value,
        }
    }

    /// Returns whether CISA has confirmed ransomware campaign use.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(self, Self::Known)
    }
}

impl fmt::Display for RansomwareUse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for RansomwareUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RansomwareUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "Known" => Self::Known,
            "Unknown" => Self::Unknown,
            _ => Self::Other(value),
        })
    }
}

/// A malformed or incomplete CISA KEV catalog.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KevParseError {
    /// The catalog is not valid JSON matching the expected wire contract.
    #[error("invalid CISA KEV catalog: {0}")]
    Json(#[from] serde_json::Error),
    /// The declared count does not match the number of downloaded entries.
    #[error("incomplete CISA KEV catalog: declared {declared} entries but decoded {actual}")]
    CountMismatch {
        /// The count declared in the catalog metadata.
        declared: usize,
        /// The number of entries actually decoded.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_validates_and_indexes_catalog() {
        let catalog =
            KevCatalog::from_json_slice(include_bytes!("../tests/fixtures/kev_catalog.json"))
                .expect("valid KEV fixture");
        let cve = CveId::new("CVE-2021-44228").expect("valid CVE");

        assert_eq!(catalog.get(&cve).map(KevEntry::product), Some("Log4j2"));
    }

    #[test]
    fn parsing_rejects_count_mismatch() {
        let input = br#"{
            "catalogVersion":"2026.07.16","dateReleased":"2026-07-16T17:00:15.6845Z",
            "count":1,"vulnerabilities":[]
        }"#;
        let error = KevCatalog::from_json_slice(input).expect_err("mismatch must fail");

        assert!(matches!(
            error,
            KevParseError::CountMismatch {
                declared: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn parsing_preserves_new_ransomware_values() {
        let json = r#""Under Investigation""#;
        let value: RansomwareUse = serde_json::from_str(json).expect("valid string");

        assert_eq!(value, RansomwareUse::Other("Under Investigation".into()));
    }
}
