//! FIRST Exploit Prediction Scoring System response models.

use std::fmt;

use chrono::NaiveDate;
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::CveId;

/// One page returned by the FIRST EPSS API.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpssResponse {
    status: String,
    #[serde(rename = "status-code")]
    status_code: u16,
    version: String,
    access: String,
    total: usize,
    offset: usize,
    limit: usize,
    data: Vec<EpssScore>,
}

impl EpssResponse {
    /// Parses an enveloped EPSS JSON response.
    ///
    /// # Errors
    ///
    /// Returns a JSON error when the envelope is malformed or a score is
    /// outside the inclusive range `0.0..=1.0`.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(input)
    }

    /// Returns the provider status string.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Returns the status code embedded in the response envelope.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Returns the FIRST API version.
    ///
    /// This is not the EPSS model version.
    #[must_use]
    pub fn api_version(&self) -> &str {
        &self.version
    }

    /// Returns the access scope reported by FIRST.
    #[must_use]
    pub fn access(&self) -> &str {
        &self.access
    }

    /// Returns the total number of records matching the query.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Returns the zero-based record offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the requested page limit.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the scores in this response page.
    #[must_use]
    pub fn scores(&self) -> &[EpssScore] {
        &self.data
    }

    /// Consumes the response and returns its scores.
    #[must_use]
    pub fn into_scores(self) -> Vec<EpssScore> {
        self.data
    }

    /// Finds a score by normalized CVE identifier.
    #[must_use]
    pub fn get(&self, cve: &CveId) -> Option<&EpssScore> {
        self.data.iter().find(|score| score.cve() == cve)
    }
}

/// The current EPSS score and percentile for one CVE.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpssScore {
    cve: CveId,
    #[serde(deserialize_with = "deserialize_unit_interval")]
    epss: f64,
    #[serde(deserialize_with = "deserialize_unit_interval")]
    percentile: f64,
    #[serde(alias = "created")]
    date: NaiveDate,
    #[serde(default, rename = "time-series")]
    time_series: Vec<EpssHistoryPoint>,
}

impl EpssScore {
    /// Returns the CVE identifier.
    #[must_use]
    pub const fn cve(&self) -> &CveId {
        &self.cve
    }

    /// Returns the EPSS probability in the inclusive range `0.0..=1.0`.
    #[must_use]
    pub const fn probability(&self) -> f64 {
        self.epss
    }

    /// Returns the percentile rank in the inclusive range `0.0..=1.0`.
    #[must_use]
    pub const fn percentile(&self) -> f64 {
        self.percentile
    }

    /// Returns the date for which the score was generated.
    #[must_use]
    pub const fn date(&self) -> NaiveDate {
        self.date
    }

    /// Returns historical points when the API was queried with time-series scope.
    #[must_use]
    pub fn time_series(&self) -> &[EpssHistoryPoint] {
        &self.time_series
    }
}

/// One historical EPSS score returned in time-series scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EpssHistoryPoint {
    #[serde(deserialize_with = "deserialize_unit_interval")]
    epss: f64,
    #[serde(deserialize_with = "deserialize_unit_interval")]
    percentile: f64,
    #[serde(alias = "created")]
    date: NaiveDate,
}

impl EpssHistoryPoint {
    /// Returns the historical EPSS probability.
    #[must_use]
    pub const fn probability(&self) -> f64 {
        self.epss
    }

    /// Returns the historical percentile rank.
    #[must_use]
    pub const fn percentile(&self) -> f64 {
        self.percentile
    }

    /// Returns the date for this historical point.
    #[must_use]
    pub const fn date(&self) -> NaiveDate {
        self.date
    }
}

/// An EPSS score or percentile outside the inclusive range `0.0..=1.0`.
#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
pub struct EpssValueError(f64);

impl fmt::Display for EpssValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "EPSS values must be finite and within 0.0..=1.0, found {}",
            self.0
        )
    }
}

fn deserialize_unit_interval<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireValue {
        String(String),
        Number(f64),
    }

    let value = match WireValue::deserialize(deserializer)? {
        WireValue::String(value) => value.parse::<f64>().map_err(de::Error::custom)?,
        WireValue::Number(value) => value,
    };

    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(value)
    } else {
        Err(de::Error::custom(EpssValueError(value)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_accepts_string_encoded_scores() {
        let response =
            EpssResponse::from_json_slice(include_bytes!("../tests/fixtures/epss_response.json"))
                .expect("valid EPSS fixture");

        assert_eq!(response.scores()[0].probability(), 0.999_99);
    }

    #[test]
    fn parsing_accepts_numeric_scores_for_forward_compatibility() {
        let input = br#"{
            "status":"OK","status-code":200,"version":"1.0","access":"public",
            "total":1,"offset":0,"limit":1,
            "data":[{"cve":"CVE-2024-3094","epss":0.975,"percentile":0.999,"date":"2026-07-16"}]
        }"#;
        let response = EpssResponse::from_json_slice(input).expect("valid numeric scores");

        assert_eq!(response.scores()[0].probability(), 0.975);
    }

    #[test]
    fn parsing_rejects_out_of_range_scores() {
        let input = br#"{
            "status":"OK","status-code":200,"version":"1.0","access":"public",
            "total":1,"offset":0,"limit":1,
            "data":[{"cve":"CVE-2024-3094","epss":"1.1","percentile":"0.999","date":"2026-07-16"}]
        }"#;
        let error = EpssResponse::from_json_slice(input).expect_err("invalid score must fail");

        assert!(error.to_string().contains("within 0.0..=1.0"));
    }
}
