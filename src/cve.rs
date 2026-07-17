//! CVE identifier normalization and validation.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A normalized CVE identifier.
///
/// Input is case-insensitive and surrounding whitespace is ignored. Values are
/// rendered in canonical uppercase form. The sequence component follows the
/// current CVE/KEV contract of 4 to 19 digits.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CveId(String);

impl CveId {
    /// Parses and normalizes a CVE identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CveIdError`] unless the value starts with `CVE-YYYY-` and ends
    /// with a sequence of 4 to 19 digits.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CveIdError> {
        value.as_ref().parse()
    }

    /// Returns the canonical CVE identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CveId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CveId {
    type Err = CveIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let value = input.trim();
        let mut parts = value.split('-');
        let prefix = parts.next();
        let year = parts.next();
        let sequence = parts.next();
        let has_extra_parts = parts.next().is_some();

        let valid = prefix.is_some_and(|part| part.eq_ignore_ascii_case("CVE"))
            && year.is_some_and(|part| {
                part.len() == 4 && part.bytes().all(|byte| byte.is_ascii_digit())
            })
            && sequence.is_some_and(|part| {
                (4..=19).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
            })
            && !has_extra_parts;

        if !valid {
            return Err(CveIdError(input.to_owned()));
        }

        let year = year.ok_or_else(|| CveIdError(input.to_owned()))?;
        let sequence = sequence.ok_or_else(|| CveIdError(input.to_owned()))?;
        Ok(Self(format!("CVE-{year}-{sequence}")))
    }
}

impl Serialize for CveId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CveId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// An invalid CVE identifier.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid CVE identifier `{0}`; expected `CVE-YYYY-` followed by 4 to 19 digits")]
pub struct CveIdError(String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_normalizes_case_and_whitespace() {
        let cve = CveId::new("  cve-2024-3094  ").expect("valid CVE");

        assert_eq!(cve.as_str(), "CVE-2024-3094");
    }

    #[test]
    fn parsing_rejects_short_sequences() {
        let error = CveId::new("CVE-2024-123").expect_err("short sequence must fail");

        assert_eq!(
            error.to_string(),
            "invalid CVE identifier `CVE-2024-123`; expected `CVE-YYYY-` followed by 4 to 19 digits"
        );
    }

    #[test]
    fn serde_round_trip_preserves_canonical_form() {
        let cve = CveId::new("cve-2021-44228").expect("valid CVE");
        let json = serde_json::to_string(&cve).expect("serialize CVE");
        let decoded: CveId = serde_json::from_str(&json).expect("deserialize CVE");

        assert_eq!(decoded, cve);
    }
}
