//! Asynchronous clients for the official FIRST EPSS and CISA KEV endpoints.

use std::{collections::HashSet, time::Duration};

use futures_util::{StreamExt, future};
use reqwest::{Response, header};
use serde::de::DeserializeOwned;

use crate::{CveId, EpssResponse, EpssScore, KevCatalog, KevParseError, SignalSet, join_signals};

/// The official FIRST EPSS JSON API endpoint.
pub const FIRST_EPSS_ENDPOINT: &str = "https://api.first.org/data/v1/epss.json";

/// The canonical CISA KEV JSON catalog endpoint.
pub const CISA_KEV_ENDPOINT: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

const MAX_EPSS_CVE_PARAMETER_CHARS: usize = 2_000;
const MAX_EPSS_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_KEV_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const ERROR_BODY_CHARS: usize = 512;
const ERROR_BODY_BYTES: usize = ERROR_BODY_CHARS * 4;
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(target_arch = "wasm32"))]
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const USER_AGENT: &str = concat!("custos-enrich/", env!("CARGO_PKG_VERSION"));

/// An upstream vulnerability-data provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DataProvider {
    /// FIRST's Exploit Prediction Scoring System API.
    FirstEpss,
    /// CISA's Known Exploited Vulnerabilities catalog.
    CisaKev,
}

impl std::fmt::Display for DataProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FirstEpss => "FIRST EPSS",
            Self::CisaKev => "CISA KEV",
        })
    }
}

/// A client configuration, transport, status, or response-validation error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// A configured endpoint is not an HTTP(S) URL.
    #[error("invalid {provider} endpoint `{endpoint}`: {message}")]
    InvalidEndpoint {
        /// The provider whose endpoint was configured.
        provider: DataProvider,
        /// A redacted representation of the rejected endpoint.
        endpoint: String,
        /// The URL parser or scheme-validation message.
        message: String,
    },
    /// The default HTTP transport could not be initialized.
    #[error("failed to initialize the default HTTP client: {error}")]
    HttpClientBuild {
        /// The underlying HTTP-client construction error.
        #[source]
        error: reqwest::Error,
    },
    /// An HTTP request or response-body read failed.
    #[error("{provider} request to `{endpoint}` failed: {error}")]
    Request {
        /// The provider being requested.
        provider: DataProvider,
        /// The requested endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The underlying HTTP error.
        #[source]
        error: reqwest::Error,
    },
    /// An upstream endpoint returned a non-success status.
    #[error("{provider} endpoint `{endpoint}` returned HTTP {status}: {body}")]
    HttpStatus {
        /// The provider being requested.
        provider: DataProvider,
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The numeric HTTP status.
        status: u16,
        /// A bounded, lossy excerpt of the response body.
        body: String,
    },
    /// A success response exceeded the provider-specific safety limit.
    #[error("{provider} response from `{endpoint}` exceeded the {limit_bytes}-byte safety limit")]
    ResponseTooLarge {
        /// The provider being requested.
        provider: DataProvider,
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The maximum accepted decoded response size.
        limit_bytes: usize,
    },
    /// A FIRST EPSS success response did not match the expected contract.
    #[error("invalid FIRST EPSS response from `{endpoint}`: {error}")]
    EpssDecode {
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The JSON decoding error.
        #[source]
        error: serde_json::Error,
    },
    /// A FIRST EPSS page claimed records that were not present in the body.
    #[error(
        "incomplete FIRST EPSS page from `{endpoint}`: total={total}, returned={returned}, offset={offset}, limit={limit}"
    )]
    IncompleteEpssPage {
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The total reported by FIRST.
        total: usize,
        /// The number of records decoded from the page.
        returned: usize,
        /// The record offset reported by FIRST.
        offset: usize,
        /// The page limit reported by FIRST.
        limit: usize,
    },
    /// A FIRST EPSS response contained a CVE outside the requested batch.
    #[error("FIRST EPSS endpoint `{endpoint}` returned unrequested CVE `{cve}`")]
    UnexpectedEpssCve {
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The unrequested CVE identifier.
        cve: CveId,
    },
    /// A FIRST EPSS response contained the same CVE more than once.
    #[error("FIRST EPSS endpoint `{endpoint}` returned duplicate CVE `{cve}`")]
    DuplicateEpssCve {
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The duplicated CVE identifier.
        cve: CveId,
    },
    /// A CISA KEV response was malformed or incomplete.
    #[error("invalid CISA KEV response from `{endpoint}`: {error}")]
    KevDecode {
        /// The final response endpoint, with credentials, query, and fragment removed.
        endpoint: String,
        /// The catalog decoding or validation error.
        #[source]
        error: KevParseError,
    },
}

/// A small asynchronous client for FIRST EPSS scores.
///
/// The client normalizes input through [`CveId`], removes duplicate queries,
/// batches on FIRST's 2,000-character CVE parameter limit, and preserves
/// missing scores as absent records.
#[derive(Clone, Debug)]
pub struct EpssClient {
    http: reqwest::Client,
    endpoint: String,
    request_timeout: Option<Duration>,
}

impl EpssClient {
    /// Creates a client with bounded timeouts and the official FIRST endpoint.
    ///
    /// Every default request has a 120-second total deadline. On native targets,
    /// the shared HTTP client also uses a 10-second connect timeout and a
    /// 30-second read-inactivity timeout.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::HttpClientBuild`] if reqwest cannot initialize its
    /// TLS or resolver configuration.
    pub fn new() -> Result<Self, ClientError> {
        Ok(Self::with_default_http_client(default_http_client()?))
    }

    /// Creates a client from a caller-configured reqwest client.
    ///
    /// The supplied client replaces the crate's default timeout policy. Use this
    /// to supply application-wide timeout, proxy, TLS, or connection-pool
    /// settings.
    #[must_use]
    pub fn with_http_client(http: reqwest::Client) -> Self {
        Self {
            http,
            endpoint: FIRST_EPSS_ENDPOINT.to_owned(),
            request_timeout: None,
        }
    }

    fn with_default_http_client(http: reqwest::Client) -> Self {
        Self {
            http,
            endpoint: FIRST_EPSS_ENDPOINT.to_owned(),
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
        }
    }

    /// Sets a total timeout for each request, overriding any client-level total
    /// timeout. Pass `None` to rely entirely on the supplied HTTP client.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Returns the per-request total timeout added by this client.
    #[must_use]
    pub const fn request_timeout(&self) -> Option<Duration> {
        self.request_timeout
    }

    /// Replaces the endpoint, primarily for mirrors and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidEndpoint`] unless `endpoint` is a valid
    /// HTTP or HTTPS URL.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self, ClientError> {
        self.endpoint = validate_endpoint(DataProvider::FirstEpss, endpoint.into())?;
        Ok(self)
    }

    /// Returns the configured endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Fetches the current scores for a set of CVEs.
    ///
    /// Results follow provider order and include each returned CVE once. FIRST
    /// silently omits unknown CVEs; the returned vector therefore may be shorter
    /// than the input. Empty input performs no network request.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport, HTTP status, or response-contract
    /// failures. Successful earlier batches are not returned if a later batch
    /// fails.
    pub async fn scores(&self, cves: &[CveId]) -> Result<Vec<EpssScore>, ClientError> {
        let batches = epss_batches(cves);
        let mut scores = Vec::with_capacity(cves.len());

        for batch in batches {
            let cve_parameter = batch
                .iter()
                .map(|cve| cve.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let limit = batch.len().to_string();
            let request = self
                .http
                .get(&self.endpoint)
                .header(header::ACCEPT, "application/json")
                .header(header::USER_AGENT, USER_AGENT)
                .query(&[
                    ("cve", cve_parameter.as_str()),
                    ("limit", limit.as_str()),
                    ("envelope", "true"),
                    ("pretty", "false"),
                ]);
            let response = with_request_timeout(request, self.request_timeout)
                .send()
                .await
                .map_err(|error| request_error(DataProvider::FirstEpss, &self.endpoint, error))?;
            let (envelope, endpoint): (EpssResponse, String) =
                decode_json(DataProvider::FirstEpss, response, MAX_EPSS_RESPONSE_BYTES)
                    .await
                    .map_err(|error| match error {
                        DecodeError::Client(error) => error,
                        DecodeError::Json { endpoint, error } => {
                            ClientError::EpssDecode { endpoint, error }
                        }
                    })?;
            validate_epss_page(&envelope, &batch, &endpoint)?;
            scores.extend(envelope.into_scores());
        }

        Ok(scores)
    }

    /// Fetches the current score for one CVE.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on request or response failure. A successful
    /// response without a score returns `Ok(None)`.
    pub async fn score(&self, cve: &CveId) -> Result<Option<EpssScore>, ClientError> {
        Ok(self.scores(std::slice::from_ref(cve)).await?.pop())
    }
}

/// A small asynchronous client for complete CISA KEV catalog snapshots.
#[derive(Clone, Debug)]
pub struct KevClient {
    http: reqwest::Client,
    endpoint: String,
    request_timeout: Option<Duration>,
}

impl KevClient {
    /// Creates a client with bounded timeouts and CISA's canonical endpoint.
    ///
    /// Every default request has a 120-second total deadline. On native targets,
    /// the shared HTTP client also uses a 10-second connect timeout and a
    /// 30-second read-inactivity timeout.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::HttpClientBuild`] if reqwest cannot initialize its
    /// TLS or resolver configuration.
    pub fn new() -> Result<Self, ClientError> {
        Ok(Self::with_default_http_client(default_http_client()?))
    }

    /// Creates a client from a caller-configured reqwest client.
    ///
    /// The supplied client replaces the crate's default timeout policy.
    #[must_use]
    pub fn with_http_client(http: reqwest::Client) -> Self {
        Self {
            http,
            endpoint: CISA_KEV_ENDPOINT.to_owned(),
            request_timeout: None,
        }
    }

    fn with_default_http_client(http: reqwest::Client) -> Self {
        Self {
            http,
            endpoint: CISA_KEV_ENDPOINT.to_owned(),
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
        }
    }

    /// Sets a total timeout for each request, overriding any client-level total
    /// timeout. Pass `None` to rely entirely on the supplied HTTP client.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Returns the per-request total timeout added by this client.
    #[must_use]
    pub const fn request_timeout(&self) -> Option<Duration> {
        self.request_timeout
    }

    /// Replaces the endpoint, primarily for the official mirror and tests.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidEndpoint`] unless `endpoint` is a valid
    /// HTTP or HTTPS URL.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Result<Self, ClientError> {
        self.endpoint = validate_endpoint(DataProvider::CisaKev, endpoint.into())?;
        Ok(self)
    }

    /// Returns the configured endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Downloads and validates the complete KEV catalog.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] on transport or HTTP failure, malformed JSON, or
    /// a declared count that does not match the downloaded entries.
    pub async fn catalog(&self) -> Result<KevCatalog, ClientError> {
        let request = self
            .http
            .get(&self.endpoint)
            .header(header::ACCEPT, "application/json")
            .header(header::USER_AGENT, USER_AGENT);
        let response = with_request_timeout(request, self.request_timeout)
            .send()
            .await
            .map_err(|error| request_error(DataProvider::CisaKev, &self.endpoint, error))?;
        let endpoint = response_endpoint(&response);
        let bytes =
            read_success_body(DataProvider::CisaKev, response, MAX_KEV_RESPONSE_BYTES).await?;
        KevCatalog::from_json_slice(&bytes)
            .map_err(|error| ClientError::KevDecode { endpoint, error })
    }
}

/// A convenience facade that joins FIRST EPSS and CISA KEV signals.
///
/// [`Self::try_default`] shares one HTTP client between both providers and uses
/// the same bounded timeouts as [`EpssClient::new`] and [`KevClient::new`].
#[derive(Clone, Debug)]
pub struct Enricher {
    epss: EpssClient,
    kev: KevClient,
}

impl Enricher {
    /// Creates an enricher whose provider clients share the default HTTP client.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::HttpClientBuild`] if reqwest cannot initialize its
    /// TLS or resolver configuration.
    pub fn try_default() -> Result<Self, ClientError> {
        let http = default_http_client()?;
        Ok(Self::new(
            EpssClient::with_default_http_client(http.clone()),
            KevClient::with_default_http_client(http),
        ))
    }

    /// Creates an enricher from independently configured provider clients.
    #[must_use]
    pub const fn new(epss: EpssClient, kev: KevClient) -> Self {
        Self { epss, kev }
    }

    /// Returns the EPSS client.
    #[must_use]
    pub const fn epss_client(&self) -> &EpssClient {
        &self.epss
    }

    /// Returns the KEV client.
    #[must_use]
    pub const fn kev_client(&self) -> &KevClient {
        &self.kev
    }

    /// Fetches both providers concurrently and joins their facts by CVE.
    ///
    /// Empty input performs no network requests. Applications making repeated
    /// queries should cache a catalog and use [`Self::enrich_with_catalog`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if either provider request or validation fails.
    pub async fn enrich(&self, cves: &[CveId]) -> Result<SignalSet, ClientError> {
        if cves.is_empty() {
            return Ok(SignalSet::empty());
        }

        let (epss, kev) = future::try_join(self.epss.scores(cves), self.kev.catalog()).await?;
        Ok(join_signals(cves, epss, &kev))
    }

    /// Fetches EPSS and joins it with a caller-cached KEV catalog.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the EPSS request or response validation fails.
    pub async fn enrich_with_catalog(
        &self,
        cves: &[CveId],
        catalog: &KevCatalog,
    ) -> Result<SignalSet, ClientError> {
        if cves.is_empty() {
            return Ok(join_signals(cves, [], catalog));
        }

        let epss = self.epss.scores(cves).await?;
        Ok(join_signals(cves, epss, catalog))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn default_http_client() -> Result<reqwest::Client, ClientError> {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .read_timeout(DEFAULT_READ_TIMEOUT)
        .build()
        .map_err(|error| ClientError::HttpClientBuild { error })
}

#[cfg(target_arch = "wasm32")]
fn default_http_client() -> Result<reqwest::Client, ClientError> {
    reqwest::Client::builder()
        .build()
        .map_err(|error| ClientError::HttpClientBuild { error })
}

fn with_request_timeout(
    request: reqwest::RequestBuilder,
    timeout: Option<Duration>,
) -> reqwest::RequestBuilder {
    match timeout {
        Some(timeout) => request.timeout(timeout),
        None => request,
    }
}

fn request_error(
    provider: DataProvider,
    configured_endpoint: &str,
    error: reqwest::Error,
) -> ClientError {
    let endpoint = error.url().map_or_else(
        || sanitized_endpoint(configured_endpoint),
        |url| sanitized_url(url.clone()),
    );
    ClientError::Request {
        provider,
        endpoint,
        error: error.without_url(),
    }
}

fn sanitized_endpoint(endpoint: &str) -> String {
    reqwest::Url::parse(endpoint)
        .map(sanitized_url)
        .unwrap_or_else(|_| "<invalid URL>".to_owned())
}

fn sanitized_url(mut url: reqwest::Url) -> String {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.into()
}

fn response_endpoint(response: &Response) -> String {
    sanitized_url(response.url().clone())
}

fn validate_endpoint(provider: DataProvider, endpoint: String) -> Result<String, ClientError> {
    let url = reqwest::Url::parse(&endpoint).map_err(|error| ClientError::InvalidEndpoint {
        provider,
        endpoint: sanitized_endpoint(&endpoint),
        message: error.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ClientError::InvalidEndpoint {
            provider,
            endpoint: sanitized_url(url),
            message: "scheme must be http or https".to_owned(),
        });
    }
    Ok(url.into())
}

fn epss_batches(cves: &[CveId]) -> Vec<Vec<&CveId>> {
    let mut seen = HashSet::with_capacity(cves.len());
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_chars = 0;

    for cve in cves {
        if !seen.insert(cve) {
            continue;
        }

        let added_chars = cve.as_str().len() + usize::from(!current.is_empty());
        if current_chars + added_chars > MAX_EPSS_CVE_PARAMETER_CHARS {
            batches.push(std::mem::take(&mut current));
            current_chars = 0;
        }
        current_chars += cve.as_str().len() + usize::from(!current.is_empty());
        current.push(cve);
    }

    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

fn validate_epss_page(
    envelope: &EpssResponse,
    requested: &[&CveId],
    endpoint: &str,
) -> Result<(), ClientError> {
    let returned = envelope.scores().len();
    if envelope.offset() != 0 || envelope.total() != returned || envelope.total() > envelope.limit()
    {
        return Err(ClientError::IncompleteEpssPage {
            endpoint: endpoint.to_owned(),
            total: envelope.total(),
            returned,
            offset: envelope.offset(),
            limit: envelope.limit(),
        });
    }

    let mut seen = HashSet::with_capacity(returned);
    for score in envelope.scores() {
        if !requested.contains(&score.cve()) {
            return Err(ClientError::UnexpectedEpssCve {
                endpoint: endpoint.to_owned(),
                cve: score.cve().clone(),
            });
        }
        if !seen.insert(score.cve()) {
            return Err(ClientError::DuplicateEpssCve {
                endpoint: endpoint.to_owned(),
                cve: score.cve().clone(),
            });
        }
    }
    Ok(())
}

async fn decode_json<T>(
    provider: DataProvider,
    response: Response,
    max_bytes: usize,
) -> Result<(T, String), DecodeError>
where
    T: DeserializeOwned,
{
    let endpoint = response_endpoint(&response);
    let body = read_success_body(provider, response, max_bytes)
        .await
        .map_err(DecodeError::Client)?;
    serde_json::from_slice(&body)
        .map(|value| (value, endpoint.clone()))
        .map_err(|error| DecodeError::Json { endpoint, error })
}

async fn read_success_body(
    provider: DataProvider,
    response: Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ClientError> {
    let status = response.status();
    let endpoint = response_endpoint(&response);
    if !status.is_success() {
        let body = read_error_excerpt(response).await;
        return Err(ClientError::HttpStatus {
            provider,
            endpoint,
            status: status.as_u16(),
            body,
        });
    }

    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(ClientError::ResponseTooLarge {
            provider,
            endpoint,
            limit_bytes: max_bytes,
        });
    }

    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(max_bytes);
    let mut body = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| ClientError::Request {
            provider,
            endpoint: endpoint.clone(),
            error: error.without_url(),
        })?;
        if chunk.len() > max_bytes.saturating_sub(body.len()) {
            return Err(ClientError::ResponseTooLarge {
                provider,
                endpoint,
                limit_bytes: max_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_error_excerpt(response: Response) -> String {
    let mut body = Vec::with_capacity(ERROR_BODY_BYTES);
    let mut stream = response.bytes_stream();
    while let Some(Ok(chunk)) = stream.next().await {
        let remaining = ERROR_BODY_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if body.len() == ERROR_BODY_BYTES {
            break;
        }
    }

    String::from_utf8_lossy(&body)
        .chars()
        .take(ERROR_BODY_CHARS)
        .collect()
}

enum DecodeError {
    Client(ClientError),
    Json {
        endpoint: String,
        error: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[test]
    fn batching_deduplicates_and_respects_character_limit() {
        let cves: Vec<CveId> = (1..=180)
            .map(|sequence| CveId::new(format!("CVE-2026-{sequence:04}")))
            .collect::<Result<_, _>>()
            .expect("valid CVEs");
        let mut with_duplicate = cves.clone();
        with_duplicate.push(cves[0].clone());

        let batches = epss_batches(&with_duplicate);

        assert!(batches.iter().all(|batch| {
            batch.iter().map(|cve| cve.as_str().len()).sum::<usize>() + batch.len() - 1
                <= MAX_EPSS_CVE_PARAMETER_CHARS
        }));
        assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), cves.len());
    }

    #[tokio::test]
    async fn response_reader_rejects_body_over_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"1234"))
            .mount(&server)
            .await;
        let response = reqwest::get(format!("{}/large", server.uri()))
            .await
            .expect("mock request succeeds");
        assert_eq!(response.content_length(), Some(4));

        let error = read_success_body(DataProvider::FirstEpss, response, 3)
            .await
            .expect_err("oversized response must fail");

        assert!(matches!(
            error,
            ClientError::ResponseTooLarge {
                provider: DataProvider::FirstEpss,
                limit_bytes: 3,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn response_reader_rejects_chunked_body_over_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/chunked"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("transfer-encoding", "chunked")
                    .set_body_bytes(b"1234"),
            )
            .mount(&server)
            .await;
        let response = reqwest::get(format!("{}/chunked", server.uri()))
            .await
            .expect("mock request succeeds");
        assert_eq!(response.content_length(), None);

        let error = read_success_body(DataProvider::FirstEpss, response, 3)
            .await
            .expect_err("oversized chunked response must fail");

        assert!(matches!(
            error,
            ClientError::ResponseTooLarge {
                provider: DataProvider::FirstEpss,
                limit_bytes: 3,
                ..
            }
        ));
    }

    #[test]
    fn diagnostic_endpoint_omits_credentials_query_and_fragment() {
        let endpoint = sanitized_endpoint("https://user:secret@example.test/feed?token=abc#part");

        assert_eq!(endpoint, "https://example.test/feed");
    }

    #[test]
    fn invalid_endpoint_errors_do_not_reveal_url_secrets() {
        let error = validate_endpoint(
            DataProvider::FirstEpss,
            "ftp://user:secret@example.test/feed?token=abc#part".to_owned(),
        )
        .expect_err("non-HTTP scheme must fail");

        assert!(!error.to_string().contains("secret"));
        assert!(!error.to_string().contains("token"));
        assert!(matches!(
            error,
            ClientError::InvalidEndpoint { endpoint, .. }
                if endpoint == "ftp://example.test/feed"
        ));
    }

    #[test]
    fn malformed_endpoint_errors_do_not_echo_input() {
        let error = validate_endpoint(
            DataProvider::CisaKev,
            "not a URL containing secret-token".to_owned(),
        )
        .expect_err("malformed URL must fail");

        assert!(!error.to_string().contains("secret-token"));
        assert!(matches!(
            error,
            ClientError::InvalidEndpoint { endpoint, .. } if endpoint == "<invalid URL>"
        ));
    }
}
