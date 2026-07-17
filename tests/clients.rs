#![cfg(feature = "client")]

use std::{collections::HashSet, time::Duration};

use custos_enrich::{
    ClientError, CveId, DataProvider, Enricher, EpssClient, KevCatalog, KevClient,
    VulnerabilitySignals,
};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{header, method, path, query_param},
};

const EXPECTED_USER_AGENT: &str = concat!("custos-enrich/", env!("CARGO_PKG_VERSION"));

fn default_epss_client() -> EpssClient {
    EpssClient::new().expect("default EPSS client initializes")
}

fn default_kev_client() -> KevClient {
    KevClient::new().expect("default KEV client initializes")
}

#[test]
fn default_clients_expose_a_bounded_total_deadline() {
    let enricher = Enricher::try_default().expect("default enricher initializes");

    assert_eq!(
        default_epss_client().request_timeout(),
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        default_kev_client().request_timeout(),
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        enricher.epss_client().request_timeout(),
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        enricher.kev_client().request_timeout(),
        Some(Duration::from_secs(120))
    );
}

#[test]
fn injected_http_clients_do_not_receive_an_implicit_total_deadline() {
    let http = reqwest::Client::new();

    assert_eq!(
        EpssClient::with_http_client(http.clone()).request_timeout(),
        None
    );
    assert_eq!(KevClient::with_http_client(http).request_timeout(), None);
}

#[tokio::test]
async fn per_request_timeout_is_enforced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_bytes(include_bytes!("fixtures/epss_single_response.json")),
        )
        .mount(&server)
        .await;
    let endpoint = format!("{}/epss.json", server.uri());
    let client = EpssClient::with_http_client(reqwest::Client::new())
        .with_request_timeout(Some(Duration::from_millis(10)))
        .with_endpoint(&endpoint)
        .expect("valid mock endpoint");
    let cve = CveId::new("CVE-2021-44228").expect("valid CVE");

    let error = client
        .score(&cve)
        .await
        .expect_err("delayed response must time out");

    assert!(matches!(
        error,
        ClientError::Request {
            endpoint: actual_endpoint,
            error,
            ..
        } if actual_endpoint == endpoint && error.is_timeout()
    ));
}

#[tokio::test]
async fn epss_client_requests_an_explicit_enveloped_json_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .and(query_param("cve", "CVE-2021-44228"))
        .and(query_param("limit", "1"))
        .and(query_param("envelope", "true"))
        .and(query_param("pretty", "false"))
        .and(header("accept", "application/json"))
        .and(header("user-agent", EXPECTED_USER_AGENT))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(include_bytes!("fixtures/epss_single_response.json")),
        )
        .mount(&server)
        .await;
    let client = default_epss_client()
        .with_endpoint(format!("{}/epss.json", server.uri()))
        .expect("valid mock endpoint");
    let cve = CveId::new("CVE-2021-44228").expect("valid CVE");

    let scores = client.scores(&[cve]).await.expect("successful request");

    assert_eq!(scores.len(), 1);
}

#[tokio::test]
async fn epss_client_rejects_incomplete_pages() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{
                "status":"OK","status-code":200,"version":"1.0","access":"public",
                "total":2,"offset":0,"limit":2,
                "data":[{
                    "cve":"CVE-2021-44228","epss":"0.99999",
                    "percentile":"1.0","date":"2026-07-16"
                }]
            }"#,
            "application/json",
        ))
        .mount(&server)
        .await;
    let client = default_epss_client()
        .with_endpoint(format!("{}/epss.json", server.uri()))
        .expect("valid mock endpoint");
    let cves = [
        CveId::new("CVE-2021-44228").expect("valid CVE"),
        CveId::new("CVE-2023-34362").expect("valid CVE"),
    ];

    let error = client
        .scores(&cves)
        .await
        .expect_err("incomplete page must fail");

    assert!(matches!(
        error,
        ClientError::IncompleteEpssPage {
            total: 2,
            returned: 1,
            offset: 0,
            limit: 2,
            ..
        }
    ));
}

#[tokio::test]
async fn epss_client_rejects_unrequested_cves() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{
                "status":"OK","status-code":200,"version":"1.0","access":"public",
                "total":1,"offset":0,"limit":1,
                "data":[{
                    "cve":"CVE-2023-34362","epss":"0.9",
                    "percentile":"0.99","date":"2026-07-16"
                }]
            }"#,
            "application/json",
        ))
        .mount(&server)
        .await;
    let endpoint = format!("{}/epss.json", server.uri());
    let client = default_epss_client()
        .with_endpoint(&endpoint)
        .expect("valid mock endpoint");
    let requested = CveId::new("CVE-2021-44228").expect("valid CVE");

    let error = client
        .scores(&[requested])
        .await
        .expect_err("unrequested record must fail");

    assert!(matches!(
        error,
        ClientError::UnexpectedEpssCve {
            endpoint: actual_endpoint,
            cve
        } if actual_endpoint == endpoint && cve.as_str() == "CVE-2023-34362"
    ));
}

#[tokio::test]
async fn epss_client_rejects_duplicate_records() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{
                "status":"OK","status-code":200,"version":"1.0","access":"public",
                "total":2,"offset":0,"limit":2,
                "data":[
                    {"cve":"CVE-2021-44228","epss":"0.9","percentile":"0.99","date":"2026-07-16"},
                    {"cve":"CVE-2021-44228","epss":"0.8","percentile":"0.98","date":"2026-07-16"}
                ]
            }"#,
            "application/json",
        ))
        .mount(&server)
        .await;
    let endpoint = format!("{}/epss.json", server.uri());
    let client = default_epss_client()
        .with_endpoint(&endpoint)
        .expect("valid mock endpoint");
    let requested = CveId::new("CVE-2021-44228").expect("valid CVE");

    let error = client
        .scores(&[requested])
        .await
        .expect_err("duplicate record must fail");

    assert!(matches!(
        error,
        ClientError::DuplicateEpssCve {
            endpoint: actual_endpoint,
            cve
        } if actual_endpoint == endpoint && cve.as_str() == "CVE-2021-44228"
    ));
}

#[tokio::test]
async fn epss_client_issues_every_character_bounded_batch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(|request: &Request| {
            let limit = request
                .url
                .query_pairs()
                .find_map(|(name, value)| (name == "limit").then_some(value.into_owned()))
                .expect("request contains limit")
                .parse::<usize>()
                .expect("limit is numeric");
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "OK",
                "status-code": 200,
                "version": "1.0",
                "access": "public",
                "total": 0,
                "offset": 0,
                "limit": limit,
                "data": []
            }))
        })
        .expect(2)
        .mount(&server)
        .await;
    let endpoint = format!("{}/epss.json", server.uri());
    let client = default_epss_client()
        .with_endpoint(endpoint)
        .expect("valid mock endpoint");
    let cves: Vec<CveId> = (1..=180)
        .map(|sequence| CveId::new(format!("CVE-2026-{sequence:04}")))
        .collect::<Result<_, _>>()
        .expect("valid CVEs");

    let scores = client.scores(&cves).await.expect("valid empty responses");
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    let mut requested = HashSet::new();
    for request in requests {
        let parameter = request
            .url
            .query_pairs()
            .find_map(|(name, value)| (name == "cve").then_some(value.into_owned()))
            .expect("request contains cve parameter");
        assert!(parameter.len() <= 2_000);
        requested.extend(parameter.split(',').map(str::to_owned));
    }

    assert!(scores.is_empty());
    assert_eq!(requested.len(), cves.len());
}

#[tokio::test]
async fn kev_client_rejects_truncated_catalogs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            r#"{"catalogVersion":"1","dateReleased":"2026-07-16T17:00:15Z","count":1,"vulnerabilities":[]}"#,
            "application/json",
        ))
        .mount(&server)
        .await;
    let client = default_kev_client()
        .with_endpoint(format!("{}/kev.json", server.uri()))
        .expect("valid mock endpoint");

    let error = client
        .catalog()
        .await
        .expect_err("truncated catalog must fail");

    assert!(matches!(error, ClientError::KevDecode { .. }));
}

#[tokio::test]
async fn client_status_errors_have_bounded_bodies_and_endpoint_context() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(ResponseTemplate::new(503).set_body_string("x".repeat(3_000)))
        .mount(&server)
        .await;
    let endpoint = format!("{}/kev.json", server.uri());
    let client = default_kev_client()
        .with_endpoint(&endpoint)
        .expect("valid mock endpoint");

    let error = client
        .catalog()
        .await
        .expect_err("non-success status must fail");

    let ClientError::HttpStatus {
        provider,
        endpoint: actual_endpoint,
        status,
        body,
    } = error
    else {
        panic!("expected HTTP status error");
    };
    assert_eq!(provider, DataProvider::CisaKev);
    assert_eq!(actual_endpoint, endpoint);
    assert_eq!(status, 503);
    assert_eq!(body.chars().count(), 512);
}

#[tokio::test]
async fn enricher_joins_both_provider_responses() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(include_bytes!("fixtures/epss_single_response.json")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/kev.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(include_bytes!("fixtures/kev_catalog.json")),
        )
        .mount(&server)
        .await;
    let epss = default_epss_client()
        .with_endpoint(format!("{}/epss.json", server.uri()))
        .expect("valid mock endpoint");
    let kev = default_kev_client()
        .with_endpoint(format!("{}/kev.json", server.uri()))
        .expect("valid mock endpoint");
    let enricher = Enricher::new(epss, kev);
    let cve = CveId::new("CVE-2021-44228").expect("valid CVE");

    let signals = enricher
        .enrich(std::slice::from_ref(&cve))
        .await
        .expect("successful enrichment");

    assert!(
        signals
            .get(&cve)
            .is_some_and(VulnerabilitySignals::has_known_ransomware_use)
    );
}

#[tokio::test]
async fn enricher_empty_input_performs_no_requests() {
    let server = MockServer::start().await;
    let epss = default_epss_client()
        .with_endpoint(format!("{}/epss.json", server.uri()))
        .expect("valid mock endpoint");
    let kev = default_kev_client()
        .with_endpoint(format!("{}/kev.json", server.uri()))
        .expect("valid mock endpoint");
    let enricher = Enricher::new(epss, kev);

    let signals = enricher.enrich(&[]).await.expect("empty input succeeds");
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");

    assert!(signals.is_empty());
    assert!(signals.kev_snapshot().is_none());
    assert!(requests.is_empty());
}

#[tokio::test]
async fn enricher_empty_cached_join_retains_catalog_provenance() {
    let server = MockServer::start().await;
    let epss = default_epss_client()
        .with_endpoint(format!("{}/epss.json", server.uri()))
        .expect("valid mock endpoint");
    let kev = default_kev_client()
        .with_endpoint(format!("{}/kev.json", server.uri()))
        .expect("valid mock endpoint");
    let catalog = KevCatalog::from_json_slice(include_bytes!("fixtures/kev_catalog.json"))
        .expect("valid KEV fixture");
    let enricher = Enricher::new(epss, kev);

    let signals = enricher
        .enrich_with_catalog(&[], &catalog)
        .await
        .expect("empty cached join succeeds");
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");

    assert!(signals.is_empty());
    assert_eq!(
        signals
            .kev_snapshot()
            .map(|metadata| metadata.catalog_version()),
        Some("2026.07.16")
    );
    assert!(requests.is_empty());
}

#[tokio::test]
async fn enricher_with_cached_catalog_only_requests_epss() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/epss.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(include_bytes!("fixtures/epss_single_response.json")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let epss = default_epss_client()
        .with_endpoint(format!("{}/epss.json", server.uri()))
        .expect("valid mock endpoint");
    let kev = default_kev_client()
        .with_endpoint(format!("{}/kev.json", server.uri()))
        .expect("valid mock endpoint");
    let catalog = KevCatalog::from_json_slice(include_bytes!("fixtures/kev_catalog.json"))
        .expect("valid KEV fixture");
    let enricher = Enricher::new(epss, kev);
    let cve = CveId::new("CVE-2021-44228").expect("valid CVE");

    let signals = enricher
        .enrich_with_catalog(std::slice::from_ref(&cve), &catalog)
        .await
        .expect("cached enrichment succeeds");
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");

    assert!(
        signals
            .get(&cve)
            .and_then(VulnerabilitySignals::epss)
            .is_some()
    );
    assert!(
        signals
            .get(&cve)
            .is_some_and(VulnerabilitySignals::is_known_exploited)
    );
    assert_eq!(requests.len(), 1);
}
