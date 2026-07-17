use custos_enrich::{CveId, EpssResponse, KevCatalog, VulnerabilitySignals, join_signals};

#[test]
fn offline_models_join_into_source_neutral_signals() {
    let epss = EpssResponse::from_json_slice(include_bytes!("fixtures/epss_response.json"))
        .expect("valid EPSS fixture");
    let kev = KevCatalog::from_json_slice(include_bytes!("fixtures/kev_catalog.json"))
        .expect("valid KEV fixture");
    let cve = CveId::new("CVE-2021-44228").expect("valid CVE");

    let signals = join_signals(std::slice::from_ref(&cve), epss.into_scores(), &kev);

    assert!(
        signals
            .get(&cve)
            .is_some_and(VulnerabilitySignals::is_known_exploited)
    );
}
