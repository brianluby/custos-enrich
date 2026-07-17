use custos_enrich::{CveId, Enricher};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cves = [CveId::new("CVE-2021-44228")?, CveId::new("CVE-2023-34362")?];
    let signals = Enricher::try_default()?.enrich(&cves).await?;

    for (cve, signal) in signals {
        println!(
            "{cve}: epss={:?}, kev={}, ransomware={}",
            signal.epss_probability(),
            signal.is_known_exploited(),
            signal.has_known_ransomware_use()
        );
    }
    Ok(())
}
