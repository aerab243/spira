use std::env;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde::Deserialize;
use thiserror::Error;

use crate::cve::cache::{CpeRecord, CveRecord};

#[derive(Debug, Error)]
pub enum NvdError {
    #[error("Erreur HTTP: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("Erreur parsing JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Rate limit NVD atteint, attendre avant de réessayer")]
    RateLimited,
}

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_REQUEST_DELAY: Duration = Duration::from_millis(100);
const NVD_RATE_LIMIT_WINDOW: usize = 5;
const NVD_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(30);

pub struct NvdClient {
    client: Client,
    api_key: Option<String>,
    request_count: usize,
    window_start: Instant,
}

impl NvdClient {
    pub fn new() -> Self {
        let api_key = env::var("NVD_API_KEY").ok();
        let client = Client::builder()
            .gzip(true)
            .brotli(true)
            .deflate(true)
            .timeout(Duration::from_secs(60))
            .build()
            .expect("client HTTP reqwest");

        Self {
            client,
            api_key,
            request_count: 0,
            window_start: Instant::now(),
        }
    }

    pub fn fetch_recent(&mut self, days: u32) -> Result<Vec<(CveRecord, Vec<CpeRecord>)>, NvdError> {
        let end_date = Utc::now();
        let start_date = end_date - chrono::Duration::days(days as i64);
        self.fetch_range(&start_date, &end_date)
    }

    pub fn fetch_range(
        &mut self,
        start: &DateTime<Utc>,
        end: &DateTime<Utc>,
    ) -> Result<Vec<(CveRecord, Vec<CpeRecord>)>, NvdError> {
        let mut all_items: Vec<(CveRecord, Vec<CpeRecord>)> = Vec::new();
        let mut start_index = 0u32;
        let page_size = 200u32;

        loop {
            self.wait_if_needed()?;

            let mut url = format!(
                "{}?pubStartDate={}&pubEndDate={}&startIndex={}&resultsPerPage={}",
                NVD_API_BASE,
                start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                start_index,
                page_size,
            );

            if let Some(ref key) = self.api_key {
                url.push_str(&format!("&apiKey={}", key));
            }

            let response = self.client.get(&url).send()?;
            if response.status() == reqwest::StatusCode::FORBIDDEN {
                return Err(NvdError::RateLimited);
            }

            let nvd_response: NvdResponse = response.json()?;
            self.request_count += 1;

            for vuln in nvd_response.vulnerabilities {
                let cve_id = vuln.cve.as_ref().and_then(|c| c.id.clone()).unwrap_or_default();
                let cve = Self::parse_cve(vuln.cve.clone());
                let cpes = extract_cpe_matches(&vuln, &cve_id);
                if let Some(cve) = cve {
                    all_items.push((cve, cpes));
                }
            }

            start_index += nvd_response.results_per_page as u32;
            if start_index >= nvd_response.total_results {
                break;
            }
        }

        Ok(all_items)
    }

    fn wait_if_needed(&mut self) -> Result<(), NvdError> {
        if self.request_count >= NVD_RATE_LIMIT_WINDOW {
            let elapsed = self.window_start.elapsed();
            if elapsed < NVD_RATE_LIMIT_INTERVAL {
                std::thread::sleep(NVD_RATE_LIMIT_INTERVAL - elapsed);
            }
            self.request_count = 0;
            self.window_start = Instant::now();
        }
        std::thread::sleep(NVD_REQUEST_DELAY);
        Ok(())
    }

    fn parse_cve(cve: Option<NvdCve>) -> Option<CveRecord> {
        let cve = cve?;
        let id = cve.id?;
        let description = cve
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.clone())
            .unwrap_or_default();

        let Some((cvss_score, severity)) = cve
            .metrics
            .cvss_metric_v31
            .or(cve.metrics.cvss_metric_v30)
            .or(cve.metrics.cvss_metric_v2)
            .and_then(|metrics| metrics.first().cloned())
            .map(|m| (Some(m.cvss_data.base_score), Some(m.cvss_severity)))
        else {
            return None;
        };

        let published = cve.published.parse().ok()?;
        let modified = cve.last_modified.parse().ok()?;

        Some(CveRecord {
            id,
            description,
            cvss_score,
            severity,
            published,
            modified,
        })
    }
}

#[derive(Debug, Deserialize)]
struct NvdResponse {
    results_per_page: usize,
    #[allow(dead_code)]
    start_index: u32,
    total_results: u32,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    #[allow(dead_code)]
    cve: Option<NvdCve>,
    configurations: Option<NvdConfigurations>,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdCve {
    id: Option<String>,
    descriptions: Vec<NvdDescription>,
    metrics: NvdMetrics,
    published: String,
    last_modified: String,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    cvss_metric_v2: Option<Vec<NvdCvssMetric>>,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
    #[serde(rename = "baseSeverity")]
    cvss_severity: String,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Deserialize)]
struct NvdConfigurations {
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdNode {
    cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NvdCpeMatch {
    pub criteria: String,
    pub vulnerable: bool,
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
}

fn extract_cpe_matches(
    vuln: &NvdVulnerability,
    cve_id: &str,
) -> Vec<CpeRecord> {
    let mut cpes = Vec::new();
    if let Some(ref configs) = vuln.configurations {
        for node in &configs.nodes {
            for cpe_match in &node.cpe_match {
                if !cpe_match.vulnerable {
                    continue;
                }
                if let Some((vendor, product, _)) = parse_cpe_uri(&cpe_match.criteria) {
                    cpes.push(CpeRecord {
                        id: None,
                        cve_id: cve_id.to_string(),
                        cpe_name: cpe_match.criteria.clone(),
                        vendor,
                        product,
                        version_start_including: cpe_match.version_start_including.clone(),
                        version_end_excluding: cpe_match.version_end_excluding.clone(),
                        version_start_excluding: cpe_match.version_start_excluding.clone(),
                        version_end_including: cpe_match.version_end_including.clone(),
                    });
                }
            }
        }
    }
    cpes
}

fn parse_cpe_uri(uri: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = uri.split(':').collect();
    if parts.len() >= 6 && parts[0] == "cpe" && parts[1] == "2.3" {
        let vendor = parts[3].to_string();
        let product = parts[4].to_string();
        return Some((vendor, product, String::new()));
    }
    None
}
