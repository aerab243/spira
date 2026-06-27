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

            let body = response.text().map_err(NvdError::HttpError)?;
            let nvd_response: NvdResponse = serde_json::from_str(&body).map_err(|e| {
                eprintln!("DEBUG body (first 500 chars): {}", &body[..body.len().min(500)]);
                NvdError::JsonError(e.into())
            })?;
            self.request_count += 1;

            for vuln in nvd_response.vulnerabilities {
                let cve_id = vuln.cve.as_ref().and_then(|c| c.id.clone()).unwrap_or_default();
                let cve = Self::parse_cve(vuln.cve.clone());
                let cpes = extract_cpe_matches(vuln.cve.as_ref(), &cve_id);
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

        // Récupération du premier set de métriques CVSS disponible, par ordre
        // de préférence : V4.0 > V3.1 > V3.0 > V2. V2 n'expose pas de
        // `baseSeverity` ; on le dérive alors du score selon les seuils NVD.
        let (cvss_score, severity) = match pick_cvss_metrics(&cve.metrics) {
            Some(v) => v,
            None => return None,
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

// ── NVD 2.0 Response structs ──

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    results_per_page: usize,
    #[allow(dead_code)]
    start_index: u32,
    total_results: u32,
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdVulnerability {
    cve: Option<NvdCve>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: Option<String>,
    #[allow(dead_code)]
    source_identifier: Option<String>,
    #[allow(dead_code)]
    vuln_status: Option<String>,
    descriptions: Vec<NvdDescription>,
    metrics: NvdMetrics,
    published: String,
    last_modified: String,
    configurations: Option<Vec<NvdConfigurationNode>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31")]
    #[allow(dead_code)]
    cvss_metric_v31: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV30")]
    #[allow(dead_code)]
    cvss_metric_v30: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV2")]
    #[allow(dead_code)]
    cvss_metric_v2: Option<Vec<NvdCvssMetric>>,
    #[serde(rename = "cvssMetricV40")]
    #[allow(dead_code)]
    cvss_metric_v40: Option<Vec<NvdCvssMetric>>,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdCvssMetric {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
    #[serde(rename = "baseSeverity")]
    #[allow(dead_code)]
    cvss_severity: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct NvdCvssData {
    #[serde(rename = "baseScore")]
    #[allow(dead_code)]
    base_score: f64,
    #[serde(rename = "baseSeverity")]
    #[allow(dead_code)]
    base_severity: Option<String>,
}

// ── CPE match nodes inside configurations ──

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvdConfigurationNode {
    #[allow(dead_code)]
    nodes: Option<Vec<NvdCpeMatchNode>>,
    #[allow(dead_code)]
    cpe_match: Option<Vec<NvdCpeMatch>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NvdCpeMatchNode {
    #[allow(dead_code)]
    operator: Option<String>,
    #[allow(dead_code)]
    negate: Option<bool>,
    #[serde(rename = "cpeMatch")]
    cpe_match: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct NvdCpeMatch {
    pub criteria: String,
    pub vulnerable: bool,
    #[allow(dead_code)]
    #[serde(rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "matchCriteriaId")]
    pub match_criteria_id: Option<String>,
}

fn extract_cpe_matches(
    cve: Option<&NvdCve>,
    cve_id: &str,
) -> Vec<CpeRecord> {
    let mut cpes = Vec::new();
    let cve = match cve {
        Some(c) => c,
        None => return cpes,
    };

    // Configurations are inside the cve object
    if let Some(ref config_nodes) = cve.configurations {
        for config_node in config_nodes {
            // Each config has nodes or cpeMatch directly
            if let Some(ref cpe_match_list) = config_node.cpe_match {
                for cpe_match in cpe_match_list {
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
            // Also try nodes (old format)
            if let Some(ref nodes) = config_node.nodes {
                for node in nodes {
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

/// Sélectionne le premier set de métriques CVSS disponible selon l'ordre de
/// préférence NVD : V4.0 > V3.1 > V3.0 > V2. Retourne `(score, severity)` où
/// `severity` est toujours dérivée si elle manque (cas de V2).
fn pick_cvss_metrics(metrics: &NvdMetrics) -> Option<(Option<f64>, Option<String>)> {
    // V3 : `baseSeverity` est exposé par NVD ; fallback sur dérivation si absent.
    for slot in [
        metrics.cvss_metric_v40.as_ref(),
        metrics.cvss_metric_v31.as_ref(),
        metrics.cvss_metric_v30.as_ref(),
    ] {
        if let Some(m) = slot.and_then(|m| m.first()) {
            let score = m.cvss_data.base_score;
            let sev = m
                .cvss_data
                .base_severity
                .clone()
                .unwrap_or_else(|| severity_from_score(score));
            return Some((Some(score), Some(sev)));
        }
    }

    // V2 : pas de `baseSeverity` dans la réponse NVD → dérivation systématique.
    if let Some(m) = metrics.cvss_metric_v2.as_ref().and_then(|m| m.first()) {
        let score = m.cvss_data.base_score;
        return Some((Some(score), Some(severity_from_score(score))));
    }

    None
}

/// Dérive la sévérité CVSS à partir du score, selon les seuils officiels.
/// Applicable aux métriques V2 et V3.
fn severity_from_score(score: f64) -> String {
    if score >= 9.0 {
        "CRITICAL".to_string()
    } else if score >= 7.0 {
        "HIGH".to_string()
    } else if score >= 4.0 {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_score_thresholds() {
        assert_eq!(severity_from_score(10.0), "CRITICAL");
        assert_eq!(severity_from_score(9.0), "CRITICAL");
        assert_eq!(severity_from_score(8.9), "HIGH");
        assert_eq!(severity_from_score(7.0), "HIGH");
        assert_eq!(severity_from_score(6.9), "MEDIUM");
        assert_eq!(severity_from_score(4.0), "MEDIUM");
        assert_eq!(severity_from_score(3.9), "LOW");
        assert_eq!(severity_from_score(0.0), "LOW");
    }
}