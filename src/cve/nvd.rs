// SPDX-License-Identifier: Apache-2.0

//! Client pour les **data feeds JSON NVD** (snapshots gzip).
//!
//! Plutôt que l'API REST `services.nvd.nist.gov` (qui impose un rate-limit
//! strict sans clé : 5 req/30s), on télécharge les fichiers gzip publiés par
//! NVD sur `nvd.nist.gov/vuln/data-feeds/json/`. Aucune authentification
//! requise, aucun rate limit, format identique à l'API.
//!
//! Deux fichiers sont consommés à chaque update :
//! - `recent_cves.json.gz`  : CVEs **publiés** dans les 8 derniers jours
//! - `modified_cves.json.gz` : CVEs **modifiés** dans les 8 derniers jours
//!   (chevauchement avec recent, mais garantit qu'un CVE corrigé récemment
//!    sera re-fetché même s'il a été publié il y a longtemps)
//!
//! Chaque snapshot est identifié par un timestamp `YYYY-MM-DD-HHMM` listé dans
//! l'index HTML `https://nvd.nist.gov/vuln/data-feeds/json/`. On prend le
//! timestamp le plus récent (= premier dossier alphabétiquement après tri).

use std::io::Read;
use std::time::Duration;

use flate2::read::GzDecoder;
use reqwest::blocking::Client;
use serde::Deserialize;
use thiserror::Error;

use crate::cve::cache::{CpeRecord, CveRecord};

#[derive(Debug, Error)]
pub enum NvdError {
    #[error("Téléchargement NVD impossible après {0} tentative(s): {1}")]
    DownloadFailed(u32, #[source] reqwest::Error),
    #[error("Erreur lecture réponse NVD: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("NVD a retourné HTTP {0} pour {1}")]
    ApiError(u16, String),
    #[error("Erreur parsing JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Erreur décompression gzip: {0}")]
    DecompressionError(#[from] std::io::Error),
}

const NVD_FEED_BASE: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
const NVD_FEED_FILES: &[&str] = &["nvdcve-2.0-recent.json.gz", "nvdcve-2.0-modified.json.gz"];
const NVD_MAX_RETRIES: u32 = 5;
const NVD_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300); // 5 min : gros fichiers

pub struct NvdClient {
    client: Client,
}

impl NvdClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .gzip(false) // on décompresse nous-mêmes via flate2
            .timeout(NVD_DOWNLOAD_TIMEOUT)
            .build()
            .expect("client HTTP reqwest");
        Self { client }
    }

    /// Télécharge les feeds NVD 2.0 (récent + modifié) et retourne toutes les
    /// entrées.
    pub fn fetch_feed(&self) -> Result<Vec<(CveRecord, Vec<CpeRecord>)>, NvdError> {
        let mut all_items: Vec<(CveRecord, Vec<CpeRecord>)> = Vec::new();
        for file in NVD_FEED_FILES {
            let url = format!("{}/{}", NVD_FEED_BASE, file);
            println!("Téléchargement de {file}…");
            let bytes = self.download_with_retry(&url)?;
            println!("Décompression et parsing de {file} ({:.1} Mo)…",
                     bytes.len() as f64 / 1_048_576.0);
            let items = parse_feed_gz(&bytes)?;
            println!("  → {} entrées extraites de {file}", items.len());
            all_items.extend(items);
        }

        Ok(all_items)
    }

    fn download_with_retry(&self, url: &str) -> Result<Vec<u8>, NvdError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.client.get(url).send() {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let bytes = resp.bytes().map_err(NvdError::HttpError)?.to_vec();
                        return Ok(bytes);
                    }
                    let code = status.as_u16();
                    if attempt < NVD_MAX_RETRIES && (code == 429 || code == 503) {
                        let backoff = Duration::from_secs(2u64.pow(attempt - 1));
                        eprintln!(
                            "NVD: HTTP {code} (tentative {}/{}). Retry dans {:?}…",
                            attempt, NVD_MAX_RETRIES, backoff
                        );
                        std::thread::sleep(backoff);
                        continue;
                    }
                    return Err(NvdError::ApiError(code, url.to_string()));
                }
                Err(e) if attempt < NVD_MAX_RETRIES => {
                    let backoff = Duration::from_secs(2u64.pow(attempt - 1));
                    eprintln!(
                        "NVD: téléchargement échoué (tentative {}/{}): {}. Retry dans {:?}…",
                        attempt, NVD_MAX_RETRIES, e, backoff
                    );
                    std::thread::sleep(backoff);
                    continue;
                }
                Err(e) => return Err(NvdError::DownloadFailed(attempt, e)),
            }
        }
    }

}

/// Décompresse un buffer gzip et parse le JSON contenu en `(CveRecord, CpeRecord)`.
pub fn parse_feed_gz(bytes: &[u8]) -> Result<Vec<(CveRecord, Vec<CpeRecord>)>, NvdError> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decompressed = Vec::with_capacity(bytes.len() * 4);
    decoder.read_to_end(&mut decompressed)?;
    let nvd_response: NvdResponse = serde_json::from_slice(&decompressed)?;
    extract_items(&nvd_response)
}

fn extract_items(
    nvd_response: &NvdResponse,
) -> Result<Vec<(CveRecord, Vec<CpeRecord>)>, NvdError> {
    let mut out = Vec::with_capacity(nvd_response.vulnerabilities.len());
    for vuln in &nvd_response.vulnerabilities {
        let cve_id = vuln.cve.as_ref().and_then(|c| c.id.clone()).unwrap_or_default();
        if let Some(cve) = parse_cve(vuln.cve.clone()) {
            let cpes = extract_cpe_matches(vuln.cve.as_ref(), &cve_id);
            out.push((cve, cpes));
        }
    }
    Ok(out)
}

// (is_valid_timestamp supprimée — plus besoin avec les URLs fixes du schema 2.0)

// ── NVD 2.0 feed structs ──

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    #[allow(dead_code)]
    results_per_page: usize,
    #[allow(dead_code)]
    start_index: u32,
    #[allow(dead_code)]
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

    if let Some(ref config_nodes) = cve.configurations {
        for config_node in config_nodes {
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

fn parse_cve(cve: Option<NvdCve>) -> Option<CveRecord> {
    let cve = cve?;
    let id = cve.id?;
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.clone())
        .unwrap_or_default();

    let (cvss_score, severity) = match pick_cvss_metrics(&cve.metrics) {
        Some(v) => v,
        None => return None,
    };

    // Les dates NVD sont au format ISO 8601 (ex: "2026-06-19T06:16:58.920")
    // avec des fractions de seconde que NaiveDateTime::parse_from_str
    // gère via "%Y-%m-%dT%H:%M:%S%.f". On convertit ensuite en DateTime<Utc>.
    use chrono::{NaiveDateTime, DateTime, Utc};
    let naive_pub = NaiveDateTime::parse_from_str(&cve.published, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    let naive_mod = NaiveDateTime::parse_from_str(&cve.last_modified, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    let published = DateTime::<Utc>::from_naive_utc_and_offset(naive_pub, Utc);
    let modified = DateTime::<Utc>::from_naive_utc_and_offset(naive_mod, Utc);

    Some(CveRecord {
        id,
        description,
        cvss_score,
        severity,
        published,
        modified,
    })
}

/// Sélectionne le premier set de métriques CVSS disponible selon l'ordre de
/// préférence NVD : V4.0 > V3.1 > V3.0 > V2. Retourne `(score, severity)` où
/// `severity` est toujours dérivée si elle manque (cas de V2).
fn pick_cvss_metrics(metrics: &NvdMetrics) -> Option<(Option<f64>, Option<String>)> {
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

    if let Some(m) = metrics.cvss_metric_v2.as_ref().and_then(|m| m.first()) {
        let score = m.cvss_data.base_score;
        return Some((Some(score), Some(severity_from_score(score))));
    }

    None
}

/// Dérive la sévérité CVSS à partir du score, selon les seuils officiels.
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

    // (test is_valid_timestamp supprimé — URLs fixes du schema 2.0)

    #[test]
    fn test_parse_cpe_uri_extracts_vendor_and_product() {
        let (vendor, product, _) = parse_cpe_uri(
            "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*",
        ).expect("valid CPE");
        assert_eq!(vendor, "openssl");
        assert_eq!(product, "openssl");
    }

    #[test]
    fn test_parse_cpe_uri_rejects_invalid() {
        assert!(parse_cpe_uri("cpe:2.2:a:openssl:openssl:1.0").is_none());
        assert!(parse_cpe_uri("not-a-cpe").is_none());
        assert!(parse_cpe_uri("").is_none());
    }
}
