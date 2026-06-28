// SPDX-License-Identifier: Apache-2.0

use std::fs;

use thiserror::Error;

use crate::cve::cache::{CveCache, CveRecord, CpeRecord};
use crate::cve::matcher::matches_version;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelInfo {
    pub version: String,
    pub release: String,
    pub arch: String,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("Impossible de lire /proc/version")]
    IoError(#[from] std::io::Error),
    #[error("Format /proc/version inattendu")]
    ParseError,
    #[error("Erreur cache CVE: {0}")]
    CacheError(String),
}

pub fn detect() -> Result<KernelInfo, KernelError> {
    let content = fs::read_to_string("/proc/version")?;
    let parts: Vec<&str> = content.split_whitespace().collect();

    if parts.len() < 3 {
        return Err(KernelError::ParseError);
    }

    let version = parts[2].to_string();
    let arch = parts
        .get(3)
        .map(|s| {
            s.trim_end_matches(|c: char| c.is_ascii_alphanumeric() && c.is_ascii_digit())
                .trim_end_matches('-')
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    Ok(KernelInfo {
        version,
        release: content.trim().to_string(),
        arch,
    })
}

pub fn scan_kernel_cves(cache: &CveCache) -> Result<Vec<(CveRecord, CpeRecord)>, KernelError> {
    let kernel = detect()?;
    let version_cleaned = clean_kernel_version(&kernel.version);

    let cpes = cache
        .search_cves_by_cpe("linux", "linux_kernel")
        .map_err(|e| KernelError::CacheError(e.to_string()))?;

    let mut results = Vec::new();
    for (cve, cpe) in cpes {
        if matches_version(&version_cleaned, &cpe) {
            results.push((cve, cpe));
        }
    }

    results.sort_by(|a, b| {
        let score_a = a.0.cvss_score.unwrap_or(0.0);
        let score_b = b.0.cvss_score.unwrap_or(0.0);
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(results)
}

fn clean_kernel_version(version: &str) -> String {
    version.split('-').next().unwrap_or(version).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_version() {
        let sample = "Linux version 6.1.0-17-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.69-1 (2023-12-30)\n";
        let parts: Vec<&str> = sample.split_whitespace().collect();
        assert_eq!(parts[2], "6.1.0-17-amd64");
    }

    #[test]
    fn test_clean_kernel_version() {
        assert_eq!(clean_kernel_version("6.1.0-17-amd64"), "6.1.0");
        assert_eq!(clean_kernel_version("5.15.0"), "5.15.0");
        assert_eq!(clean_kernel_version("4.19.0-21-amd64"), "4.19.0");
    }
}
