// SPDX-License-Identifier: Apache-2.0

use semver::Version;

use crate::cve::cache::CpeRecord;

pub fn matches_version(
    installed_version: &str,
    cpe: &CpeRecord,
) -> bool {
    let start_incl = cpe.version_start_including.as_deref();
    let end_excl = cpe.version_end_excluding.as_deref();
    let start_excl = cpe.version_start_excluding.as_deref();
    let end_incl = cpe.version_end_including.as_deref();

    if start_incl.is_none()
        && end_excl.is_none()
        && start_excl.is_none()
        && end_incl.is_none()
    {
        return true;
    }

    let ver = match parse_version(installed_version) {
        Some(v) => v,
        None => return false,
    };

    if let Some(start) = start_incl {
        if let Some(start_ver) = parse_version(start) {
            if !(ver >= start_ver) {
                return false;
            }
        } else if installed_version < start {
            return false;
        }
    }
    if let Some(start) = start_excl {
        if let Some(start_ver) = parse_version(start) {
            if !(ver > start_ver) {
                return false;
            }
        } else if installed_version <= start {
            return false;
        }
    }
    if let Some(end) = end_excl {
        if let Some(end_ver) = parse_version(end) {
            if !(ver < end_ver) {
                return false;
            }
        } else if installed_version >= end {
            return false;
        }
    }
    if let Some(end) = end_incl {
        if let Some(end_ver) = parse_version(end) {
            if !(ver <= end_ver) {
                return false;
            }
        } else if installed_version > end {
            return false;
        }
    }
    true
}

fn parse_version(version: &str) -> Option<Version> {
    let cleaned = clean_version(version);
    Version::parse(&cleaned).ok()
}

fn clean_version(version: &str) -> String {
    let mut cleaned = version.to_string();
    cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join("");
    cleaned = cleaned
        .split(|c: char| c == '-' || c == '_' || c == '+')
        .next()
        .unwrap_or(&cleaned)
        .to_string();
    cleaned = cleaned.trim_start_matches(|c: char| !c.is_ascii_digit() && c != '.').to_string();
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::cache::CpeRecord;

    fn make_cpe(
        product: &str,
        start_incl: Option<&str>,
        end_excl: Option<&str>,
        start_excl: Option<&str>,
        end_incl: Option<&str>,
    ) -> CpeRecord {
        CpeRecord {
            id: None,
            cve_id: "CVE-TEST".to_string(),
            cpe_name: format!("cpe:2.3:a:vendor:{}:{}:*:*:*:*:*:*:*", product, "*"),
            vendor: "vendor".to_string(),
            product: product.to_string(),
            version_start_including: start_incl.map(|s| s.to_string()),
            version_end_excluding: end_excl.map(|s| s.to_string()),
            version_start_excluding: start_excl.map(|s| s.to_string()),
            version_end_including: end_incl.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_exact_match_no_versions() {
        let cpe = make_cpe("openssl", None, None, None, None);
        assert!(matches_version("3.0.0", &cpe));
    }

    #[test]
    fn test_version_range_inclusive_exclusive() {
        let cpe = make_cpe("openssl", Some("1.0.0"), Some("3.0.0"), None, None);
        assert!(matches_version("1.0.0", &cpe));
        assert!(matches_version("1.5.0", &cpe));
        assert!(matches_version("2.9.9", &cpe));
        assert!(!matches_version("3.0.0", &cpe));
        assert!(!matches_version("0.9.0", &cpe));
    }

    #[test]
    fn test_version_range_exclusive_inclusive() {
        let cpe = make_cpe("openssl", None, None, Some("1.0.0"), Some("3.0.0"));
        assert!(!matches_version("1.0.0", &cpe));
        assert!(matches_version("1.5.0", &cpe));
        assert!(matches_version("3.0.0", &cpe));
        assert!(!matches_version("0.9.0", &cpe));
    }
}
