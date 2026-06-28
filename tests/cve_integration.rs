// SPDX-License-Identifier: Apache-2.0

//! Tests d'intégration du cache CVE (SQLite en mémoire) et du matcher de versions.

use chrono::Utc;
use spira::cve::cache::{CpeRecord, CveCache, CveRecord};

fn make_cve(id: &str, severity: Option<&str>, score: Option<f64>) -> CveRecord {
    let now = Utc::now();
    CveRecord {
        id: id.to_string(),
        description: format!("Test vulnerability {id}"),
        cvss_score: score,
        severity: severity.map(|s| s.to_string()),
        published: now,
        modified: now,
    }
}

fn make_cpe(cve_id: &str, product: &str, vendor: &str, start: Option<&str>, end: Option<&str>) -> CpeRecord {
    CpeRecord {
        id: None,
        cve_id: cve_id.to_string(),
        cpe_name: format!("cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"),
        vendor: vendor.to_string(),
        product: product.to_string(),
        version_start_including: start.map(String::from),
        version_end_excluding: end.map(String::from),
        version_start_excluding: None,
        version_end_including: None,
    }
}

#[test]
fn upsert_then_get_cve_roundtrip() {
    let cache = CveCache::in_memory().expect("in_memory cache");
    let cve = make_cve("CVE-2024-0001", Some("HIGH"), Some(7.5));
    cache.upsert_cve(&cve).expect("upsert");

    let fetched = cache.get_cve("CVE-2024-0001").expect("get").expect("present");
    assert_eq!(fetched.id, "CVE-2024-0001");
    assert_eq!(fetched.severity.as_deref(), Some("HIGH"));
    assert_eq!(fetched.cvss_score, Some(7.5));
}

#[test]
fn upsert_is_idempotent() {
    let cache = CveCache::in_memory().expect("in_memory cache");
    let cve = make_cve("CVE-2024-0002", Some("LOW"), Some(3.0));
    cache.upsert_cve(&cve).expect("upsert 1");
    cache.upsert_cve(&cve).expect("upsert 2");
    cache.upsert_cve(&cve).expect("upsert 3");

    assert_eq!(cache.count_cves().expect("count"), 1);
}

#[test]
fn search_cves_by_cpe_returns_matching_pairs() {
    let cache = CveCache::in_memory().expect("in_memory cache");
    cache.upsert_cve(&make_cve("CVE-2024-1000", Some("CRITICAL"), Some(9.8))).unwrap();
    cache.upsert_cve(&make_cve("CVE-2024-1001", Some("MEDIUM"), Some(5.0))).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-1000", "openssl", "openssl", None, None)).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-1001", "openssl", "openssl", Some("1.0.0"), Some("3.0.0"))).unwrap();

    let hits = cache.search_cves_by_cpe("openssl", "openssl").expect("search");
    assert_eq!(hits.len(), 2);
    let ids: Vec<&str> = hits.iter().map(|(c, _)| c.id.as_str()).collect();
    assert!(ids.contains(&"CVE-2024-1000"));
    assert!(ids.contains(&"CVE-2024-1001"));
}

#[test]
fn search_cves_by_cpe_filters_other_products() {
    let cache = CveCache::in_memory().expect("in_memory cache");
    cache.upsert_cve(&make_cve("CVE-2024-2000", Some("HIGH"), Some(7.0))).unwrap();
    cache.upsert_cve(&make_cve("CVE-2024-2001", Some("HIGH"), Some(7.0))).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-2000", "openssl", "openssl", None, None)).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-2001", "curl", "haxx", None, None)).unwrap();

    let openssl = cache.search_cves_by_cpe("openssl", "openssl").expect("openssl");
    let curl = cache.search_cves_by_cpe("haxx", "curl").expect("curl");
    assert_eq!(openssl.len(), 1);
    assert_eq!(curl.len(), 1);
    assert_eq!(openssl[0].0.id, "CVE-2024-2000");
    assert_eq!(curl[0].0.id, "CVE-2024-2001");
}

#[test]
fn search_cpes_by_product_returns_vendor_agnostic_matches() {
    // Le cas d'usage de network.rs : on ne connaît pas le vendor.
    let cache = CveCache::in_memory().expect("in_memory cache");
    cache.upsert_cve(&make_cve("CVE-2024-3000", Some("HIGH"), Some(8.0))).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-3000", "nginx", "f5", None, None)).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-3000", "nginx", "nginx_org", None, None)).unwrap();

    let hits = cache.search_cpes_by_product("nginx").expect("product search");
    assert_eq!(hits.len(), 2, "doit matcher les deux vendors");
}

#[test]
fn unknown_product_returns_empty() {
    let cache = CveCache::in_memory().expect("in_memory cache");
    cache.upsert_cve(&make_cve("CVE-2024-9999", Some("LOW"), Some(2.0))).unwrap();
    cache.insert_cpe(&make_cpe("CVE-2024-9999", "openssl", "openssl", None, None)).unwrap();

    let hits = cache.search_cves_by_cpe("openssl", "inexistant").expect("search");
    assert!(hits.is_empty());
}
