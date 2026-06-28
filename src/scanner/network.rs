// SPDX-License-Identifier: Apache-2.0

use crate::cve::cache::CveCache;
use crate::scanner::services::{detect_open_ports, PortInfo, ServiceError};

#[derive(Debug, Clone, PartialEq)]
pub struct PortVulnerability {
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub cves: Vec<(String, Option<f64>, Option<String>)>,
}

pub fn scan_ports_cves(cache: &CveCache) -> Result<Vec<PortVulnerability>, ServiceError> {
    let ports = detect_open_ports()?;
    let mut results = Vec::new();

    for port in &ports {
        // On collecte les CVE pour tous les candidats (process name + ports)
        // pour ne pas rater de matches (apache2/httpd, sshd/openssh, etc.).
        let candidates = guess_service_names(port);
        let primary = candidates
            .first()
            .cloned()
            .unwrap_or_else(|| format!("port_{}", port.port));

        let mut seen = std::collections::HashSet::new();
        let mut cves: Vec<(String, Option<f64>, Option<String>)> = Vec::new();
        for candidate in &candidates {
            // search_cpes_by_product matche uniquement sur p.product (sans exiger
            // un vendor exact), ce qui est exactement ce qu'on veut ici puisque
            // on ne connaît pas le vendor à partir du nom de processus.
            let cpes = cache.search_cpes_by_product(candidate).unwrap_or_default();
            for (cve, _cpe) in cpes {
                if seen.insert(cve.id.clone()) {
                    cves.push((cve.id, cve.cvss_score, cve.severity));
                }
            }
        }

        cves.sort_by(|a, b| {
            let score_a = a.1.unwrap_or(0.0);
            let score_b = b.1.unwrap_or(0.0);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        results.push(PortVulnerability {
            port: port.port,
            protocol: port.protocol.clone(),
            service_name: primary,
            cves,
        });
    }

    Ok(results)
}

/// Retourne une liste de noms de produits candidats pour un port ouvert.
/// Plusieurs noms sont essayés car le même service peut apparaître sous
/// différents noms selon la distro (apache2 vs httpd, openssh vs ssh, etc.).
fn guess_service_names(port: &PortInfo) -> Vec<String> {
    let mut candidates = Vec::new();

    // 1. Extraire le nom de binaire depuis le champ process de `ss -tulpn`
    //    (format: users:(("sshd",pid=1234,fd=3)))
    if let Some(start) = port.process.find("(\"") {
        if let Some(end) = port.process[start + 2..].find('"') {
            let bin = &port.process[start + 2..start + 2 + end];
            // Le nom de binaire est un très bon premier candidat CPE.
            candidates.push(bin.to_string());
        }
    }

    // 2. Ajouter les alias de port connus pour maximiser les chances
    //    de matcher un CPE dans le cache NVD.
    for alias in port_aliases(port.port) {
        if !candidates.contains(&alias) {
            candidates.push(alias);
        }
    }

    if candidates.is_empty() {
        candidates.push(format!("port_{}", port.port));
    }

    candidates
}

fn port_aliases(port: u16) -> Vec<String> {
    match port {
        21 => vec!["ftp".to_string(), "vsftpd".to_string()],
        22 => vec![
            "openssh".to_string(),
            "sshd".to_string(),
            "ssh".to_string(),
        ],
        23 => vec!["telnet".to_string(), "telnetd".to_string()],
        25 => vec![
            "postfix".to_string(),
            "sendmail".to_string(),
            "exim".to_string(),
            "smtp".to_string(),
        ],
        53 => vec![
            "bind".to_string(),
            "named".to_string(),
            "dns".to_string(),
            "dnsmasq".to_string(),
            "unbound".to_string(),
        ],
        80 => vec![
            "apache".to_string(),
            "apache2".to_string(),
            "httpd".to_string(),
            "nginx".to_string(),
            "lighttpd".to_string(),
            "http_server".to_string(),
        ],
        110 => vec!["dovecot".to_string(), "pop3".to_string(), "pop3d".to_string()],
        143 => vec!["dovecot".to_string(), "imap".to_string(), "imapd".to_string()],
        443 => vec![
            "apache".to_string(),
            "apache2".to_string(),
            "httpd".to_string(),
            "nginx".to_string(),
            "lighttpd".to_string(),
        ],
        445 => vec!["samba".to_string(), "smbd".to_string()],
        3306 => vec![
            "mysql".to_string(),
            "mariadb".to_string(),
            "mysqld".to_string(),
        ],
        5432 => vec!["postgresql".to_string(), "postgres".to_string()],
        6379 => vec!["redis".to_string(), "redis-server".to_string()],
        27017 => vec!["mongodb".to_string(), "mongod".to_string()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_port(port: u16, process: &str) -> PortInfo {
        PortInfo {
            protocol: "tcp".to_string(),
            local_addr: "0.0.0.0".to_string(),
            port,
            process: process.to_string(),
        }
    }

    #[test]
    fn test_guess_service_name_from_process() {
        let port = make_port(22, "users:((\"sshd\",pid=1234,fd=3))");
        let candidates = guess_service_names(&port);
        assert_eq!(candidates[0], "sshd");
        // les alias du port 22 sont ajoutés après
        assert!(candidates.contains(&"openssh".to_string()));
    }

    #[test]
    fn test_guess_service_name_from_port_only() {
        // Pas de champ process → on retombe sur les alias du port.
        let port = make_port(80, "");
        let candidates = guess_service_names(&port);
        assert!(candidates.contains(&"apache".to_string()));
        assert!(candidates.contains(&"httpd".to_string()));
        assert!(candidates.contains(&"nginx".to_string()));
    }

    #[test]
    fn test_guess_unknown_port() {
        let port = make_port(9999, "");
        let candidates = guess_service_names(&port);
        assert_eq!(candidates, vec!["port_9999".to_string()]);
    }

    #[test]
    fn test_no_duplicate_candidates() {
        // Le nom de process peut déjà apparaître dans les alias → on dédoublonne.
        let port = make_port(22, "users:((\"sshd\",pid=1234,fd=3))");
        let candidates = guess_service_names(&port);
        let unique: std::collections::HashSet<_> = candidates.iter().collect();
        assert_eq!(unique.len(), candidates.len());
    }
}
