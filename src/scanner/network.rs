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
        let service_name = guess_service_name(port);
        let cpes = cache.search_cves_by_cpe("", &service_name).unwrap_or_default();

        let mut cves: Vec<_> = cpes
            .into_iter()
            .map(|(cve, _)| (cve.id, cve.cvss_score, cve.severity))
            .collect();

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
            service_name,
            cves,
        });
    }

    Ok(results)
}

fn guess_service_name(port: &PortInfo) -> String {
    let process = &port.process;
    if let Some(start) = process.find("(\"") {
        if let Some(end) = process[start + 2..].find('"') {
            return process[start + 2..start + 2 + end].to_string();
        }
    }
    match port.port {
        21 => "ftp".to_string(),
        22 => "openssh".to_string(),
        23 => "telnet".to_string(),
        25 => "smtp".to_string(),
        53 => "dns".to_string(),
        80 => "httpd".to_string(),
        110 => "pop3".to_string(),
        143 => "imap".to_string(),
        443 => "nginx".to_string(),
        3306 => "mysql".to_string(),
        5432 => "postgresql".to_string(),
        6379 => "redis".to_string(),
        27017 => "mongodb".to_string(),
        _ => format!("port_{}", port.port),
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
        assert_eq!(guess_service_name(&port), "sshd");
    }

    #[test]
    fn test_guess_service_name_from_port() {
        let port = make_port(80, "");
        assert_eq!(guess_service_name(&port), "httpd");
        let port = make_port(3306, "");
        assert_eq!(guess_service_name(&port), "mysql");
    }

    #[test]
    fn test_guess_unknown_port() {
        let port = make_port(9999, "");
        assert_eq!(guess_service_name(&port), "port_9999");
    }
}
