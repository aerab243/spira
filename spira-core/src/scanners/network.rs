/// Scanner réseau — détecte les ports ouverts et services exposés.
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::process::Command;

pub struct NetworkScanner;

impl NetworkScanner {
    /// Récupère la liste des ports d'écoute via `ss -tlnp`.
    async fn get_listening_ports() -> Result<Vec<PortInfo>, ScanError> {
        let output = Command::new("ss")
            .arg("-tlnp4")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur ss: {}", e)))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let mut ports = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format ss: "LISTEN 0      128        0.0.0.0:22       0.0.0.0:*    users:(("sshd:..."))"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            // Extraire le port de la 4e colonne (local address:port)
            let local = parts[3];
            let (address, port_str) = match local.rsplit_once(':') {
                Some((addr, p)) => (addr.to_string(), p.to_string()),
                None => continue,
            };

            let port: u16 = match port_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Extraire le nom du process de la dernière colonne
            let process = if parts.len() > 5 {
                let last = parts[parts.len() - 1];
                // Format: "users:(("nginx",...))" ou "users:(("sshd",...))"
                if let Some(inner) = last.strip_prefix("users:((\"") {
                    inner.split('"').next().unwrap_or("").to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            ports.push(PortInfo {
                port,
                address,
                process,
            });
        }

        Ok(ports)
    }

    /// Récupère aussi les ports UDP via `ss -ulnp`.
    async fn get_listening_udp_ports() -> Result<Vec<PortInfo>, ScanError> {
        let output = Command::new("ss")
            .arg("-ulnp4")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur ss: {}", e)))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let mut ports = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format UDP similaire à TCP
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let local = parts[3];
            let (address, port_str) = match local.rsplit_once(':') {
                Some((addr, p)) => (addr.to_string(), p.to_string()),
                None => continue,
            };

            let port: u16 = match port_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            ports.push(PortInfo {
                port,
                address,
                process: String::new(),
            });
        }

        Ok(ports)
    }

    /// Vérifie si un port est considéré comme dangereux (service exposé sur 0.0.0.0).
    fn check_port_risk(port: u16, address: &str, process: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Services qui ne devraient PAS être exposés sur 0.0.0.0
        let exposed = address == "0.0.0.0" || address == "::";
        if !exposed && !address.starts_with('*') {
            return vulns;
        }

        // Liste des ports sensibles
        let (severity, desc, remediation) = match port {
            21 => (Severity::High,
                "FTP (port 21) exposé sur toutes les interfaces. FTP transmet les identifiants en clair.",
                "Utilisez SFTP ou SCP avec SSH à la place de FTP. Iptables: sudo ufw deny 21/tcp"),
            22 => (Severity::Info,
                "SSH (port 22) exposé sur toutes les interfaces. Vérifiez que l'authentification par clé est utilisée.",
                "Restreignez l'accès SSH par IP si possible : /etc/hosts.allow"),
            23 => (Severity::High,
                "Telnet (port 23) exposé. Telnet transmet tout en clair, y compris les mots de passe.",
                "Désactivez Telnet (sudo apt purge telnetd) et utilisez SSH."),
            25 => (Severity::Medium,
                "SMTP (port 25) exposé. Serveur mail potentiellement ouvert au relay.",
                "Vérifiez la configuration anti-relay. Utilisez un firewall pour limiter l'accès."),
            53 => (Severity::Medium,
                "DNS (port 53) exposé. Serveur DNS potentiellement vulnérable aux attaques DDoS par amplification.",
                "Restreignez les requêtes DNS récursives aux clients autorisés."),
            80 => (Severity::Info,
                "HTTP (port 80) exposé. Assurez-vous que le trafic est redirigé vers HTTPS.",
                "Configurez une redirection 301 vers HTTPS dans votre serveur web."),
            135 | 139 | 445 => (Severity::High,
                "SMB/NetBIOS (port {port}) exposé. Protocole Windows potentiellement vulnérable.",
                "Désactivez SMB si non utilisé : sudo ufw deny 135 139 445"),
            3306 => (Severity::Critical,
                "MySQL/MariaDB (port 3306) exposé sur toutes les interfaces. Base de données accessible depuis le réseau.",
                "Configurez MySQL pour écouter uniquement sur localhost dans /etc/mysql/my.cnf (bind-address = 127.0.0.1)"),
            5432 => (Severity::Critical,
                "PostgreSQL (port 5432) exposé sur toutes les interfaces.",
                "Configurez pg_hba.conf pour restreindre les connexions et écouter sur localhost."),
            6379 => (Severity::Critical,
                "Redis (port 6379) exposé sur toutes les interfaces. Redis sans authentification est dangereux.",
                "Configurez Redis avec requirepass et bind 127.0.0.1 dans redis.conf"),
            27017 => (Severity::Critical,
                "MongoDB (port 27017) exposé sur toutes les interfaces. Risque de ransomwares.",
                "Configurez MongoDB avec authentification et bind_ip = 127.0.0.1"),
            8080 => (Severity::Medium,
                "Proxy HTTP (port 8080) exposé. Risque de proxy ouvert.",
                "Vérifiez que le service nécessite une authentification."),
            8443 => (Severity::Info,
                "HTTPS alternatif (port 8443) exposé.",
                "Assurez-vous que le certificat TLS est valide."),
            _ => return vulns,
        };

        let service_name = if process.is_empty() {
            match port {
                21 => "FTP".to_string(),
                22 => "SSH".to_string(),
                23 => "Telnet".to_string(),
                25 => "SMTP".to_string(),
                53 => "DNS".to_string(),
                80 => "HTTP".to_string(),
                139 | 445 => "SMB".to_string(),
                3306 => "MySQL".to_string(),
                5432 => "PostgreSQL".to_string(),
                6379 => "Redis".to_string(),
                27017 => "MongoDB".to_string(),
                _ => format!("Port {}", port),
            }
        } else {
            process.to_string()
        };

        let id = format!("NET-OPEN-{}", port);
        vulns.push(Vulnerability {
            id,
            package: format!("{}", service_name),
            version: String::new(),
            severity,
            description: desc.replace("{port}", &port.to_string()),
            affected_version: format!("Port {} ({})", port, address),
            fixed_version: None,
            cvss_score: match severity {
                Severity::Critical => 9.0,
                Severity::High => 7.5,
                Severity::Medium => 5.5,
                Severity::Low => 3.5,
                Severity::Info => 1.0,
            },
            scan_type: ScanType::Network,
            remediation: Some(remediation.to_string()),
        });

        vulns
    }
}

#[derive(Debug)]
struct PortInfo {
    port: u16,
    address: String,
    process: String,
}

#[async_trait::async_trait]
impl Scanner for NetworkScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Network
    }

    fn description(&self) -> &'static str {
        "Analyse les ports ouverts et les services réseau exposés"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan réseau démarré");

        let tcp_ports = Self::get_listening_ports().await?;
        let udp_ports = Self::get_listening_udp_ports().await?;

        log::info!("{} ports TCP ouverts, {} ports UDP ouverts détectés", tcp_ports.len(), udp_ports.len());

        let mut vulnerabilities = Vec::new();

        for port_info in &tcp_ports {
            let mut port_vulns = Self::check_port_risk(port_info.port, &port_info.address, &port_info.process);
            vulnerabilities.append(&mut port_vulns);
        }

        for port_info in &udp_ports {
            let mut port_vulns = Self::check_port_risk(port_info.port, &port_info.address, &port_info.process);
            vulnerabilities.append(&mut port_vulns);
        }

        log::info!(
            "Scan réseau terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
