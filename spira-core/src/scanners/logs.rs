/// Scanner des logs — analyse les journaux d'authentification pour détecter
/// les tentatives d'intrusion et les activités suspectes.
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::{fs, process::Command};

pub struct LogScanner;

impl LogScanner {
    /// Chemins possibles pour les logs d'authentification.
    const AUTH_LOG_PATHS: &'static [&'static str] = &[
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
    ];

    /// Détecte quel fichier de log d'authentification est disponible.
    async fn detect_auth_log() -> Result<Option<String>, ScanError> {
        for path in Self::AUTH_LOG_PATHS {
            if let Ok(metadata) = fs::metadata(path).await {
                if metadata.is_file() && metadata.len() > 0 {
                    return Ok(Some(path.to_string()));
                }
            }
        }
        Ok(None)
    }

    /// Analyse les logs d'authentification pour les tentatives SSH échouées.
    async fn analyze_auth_logs(path: &str) -> Result<LogAnalysis, ScanError> {
        // Lire les 5000 dernières lignes du fichier de log
        let output = Command::new("tail")
            .arg("-n")
            .arg("5000")
            .arg(path)
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur lecture log: {}", e)))?;

        if !output.status.success() {
            return Err(ScanError::CommandError(
                "Impossible de lire les logs d'authentification".into(),
            ));
        }

        let content = String::from_utf8_lossy(&output.stdout);
        let mut analysis = LogAnalysis::default();

        for line in content.lines() {
            // Tentatives SSH échouées
            if line.contains("Failed password") || line.contains("authentication failure") {
                analysis.failed_logins += 1;

                // Extraire l'IP si présente
                if let Some(ip) = extract_ip_from_log(line) {
                    analysis.failed_ips
                        .entry(ip.clone())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);
                }
            }

            // Tentatives SSH réussies
            if line.contains("Accepted password") || line.contains("Accepted publickey") {
                analysis.successful_logins += 1;
            }

            // Sessions sudo
            if line.contains("sudo:") {
                if line.contains("COMMAND=") {
                    analysis.sudo_commands += 1;
                }
                if line.contains("FAILED") || line.contains("failure") {
                    analysis.sudo_failures += 1;
                }
                if line.contains("NOPASSWD") {
                    analysis.sudo_nopasswd += 1;
                }
            }

            // Connexions root directes
            if line.contains("sshd") && line.contains("root") && line.contains("Accepted") {
                analysis.root_logins += 1;
            }

            // Service SSH en écoute
            if line.contains("Server listening on") && line.contains("sshd") {
                // Pas un problème, mais indique que SSH est actif
                analysis.ssh_active = true;
            }
        }

        Ok(analysis)
    }

    /// Vérifie les dernières modifications des logs système.
    async fn check_log_integrity() -> Result<Vec<Vulnerability>, ScanError> {
        let mut vulns = Vec::new();

        for path in Self::AUTH_LOG_PATHS {
            if let Ok(metadata) = fs::metadata(path).await {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        // Log non modifié depuis plus de 7 jours
                        if elapsed.as_secs() > 7 * 86400 {
                            vulns.push(Vulnerability {
                                id: format!("LOG-STALE-{}", path.replace('/', "-")),
                                package: path.to_string(),
                                version: String::new(),
                                severity: Severity::Medium,
                                description: format!(
                                    "Le fichier de log {} n'a pas été modifié depuis plus de 7 jours. Les logs pourraient avoir été effacés ou le service d'audit désactivé.",
                                    path
                                ),
                                affected_version: path.to_string(),
                                fixed_version: None,
                                cvss_score: 5.0,
                                scan_type: ScanType::Logs,
                                remediation: Some("Vérifiez le service rsyslog : sudo systemctl status rsyslog".to_string()),
                            });
                        }
                    }
                }
            }
        }

        Ok(vulns)
    }
}

#[derive(Debug, Default)]
struct LogAnalysis {
    failed_logins: u32,
    successful_logins: u32,
    failed_ips: std::collections::HashMap<String, u32>,
    sudo_commands: u32,
    sudo_failures: u32,
    sudo_nopasswd: u32,
    root_logins: u32,
    ssh_active: bool,
}

/// Extrait une adresse IP d'une ligne de log d'authentification.
fn extract_ip_from_log(line: &str) -> Option<String> {
    // Cherche des patterns d'IP dans les logs SSH
    // Format typique : "Failed password for user X from 192.168.1.1 port 22"
    let line_lower = line.to_lowercase();

    for keyword in &["from ", "rhost="] {
        if let Some(pos) = line_lower.find(keyword) {
            let after = &line[pos + keyword.len()..];
            let ip_candidate = after.split(|c: char| c == ' ' || c == '\t' || c == '\n')
                .next()
                .unwrap_or("")
                .trim();

            // Vérifier si c'est une IP valide
            if is_valid_ip(ip_candidate) {
                return Some(ip_candidate.to_string());
            }
        }
    }

    None
}

/// Vérifie grossièrement si une chaîne ressemble à une adresse IP.
fn is_valid_ip(s: &str) -> bool {
    // IPv4
    if s.chars().filter(|&c| c == '.').count() == 3 {
        return s.split('.').all(|part| part.parse::<u16>().map_or(false, |n| n <= 255));
    }
    false
}

#[async_trait::async_trait]
impl Scanner for LogScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Logs
    }

    fn description(&self) -> &'static str {
        "Analyse les journaux d'authentification pour détecter les intrusions"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan des logs démarré");

        let mut vulnerabilities = Vec::new();

        // Détecter le fichier de log
        let auth_log = Self::detect_auth_log().await?;

        match auth_log {
            Some(path) => {
                log::info!("Analyse du fichier de log : {}", path);
                let analysis = Self::analyze_auth_logs(&path).await?;

                // 1. Nombre élevé de tentatives échouées
                if analysis.failed_logins > 100 {
                    let top_ips: Vec<String> = {
                        let mut ips: Vec<_> = analysis.failed_ips.iter().collect();
                        ips.sort_by(|a, b| b.1.cmp(a.1));
                        ips.iter().take(5).map(|(ip, count)| format!("{} ({} fois)", ip, count)).collect()
                    };

                    let description = if analysis.failed_logins > 1000 {
                        format!(
                            "⚠️ ALERTE : {} tentatives de connexion SSH échouées détectées. Attaque par force brute en cours probable !",
                            analysis.failed_logins
                        )
                    } else {
                        format!(
                            "{} tentatives de connexion SSH échouées détectées. Les principales IP suspectes : {}",
                            analysis.failed_logins,
                            top_ips.join(", ")
                        )
                    };

                    let severity = if analysis.failed_logins > 1000 {
                        Severity::Critical
                    } else if analysis.failed_logins > 500 {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                    let cvss = match severity {
                        Severity::Critical => 9.0,
                        Severity::High => 7.5,
                        _ => 5.5,
                    };

                    vulnerabilities.push(Vulnerability {
                        id: "LOG-BRUTE-FORCE".to_string(),
                        package: "ssh".to_string(),
                        version: String::new(),
                        severity,
                        description,
                        affected_version: analysis.failed_logins.to_string(),
                        fixed_version: None,
                        cvss_score: cvss,
                        scan_type: ScanType::Logs,
                        remediation: Some(
                            "Installez fail2ban : sudo apt install fail2ban. \
                             Changez le port SSH dans /etc/ssh/sshd_config. \
                             Utilisez l'authentification par clé SSH."
                                .to_string(),
                        ),
                    });
                }

                // 2. Connexions root directes
                if analysis.root_logins > 0 {
                    vulnerabilities.push(Vulnerability {
                        id: "LOG-ROOT-LOGIN".to_string(),
                        package: "ssh".to_string(),
                        version: String::new(),
                        severity: Severity::High,
                        description: format!(
                            "{} connexion(s) directe(s) en tant que root détectée(s) via SSH. La connexion root directe est déconseillée.",
                            analysis.root_logins
                        ),
                        affected_version: analysis.root_logins.to_string(),
                        fixed_version: None,
                        cvss_score: 7.0,
                        scan_type: ScanType::Logs,
                        remediation: Some(
                            "Désactivez la connexion root SSH : dans /etc/ssh/sshd_config, \
                             définissez PermitRootLogin no, puis sudo systemctl restart sshd"
                                .to_string(),
                        ),
                    });
                }

                // 3. Utilisation de sudo sans mot de passe
                if analysis.sudo_nopasswd > 0 {
                    vulnerabilities.push(Vulnerability {
                        id: "LOG-SUDO-NOPASSWD".to_string(),
                        package: "sudo".to_string(),
                        version: String::new(),
                        severity: Severity::Medium,
                        description: format!(
                            "{} utilisation(s) de sudo sans mot de passe détectée(s). Certains utilisateurs peuvent exécuter des commandes sudo sans authentification.",
                            analysis.sudo_nopasswd
                        ),
                        affected_version: analysis.sudo_nopasswd.to_string(),
                        fixed_version: None,
                        cvss_score: 6.5,
                        scan_type: ScanType::Logs,
                        remediation: Some(
                            "Vérifiez les règles NOPASSWD dans /etc/sudoers : sudo visudo"
                                .to_string(),
                        ),
                    });
                }
            }
            None => {
                // Aucun log trouvé — c'est inquiétant
                vulnerabilities.push(Vulnerability {
                    id: "LOG-NOT-FOUND".to_string(),
                    package: "rsyslog".to_string(),
                    version: String::new(),
                    severity: Severity::High,
                    description: "Aucun fichier de log d'authentification trouvé. Le service de logging pourrait être désactivé ou les logs ont été effacés.".to_string(),
                    affected_version: "N/A".to_string(),
                    fixed_version: None,
                    cvss_score: 7.0,
                    scan_type: ScanType::Logs,
                    remediation: Some("Installez et configurez rsyslog : sudo apt install rsyslog && sudo systemctl enable rsyslog".to_string()),
                });
            }
        }

        // 4. Vérifier l'intégrité des logs
        if let Ok(integrity_issues) = Self::check_log_integrity().await {
            vulnerabilities.extend(integrity_issues);
        }

        log::info!(
            "Scan des logs terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
