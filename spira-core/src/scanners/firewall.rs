/// Scanner du pare-feu — vérifie l'état des règles iptables/nftables.
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::process::Command;

pub struct FirewallScanner;

impl FirewallScanner {
    /// Vérifie si iptables est installé et la politique par défaut.
    async fn check_iptables() -> Result<IptablesStatus, ScanError> {
        let output = Command::new("iptables")
            .arg("-L")
            .arg("-n")
            .arg("--line-numbers")
            .output()
            .await;

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let has_rules = output.status.success()
                    && stdout.lines().count() > 2; // Plus que l'en-tête

                // Détection des politiques par défaut
                let input_policy = stdout.lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let is_default_drop = input_policy.contains("DROP") || input_policy.contains("REJECT");

                Ok(IptablesStatus {
                    available: true,
                    has_rules,
                    is_default_drop,
                    rules_output: stdout,
                    error_output: stderr,
                })
            }
            Err(_) => Ok(IptablesStatus {
                available: false,
                has_rules: false,
                is_default_drop: false,
                rules_output: String::new(),
                error_output: String::new(),
            }),
        }
    }

    /// Vérifie si nftables est actif.
    async fn check_nftables() -> Result<NftablesStatus, ScanError> {
        let output = Command::new("nft")
            .arg("list ruleset")
            .output()
            .await;

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let has_rules = output.status.success() && !stdout.trim().is_empty();

                Ok(NftablesStatus {
                    available: true,
                    has_rules,
                    rules_output: stdout,
                })
            }
            Err(_) => Ok(NftablesStatus {
                available: false,
                has_rules: false,
                rules_output: String::new(),
            }),
        }
    }

    /// Vérifie si ufw (Uncomplicated Firewall) est actif.
    async fn check_ufw() -> Result<UfwStatus, ScanError> {
        let output = Command::new("ufw")
            .arg("status")
            .output()
            .await;

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let is_active = stdout.to_lowercase().contains("active")
                    || stdout.to_lowercase().contains("actif");

                Ok(UfwStatus {
                    available: true,
                    is_active,
                    status_output: stdout,
                })
            }
            Err(_) => Ok(UfwStatus {
                available: false,
                is_active: false,
                status_output: String::new(),
            }),
        }
    }

    /// Vérifie les règles iptables pour détecter des configurations dangereuses.
    fn analyze_iptables_rules(
        iptables: &IptablesStatus,
        nftables: &NftablesStatus,
        ufw: &UfwStatus,
    ) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let has_firewall = iptables.has_rules || nftables.has_rules || ufw.is_active;
        let has_tool = iptables.available || nftables.available || ufw.available;

        if !has_firewall {
            if has_tool {
                vulns.push(Vulnerability {
                    id: "FW-NO-RULES".to_string(),
                    package: "iptables/nftables".to_string(),
                    version: String::new(),
                    severity: Severity::Critical,
                    description: "Aucune règle de pare-feu active détectée. Tous les ports sont potentiellement accessibles.".to_string(),
                    affected_version: "Toutes".to_string(),
                    fixed_version: None,
                    cvss_score: 9.0,
                    scan_type: ScanType::Firewall,
                    remediation: Some("Activez un pare-feu : sudo ufw enable (ou configurez iptables/nftables)".to_string()),
                });
            } else {
                vulns.push(Vulnerability {
                    id: "FW-NOT-INSTALLED".to_string(),
                    package: "firewall".to_string(),
                    version: String::new(),
                    severity: Severity::High,
                    description: "Aucun outil de pare-feu (iptables/nftables/ufw) n'est installé sur le système. Aucune protection réseau !".to_string(),
                    affected_version: "N/A".to_string(),
                    fixed_version: None,
                    cvss_score: 8.0,
                    scan_type: ScanType::Firewall,
                    remediation: Some("Installez un pare-feu : sudo apt install ufw && sudo ufw enable".to_string()),
                });
            }
        } else if !iptables.is_default_drop && iptables.has_rules {
            vulns.push(Vulnerability {
                id: "FW-POLICY-ACCEPT".to_string(),
                package: "iptables".to_string(),
                version: String::new(),
                severity: Severity::Medium,
                description: "La politique par défaut d'INPUT est ACCEPT. Les paquets entrants sont acceptés par défaut.".to_string(),
                affected_version: "INPUT".to_string(),
                fixed_version: None,
                cvss_score: 5.5,
                scan_type: ScanType::Firewall,
                remediation: Some("Changez la politique par défaut : sudo iptables -P INPUT DROP".to_string()),
            });
        }

        vulns
    }
}

#[derive(Debug)]
struct IptablesStatus {
    available: bool,
    has_rules: bool,
    is_default_drop: bool,
    #[allow(dead_code)]
    rules_output: String,
    #[allow(dead_code)]
    error_output: String,
}

#[derive(Debug)]
struct NftablesStatus {
    available: bool,
    has_rules: bool,
    #[allow(dead_code)]
    rules_output: String,
}

#[derive(Debug)]
struct UfwStatus {
    available: bool,
    is_active: bool,
    #[allow(dead_code)]
    status_output: String,
}

#[async_trait::async_trait]
impl Scanner for FirewallScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Firewall
    }

    fn description(&self) -> &'static str {
        "Vérifie la configuration du pare-feu (iptables/nftables)"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan du pare-feu démarré");

        let iptables = Self::check_iptables().await?;
        let nftables = Self::check_nftables().await?;
        let ufw = Self::check_ufw().await?;

        log::info!(
            "Pare-feu : iptables={}, nftables={}, ufw={}",
            if iptables.available { "OK" } else { "absent" },
            if nftables.available { "OK" } else { "absent" },
            if ufw.available && ufw.is_active { "actif" } else { "inactif" }
        );

        let vulnerabilities = Self::analyze_iptables_rules(&iptables, &nftables, &ufw);

        log::info!(
            "Scan du pare-feu terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
