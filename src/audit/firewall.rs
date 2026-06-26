use std::process::Command;

use thiserror::Error;

use crate::audit::ssh::AuditFinding;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("Commande introuvable: {0}")]
    CommandNotFound(String),
    #[error("Erreur d'exécution: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Erreur de parsing: {0}")]
    ParseError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallInfo {
    pub backend: &'static str,
    pub active: bool,
    pub rules: Vec<String>,
    pub findings: Vec<AuditFinding>,
}

pub fn audit_firewall() -> Result<Vec<FirewallInfo>, FirewallError> {
    let mut results = Vec::new();

    if let Ok(info) = audit_iptables() {
        results.push(info);
    }
    if let Ok(info) = audit_nftables() {
        results.push(info);
    }
    if let Ok(info) = audit_firewalld() {
        results.push(info);
    }
    if let Ok(info) = audit_ufw() {
        results.push(info);
    }

    if results.is_empty() {
        results.push(FirewallInfo {
            backend: "unknown",
            active: false,
            rules: Vec::new(),
            findings: vec![AuditFinding {
                check: "firewall",
                status: "FAIL",
                severity: "HIGH",
                recommendation: "Aucun firewall détecté (iptables/nftables/firewalld/ufw). Installer et configurer un firewall.",
            }],
        });
    }

    Ok(results)
}

fn audit_iptables() -> Result<FirewallInfo, FirewallError> {
    let output = Command::new("iptables")
        .args(["-L", "-n", "-v"])
        .output()
        .map_err(|_| FirewallError::CommandNotFound("iptables".to_string()))?;

    if !output.status.success() {
        return Ok(FirewallInfo {
            backend: "iptables",
            active: false,
            rules: Vec::new(),
            findings: vec![AuditFinding {
                check: "iptables",
                status: "WARN",
                severity: "MEDIUM",
                recommendation: "iptables installé mais inactif ou permissions insuffisantes",
            }],
        });
    }

    let rules = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();
    let findings = check_iptables_rules(&String::from_utf8_lossy(&output.stdout));

    Ok(FirewallInfo {
        backend: "iptables",
        active: true,
        rules,
        findings,
    })
}

fn check_iptables_rules(output: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let has_input_policy = output.lines().any(|l| l.trim_start().starts_with("Chain INPUT"));
    let has_forward_policy = output.lines().any(|l| l.trim_start().starts_with("Chain FORWARD"));

    if !has_input_policy {
        findings.push(AuditFinding {
            check: "iptables INPUT",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "Vérifier la politique de la chaîne INPUT (DROP recommandé)",
        });
    }

    if !has_forward_policy {
        findings.push(AuditFinding {
            check: "iptables FORWARD",
            status: "WARN",
            severity: "LOW",
            recommendation: "Vérifier la politique de la chaîne FORWARD (DROP recommandé si pas de routage)",
        });
    }

    let accept_rules = output
        .lines()
        .filter(|l| l.contains("ACCEPT"))
        .count();
    if accept_rules > 20 {
        findings.push(AuditFinding {
            check: "iptables ACCEPT rules",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "Nombreuses règles ACCEPT ({accept_rules}), vérifier la nécessité de chaque règle",
        });
    }

    findings
}

fn audit_nftables() -> Result<FirewallInfo, FirewallError> {
    let output = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .map_err(|_| FirewallError::CommandNotFound("nft".to_string()))?;

    if !output.status.success() {
        return Ok(FirewallInfo {
            backend: "nftables",
            active: false,
            rules: Vec::new(),
            findings: vec![AuditFinding {
                check: "nftables",
                status: "WARN",
                severity: "MEDIUM",
                recommendation: "nftables installé mais inactif",
            }],
        });
    }

    let rules = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    Ok(FirewallInfo {
        backend: "nftables",
        active: true,
        rules,
        findings: Vec::new(),
    })
}

fn audit_firewalld() -> Result<FirewallInfo, FirewallError> {
    let output = Command::new("firewall-cmd")
        .args(["--state"])
        .output()
        .map_err(|_| FirewallError::CommandNotFound("firewall-cmd".to_string()))?;

    if !output.status.success() {
        return Ok(FirewallInfo {
            backend: "firewalld",
            active: false,
            rules: Vec::new(),
            findings: vec![AuditFinding {
                check: "firewalld",
                status: "WARN",
                severity: "MEDIUM",
                recommendation: "firewalld installé mais inactif",
            }],
        });
    }

    let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let active = state == "running";

    let rules_output = Command::new("firewall-cmd")
        .args(["--list-all"])
        .output();
    let rules = if let Ok(out) = rules_output {
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    };

    let mut findings = Vec::new();
    if !active {
        findings.push(AuditFinding {
            check: "firewalld",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "firewalld n'est pas en état running",
        });
    }

    Ok(FirewallInfo {
        backend: "firewalld",
        active,
        rules,
        findings,
    })
}

fn audit_ufw() -> Result<FirewallInfo, FirewallError> {
    let output = Command::new("ufw")
        .args(["status"])
        .output()
        .map_err(|_| FirewallError::CommandNotFound("ufw".to_string()))?;

    if !output.status.success() {
        return Ok(FirewallInfo {
            backend: "ufw",
            active: false,
            rules: Vec::new(),
            findings: vec![AuditFinding {
                check: "ufw",
                status: "WARN",
                severity: "MEDIUM",
                recommendation: "ufw installé mais erreur lors de la vérification du statut",
            }],
        });
    }

    let status = String::from_utf8_lossy(&output.stdout);
    let active = status.contains("Status: active");
    let rules = status.lines().map(|s| s.to_string()).collect();

    let mut findings = Vec::new();
    if !active {
        findings.push(AuditFinding {
            check: "ufw",
            status: "FAIL",
            severity: "HIGH",
            recommendation: "ufw est inactif. Activer avec: ufw enable",
        });
    } else if status.contains("(disabled)") || status.contains("inactive") {
        findings.push(AuditFinding {
            check: "ufw",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "ufw semble inactif malgré le statut. Vérifier la configuration.",
        });
    }

    Ok(FirewallInfo {
        backend: "ufw",
        active,
        rules,
        findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iptables_parse() {
        let output = r#"Chain INPUT (policy ACCEPT)
Chain FORWARD (policy ACCEPT)
Chain OUTPUT (policy ACCEPT)
"#;
        let findings = check_iptables_rules(output);
        assert!(findings.is_empty());
    }
}
