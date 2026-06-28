// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use thiserror::Error;

use crate::audit::ssh::AuditFinding;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("Commande introuvable: {0}")]
    CommandNotFound(String),
    #[error("Erreur d'exécution: {0}")]
    IoError(#[from] std::io::Error),
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
                recommendation: "Aucun firewall détecté (iptables/nftables/firewalld/ufw). Installer et configurer un firewall.".to_string(),
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
                recommendation: "iptables installé mais inactif ou permissions insuffisantes".to_string(),
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
            recommendation: "Vérifier la politique de la chaîne INPUT (DROP recommandé)".to_string(),
        });
    }

    if !has_forward_policy {
        findings.push(AuditFinding {
            check: "iptables FORWARD",
            status: "WARN",
            severity: "LOW",
            recommendation: "Vérifier la politique de la chaîne FORWARD (DROP recommandé si pas de routage)".to_string(),
        });
    }

    // On ne compte que les *vraies* lignes de règles dont la cible est
    // `ACCEPT`. Avec `iptables -L -n -v` la ligne commence par le numéro de
    // règle + compteurs, puis ACCEPT ; sans `-v`, ACCEPT est en premier.
    let accept_rules = output
        .lines()
        .filter(|l| {
            is_iptables_rule_line(l)
                && l.split_whitespace().any(|tok| tok == "ACCEPT")
        })
        .count();

    if accept_rules > 20 {
        findings.push(AuditFinding {
            check: "iptables ACCEPT rules",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: format!(
                "Nombreuses règles ACCEPT ({accept_rules}), vérifier la nécessité de chaque règle"
            ),
        });
    }

    findings
}

/// Détecte si une ligne correspond à une règle iptables.
///
/// La commande `iptables -L -n -v` préfixe chaque ligne de règle par un
/// numéro (1, 2, …) et des compteurs (`0 0 ACCEPT tcp ...`). Sans `-v`,
/// la ligne commence directement par la cible (`ACCEPT tcp ...`).
///
/// On accepte donc :
/// - une cible en majuscules comme premier token (format court)
/// - un chiffre comme premier token (numéro de règle, format `-v`)
/// - une option `-X` de sélection/jump
///
/// Et on exclut explicitement :
/// - les en-têtes `Chain …`
/// - les en-têtes de colonnes (`num   pkts bytes target …`)
/// - les commentaires (`#`)
fn is_iptables_rule_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    if trimmed.starts_with("Chain ") {
        return false;
    }
    // En-tête de colonnes `num pkts bytes target prot opt in out source destination`
    if trimmed.starts_with("num ") || trimmed.starts_with("pkts ") {
        return false;
    }
    let first = trimmed.split_whitespace().next().unwrap_or("");
    first == "ACCEPT"
        || first == "DROP"
        || first == "REJECT"
        || first == "LOG"
        || first == "QUEUE"
        || first == "RETURN"
        || first == "MASQUERADE"
        || first == "SNAT"
        || first == "DNAT"
        || first.starts_with('-')
        // Format `-L -n -v` : préfixe par numéro de règle (entier).
        || first.parse::<u32>().is_ok()
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
                recommendation: "nftables installé mais inactif".to_string(),
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
                recommendation: "firewalld installé mais inactif".to_string(),
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
            recommendation: "firewalld n'est pas en état running".to_string(),
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
                recommendation: "ufw installé mais erreur lors de la vérification du statut".to_string(),
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
            recommendation: "ufw est inactif. Activer avec: ufw enable".to_string(),
        });
    } else if status.contains("(disabled)") || status.contains("inactive") {
        findings.push(AuditFinding {
            check: "ufw",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "ufw semble inactif malgré le statut. Vérifier la configuration.".to_string(),
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

    #[test]
    fn test_iptables_accept_rule_counting() {
        // Sortie réaliste de `iptables -L -n -v`. La ligne d'en-tête contient
        // "ACCEPT" (policy) mais ne doit pas être comptée. Seules les vraies
        // règles ACCEPT comptent.
        let mut output = String::from(
            "Chain INPUT (policy DROP 0 packets, 0 bytes)\n\
             pkts bytes target     prot opt in     out     source               destination\n",
        );
        for i in 0..10 {
            output.push_str(&format!(
                "    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:{i}\n"
            ));
        }
        let findings = check_iptables_rules(&output);
        // 10 règles → pas de warning
        assert!(
            !findings.iter().any(|f| f.check == "iptables ACCEPT rules"),
            "10 règles ne devraient pas déclencher le warning, got: {:?}",
            findings
        );

        // 21 règles → warning attendu
        let mut big = output;
        for i in 10..21 {
            big.push_str(&format!(
                "    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:{i}\n"
            ));
        }
        let findings = check_iptables_rules(&big);
        assert!(
            findings.iter().any(|f| f.check == "iptables ACCEPT rules"),
            "21 règles devraient déclencher le warning"
        );
    }

    #[test]
    fn test_is_iptables_rule_line() {
        // Headers : pas des règles
        assert!(!is_iptables_rule_line("Chain INPUT (policy ACCEPT)"));
        assert!(!is_iptables_rule_line(""));
        assert!(!is_iptables_rule_line("  "));
        assert!(!is_iptables_rule_line("# commentaire"));
        // Vraies règles
        assert!(is_iptables_rule_line("ACCEPT     tcp  --  0.0.0.0/0  0.0.0.0/0"));
        assert!(is_iptables_rule_line("DROP       all  --  *  *  0.0.0.0/0  0.0.0.0/0"));
        assert!(is_iptables_rule_line("    0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22"));
        assert!(is_iptables_rule_line("-A INPUT -p tcp --dport 22 -j ACCEPT"));
        assert!(!is_iptables_rule_line("pkts bytes target prot opt in out source destination"));
    }
}
