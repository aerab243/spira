use std::fs;
use std::path::Path;

use thiserror::Error;

use crate::audit::ssh::AuditFinding;

#[derive(Debug, Error)]
pub enum SudoersError {
    #[error("Fichier sudoers introuvable: {0}")]
    ConfigNotFound(String),
    #[error("Erreur de lecture: {0}")]
    IoError(#[from] std::io::Error),
}

const SUDOERS_PATHS: [&str; 3] = [
    "/etc/sudoers",
    "/etc/sudoers.d/README",
    "/usr/local/etc/sudoers",
];

pub fn audit_sudoers() -> Result<Vec<AuditFinding>, SudoersError> {
    let sudoers_path = SUDOERS_PATHS
        .iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| SudoersError::ConfigNotFound("sudoers".to_string()))?;

    let content = fs::read_to_string(sudoers_path)?;
    let findings = analyze_sudoers(&content);
    Ok(findings)
}

fn analyze_sudoers(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut has_nopasswd = false;
    let mut has_authenticate = false;
    let mut has_wheel_sudo = false;
    let mut has_dangerous_path = false;
    let mut has_root_all = false;

    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let upper = line.to_uppercase();

        if upper.contains("NOPASSWD") {
            has_nopasswd = true;
            findings.push(AuditFinding {
                check: "NOPASSWD",
                status: "WARN",
                severity: "HIGH",
                recommendation: "Éviter NOPASSWD dans sudoers pour des commandes sensibles. Utiliser des règles restrictives.".to_string(),
            });
        }

        if upper.contains("!AUTHENTICATE") || upper.contains("!AUTH") {
            has_authenticate = true;
            findings.push(AuditFinding {
                check: "!authenticate",
                status: "WARN",
                severity: "HIGH",
                recommendation: "Éviter !authenticate qui contourne l'authentification pour sudo".to_string(),
            });
        }

        if upper.contains("%wheel") || upper.contains("%sudo") || upper.contains("%admin") {
            if upper.contains("ALL=(ALL:ALL) ALL") || upper.contains("ALL=(ALL) ALL") {
                has_wheel_sudo = true;
            }
        }

        if line.contains("secure_path") || line.contains("PATH=") {
            if line.contains("/usr/local/sbin") && line.contains("/usr/local/bin") {
                has_dangerous_path = false;
            } else if line.contains("PATH") && !line.contains("secure_path") {
                has_dangerous_path = true;
                findings.push(AuditFinding {
                    check: "PATH",
                    status: "WARN",
                    severity: "MEDIUM",
                    recommendation: "Utiliser secure_path pour définir un PATH sûr pour sudo".to_string(),
                });
            }
        }

        if upper.contains("ALL=(ALL:ALL) ALL") || upper.contains("ALL=(ALL) ALL") {
            if !upper.contains("NOPASSWD") && !upper.contains("!authenticate") {
                has_root_all = true;
            }
        }
    }

    if !has_nopasswd && !has_authenticate && has_wheel_sudo {
        findings.push(AuditFinding {
            check: "sudoers policy",
            status: "OK",
            severity: "INFO",
            recommendation: "Configuration sudoers standard (authentification requise). OK.".to_string(),
        });
    }

    if has_dangerous_path {
        findings.push(AuditFinding {
            check: "dangerous_PATH",
            status: "FAIL",
            severity: "HIGH",
            recommendation: "Chemin PATH dangereux dans sudoers. Utiliser secure_path pour éviter les binaires non fiables.".to_string(),
        });
    }

    if !has_root_all && !has_wheel_sudo && !has_nopasswd {
        findings.push(AuditFinding {
            check: "sudoers configuration",
            status: "INFO",
            severity: "INFO",
            recommendation: "Aucune règle sudoers standard détectée. Vérifier les includes.".to_string(),
        });
    }

    findings
}

pub fn sudoers_security_score(findings: &[AuditFinding]) -> u8 {
    let mut score = 100u8;
    for f in findings {
        match f.severity {
            "CRITICAL" => score = score.saturating_sub(40),
            "HIGH" => score = score.saturating_sub(20),
            "MEDIUM" => score = score.saturating_sub(10),
            "LOW" => score = score.saturating_sub(5),
            _ => {}
        }
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_sudoers() {
        let content = r#"# Sudoers secure path
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
%wheel ALL=(ALL:ALL) ALL
"#;
        let findings = analyze_sudoers(content);
        assert!(findings.is_empty(), "Expected no findings for secure sudoers, got: {:?}", findings);
    }

    #[test]
    fn test_insecure_sudoers() {
        let content = r#"%wheel ALL=(ALL:ALL) NOPASSWD: ALL
Defaults !authenticate
Defaults secure_path="/usr/local/bin:/bin"
"#;
        let findings = analyze_sudoers(content);
        assert!(findings.iter().any(|f| f.check == "NOPASSWD"));
        assert!(findings.iter().any(|f| f.check == "!authenticate"));
    }
}
