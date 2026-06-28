// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFinding {
    pub check: &'static str,
    pub status: &'static str,
    pub severity: &'static str,
    pub recommendation: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Fichier de configuration introuvable: {0}")]
    ConfigNotFound(String),
    #[error("Erreur de lecture: {0}")]
    IoError(#[from] std::io::Error),
}

const SSH_CONFIG_PATHS: [&str; 4] = [
    "/etc/ssh/sshd_config",
    "/etc/sshd_config",
    "/usr/local/etc/sshd_config",
    "/etc/openssh/sshd_config",
];

pub fn audit_ssh() -> Result<Vec<AuditFinding>, AuditError> {
    let config_path = SSH_CONFIG_PATHS
        .iter()
        .find(|p| Path::new(p).exists())
        .ok_or_else(|| AuditError::ConfigNotFound("sshd_config".to_string()))?;

    let content = fs::read_to_string(config_path)?;
    let findings = analyze_ssh_config(&content);
    Ok(findings)
}

fn analyze_ssh_config(content: &str) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let mut permit_root_login = None;
    let mut password_auth = None;
    let mut pubkey_auth = None;
    let mut permit_empty_passwords = None;
    let mut challenge_response = None;
    let mut use_pam = None;

    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let key = parts[0].to_lowercase();
        let value = parts[1].to_lowercase();

        match key.as_str() {
            "permitrootlogin" => permit_root_login = Some(value),
            "passwordauthentication" => password_auth = Some(value),
            "pubkeyauthentication" => pubkey_auth = Some(value),
            "permitemptypasswords" => permit_empty_passwords = Some(value),
            "challengeresponseauthentication" => challenge_response = Some(value),
            "usepam" => use_pam = Some(value),
            _ => {}
        }
    }

    match permit_root_login.as_deref() {
        Some("no") | Some("prohibit-password") | Some("prohibit-opensession") => {}
        Some("yes") => findings.push(AuditFinding {
            check: "PermitRootLogin",
            status: "FAIL",
            severity: "HIGH",
            recommendation: "Désactiver la connexion root directe: PermitRootLogin no".to_string(),
        }),
        _ => findings.push(AuditFinding {
            check: "PermitRootLogin",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "Définir PermitRootLogin explicitement (no ou prohibit-password)".to_string(),
        }),
    }

    match password_auth.as_deref() {
        Some("no") => {}
        Some("yes") => findings.push(AuditFinding {
            check: "PasswordAuthentication",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "Préférer l'authentification par clé SSH: PasswordAuthentication no".to_string(),
        }),
        _ => findings.push(AuditFinding {
            check: "PasswordAuthentication",
            status: "WARN",
            severity: "LOW",
            recommendation: "Définir PasswordAuthentication explicitement (no recommandé)".to_string(),
        }),
    }

    match pubkey_auth.as_deref() {
        Some("yes") => {}
        Some("no") => findings.push(AuditFinding {
            check: "PubkeyAuthentication",
            status: "FAIL",
            severity: "HIGH",
            recommendation: "Activer l'authentification par clé: PubkeyAuthentication yes".to_string(),
        }),
        _ => findings.push(AuditFinding {
            check: "PubkeyAuthentication",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "Définir PubkeyAuthentication explicitement (yes recommandé)".to_string(),
        }),
    }

    if let Some("yes") = permit_empty_passwords.as_deref() {
        findings.push(AuditFinding {
            check: "PermitEmptyPasswords",
            status: "FAIL",
            severity: "CRITICAL",
            recommendation: "Interdire les mots de passe vides: PermitEmptyPasswords no".to_string(),
        });
    }

    if let Some("yes") = challenge_response.as_deref() {
        findings.push(AuditFinding {
            check: "ChallengeResponseAuthentication",
            status: "WARN",
            severity: "MEDIUM",
            recommendation: "Désactiver ChallengeResponseAuthentication si non nécessaire".to_string(),
        });
    }

    if let Some("no") = use_pam.as_deref() {
        findings.push(AuditFinding {
            check: "UsePAM",
            status: "WARN",
            severity: "LOW",
            recommendation: "UsePAM no peut limiter les fonctionnalités (MFA, limits). Vérifier la nécessité.".to_string(),
        });
    }

    findings
}

pub fn ssh_security_score(findings: &[AuditFinding]) -> u8 {
    let mut score = 100u8;
    for f in findings {
        match f.severity {
            "CRITICAL" => score = score.saturating_sub(40),
            "HIGH" => score = score.saturating_sub(25),
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
    fn test_secure_ssh_config() {
        let config = r#"PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
"#;
        let findings = analyze_ssh_config(config);
        assert!(findings.is_empty(), "Expected no findings for secure config, got: {:?}", findings);
    }

    #[test]
    fn test_insecure_ssh_config() {
        let config = r#"PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication no
PermitEmptyPasswords yes
"#;
        let findings = analyze_ssh_config(config);
        assert!(findings.iter().any(|f| f.check == "PermitRootLogin" && f.severity == "HIGH"));
        assert!(findings.iter().any(|f| f.check == "PermitEmptyPasswords" && f.severity == "CRITICAL"));
    }

    #[test]
    fn test_score_calculation() {
        let findings = vec![
            AuditFinding { check: "A", status: "FAIL", severity: "HIGH", recommendation: "Fix A".to_string() },
            AuditFinding { check: "B", status: "FAIL", severity: "MEDIUM", recommendation: "Fix B".to_string() },
        ];
        assert_eq!(ssh_security_score(&findings), 65);
    }

    #[test]
    fn test_score_floor() {
        let findings = vec![
            AuditFinding { check: "A", status: "FAIL", severity: "CRITICAL", recommendation: "Fix A".to_string() },
            AuditFinding { check: "B", status: "FAIL", severity: "CRITICAL", recommendation: "Fix B".to_string() },
        ];
        assert!(ssh_security_score(&findings) <= 20);
    }
}
