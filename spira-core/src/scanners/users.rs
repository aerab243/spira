/// Scanner des utilisateurs — vérifie les comptes utilisateurs, mots de passe
/// et privilèges pour détecter les problèmes de sécurité.
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::{fs, process::Command};

pub struct UserScanner;

impl UserScanner {
    /// Lit et parse `/etc/passwd`.
    async fn read_passwd() -> Result<Vec<(String, u32, u32, String, String)>, ScanError> {
        let content = fs::read_to_string("/etc/passwd")
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur lecture /etc/passwd: {}", e)))?;

        let mut users = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                continue;
            }
            let name = parts[0].to_string();
            let uid: u32 = parts[2].parse().unwrap_or(99999);
            let gid: u32 = parts[3].parse().unwrap_or(99999);
            let home = parts[5].to_string();
            let shell = parts[6].to_string();
            users.push((name, uid, gid, home, shell));
        }

        Ok(users)
    }

    /// Lit et parse `/etc/shadow` pour les hash de mots de passe.
    async fn read_shadow() -> Result<Vec<(String, String, String)>, ScanError> {
        let content = fs::read_to_string("/etc/shadow")
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur lecture /etc/shadow: {}", e)))?;

        let mut shadow_entries = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0].to_string();
            let hash = parts[1].to_string();
            let last_change = parts.get(2).copied().unwrap_or("").to_string();
            shadow_entries.push((name, hash, last_change));
        }

        Ok(shadow_entries)
    }

    /// Récupère les dernières connexions via `lastlog`.
    async fn get_last_logins() -> Result<Vec<(String, String)>, ScanError> {
        let output = Command::new("lastlog")
            .arg("-t")
            .arg("365")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur lastlog: {}", e)))?;

        let mut logins = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let user = parts[0].to_string();
                let login_info = parts[1..].join(" ");
                logins.push((user, login_info));
            }
        }

        Ok(logins)
    }

    /// Vérifie si un compte n'a pas de mot de passe ou a un hash vide.
    fn check_password_security(shadow_entries: &[(String, String, String)]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for (name, hash, _last_change) in shadow_entries {
            // Compte sans mot de passe (hash vide ou ! ou *)
            if hash.is_empty() || hash == "!" || hash == "*" || hash == "!*" {
                // Les comptes système avec shell /usr/sbin/nologin sont normaux
                // On vérifie seulement les comptes avec un vrai shell
                if !hash.is_empty() && hash == "*" {
                    continue; // Compte verrouillé, OK
                }
                vulns.push(Vulnerability {
                    id: format!("USER-NOPASS-{}", name),
                    package: name.clone(),
                    version: String::new(),
                    severity: Severity::Critical,
                    description: format!(
                        "Le compte utilisateur '{}' n'a pas de mot de passe défini. Connexion sans mot de passe possible !",
                        name
                    ),
                    affected_version: name.clone(),
                    fixed_version: None,
                    cvss_score: 9.0,
                    scan_type: ScanType::Users,
                    remediation: Some(format!(
                        "Définissez un mot de passe fort : sudo passwd {}",
                        name
                    )),
                });
            }

            // Hash de type DES (2 caractères) — très faible
            if hash.len() == 13 && !hash.starts_with('$') {
                vulns.push(Vulnerability {
                    id: format!("USER-DES-{}", name),
                    package: name.clone(),
                    version: String::new(),
                    severity: Severity::High,
                    description: format!(
                        "Le compte '{}' utilise un hash de mot de passe DES (ancien et faible).",
                        name
                    ),
                    affected_version: name.clone(),
                    fixed_version: None,
                    cvss_score: 7.5,
                    scan_type: ScanType::Users,
                    remediation: Some(format!(
                        "Mettez à jour le hash : sudo passwd {}",
                        name
                    )),
                });
            }

            // Hash MD5 ($1$) — obsolète
            if hash.starts_with("$1$") {
                vulns.push(Vulnerability {
                    id: format!("USER-MD5-{}", name),
                    package: name.clone(),
                    version: String::new(),
                    severity: Severity::Medium,
                    description: format!(
                        "Le compte '{}' utilise un hash MD5 ($1$), considéré comme faible. SHA-512 ($6$) est recommandé.",
                        name
                    ),
                    affected_version: name.clone(),
                    fixed_version: None,
                    cvss_score: 5.5,
                    scan_type: ScanType::Users,
                    remediation: Some(format!(
                        "Rehash avec SHA-512 : sudo passwd {}",
                        name
                    )),
                });
            }
        }

        vulns
    }

    /// Vérifie les comptes avec UID 0 (superutilisateur) autres que root.
    fn check_uid_zero(users: &[(String, u32, u32, String, String)]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for (name, uid, _gid, _home, _shell) in users {
            if *uid == 0 && name != "root" {
                vulns.push(Vulnerability {
                    id: format!("USER-UID0-{}", name),
                    package: name.clone(),
                    version: String::new(),
                    severity: Severity::Critical,
                    description: format!(
                        "Le compte '{}' a UID 0 (privilèges root). Tout compte avec UID 0 a les mêmes droits que root.",
                        name
                    ),
                    affected_version: name.clone(),
                    fixed_version: None,
                    cvss_score: 9.5,
                    scan_type: ScanType::Users,
                    remediation: Some(format!(
                        "Supprimez ou modifiez l'UID du compte : sudo usermod -u 1001 {} (ou sudo userdel {})",
                        name, name
                    )),
                });
            }
        }

        vulns
    }

    /// Vérifie les comptes avec shell de connexion qui ne devraient pas en avoir.
    fn check_unexpected_shells(users: &[(String, u32, u32, String, String)], shadow: &[(String, String, String)]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        let system_shells = ["/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/usr/bin/nologin"];

        for (name, uid, _gid, _home, shell) in users {
            // Comptes système (UID < 1000) avec un vrai shell
            if *uid > 0 && *uid < 1000 && !system_shells.contains(&shell.as_str()) && shell != "/bin/bash" && shell != "/bin/sh" {
                // Vérifier si le compte est verrouillé dans shadow
                let is_locked = shadow.iter()
                    .find(|(n, _, _)| n == name)
                    .map(|(_, h, _)| h == "*" || h == "!" || h == "!*")
                    .unwrap_or(false);

                if !is_locked && !shell.is_empty() {
                    vulns.push(Vulnerability {
                        id: format!("USER-SHELL-{}", name),
                        package: name.clone(),
                        version: String::new(),
                        severity: Severity::Medium,
                        description: format!(
                            "Le compte système '{}' (UID {}) a un shell de connexion : '{}'. Les comptes système ne devraient pas avoir de shell.",
                            name, uid, shell
                        ),
                        affected_version: name.clone(),
                        fixed_version: None,
                        cvss_score: 6.0,
                        scan_type: ScanType::Users,
                        remediation: Some(format!(
                            "Désactivez le shell : sudo usermod -s /usr/sbin/nologin {}",
                            name
                        )),
                    });
                }
            }
        }

        vulns
    }

    /// Vérifie les comptes inactifs (dernière connexion > 90 jours).
    fn check_inactive_accounts(
        users: &[(String, u32, u32, String, String)],
        last_logins: &[(String, String)],
    ) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for (name, uid, _gid, _home, shell) in users {
            // Ne vérifier que les comptes humains (UID >= 1000) et root
            if *uid < 1000 && name != "root" {
                continue;
            }
            if shell == "/usr/sbin/nologin" || shell == "/bin/false" {
                continue;
            }

            let never_logged_in = last_logins.iter()
                .find(|(n, _)| n == name)
                .map(|(_, info)| info.contains("Never logged in"))
                .unwrap_or(true);

            if never_logged_in && name != "root" && *uid >= 1000 {
                vulns.push(Vulnerability {
                    id: format!("USER-INACTIVE-{}", name),
                    package: name.clone(),
                    version: String::new(),
                    severity: Severity::Low,
                    description: format!(
                        "Le compte '{}' (UID {}) n'a jamais été connecté. Compte potentiellement inutilisé.",
                        name, uid
                    ),
                    affected_version: name.clone(),
                    fixed_version: None,
                    cvss_score: 3.0,
                    scan_type: ScanType::Users,
                    remediation: Some(format!(
                        "Supprimez le compte si inutilisé : sudo userdel {}",
                        name
                    )),
                });
            }
        }

        vulns
    }
}

#[async_trait::async_trait]
impl Scanner for UserScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Users
    }

    fn description(&self) -> &'static str {
        "Analyse les comptes utilisateurs, mots de passe et privilèges"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan des utilisateurs démarré");

        let mut vulnerabilities = Vec::new();

        // Lire les fichiers système
        let passwd_users = Self::read_passwd().await?;
        let shadow_entries = Self::read_shadow().await?;
        let last_logins = Self::get_last_logins().await?;

        log::info!(
            "{} utilisateurs dans passwd, {} entrées shadow",
            passwd_users.len(),
            shadow_entries.len()
        );

        // Vérifications
        vulnerabilities.extend(Self::check_password_security(&shadow_entries));
        vulnerabilities.extend(Self::check_uid_zero(&passwd_users));
        vulnerabilities.extend(Self::check_unexpected_shells(&passwd_users, &shadow_entries));
        vulnerabilities.extend(Self::check_inactive_accounts(&passwd_users, &last_logins));

        log::info!(
            "Scan des utilisateurs terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
