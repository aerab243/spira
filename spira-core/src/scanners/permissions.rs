/// Scanner des permissions — vérifie les permissions dangereuses (SUID, SGID,
/// world-writable, fichiers sans propriétaire).
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::process::Command;

pub struct PermissionScanner;

impl PermissionScanner {
    /// Recherche les fichiers SUID (Set User ID) sur tout le système.
    ///
    /// Structure find : exclure /proc, /sys, /dev → chercher les SUID dans le reste.
    async fn find_suid_files() -> Result<Vec<(String, String)>, ScanError> {
        let output = Command::new("find")
            .arg("/")
            .arg("(")
                .arg("-path").arg("/proc")
                .arg("-o").arg("-path").arg("/sys")
                .arg("-o").arg("-path").arg("/dev")
            .arg(")")
            .arg("-prune")
            .arg("-o")
            .arg("-type").arg("f")
            .arg("-perm").arg("-4000")
            .arg("-print")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur find SUID: {}", e)))?;

        let mut files = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let path = line.trim();
            if path.is_empty() || path == "/" {
                continue;
            }
            if let Ok(perm) = Self::get_file_permissions(path).await {
                files.push((path.to_string(), perm));
            }
        }

        // Limiter à 50 résultats pour éviter les listings trop longs
        if files.len() > 50 {
            files.truncate(50);
        }

        Ok(files)
    }

    /// Recherche les fichiers SGID (Set Group ID).
    async fn find_sgid_files() -> Result<Vec<(String, String)>, ScanError> {
        let output = Command::new("find")
            .arg("/")
            .arg("(")
                .arg("-path").arg("/proc")
                .arg("-o").arg("-path").arg("/sys")
                .arg("-o").arg("-path").arg("/dev")
            .arg(")")
            .arg("-prune")
            .arg("-o")
            .arg("-type").arg("f")
            .arg("-perm").arg("-2000")
            .arg("-print")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur find SGID: {}", e)))?;

        let mut files = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let path = line.trim();
            if path.is_empty() || path == "/" {
                continue;
            }
            if let Ok(perm) = Self::get_file_permissions(path).await {
                files.push((path.to_string(), perm));
            }
        }

        if files.len() > 50 {
            files.truncate(50);
        }

        Ok(files)
    }

    /// Recherche les répertoires world-writable (hors /tmp qui est normal).
    async fn find_world_writable_dirs() -> Result<Vec<String>, ScanError> {
        let output = Command::new("find")
            .arg("/")
            .arg("(")
                .arg("-path").arg("/proc")
                .arg("-o").arg("-path").arg("/sys")
                .arg("-o").arg("-path").arg("/dev")
                .arg("-o").arg("-path").arg("/tmp")
            .arg(")")
            .arg("-prune")
            .arg("-o")
            .arg("-type").arg("d")
            .arg("-perm").arg("-o+w")
            .arg("-print")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur find world-writable: {}", e)))?;

        let mut dirs = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let path = line.trim();
            if path.is_empty() || path.len() < 4 {
                continue;
            }
            dirs.push(path.to_string());
        }

        if dirs.len() > 50 {
            dirs.truncate(50);
        }

        Ok(dirs)
    }

    /// Vérifie les fichiers sans propriétaire (orphan files).
    async fn find_orphan_files() -> Result<Vec<String>, ScanError> {
        let output = Command::new("find")
            .arg("/")
            .arg("(")
                .arg("-path").arg("/proc")
                .arg("-o").arg("-path").arg("/sys")
                .arg("-o").arg("-path").arg("/dev")
            .arg(")")
            .arg("-prune")
            .arg("-o")
            .arg("(")
                .arg("-nouser")
                .arg("-o")
                .arg("-nogroup")
            .arg(")")
            .arg("-print")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur find orphan: {}", e)))?;

        let mut files = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let path = line.trim();
            if path.is_empty() || path == "/" {
                continue;
            }
            files.push(path.to_string());
        }

        if files.len() > 50 {
            files.truncate(50);
        }

        Ok(files)
    }

    /// Récupère les permissions d'un fichier via `ls -la`.
    async fn get_file_permissions(path: &str) -> Result<String, ScanError> {
        let output = Command::new("ls")
            .arg("-la")
            .arg("-d")
            .arg(path)
            .output()
            .await
            .map_err(|_| ScanError::CommandError(format!("Erreur ls: {}", path)))?;

        if output.status.success() {
            let line = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            return Ok(line);
        }

        Ok(String::new())
    }

    /// Liste des binaires SUID légitimes connus (ne pas alerter sur ceux-ci).
    fn is_known_legitimate_suid(path: &str) -> bool {
        let legit = [
            "/usr/bin/su",
            "/usr/bin/sudo",
            "/usr/bin/passwd",
            "/usr/bin/gpasswd",
            "/usr/bin/newgrp",
            "/usr/bin/chsh",
            "/usr/bin/chfn",
            "/usr/bin/mount",
            "/usr/bin/umount",
            "/usr/bin/pkexec",
            "/usr/sbin/mount.nfs",
            "/usr/lib/policykit-1/polkit-agent-helper-1",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/lib/openssh/ssh-keysign",
            "/snap/core20/",
            "/snap/core22/",
            "/snap/core24/",
            "/snap/snapd/",
            "/usr/libexec/",
            "/usr/lib/xorg/",
        ];
        legit.iter().any(|&l| path == l || path.starts_with(l))
    }
}

#[async_trait::async_trait]
impl Scanner for PermissionScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Permissions
    }

    fn description(&self) -> &'static str {
        "Recherche les permissions dangereuses (SUID, SGID, fichiers world-writable)"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan des permissions démarré");

        let mut vulnerabilities = Vec::new();

        // 1. Fichiers SUID — on rattrape les erreurs (ex: permissions insuffisantes)
        let suid_files = match Self::find_suid_files().await {
            Ok(files) => files,
            Err(e) => {
                log::warn!("Impossible de scanner les fichiers SUID: {}", e);
                Vec::new()
            }
        };

        let unknown_suid: Vec<_> = suid_files
            .iter()
            .filter(|(path, _)| !Self::is_known_legitimate_suid(path))
            .collect();

        if !unknown_suid.is_empty() {
            let paths: Vec<&str> = unknown_suid.iter().map(|(p, _)| p.as_str()).collect();
            vulnerabilities.push(Vulnerability {
                id: "PERM-SUID-UNKNOWN".to_string(),
                package: "filesystem".to_string(),
                version: String::new(),
                severity: Severity::High,
                description: format!(
                    "{} fichier(s) SUID non standard trouvé(s) sur le système : {}",
                    unknown_suid.len(),
                    paths.join(", ")
                ),
                affected_version: paths.join(", "),
                fixed_version: None,
                cvss_score: 7.0,
                scan_type: ScanType::Permissions,
                remediation: Some(
                    "Examinez chaque fichier SUID. Si le binaire n'est plus nécessaire, retirez le bit SUID : sudo chmod u-s <fichier>".to_string(),
                ),
            });
        }

        // 2. Fichiers SGID
        let sgid_files = match Self::find_sgid_files().await {
            Ok(files) => files,
            Err(e) => {
                log::warn!("Impossible de scanner les fichiers SGID: {}", e);
                Vec::new()
            }
        };

        let unknown_sgid: Vec<_> = sgid_files
            .iter()
            .filter(|(path, _)| !Self::is_known_legitimate_suid(path))
            .collect();

        if !unknown_sgid.is_empty() {
            let paths: Vec<&str> = unknown_sgid.iter().map(|(p, _)| p.as_str()).collect();
            vulnerabilities.push(Vulnerability {
                id: "PERM-SGID-UNKNOWN".to_string(),
                package: "filesystem".to_string(),
                version: String::new(),
                severity: Severity::Medium,
                description: format!(
                    "{} fichier(s) SGID non standard trouvé(s) : {}",
                    unknown_sgid.len(),
                    paths.join(", ")
                ),
                affected_version: paths.join(", "),
                fixed_version: None,
                cvss_score: 5.5,
                scan_type: ScanType::Permissions,
                remediation: Some(
                    "Examinez chaque fichier SGID. Retirez le bit SGID si non nécessaire : sudo chmod g-s <fichier>".to_string(),
                ),
            });
        }

        // 3. Répertoires world-writable
        let world_writable = match Self::find_world_writable_dirs().await {
            Ok(dirs) => dirs,
            Err(e) => {
                log::warn!("Impossible de scanner les répertoires world-writable: {}", e);
                Vec::new()
            }
        };

        if !world_writable.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: "PERM-WORLD-WRITABLE".to_string(),
                package: "filesystem".to_string(),
                version: String::new(),
                severity: Severity::Low,
                description: format!(
                    "{} répertoire(s) world-writable trouvé(s) (hors /tmp) : {}",
                    world_writable.len(),
                    world_writable.join(", ")
                ),
                affected_version: world_writable.join(", "),
                fixed_version: None,
                cvss_score: 3.5,
                scan_type: ScanType::Permissions,
                remediation: Some(
                    "Vérifiez chaque répertoire. Restreignez les permissions : sudo chmod o-w <répertoire>".to_string(),
                ),
            });
        }

        // 4. Fichiers orphelins
        let orphan_files = match Self::find_orphan_files().await {
            Ok(files) => files,
            Err(e) => {
                log::warn!("Impossible de scanner les fichiers orphelins: {}", e);
                Vec::new()
            }
        };

        if !orphan_files.is_empty() {
            vulnerabilities.push(Vulnerability {
                id: "PERM-ORPHAN".to_string(),
                package: "filesystem".to_string(),
                version: String::new(),
                severity: Severity::Info,
                description: format!(
                    "{} fichier(s) sans propriétaire trouvé(s). Cela peut indiquer des restes de paquets désinstallés.",
                    orphan_files.len()
                ),
                affected_version: orphan_files.join(", "),
                fixed_version: None,
                cvss_score: 2.0,
                scan_type: ScanType::Permissions,
                remediation: Some(
                    "Identifiez le propriétaire de ces fichiers : sudo chown user:group <fichier>".to_string(),
                ),
            });
        }

        log::info!(
            "Scan des permissions terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
