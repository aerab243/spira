/// Scanner du kernel — vérifie la version du kernel Linux contre
/// une base de vulnérabilités connues (CVE et issues de sécurité majeures).
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::process::Command;

pub struct KernelScanner;

impl KernelScanner {
    /// Récupère la version du kernel via `uname -r`.
    async fn get_kernel_version() -> Result<String, ScanError> {
        let output = Command::new("uname").arg("-r").output().await?;
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if version.is_empty() {
            Err(ScanError::CommandError("Impossible de lire la version du kernel".into()))
        } else {
            Ok(version)
        }
    }

    /// Récupère le nom complet du kernel via `uname -a`.
    async fn get_kernel_release() -> Result<String, ScanError> {
        let output = Command::new("uname").arg("-a").output().await?;
        let release = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(release)
    }

    /// Vérifie les vulnérabilités critiques connues du kernel Linux.
    /// Ces vérifications sont basées sur des plages de versions affectées.
    fn check_known_vulnerabilities(version: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        // Extrait le numéro de version majeur.mineur (.sub)
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() < 2 {
            return vulns;
        }

        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        // La sous-version peut contenir un suffixe (ex: "5" dans "5.15.0-91-generic")
        let sub: u32 = parts.get(2)
            .and_then(|s| s.split(|c: char| !c.is_alphanumeric()).next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Dirty Pipe (CVE-2022-0847) — Linux 5.8 à 5.16.11, 5.15.25, 5.10.102
        if (major == 5 && minor >= 8 && (minor < 16 || (minor == 16 && sub <= 11)))
            || (major == 5 && minor == 15 && sub <= 25)
            || (major == 5 && minor == 10 && sub <= 102)
        {
            vulns.push(Vulnerability {
                id: "CVE-2022-0847".to_string(),
                package: "linux-kernel".to_string(),
                version: version.to_string(),
                severity: Severity::High,
                description: "Dirty Pipe — Vulnérabilité de contournement d'écriture dans le pipe du noyau Linux. Permet à un utilisateur local d'écrire dans des fichiers en lecture seule.".to_string(),
                affected_version: format!("5.8 à 5.16.11 / 5.15.25 / 5.10.102"),
                fixed_version: Some("5.16.12 / 5.15.26 / 5.10.103".to_string()),
                cvss_score: 7.8,
                scan_type: ScanType::Kernel,
                remediation: Some("Mettez à jour le kernel Linux vers la dernière version disponible via 'sudo apt update && sudo apt upgrade'.".to_string()),
            });
        }

        // Dirty Cow (CVE-2016-5195) — Linux 2.6.22+ à 4.8.3
        if major == 2 && minor >= 6 && sub >= 22
            || (major == 3)
            || (major == 4 && (minor < 8 || (minor == 8 && sub <= 3)))
        {
            vulns.push(Vulnerability {
                id: "CVE-2016-5195".to_string(),
                package: "linux-kernel".to_string(),
                version: version.to_string(),
                severity: Severity::High,
                description: "Dirty Cow — Vulnérabilité de race condition dans le mécanisme copy-on-write de la mémoire virtuelle. Permet une escalade de privilèges locale.".to_string(),
                affected_version: "2.6.22+ à 4.8.3".to_string(),
                fixed_version: Some("4.8.4 / 4.7.10 / 4.4.27".to_string()),
                cvss_score: 7.8,
                scan_type: ScanType::Kernel,
                remediation: Some("Mettez à jour le kernel Linux (version >= 4.8.4).".to_string()),
            });
        }

        // CVE-2023-4911 (Looney Tunables) — glibc ld.so
        // CVE-2024-1086 — Use-after-free in nf_tables (Linux 3.15-6.8)
        if (major == 3 && minor >= 15)
            || (major == 4)
            || (major == 5)
            || (major == 6 && minor <= 8)
        {
            vulns.push(Vulnerability {
                id: "CVE-2024-1086".to_string(),
                package: "linux-kernel".to_string(),
                version: version.to_string(),
                severity: Severity::High,
                description: "Use-after-free dans nf_tables — Vulnérabilité dans le sous-système netfilter du noyau Linux. Permet une escalade de privilèges locale.".to_string(),
                affected_version: "3.15 à 6.8".to_string(),
                fixed_version: Some("6.9".to_string()),
                cvss_score: 7.8,
                scan_type: ScanType::Kernel,
                remediation: Some("Mettez à jour le kernel vers la version 6.9 ou ultérieure. Si la mise à jour n'est pas disponible, appliquez le patch de sécurité.".to_string()),
            });
        }

        // CVE-2022-2588 — Use-after-free in cls_route (Linux 4.0+)
        if major >= 4
            || (major == 3)
        {
            vulns.push(Vulnerability {
                id: "CVE-2022-2588".to_string(),
                package: "linux-kernel".to_string(),
                version: version.to_string(),
                severity: Severity::Medium,
                description: "Use-after-free dans cls_route — Vulnérabilité dans le routeur de classe réseau du noyau Linux. Peut permettre une escalade de privilèges.".to_string(),
                affected_version: "4.0+".to_string(),
                fixed_version: Some("5.19 / 6.0".to_string()),
                cvss_score: 7.0,
                scan_type: ScanType::Kernel,
                remediation: Some("Mettez à jour le kernel vers la version 5.19 ou 6.0+".to_string()),
            });
        }

        vulns
    }

    /// Extrait la version sémantique principale (majeur.mineur.sous-version).
    fn extract_version(version: &str) -> (u32, u32, u32) {
        let parts: Vec<&str> = version.split(|c: char| !c.is_ascii_digit() && c != '.')
            .filter(|s| !s.is_empty())
            .collect();
        
        let major: u32 = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
        
        (major, minor, patch)
    }
}

#[async_trait::async_trait]
impl Scanner for KernelScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Kernel
    }

    fn description(&self) -> &'static str {
        "Vérifie la version du kernel Linux et ses vulnérabilités connues"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan du kernel démarré");

        let version = Self::get_kernel_version().await?;
        let release = Self::get_kernel_release().await?;

        log::info!("Version du kernel détectée : {} | {}", version, release);

        // Vérifier les CVE connues basées sur la version
        let mut vulnerabilities = Self::check_known_vulnerabilities(&version);

        // Vérifier si le kernel est ancien
        let (major, minor, _patch) = Self::extract_version(&version);

        // Alerter si le kernel a plus de 2 ans (considéré comme obsolète)
        if major < 5 || (major == 5 && minor < 10) {
            vulnerabilities.push(Vulnerability {
                id: "KERNEL-OBSOLETE".to_string(),
                package: "linux-kernel".to_string(),
                version: version.clone(),
                severity: Severity::Medium,
                description: format!(
                    "Le kernel Linux {} est considéré comme obsolète. Les versions récentes contiennent des correctifs de sécurité critiques qui ne sont pas rétroportés.",
                    version
                ),
                affected_version: version.clone(),
                fixed_version: Some("5.15+".to_string()),
                cvss_score: 5.0,
                scan_type: ScanType::Kernel,
                remediation: Some("Envisagez de migrer vers un kernel LTS récent (5.15+, 6.1+).".to_string()),
            });
        }

        log::info!(
            "Scan du kernel terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
