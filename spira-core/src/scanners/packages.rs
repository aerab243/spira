/// Scanner des paquets installés — vérifie les vulnérabilités connues
/// dans les paquets APT/DPKG du système en utilisant la base CVE OVAL.
use super::Scanner;
use crate::cve::CveDatabase;
use crate::types::{Vulnerability, ScanError, ScanType};
use tokio::process::Command;

pub struct PackageScanner {
    /// Base de données CVE/OVAL pour la comparaison.
    cve_db: CveDatabase,
}

impl PackageScanner {
    /// Crée un nouveau scanner de paquets avec une base CVE.
    pub fn new() -> Self {
        Self {
            cve_db: CveDatabase::new(),
        }
    }

    /// Crée un scanner avec un codename Ubuntu explicite.
    pub fn with_codename(codename: &str) -> Self {
        Self {
            cve_db: CveDatabase::with_codename(codename),
        }
    }

    /// Initialise la base CVE (téléchargement OVAL si nécessaire).
    pub async fn initialize(&mut self) -> Result<(), ScanError> {
        self.cve_db.initialize().await
    }

    /// Retourne une référence à la base CVE.
    pub fn cve_database(&self) -> &CveDatabase {
        &self.cve_db
    }

    /// Liste tous les paquets installés via dpkg-query.
    /// Retourne une liste de (nom_paquet, version).
    async fn list_installed_packages() -> Result<Vec<(String, String)>, ScanError> {
        let output = Command::new("dpkg-query")
            .arg("-f")
            .arg("${Package} ${Version}\n")
            .arg("-W")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur dpkg-query: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ScanError::CommandError(format!(
                "dpkg-query a échoué: {}",
                stderr
            )));
        }

        let mut packages = Vec::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Format: "package-name version-string"
            if let Some((name, version)) = line.split_once(' ') {
                let version = version.trim();
                if !name.is_empty() && !version.is_empty() {
                    packages.push((name.to_string(), version.to_string()));
                }
            }
        }

        Ok(packages)
    }
}

impl Default for PackageScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Scanner for PackageScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Packages
    }

    fn description(&self) -> &'static str {
        "Analyse les paquets installés et les compare aux bases CVE"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan des paquets démarré");

        if !self.cve_db.initialized {
            return Err(ScanError::CveDatabaseError(
                "Base CVE non initialisée. Appelez initialize() d'abord.".into(),
            ));
        }

        let packages = Self::list_installed_packages().await?;
        log::info!("{} paquets installés détectés", packages.len());

        let mut all_vulnerabilities = Vec::new();

        for (name, version) in &packages {
            match self.cve_db.check_package(name, version).await {
                Ok(vulns) => {
                    all_vulnerabilities.extend(vulns);
                }
                Err(e) => {
                    log::warn!("Erreur lors de la vérification de '{}': {}", name, e);
                }
            }
        }

        log::info!(
            "Scan des paquets terminé : {} vulnérabilités trouvées",
            all_vulnerabilities.len()
        );

        Ok(all_vulnerabilities)
    }
}
