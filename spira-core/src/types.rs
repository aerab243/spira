/// `Severity` représente le niveau de gravité d'une vulnérabilité.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "Critique",
            Self::High => "Élevée",
            Self::Medium => "Moyenne",
            Self::Low => "Basse",
            Self::Info => "Information",
        }
    }

    /// Convertit un score CVSS (0-10) en niveau de sévérité.
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s >= 0.1 => Self::Low,
            _ => Self::Info,
        }
    }

    pub fn cvss_range(&self) -> (f32, f32) {
        match self {
            Self::Critical => (9.0, 10.0),
            Self::High => (7.0, 8.9),
            Self::Medium => (4.0, 6.9),
            Self::Low => (0.1, 3.9),
            Self::Info => (0.0, 0.0),
        }
    }
}

/// `ScanType` identifie le type de scan qui a détecté la vulnérabilité.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScanType {
    Packages,
    Network,
    Permissions,
    Kernel,
    Users,
    Firewall,
    Logs,
    Rootkit,
}

impl ScanType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Packages => "Paquets",
            Self::Network => "Réseau",
            Self::Permissions => "Permissions",
            Self::Kernel => "Kernel",
            Self::Users => "Utilisateurs",
            Self::Firewall => "Pare-feu",
            Self::Logs => "Journaux",
            Self::Rootkit => "Rootkit",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Packages => "📦",
            Self::Network => "🔌",
            Self::Permissions => "🔐",
            Self::Kernel => "🐧",
            Self::Users => "👥",
            Self::Firewall => "🔥",
            Self::Logs => "📋",
            Self::Rootkit => "🧪",
        }
    }
}

/// `Vulnerability` représente une vulnérabilité détectée sur le système.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub package: String,
    pub version: String,
    pub severity: Severity,
    pub description: String,
    pub affected_version: String,
    pub fixed_version: Option<String>,
    pub cvss_score: f32,
    pub scan_type: ScanType,
    pub remediation: Option<String>,
}

/// `ScanStats` contient les statistiques agrégées d'un scan.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub total: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

impl ScanStats {
    pub fn from_vulnerabilities(vulns: &[Vulnerability]) -> Self {
        let mut stats = Self::default();
        stats.total = vulns.len() as u32;
        for v in vulns {
            match v.severity {
                Severity::Critical => stats.critical += 1,
                Severity::High => stats.high += 1,
                Severity::Medium => stats.medium += 1,
                Severity::Low => stats.low += 1,
                Severity::Info => stats.info += 1,
            }
        }
        stats
    }

    /// Calcule un score de sécurité de 0 à 100.
    pub fn security_score(&self) -> u32 {
        if self.total == 0 {
            return 100;
        }
        let weighted = self.critical as f64 * 10.0
            + self.high as f64 * 5.0
            + self.medium as f64 * 2.0
            + self.low as f64 * 1.0
            + self.info as f64 * 0.5;
        let score = 100.0 - (weighted / self.total as f64) * 10.0;
        score.clamp(0.0, 100.0) as u32
    }
}

/// `ScanResult` regroupe les résultats d'un scan complet.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub stats: ScanStats,
    pub scan_time_ms: u64,
}

impl ScanResult {
    pub fn new(vulnerabilities: Vec<Vulnerability>, scan_time_ms: u64) -> Self {
        let stats = ScanStats::from_vulnerabilities(&vulnerabilities);
        Self {
            vulnerabilities,
            stats,
            scan_time_ms,
        }
    }
}

/// `SystemInfo` contient les informations sur le système audité.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub kernel_version: String,
    pub hostname: String,
    pub uptime_seconds: u64,
    pub packages_count: u32,
    pub cpu_cores: u32,
    pub total_memory_mb: u64,
}

/// `ScanConfig` permet de configurer les vérifications à effectuer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanConfig {
    pub scan_packages: bool,
    pub scan_network: bool,
    pub scan_permissions: bool,
    pub scan_kernel: bool,
    pub scan_users: bool,
    pub scan_firewall: bool,
    pub scan_logs: bool,
    pub scan_rootkit: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            scan_packages: true,
            scan_network: true,
            scan_permissions: true,
            scan_kernel: true,
            scan_users: true,
            scan_firewall: true,
            scan_logs: true,
            scan_rootkit: true,
        }
    }
}

/// `ReportFormat` définit le format d'export du rapport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Csv,
    Html,
    Txt,
}

impl ReportFormat {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Csv => "CSV",
            Self::Html => "HTML",
            Self::Txt => "Texte",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::Html => "html",
            Self::Txt => "txt",
        }
    }
}

/// Les différents onglets de navigation de l'interface graphique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Dashboard,
    Scan,
    Results,
    Reports,
    Settings,
    About,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dashboard => "Tableau de bord",
            Self::Scan => "Analyse",
            Self::Results => "Résultats",
            Self::Reports => "Rapports",
            Self::Settings => "Paramètres",
            Self::About => "À propos",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Dashboard => "📊",
            Self::Scan => "🔍",
            Self::Results => "📋",
            Self::Reports => "📄",
            Self::Settings => "⚙️",
            Self::About => "ℹ️",
        }
    }
}

/// Erreurs pouvant survenir lors des scans.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("Erreur lors de l'exécution de la commande système: {0}")]
    CommandError(String),
    #[error("Erreur de parsing: {0}")]
    ParseError(String),
    #[error("Erreur réseau: {0}")]
    NetworkError(String),
    #[error("Erreur de base de données CVE: {0}")]
    CveDatabaseError(String),
    #[error("Permission insuffisante pour exécuter ce scan")]
    PermissionDenied,
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        Self::CommandError(err.to_string())
    }
}
