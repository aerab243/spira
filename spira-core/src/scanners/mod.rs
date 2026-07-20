/// Module `scanners` — Tous les moteurs de vérification de vulnérabilités.
///
/// Chaque scanner implémente le trait `Scanner` et peut être exécuté
/// indépendamment pour vérifier un aspect spécifique du système.
use crate::types::{Vulnerability, ScanError, ScanType};
use async_trait::async_trait;

pub mod packages;
pub mod network;
pub mod permissions;
pub mod kernel;
pub mod users;
pub mod firewall;
pub mod logs;
pub mod rootkit;

/// Trait commun à tous les scanners.
///
/// Chaque scanner doit implémenter `scan()` qui retourne la liste des
/// vulnérabilités détectées, ou une erreur.
#[async_trait]
pub trait Scanner {
    /// Retourne le type de scan (Packages, Network, etc.)
    fn scan_type(&self) -> ScanType;

    /// Exécute le scan et retourne les vulnérabilités détectées.
    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError>;

    /// Retourne une description lisible du scan.
    fn description(&self) -> &'static str;
}
