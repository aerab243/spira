/// `spira-core` — Moteur de vérification de vulnérabilités du projet Spira.
///
/// Ce crate fournit tous les types, les scanners et la logique métier
/// pour détecter les vulnérabilités sur un système Linux.
pub mod types;
pub mod scanners;
pub mod cve;
pub mod system;

pub use types::*;

/// Version de l'application.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Nom de l'application
pub const APP_NAME: &str = "Spira";
