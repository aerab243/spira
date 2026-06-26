use std::process::Command;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Unknown,
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("Commande introuvable: {0}")]
    CommandNotFound(String),
    #[error("Erreur d'exécution: {0}")]
    IoError(#[from] std::io::Error),
}

pub fn detect() -> Result<PackageManager, PackageError> {
    let managers = vec![
        ("dpkg", PackageManager::Dpkg),
        ("rpm", PackageManager::Rpm),
        ("pacman", PackageManager::Pacman),
        ("apk", PackageManager::Apk),
    ];

    for (cmd, manager) in managers {
        if command_exists(cmd)? {
            return Ok(manager);
        }
    }

    Ok(PackageManager::Unknown)
}

fn command_exists(cmd: &str) -> Result<bool, PackageError> {
    let result = Command::new("which")
        .arg(cmd)
        .output()
        .map_err(|_| PackageError::CommandNotFound(cmd.to_string()))?;

    Ok(result.status.success())
}
