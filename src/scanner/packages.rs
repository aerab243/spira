// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use thiserror::Error;

use crate::scanner::package::{Package, PackageSource};

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("Gestionnaire de paquets inconnu")]
    UnknownManager,
    #[error("Commande introuvable: {0}")]
    CommandNotFound(String),
    #[error("Erreur d'exécution: {0}")]
    IoError(#[from] std::io::Error),
}

pub trait PackageManagerTrait {
    fn list_packages(&self) -> Result<Vec<Package>, PackageError>;
}

#[derive(Debug)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Unknown,
}

impl PackageManagerTrait for PackageManager {
    fn list_packages(&self) -> Result<Vec<Package>, PackageError> {
        match self {
            PackageManager::Dpkg => DpkgManager.list_packages(),
            PackageManager::Rpm => RpmManager.list_packages(),
            PackageManager::Pacman => PacmanManager.list_packages(),
            PackageManager::Apk => ApkManager.list_packages(),
            PackageManager::Unknown => Err(PackageError::UnknownManager),
        }
    }
}

pub fn detect() -> Result<PackageManager, PackageError> {
    let managers: Vec<(&str, PackageManager)> = vec![
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

struct DpkgManager;
struct RpmManager;
struct PacmanManager;
struct ApkManager;

impl PackageManagerTrait for DpkgManager {
    fn list_packages(&self) -> Result<Vec<Package>, PackageError> {
        let output = Command::new("dpkg")
            .args(["--list"])
            .output()?;

        if !output.status.success() {
            return Err(PackageError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "dpkg --list failed",
            )));
        }

        parse_dpkg_output(&String::from_utf8_lossy(&output.stdout))
    }
}

impl PackageManagerTrait for RpmManager {
    fn list_packages(&self) -> Result<Vec<Package>, PackageError> {
        let output = Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME}|%{VERSION}\n"])
            .output()?;

        if !output.status.success() {
            return Err(PackageError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "rpm -qa failed",
            )));
        }

        parse_rpm_output(&String::from_utf8_lossy(&output.stdout))
    }
}

impl PackageManagerTrait for PacmanManager {
    fn list_packages(&self) -> Result<Vec<Package>, PackageError> {
        let output = Command::new("pacman")
            .args(["-Q"])
            .output()?;

        if !output.status.success() {
            return Err(PackageError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "pacman -Q failed",
            )));
        }

        parse_pacman_output(&String::from_utf8_lossy(&output.stdout))
    }
}

impl PackageManagerTrait for ApkManager {
    fn list_packages(&self) -> Result<Vec<Package>, PackageError> {
        let output = Command::new("apk")
            .args(["list", "--installed"])
            .output()?;

        if !output.status.success() {
            return Err(PackageError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                "apk list failed",
            )));
        }

        parse_apk_output(&String::from_utf8_lossy(&output.stdout))
    }
}

fn parse_dpkg_output(output: &str) -> Result<Vec<Package>, PackageError> {
    let mut packages = Vec::new();
    for line in output.lines().skip(3) {
        let line = line.trim();
        if line.is_empty() || !line.starts_with("ii ") {
            continue;
        }
        let line = line.strip_prefix("ii ").unwrap_or(line);
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            packages.push(Package {
                name: parts[0].to_string(),
                version: parts[1].to_string(),
                source: PackageSource::Dpkg,
            });
        }
    }
    Ok(packages)
}

fn parse_rpm_output(output: &str) -> Result<Vec<Package>, PackageError> {
    let mut packages = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, version)) = line.split_once('|') {
            packages.push(Package {
                name: name.to_string(),
                version: version.to_string(),
                source: PackageSource::Rpm,
            });
        }
    }
    Ok(packages)
}

fn parse_pacman_output(output: &str) -> Result<Vec<Package>, PackageError> {
    let mut packages = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: name version
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            packages.push(Package {
                name: parts[0].to_string(),
                version: parts[1].to_string(),
                source: PackageSource::Pacman,
            });
        }
    }
    Ok(packages)
}

fn parse_apk_output(output: &str) -> Result<Vec<Package>, PackageError> {
    let mut packages = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, version)) = line.split_once('-') {
            packages.push(Package {
                name: name.to_string(),
                version: version.to_string(),
                source: PackageSource::Apk,
            });
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_dpkg_output() -> &'static str {
        r#"Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name                                   Version                                Architecture Description
+++-=======================================-======================================-============-===============================================================================
ii  adduser                                3.134                                   all          add and remove users and groups
ii  apt                                    2.8.2                                   amd64        commandline package manager
ii  base-files                             12.5                                     amd64        Debian base system miscellaneous files
ii  bash                                   5.2.21-1                                amd64        GNU Bourne Again SHell
"#
    }

    fn mock_rpm_output() -> &'static str {
    "bash|5.2.21-1.fc40\nopenssl|3.2.2-4.fc40\nsystemd|255.4-1.fc40\n"
}

    fn mock_pacman_output() -> &'static str {
        "bash 5.2.21-1\nopenssl 3.2.2-1\nsystemd 255.4-1\n"
    }

    fn mock_apk_output() -> &'static str {
        "bash-5.2.21-r1\nopenssl-3.2.2-r1\nsystemd-255.4-r1\n"
    }

    #[test]
    fn test_parse_dpkg() {
        let packages = parse_dpkg_output(mock_dpkg_output()).unwrap();
        assert_eq!(packages.len(), 4);
        assert_eq!(packages[0].name, "adduser");
        assert_eq!(packages[0].version, "3.134");
        assert_eq!(packages[0].source, PackageSource::Dpkg);
    }

    #[test]
    fn test_parse_rpm() {
        let packages = parse_rpm_output(mock_rpm_output()).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "bash");
        assert_eq!(packages[0].version, "5.2.21-1.fc40");
        assert_eq!(packages[0].source, PackageSource::Rpm);
    }

    #[test]
    fn test_parse_pacman() {
        let packages = parse_pacman_output(mock_pacman_output()).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "bash");
        assert_eq!(packages[0].version, "5.2.21-1");
        assert_eq!(packages[0].source, PackageSource::Pacman);
    }

    #[test]
    fn test_parse_apk() {
        let packages = parse_apk_output(mock_apk_output()).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "bash");
        assert_eq!(packages[0].version, "5.2.21-r1");
        assert_eq!(packages[0].source, PackageSource::Apk);
    }
}
