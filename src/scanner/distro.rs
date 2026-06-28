// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistroInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub codename: Option<String>,
    pub pretty_name: String,
}

#[derive(Debug, Error)]
pub enum DistroError {
    #[error("Fichier /etc/os-release introuvable")]
    OsReleaseNotFound,
    #[error("Erreur de lecture: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Erreur de parsing: {0}")]
    ParseError(String),
}

const OS_RELEASE_PATHS: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

pub fn detect() -> Result<DistroInfo, DistroError> {
    let path = OS_RELEASE_PATHS
        .iter()
        .find(|p| Path::new(p).exists())
        .ok_or(DistroError::OsReleaseNotFound)?;

    let content = fs::read_to_string(path)?;
    let mut fields: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim_matches('"');
            fields.insert(key.trim().to_string(), value.to_string());
        }
    }

    let id = fields
        .get("ID")
        .ok_or_else(|| DistroError::ParseError("ID manquant".into()))?
        .clone();
    let name = fields
        .get("NAME")
        .ok_or_else(|| DistroError::ParseError("NAME manquant".into()))?
        .clone();
    let version = fields
        .get("VERSION_ID")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let codename = fields.get("VERSION_CODENAME").cloned();
    let pretty_name = fields
        .get("PRETTY_NAME")
        .cloned()
        .unwrap_or_else(|| name.clone());

    Ok(DistroInfo {
        id,
        name,
        version,
        codename,
        pretty_name,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    fn parse_os_release(content: &str) -> HashMap<String, String> {
        let mut fields = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim_matches('"');
                fields.insert(key.trim().to_string(), value.to_string());
            }
        }
        fields
    }

    #[test]
    fn test_detect_ubuntu() {
        let content = r#"ID=ubuntu
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION_CODENAME="jammy"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"#;
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID"), Some(&"ubuntu".to_string()));
        assert_eq!(fields.get("NAME"), Some(&"Ubuntu".to_string()));
        assert_eq!(fields.get("VERSION_ID"), Some(&"22.04".to_string()));
        assert_eq!(fields.get("VERSION_CODENAME"), Some(&"jammy".to_string()));
    }

    #[test]
    fn test_detect_fedora() {
        let content = r#"ID=fedora
NAME="Fedora Linux"
VERSION_ID="39"
PRETTY_NAME="Fedora Linux 39"
"#;
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID"), Some(&"fedora".to_string()));
        assert_eq!(fields.get("VERSION_ID"), Some(&"39".to_string()));
        assert!(fields.get("VERSION_CODENAME").is_none());
    }

    #[test]
    fn test_detect_debian() {
        let content = r#"ID=debian
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME="bookworm"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
"#;
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID"), Some(&"debian".to_string()));
        assert_eq!(fields.get("VERSION_CODENAME"), Some(&"bookworm".to_string()));
    }
}
