use std::fs;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelInfo {
    pub version: String,
    pub release: String,
    pub arch: String,
}

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("Impossible de lire /proc/version")]
    IoError(#[from] std::io::Error),
    #[error("Format /proc/version inattendu")]
    ParseError,
}

pub fn detect() -> Result<KernelInfo, KernelError> {
    let content = fs::read_to_string("/proc/version")?;
    let parts: Vec<&str> = content.split_whitespace().collect();

    // Format typique: "Linux version 6.1.0-17-amd64 ..."
    if parts.len() < 3 {
        return Err(KernelError::ParseError);
    }

    let version = parts[2].to_string();
    let arch = parts
        .get(3)
        .map(|s| {
            s.trim_end_matches(|c: char| c.is_ascii_alphanumeric() && c.is_ascii_digit())
                .trim_end_matches('-')
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    Ok(KernelInfo {
        version,
        release: content.trim().to_string(),
        arch,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_version() {
        let sample = "Linux version 6.1.0-17-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.69-1 (2023-12-30)\n";
        let parts: Vec<&str> = sample.split_whitespace().collect();
        assert_eq!(parts[2], "6.1.0-17-amd64");
    }
}
