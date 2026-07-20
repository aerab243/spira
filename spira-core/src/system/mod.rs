/// Module `system` — Collecte des informations sur le système Linux.
///
/// Fournit des fonctions pour interroger le système d'exploitation,
/// le kernel, les paquets installés, et les ressources matérielles.
///
/// IMPORTANT : Utilise `tokio::process::Command` pour éviter de bloquer
/// le thread async de Tokio.
use crate::types::{ScanError, SystemInfo};
use tokio::process::Command;

/// Collecte toutes les informations système disponibles.
pub async fn collect_system_info() -> Result<SystemInfo, ScanError> {
    let os = get_os_info().await?;
    let kernel_version = get_kernel_version().await?;
    let hostname = get_hostname().await?;
    let uptime_seconds = get_uptime().await?;
    let packages_count = get_packages_count().await?;
    let cpu_cores = get_cpu_cores().await?;
    let total_memory_mb = get_total_memory().await?;

    Ok(SystemInfo {
        os,
        kernel_version,
        hostname,
        uptime_seconds,
        packages_count,
        cpu_cores,
        total_memory_mb,
    })
}

/// Récupère le nom et la version de la distribution Linux.
pub async fn get_os_info() -> Result<String, ScanError> {
    // Essaie /etc/os-release d'abord (standard)
    let output = Command::new("sh")
        .arg("-c")
        .arg(". /etc/os-release && echo \"$NAME $VERSION_ID\"")
        .output()
        .await;

    if let Ok(output) = output {
        if output.status.success() {
            let info = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !info.is_empty() {
                return Ok(info);
            }
        }
    }

    // Fallback: lsb_release
    let output = Command::new("lsb_release").arg("-ds").output().await;
    if let Ok(output) = output {
        if output.status.success() {
            let info = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !info.is_empty() {
                return Ok(info);
            }
        }
    }

    Ok("Linux (distribution inconnue)".to_string())
}

/// Récupère la version du kernel Linux.
pub async fn get_kernel_version() -> Result<String, ScanError> {
    let output = Command::new("uname").arg("-r").output().await?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(version)
}

/// Récupère le nom d'hôte de la machine.
pub async fn get_hostname() -> Result<String, ScanError> {
    let output = Command::new("hostname").output().await?;
    let hostname = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(hostname)
}

/// Récupère le temps d'activité du système en secondes.
pub async fn get_uptime() -> Result<u64, ScanError> {
    // Lit /proc/uptime
    if let Ok(content) = tokio::fs::read_to_string("/proc/uptime").await {
        if let Some(seconds_str) = content.split_whitespace().next() {
            if let Ok(seconds) = seconds_str.parse::<f64>() {
                return Ok(seconds as u64);
            }
        }
    }
    Ok(0)
}

/// Compte le nombre de paquets installés via dpkg.
pub async fn get_packages_count() -> Result<u32, ScanError> {
    let output = Command::new("dpkg-query")
        .arg("-f")
        .arg("${Package}\n")
        .arg("-W")
        .output()
        .await?;
    let count = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .count() as u32;
    Ok(count)
}

/// Récupère le nombre de cœurs CPU.
pub async fn get_cpu_cores() -> Result<u32, ScanError> {
    if let Ok(content) = tokio::fs::read_to_string("/proc/cpuinfo").await {
        let count = content
            .lines()
            .filter(|l| l.starts_with("processor"))
            .count() as u32;
        if count > 0 {
            return Ok(count);
        }
    }
    // Fallback
    let output = Command::new("nproc").output().await?;
    let count = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .unwrap_or(1);
    Ok(count)
}

/// Récupère la mémoire totale en Mo.
pub async fn get_total_memory() -> Result<u64, ScanError> {
    if let Ok(content) = tokio::fs::read_to_string("/proc/meminfo").await {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                // Format: "MemTotal:       16392452 kB"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return Ok(kb / 1024);
                    }
                }
            }
        }
    }
    Ok(0)
}
