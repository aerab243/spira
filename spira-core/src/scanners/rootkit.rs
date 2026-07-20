/// Scanner de rootkits — recherche les signes de rootkits et malwares courants
/// en inspectant les processus, modules kernel, fichiers cachés et connexions.
use super::Scanner;
use crate::types::{Severity, Vulnerability, ScanError, ScanType};
use tokio::{fs, process::Command};

pub struct RootkitScanner;

impl RootkitScanner {
    /// Liste des processus suspects (noms de rootkits connus).
    const SUSPICIOUS_PROCESSES: &'static [&'static str] = &[
        "lvp", "inetd", "/dev/tty",
        "worm", "sched", "rookit",
        "srvstr", "/tmp/", "/dev/pty",
        "...", "x11-ssh-askpass",
    ];

    /// Fichiers et répertoires suspects couramment associés aux rootkits.
    const SUSPICIOUS_PATHS: &'static [&'static str] = &[
        "/dev/.mdl",
        "/dev/.lil",
        "/dev/ttyoa",
        "/dev/ttyop",
        "/dev/hda0",
        "/dev/hda1",
        "/dev/ida",
        "/dev/inet",
        "/dev/rd/rd",
        "/dev/port",
        "/dev/md",
        "/dev/.wabbit",
        "/etc/.mdl",
        "/etc/.lil",
        "/etc/inetd.conf",
        "/etc/rc.d/rc.local",
        "/usr/bin/.mdl",
        "/usr/bin/gdaemon",
        "/usr/bin/addr",
        "/usr/bin/atm",
        "/usr/bin/sourcemask",
        "/usr/bin/getty",
        "/usr/sbin/getty",
        "/usr/sbin/inetd",
        "/usr/sbin/sshd",
        "/usr/lib/libkeyutils.so.1.9",
        "/lib/ld.so",
        "/lib/ld-linux.so.2",
        "/lib/ld-lsb.so.3",
        "/lib/ld-lsb.so.2",
        "/tmp/.mdl",
        "/tmp/.lil",
        "/tmp/...",
        "/tmp/.X",
        "/tmp/.x",
    ];

    /// Liste des modules kernel suspects associés aux rootkits.
    const SUSPICIOUS_MODULES: &'static [&'static str] = &[
        "hide_proc", "adore", "adore-ng",
        "knark", "modhide", "sR00t",
        "ipsecs", "phide", "ynve",
        "ark", "kbdv3", "kis",
        "ntfn", "sDbt", "sock",
        "sock2", "tcpl", "wkmr",
        "rpldev", "pkt", "tasker",
        "dyn3", "dyn5", "dyn8",
        "mundek", "mxmod", "poc_mod",
        "skpw", "thy", "ur",
        "mx", "sct", "sd",
        "tux", "ogid", "ogid2",
        "xgn", "mod", "loki",
        "kld", "ktest", "ntdos",
    ];

    /// Vérifie les processus suspects via `ps aux`.
    async fn check_suspicious_processes() -> Result<Vec<String>, ScanError> {
        let output = Command::new("ps")
            .arg("aux")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur ps: {}", e)))?;

        let mut found = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let line_lower = line.to_lowercase();
            for &suspicious in Self::SUSPICIOUS_PROCESSES {
                if line_lower.contains(suspicious) {
                    found.push(format!("Processus suspect : {}", line.trim()));
                    break;
                }
            }
        }

        Ok(found)
    }

    /// Vérifie les connexions réseau suspectes via `ss -tunap`.
    async fn check_suspicious_connections() -> Result<Vec<String>, ScanError> {
        let output = Command::new("ss")
            .arg("-tunap")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur ss: {}", e)))?;

        let mut found = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            // Connexions vers des ports suspects
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let remote = parts[4];
                // Connexions établies vers l'extérieur
                if !remote.starts_with("127.") && !remote.starts_with("::1") && !remote.starts_with("0.0.0.0") {
                    // Ports IRC (souvent utilisés par les botnets)
                    if remote.ends_with(":6667") || remote.ends_with(":6668") || remote.ends_with(":6669") {
                        found.push(format!("Connexion IRC détectée (botnet potentiel) : {}", line.trim()));
                    }
                    // Ports proxy suspects
                    if remote.ends_with(":1080") || remote.ends_with(":9050") || remote.ends_with(":9150") {
                        found.push(format!("Connexion proxy/Tor détectée : {}", line.trim()));
                    }
                }
            }
        }

        Ok(found)
    }

    /// Vérifie les fichiers suspects.
    async fn check_suspicious_files() -> Result<Vec<String>, ScanError> {
        let mut found = Vec::new();

        for path in Self::SUSPICIOUS_PATHS {
            if let Ok(metadata) = fs::metadata(path).await {
                if metadata.is_file() || metadata.is_dir() {
                    found.push(format!("Fichier/répertoire suspect : {}", path));
                }
            }
        }

        Ok(found)
    }

    /// Vérifie les modules kernel chargés via `lsmod`.
    async fn check_kernel_modules() -> Result<Vec<String>, ScanError> {
        let output = Command::new("lsmod")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur lsmod: {}", e)))?;

        let mut found = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(module_name) = parts.first() {
                let module_lower = module_name.to_lowercase();
                for &suspicious in Self::SUSPICIOUS_MODULES {
                    if module_lower.contains(suspicious) {
                        found.push(format!("Module kernel suspect : {} ({})", module_name, line.trim()));
                        break;
                    }
                }
            }
        }

        Ok(found)
    }

    /// Vérifie les crontabs utilisateur pour des entrées suspectes.
    async fn check_cron() -> Result<Vec<String>, ScanError> {
        let output = Command::new("crontab")
            .arg("-l")
            .output()
            .await;

        let mut found = Vec::new();

        if let Ok(output) = output {
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    // Chercher des téléchargements ou scripts depuis des sources externes
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("wget") || line_lower.contains("curl") || line_lower.contains("bash -c") {
                        if line_lower.contains("http") || line_lower.contains("bit.ly") {
                            found.push(format!("Crontab suspecte : {}", line));
                        }
                    }
                }
            }
        }

        Ok(found)
    }

    /// Vérifie les alias bash suspects (qui pourraient masquer des commandes).
    async fn check_bash_aliases() -> Result<Vec<String>, ScanError> {
        let mut found = Vec::new();

        let alias_paths = [
            "/root/.bashrc",
            "/root/.bash_aliases",
            "/etc/bash.bashrc",
        ];

        for path in &alias_paths {
            if let Ok(content) = fs::read_to_string(path).await {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("alias ") {
                        // Vérifier les alias suspects (qui redirigent des commandes standards)
                        let lower = line.to_lowercase();
                        if lower.contains("ls") && (lower.contains("nc") || lower.contains("netcat")) {
                            found.push(format!("Alias suspect détecté dans {} : {}", path, line));
                        }
                        if lower.contains("ps") && lower.contains("grep -v") {
                            found.push(format!("Alias ps suspect (filtrage) dans {} : {}", path, line));
                        }
                    }
                }
            }
        }

        Ok(found)
    }

    /// Vérifie les processus cachés via `/proc`.
    async fn check_hidden_processes() -> Result<Vec<String>, ScanError> {
        let mut found = Vec::new();

        // Lister les PID via /proc
        let mut proc_pids = Vec::new();
        if let Ok(mut dir) = fs::read_dir("/proc").await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Ok(file_type) = entry.file_type().await {
                    if file_type.is_dir() {
                        if let Some(name) = entry.file_name().to_str() {
                            if let Ok(pid) = name.parse::<u32>() {
                                proc_pids.push(pid);
                            }
                        }
                    }
                }
            }
        }

        // Comparer avec ps
        let output = Command::new("ps")
            .arg("-eo pid")
            .output()
            .await
            .map_err(|e| ScanError::CommandError(format!("Erreur ps: {}", e)))?;

        let ps_pids: std::collections::HashSet<u32> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .skip(1)
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .collect();

        // Vérifier si des PID dans /proc n'apparaissent pas dans ps
        let hidden: Vec<u32> = proc_pids
            .iter()
            .filter(|pid| !ps_pids.contains(pid))
            .copied()
            .collect();

        if !hidden.is_empty() {
            found.push(format!(
                "{} processus potentiellement cachés (PID visibles dans /proc mais pas dans ps)",
                hidden.len()
            ));
        }

        Ok(found)
    }
}

#[async_trait::async_trait]
impl Scanner for RootkitScanner {
    fn scan_type(&self) -> ScanType {
        ScanType::Rootkit
    }

    fn description(&self) -> &'static str {
        "Recherche les signes de rootkits et malwares connus"
    }

    async fn scan(&self) -> Result<Vec<Vulnerability>, ScanError> {
        log::info!("Scan de rootkits démarré");

        let mut vulnerabilities = Vec::new();

        // Exécuter toutes les vérifications en parallèle
        let (proc_res, conn_res, file_res, mod_res, cron_res, alias_res, hidden_res) = tokio::join!(
            Self::check_suspicious_processes(),
            Self::check_suspicious_connections(),
            Self::check_suspicious_files(),
            Self::check_kernel_modules(),
            Self::check_cron(),
            Self::check_bash_aliases(),
            Self::check_hidden_processes(),
        );

        // Collecter les résultats, ignorr les erreurs
        let all_findings: Vec<(&str, Vec<String>)> = vec![
            ("Processus suspects", proc_res.unwrap_or_default()),
            ("Connexions suspectes", conn_res.unwrap_or_default()),
            ("Fichiers suspects", file_res.unwrap_or_default()),
            ("Modules kernel suspects", mod_res.unwrap_or_default()),
            ("Crontabs suspectes", cron_res.unwrap_or_default()),
            ("Alias bash suspects", alias_res.unwrap_or_default()),
            ("Processus cachés", hidden_res.unwrap_or_default()),
        ];

        for (category, findings) in &all_findings {
            if findings.is_empty() {
                continue;
            }

            let details = findings.join("\n");
            let count = findings.len();

            let severity = match *category {
                "Modules kernel suspects" | "Processus cachés" => Severity::Critical,
                "Processus suspects" | "Connexions suspectes" => Severity::High,
                "Fichiers suspects" | "Crontabs suspectes" => Severity::Medium,
                _ => Severity::Medium,
            };

            let cvss = match severity {
                Severity::Critical => 9.5,
                Severity::High => 8.0,
                _ => 6.0,
            };

            vulnerabilities.push(Vulnerability {
                id: format!("ROOTKIT-{}", category.to_uppercase().replace(' ', "-")),
                package: "system".to_string(),
                version: String::new(),
                severity,
                description: format!(
                    "{} {} trouvé(s) :\n{}",
                    count, category, details
                ),
                affected_version: count.to_string(),
                fixed_version: None,
                cvss_score: cvss,
                scan_type: ScanType::Rootkit,
                remediation: Some(
                    "Installez et exécutez un outil anti-rootkit (chkrootkit, rkhunter). \
                     Examinez manuellement les fichiers et processus suspects. \
                     En cas de confirmation : réinstallez le système depuis une sauvegarde propre."
                        .to_string(),
                ),
            });
        }

        if all_findings.iter().all(|(_, f)| f.is_empty()) {
            log::info!("✅ Aucun signe de rootkit détecté");
        }

        log::info!(
            "Scan de rootkits terminé : {} vulnérabilités trouvées",
            vulnerabilities.len()
        );

        Ok(vulnerabilities)
    }
}
