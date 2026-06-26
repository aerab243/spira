use clap::Parser;
use crate::cli::{Cli, Commands};
use crate::scanner::packages::PackageManagerTrait;
use crate::cve::cache::CveCache;
use crate::cve::nvd::NvdClient;
use crate::utils::truncate;

mod cli;
mod scanner;
mod utils;
mod cve;
mod audit;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Detect { kernel, packages } => cmd_detect(cli, kernel, packages),
        Commands::Packages => cmd_packages(cli),
        Commands::Scan { kernel, services } => cmd_scan(cli, kernel, services),
        Commands::Audit => cmd_audit(cli),
        Commands::Vulns { ref name } => cmd_vulns(name.clone()),
        Commands::Update => cmd_update(cli),
    };

    if let Err(e) = result {
        eprintln!("Erreur: {e}");
        std::process::exit(1);
    }
}

fn cmd_detect(cli: Cli, _kernel: bool, _packages: bool) -> Result<(), Box<dyn std::error::Error>> {
    let distro = scanner::distro::detect()?;
    let kernel = scanner::kernel::detect().ok();
    let pkg_mgr = scanner::packages::detect().ok();

    if cli.json {
        let json = serde_json::json!({
            "distro": {
                "id": distro.id,
                "name": distro.name,
                "version": distro.version,
                "codename": distro.codename,
                "pretty_name": distro.pretty_name,
            },
            "kernel": kernel.map(|k| serde_json::json!({
                "version": k.version,
                "arch": k.arch,
            })),
            "package_manager": pkg_mgr.map(|p| format!("{:?}", p)),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("Distro: {} ({})", distro.pretty_name, distro.id);
    println!("Version: {}", distro.version);
    if let Some(codename) = distro.codename {
        println!("Codename: {codename}");
    }
    if let Some(k) = kernel {
        println!("Kernel: {} [{}]", k.version, k.arch);
    }
    if let Some(p) = pkg_mgr {
        println!("Package Manager: {:?}", p);
    }

    Ok(())
}

fn cmd_packages(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let manager = scanner::packages::detect()?;
    let packages = manager.list_packages()?;

    if cli.json {
        let json: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": format!("{:?}", p.source),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("{} paquets trouvés:", packages.len());
    for p in packages {
        println!("  {} {} ({:?})", p.name, p.version, p.source);
    }

    Ok(())
}

fn cmd_scan(_cli: Cli, kernel: bool, services: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Scan complet du système ===\n");

    let distro = scanner::distro::detect()?;
    let kernel_info = scanner::kernel::detect().ok();
    let manager = scanner::packages::detect()?;
    let packages = manager.list_packages()?;

    println!("Distro: {} ({})", distro.pretty_name, distro.id);
    println!("Version: {}", distro.version);
    if let Some(codename) = distro.codename {
        println!("Codename: {codename}");
    }
    if let Some(ref k) = kernel_info {
        println!("Kernel: {} [{}]", k.version, k.arch);
    }
    println!("Package Manager: {:?}", manager);
    println!("Paquets installés: {}\n", packages.len());

    let cache = CveCache::new(std::path::PathBuf::from("./spira_cache.db")).ok();

    if cache.is_none() {
        println!(
            "⚠ Cache CVE introuvable. Exécutez 'spira update' pour activer la détection de vulnérabilités."
        );
    }

    if let Some(ref cache) = cache {
        println!("--- Paquets à risque ---");
        let mut pkg_vulns = Vec::new();
        for pkg in &packages {
            let cpes = cache.search_cpes_by_product(&pkg.name)?;
            let mut seen = std::collections::HashSet::new();
            for (cve, _cpe) in &cpes {
                if seen.insert(cve.id.clone()) {
                    pkg_vulns.push((cve.clone(), pkg.name.clone(), pkg.version.clone()));
                }
            }
        }

        if pkg_vulns.is_empty() {
            println!("Aucune vulnérabilité de paquet détectée.");
        } else {
            pkg_vulns.sort_by(|a, b| {
                let score_a = a.0.cvss_score.unwrap_or(0.0);
                let score_b = b.0.cvss_score.unwrap_or(0.0);
                score_b
                    .partial_cmp(&score_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            println!(
                "{} vulnérabilité(s) de paquet détectée(s):\n",
                pkg_vulns.len()
            );
            for (cve, pkg_name, pkg_ver) in &pkg_vulns {
                println!("CVE: {}", cve.id);
                println!(
                    "  Score: {:?}",
                    cve.cvss_score
                        .map(|s| format!("{:.1}", s))
                        .unwrap_or_else(|| "N/A".to_string())
                );
                println!(
                    "  Sévérité: {}",
                    cve.severity.as_deref().unwrap_or("N/A")
                );
                println!("  Paquet: {} {}", pkg_name, pkg_ver);
                println!(
                    "  Description: {}\n",
                    truncate(&cve.description, 120)
                );
            }
        }

        if kernel {
            println!("\n--- Vulnérabilités du noyau ---");
            match scanner::kernel::scan_kernel_cves(cache) {
                Ok(kernel_vulns) => {
                    if kernel_vulns.is_empty() {
                        println!("Aucune vulnérabilité du noyau détectée.");
                    } else {
                        println!(
                            "{} vulnérabilité(s) du noyau détectée(s):\n",
                            kernel_vulns.len()
                        );
                        for (cve, _cpe) in &kernel_vulns {
                            println!("CVE: {}", cve.id);
                            println!(
                                "  Score: {:?}",
                                cve.cvss_score
                                    .map(|s| format!("{:.1}", s))
                                    .unwrap_or_else(|| "N/A".to_string())
                            );
                            println!(
                                "  Sévérité: {}",
                                cve.severity.as_deref().unwrap_or("N/A")
                            );
                            println!(
                                "  Description: {}\n",
                                truncate(&cve.description, 120)
                            );
                        }
                    }
                }
                Err(e) => println!("Erreur lors du scan du noyau: {e}"),
            }
        }

        if services {
            println!("\n--- Services systemd actifs ---");
            match scanner::services::detect_services() {
                Ok(svcs) => {
                    if svcs.is_empty() {
                        println!("Aucun service systemd actif détecté.");
                    } else {
                        println!("{} service(s) actif(s):\n", svcs.len());
                        for s in &svcs {
                            println!("  {} - {} ({})", s.name, s.description, s.status);
                        }
                    }
                }
                Err(e) => println!("Erreur lors de la détection des services: {e}"),
            }

            println!("\n--- Ports ouverts ---");
            match scanner::services::detect_open_ports() {
                Ok(ports) => {
                    if ports.is_empty() {
                        println!("Aucun port ouvert détecté.");
                    } else {
                        println!("{} port(s) ouvert(s):\n", ports.len());
                        for p in &ports {
                            println!(
                                "  {}:{} ({}) - {}",
                                p.local_addr, p.port, p.protocol, p.process
                            );
                        }
                    }
                }
                Err(e) => println!("Erreur lors de la détection des ports: {e}"),
            }

            println!("\n--- Vulnérabilités des services réseau ---");
            match scanner::network::scan_ports_cves(cache) {
                Ok(net_vulns) => {
                    let total: usize = net_vulns.iter().map(|v| v.cves.len()).sum();
                    if total == 0 {
                        println!("Aucune vulnérabilité de service réseau détectée.");
                    } else {
                        println!(
                            "{} vulnérabilité(s) détectée(s) sur les services réseau:\n",
                            total
                        );
                        for vuln in &net_vulns {
                            for (cve_id, score, severity) in &vuln.cves {
                                println!(
                                    "CVE: {} (port {}/{}, service: {})",
                                    cve_id, vuln.port, vuln.protocol, vuln.service_name
                                );
                                println!(
                                    "  Score: {:?}",
                                    score
                                        .map(|s| format!("{:.1}", s))
                                        .unwrap_or_else(|| "N/A".to_string())
                                );
                                println!(
                                    "  Sévérité: {}\n",
                                    severity.as_deref().unwrap_or("N/A")
                                );
                            }
                        }
                    }
                }
                Err(e) => println!("Erreur lors du scan réseau: {e}"),
            }
        }
    }

    Ok(())
}

fn cmd_audit(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Audit configuration du système ===\n");

    println!("--- Audit SSH ---");
    match audit::ssh::audit_ssh() {
        Ok(findings) => {
            if findings.is_empty() {
                println!("✓ Configuration SSH sécurisée (score: 100/100)");
            } else {
                let score = audit::ssh::ssh_security_score(&findings);
                println!("Score de sécurité SSH: {}/100\n", score);
                for f in &findings {
                    println!("[{}] {} - {}", f.status, f.check, f.severity);
                    println!("  → {}\n", f.recommendation);
                }
            }
        }
        Err(e) => println!("Erreur lors de l'audit SSH: {e}"),
    }

    println!("\n--- Audit Firewall ---");
    match audit::firewall::audit_firewall() {
        Ok(infos) => {
            for info in &infos {
                println!("Backend: {} (actif: {})", info.backend, info.active);
                if !info.findings.is_empty() {
                    for f in &info.findings {
                        println!("  [{}] {} - {}", f.status, f.check, f.severity);
                        println!("    → {}\n", f.recommendation);
                    }
                }
                if info.rules.is_empty() && info.active {
                    println!("  Aucune règle personnalisée détectée.");
                }
            }
        }
        Err(e) => println!("Erreur lors de l'audit firewall: {e}"),
    }

    println!("\n--- Audit Sudoers ---");
    match audit::sudoers::audit_sudoers() {
        Ok(findings) => {
            if findings.is_empty() {
                println!("✓ Configuration sudoers sécurisée (score: 100/100)");
            } else {
                let score = audit::sudoers::sudoers_security_score(&findings);
                println!("Score de sécurité sudoers: {}/100\n", score);
                for f in &findings {
                    println!("[{}] {} - {}", f.status, f.check, f.severity);
                    println!("  → {}\n", f.recommendation);
                }
            }
        }
        Err(e) => println!("Erreur lors de l'audit sudoers: {e}"),
    }

    Ok(())
}

fn cmd_vulns(name: String) -> Result<(), Box<dyn std::error::Error>> {
    let cache = CveCache::new(std::path::PathBuf::from("./spira_cache.db"))?;
    let cpes = cache.search_cpes_by_product(&name)?;

    if cpes.is_empty() {
        println!("Aucun CPE trouvé pour le paquet '{}' dans le cache.", name);
        println!("Exécutez 'spira update' pour mettre à jour la base CVE.");
        return Ok(());
    }

    let mut seen_cves = std::collections::HashSet::new();
    let mut matches = Vec::new();

    for (cve, cpe) in &cpes {
        if seen_cves.insert(cve.id.clone()) {
            matches.push((cve.clone(), cpe.clone()));
        }
    }

    if matches.is_empty() {
        println!("Aucune vulnérabilité correspondante trouvée pour '{}'.", name);
        return Ok(());
    }

    matches.sort_by(|a, b| {
        let score_a = a.0.cvss_score.unwrap_or(0.0);
        let score_b = b.0.cvss_score.unwrap_or(0.0);
        score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
    });

    println!("{} vulnérabilité(s) pour '{}':\n", matches.len(), name);
    for (cve, cpe) in &matches {
        println!("CVE: {}", cve.id);
        println!("  Score: {:?}", cve.cvss_score.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "N/A".to_string()));
        println!("  Sévérité: {}", cve.severity.as_deref().unwrap_or("N/A"));
        println!("  CPE: {}", cpe.cpe_name);
        if let (Some(start), Some(end)) = (&cpe.version_start_including, &cpe.version_end_excluding) {
            println!("  Versions affectées: {} <= version < {}", start, end);
        }
        println!("  Description: {}\n", truncate(&cve.description, 120));
    }

    Ok(())
}

fn cmd_update(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Mise à jour du cache CVE depuis NVD...");

    let cache = CveCache::new(std::path::PathBuf::from("./spira_cache.db"))?;
    let mut client = NvdClient::new();

    let days = 30;
    println!("Récupération des CVEs des {} derniers jours...", days);

    let items = client.fetch_recent(days)?;
    println!("{} entrées récupérées, insertion dans le cache...", items.len());

    let mut cve_count = 0;
    let mut cpe_count = 0;
    for (cve, cpes) in items {
        cache.upsert_cve(&cve)?;
        cve_count += 1;
        for cpe in cpes {
            cache.insert_cpe(&cpe)?;
            cpe_count += 1;
        }
    }

    println!("Cache mis à jour: {} CVE(s), {} CPE(s).", cve_count, cpe_count);

    Ok(())
}
