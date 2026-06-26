use clap::Parser;
use std::str::FromStr;
use crate::cli::{Cli, Commands};
use crate::scanner::packages::PackageManagerTrait;
use crate::cve::cache::CveCache;
use crate::cve::nvd::NvdClient;
use crate::reporter::terminal::{AuditReport, ScanReport};
use crate::reporter::{html, json, markdown, terminal, ReportFormat};
use crate::utils::truncate;

mod cli;
mod scanner;
mod utils;
mod cve;
mod audit;
mod reporter;

fn main() {
    let cli = Cli::parse();

    let scan_format = match &cli.command {
        Commands::Scan { format, .. } => format.clone(),
        _ => String::new(),
    };
    let audit_format = match &cli.command {
        Commands::Audit { format } => format.clone(),
        _ => String::new(),
    };

    let result = match cli.command {
        Commands::Detect { kernel, packages } => cmd_detect(cli, kernel, packages),
        Commands::Packages => cmd_packages(cli),
        Commands::Scan { kernel, services, .. } => cmd_scan(cli, kernel, services, &scan_format),
        Commands::Audit { .. } => cmd_audit(cli, &audit_format),
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

fn cmd_scan(_cli: Cli, kernel: bool, services: bool, format_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let distro = scanner::distro::detect()?;
    let kernel_info = scanner::kernel::detect().ok();
    let manager = scanner::packages::detect()?;
    let packages = manager.list_packages()?;

    let cache = CveCache::new(std::path::PathBuf::from("./spira_cache.db")).ok();

    let mut package_vulns = Vec::new();
    let mut kernel_vulns = Vec::new();
    let mut network_vulns = Vec::new();
    let mut svcs = Vec::new();
    let mut ports = Vec::new();

    if let Some(ref cache) = cache {
        for pkg in &packages {
            let cpes = cache.search_cpes_by_product(&pkg.name)?;
            let mut seen = std::collections::HashSet::new();
            for (cve, _cpe) in &cpes {
                if seen.insert(cve.id.clone()) {
                    package_vulns.push(terminal::CveSummary {
                        id: cve.id.clone(),
                        score: cve.cvss_score,
                        severity: cve.severity.clone(),
                        description: cve.description.clone(),
                    });
                }
            }
        }

        if kernel {
            for (cve, _cpe) in scanner::kernel::scan_kernel_cves(cache)? {
                kernel_vulns.push(terminal::CveSummary {
                    id: cve.id,
                    score: cve.cvss_score,
                    severity: cve.severity,
                    description: cve.description,
                });
            }
        }

        if services {
            network_vulns = scanner::network::scan_ports_cves(cache)?;
        }
    }

    if services {
        svcs = scanner::services::detect_services().unwrap_or_default();
        ports = scanner::services::detect_open_ports().unwrap_or_default();
    }

    package_vulns.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    kernel_vulns.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    let report = ScanReport {
        distro_id: distro.id,
        distro_name: distro.pretty_name,
        distro_version: distro.version,
        kernel: kernel_info,
        package_manager: format!("{:?}", manager),
        total_packages: packages.len(),
        package_vulns,
        kernel_vulns,
        services: svcs,
        open_ports: ports,
        network_vulns,
    };

    let fmt = ReportFormat::from_str(format_str).unwrap_or_default();

    match fmt {
        ReportFormat::Json => {
            println!("{}", json::render_scan(&report)?);
        }
        ReportFormat::Html => {
            println!("{}", html::render_scan(&report));
        }
        ReportFormat::Markdown => {
            println!("{}", markdown::render_scan(&report));
        }
        ReportFormat::Terminal => {
            print!("{report}");
        }
    }

    Ok(())
}

fn cmd_audit(_cli: Cli, format_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ssh_findings = audit::ssh::audit_ssh().unwrap_or_default();
    let ssh_score = audit::ssh::ssh_security_score(&ssh_findings);

    let firewalls = audit::firewall::audit_firewall()?;
    let firewall_summaries: Vec<terminal::FirewallSummary> = firewalls
        .into_iter()
        .map(|info| terminal::FirewallSummary {
            backend: info.backend,
            active: info.active,
            findings: info.findings,
        })
        .collect();

    let sudoers_findings = audit::sudoers::audit_sudoers().unwrap_or_default();
    let sudoers_score = audit::sudoers::sudoers_security_score(&sudoers_findings);

    let report = AuditReport {
        ssh_findings,
        ssh_score,
        firewalls: firewall_summaries,
        sudoers_findings,
        sudoers_score,
    };

    let fmt = ReportFormat::from_str(format_str).unwrap_or_default();

    match fmt {
        ReportFormat::Json => {
            println!("{}", json::render_audit(&report)?);
        }
        ReportFormat::Html => {
            println!("{}", html::render_audit(&report));
        }
        ReportFormat::Markdown => {
            println!("{}", markdown::render_audit(&report));
        }
        ReportFormat::Terminal => {
            print!("{report}");
        }
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
