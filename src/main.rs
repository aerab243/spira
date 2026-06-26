use clap::Parser;
use crate::cli::{Cli, Commands};
use crate::scanner::packages::PackageManagerTrait;

mod cli;
mod scanner;
mod utils;

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

fn cmd_scan(_cli: Cli, _kernel: bool, _services: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("Scan complet... (à implémenter en Phase 3)");
    Ok(())
}

fn cmd_audit(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Audit configuration... (à implémenter en Phase 4)");
    Ok(())
}

fn cmd_vulns(name: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Recherche CVEs pour '{name}'... (à implémenter en Phase 2)");
    Ok(())
}

fn cmd_update(_cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Mise à jour du cache NVD... (à implémenter en Phase 2)");
    Ok(())
}
