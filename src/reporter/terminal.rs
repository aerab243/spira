use crate::audit::ssh::AuditFinding;
use crate::scanner::kernel::KernelInfo;
use crate::scanner::network::PortVulnerability;
use crate::scanner::services::{PortInfo, ServiceInfo};
use crate::utils::truncate;

#[allow(dead_code)]
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";

#[derive(Debug, Clone)]
pub struct CveSummary {
    pub id: String,
    pub score: Option<f64>,
    pub severity: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub distro_id: String,
    pub distro_name: String,
    pub distro_version: String,
    pub kernel: Option<KernelInfo>,
    pub package_manager: String,
    pub total_packages: usize,
    pub package_vulns: Vec<CveSummary>,
    pub kernel_vulns: Vec<CveSummary>,
    pub services: Vec<ServiceInfo>,
    pub open_ports: Vec<PortInfo>,
    pub network_vulns: Vec<PortVulnerability>,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub ssh_findings: Vec<AuditFinding>,
    pub ssh_score: u8,
    pub firewalls: Vec<FirewallSummary>,
    pub sudoers_findings: Vec<AuditFinding>,
    pub sudoers_score: u8,
}

#[derive(Debug, Clone)]
pub struct FirewallSummary {
    pub backend: &'static str,
    pub active: bool,
    pub findings: Vec<AuditFinding>,
}

impl ScanReport {
    pub fn total_vulns(&self) -> usize {
        self.package_vulns.len()
            + self.kernel_vulns.len()
            + self.network_vulns.iter().map(|v| v.cves.len()).sum::<usize>()
    }

    pub fn critical_count(&self) -> usize {
        count_severity(&self.package_vulns, "CRITICAL")
            + count_severity(&self.kernel_vulns, "CRITICAL")
            + self.network_vulns.iter().filter(|v| {
                v.cves.iter().any(|(_, _, sev)| sev.as_deref() == Some("CRITICAL"))
            }).count()
    }

    pub fn high_count(&self) -> usize {
        count_severity(&self.package_vulns, "HIGH")
            + count_severity(&self.kernel_vulns, "HIGH")
            + self.network_vulns.iter().filter(|v| {
                v.cves.iter().any(|(_, _, sev)| sev.as_deref() == Some("HIGH"))
            }).count()
    }
}

impl AuditReport {
    pub fn total_findings(&self) -> usize {
        self.ssh_findings.len()
            + self.firewalls.iter().map(|f| f.findings.len()).sum::<usize>()
            + self.sudoers_findings.len()
    }

    pub fn critical_count(&self) -> usize {
        count_findings(&self.ssh_findings, "CRITICAL")
            + self.firewalls.iter().map(|f| count_findings(&f.findings, "CRITICAL")).sum::<usize>()
            + count_findings(&self.sudoers_findings, "CRITICAL")
    }

    pub fn high_count(&self) -> usize {
        count_findings(&self.ssh_findings, "HIGH")
            + self.firewalls.iter().map(|f| count_findings(&f.findings, "HIGH")).sum::<usize>()
            + count_findings(&self.sudoers_findings, "HIGH")
    }

    pub fn overall_score(&self) -> u8 {
        let scores = [self.ssh_score as u16, self.sudoers_score as u16];
        let avg = scores.iter().sum::<u16>() / scores.len() as u16;
        avg as u8
    }
}

fn count_severity(vulns: &[CveSummary], severity: &str) -> usize {
    vulns.iter().filter(|v| v.severity.as_deref() == Some(severity)).count()
}

fn count_findings(findings: &[AuditFinding], severity: &str) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

impl std::fmt::Display for ScanReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_scan_report(self, f)
    }
}

impl std::fmt::Display for AuditReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write_audit_report(self, f)
    }
}

fn write_scan_report(r: &ScanReport, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

    writeln!(f, "{BOLD}╔══════════════════════════════════════════════╗{RESET}")?;
    writeln!(f, "{BOLD}║         SPIRA - Scan du système             ║{RESET}")?;
    writeln!(f, "{BOLD}╚══════════════════════════════════════════════╝{RESET}")?;
    writeln!(f)?;
    writeln!(f, "{BOLD}Distro:{RESET} {} ({})", r.distro_name, r.distro_id)?;
    writeln!(f, "{BOLD}Version:{RESET} {}", r.distro_version)?;
    if let Some(ref k) = r.kernel {
        writeln!(f, "{BOLD}Noyau:{RESET} {} [{}]", k.version, k.arch)?;
    }
    writeln!(f, "{BOLD}Gestionnaire de paquets:{RESET} {:?}", r.package_manager)?;
    writeln!(f, "{BOLD}Paquets installes:{RESET} {}", r.total_packages)?;
    writeln!(f)?;

    let total = r.total_vulns();
    let crit = r.critical_count();
    let high = r.high_count();

    writeln!(f, "{CYAN}┌─ Resume vulnerabilites ─────────────────────┐{RESET}")?;
    write!(f, "│ Total: {} ", colorize_count(total, ""))?;
    write!(f, "│ Critique: {} ", colorize_count(crit, "CRITICAL"))?;
    writeln!(f, "│ Elevee: {} │", colorize_count(high, "HIGH"))?;
    writeln!(f, "{CYAN}└─────────────────────────────────────────────┘{RESET}")?;
    writeln!(f)?;

    if !r.package_vulns.is_empty() {
        writeln!(f, "{YELLOW}═══ Vulnerabilites des paquets ═══{RESET}")?;
        for (i, v) in r.package_vulns.iter().enumerate() {
            writeln!(f, "  {}. {}", i + 1, colorize_cve(&v.id, v.severity.as_deref()))?;
            writeln!(f, "     Score: {}", colorize_score(v.score))?;
            writeln!(f, "     Severite: {}", colorize_severity(v.severity.as_deref()))?;
            writeln!(f, "     {DIM}{}{RESET}", truncate(&v.description, 100))?;
            writeln!(f)?;
        }
    }

    if !r.kernel_vulns.is_empty() {
        writeln!(f, "{YELLOW}═══ Vulnerabilites du noyau ═══{RESET}")?;
        for (i, v) in r.kernel_vulns.iter().enumerate() {
            writeln!(f, "  {}. {}", i + 1, colorize_cve(&v.id, v.severity.as_deref()))?;
            writeln!(f, "     Score: {}", colorize_score(v.score))?;
            writeln!(f, "     Severite: {}", colorize_severity(v.severity.as_deref()))?;
            writeln!(f, "     {DIM}{}{RESET}", truncate(&v.description, 100))?;
            writeln!(f)?;
        }
    }

    if !r.services.is_empty() {
        writeln!(f, "{BLUE}═══ Services systemd actifs ═══{RESET}")?;
        for s in &r.services {
            writeln!(f, "  {} - {} ({})", s.name, s.description, s.status)?;
        }
        writeln!(f)?;
    }

    if !r.open_ports.is_empty() {
        writeln!(f, "{BLUE}═══ Ports ouverts ═══{RESET}")?;
        for p in &r.open_ports {
            writeln!(f, "  {}:{} ({}) - {}", p.local_addr, p.port, p.protocol, p.process)?;
        }
        writeln!(f)?;
    }

    if !r.network_vulns.is_empty() {
        writeln!(f, "{YELLOW}═══ Vulnerabilites services reseau ═══{RESET}")?;
        for vuln in &r.network_vulns {
            for (id, score, severity) in &vuln.cves {
                writeln!(f, "  {} (port {}/{})", colorize_cve(id, severity.as_deref()), vuln.port, vuln.protocol)?;
                writeln!(f, "     Service: {}", vuln.service_name)?;
                writeln!(f, "     Score: {}", colorize_score(*score))?;
                writeln!(f, "     Severite: {}", colorize_severity(severity.as_deref()))?;
                writeln!(f)?;
            }
        }
    }

    if total == 0 {
        writeln!(f, "{GREEN}Aucune vulnerabilite detectee.{RESET}")?;
    }

    Ok(())
}

fn write_audit_report(r: &AuditReport, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

    writeln!(f, "{BOLD}╔══════════════════════════════════════════════╗{RESET}")?;
    writeln!(f, "{BOLD}║      SPIRA - Audit configuration            ║{RESET}")?;
    writeln!(f, "{BOLD}╚══════════════════════════════════════════════╝{RESET}")?;
    writeln!(f)?;

    let overall = r.overall_score();
    writeln!(f, "{BOLD}Score global:{RESET} {}", colorize_score(Some(overall as f64)))?;
    writeln!(f, "{BOLD}Findings:{RESET} {}", r.total_findings())?;
    writeln!(f, "  Critique: {}  Eleve: {}", colorize_count(r.critical_count(), "CRITICAL"), colorize_count(r.high_count(), "HIGH"))?;
    writeln!(f)?;

    writeln!(f, "{CYAN}─── Audit SSH (score: {}/100) ───{RESET}", colorize_score(Some(r.ssh_score as f64)))?;
    if r.ssh_findings.is_empty() {
        writeln!(f, "{GREEN}Configuration SSH securisee.{RESET}")?;
    } else {
        for finding in &r.ssh_findings {
            writeln!(f, "  [{}] {} - {}", finding.status, finding.check, colorize_severity(Some(finding.severity)))?;
            writeln!(f, "    → {DIM}{}{RESET}", finding.recommendation)?;
        }
    }
    writeln!(f)?;

    for fw in &r.firewalls {
        writeln!(f, "{CYAN}─── Firewall: {} (actif: {}) ───{RESET}", fw.backend, fw.active)?;
        if fw.findings.is_empty() {
            writeln!(f, "{GREEN}Aucun probleme detecte.{RESET}")?;
        } else {
            for finding in &fw.findings {
                writeln!(f, "  [{}] {} - {}", finding.status, finding.check, colorize_severity(Some(finding.severity)))?;
                writeln!(f, "    → {DIM}{}{RESET}", finding.recommendation)?;
            }
        }
        writeln!(f)?;
    }

    writeln!(f, "{CYAN}─── Audit Sudoers (score: {}/100) ───{RESET}", colorize_score(Some(r.sudoers_score as f64)))?;
    if r.sudoers_findings.is_empty() {
        writeln!(f, "{GREEN}Configuration sudoers securisee.{RESET}")?;
    } else {
        for finding in &r.sudoers_findings {
            writeln!(f, "  [{}] {} - {}", finding.status, finding.check, colorize_severity(Some(finding.severity)))?;
            writeln!(f, "    → {DIM}{}{RESET}", finding.recommendation)?;
        }
    }

    Ok(())
}

fn colorize_cve(id: &str, severity: Option<&str>) -> String {
    let color = match severity {
        Some("CRITICAL") | Some("HIGH") => "\x1b[31m",
        Some("MEDIUM") => "\x1b[33m",
        Some("LOW") => "\x1b[32m",
        _ => "\x1b[0m",
    };
    format!("{color}\x1b[1m{id}\x1b[0m")
}

fn colorize_score(score: Option<f64>) -> String {
    match score {
        Some(s) if s >= 9.0 => format!("\x1b[31m\x1b[1m{:.1}\x1b[0m", s),
        Some(s) if s >= 7.0 => format!("\x1b[33m\x1b[1m{:.1}\x1b[0m", s),
        Some(s) if s >= 4.0 => format!("\x1b[33m{:.1}\x1b[0m", s),
        Some(s) => format!("\x1b[32m\x1b[1m{:.1}\x1b[0m", s),
        None => "N/A".to_string(),
    }
}

fn colorize_severity(severity: Option<&str>) -> String {
    match severity {
        Some("CRITICAL") => "[\x1b[31mCRITIQUE\x1b[0m]".to_string(),
        Some("HIGH") => "[\x1b[31mELEVEE\x1b[0m]".to_string(),
        Some("MEDIUM") => "[\x1b[33mMOYENNE\x1b[0m]".to_string(),
        Some("LOW") => "[\x1b[32mFAIBLE\x1b[0m]".to_string(),
        Some(s) => format!("[\x1b[2m{s}\x1b[0m]"),
        None => "N/A".to_string(),
    }
}

fn colorize_count(count: usize, severity: &str) -> String {
    let color = match severity {
        "CRITICAL" | "HIGH" => "\x1b[31m",
        "MEDIUM" => "\x1b[33m",
        "LOW" => "\x1b[32m",
        _ => "\x1b[0m",
    };
    if count > 0 {
        format!("{color}\x1b[1m{count}\x1b[0m")
    } else {
        format!("\x1b[32m{count}\x1b[0m")
    }
}
