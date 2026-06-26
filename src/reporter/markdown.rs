use crate::reporter::terminal::{AuditReport, ScanReport};

pub fn render_scan(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = write_md_scan(report, &mut out);
    out
}

pub fn render_audit(report: &AuditReport) -> String {
    let mut out = String::new();
    let _ = write_md_audit(report, &mut out);
    out
}

fn write_md_scan(report: &ScanReport, f: &mut String) -> std::fmt::Result {
    push(f, "# SPIRA - Scan du système\n")?;
    push(f, "\n")?;
    push(f, "**Distro:** ")?;
    push(f, &report.distro_name)?;
    push(f, " (")?;
    push(f, &report.distro_id)?;
    push(f, ")\n")?;
    push(f, "**Version:** ")?;
    push(f, &report.distro_version)?;
    push(f, "\n")?;
    if let Some(ref k) = report.kernel {
        push(f, "**Noyau:** ")?;
        push(f, &k.version)?;
        push(f, " [")?;
        push(f, &k.arch)?;
        push(f, "]\n")?;
    }
    push(f, "**Gestionnaire de paquets:** ")?;
    push(f, &report.package_manager)?;
    push(f, "\n")?;
    push(f, "**Paquets installes:** ")?;
    push(f, &report.total_packages.to_string())?;
    push(f, "\n\n")?;

    let total = report.total_vulns();
    let crit = report.critical_count();
    let high = report.high_count();

    push(f, "## Resume\n")?;
    push(f, "| Metrique | Valeur |\n")?;
    push(f, "|----------|--------|\n")?;
    push(f, "| Total vulnerabilites | ")?;
    push(f, &total.to_string())?;
    push(f, " |\n")?;
    push(f, "| Critique | **")?;
    push(f, &crit.to_string())?;
    push(f, "** |\n")?;
    push(f, "| Elevee | **")?;
    push(f, &high.to_string())?;
    push(f, "** |\n\n")?;

    if !report.package_vulns.is_empty() {
        push(f, "## Vulnerabilites des paquets\n\n")?;
        push(f, "| CVE | Score | Severite | Description |\n")?;
        push(f, "|-----|-------|----------|-------------|\n")?;
        for v in &report.package_vulns {
            push(f, "| ")?;
            push(f, &v.id)?;
            push(f, " | ")?;
            push(f, &format!("{:.1}", v.score.unwrap_or(0.0)))?;
            push(f, " | ")?;
            push(f, v.severity.as_deref().unwrap_or("N/A"))?;
            push(f, " | ")?;
            push(f, &truncate_md(&v.description, 60))?;
            push(f, " |\n")?;
        }
        push(f, "\n")?;
    }

    if !report.kernel_vulns.is_empty() {
        push(f, "## Vulnerabilites du noyau\n\n")?;
        push(f, "| CVE | Score | Severite | Description |\n")?;
        push(f, "|-----|-------|----------|-------------|\n")?;
        for v in &report.kernel_vulns {
            push(f, "| ")?;
            push(f, &v.id)?;
            push(f, " | ")?;
            push(f, &format!("{:.1}", v.score.unwrap_or(0.0)))?;
            push(f, " | ")?;
            push(f, v.severity.as_deref().unwrap_or("N/A"))?;
            push(f, " | ")?;
            push(f, &truncate_md(&v.description, 60))?;
            push(f, " |\n")?;
        }
        push(f, "\n")?;
    }

    if !report.services.is_empty() {
        push(f, "## Services systemd actifs\n\n")?;
        push(f, "| Nom | Description | Statut |\n")?;
        push(f, "|-----|-------------|--------|\n")?;
        for s in &report.services {
            push(f, "| ")?;
            push(f, &s.name)?;
            push(f, " | ")?;
            push(f, &s.description)?;
            push(f, " | ")?;
            push(f, &s.status)?;
            push(f, " |\n")?;
        }
        push(f, "\n")?;
    }

    if !report.open_ports.is_empty() {
        push(f, "## Ports ouverts\n\n")?;
        push(f, "| Adresse | Port | Protocole | Processus |\n")?;
        push(f, "|---------|------|-----------|-----------|\n")?;
        for p in &report.open_ports {
            push(f, "| ")?;
            push(f, &p.local_addr)?;
            push(f, ":")?;
            push(f, &p.port.to_string())?;
            push(f, " | ")?;
            push(f, &p.port.to_string())?;
            push(f, " | ")?;
            push(f, &p.protocol)?;
            push(f, " | ")?;
            push(f, &p.process)?;
            push(f, " |\n")?;
        }
        push(f, "\n")?;
    }

    if !report.network_vulns.is_empty() {
        push(f, "## Vulnerabilites services réseau\n\n")?;
        for vuln in &report.network_vulns {
            push(f, "### Port ")?;
            push(f, &vuln.port.to_string())?;
            push(f, "/")?;
            push(f, &vuln.protocol)?;
            push(f, " (")?;
            push(f, &vuln.service_name)?;
            push(f, ")\n\n")?;
            push(f, "| CVE | Score | Severite |\n")?;
            push(f, "|-----|-------|----------|\n")?;
            for (id, score, severity) in &vuln.cves {
                push(f, "| ")?;
                push(f, id)?;
                push(f, " | ")?;
                push(f, &format!("{:.1}", score.unwrap_or(0.0)))?;
                push(f, " | ")?;
                push(f, severity.as_deref().unwrap_or("N/A"))?;
                push(f, " |\n")?;
            }
            push(f, "\n")?;
        }
    }

    if total == 0 {
        push(f, "> Aucune vulnerabilite detectee.\n")?;
    }

    Ok(())
}

fn write_md_audit(report: &AuditReport, f: &mut String) -> std::fmt::Result {
    let overall = report.overall_score();

    push(f, "# SPIRA - Audit configuration\n\n")?;
    push(f, "**Score global:** ")?;
    push(f, &overall.to_string())?;
    push(f, "/100\n")?;
    push(f, "**Findings:** ")?;
    push(f, &report.total_findings().to_string())?;
    push(f, "\n")?;
    push(f, "**Critique:** ")?;
    push(f, &report.critical_count().to_string())?;
    push(f, " | **Eleve:** ")?;
    push(f, &report.high_count().to_string())?;
    push(f, "\n\n")?;

    push(f, "## Audit SSH (score: ")?;
    push(f, &report.ssh_score.to_string())?;
    push(f, "/100)\n\n")?;
    if report.ssh_findings.is_empty() {
        push(f, "> Configuration SSH securisee.\n")?;
    } else {
        push(f, "| Statut | Check | Severite | Recommandation |\n")?;
        push(f, "|--------|-------|----------|----------------|\n")?;
        for finding in &report.ssh_findings {
            push(f, "| ")?;
            push(f, finding.status)?;
            push(f, " | **")?;
            push(f, finding.check)?;
            push(f, "** | ")?;
            push(f, finding.severity)?;
            push(f, " | ")?;
            push(f, finding.recommendation)?;
            push(f, " |\n")?;
        }
    }
    push(f, "\n")?;

    for fw in &report.firewalls {
        push(f, "## Firewall: ")?;
        push(f, fw.backend)?;
        push(f, " (actif: ")?;
        push(f, &fw.active.to_string())?;
        push(f, ")\n\n")?;
        if fw.findings.is_empty() {
            push(f, "> Aucun probleme detecte.\n")?;
        } else {
            push(f, "| Statut | Check | Severite | Recommandation |\n")?;
            push(f, "|--------|-------|----------|----------------|\n")?;
            for finding in &fw.findings {
                push(f, "| ")?;
                push(f, finding.status)?;
                push(f, " | **")?;
                push(f, finding.check)?;
                push(f, "** | ")?;
                push(f, finding.severity)?;
                push(f, " | ")?;
                push(f, finding.recommendation)?;
                push(f, " |\n")?;
            }
        }
        push(f, "\n")?;
    }

    push(f, "## Audit Sudoers (score: ")?;
    push(f, &report.sudoers_score.to_string())?;
    push(f, "/100)\n\n")?;
    if report.sudoers_findings.is_empty() {
        push(f, "> Configuration sudoers securisee.\n")?;
    } else {
        push(f, "| Statut | Check | Severite | Recommandation |\n")?;
        push(f, "|--------|-------|----------|----------------|\n")?;
        for finding in &report.sudoers_findings {
            push(f, "| ")?;
            push(f, finding.status)?;
            push(f, " | **")?;
            push(f, finding.check)?;
            push(f, "** | ")?;
            push(f, finding.severity)?;
            push(f, " | ")?;
            push(f, finding.recommendation)?;
            push(f, " |\n")?;
        }
    }

    Ok(())
}

fn truncate_md(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}

fn push(f: &mut String, s: &str) -> std::fmt::Result {
    f.push_str(s);
    Ok(())
}
