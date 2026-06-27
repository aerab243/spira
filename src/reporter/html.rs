use crate::reporter::terminal::{AuditReport, ScanReport};

pub fn render_scan(report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = write_html_scan(report, &mut out);
    out
}

pub fn render_audit(report: &AuditReport) -> String {
    let mut out = String::new();
    let _ = write_html_audit(report, &mut out);
    out
}

fn write_html_scan(report: &ScanReport, f: &mut String) -> std::fmt::Result {
    push(f, "<!DOCTYPE html>")?;
    push(f, "<html lang=\"fr\">")?;
    push(f, "<head>")?;
    push(f, "  <meta charset=\"UTF-8\">")?;
    push(f, "  <title>SPIRA - Scan ")?;
    push(f, &html_escape(&report.distro_name))?;
    push(f, "</title>")?;
    push(f, "  <style>")?;
    push(f, "    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }")?;
    push(f, "    h1 { color: #2c3e50; }")?;
    push(f, "    h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 8px; }")?;
    push(f, "    .summary { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")?;
    push(f, "    .critical { color: #c0392b; font-weight: bold; }")?;
    push(f, "    .high { color: #e74c3c; }")?;
    push(f, "    .medium { color: #f39c12; }")?;
    push(f, "    .low { color: #27ae60; }")?;
    push(f, "    .ok { color: #27ae60; font-weight: bold; }")?;
    push(f, "    table { border-collapse: collapse; width: 100%; margin: 15px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")?;
    push(f, "    th { background: #3498db; color: white; padding: 12px; text-align: left; }")?;
    push(f, "    td { padding: 10px 12px; border-bottom: 1px solid #ecf0f1; }")?;
    push(f, "    tr:hover { background: #f8f9fa; }")?;
    push(f, "    .score { font-size: 2em; font-weight: bold; }")?;
    push(f, "    .recommendation { color: #7f8c8d; font-style: italic; }")?;
    push(f, "  </style>")?;
    push(f, "</head>")?;
    push(f, "<body>")?;
    push(f, "  <h1>SPIRA - Scan du système</h1>")?;

    push(f, "  <div class=\"summary\">")?;
    push(f, "    <strong>Distro:</strong> ")?;
    push(f, &html_escape(&format!("{} ({})", report.distro_name, report.distro_id)))?;
    push(f, "<br>")?;
    push(f, "    <strong>Version:</strong> ")?;
    push(f, &html_escape(&report.distro_version))?;
    push(f, "<br>")?;
    if let Some(ref k) = report.kernel {
        push(f, "    <strong>Noyau:</strong> ")?;
        push(f, &html_escape(&format!("{} [{}]", k.version, k.arch)))?;
        push(f, "<br>")?;
    }
    push(f, "    <strong>Paquets:</strong> ")?;
    push(f, &report.total_packages.to_string())?;
    push(f, "<br>")?;
    push(f, "  </div>")?;

    let total = report.total_vulns();
    let crit = report.critical_count();
    let high = report.high_count();

    push(f, "  <div class=\"summary\">")?;
    push(f, "    <h2>Résumé</h2>")?;
    push(f, "    <p>Total vulnérabilités: <strong>")?;
    push(f, &total.to_string())?;
    push(f, "</strong></p>")?;
    push(f, "    <p>Critique: <span class=\"critical\">")?;
    push(f, &crit.to_string())?;
    push(f, "</span></p>")?;
    push(f, "    <p>Élevée: <span class=\"high\">")?;
    push(f, &high.to_string())?;
    push(f, "</span></p>")?;
    push(f, "  </div>")?;

    if !report.package_vulns.is_empty() {
        push(f, "  <h2>Vulnérabilités des paquets</h2>")?;
        push(f, "  <table>")?;
        push(f, "    <tr><th>CVE</th><th>Paquet</th><th>Version</th><th>Score</th><th>Sévérité</th><th>Description</th></tr>")?;
        for v in &report.package_vulns {
            let sev_class = severity_class(v.severity.as_deref());
            push(f, "    <tr>")?;
            push(f, "      <td><strong>")?;
            push(f, &html_escape(&v.id))?;
            push(f, "</strong></td>")?;
            push(f, "      <td>")?;
            push(f, &html_escape(v.package_name.as_deref().unwrap_or("?")))?;
            push(f, "</td>")?;
            push(f, "      <td>")?;
            push(f, &html_escape(v.installed_version.as_deref().unwrap_or("?")))?;
            push(f, "</td>")?;
            push(f, "      <td>")?;
            push(f, &format!("{:.1}", v.score.unwrap_or(0.0)))?;
            push(f, "</td>")?;
            push(f, "      <td class=\"")?;
            push(f, sev_class)?;
            push(f, "\">")?;
            push(f, &html_escape(v.severity.as_deref().unwrap_or("N/A")))?;
            push(f, "</td>")?;
            push(f, "      <td>")?;
            push(f, &html_escape(&v.description))?;
            push(f, "</td>")?;
            push(f, "    </tr>")?;
        }
        push(f, "  </table>")?;
    }

    if !report.kernel_vulns.is_empty() {
        push(f, "  <h2>Vulnérabilités du noyau</h2>")?;
        push(f, "  <table>")?;
        push(f, "    <tr><th>CVE</th><th>Score</th><th>Sévérité</th><th>Description</th></tr>")?;
        for v in &report.kernel_vulns {
            let sev_class = severity_class(v.severity.as_deref());
            push(f, "    <tr>")?;
            push(f, "      <td><strong>")?;
            push(f, &html_escape(&v.id))?;
            push(f, "</strong></td>")?;
            push(f, "      <td>")?;
            push(f, &format!("{:.1}", v.score.unwrap_or(0.0)))?;
            push(f, "</td>")?;
            push(f, "      <td class=\"")?;
            push(f, sev_class)?;
            push(f, "\">")?;
            push(f, &html_escape(v.severity.as_deref().unwrap_or("N/A")))?;
            push(f, "</td>")?;
            push(f, "      <td>")?;
            push(f, &html_escape(&v.description))?;
            push(f, "</td>")?;
            push(f, "    </tr>")?;
        }
        push(f, "  </table>")?;
    }

    if !report.services.is_empty() {
        push(f, "  <h2>Services systemd actifs</h2>")?;
        push(f, "  <table>")?;
        push(f, "    <tr><th>Nom</th><th>Description</th><th>Statut</th></tr>")?;
        for s in &report.services {
            push(f, "    <tr><td>")?;
            push(f, &html_escape(&s.name))?;
            push(f, "</td><td>")?;
            push(f, &html_escape(&s.description))?;
            push(f, "</td><td>")?;
            push(f, &html_escape(&s.status))?;
            push(f, "</td></tr>")?;
        }
        push(f, "  </table>")?;
    }

    if !report.open_ports.is_empty() {
        push(f, "  <h2>Ports ouverts</h2>")?;
        push(f, "  <table>")?;
        push(f, "    <tr><th>Adresse</th><th>Port</th><th>Protocole</th><th>Processus</th></tr>")?;
        for p in &report.open_ports {
            push(f, "    <tr><td>")?;
            push(f, &html_escape(&p.local_addr))?;
            push(f, ":")?;
            push(f, &p.port.to_string())?;
            push(f, "</td><td>")?;
            push(f, &p.port.to_string())?;
            push(f, "</td><td>")?;
            push(f, &html_escape(&p.protocol))?;
            push(f, "</td><td>")?;
            push(f, &html_escape(&p.process))?;
            push(f, "</td></tr>")?;
        }
        push(f, "  </table>")?;
    }

    push(f, "</body>")?;
    push(f, "</html>")?;
    Ok(())
}

fn write_html_audit(report: &AuditReport, f: &mut String) -> std::fmt::Result {
    let overall = report.overall_score();
    let sev_class = score_severity_class(overall);

    push(f, "<!DOCTYPE html>")?;
    push(f, "<html lang=\"fr\">")?;
    push(f, "<head>")?;
    push(f, "  <meta charset=\"UTF-8\">")?;
    push(f, "  <title>SPIRA - Audit</title>")?;
    push(f, "  <style>")?;
    push(f, "    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }")?;
    push(f, "    h1 { color: #2c3e50; }")?;
    push(f, "    h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 8px; }")?;
    push(f, "    .summary { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")?;
    push(f, "    .critical { color: #c0392b; font-weight: bold; }")?;
    push(f, "    .high { color: #e74c3c; }")?;
    push(f, "    .medium { color: #f39c12; }")?;
    push(f, "    .low { color: #27ae60; }")?;
    push(f, "    .ok { color: #27ae60; font-weight: bold; }")?;
    push(f, "    table { border-collapse: collapse; width: 100%; margin: 15px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }")?;
    push(f, "    th { background: #3498db; color: white; padding: 12px; text-align: left; }")?;
    push(f, "    td { padding: 10px 12px; border-bottom: 1px solid #ecf0f1; }")?;
    push(f, "    tr:hover { background: #f8f9fa; }")?;
    push(f, "    .score { font-size: 2em; }")?;
    push(f, "    .recommendation { color: #7f8c8d; font-style: italic; }")?;
    push(f, "  </style>")?;
    push(f, "</head>")?;
    push(f, "<body>")?;
    push(f, "  <h1>SPIRA - Audit configuration</h1>")?;

    push(f, "  <div class=\"summary\">")?;
    push(f, "    <p>Score global: <span class=\"")?;
    push(f, sev_class)?;
    push(f, "\">")?;
    push(f, &overall.to_string())?;
    push(f, "/100</span></p>")?;
    push(f, "    <p>Findings: <strong>")?;
    push(f, &report.total_findings().to_string())?;
    push(f, "</strong></p>")?;
    push(f, "    <p>Critique: <span class=\"critical\">")?;
    push(f, &report.critical_count().to_string())?;
    push(f, "</span> | Élevé: <span class=\"high\">")?;
    push(f, &report.high_count().to_string())?;
    push(f, "</span></p>")?;
    push(f, "  </div>")?;

    push(f, "  <h2>Audit SSH (score: ")?;
    push(f, &report.ssh_score.to_string())?;
    push(f, "/100)</h2>")?;
    if report.ssh_findings.is_empty() {
        push(f, "  <p class=\"ok\">✓ Configuration SSH sécurisée.</p>")?;
    } else {
        push(f, "  <table>")?;
        push(f, "    <tr><th>Statut</th><th>Check</th><th>Sévérité</th><th>Recommandation</th></tr>")?;
        for finding in &report.ssh_findings {
            let sev_class = severity_class(Some(finding.severity));
            push(f, "    <tr>")?;
            push(f, "      <td>")?;
            push(f, &html_escape(finding.status))?;
            push(f, "</td>")?;
            push(f, "      <td><strong>")?;
            push(f, &html_escape(finding.check))?;
            push(f, "</strong></td>")?;
            push(f, "      <td class=\"")?;
            push(f, sev_class)?;
            push(f, "\">")?;
            push(f, &html_escape(finding.severity))?;
            push(f, "</td>")?;
            push(f, "      <td class=\"recommendation\">")?;
            push(f, &html_escape(&finding.recommendation))?;
            push(f, "</td>")?;
            push(f, "    </tr>")?;
        }
        push(f, "  </table>")?;
    }

    for fw in &report.firewalls {
        push(f, "  <h2>Firewall: ")?;
        push(f, fw.backend)?;
        push(f, " (actif: ")?;
        push(f, &fw.active.to_string())?;
        push(f, ")</h2>")?;
        if fw.findings.is_empty() {
            push(f, "  <p class=\"ok\">✓ Aucun problème détecté.</p>")?;
        } else {
            push(f, "  <table>")?;
            push(f, "    <tr><th>Statut</th><th>Check</th><th>Sévérité</th><th>Recommandation</th></tr>")?;
            for finding in &fw.findings {
                let sev_class = severity_class(Some(finding.severity));
                push(f, "    <tr>")?;
                push(f, "      <td>")?;
                push(f, &html_escape(finding.status))?;
                push(f, "</td>")?;
                push(f, "      <td><strong>")?;
                push(f, &html_escape(finding.check))?;
                push(f, "</strong></td>")?;
                push(f, "      <td class=\"")?;
                push(f, sev_class)?;
                push(f, "\">")?;
                push(f, &html_escape(finding.severity))?;
                push(f, "</td>")?;
                push(f, "      <td class=\"recommendation\">")?;
                push(f, &html_escape(&finding.recommendation))?;
                push(f, "</td>")?;
                push(f, "    </tr>")?;
            }
            push(f, "  </table>")?;
        }
    }

    push(f, "  <h2>Audit Sudoers (score: ")?;
    push(f, &report.sudoers_score.to_string())?;
    push(f, "/100)</h2>")?;
    if report.sudoers_findings.is_empty() {
        push(f, "  <p class=\"ok\">✓ Configuration sudoers sécurisée.</p>")?;
    } else {
        push(f, "  <table>")?;
        push(f, "    <tr><th>Statut</th><th>Check</th><th>Sévérité</th><th>Recommandation</th></tr>")?;
        for finding in &report.sudoers_findings {
            let sev_class = severity_class(Some(finding.severity));
            push(f, "    <tr>")?;
            push(f, "      <td>")?;
            push(f, &html_escape(finding.status))?;
            push(f, "</td>")?;
            push(f, "      <td><strong>")?;
            push(f, &html_escape(finding.check))?;
            push(f, "</strong></td>")?;
            push(f, "      <td class=\"")?;
            push(f, sev_class)?;
            push(f, "\">")?;
            push(f, &html_escape(finding.severity))?;
            push(f, "</td>")?;
            push(f, "      <td class=\"recommendation\">")?;
            push(f, &html_escape(&finding.recommendation))?;
            push(f, "</td>")?;
            push(f, "    </tr>")?;
        }
        push(f, "  </table>")?;
    }

    push(f, "</body>")?;
    push(f, "</html>")?;
    Ok(())
}

fn severity_class(severity: Option<&str>) -> &'static str {
    match severity {
        Some("CRITICAL") => "critical",
        Some("HIGH") => "high",
        Some("MEDIUM") => "medium",
        Some("LOW") => "low",
        _ => "low",
    }
}

fn score_severity_class(score: u8) -> &'static str {
    if score >= 80 {
        "ok"
    } else if score >= 60 {
        "medium"
    } else if score >= 40 {
        "high"
    } else {
        "critical"
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
}

fn push(f: &mut String, s: &str) -> std::fmt::Result {
    f.push_str(s);
    Ok(())
}
