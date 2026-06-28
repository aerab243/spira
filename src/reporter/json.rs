// SPDX-License-Identifier: Apache-2.0

use crate::reporter::terminal::{AuditReport, ScanReport};

pub fn render_scan(report: &ScanReport) -> Result<String, serde_json::Error> {
    let json = serde_json::json!({
        "report_type": "scan",
        "distro": {
            "id": report.distro_id,
            "name": report.distro_name,
            "version": report.distro_version,
        },
        "kernel": report.kernel.as_ref().map(|k| serde_json::json!({
            "version": k.version,
            "arch": k.arch,
        })),
        "package_manager": report.package_manager,
        "total_packages": report.total_packages,
        "summary": {
            "total_vulnerabilities": report.total_vulns(),
            "critical": report.critical_count(),
            "high": report.high_count(),
        },
        "package_vulnerabilities": report.package_vulns.iter().map(|v| serde_json::json!({
            "id": v.id,
            "package": v.package_name,
            "installed_version": v.installed_version,
            "score": v.score,
            "severity": v.severity,
            "description": v.description,
        })).collect::<Vec<_>>(),
        "kernel_vulnerabilities": report.kernel_vulns.iter().map(|v| serde_json::json!({
            "id": v.id,
            "score": v.score,
            "severity": v.severity,
            "description": v.description,
        })).collect::<Vec<_>>(),
        "services": report.services.iter().map(|s| serde_json::json!({
            "name": s.name,
            "description": s.description,
            "status": s.status,
        })).collect::<Vec<_>>(),
        "open_ports": report.open_ports.iter().map(|p| serde_json::json!({
            "protocol": p.protocol,
            "address": p.local_addr,
            "port": p.port,
            "process": p.process,
        })).collect::<Vec<_>>(),
        "network_vulnerabilities": report.network_vulns.iter().map(|v| serde_json::json!({
            "port": v.port,
            "protocol": v.protocol,
            "service": v.service_name,
            "cves": v.cves.iter().map(|(id, score, sev)| serde_json::json!({
                "id": id,
                "score": score,
                "severity": sev,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&json)
}

pub fn render_audit(report: &AuditReport) -> Result<String, serde_json::Error> {
    let json = serde_json::json!({
        "report_type": "audit",
        "summary": {
            "overall_score": report.overall_score(),
            "total_findings": report.total_findings(),
            "critical": report.critical_count(),
            "high": report.high_count(),
        },
        "ssh": {
            "score": report.ssh_score,
            "findings": report.ssh_findings.iter().map(|f| serde_json::json!({
                "check": f.check,
                "status": f.status,
                "severity": f.severity,
                "recommendation": f.recommendation,
            })).collect::<Vec<_>>(),
        },
        "firewalls": report.firewalls.iter().map(|fw| serde_json::json!({
            "backend": fw.backend,
            "active": fw.active,
            "findings": fw.findings.iter().map(|f| serde_json::json!({
                "check": f.check,
                "status": f.status,
                "severity": f.severity,
                "recommendation": f.recommendation,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "sudoers": {
            "score": report.sudoers_score,
            "findings": report.sudoers_findings.iter().map(|f| serde_json::json!({
                "check": f.check,
                "status": f.status,
                "severity": f.severity,
                "recommendation": f.recommendation,
            })).collect::<Vec<_>>(),
        },
    });
    serde_json::to_string_pretty(&json)
}
