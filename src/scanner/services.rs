use std::process::Command;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortInfo {
    pub protocol: String,
    pub local_addr: String,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Erreur d'exécution systemctl: {0}")]
    SystemctlError(String),
    #[error("Erreur d'exécution ss: {0}")]
    SsError(String),
}

pub fn detect_services() -> Result<Vec<ServiceInfo>, ServiceError> {
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ])
        .output()
        .map_err(|e| ServiceError::SystemctlError(e.to_string()))?;

    if !output.status.success() {
        return Err(ServiceError::SystemctlError(
            "systemctl list-units a échoué".to_string(),
        ));
    }

    parse_systemctl_output(&String::from_utf8_lossy(&output.stdout))
}

fn parse_systemctl_output(output: &str) -> Result<Vec<ServiceInfo>, ServiceError> {
    let mut services = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            services.push(ServiceInfo {
                name: parts[0].to_string(),
                description: parts[4..].join(" "),
                status: parts[2].to_string(),
            });
        }
    }
    Ok(services)
}

pub fn detect_open_ports() -> Result<Vec<PortInfo>, ServiceError> {
    let output = Command::new("ss")
        .args(["-tulpn"])
        .output()
        .map_err(|e| ServiceError::SsError(e.to_string()))?;

    if !output.status.success() {
        return Err(ServiceError::SsError(
            "ss -tulpn a échoué".to_string(),
        ));
    }

    parse_ss_output(&String::from_utf8_lossy(&output.stdout))
}

fn parse_ss_output(output: &str) -> Result<Vec<PortInfo>, ServiceError> {
    let mut ports = Vec::new();
    for line in output.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            let local = parts[3];
            let process = if parts.len() >= 6 {
                parts[5..].join(" ")
            } else {
                "unknown".to_string()
            };

            if let Some((addr, port_str)) = local.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    let addr = addr
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string();
                    let protocol = if parts[0] == "LISTEN" {
                        "tcp"
                    } else {
                        "udp"
                    };
                    ports.push(PortInfo {
                        protocol: protocol.to_string(),
                        local_addr: addr,
                        port,
                        process,
                    });
                }
            }
        }
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_systemctl_output() -> &'static str {
        r#"sshd.service loaded active running OpenSSH server daemon
cron.service loaded active running Regular background program processing daemon
systemd-resolved.service loaded active running Network Name Resolution
"#
    }

    fn mock_ss_output() -> &'static str {
        r#"State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
LISTEN 0      128     0.0.0.0:22          0.0.0.0:*         users:(("sshd",pid=1234,fd=3))
LISTEN 0      128     127.0.0.1:25        0.0.0.0:*         users:(("master",pid=567,fd=3))
LISTEN 0      128     [::]:22             [::]:*            users:(("sshd",pid=1234,fd=4))
"#
    }

    #[test]
    fn test_parse_systemctl() {
        let services = parse_systemctl_output(mock_systemctl_output()).unwrap();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].name, "sshd.service");
        assert_eq!(services[0].description, "OpenSSH server daemon");
        assert_eq!(services[0].status, "active");
    }

    #[test]
    fn test_parse_ss() {
        let ports = parse_ss_output(mock_ss_output()).unwrap();
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].local_addr, "0.0.0.0");
        assert_eq!(ports[1].port, 25);
        assert_eq!(ports[1].local_addr, "127.0.0.1");
        assert_eq!(ports[2].local_addr, "::");
    }
}
