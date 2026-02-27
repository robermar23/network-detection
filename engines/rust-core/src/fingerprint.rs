use crate::models::{DeepScanPort, Fingerprint, Host, TlsCertInfo};
use regex::Regex;

/// Analyze a host's deep scan ports and produce service fingerprints with confidence scores.
pub fn analyze(host: &Host, ports: &[DeepScanPort]) -> Vec<Fingerprint> {
    let mut fingerprints = Vec::new();

    for port_data in ports {
        let mut fp = Fingerprint {
            port: port_data.port,
            protocol: "unknown".to_string(),
            product: "".to_string(),
            version: "".to_string(),
            confidence: 0.0,
            evidence: Vec::new(),
            tls_cert: None,
            cpe: None,
        };

        let banner = port_data.raw_banner.as_deref().unwrap_or("");
        let details = &port_data.details;
        let combined = format!("{} {}", banner, details);

        // Try each fingerprinting strategy, accumulate evidence
        try_http_fingerprint(&combined, &mut fp);
        try_ssh_fingerprint(&combined, &mut fp);
        try_tls_fingerprint(details, &mut fp);
        try_smtp_fingerprint(&combined, &mut fp);
        try_ftp_fingerprint(&combined, &mut fp);

        // Port-based fallback if nothing matched
        if fp.confidence == 0.0 {
            apply_port_heuristic(port_data.port, &mut fp);
        }

        // Cap confidence
        if fp.confidence > 0.99 {
            fp.confidence = 0.99;
        }

        fingerprints.push(fp);
    }

    fingerprints
}

fn try_http_fingerprint(text: &str, fp: &mut Fingerprint) {
    // Server header
    let server_re = Regex::new(r"(?i)Server:\s*([^\r\n]+)").unwrap();
    if let Some(caps) = server_re.captures(text) {
        let server = caps[1].trim();
        fp.protocol = "http".to_string();
        fp.evidence.push(format!("Server: {}", server));

        // Extract product and version
        let product_re = Regex::new(r"(?i)^(nginx|apache|lighttpd|microsoft-iis|caddy|openresty|cloudflare)[/\s]*([0-9.]+)?").unwrap();
        if let Some(pcaps) = product_re.captures(server) {
            fp.product = pcaps[1].to_lowercase();
            fp.version = pcaps.get(2).map_or("".to_string(), |m| m.as_str().to_string());
            fp.confidence = 0.9;
        } else {
            fp.product = server.to_string();
            fp.confidence = 0.7;
        }
    }

    // X-Powered-By header
    let powered_re = Regex::new(r"(?i)X-Powered-By:\s*([^\r\n]+)").unwrap();
    if let Some(caps) = powered_re.captures(text) {
        let powered = caps[1].trim();
        fp.evidence.push(format!("X-Powered-By: {}", powered));
        if fp.protocol != "http" {
            fp.protocol = "http".to_string();
        }
        // Boost confidence if we also have Server header
        if fp.confidence > 0.0 {
            fp.confidence = (fp.confidence + 0.05).min(0.95);
        } else {
            fp.product = powered.to_string();
            fp.confidence = 0.6;
        }
    }

    // HTML title
    let title_re = Regex::new(r"(?i)<title>([^<]+)</title>").unwrap();
    if let Some(caps) = title_re.captures(text) {
        let title = caps[1].trim();
        fp.evidence.push(format!("HTML title: {}", title));

        // Detect specific applications
        let title_lower = title.to_lowercase();
        if title_lower.contains("wordpress") {
            fp.product = "wordpress".to_string();
            fp.confidence = fp.confidence.max(0.8);
        } else if title_lower.contains("grafana") {
            fp.product = "grafana".to_string();
            fp.confidence = fp.confidence.max(0.85);
        } else if title_lower.contains("jenkins") {
            fp.product = "jenkins".to_string();
            fp.confidence = fp.confidence.max(0.85);
        }
    }
}

fn try_ssh_fingerprint(text: &str, fp: &mut Fingerprint) {
    let ssh_re = Regex::new(r"SSH-2\.0-(\S+)").unwrap();
    if let Some(caps) = ssh_re.captures(text) {
        let banner = &caps[1];
        fp.protocol = "ssh".to_string();
        fp.evidence.push(format!("SSH banner: {}", banner));

        let openssh_re = Regex::new(r"(?i)OpenSSH[_\s]?([0-9.p]+)?").unwrap();
        if let Some(vcaps) = openssh_re.captures(banner) {
            fp.product = "OpenSSH".to_string();
            fp.version = vcaps.get(1).map_or("".to_string(), |m| m.as_str().to_string());
            fp.confidence = 0.95;
        } else if banner.to_lowercase().contains("dropbear") {
            fp.product = "Dropbear".to_string();
            let drop_re = Regex::new(r"(?i)dropbear[_\s]?([0-9.]+)?").unwrap();
            fp.version = drop_re.captures(banner)
                .and_then(|c| c.get(1))
                .map_or("".to_string(), |m| m.as_str().to_string());
            fp.confidence = 0.9;
        } else {
            fp.product = banner.to_string();
            fp.confidence = 0.8;
        }
    }
}

fn try_tls_fingerprint(details: &str, fp: &mut Fingerprint) {
    // Look for TLS certificate information in the details
    let cert_re = Regex::new(r"(?i)(?:TLS|SSL|Certificate|CN[=:])").unwrap();
    if !cert_re.is_match(details) {
        return;
    }

    if fp.protocol == "unknown" {
        fp.protocol = "tls".to_string();
    }

    // Parse certificate subject/CN
    let cn_re = Regex::new(r"(?i)(?:CN[=:]\s*|Subject:\s*)([^\s,;]+)").unwrap();
    if let Some(caps) = cn_re.captures(details) {
        let cn = caps[1].trim();
        fp.evidence.push(format!("TLS CN: {}", cn));

        let mut cert_info = TlsCertInfo {
            subject: cn.to_string(),
            issuer: "".to_string(),
            valid_from: "".to_string(),
            valid_to: "".to_string(),
            days_until_expiry: 0,
            key_size: None,
            signature: None,
        };

        // Parse issuer
        let issuer_re = Regex::new(r"(?i)Issuer[=:]\s*([^\r\n;]+)").unwrap();
        if let Some(icaps) = issuer_re.captures(details) {
            cert_info.issuer = icaps[1].trim().to_string();
            fp.evidence.push(format!("Issuer: {}", cert_info.issuer));
        }

        // Parse expiry
        let expiry_re = Regex::new(r"(?i)(?:validTo|expires?|not\s*after)[=:]\s*([^\r\n;]+)").unwrap();
        if let Some(ecaps) = expiry_re.captures(details) {
            cert_info.valid_to = ecaps[1].trim().to_string();
            fp.evidence.push(format!("Expires: {}", cert_info.valid_to));
        }

        fp.tls_cert = Some(cert_info);
        fp.confidence = fp.confidence.max(0.7);
    }
}

fn try_smtp_fingerprint(text: &str, fp: &mut Fingerprint) {
    let smtp_re = Regex::new(r"^220[\s-](.+)$").unwrap();
    if let Some(caps) = smtp_re.captures(text) {
        let banner = caps[1].trim();
        fp.protocol = "smtp".to_string();
        fp.evidence.push(format!("SMTP banner: {}", banner));

        let postfix_re = Regex::new(r"(?i)Postfix").unwrap();
        let exim_re = Regex::new(r"(?i)Exim\s*([0-9.]+)?").unwrap();
        let exchange_re = Regex::new(r"(?i)Microsoft\s+ESMTP").unwrap();

        if postfix_re.is_match(banner) {
            fp.product = "Postfix".to_string();
            fp.confidence = 0.9;
        } else if let Some(ecaps) = exim_re.captures(banner) {
            fp.product = "Exim".to_string();
            fp.version = ecaps.get(1).map_or("".to_string(), |m| m.as_str().to_string());
            fp.confidence = 0.9;
        } else if exchange_re.is_match(banner) {
            fp.product = "Microsoft Exchange".to_string();
            fp.confidence = 0.85;
        } else {
            fp.product = banner.to_string();
            fp.confidence = 0.7;
        }
    }
}

fn try_ftp_fingerprint(text: &str, fp: &mut Fingerprint) {
    let ftp_re = Regex::new(r"^220[\s-].*(?i)(FTP|ProFTPD|vsftpd|Pure-FTPd|FileZilla)").unwrap();
    if let Some(caps) = ftp_re.captures(text) {
        let matched = &caps[1];
        fp.protocol = "ftp".to_string();
        fp.evidence.push(format!("FTP banner match: {}", matched));

        let vsftpd_re = Regex::new(r"(?i)vsftpd\s*([0-9.]+)?").unwrap();
        let proftpd_re = Regex::new(r"(?i)ProFTPD\s*([0-9.]+)?").unwrap();

        if let Some(vcaps) = vsftpd_re.captures(text) {
            fp.product = "vsftpd".to_string();
            fp.version = vcaps.get(1).map_or("".to_string(), |m| m.as_str().to_string());
            fp.confidence = 0.9;
        } else if let Some(pcaps) = proftpd_re.captures(text) {
            fp.product = "ProFTPD".to_string();
            fp.version = pcaps.get(1).map_or("".to_string(), |m| m.as_str().to_string());
            fp.confidence = 0.9;
        } else {
            fp.product = matched.to_string();
            fp.confidence = 0.7;
        }
    }
}

fn apply_port_heuristic(port: u16, fp: &mut Fingerprint) {
    let (protocol, product, confidence) = match port {
        21 => ("ftp", "FTP", 0.2),
        22 => ("ssh", "SSH", 0.2),
        23 => ("telnet", "Telnet", 0.2),
        25 => ("smtp", "SMTP", 0.2),
        53 => ("dns", "DNS", 0.2),
        80 => ("http", "HTTP", 0.15),
        110 => ("pop3", "POP3", 0.2),
        143 => ("imap", "IMAP", 0.2),
        443 => ("https", "HTTPS", 0.15),
        445 => ("smb", "SMB", 0.25),
        993 => ("imaps", "IMAPS", 0.2),
        995 => ("pop3s", "POP3S", 0.2),
        1433 => ("mssql", "Microsoft SQL Server", 0.3),
        1723 => ("pptp", "PPTP VPN", 0.25),
        3306 => ("mysql", "MySQL", 0.3),
        3389 => ("rdp", "RDP", 0.3),
        5432 => ("postgresql", "PostgreSQL", 0.3),
        5900 => ("vnc", "VNC", 0.25),
        6379 => ("redis", "Redis", 0.3),
        8080 => ("http-proxy", "HTTP Proxy", 0.1),
        8443 => ("https-alt", "HTTPS Alt", 0.1),
        27017 => ("mongodb", "MongoDB", 0.3),
        _ => ("unknown", "Unknown", 0.1),
    };

    fp.protocol = protocol.to_string();
    fp.product = product.to_string();
    fp.confidence = confidence;
    fp.evidence.push(format!("Port heuristic: {}/{}", port, protocol));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_port(port: u16, banner: Option<&str>, details: &str) -> DeepScanPort {
        DeepScanPort {
            port,
            service_name: "".to_string(),
            details: details.to_string(),
            vulnerable: false,
            severity: "info".to_string(),
            raw_banner: banner.map(|b| b.to_string()),
        }
    }

    fn make_host() -> Host {
        Host {
            ip: "192.168.1.1".to_string(),
            mac: "".to_string(),
            hostname: "".to_string(),
            vendor: "".to_string(),
            os: "".to_string(),
            ports: vec![],
        }
    }

    #[test]
    fn test_http_server_header() {
        let ports = vec![make_port(80, Some("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n"), "")];
        let results = analyze(&make_host(), &ports);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].protocol, "http");
        assert_eq!(results[0].product, "nginx");
        assert_eq!(results[0].version, "1.25.3");
        assert!(results[0].confidence >= 0.9);
    }

    #[test]
    fn test_ssh_openssh() {
        let ports = vec![make_port(22, Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"), "")];
        let results = analyze(&make_host(), &ports);
        assert_eq!(results[0].protocol, "ssh");
        assert_eq!(results[0].product, "OpenSSH");
        assert_eq!(results[0].version, "8.9p1");
        assert!(results[0].confidence >= 0.9);
    }

    #[test]
    fn test_ssh_dropbear() {
        let ports = vec![make_port(22, Some("SSH-2.0-dropbear_2022.83"), "")];
        let results = analyze(&make_host(), &ports);
        assert_eq!(results[0].product, "Dropbear");
        assert!(results[0].confidence >= 0.9);
    }

    #[test]
    fn test_port_heuristic_fallback() {
        let ports = vec![make_port(3306, None, "")];
        let results = analyze(&make_host(), &ports);
        assert_eq!(results[0].protocol, "mysql");
        assert_eq!(results[0].product, "MySQL");
        assert!(results[0].confidence <= 0.3);
    }

    #[test]
    fn test_unknown_port() {
        let ports = vec![make_port(12345, None, "")];
        let results = analyze(&make_host(), &ports);
        assert_eq!(results[0].protocol, "unknown");
        assert!(results[0].confidence <= 0.1);
    }

    #[test]
    fn test_confidence_cap() {
        let ports = vec![make_port(80, Some("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nX-Powered-By: Express\r\n<title>Jenkins</title>"), "")];
        let results = analyze(&make_host(), &ports);
        assert!(results[0].confidence <= 0.99);
    }

    #[test]
    fn test_tls_fingerprint() {
        let ports = vec![make_port(443, None, "TLS Service CN=example.com Issuer=Let's Encrypt validTo=2025-12-01")];
        let results = analyze(&make_host(), &ports);
        assert!(results[0].tls_cert.is_some());
        let cert = results[0].tls_cert.as_ref().unwrap();
        assert_eq!(cert.subject, "example.com");
    }

    #[test]
    fn test_multiple_ports() {
        let ports = vec![
            make_port(22, Some("SSH-2.0-OpenSSH_9.0"), ""),
            make_port(80, Some("HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n"), ""),
            make_port(3306, None, ""),
        ];
        let results = analyze(&make_host(), &ports);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].protocol, "ssh");
        assert_eq!(results[1].protocol, "http");
        assert_eq!(results[2].protocol, "mysql");
    }
}
