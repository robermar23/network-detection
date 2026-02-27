use crate::models::{Baseline, DiffResult, DiffSummary, Host, PortChange, BannerChange, TlsChange};
use std::collections::{HashMap, HashSet};

pub fn compute_diff(baseline: &Baseline, current_hosts: &[Host]) -> DiffResult {
    let baseline_map: HashMap<&str, &Host> = baseline.hosts.iter()
        .map(|h| (h.ip.as_str(), h))
        .collect();

    let current_map: HashMap<&str, &Host> = current_hosts.iter()
        .map(|h| (h.ip.as_str(), h))
        .collect();

    let baseline_ips: HashSet<&str> = baseline_map.keys().copied().collect();
    let current_ips: HashSet<&str> = current_map.keys().copied().collect();

    // New hosts: in current but not in baseline
    let new_hosts: Vec<Host> = current_ips.difference(&baseline_ips)
        .filter_map(|ip| current_map.get(ip))
        .map(|h| (*h).clone())
        .collect();

    // Missing hosts: in baseline but not in current
    let missing_hosts: Vec<Host> = baseline_ips.difference(&current_ips)
        .filter_map(|ip| baseline_map.get(ip))
        .map(|h| (*h).clone())
        .collect();

    // Port changes: hosts present in both with different ports
    let mut port_changes = Vec::new();
    for ip in baseline_ips.intersection(&current_ips) {
        let old_host = baseline_map[ip];
        let new_host = current_map[ip];

        let old_ports: HashSet<u16> = old_host.ports.iter().copied().collect();
        let new_ports: HashSet<u16> = new_host.ports.iter().copied().collect();

        let added: Vec<u16> = new_ports.difference(&old_ports).copied().collect();
        let removed: Vec<u16> = old_ports.difference(&new_ports).copied().collect();

        if !added.is_empty() || !removed.is_empty() {
            port_changes.push(PortChange {
                ip: ip.to_string(),
                added_ports: added,
                removed_ports: removed,
            });
        }
    }

    let total_port_changes = port_changes.len();

    // Banner and TLS changes are detected when deep scan data is available
    // For the basic diff, we compare host-level fields
    let banner_changes: Vec<BannerChange> = Vec::new();
    let tls_changes: Vec<TlsChange> = Vec::new();

    let summary_stats = DiffSummary {
        total_new: new_hosts.len(),
        total_missing: missing_hosts.len(),
        total_port_changes,
        total_banner_changes: banner_changes.len(),
        total_tls_changes: tls_changes.len(),
    };

    DiffResult {
        new_hosts,
        missing_hosts,
        port_changes,
        banner_changes,
        tls_changes,
        summary_stats,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::BaselineMeta;

    fn make_host(ip: &str, ports: Vec<u16>) -> Host {
        Host {
            ip: ip.to_string(),
            mac: "00:00:00:00:00:00".to_string(),
            hostname: "".to_string(),
            vendor: "".to_string(),
            os: "".to_string(),
            ports,
        }
    }

    fn make_baseline(hosts: Vec<Host>) -> Baseline {
        Baseline {
            meta: BaselineMeta {
                id: "test-id".to_string(),
                label: "test".to_string(),
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                host_count: hosts.len(),
            },
            hosts,
        }
    }

    #[test]
    fn test_no_changes() {
        let hosts = vec![make_host("192.168.1.1", vec![22, 80])];
        let baseline = make_baseline(hosts.clone());
        let diff = compute_diff(&baseline, &hosts);

        assert!(diff.new_hosts.is_empty());
        assert!(diff.missing_hosts.is_empty());
        assert!(diff.port_changes.is_empty());
        assert_eq!(diff.summary_stats.total_new, 0);
    }

    #[test]
    fn test_new_host() {
        let baseline = make_baseline(vec![make_host("192.168.1.1", vec![22])]);
        let current = vec![
            make_host("192.168.1.1", vec![22]),
            make_host("192.168.1.2", vec![80]),
        ];
        let diff = compute_diff(&baseline, &current);

        assert_eq!(diff.new_hosts.len(), 1);
        assert_eq!(diff.new_hosts[0].ip, "192.168.1.2");
        assert_eq!(diff.summary_stats.total_new, 1);
    }

    #[test]
    fn test_missing_host() {
        let baseline = make_baseline(vec![
            make_host("192.168.1.1", vec![22]),
            make_host("192.168.1.2", vec![80]),
        ]);
        let current = vec![make_host("192.168.1.1", vec![22])];
        let diff = compute_diff(&baseline, &current);

        assert_eq!(diff.missing_hosts.len(), 1);
        assert_eq!(diff.missing_hosts[0].ip, "192.168.1.2");
        assert_eq!(diff.summary_stats.total_missing, 1);
    }

    #[test]
    fn test_port_changes() {
        let baseline = make_baseline(vec![make_host("192.168.1.1", vec![22, 80])]);
        let current = vec![make_host("192.168.1.1", vec![22, 443])];
        let diff = compute_diff(&baseline, &current);

        assert_eq!(diff.port_changes.len(), 1);
        let change = &diff.port_changes[0];
        assert_eq!(change.ip, "192.168.1.1");
        assert!(change.added_ports.contains(&443));
        assert!(change.removed_ports.contains(&80));
    }

    #[test]
    fn test_empty_baseline() {
        let baseline = make_baseline(vec![]);
        let current = vec![make_host("192.168.1.1", vec![22])];
        let diff = compute_diff(&baseline, &current);

        assert_eq!(diff.new_hosts.len(), 1);
        assert!(diff.missing_hosts.is_empty());
    }

    #[test]
    fn test_empty_current() {
        let baseline = make_baseline(vec![make_host("192.168.1.1", vec![22])]);
        let current: Vec<Host> = vec![];
        let diff = compute_diff(&baseline, &current);

        assert!(diff.new_hosts.is_empty());
        assert_eq!(diff.missing_hosts.len(), 1);
    }

    #[test]
    fn test_combined_changes() {
        let baseline = make_baseline(vec![
            make_host("192.168.1.1", vec![22, 80]),
            make_host("192.168.1.2", vec![443]),
        ]);
        let current = vec![
            make_host("192.168.1.1", vec![22, 80, 8080]),
            make_host("192.168.1.3", vec![3389]),
        ];
        let diff = compute_diff(&baseline, &current);

        assert_eq!(diff.new_hosts.len(), 1);     // .3 is new
        assert_eq!(diff.missing_hosts.len(), 1);  // .2 is missing
        assert_eq!(diff.port_changes.len(), 1);   // .1 has port change (added 8080)
    }
}
