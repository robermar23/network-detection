use crate::models::{Host, TopoEdge, TopoNode, TopologyResult};
use std::collections::{HashMap, HashSet};

pub fn build(hosts: &[Host]) -> TopologyResult {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Build nodes with type classification
    for host in hosts {
        let node_type = classify_node(host);
        let label = if host.hostname.is_empty() || host.hostname == "Unknown" {
            host.ip.clone()
        } else {
            host.hostname.clone()
        };

        nodes.push(TopoNode {
            id: host.ip.clone(),
            label,
            node_type,
            ports: host.ports.clone(),
            os: host.os.clone(),
        });
    }

    // Build edges based on subnet grouping
    let subnet_groups = group_by_subnet(hosts);
    for (_subnet, group_hosts) in &subnet_groups {
        // Create edges between all hosts in the same subnet
        for i in 0..group_hosts.len() {
            for j in (i + 1)..group_hosts.len() {
                edges.push(TopoEdge {
                    source: group_hosts[i].ip.clone(),
                    target: group_hosts[j].ip.clone(),
                    evidence: "same-subnet".to_string(),
                });
            }
        }

        // Identify potential gateway and add gateway edges
        for host in group_hosts {
            if is_likely_gateway(&host.ip) {
                for other in group_hosts {
                    if other.ip != host.ip {
                        // Check if we already have an edge between these two
                        let has_edge = edges.iter().any(|e| {
                            (e.source == host.ip && e.target == other.ip && e.evidence == "gateway")
                                || (e.source == other.ip && e.target == host.ip && e.evidence == "gateway")
                        });
                        if !has_edge {
                            edges.push(TopoEdge {
                                source: host.ip.clone(),
                                target: other.ip.clone(),
                                evidence: "gateway".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    TopologyResult { nodes, edges }
}

fn classify_node(host: &Host) -> String {
    let vendor_lower = host.vendor.to_lowercase();
    let ports_set: HashSet<u16> = host.ports.iter().copied().collect();

    // Router detection
    if is_likely_gateway(&host.ip) {
        return "router".to_string();
    }
    if vendor_lower.contains("cisco")
        || vendor_lower.contains("ubiquiti")
        || vendor_lower.contains("juniper")
        || vendor_lower.contains("mikrotik")
        || vendor_lower.contains("netgear")
        || vendor_lower.contains("tp-link")
    {
        return "router".to_string();
    }

    // Server detection (has web/dns/mail ports)
    let server_ports: HashSet<u16> = [53, 80, 443, 8080, 8443, 25, 993, 995, 3306, 5432, 27017]
        .iter()
        .copied()
        .collect();
    if !ports_set.is_disjoint(&server_ports) {
        return "server".to_string();
    }

    // IoT detection
    if vendor_lower.contains("nest")
        || vendor_lower.contains("ring")
        || vendor_lower.contains("wyze")
        || vendor_lower.contains("sonos")
        || vendor_lower.contains("philips")
        || vendor_lower.contains("ecobee")
        || vendor_lower.contains("chamberlain")
        || vendor_lower.contains("espressif")
        || vendor_lower.contains("tuya")
        || vendor_lower.contains("shenzhen")
    {
        return "iot".to_string();
    }

    // Workstation detection
    let workstation_ports: HashSet<u16> = [22, 3389, 5900].iter().copied().collect();
    if !ports_set.is_disjoint(&workstation_ports) {
        return "workstation".to_string();
    }

    "unknown".to_string()
}

fn is_likely_gateway(ip: &str) -> bool {
    if let Some(last_octet_str) = ip.rsplit('.').next() {
        if let Ok(last_octet) = last_octet_str.parse::<u8>() {
            return last_octet == 1 || last_octet == 254;
        }
    }
    false
}

fn group_by_subnet(hosts: &[Host]) -> HashMap<String, Vec<&Host>> {
    let mut groups: HashMap<String, Vec<&Host>> = HashMap::new();
    for host in hosts {
        let parts: Vec<&str> = host.ip.split('.').collect();
        if parts.len() == 4 {
            let subnet = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
            groups.entry(subnet).or_default().push(host);
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_host(ip: &str, vendor: &str, ports: Vec<u16>) -> Host {
        Host {
            ip: ip.to_string(),
            mac: "".to_string(),
            hostname: "".to_string(),
            vendor: vendor.to_string(),
            os: "".to_string(),
            ports,
        }
    }

    #[test]
    fn test_gateway_classification() {
        let hosts = vec![make_host("192.168.1.1", "", vec![80, 443])];
        let result = build(&hosts);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].node_type, "router");
    }

    #[test]
    fn test_server_classification() {
        let hosts = vec![make_host("192.168.1.50", "", vec![80, 443, 22])];
        let result = build(&hosts);
        assert_eq!(result.nodes[0].node_type, "server");
    }

    #[test]
    fn test_workstation_classification() {
        let hosts = vec![make_host("192.168.1.50", "", vec![3389])];
        let result = build(&hosts);
        assert_eq!(result.nodes[0].node_type, "workstation");
    }

    #[test]
    fn test_iot_classification() {
        let hosts = vec![make_host("192.168.1.50", "Espressif Inc.", vec![])];
        let result = build(&hosts);
        assert_eq!(result.nodes[0].node_type, "iot");
    }

    #[test]
    fn test_vendor_router_classification() {
        let hosts = vec![make_host("192.168.1.50", "Cisco Systems", vec![])];
        let result = build(&hosts);
        assert_eq!(result.nodes[0].node_type, "router");
    }

    #[test]
    fn test_same_subnet_edges() {
        let hosts = vec![
            make_host("192.168.1.1", "", vec![]),
            make_host("192.168.1.2", "", vec![]),
            make_host("192.168.1.3", "", vec![]),
        ];
        let result = build(&hosts);
        assert_eq!(result.nodes.len(), 3);
        // Should have edges: 1-2, 1-3, 2-3 (same-subnet) + gateway edges from .1
        let same_subnet_edges: Vec<_> = result.edges.iter()
            .filter(|e| e.evidence == "same-subnet")
            .collect();
        assert_eq!(same_subnet_edges.len(), 3);
    }

    #[test]
    fn test_cross_subnet_no_edges() {
        let hosts = vec![
            make_host("192.168.1.50", "", vec![]),
            make_host("10.0.0.50", "", vec![]),
        ];
        let result = build(&hosts);
        let same_subnet_edges: Vec<_> = result.edges.iter()
            .filter(|e| e.evidence == "same-subnet")
            .collect();
        assert_eq!(same_subnet_edges.len(), 0);
    }

    #[test]
    fn test_gateway_edges() {
        let hosts = vec![
            make_host("192.168.1.1", "", vec![]),
            make_host("192.168.1.50", "", vec![]),
        ];
        let result = build(&hosts);
        let gateway_edges: Vec<_> = result.edges.iter()
            .filter(|e| e.evidence == "gateway")
            .collect();
        assert_eq!(gateway_edges.len(), 1);
    }

    #[test]
    fn test_empty_hosts() {
        let result = build(&[]);
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
    }

    #[test]
    fn test_hostname_label() {
        let mut host = make_host("192.168.1.50", "", vec![]);
        host.hostname = "myserver.local".to_string();
        let result = build(&[host]);
        assert_eq!(result.nodes[0].label, "myserver.local");
    }

    #[test]
    fn test_unknown_hostname_uses_ip() {
        let mut host = make_host("192.168.1.50", "", vec![]);
        host.hostname = "Unknown".to_string();
        let result = build(&[host]);
        assert_eq!(result.nodes[0].label, "192.168.1.50");
    }
}
