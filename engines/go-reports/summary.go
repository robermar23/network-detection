package main

import (
	"sort"
)

// Summary represents the management summary section of a report
type Summary struct {
	TotalHosts    int            `json:"totalHosts"`
	TotalPorts    int            `json:"totalPorts"`
	CriticalCount int            `json:"criticalCount"`
	WarningCount  int            `json:"warningCount"`
	RiskyHosts    []RiskyHost    `json:"riskyHosts,omitempty"`
	ExposedPorts  []ExposedPort  `json:"exposedPorts,omitempty"`
	NewExposures  []NewExposure  `json:"newExposures,omitempty"`
}

// RiskyHost represents a host with vulnerability findings
type RiskyHost struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	VulnCount int    `json:"vulnCount"`
}

// ExposedPort represents a port exposed across multiple hosts
type ExposedPort struct {
	Port    uint16 `json:"port"`
	Service string `json:"service"`
	Count   int    `json:"count"`
}

// NewExposure represents a newly opened port since baseline
type NewExposure struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// GenerateSummary analyzes host data and produces a management summary
func GenerateSummary(hosts []HostWithPorts, baseline *DiffResult) Summary {
	summary := Summary{
		TotalHosts: len(hosts),
	}

	// Count total ports
	for _, host := range hosts {
		summary.TotalPorts += len(host.Ports)
	}

	// Analyze risky hosts (those with vulnerable deep scan ports)
	riskyMap := make(map[string]*RiskyHost)
	portCounts := make(map[uint16]int)
	portServices := make(map[uint16]string)

	for _, host := range hosts {
		for _, dp := range host.DeepPorts {
			if dp.Vulnerable {
				if rh, exists := riskyMap[host.IP]; exists {
					rh.VulnCount++
				} else {
					riskyMap[host.IP] = &RiskyHost{
						IP:        host.IP,
						Hostname:  host.Hostname,
						VulnCount: 1,
					}
				}

				// Count severity
				switch dp.Severity {
				case "critical":
					summary.CriticalCount++
				case "warning":
					summary.WarningCount++
				}
			}

			// Track port exposure across hosts
			portCounts[dp.Port]++
			if portServices[dp.Port] == "" {
				portServices[dp.Port] = dp.ServiceName
			}
		}

		// Also count basic ports for exposure tracking
		for _, p := range host.Ports {
			portCounts[p]++
		}
	}

	// Convert risky hosts map to sorted slice (most vulnerabilities first)
	for _, rh := range riskyMap {
		summary.RiskyHosts = append(summary.RiskyHosts, *rh)
	}
	sort.Slice(summary.RiskyHosts, func(i, j int) bool {
		return summary.RiskyHosts[i].VulnCount > summary.RiskyHosts[j].VulnCount
	})
	// Limit to top 10
	if len(summary.RiskyHosts) > 10 {
		summary.RiskyHosts = summary.RiskyHosts[:10]
	}

	// Find widely exposed ports (appearing on 3+ hosts)
	for port, count := range portCounts {
		if count >= 3 {
			service := portServices[port]
			if service == "" {
				service = guessService(port)
			}
			summary.ExposedPorts = append(summary.ExposedPorts, ExposedPort{
				Port:    port,
				Service: service,
				Count:   count,
			})
		}
	}
	sort.Slice(summary.ExposedPorts, func(i, j int) bool {
		return summary.ExposedPorts[i].Count > summary.ExposedPorts[j].Count
	})

	// Add new exposures from baseline diff
	if baseline != nil {
		for _, pc := range baseline.PortChanges {
			for _, port := range pc.AddedPorts {
				summary.NewExposures = append(summary.NewExposures, NewExposure{
					IP:   pc.IP,
					Port: port,
				})
			}
		}
	}

	return summary
}

func guessService(port uint16) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP Proxy"
	case 27017:
		return "MongoDB"
	default:
		return "Unknown"
	}
}
