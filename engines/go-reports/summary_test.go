package main

import (
	"testing"
)

func TestGenerateSummary_EmptyHosts(t *testing.T) {
	s := GenerateSummary(nil, nil)
	if s.TotalHosts != 0 || s.TotalPorts != 0 {
		t.Errorf("empty summary = %+v, want zeroed", s)
	}
}

func TestGenerateSummary_CountsHostsAndPorts(t *testing.T) {
	hosts := []HostWithPorts{
		{Host: Host{IP: "10.0.0.1", Ports: []uint16{22, 80}}},
		{Host: Host{IP: "10.0.0.2", Ports: []uint16{443}}},
	}
	s := GenerateSummary(hosts, nil)
	if s.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2", s.TotalHosts)
	}
	if s.TotalPorts != 3 {
		t.Errorf("TotalPorts = %d, want 3", s.TotalPorts)
	}
}

func TestGenerateSummary_RiskyHosts(t *testing.T) {
	hosts := []HostWithPorts{
		{
			Host: Host{IP: "10.0.0.1", Hostname: "srv1"},
			DeepPorts: []DeepScanPort{
				{Port: 22, Vulnerable: true, Severity: "critical"},
				{Port: 80, Vulnerable: true, Severity: "warning"},
			},
		},
		{
			Host: Host{IP: "10.0.0.2", Hostname: "srv2"},
			DeepPorts: []DeepScanPort{
				{Port: 443, Vulnerable: true, Severity: "critical"},
			},
		},
	}
	s := GenerateSummary(hosts, nil)

	if len(s.RiskyHosts) != 2 {
		t.Fatalf("RiskyHosts len = %d, want 2", len(s.RiskyHosts))
	}
	// First should have most vulns
	if s.RiskyHosts[0].VulnCount != 2 {
		t.Errorf("top risky host VulnCount = %d, want 2", s.RiskyHosts[0].VulnCount)
	}
	if s.CriticalCount != 2 {
		t.Errorf("CriticalCount = %d, want 2", s.CriticalCount)
	}
	if s.WarningCount != 1 {
		t.Errorf("WarningCount = %d, want 1", s.WarningCount)
	}
}

func TestGenerateSummary_RiskyHostsCappedAt10(t *testing.T) {
	hosts := make([]HostWithPorts, 15)
	for i := range hosts {
		hosts[i] = HostWithPorts{
			Host: Host{IP: "10.0.0." + string(rune('A'+i))},
			DeepPorts: []DeepScanPort{
				{Port: 22, Vulnerable: true, Severity: "critical"},
			},
		}
	}
	s := GenerateSummary(hosts, nil)
	if len(s.RiskyHosts) > 10 {
		t.Errorf("RiskyHosts len = %d, should be capped at 10", len(s.RiskyHosts))
	}
}

func TestGenerateSummary_ExposedPorts(t *testing.T) {
	hosts := []HostWithPorts{
		{Host: Host{IP: "10.0.0.1", Ports: []uint16{22, 80}}},
		{Host: Host{IP: "10.0.0.2", Ports: []uint16{22, 80}}},
		{Host: Host{IP: "10.0.0.3", Ports: []uint16{22, 443}}},
	}
	s := GenerateSummary(hosts, nil)

	// Port 22 appears on 3 hosts → exposed; port 80 on 2 → not exposed
	foundPort22 := false
	for _, ep := range s.ExposedPorts {
		if ep.Port == 22 {
			foundPort22 = true
			if ep.Count != 3 {
				t.Errorf("port 22 count = %d, want 3", ep.Count)
			}
		}
		if ep.Port == 80 {
			t.Error("port 80 should not be exposed (only on 2 hosts)")
		}
	}
	if !foundPort22 {
		t.Error("port 22 should be in ExposedPorts")
	}
}

func TestGenerateSummary_NewExposures(t *testing.T) {
	baseline := &DiffResult{
		PortChanges: []PortChange{
			{IP: "10.0.0.1", AddedPorts: []uint16{8080, 9090}},
			{IP: "10.0.0.2", AddedPorts: []uint16{3306}},
		},
	}
	s := GenerateSummary(nil, baseline)
	if len(s.NewExposures) != 3 {
		t.Errorf("NewExposures len = %d, want 3", len(s.NewExposures))
	}
}

func TestGenerateSummary_NilBaseline(t *testing.T) {
	s := GenerateSummary(nil, nil)
	if s.NewExposures != nil {
		t.Errorf("NewExposures should be nil with nil baseline, got %v", s.NewExposures)
	}
}

func TestGuessService_KnownPorts(t *testing.T) {
	cases := []struct {
		port uint16
		want string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{6379, "Redis"},
		{27017, "MongoDB"},
	}
	for _, tc := range cases {
		got := guessService(tc.port)
		if got != tc.want {
			t.Errorf("guessService(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestGuessService_UnknownPort(t *testing.T) {
	got := guessService(9999)
	if got != "Unknown" {
		t.Errorf("guessService(9999) = %q, want 'Unknown'", got)
	}
}
