package main

import (
	"testing"
)

func TestSanitizeMAC_ColonSeparator(t *testing.T) {
	got := sanitizeMAC("00:1B:44:11:3A:B7")
	want := "00:1B:44:XX:XX:XX"
	if got != want {
		t.Errorf("sanitizeMAC colon = %q, want %q", got, want)
	}
}

func TestSanitizeMAC_DashSeparator(t *testing.T) {
	got := sanitizeMAC("00-1B-44-11-3A-B7")
	want := "00-1B-44-XX-XX-XX"
	if got != want {
		t.Errorf("sanitizeMAC dash = %q, want %q", got, want)
	}
}

func TestSanitizeMAC_Empty(t *testing.T) {
	got := sanitizeMAC("")
	if got != "" {
		t.Errorf("sanitizeMAC empty = %q, want empty", got)
	}
}

func TestSanitizeMAC_Short(t *testing.T) {
	got := sanitizeMAC("AA:BB")
	if got != "AA:BB" {
		t.Errorf("sanitizeMAC short = %q, want unchanged", got)
	}
}

func TestSanitizeIP_Standard(t *testing.T) {
	got := sanitizeIP("192.168.1.50")
	want := "192.168.1.x"
	if got != want {
		t.Errorf("sanitizeIP = %q, want %q", got, want)
	}
}

func TestSanitizeIP_Empty(t *testing.T) {
	got := sanitizeIP("")
	if got != "" {
		t.Errorf("sanitizeIP empty = %q, want empty", got)
	}
}

func TestSanitizeIP_SingleOctet(t *testing.T) {
	got := sanitizeIP("10")
	if got != "10" {
		t.Errorf("sanitizeIP single = %q, want unchanged", got)
	}
}

func TestSanitizeHostname_Normal(t *testing.T) {
	got := sanitizeHostname("myserver.local")
	if got == "myserver.local" {
		t.Error("sanitizeHostname should hash, not return original")
	}
	if len(got) == 0 {
		t.Error("sanitizeHostname returned empty")
	}
	if got[:5] != "host-" {
		t.Errorf("sanitizeHostname = %q, should start with 'host-'", got)
	}
}

func TestSanitizeHostname_Empty(t *testing.T) {
	got := sanitizeHostname("")
	if got != "" {
		t.Errorf("sanitizeHostname empty = %q, want empty", got)
	}
}

func TestSanitizeHostname_Unknown(t *testing.T) {
	got := sanitizeHostname("Unknown")
	if got != "Unknown" {
		t.Errorf("sanitizeHostname Unknown = %q, want 'Unknown'", got)
	}
}

func TestSanitizeHostname_Deterministic(t *testing.T) {
	a := sanitizeHostname("test-server")
	b := sanitizeHostname("test-server")
	if a != b {
		t.Errorf("sanitizeHostname not deterministic: %q != %q", a, b)
	}
}

func TestSanitizeHost_Full(t *testing.T) {
	host := &HostWithPorts{
		Host: Host{
			IP:       "192.168.1.100",
			MAC:      "AA:BB:CC:DD:EE:FF",
			Hostname: "web-server",
		},
	}

	SanitizeHost(host)

	if host.IP != "192.168.1.x" {
		t.Errorf("SanitizeHost IP = %q, want '192.168.1.x'", host.IP)
	}
	if host.MAC != "AA:BB:CC:XX:XX:XX" {
		t.Errorf("SanitizeHost MAC = %q, want 'AA:BB:CC:XX:XX:XX'", host.MAC)
	}
	if host.Hostname == "web-server" {
		t.Error("SanitizeHost should have hashed hostname")
	}
	if host.Hostname[:5] != "host-" {
		t.Errorf("SanitizeHost hostname = %q, should start with 'host-'", host.Hostname)
	}
}
