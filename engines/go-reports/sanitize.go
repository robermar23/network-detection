package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// SanitizeHost applies data sanitization in-place to a host
func SanitizeHost(host *HostWithPorts) {
	host.MAC = sanitizeMAC(host.MAC)
	host.IP = sanitizeIP(host.IP)
	host.Hostname = sanitizeHostname(host.Hostname)
}

// sanitizeMAC masks the last 3 octets of a MAC address
// e.g., "00:1B:44:11:3A:B7" -> "00:1B:44:XX:XX:XX"
func sanitizeMAC(mac string) string {
	if mac == "" {
		return mac
	}

	// Handle both colon and dash separators
	sep := ":"
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		parts = strings.Split(mac, "-")
		sep = "-"
	}
	if len(parts) != 6 {
		return mac // Can't parse, return as-is
	}

	return fmt.Sprintf("%s%s%s%s%s%sXX%sXX%sXX",
		parts[0], sep, parts[1], sep, parts[2], sep, sep, sep)
}

// sanitizeIP replaces the host portion with 'x'
// e.g., "192.168.1.50" -> "192.168.1.x"
func sanitizeIP(ip string) string {
	if ip == "" {
		return ip
	}

	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip // Not a valid IPv4, return as-is
	}

	return fmt.Sprintf("%s.%s.%s.x", parts[0], parts[1], parts[2])
}

// sanitizeHostname hashes the hostname with SHA256 and returns a prefix
// e.g., "myserver.local" -> "host-a1b2c3d4"
func sanitizeHostname(hostname string) string {
	if hostname == "" || hostname == "Unknown" {
		return hostname
	}

	hash := sha256.Sum256([]byte(hostname))
	return fmt.Sprintf("host-%x", hash[:4])
}
