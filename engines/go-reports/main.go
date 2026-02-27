package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// Host mirrors the Electron scan result schema
type Host struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Hostname string   `json:"hostname"`
	Vendor   string   `json:"vendor"`
	OS       string   `json:"os"`
	Ports    []uint16 `json:"ports"`
}

// DeepScanPort mirrors the deep scan port result schema
type DeepScanPort struct {
	Port        uint16 `json:"port"`
	ServiceName string `json:"serviceName"`
	Details     string `json:"details"`
	Vulnerable  bool   `json:"vulnerable"`
	Severity    string `json:"severity"`
	RawBanner   string `json:"rawBanner,omitempty"`
}

// HostWithPorts combines host data with deep scan port data
type HostWithPorts struct {
	Host
	DeepPorts []DeepScanPort `json:"deepPorts,omitempty"`
}

// InputPayload is the JSON structure read from stdin
type InputPayload struct {
	Hosts    []HostWithPorts `json:"hosts"`
	Baseline *DiffResult     `json:"baseline,omitempty"`
}

// DiffResult mirrors the Rust engine's diff output
type DiffResult struct {
	NewHosts     []Host       `json:"new_hosts"`
	MissingHosts []Host       `json:"missing_hosts"`
	PortChanges  []PortChange `json:"port_changes"`
	SummaryStats DiffSummary  `json:"summary_stats"`
}

type PortChange struct {
	IP           string   `json:"ip"`
	AddedPorts   []uint16 `json:"added_ports"`
	RemovedPorts []uint16 `json:"removed_ports"`
}

type DiffSummary struct {
	TotalNew           int `json:"total_new"`
	TotalMissing       int `json:"total_missing"`
	TotalPortChanges   int `json:"total_port_changes"`
	TotalBannerChanges int `json:"total_banner_changes"`
	TotalTLSChanges    int `json:"total_tls_changes"`
}

// OutputResult is written to stdout as JSON
type OutputResult struct {
	Success bool   `json:"success"`
	Format  string `json:"format"`
	Path    string `json:"path"`
	Error   string `json:"error,omitempty"`
}

func main() {
	format := flag.String("format", "json", "Export format: json, csv, html, pdf")
	output := flag.String("output", "", "Output file path")
	sanitizeFlag := flag.Bool("sanitize", false, "Sanitize sensitive data")
	summaryFlag := flag.Bool("summary", false, "Include management summary")
	flag.Parse()

	if *output == "" {
		writeResult(OutputResult{Success: false, Error: "Missing --output flag"})
		os.Exit(1)
	}

	// Read JSON payload from stdin
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		writeResult(OutputResult{Success: false, Error: fmt.Sprintf("Failed to read stdin: %v", err)})
		os.Exit(1)
	}

	var payload InputPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		writeResult(OutputResult{Success: false, Error: fmt.Sprintf("Failed to parse input: %v", err)})
		os.Exit(1)
	}

	// Apply sanitization if requested
	if *sanitizeFlag {
		for i := range payload.Hosts {
			SanitizeHost(&payload.Hosts[i])
		}
	}

	// Generate summary if requested
	var summary *Summary
	if *summaryFlag {
		s := GenerateSummary(payload.Hosts, payload.Baseline)
		summary = &s
	}

	// Export in requested format
	err = Export(*format, *output, payload.Hosts, summary)
	if err != nil {
		writeResult(OutputResult{
			Success: false,
			Format:  *format,
			Path:    *output,
			Error:   err.Error(),
		})
		os.Exit(1)
	}

	writeResult(OutputResult{
		Success: true,
		Format:  *format,
		Path:    *output,
	})
}

func writeResult(result OutputResult) {
	json.NewEncoder(os.Stdout).Encode(result)
}
