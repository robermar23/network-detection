package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExport_UnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	err := Export("yaml", filepath.Join(dir, "out.yaml"), nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error = %q, want 'unsupported format'", err.Error())
	}
}

func TestExportJSON_Basic(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.json")

	hosts := []HostWithPorts{
		{Host: Host{IP: "10.0.0.1", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "srv1", Ports: []uint16{22, 80}}},
	}

	err := Export("json", outPath, hosts, nil)
	if err != nil {
		t.Fatalf("exportJSON failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}

	if len(report.Hosts) != 1 {
		t.Errorf("hosts len = %d, want 1", len(report.Hosts))
	}
	if report.Hosts[0].IP != "10.0.0.1" {
		t.Errorf("host IP = %q, want '10.0.0.1'", report.Hosts[0].IP)
	}
	if report.Summary != nil {
		t.Error("summary should be nil when not provided")
	}
}

func TestExportJSON_WithSummary(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.json")

	summary := &Summary{TotalHosts: 5, TotalPorts: 12}
	err := Export("json", outPath, nil, summary)
	if err != nil {
		t.Fatalf("exportJSON failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var report jsonReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}

	if report.Summary == nil {
		t.Fatal("summary should be present")
	}
	if report.Summary.TotalHosts != 5 {
		t.Errorf("summary TotalHosts = %d, want 5", report.Summary.TotalHosts)
	}
}

func TestExportCSV_HeaderAndRows(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.csv")

	hosts := []HostWithPorts{
		{Host: Host{IP: "10.0.0.1", MAC: "AA:BB:CC:DD:EE:FF", Hostname: "srv1", Ports: []uint16{22, 80}}},
	}

	err := Export("csv", outPath, hosts, nil)
	if err != nil {
		t.Fatalf("exportCSV failed: %v", err)
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 1 data row
	if len(records) != 2 {
		t.Fatalf("CSV rows = %d, want 2 (header + 1 data)", len(records))
	}

	header := records[0]
	if header[0] != "IP" {
		t.Errorf("header[0] = %q, want 'IP'", header[0])
	}

	row := records[1]
	if row[0] != "10.0.0.1" {
		t.Errorf("row IP = %q, want '10.0.0.1'", row[0])
	}
}

func TestExportCSV_DeepPorts(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.csv")

	hosts := []HostWithPorts{
		{
			Host: Host{IP: "10.0.0.1"},
			DeepPorts: []DeepScanPort{
				{Port: 22, ServiceName: "SSH", Vulnerable: false},
				{Port: 80, ServiceName: "HTTP", Vulnerable: true, Severity: "warning"},
			},
		},
	}

	err := Export("csv", outPath, hosts, nil)
	if err != nil {
		t.Fatalf("exportCSV failed: %v", err)
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 2 deep port rows
	if len(records) != 3 {
		t.Fatalf("CSV rows = %d, want 3 (header + 2 deep ports)", len(records))
	}
}

func TestExportHTML_ContainsExpectedElements(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.html")

	hosts := []HostWithPorts{
		{Host: Host{IP: "10.0.0.1", Hostname: "web-server", Ports: []uint16{80, 443}}},
	}
	summary := &Summary{TotalHosts: 1, TotalPorts: 2}

	err := Export("html", outPath, hosts, summary)
	if err != nil {
		t.Fatalf("exportHTML failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	html := string(data)
	checks := []string{"<html", "10.0.0.1", "web-server", "Total Hosts", "NetSpecter"}
	for _, check := range checks {
		if !strings.Contains(html, check) {
			t.Errorf("HTML missing expected content: %q", check)
		}
	}
}

func TestExportPDF_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.pdf")

	err := Export("pdf", outPath, nil, nil)
	if err == nil {
		t.Fatal("expected error from PDF export stub")
	}
	if !strings.Contains(err.Error(), "gofpdf") {
		t.Errorf("error = %q, expected mention of gofpdf", err.Error())
	}
}
