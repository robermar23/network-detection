use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── JSON-RPC Protocol ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcSuccessResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub result: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: String,
    pub id: u64,
    pub error: JsonRpcError,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// Error codes
pub const ERR_PARSE: i32 = -32700;
pub const ERR_INVALID_REQUEST: i32 = -32600;
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERR_INVALID_PARAMS: i32 = -32602;
pub const ERR_INTERNAL: i32 = -32603;
pub const ERR_PROFILE_NOT_FOUND: i32 = -1;
pub const ERR_BASELINE_NOT_FOUND: i32 = -2;
pub const ERR_FINGERPRINT_FAILED: i32 = -3;
pub const ERR_TOPOLOGY_FAILED: i32 = -4;

// ── Scan Profiles ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub port_range: String,
    pub timeout: u32,
    pub chunk_size: u32,
    pub banner_grab: bool,
    pub tls_inspect: bool,
    pub security_audit: bool,
    pub safe_mode: bool,
    pub description: String,
}

// ── Host & Scan Data ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: String,
    #[serde(default)]
    pub mac: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepScanPort {
    pub port: u16,
    #[serde(rename = "serviceName")]
    pub service_name: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub vulnerable: bool,
    #[serde(default)]
    pub severity: String,
    #[serde(rename = "rawBanner", default)]
    pub raw_banner: Option<String>,
}

// ── Baseline & Diff ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMeta {
    pub id: String,
    pub label: String,
    pub timestamp: String,
    pub host_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub meta: BaselineMeta,
    pub hosts: Vec<Host>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub new_hosts: Vec<Host>,
    pub missing_hosts: Vec<Host>,
    pub port_changes: Vec<PortChange>,
    pub banner_changes: Vec<BannerChange>,
    pub tls_changes: Vec<TlsChange>,
    pub summary_stats: DiffSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortChange {
    pub ip: String,
    pub added_ports: Vec<u16>,
    pub removed_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerChange {
    pub ip: String,
    pub port: u16,
    pub old_banner: String,
    pub new_banner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsChange {
    pub ip: String,
    pub port: u16,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub total_new: usize,
    pub total_missing: usize,
    pub total_port_changes: usize,
    pub total_banner_changes: usize,
    pub total_tls_changes: usize,
}

// ── Service Fingerprinting ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub port: u16,
    pub protocol: String,
    pub product: String,
    pub version: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<TlsCertInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_to: String,
    pub days_until_expiry: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

// ── Topology ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopoNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub ports: Vec<u16>,
    pub os: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopoEdge {
    pub source: String,
    pub target: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyResult {
    pub nodes: Vec<TopoNode>,
    pub edges: Vec<TopoEdge>,
}

// ── Application State ──────────────────────────────────────────────

pub struct AppState {
    pub data_dir: std::path::PathBuf,
}

impl AppState {
    pub fn new(data_dir: std::path::PathBuf) -> Self {
        Self { data_dir }
    }
}
