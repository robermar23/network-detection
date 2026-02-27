mod models;
mod profiles;
mod baseline;
mod diff;
mod fingerprint;
mod topology;

use models::*;
use profiles::ProfileManager;
use baseline::BaselineManager;
use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn main() {
    let data_dir = parse_data_dir();

    let profile_mgr = ProfileManager::new(&data_dir);
    let baseline_mgr = BaselineManager::new(&data_dir);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        match line {
            Ok(input) => {
                let input = input.trim().to_string();
                if input.is_empty() {
                    continue;
                }

                let response = handle_request(&input, &profile_mgr, &baseline_mgr);
                if writeln!(stdout_lock, "{}", response).is_err() {
                    break;
                }
                if stdout_lock.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn parse_data_dir() -> PathBuf {
    let args: Vec<String> = env::args().collect();
    for i in 0..args.len() {
        if args[i] == "--data-dir" {
            if let Some(dir) = args.get(i + 1) {
                let path = PathBuf::from(dir);
                std::fs::create_dir_all(&path).ok();
                return path;
            }
        }
    }
    // Default to current directory
    let default = PathBuf::from("./netspectre-data");
    std::fs::create_dir_all(&default).ok();
    default
}

fn handle_request(
    input: &str,
    profile_mgr: &ProfileManager,
    baseline_mgr: &BaselineManager,
) -> String {
    // Parse JSON-RPC request
    let req: JsonRpcRequest = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(e) => {
            return error_response(0, ERR_PARSE, &format!("Parse error: {}", e));
        }
    };

    let id = req.id;
    let result = dispatch(&req.method, req.params, profile_mgr, baseline_mgr);

    match result {
        Ok(value) => success_response(id, value),
        Err((code, msg)) => error_response(id, code, &msg),
    }
}

fn dispatch(
    method: &str,
    params: serde_json::Value,
    profile_mgr: &ProfileManager,
    baseline_mgr: &BaselineManager,
) -> Result<serde_json::Value, (i32, String)> {
    match method {
        // ── Profiles ───────────────────────────────────────────
        "profiles.list" => {
            let profiles = profile_mgr.list()?;
            Ok(serde_json::json!({ "profiles": profiles }))
        }
        "profiles.get" => {
            let name = extract_string(&params, "name")?;
            let profile = profile_mgr.get(&name)?;
            Ok(serde_json::json!({ "profile": profile }))
        }
        "profiles.create" => {
            let profile: Profile = extract_param(&params, "profile")?;
            let created = profile_mgr.create(profile)?;
            Ok(serde_json::json!({ "profile": created }))
        }
        "profiles.update" => {
            let name = extract_string(&params, "name")?;
            let profile: Profile = extract_param(&params, "profile")?;
            let updated = profile_mgr.update(&name, profile)?;
            Ok(serde_json::json!({ "profile": updated }))
        }
        "profiles.delete" => {
            let name = extract_string(&params, "name")?;
            profile_mgr.delete(&name)?;
            Ok(serde_json::json!({ "deleted": true }))
        }
        "profiles.validate" => {
            let profile: Profile = extract_param(&params, "profile")?;
            match profile_mgr.validate(&profile) {
                Ok(_) => Ok(serde_json::json!({ "valid": true, "errors": [] as [String; 0] })),
                Err((_, msg)) => Ok(serde_json::json!({ "valid": false, "errors": [msg] })),
            }
        }

        // ── Baseline ───────────────────────────────────────────
        "baseline.createSnapshot" => {
            let hosts: Vec<Host> = extract_param(&params, "hosts")?;
            let label = params.get("label").and_then(|v| v.as_str()).map(|s| s.to_string());
            let meta = baseline_mgr.create_snapshot(hosts, label)?;
            Ok(serde_json::to_value(meta).unwrap())
        }
        "baseline.listSnapshots" => {
            let list = baseline_mgr.list()?;
            Ok(serde_json::json!({ "baselines": list }))
        }
        "baseline.getSnapshot" => {
            let id = extract_string(&params, "id")?;
            let baseline = baseline_mgr.get(&id)?;
            Ok(serde_json::json!({ "baseline": baseline }))
        }
        "baseline.delete" => {
            let id = extract_string(&params, "id")?;
            baseline_mgr.delete(&id)?;
            Ok(serde_json::json!({ "deleted": true }))
        }
        "baseline.diff" => {
            let baseline_id = extract_string(&params, "baselineId")?;
            let current_hosts: Vec<Host> = extract_param(&params, "currentHosts")?;
            let baseline = baseline_mgr.get(&baseline_id)?;
            let result = diff::compute_diff(&baseline, &current_hosts);
            Ok(serde_json::to_value(result).unwrap())
        }

        // ── Fingerprint ────────────────────────────────────────
        "fingerprint.analyze" => {
            let host: Host = extract_param(&params, "host")?;
            let ports: Vec<DeepScanPort> = extract_param(&params, "ports")?;
            let fingerprints = fingerprint::analyze(&host, &ports);
            Ok(serde_json::json!({ "fingerprints": fingerprints }))
        }

        // ── Topology ───────────────────────────────────────────
        "topology.build" => {
            let hosts: Vec<Host> = extract_param(&params, "hosts")?;
            let result = topology::build(&hosts);
            Ok(serde_json::to_value(result).unwrap())
        }

        _ => Err((ERR_METHOD_NOT_FOUND, format!("Method '{}' not found", method))),
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn extract_string(params: &serde_json::Value, key: &str) -> Result<String, (i32, String)> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or((ERR_INVALID_PARAMS, format!("Missing required parameter: {}", key)))
}

fn extract_param<T: serde::de::DeserializeOwned>(
    params: &serde_json::Value,
    key: &str,
) -> Result<T, (i32, String)> {
    let value = params
        .get(key)
        .ok_or((ERR_INVALID_PARAMS, format!("Missing required parameter: {}", key)))?;
    serde_json::from_value(value.clone())
        .map_err(|e| (ERR_INVALID_PARAMS, format!("Invalid parameter '{}': {}", key, e)))
}

fn success_response(id: u64, result: serde_json::Value) -> String {
    serde_json::to_string(&JsonRpcSuccessResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result,
    })
    .unwrap_or_else(|_| error_response(id, ERR_INTERNAL, "Failed to serialize response"))
}

fn error_response(id: u64, code: i32, message: &str) -> String {
    serde_json::to_string(&JsonRpcErrorResponse {
        jsonrpc: "2.0".to_string(),
        id,
        error: JsonRpcError {
            code,
            message: message.to_string(),
            data: None,
        },
    })
    .unwrap_or_else(|_| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":{},"message":"{}"}}}}"#,
            id, code, message
        )
    })
}
