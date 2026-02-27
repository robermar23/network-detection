use crate::models::{Baseline, BaselineMeta, Host, ERR_BASELINE_NOT_FOUND};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

pub struct BaselineManager {
    baselines_dir: PathBuf,
}

impl BaselineManager {
    pub fn new(data_dir: &PathBuf) -> Self {
        let baselines_dir = data_dir.join("baselines");
        fs::create_dir_all(&baselines_dir).ok();
        Self { baselines_dir }
    }

    fn baseline_path(&self, id: &str) -> PathBuf {
        self.baselines_dir.join(format!("{}.json", id))
    }

    pub fn create_snapshot(&self, hosts: Vec<Host>, label: Option<String>) -> Result<BaselineMeta, (i32, String)> {
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().to_rfc3339();
        let host_count = hosts.len();
        let label = label.unwrap_or_else(|| format!("Baseline {}", &id[..8]));

        let meta = BaselineMeta {
            id: id.clone(),
            label,
            timestamp,
            host_count,
        };

        let baseline = Baseline {
            meta: meta.clone(),
            hosts,
        };

        let content = serde_json::to_string_pretty(&baseline).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to serialize baseline: {}", e))
        })?;

        fs::write(self.baseline_path(&id), content).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to write baseline: {}", e))
        })?;

        Ok(meta)
    }

    pub fn list(&self) -> Result<Vec<BaselineMeta>, (i32, String)> {
        let mut baselines = Vec::new();

        let entries = fs::read_dir(&self.baselines_dir).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to read baselines directory: {}", e))
        })?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        if let Ok(baseline) = serde_json::from_str::<Baseline>(&content) {
                            baselines.push(baseline.meta);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // Sort by timestamp descending (newest first)
        baselines.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(baselines)
    }

    pub fn get(&self, id: &str) -> Result<Baseline, (i32, String)> {
        let path = self.baseline_path(id);
        if !path.exists() {
            return Err((ERR_BASELINE_NOT_FOUND, format!("Baseline '{}' not found", id)));
        }

        let content = fs::read_to_string(&path).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to read baseline: {}", e))
        })?;

        serde_json::from_str::<Baseline>(&content).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to parse baseline: {}", e))
        })
    }

    pub fn delete(&self, id: &str) -> Result<(), (i32, String)> {
        let path = self.baseline_path(id);
        if !path.exists() {
            return Err((ERR_BASELINE_NOT_FOUND, format!("Baseline '{}' not found", id)));
        }

        fs::remove_file(&path).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to delete baseline: {}", e))
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (BaselineManager, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(&tmp.path().to_path_buf());
        (mgr, tmp)
    }

    fn sample_hosts() -> Vec<Host> {
        vec![
            Host {
                ip: "192.168.1.1".to_string(),
                mac: "AA:BB:CC:DD:EE:FF".to_string(),
                hostname: "router.local".to_string(),
                vendor: "Cisco".to_string(),
                os: "Linux".to_string(),
                ports: vec![22, 80, 443],
            },
            Host {
                ip: "192.168.1.50".to_string(),
                mac: "11:22:33:44:55:66".to_string(),
                hostname: "desktop.local".to_string(),
                vendor: "Intel".to_string(),
                os: "Windows".to_string(),
                ports: vec![135, 445, 3389],
            },
        ]
    }

    #[test]
    fn test_create_snapshot() {
        let (mgr, _tmp) = setup();
        let meta = mgr.create_snapshot(sample_hosts(), Some("Test baseline".to_string())).unwrap();
        assert_eq!(meta.host_count, 2);
        assert_eq!(meta.label, "Test baseline");
        assert!(!meta.id.is_empty());
    }

    #[test]
    fn test_create_snapshot_default_label() {
        let (mgr, _tmp) = setup();
        let meta = mgr.create_snapshot(sample_hosts(), None).unwrap();
        assert!(meta.label.starts_with("Baseline "));
    }

    #[test]
    fn test_list() {
        let (mgr, _tmp) = setup();
        mgr.create_snapshot(sample_hosts(), Some("First".to_string())).unwrap();
        mgr.create_snapshot(sample_hosts(), Some("Second".to_string())).unwrap();

        let list = mgr.list().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_get() {
        let (mgr, _tmp) = setup();
        let meta = mgr.create_snapshot(sample_hosts(), None).unwrap();
        let baseline = mgr.get(&meta.id).unwrap();
        assert_eq!(baseline.hosts.len(), 2);
        assert_eq!(baseline.meta.id, meta.id);
    }

    #[test]
    fn test_delete() {
        let (mgr, _tmp) = setup();
        let meta = mgr.create_snapshot(sample_hosts(), None).unwrap();
        mgr.delete(&meta.id).unwrap();
        assert!(mgr.get(&meta.id).is_err());
    }

    #[test]
    fn test_get_not_found() {
        let (mgr, _tmp) = setup();
        let result = mgr.get("nonexistent-id");
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, ERR_BASELINE_NOT_FOUND);
    }
}
