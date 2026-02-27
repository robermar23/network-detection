use crate::models::{Profile, ERR_INVALID_PARAMS, ERR_PROFILE_NOT_FOUND};
use regex::Regex;
use std::fs;
use std::path::PathBuf;

pub struct ProfileManager {
    profiles_dir: PathBuf,
}

impl ProfileManager {
    pub fn new(data_dir: &PathBuf) -> Self {
        let profiles_dir = data_dir.join("profiles");
        fs::create_dir_all(&profiles_dir).ok();
        Self { profiles_dir }
    }

    fn profile_path(&self, name: &str) -> PathBuf {
        self.profiles_dir.join(format!("{}.json", name))
    }

    pub fn list(&self) -> Result<Vec<Profile>, (i32, String)> {
        let mut profiles = Vec::new();

        let entries = fs::read_dir(&self.profiles_dir).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to read profiles directory: {}", e))
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
                        if let Ok(profile) = serde_json::from_str::<Profile>(&content) {
                            profiles.push(profile);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        profiles.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(profiles)
    }

    pub fn get(&self, name: &str) -> Result<Profile, (i32, String)> {
        let path = self.profile_path(name);
        if !path.exists() {
            return Err((ERR_PROFILE_NOT_FOUND, format!("Profile '{}' not found", name)));
        }

        let content = fs::read_to_string(&path).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to read profile: {}", e))
        })?;

        serde_json::from_str::<Profile>(&content).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to parse profile: {}", e))
        })
    }

    pub fn create(&self, mut profile: Profile) -> Result<Profile, (i32, String)> {
        self.validate(&profile)?;

        let path = self.profile_path(&profile.name);
        if path.exists() {
            return Err((ERR_INVALID_PARAMS, format!("Profile '{}' already exists", profile.name)));
        }

        // Enforce safe mode constraints
        if profile.safe_mode {
            enforce_safe_mode(&mut profile);
        }

        let content = serde_json::to_string_pretty(&profile).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to serialize profile: {}", e))
        })?;

        fs::write(&path, content).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to write profile: {}", e))
        })?;

        Ok(profile)
    }

    pub fn update(&self, name: &str, mut profile: Profile) -> Result<Profile, (i32, String)> {
        let old_path = self.profile_path(name);
        if !old_path.exists() {
            return Err((ERR_PROFILE_NOT_FOUND, format!("Profile '{}' not found", name)));
        }

        self.validate(&profile)?;

        // Enforce safe mode constraints
        if profile.safe_mode {
            enforce_safe_mode(&mut profile);
        }

        // If name changed, remove old file
        if profile.name != name {
            let new_path = self.profile_path(&profile.name);
            if new_path.exists() {
                return Err((ERR_INVALID_PARAMS, format!("Profile '{}' already exists", profile.name)));
            }
            fs::remove_file(&old_path).ok();
        }

        let content = serde_json::to_string_pretty(&profile).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to serialize profile: {}", e))
        })?;

        let path = self.profile_path(&profile.name);
        fs::write(&path, content).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to write profile: {}", e))
        })?;

        Ok(profile)
    }

    pub fn delete(&self, name: &str) -> Result<(), (i32, String)> {
        let path = self.profile_path(name);
        if !path.exists() {
            return Err((ERR_PROFILE_NOT_FOUND, format!("Profile '{}' not found", name)));
        }

        fs::remove_file(&path).map_err(|e| {
            (crate::models::ERR_INTERNAL, format!("Failed to delete profile: {}", e))
        })?;

        Ok(())
    }

    pub fn validate(&self, profile: &Profile) -> Result<Vec<String>, (i32, String)> {
        let mut errors = Vec::new();

        // Name validation
        if profile.name.is_empty() {
            errors.push("Name cannot be empty".to_string());
        } else if profile.name.len() > 64 {
            errors.push("Name must be 64 characters or less".to_string());
        } else {
            let name_re = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\-_ ]*$").unwrap();
            if !name_re.is_match(&profile.name) {
                errors.push("Name must start with alphanumeric and contain only alphanumeric, hyphens, underscores, and spaces".to_string());
            }
        }

        // Port range validation
        if profile.port_range.is_empty() {
            errors.push("Port range cannot be empty".to_string());
        } else if !validate_port_range(&profile.port_range) {
            errors.push("Invalid port range format. Use: single port (80), range (1-1024), or comma-separated (21,22,80,443)".to_string());
        }

        // Timeout validation
        if profile.timeout < 100 || profile.timeout > 60000 {
            errors.push("Timeout must be between 100 and 60000 milliseconds".to_string());
        }

        // Chunk size validation
        if profile.chunk_size < 1 || profile.chunk_size > 500 {
            errors.push("Chunk size must be between 1 and 500".to_string());
        }

        if !errors.is_empty() {
            return Err((ERR_INVALID_PARAMS, errors.join("; ")));
        }

        Ok(errors)
    }
}

fn validate_port_range(range: &str) -> bool {
    let port_re = Regex::new(r"^(\d{1,5}(-\d{1,5})?)(,\s*\d{1,5}(-\d{1,5})?)*$").unwrap();
    if !port_re.is_match(range) {
        return false;
    }

    // Validate individual port numbers are within bounds
    for segment in range.split(',') {
        let segment = segment.trim();
        let parts: Vec<&str> = segment.split('-').collect();
        for part in &parts {
            if let Ok(port) = part.parse::<u32>() {
                if port < 1 || port > 65535 {
                    return false;
                }
            } else {
                return false;
            }
        }
        // Validate range order
        if parts.len() == 2 {
            let start: u32 = parts[0].parse().unwrap_or(0);
            let end: u32 = parts[1].parse().unwrap_or(0);
            if start > end {
                return false;
            }
        }
    }
    true
}

fn enforce_safe_mode(profile: &mut Profile) {
    if profile.chunk_size > 50 {
        profile.chunk_size = 50;
    }
    if profile.timeout < 1000 {
        profile.timeout = 1000;
    }
    // Disable intrusive modules in safe mode
    profile.security_audit = false;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (ProfileManager, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mgr = ProfileManager::new(&tmp.path().to_path_buf());
        (mgr, tmp)
    }

    fn sample_profile() -> Profile {
        Profile {
            name: "test-profile".to_string(),
            port_range: "1-1024".to_string(),
            timeout: 2000,
            chunk_size: 100,
            banner_grab: true,
            tls_inspect: true,
            security_audit: true,
            safe_mode: false,
            description: "A test profile".to_string(),
        }
    }

    #[test]
    fn test_create_and_get() {
        let (mgr, _tmp) = setup();
        let profile = sample_profile();
        let created = mgr.create(profile.clone()).unwrap();
        assert_eq!(created.name, "test-profile");

        let fetched = mgr.get("test-profile").unwrap();
        assert_eq!(fetched.port_range, "1-1024");
    }

    #[test]
    fn test_list() {
        let (mgr, _tmp) = setup();
        mgr.create(sample_profile()).unwrap();

        let mut p2 = sample_profile();
        p2.name = "another-profile".to_string();
        mgr.create(p2).unwrap();

        let profiles = mgr.list().unwrap();
        assert_eq!(profiles.len(), 2);
        // Should be sorted alphabetically
        assert_eq!(profiles[0].name, "another-profile");
        assert_eq!(profiles[1].name, "test-profile");
    }

    #[test]
    fn test_update() {
        let (mgr, _tmp) = setup();
        mgr.create(sample_profile()).unwrap();

        let mut updated = sample_profile();
        updated.port_range = "1-65535".to_string();
        let result = mgr.update("test-profile", updated).unwrap();
        assert_eq!(result.port_range, "1-65535");

        let fetched = mgr.get("test-profile").unwrap();
        assert_eq!(fetched.port_range, "1-65535");
    }

    #[test]
    fn test_delete() {
        let (mgr, _tmp) = setup();
        mgr.create(sample_profile()).unwrap();
        mgr.delete("test-profile").unwrap();

        let result = mgr.get("test-profile");
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_name() {
        let (mgr, _tmp) = setup();
        mgr.create(sample_profile()).unwrap();
        let result = mgr.create(sample_profile());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_empty_name() {
        let (mgr, _tmp) = setup();
        let mut p = sample_profile();
        p.name = "".to_string();
        let result = mgr.validate(&p);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bad_port_range() {
        let (mgr, _tmp) = setup();
        let mut p = sample_profile();
        p.port_range = "abc".to_string();
        let result = mgr.validate(&p);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_port_out_of_bounds() {
        let (mgr, _tmp) = setup();
        let mut p = sample_profile();
        p.port_range = "0-70000".to_string();
        let result = mgr.validate(&p);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_mode_enforcement() {
        let (mgr, _tmp) = setup();
        let mut p = sample_profile();
        p.safe_mode = true;
        p.chunk_size = 200;
        p.timeout = 500;
        p.security_audit = true;

        let created = mgr.create(p).unwrap();
        assert_eq!(created.chunk_size, 50);
        assert_eq!(created.timeout, 1000);
        assert!(!created.security_audit);
    }

    #[test]
    fn test_validate_port_range_formats() {
        assert!(validate_port_range("80"));
        assert!(validate_port_range("1-1024"));
        assert!(validate_port_range("21,22,80,443"));
        assert!(validate_port_range("1-1024,8080,8443"));
        assert!(!validate_port_range(""));
        assert!(!validate_port_range("abc"));
        assert!(!validate_port_range("1024-1")); // reversed range
        assert!(!validate_port_range("99999")); // out of bounds
    }

    #[test]
    fn test_get_not_found() {
        let (mgr, _tmp) = setup();
        let result = mgr.get("nonexistent");
        assert!(result.is_err());
        let (code, _) = result.unwrap_err();
        assert_eq!(code, ERR_PROFILE_NOT_FOUND);
    }
}
