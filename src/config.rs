//! Configuration-related things
//!
use std::collections::HashMap;
use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    fmt::Display,
    fs,
    hash::{Hash, Hasher},
    net::IpAddr,
    num::NonZeroU16,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Device, DeviceType, Owner, TrailFinderError};

fn default_ssh_port() -> NonZeroU16 {
    #[allow(clippy::expect_used)]
    NonZeroU16::new(22).expect("22 is a valid non-zero port number")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Device brand enumeration
#[derive(PartialEq)]
pub enum DeviceBrand {
    Unknown,
    Mikrotik,
    Cisco,
    Juniper,
    Ubiquiti,
    Other(String),
}

impl Display for DeviceBrand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceBrand::Unknown => write!(f, "Unknown"),
            DeviceBrand::Mikrotik => write!(f, "Mikrotik"),
            DeviceBrand::Cisco => write!(f, "Cisco"),
            DeviceBrand::Juniper => write!(f, "Juniper"),
            DeviceBrand::Ubiquiti => write!(f, "Ubiquiti"),
            DeviceBrand::Other(name) => write!(f, "Other: {}", name),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    #[serde(default = "Uuid::new_v4")]
    /// Internal device ID record
    pub device_id: Uuid,
    /// IP address or hostname to connect to (used as human-facing identifier)
    pub hostname: String,
    /// IP Address of the device (optional, if you want to use it instead)
    pub ip_address: Option<IpAddr>,
    pub brand: Option<DeviceBrand>,
    pub device_type: Option<DeviceType>,
    pub owner: Owner,
    pub ssh_username: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: NonZeroU16,
    pub ssh_key_path: Option<PathBuf>,
    pub ssh_key_passphrase: Option<String>,
    pub last_interrogated: Option<String>, // ISO 8601 timestamp
    pub notes: Option<String>,
    #[serde(skip)]
    pub resolved_ssh_key_paths: Vec<PathBuf>,
    #[serde(skip)]
    pub ssh_config: Option<ssh::SshHostConfig>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            device_id: Uuid::new_v4(),
            hostname: String::new(),
            ip_address: None,
            brand: None,
            device_type: None,
            owner: Owner::Unknown,
            ssh_username: None,
            ssh_port: default_ssh_port(),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            last_interrogated: None,
            notes: None,
            resolved_ssh_key_paths: Vec::new(),
            ssh_config: None,
        }
    }
}

impl DeviceConfig {
    /// Get the effective SSH username for this device
    /// Returns SSH config username, device config username, or system username as fallback
    pub fn get_effective_ssh_username(&self) -> Option<String> {
        // Priority order: SSH config -> device config -> system user
        self.ssh_config
            .as_ref()
            .and_then(|config| config.user.clone())
            .or_else(|| self.ssh_username.clone())
            .or_else(|| std::env::var("USER").ok())
    }

    /// Get the resolved SSH key file paths for this device
    pub fn get_resolved_ssh_key_paths(&self) -> &[PathBuf] {
        &self.resolved_ssh_key_paths
    }

    /// Check if SSH agent should be used for this device
    pub fn should_use_ssh_agent(&self) -> bool {
        // If SSH config specifies IdentitiesOnly=yes, don't use SSH agent
        !self
            .ssh_config
            .as_ref()
            .and_then(|config| config.identities_only)
            .unwrap_or(false)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceState {
    pub device: Device,
    pub timestamp: String, // ISO 8601 timestamp
    pub config_hash: u64,  // Hash of the raw configuration for change detection
}

impl DeviceState {
    pub fn new(device: Device, raw_config: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        raw_config.hash(&mut hasher);
        let config_hash = hasher.finish();

        Self {
            device,
            timestamp: chrono::Utc::now().to_rfc3339(),
            config_hash,
        }
    }

    pub fn has_config_changed(&self, raw_config: &str) -> bool {
        let mut hasher = DefaultHasher::new();
        raw_config.hash(&mut hasher);
        let new_hash = hasher.finish();
        self.config_hash != new_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Application configuration, loaded from [super::cli::DEFAULT_CONFIG_FILE] by default.
pub struct AppConfig {
    /// The devices that are polled for details
    pub devices: Vec<DeviceConfig>,
    /// SSH connection timeout in seconds, affects all devices
    pub ssh_timeout_seconds: u64,
    /// Attempt to use SSH agent authentication (flaky)
    pub use_ssh_agent: Option<bool>,
    /// Where we keep the device state files
    pub state_directory: Option<PathBuf>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            ssh_timeout_seconds: 30,
            use_ssh_agent: None, // Default to using ssh-agent when None
            state_directory: Some(PathBuf::from("states")),
        }
    }
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let mut config: AppConfig = serde_json::from_str(&content)?;

        // Validate that all devices have non-empty hostnames and unique names
        let mut seen_hostnames = HashSet::new();
        for device_config in &config.devices {
            if device_config.hostname.trim().is_empty() {
                return Err(
                    "Device has empty hostname - hostname is required for all devices".into(),
                );
            }

            // Check for duplicate hostnames
            if !seen_hostnames.insert(device_config.hostname.clone()) {
                return Err(format!(
                    "Duplicate hostname '{}' found - all device hostnames must be unique",
                    device_config.hostname
                )
                .into());
            }
        }

        // Process SSH configurations for all devices during loading
        config.process_device_ssh_configs()?;

        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), TrailFinderError> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn add_device(&mut self, device: DeviceConfig) {
        self.devices.push(device);
    }

    pub fn get_device(&self, hostname: &str) -> Option<&DeviceConfig> {
        self.devices
            .iter()
            .find(|device| device.hostname == hostname)
    }

    pub fn get_device_mut(&mut self, hostname: &str) -> Option<&mut DeviceConfig> {
        self.devices
            .iter_mut()
            .find(|device| device.hostname == hostname)
    }

    /// Remove a device from configuration by hostname
    /// Returns true if device was found and removed, false if not found
    pub fn remove_device(&mut self, hostname: &str) -> bool {
        let initial_len = self.devices.len();
        self.devices.retain(|device| device.hostname != hostname);
        self.devices.len() < initial_len
    }

    /// Remove a device and optionally its state file
    pub fn remove_device_with_state(
        &mut self,
        hostname: &str,
        delete_state: bool,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let device_removed = self.remove_device(hostname);

        if device_removed && delete_state {
            let state_file_path = self.get_state_file_path(hostname);
            if state_file_path.exists() {
                std::fs::remove_file(&state_file_path)?;
            }
        }

        Ok(device_removed)
    }

    pub fn needs_identification(&self, hostname: &str) -> bool {
        if let Some(device) = self.get_device(hostname) {
            // Need identification if brand/type is unknown or if cache expired
            if device.brand.is_none() || device.device_type.is_none() {
                return true;
            }

            // Check if cache has expired
            device.last_interrogated.is_none()
        } else {
            false
        }
    }

    pub fn needs_update(&self, hostname: &str) -> bool {
        if let Some(device) = self.get_device(hostname) {
            // Always need update if never interrogated
            let Some(last_interrogated_str) = &device.last_interrogated else {
                return true;
            };

            // Parse the last interrogated time
            match chrono::DateTime::parse_from_rfc3339(last_interrogated_str) {
                Ok(last_interrogated) => {
                    let now = chrono::Utc::now();
                    let age = now.signed_duration_since(last_interrogated);

                    // Update if more than 1 hour old (configurable in future)
                    age.num_hours() >= 1
                }
                Err(_) => {
                    // Invalid timestamp format, assume needs update
                    true
                }
            }
        } else {
            false
        }
    }

    pub fn use_ssh_agent(&self) -> bool {
        self.use_ssh_agent.unwrap_or(true) // Default to true
    }

    pub fn get_hostname_by_id(&self, device_id: Uuid) -> Option<String> {
        self.devices
            .iter()
            .find(|device| device.device_id == device_id)
            .map(|device| device.hostname.clone())
    }

    pub fn update_device_identification(
        &mut self,
        hostname: &str,
        brand: DeviceBrand,
        device_type: DeviceType,
    ) -> Result<(), TrailFinderError> {
        if let Some(device) = self.get_device_mut(hostname) {
            device.brand = Some(brand);
            device.device_type = Some(device_type);
            device.last_interrogated = Some(chrono::Utc::now().to_rfc3339());
            Ok(())
        } else {
            Err(TrailFinderError::NotFound(format!(
                "Device '{}' not found in configuration",
                hostname
            )))
        }
    }

    pub fn get_state_directory(&self) -> &Path {
        self.state_directory
            .as_deref()
            .unwrap_or_else(|| Path::new("states"))
    }

    pub fn get_state_file_path(&self, hostname: &str) -> PathBuf {
        Path::new(self.get_state_directory()).join(format!("{}.json", hostname))
    }

    pub fn load_device_state(
        &self,
        hostname: &str,
    ) -> Result<DeviceState, Box<dyn std::error::Error>> {
        let state_path = self.get_state_file_path(hostname);
        let content = fs::read_to_string(state_path)?;
        let state: DeviceState = serde_json::from_str(&content)?;
        Ok(state)
    }

    pub fn save_device_state(
        &self,
        hostname: &str,
        state: &DeviceState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state_dir = Path::new(self.get_state_directory());
        if !state_dir.exists() {
            fs::create_dir_all(state_dir)?;
        }

        let state_path = self.get_state_file_path(hostname);
        let content = serde_json::to_string_pretty(state)?;
        fs::write(state_path, content)?;
        Ok(())
    }

    pub fn load_all_device_states(
        &self,
    ) -> Result<HashMap<String, DeviceState>, Box<dyn std::error::Error>> {
        let mut device_states = HashMap::new();
        let state_dir = Path::new(self.get_state_directory());

        if !state_dir.exists() {
            return Ok(device_states); // Return empty map if directory doesn't exist
        }

        // Iterate through all devices and try to load their states
        for device in &self.devices {
            match self.load_device_state(&device.hostname) {
                Ok(state) => {
                    device_states.insert(device.hostname.clone(), state);
                }
                Err(e) => {
                    // Log but don't fail if we can't load one device state
                    tracing::debug!("Could not load device state for {}: {}", device.hostname, e);
                }
            }
        }

        Ok(device_states)
    }

    pub fn has_state_file(&self, hostname: &str) -> bool {
        self.get_state_file_path(hostname).exists()
    }

    /// Process SSH configurations for all devices during config loading
    /// This resolves paths and deduplicates SSH keys, and loads SSH config
    fn process_device_ssh_configs(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Load SSH config once
        let ssh_config = Self::load_ssh_config()?;

        for device_config in &mut self.devices {
            // Get SSH host configuration for this device
            device_config.ssh_config = ssh_config.get_host_config(&device_config.hostname);

            // Collect all SSH key paths from various sources
            let mut ssh_key_paths = Vec::new();

            // Add key from device config
            if let Some(key_path) = &device_config.ssh_key_path {
                ssh_key_paths.push(PathBuf::from(key_path));
            }

            // Add keys from SSH config
            if let Some(ssh_host_config) = &device_config.ssh_config {
                ssh_key_paths.extend(ssh_host_config.get_identity_files());
            }

            // Resolve full paths and deduplicate
            device_config.resolved_ssh_key_paths =
                Self::resolve_and_deduplicate_key_paths(ssh_key_paths)?;
        }

        Ok(())
    }

    /// Load SSH configuration using our custom parser
    fn load_ssh_config() -> Result<ssh::SshConfig, Box<dyn std::error::Error>> {
        use ssh::SshConfig;

        let ssh_config_path = if let Some(home_dir) = dirs::home_dir() {
            home_dir.join(".ssh").join("config")
        } else {
            return Ok(SshConfig::default()); // Return empty config if no home dir
        };

        if !ssh_config_path.exists() {
            return Ok(SshConfig::default()); // Return empty config if file doesn't exist
        }

        SshConfig::parse_file(&ssh_config_path)
            .map_err(|e| format!("Failed to parse SSH config: {}", e).into())
    }

    /// Resolve full paths and deduplicate SSH key files
    fn resolve_and_deduplicate_key_paths(
        key_paths: Vec<PathBuf>,
    ) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        let mut resolved_paths = Vec::new();
        let mut seen_paths = HashSet::new();

        for key_path in key_paths {
            // Expand tilde and resolve to absolute path
            let key_path_str = key_path.to_string_lossy();
            let expanded_path = shellexpand::tilde(&key_path_str);
            let absolute_path = Path::new(expanded_path.as_ref()).to_path_buf();

            // Canonicalize the path to resolve any symlinks and get the real path
            let canonical_path = match absolute_path.canonicalize() {
                Ok(path) => path,
                Err(_) => {
                    // If canonicalization fails (e.g., file doesn't exist), use the absolute path
                    absolute_path
                }
            };

            // Only add if we haven't seen this path before
            if seen_paths.insert(canonical_path.clone()) {
                resolved_paths.push(canonical_path);
            }
        }

        Ok(resolved_paths)
    }
}

/// SSH configuration parsing module
pub mod ssh {
    use crate::TrailFinderError;
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };

    #[derive(Debug, Clone, PartialEq)]
    pub struct SshHostConfig {
        pub hostname: String,
        pub user: Option<String>,
        pub port: Option<u16>,
        pub identity_files: Vec<PathBuf>,
        pub identities_only: Option<bool>,
    }

    impl SshHostConfig {
        fn new(hostname: String) -> Self {
            Self {
                hostname,
                user: None,
                port: None,
                identity_files: Vec::new(),
                identities_only: None,
            }
        }

        /// Apply variable substitution for SSH config tokens
        /// Supports %h (hostname) and %p (port)
        fn substitute_variables(&self, value: &str) -> String {
            value
                .replace("%h", &self.hostname)
                .replace("%p", &self.port.unwrap_or(22).to_string())
        }

        /// Get the identity files with variable substitution applied
        pub fn get_identity_files(&self) -> Vec<PathBuf> {
            self.identity_files
                .iter()
                .map(|path| {
                    let path_str = path.to_string_lossy();
                    let substituted = self.substitute_variables(&path_str);
                    PathBuf::from(shellexpand::tilde(&substituted).to_string())
                })
                .collect()
        }
    }

    #[derive(Debug, Default)]
    pub struct SshConfig {
        hosts: HashMap<String, SshHostConfig>,
    }

    impl SshConfig {
        /// Parse SSH config from a string
        pub fn parse(content: &str) -> Result<Self, TrailFinderError> {
            let mut config = SshConfig::default();
            let mut current_host: Option<SshHostConfig> = None;

            for line in content.lines() {
                let line = line.trim();

                // Skip empty lines and comments
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    continue;
                }

                let directive = parts[0].to_lowercase();
                let value = parts[1].trim();

                match directive.as_str() {
                    "host" => {
                        // Save the previous host config if it exists
                        if let Some(host_config) = current_host.take() {
                            config
                                .hosts
                                .insert(host_config.hostname.clone(), host_config);
                        }

                        // Start a new host config
                        current_host = Some(SshHostConfig::new(value.to_string()));
                    }
                    "user" => {
                        if let Some(ref mut host_config) = current_host {
                            host_config.user = Some(value.to_string());
                        }
                    }
                    "port" => {
                        if let Some(ref mut host_config) = current_host
                            && let Ok(port) = value.parse::<u16>()
                        {
                            host_config.port = Some(port);
                        }
                    }
                    "identityfile" => {
                        if let Some(ref mut host_config) = current_host {
                            host_config.identity_files.push(PathBuf::from(value));
                        }
                    }
                    "identitiesonly" => {
                        if let Some(ref mut host_config) = current_host {
                            host_config.identities_only = Some(
                                value.to_lowercase() == "yes" || value.to_lowercase() == "true",
                            );
                        }
                    }
                    _ => {
                        // Ignore unknown directives
                    }
                }
            }

            // Don't forget to save the last host config
            if let Some(host_config) = current_host {
                config
                    .hosts
                    .insert(host_config.hostname.clone(), host_config);
            }

            Ok(config)
        }

        /// Parse SSH config from a file
        pub fn parse_file<P: AsRef<Path>>(path: P) -> Result<Self, TrailFinderError> {
            let content = std::fs::read_to_string(path)?;
            Self::parse(&content)
        }

        /// Get configuration for a specific host
        /// This will merge configurations from matching patterns, with more specific patterns taking precedence
        pub fn get_host_config(&self, hostname: &str) -> Option<SshHostConfig> {
            let mut result_config = SshHostConfig::new(hostname.to_string());
            let mut found_any_match = false;

            // Collect all matching patterns with their specificity scores
            let mut matches: Vec<(&str, &SshHostConfig, usize)> = Vec::new();

            for (pattern, config) in &self.hosts {
                if pattern == hostname {
                    // Exact match has highest priority
                    matches.push((pattern, config, 1000));
                } else if pattern == "*" {
                    // Wildcard matches everything but has lowest priority
                    matches.push((pattern, config, 0));
                } else if pattern.contains('*') {
                    // Simple wildcard matching (only supports * at the end for now)
                    if let Some(prefix) = pattern.strip_suffix('*')
                        && hostname.starts_with(prefix)
                    {
                        matches.push((pattern, config, prefix.len()));
                    }
                }
            }

            if matches.is_empty() {
                return None;
            }

            // Sort by specificity (lowest first, so we apply in order of increasing precedence)
            matches.sort_by_key(|(_, _, specificity)| *specificity);

            // Apply configurations in order of increasing specificity
            for (_, config, _) in matches {
                found_any_match = true;

                // Merge configuration values, with later (more specific) configs taking precedence
                if config.user.is_some() {
                    result_config.user = config.user.clone();
                }
                if config.port.is_some() {
                    result_config.port = config.port;
                }
                if config.identities_only.is_some() {
                    result_config.identities_only = config.identities_only;
                }

                // For identity files, we append them (SSH tries multiple keys)
                for identity_file in &config.identity_files {
                    if !result_config.identity_files.contains(identity_file) {
                        result_config.identity_files.push(identity_file.clone());
                    }
                }
            }

            if found_any_match {
                Some(result_config)
            } else {
                None
            }
        }

        /// Get all host patterns in the config
        pub fn get_host_patterns(&self) -> Vec<String> {
            self.hosts.keys().cloned().collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ssh::*;

    #[test]
    fn test_ssh_config_parsing() {
        let config_content = r#"
Host example.com
    User exampleuser

Host *
	IdentityFile ~/.ssh/%h
"#;

        let config = SshConfig::parse(config_content).expect("Should parse SSH config");

        // Test exact match
        let example_config = config
            .get_host_config("example.com")
            .expect("Should find example.com config");
        assert_eq!(example_config.user, Some("exampleuser".to_string()));
        assert_eq!(
            example_config.get_identity_files(),
            vec![PathBuf::from(
                shellexpand::tilde("~/.ssh/example.com").to_string()
            )]
        );

        // Test wildcard match
        let other_config = config
            .get_host_config("other.com")
            .expect("Should match wildcard config");
        assert_eq!(
            other_config.get_identity_files(),
            vec![PathBuf::from(
                shellexpand::tilde("~/.ssh/other.com").to_string()
            )]
        );
    }

    #[test]
    fn test_variable_substitution() {
        let host_config = SshHostConfig {
            hostname: "example.com".to_string(),
            user: None,
            port: None,
            identity_files: vec![PathBuf::from("~/.ssh/%h")],
            identities_only: None,
        };

        let identity_files = host_config.get_identity_files();
        assert_eq!(
            identity_files,
            vec![PathBuf::from(
                shellexpand::tilde("~/.ssh/example.com").to_string()
            )]
        );
    }

    #[test]
    fn test_test_ssh_config_file() {
        // Test parsing the actual test file
        let config = SshConfig::parse_file("src/tests/test_ssh_config.txt")
            .expect("Should parse test SSH config file");

        // Test example.com (exact match with user "exampleuser", inherits IdentityFile from wildcard)
        let example_config = config
            .get_host_config("example.com")
            .expect("Should find example.com config");
        assert_eq!(example_config.user, Some("exampleuser".to_string()));
        assert_eq!(
            example_config.get_identity_files(),
            vec![PathBuf::from(
                shellexpand::tilde("~/.ssh/example.com").to_string()
            )]
        );

        // Test example2.com (exact match but no user specified, should inherit user "foo" from wildcard)
        let example2_config = config
            .get_host_config("example2.com")
            .expect("Should find example2.com config");
        assert_eq!(example2_config.user, Some("foo".to_string()));
        assert_eq!(
            example2_config.get_identity_files(),
            vec![PathBuf::from(
                shellexpand::tilde("~/.ssh/example2.com").to_string()
            )]
        );

        // Test a random hostname (should match wildcard pattern only)
        let random_config = config
            .get_host_config("random.com")
            .expect("Should match wildcard config");
        assert_eq!(random_config.user, Some("foo".to_string()));
        assert_eq!(
            random_config.get_identity_files(),
            vec![PathBuf::from(
                shellexpand::tilde("~/.ssh/random.com").to_string()
            )]
        );
    }

    #[test]
    fn test_app_config_remove_device() {
        use crate::config::{AppConfig, DeviceBrand, DeviceConfig};
        use crate::{DeviceType, Owner};
        use uuid::Uuid;

        let mut app_config = AppConfig::default();

        // Add test devices
        let device1 = DeviceConfig {
            device_id: Uuid::new_v4(),
            hostname: "device1.example.com".to_string(),
            ip_address: None,
            brand: Some(DeviceBrand::Mikrotik),
            device_type: Some(DeviceType::Router),
            owner: Owner::Unknown,
            ssh_username: None,
            ssh_port: std::num::NonZeroU16::new(22).unwrap(),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            resolved_ssh_key_paths: Vec::new(),
            ssh_config: None,
            last_interrogated: None,
            notes: None,
        };

        let device2 = DeviceConfig {
            device_id: Uuid::new_v4(),
            hostname: "device2.example.com".to_string(),
            ip_address: None,
            brand: Some(DeviceBrand::Cisco),
            device_type: Some(DeviceType::Switch),
            owner: Owner::Unknown,
            ssh_username: None,
            ssh_port: std::num::NonZeroU16::new(22).unwrap(),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            resolved_ssh_key_paths: Vec::new(),
            ssh_config: None,
            last_interrogated: None,
            notes: None,
        };

        app_config.add_device(device1);
        app_config.add_device(device2);

        assert_eq!(app_config.devices.len(), 2);

        // Test successful removal
        let removed = app_config.remove_device("device1.example.com");
        assert!(removed);
        assert_eq!(app_config.devices.len(), 1);
        assert_eq!(app_config.devices[0].hostname, "device2.example.com");

        // Test removal of non-existent device
        let removed = app_config.remove_device("nonexistent.example.com");
        assert!(!removed);
        assert_eq!(app_config.devices.len(), 1);

        // Test removal of last device
        let removed = app_config.remove_device("device2.example.com");
        assert!(removed);
        assert_eq!(app_config.devices.len(), 0);
    }
}
