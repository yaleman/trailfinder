use std::{
    collections::hash_map::DefaultHasher,
    fmt::Display,
    fs,
    hash::{Hash, Hasher},
    net::IpAddr,
    num::NonZeroU16,
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{Device, DeviceType, Owner};

fn default_ssh_port() -> NonZeroU16 {
    NonZeroU16::new(22).expect("22 is a valid non-zero port number")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub hostname: String,
    pub ip_address: Option<IpAddr>,
    pub brand: Option<DeviceBrand>,
    pub device_type: Option<DeviceType>,
    pub owner: Owner,
    pub ssh_username: Option<String>,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: NonZeroU16,
    pub ssh_key_path: Option<String>,
    pub ssh_key_passphrase: Option<String>,
    pub last_interrogated: Option<String>, // ISO 8601 timestamp
    pub notes: Option<String>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
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
        }
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub devices: Vec<DeviceConfig>,
    pub ssh_timeout_seconds: u64,
    pub use_ssh_agent: Option<bool>,
    pub state_directory: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            ssh_timeout_seconds: 30,
            use_ssh_agent: None, // Default to using ssh-agent when None
            state_directory: Some("states".to_string()),
        }
    }
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: AppConfig = serde_json::from_str(&content)?;

        // Validate that all devices have non-empty hostnames and unique names
        let mut seen_hostnames = std::collections::HashSet::new();
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

        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn update_device_identification(
        &mut self,
        hostname: &str,
        brand: DeviceBrand,
        device_type: DeviceType,
    ) -> Result<(), String> {
        if let Some(device) = self.get_device_mut(hostname) {
            device.brand = Some(brand);
            device.device_type = Some(device_type);
            device.last_interrogated = Some(chrono::Utc::now().to_rfc3339());
            Ok(())
        } else {
            Err(format!("Device '{}' not found in configuration", hostname))
        }
    }

    pub fn get_state_directory(&self) -> &str {
        self.state_directory.as_deref().unwrap_or("states")
    }

    pub fn get_state_file_path(&self, hostname: &str) -> std::path::PathBuf {
        std::path::Path::new(self.get_state_directory()).join(format!("{}.json", hostname))
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
        let state_dir = std::path::Path::new(self.get_state_directory());
        if !state_dir.exists() {
            fs::create_dir_all(state_dir)?;
        }

        let state_path = self.get_state_file_path(hostname);
        let content = serde_json::to_string_pretty(state)?;
        fs::write(state_path, content)?;
        Ok(())
    }

    pub fn has_state_file(&self, hostname: &str) -> bool {
        self.get_state_file_path(hostname).exists()
    }

    pub fn needs_state_update(
        &self,
        hostname: &str,
        raw_config: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if !self.has_state_file(hostname) {
            return Ok(true); // No state file, definitely need to create one
        }

        match self.load_device_state(hostname) {
            Ok(state) => Ok(state.has_config_changed(raw_config)),
            Err(_) => Ok(true), // Error loading state, assume we need update
        }
    }
}
