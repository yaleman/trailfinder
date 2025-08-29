use std::{fs, net::IpAddr, num::NonZeroU16, path::Path};

use serde::{Deserialize, Serialize};

use crate::{DeviceType, Owner};

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
            last_interrogated: None,
            notes: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub devices: Vec<DeviceConfig>,
    pub ssh_timeout_seconds: u64,
    pub use_ssh_agent: Option<bool>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            ssh_timeout_seconds: 30,
            use_ssh_agent: None, // Default to using ssh-agent when None
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
}
