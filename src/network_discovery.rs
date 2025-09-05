//! Network discovery functionality for scanning IP ranges and discovering devices

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use cidr::IpCidr;
use tokio::{net::TcpStream, time::timeout};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    DeviceType, TrailFinderError,
    config::{DeviceBrand, DeviceConfig},
    ssh::{DeviceIdentifier, SshClient},
};

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub ip_address: IpAddr,
    pub hostname: Option<String>,
    pub brand: Option<DeviceBrand>,
    pub device_type: Option<DeviceType>,
    pub ssh_responsive: bool,
    pub identification_successful: bool,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub port: u16,
    pub timeout_seconds: u64,
    pub username: Option<String>,
    pub keyfile: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            port: 22,
            timeout_seconds: 5,
            username: None,
            keyfile: None,
        }
    }
}

/// Parse target strings (IP addresses or CIDR networks) into individual IP addresses
pub fn parse_scan_targets(targets: &[String]) -> Result<Vec<IpAddr>, TrailFinderError> {
    let mut ip_addresses = Vec::new();

    for target in targets {
        if let Ok(cidr) = target.parse::<IpCidr>() {
            // CIDR network - expand to individual IPs
            let hosts: Vec<IpAddr> = cidr.iter().map(|ip_inet| ip_inet.address()).collect();
            info!("Expanded CIDR {} to {} addresses", target, hosts.len());

            // Limit to reasonable number of hosts to avoid resource exhaustion
            if hosts.len() > 65536 {
                return Err(TrailFinderError::Generic(format!(
                    "CIDR network {} contains too many addresses ({}), maximum is 65536",
                    target,
                    hosts.len()
                )));
            }

            ip_addresses.extend(hosts);
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            // Single IP address
            ip_addresses.push(ip);
        } else {
            return Err(TrailFinderError::Generic(format!(
                "Invalid IP address or CIDR network: {}",
                target
            )));
        }
    }

    Ok(ip_addresses)
}

/// Test if a host responds on the specified port
pub async fn test_tcp_connectivity(ip: IpAddr, port: u16, timeout_duration: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);

    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => {
            debug!("TCP connection successful to {}:{}", ip, port);
            true
        }
        Ok(Err(e)) => {
            debug!("TCP connection failed to {}:{} - {}", ip, port, e);
            false
        }
        Err(_) => {
            debug!("TCP connection timeout to {}:{}", ip, port);
            false
        }
    }
}

/// Attempt to identify a device via SSH
pub async fn identify_device_via_ssh(
    ip: IpAddr,
    config: &ScanConfig,
) -> Result<DiscoveredDevice, TrailFinderError> {
    let mut discovered = DiscoveredDevice {
        ip_address: ip,
        hostname: None,
        brand: None,
        device_type: None,
        ssh_responsive: false,
        identification_successful: false,
    };

    // First test basic TCP connectivity
    let timeout_duration = Duration::from_secs(config.timeout_seconds);
    if !test_tcp_connectivity(ip, config.port, timeout_duration).await {
        return Ok(discovered);
    }

    discovered.ssh_responsive = true;

    // Load SSH config for better integration
    let ssh_config = load_ssh_config()?;
    let hostname = ip.to_string();
    let host_config = ssh_config
        .get_host_config(&hostname)
        .or_else(|| ssh_config.get_host_config("*")); // Try wildcard match

    // Merge scan config with SSH config, preferring explicit scan config values
    let effective_username = config
        .username
        .clone()
        .or_else(|| host_config.as_ref().and_then(|hc| hc.user.clone()))
        .or_else(|| std::env::var("USER").ok());

    // Get all identity files from SSH config (with variable substitution)
    let ssh_identity_files = host_config
        .as_ref()
        .map(|hc| hc.get_identity_files())
        .unwrap_or_default();

    // Prefer explicit keyfile, but fall back to SSH config identity files
    let effective_keyfile = config.keyfile.clone().or_else(|| {
        ssh_identity_files
            .first()
            .map(|path| path.to_string_lossy().to_string())
    });

    // Create a temporary device config for SSH connection
    let mut device_config = DeviceConfig {
        device_id: Uuid::new_v4(),
        hostname: hostname.clone(),
        ip_address: Some(ip),
        brand: None,
        device_type: None,
        owner: crate::Owner::Unknown,
        ssh_username: effective_username,
        ssh_port: std::num::NonZeroU16::new(config.port)
            .or_else(|| std::num::NonZeroU16::new(22))
            .ok_or_else(|| std::io::Error::other("Invalid SSH port"))?,
        ssh_key_path: effective_keyfile.as_ref().map(|f| f.into()),
        ssh_key_passphrase: None,
        resolved_ssh_key_paths: Vec::new(),
        ssh_config: host_config,
        last_interrogated: None,
        notes: None,
    };

    // Resolve SSH key paths to support multiple identity files
    if let Some(ref ssh_config) = device_config.ssh_config {
        device_config.resolved_ssh_key_paths = ssh_config.get_identity_files();
    } else if let Some(ref key_path) = device_config.ssh_key_path {
        device_config.resolved_ssh_key_paths = vec![key_path.clone()];
    }

    // If we have explicit keyfile but also SSH config, combine them
    // Prefer explicit keyfile first, then SSH config identity files
    if config.keyfile.is_some() && !ssh_identity_files.is_empty() {
        let mut all_keys = vec![];
        if let Some(ref key_path) = device_config.ssh_key_path {
            all_keys.push(key_path.clone());
        }
        all_keys.extend(ssh_identity_files);
        device_config.resolved_ssh_key_paths = all_keys;
    }

    let socket_addr = SocketAddr::new(ip, config.port);

    // Attempt SSH connection and device identification
    match SshClient::connect_with_device_config(&device_config, socket_addr, timeout_duration).await
    {
        Ok(mut ssh_client) => {
            debug!("SSH connection successful to {}", ip);

            match DeviceIdentifier::identify_device(&mut ssh_client).await {
                Ok((brand, device_type)) => {
                    discovered.brand = Some(brand.clone());
                    discovered.device_type = Some(device_type);
                    discovered.identification_successful = true;
                    discovered.hostname = Some(hostname);
                    info!("Identified device at {}: {:?} {:?}", ip, brand, device_type);
                }
                Err(e) => {
                    warn!("Device identification failed for {}: {}", ip, e);
                    discovered.hostname = Some(hostname);
                }
            }
        }
        Err(e) => {
            debug!("SSH connection failed to {}: {}", ip, e);
        }
    }

    Ok(discovered)
}

/// Scan multiple targets concurrently
pub async fn scan_network_targets(
    targets: Vec<String>,
    config: ScanConfig,
) -> Result<Vec<DiscoveredDevice>, TrailFinderError> {
    info!("Starting network scan of {} targets", targets.len());

    let ip_addresses = parse_scan_targets(&targets)?;
    info!("Expanded to {} IP addresses to scan", ip_addresses.len());

    let mut handles = Vec::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50)); // Limit concurrent connections

    for ip in ip_addresses {
        let config = config.clone();
        let semaphore = semaphore.clone();

        let handle = tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => return None,
            };
            (identify_device_via_ssh(ip, &config).await).ok()
        });

        handles.push(handle);
    }

    let mut discovered_devices = Vec::new();

    for handle in handles {
        match handle.await {
            Ok(Some(device)) => discovered_devices.push(device),
            Ok(None) => {} // No device discovered or error occurred
            Err(e) => warn!("Task join error: {}", e),
        }
    }

    info!(
        "Network scan completed. Found {} responsive devices",
        discovered_devices
            .iter()
            .filter(|d| d.ssh_responsive)
            .count()
    );

    Ok(discovered_devices)
}

/// Convert a discovered device to a DeviceConfig for adding to configuration
pub fn discovered_device_to_config(
    discovered: &DiscoveredDevice,
    username: Option<String>,
    keyfile: Option<&String>,
) -> DeviceConfig {
    let hostname = discovered
        .hostname
        .clone()
        .unwrap_or_else(|| format!("device-{}", discovered.ip_address));

    // Load SSH config to get defaults for the hostname
    let ssh_config = load_ssh_config().unwrap_or_default();
    let host_config = ssh_config
        .get_host_config(&hostname)
        .or_else(|| ssh_config.get_host_config("*"));

    // Merge provided config with SSH config, preferring provided values
    let effective_username = username
        .or_else(|| host_config.as_ref().and_then(|hc| hc.user.clone()))
        .or_else(|| std::env::var("USER").ok());

    // Get all identity files from SSH config (with variable substitution)
    let ssh_identity_files = host_config
        .as_ref()
        .map(|hc| hc.get_identity_files())
        .unwrap_or_default();

    // Prefer explicit keyfile, but fall back to SSH config identity files
    let effective_keyfile = keyfile.cloned().or_else(|| {
        ssh_identity_files
            .first()
            .map(|path| path.to_string_lossy().to_string())
    });

    let mut device_config = DeviceConfig {
        device_id: Uuid::new_v4(),
        hostname,
        ip_address: Some(discovered.ip_address),
        brand: discovered.brand.clone(),
        device_type: discovered.device_type,
        owner: crate::Owner::Unknown,
        ssh_username: effective_username,
        ssh_port: unsafe { std::num::NonZeroU16::new_unchecked(22) },
        ssh_key_path: effective_keyfile.as_ref().map(|f| f.into()),
        ssh_key_passphrase: None,
        resolved_ssh_key_paths: Vec::new(),
        ssh_config: host_config,
        last_interrogated: None,
        notes: Some("Discovered via network scan".to_string()),
    };

    // Resolve SSH key paths to support multiple identity files
    if let Some(ref ssh_config) = device_config.ssh_config {
        device_config.resolved_ssh_key_paths = ssh_config.get_identity_files();
    } else if let Some(ref key_path) = device_config.ssh_key_path {
        device_config.resolved_ssh_key_paths = vec![key_path.clone()];
    }

    // If we have explicit keyfile but also SSH config, combine them
    // Prefer explicit keyfile first, then SSH config identity files
    if keyfile.is_some() && !ssh_identity_files.is_empty() {
        let mut all_keys = vec![];
        if let Some(ref key_path) = device_config.ssh_key_path {
            all_keys.push(key_path.clone());
        }
        all_keys.extend(ssh_identity_files);
        device_config.resolved_ssh_key_paths = all_keys;
    }

    device_config
}

/// Load SSH configuration from ~/.ssh/config
fn load_ssh_config() -> Result<crate::config::ssh::SshConfig, crate::TrailFinderError> {
    use crate::config::ssh::SshConfig;

    let ssh_config_path = if let Some(home_dir) = dirs::home_dir() {
        home_dir.join(".ssh").join("config")
    } else {
        debug!("Cannot find home directory, using empty SSH config");
        return Ok(SshConfig::default());
    };

    if !ssh_config_path.exists() {
        debug!(
            "SSH config file not found at {:?}, using empty config",
            ssh_config_path
        );
        return Ok(SshConfig::default());
    }

    debug!("Loading SSH config from {:?}", ssh_config_path);
    SshConfig::parse_file(&ssh_config_path).map_err(|e| {
        crate::TrailFinderError::Io(std::io::Error::other(format!(
            "Failed to parse SSH config: {}",
            e
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_targets_single_ip() {
        let targets = vec!["192.168.1.1".to_string()];
        let result = parse_scan_targets(&targets).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_scan_targets_cidr() {
        let targets = vec!["192.168.1.0/30".to_string()];
        let result = parse_scan_targets(&targets).unwrap();
        assert_eq!(result.len(), 4); // /30 contains 4 addresses
        assert!(result.contains(&"192.168.1.0".parse::<IpAddr>().unwrap()));
        assert!(result.contains(&"192.168.1.3".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_parse_scan_targets_invalid() {
        let targets = vec!["invalid.address".to_string()];
        let result = parse_scan_targets(&targets);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scan_targets_mixed() {
        let targets = vec![
            "192.168.1.1".to_string(),
            "10.0.0.0/31".to_string(), // Contains 2 addresses
        ];
        let result = parse_scan_targets(&targets).unwrap();
        assert_eq!(result.len(), 3); // 1 + 2 = 3
    }

    #[test]
    fn test_discovered_device_to_config() {
        let discovered = DiscoveredDevice {
            ip_address: "192.168.1.100".parse().unwrap(),
            hostname: Some("test-device".to_string()),
            brand: Some(DeviceBrand::Mikrotik),
            device_type: Some(DeviceType::Router),
            ssh_responsive: true,
            identification_successful: true,
        };

        let config = discovered_device_to_config(&discovered, Some("admin".to_string()), None);

        assert_eq!(config.hostname, "test-device");
        assert_eq!(config.ip_address, Some("192.168.1.100".parse().unwrap()));
        assert_eq!(config.brand, Some(DeviceBrand::Mikrotik));
        assert_eq!(config.device_type, Some(DeviceType::Router));
        assert_eq!(config.ssh_username, Some("admin".to_string()));
        assert!(config.notes.as_ref().unwrap().contains("network scan"));
        // Note: resolved_ssh_key_paths and ssh_config may be populated from ~/.ssh/config
        // We can't assert they're empty/None since SSH config integration was added
    }

    #[test]
    fn test_ssh_config_token_expansion() {
        // Create a mock discovered device
        let discovered = DiscoveredDevice {
            ip_address: "192.168.1.100".parse().unwrap(),
            hostname: Some("router.example.com".to_string()),
            brand: Some(DeviceBrand::Cisco),
            device_type: Some(DeviceType::Router),
            ssh_responsive: true,
            identification_successful: true,
        };

        // Test that the function doesn't panic with SSH config integration
        // Note: This test validates the code path works but can't test actual token expansion
        // without mocking the SSH config file system
        let config = discovered_device_to_config(&discovered, Some("testuser".to_string()), None);

        // Basic assertions to ensure the function works
        assert_eq!(config.hostname, "router.example.com");
        assert_eq!(config.ssh_username, Some("testuser".to_string()));
        assert_eq!(config.brand, Some(DeviceBrand::Cisco));
    }
}
