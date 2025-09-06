//! Network discovery functionality for scanning IP ranges and discovering devices

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
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

/// Information about a resolved scan target
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub ip_address: IpAddr,
    /// None if this was a direct IP/CIDR, Some if resolved from hostname
    pub original_hostname: Option<String>,
}

/// Parse target strings (IP addresses, hostnames, or CIDR networks) into individual resolved targets
pub fn parse_scan_targets(targets: &[String]) -> Result<Vec<ResolvedTarget>, TrailFinderError> {
    let mut resolved_targets = Vec::new();

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

            // CIDR targets don't have original hostnames
            resolved_targets.extend(hosts.into_iter().map(|ip| ResolvedTarget {
                ip_address: ip,
                original_hostname: None,
            }));
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            // Single IP address - no original hostname
            resolved_targets.push(ResolvedTarget {
                ip_address: ip,
                original_hostname: None,
            });
        } else {
            // Try to resolve as hostname
            match resolve_hostname(target) {
                Ok(resolved_ips) => {
                    info!(
                        "Resolved hostname '{}' to {} address(es)",
                        target,
                        resolved_ips.len()
                    );
                    // Hostname targets preserve the original hostname
                    resolved_targets.extend(resolved_ips.into_iter().map(|ip| ResolvedTarget {
                        ip_address: ip,
                        original_hostname: Some(target.clone()),
                    }));
                }
                Err(e) => {
                    return Err(TrailFinderError::Generic(format!(
                        "Unable to resolve target '{}': {}",
                        target, e
                    )));
                }
            }
        }
    }

    Ok(resolved_targets)
}

/// Resolve a hostname to one or more IP addresses
fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, TrailFinderError> {
    debug!("Attempting to resolve hostname: {}", hostname);

    // Use a dummy port for resolution - we only care about the IP addresses
    let hostname_with_port = format!("{}:80", hostname);

    match hostname_with_port.to_socket_addrs() {
        Ok(socket_addrs) => {
            let ips: Vec<IpAddr> = socket_addrs
                .map(|addr| addr.ip())
                .collect::<HashSet<_>>() // Remove duplicates
                .into_iter()
                .collect();

            if ips.is_empty() {
                Err(TrailFinderError::Generic(format!(
                    "Hostname '{}' resolved to no addresses",
                    hostname
                )))
            } else {
                debug!(
                    "Resolved '{}' to {}",
                    hostname,
                    ips.iter()
                        .map(|ipaddr| ipaddr.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                Ok(ips)
            }
        }
        Err(e) => Err(TrailFinderError::Generic(format!(
            "Failed to resolve hostname '{}': {}",
            hostname, e
        ))),
    }
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
    resolved_target: &ResolvedTarget,
    config: &ScanConfig,
) -> Result<DiscoveredDevice, TrailFinderError> {
    let ip = resolved_target.ip_address;
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

    // Use original hostname if available, otherwise fall back to IP address
    let ip_string = ip.to_string();
    let hostname_for_ssh_config = resolved_target
        .original_hostname
        .as_ref()
        .unwrap_or(&ip_string);

    let host_config = ssh_config
        .get_host_config(hostname_for_ssh_config)
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
    // Use original hostname if available, otherwise use IP address
    let hostname_for_device = resolved_target
        .original_hostname
        .clone()
        .unwrap_or_else(|| ip.to_string());

    let mut device_config = DeviceConfig {
        device_id: Uuid::new_v4(),
        hostname: hostname_for_device.clone(),
        ip_address: Some(ip),
        brand: None,
        device_type: None,
        owner: crate::Owner::Unknown,
        ssh_username: effective_username,
        ssh_port: std::num::NonZeroU16::new(config.port)
            .or_else(|| std::num::NonZeroU16::new(22))
            .ok_or_else(|| std::io::Error::other("Invalid SSH port"))?,
        ssh_identity_files: effective_keyfile
            .as_ref()
            .map(|f| vec![f.into()])
            .unwrap_or_default(),
        ssh_key_passphrase: None,
        all_ssh_identity_files: Vec::new(),
        ssh_config: host_config,
        last_interrogated: None,
        notes: None,
    };

    // Resolve SSH key paths to support multiple identity files
    let mut all_keys = device_config.ssh_identity_files.clone();
    if let Some(ref ssh_config) = device_config.ssh_config {
        all_keys.extend(ssh_config.get_identity_files());
    }
    device_config.all_ssh_identity_files = all_keys;

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
                    discovered.hostname = Some(hostname_for_device.clone());
                    info!("Identified device at {}: {:?} {:?}", ip, brand, device_type);
                }
                Err(e) => {
                    warn!("Device identification failed for {}: {}", ip, e);
                    discovered.hostname = Some(hostname_for_device.clone());
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

    let resolved_targets = parse_scan_targets(&targets)?;
    info!(
        "Expanded to {} IP addresses to scan",
        resolved_targets.len()
    );

    let mut handles = Vec::new();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50)); // Limit concurrent connections

    for resolved_target in resolved_targets {
        let config = config.clone();
        let semaphore = semaphore.clone();

        let handle = tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => return None,
            };
            (identify_device_via_ssh(&resolved_target, &config).await).ok()
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
        ssh_identity_files: effective_keyfile
            .as_ref()
            .map(|f| vec![f.into()])
            .unwrap_or_default(),
        ssh_key_passphrase: None,
        all_ssh_identity_files: Vec::new(),
        ssh_config: host_config,
        last_interrogated: None,
        notes: Some("Discovered via network scan".to_string()),
    };

    // Resolve SSH key paths to support multiple identity files
    let mut all_keys = device_config.ssh_identity_files.clone();
    if let Some(ref ssh_config) = device_config.ssh_config {
        all_keys.extend(ssh_config.get_identity_files());
    }
    device_config.all_ssh_identity_files = all_keys;

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
        assert_eq!(
            result[0].ip_address,
            "192.168.1.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(result[0].original_hostname, None);
    }

    #[test]
    fn test_parse_scan_targets_cidr() {
        let targets = vec!["192.168.1.0/30".to_string()];
        let result = parse_scan_targets(&targets).unwrap();
        assert_eq!(result.len(), 4); // /30 contains 4 addresses

        let ips: Vec<IpAddr> = result.iter().map(|r| r.ip_address).collect();
        assert!(ips.contains(&"192.168.1.0".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"192.168.1.3".parse::<IpAddr>().unwrap()));

        // All should have no original hostname (direct CIDR)
        assert!(result.iter().all(|r| r.original_hostname.is_none()));
    }

    #[test]
    fn test_parse_scan_targets_localhost_hostname() {
        let targets = vec!["localhost".to_string()];
        let result = parse_scan_targets(&targets).unwrap();
        assert!(!result.is_empty());

        let ips: Vec<IpAddr> = result.iter().map(|r| r.ip_address).collect();
        // localhost should resolve to 127.0.0.1 and/or ::1
        assert!(
            ips.contains(&"127.0.0.1".parse::<IpAddr>().unwrap())
                || ips.contains(&"::1".parse::<IpAddr>().unwrap())
        );

        // All should preserve the original hostname
        assert!(
            result
                .iter()
                .all(|r| r.original_hostname == Some("localhost".to_string()))
        );
    }

    #[test]
    fn test_parse_scan_targets_invalid_hostname() {
        let targets = vec!["this-hostname-should-not-exist.invalid".to_string()];
        let result = parse_scan_targets(&targets);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unable to resolve target"));
    }

    #[test]
    fn test_resolve_hostname_localhost() {
        let result = resolve_hostname("localhost").unwrap();
        assert!(!result.is_empty());
        // localhost should resolve to at least one address
        assert!(
            result.contains(&"127.0.0.1".parse::<IpAddr>().unwrap())
                || result.contains(&"::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_resolve_hostname_invalid() {
        let result = resolve_hostname("this-hostname-should-not-exist.invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scan_targets_ipv6_direct() {
        let targets = vec!["::1".to_string()];
        let result = parse_scan_targets(&targets).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].ip_address, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(result[0].original_hostname, None);
    }

    #[test]
    fn test_parse_scan_targets_mixed_ipv4_ipv6() {
        let targets = vec!["127.0.0.1".to_string(), "::1".to_string()];
        let result = parse_scan_targets(&targets).unwrap();
        assert_eq!(result.len(), 2);

        let ips: Vec<IpAddr> = result.iter().map(|r| r.ip_address).collect();
        assert!(ips.contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"::1".parse::<IpAddr>().unwrap()));

        // Both should have no original hostname (direct IPs)
        assert!(result.iter().all(|r| r.original_hostname.is_none()));
    }

    #[test]
    fn test_parse_scan_targets_mixed() {
        let targets = vec![
            "192.168.1.1".to_string(),
            "10.0.0.0/31".to_string(), // Contains 2 addresses
            "localhost".to_string(),   // Should resolve to at least 1 address
        ];
        let result = parse_scan_targets(&targets).unwrap();
        assert!(result.len() >= 4); // At least 1 + 2 + 1 = 4, but localhost might resolve to multiple addresses

        let ips: Vec<IpAddr> = result.iter().map(|r| r.ip_address).collect();
        // Check that we have the expected IP address
        assert!(ips.contains(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        // Check that we have at least one localhost resolution
        assert!(
            ips.contains(&"127.0.0.1".parse::<IpAddr>().unwrap())
                || ips.contains(&"::1".parse::<IpAddr>().unwrap())
        );

        // Check hostname preservation
        let localhost_targets: Vec<_> = result
            .iter()
            .filter(|r| r.original_hostname == Some("localhost".to_string()))
            .collect();
        assert!(!localhost_targets.is_empty());

        let direct_ip_targets: Vec<_> = result
            .iter()
            .filter(|r| r.original_hostname.is_none())
            .collect();
        assert!(direct_ip_targets.len() >= 3); // At least the direct IP + 2 CIDR addresses
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
