use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use crate::{
    config::{AppConfig, DeviceState},
    TrailFinderError,
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathEndpoint {
    pub device: Option<String>,
    pub device_id: Option<String>,
    pub interface: Option<String>,
    pub ip: Option<String>,
    pub vlan: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathFindRequest {
    pub source: PathEndpoint,
    pub destination: PathEndpoint,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathFindResult {
    pub path: Vec<PathHop>,
    pub total_hops: usize,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathHop {
    pub device: String,
    pub interface: String,
    pub gateway: Option<String>,
    pub network: String,
    pub vlan: Option<u16>,
}

impl PathEndpoint {
    pub fn new() -> Self {
        Self {
            device: None,
            device_id: None,
            interface: None,
            ip: None,
            vlan: None,
        }
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn with_device(mut self, device: String) -> Self {
        self.device = Some(device);
        self
    }

    pub fn with_interface(mut self, interface: String) -> Self {
        self.interface = Some(interface);
        self
    }

    pub fn with_vlan(mut self, vlan: u16) -> Self {
        self.vlan = Some(vlan);
        self
    }
}

impl Default for PathEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn find_path(
    config: &AppConfig,
    request: PathFindRequest,
) -> Result<PathFindResult, TrailFinderError> {
    match perform_pathfind(config, request).await {
        Ok(path) => Ok(PathFindResult {
            total_hops: path.len(),
            path,
            success: true,
            error: None,
        }),
        Err(error) => Ok(PathFindResult {
            path: Vec::new(),
            total_hops: 0,
            success: false,
            error: Some(error),
        }),
    }
}

async fn perform_pathfind(
    config: &AppConfig,
    request: PathFindRequest,
) -> Result<Vec<PathHop>, String> {
    use cidr::IpCidr;

    // Parse destination IP/network
    let dest_network: IpCidr = request
        .destination
        .ip
        .as_ref()
        .ok_or("No destination IP specified")?
        .parse()
        .map_err(|e| format!("Invalid destination IP/network: {}", e))?;

    // Load all device states
    let mut device_states = Vec::new();
    for device_config in &config.devices {
        if let Ok(device_state) = config.load_device_state(&device_config.hostname) {
            device_states.push(device_state);
        }
    }

    if device_states.is_empty() {
        return Err("No device states available for pathfinding".to_string());
    }

    // Find and validate the source device
    let source_device = find_source_device(&device_states, &request.source)?;

    // Validate source endpoint constraints
    validate_source_endpoint(&source_device.device, &request.source)?;

    // Validate destination endpoint constraints if specified
    if request.destination.device.is_some() || request.destination.interface.is_some() {
        let dest_device = find_destination_device(&device_states, &request.destination)?;
        validate_destination_endpoint(&dest_device.device, &request.destination, &dest_network)?;
    }

    // Perform pathfinding with VLAN awareness
    let mut path = Vec::new();
    let mut current_device = source_device;
    let mut visited_devices = HashSet::new();
    let max_hops = 10;

    for _hop_count in 0..max_hops {
        // Check for routing loops
        if visited_devices.contains(&current_device.device.hostname) {
            return Err("Routing loop detected".to_string());
        }
        visited_devices.insert(current_device.device.hostname.clone());

        // Find the best matching route
        let matching_route = find_best_route(&current_device.device, &dest_network, &request)?;

        if matching_route.is_none() {
            return Err(format!(
                "No route found to {} from device {}",
                dest_network, current_device.device.hostname
            ));
        }

        let route = matching_route.unwrap();
        let route_interface_id = route.interface_id();

        // Find the exit interface - try by ID first, then by gateway subnet matching
        let exit_interface = current_device
            .device
            .interfaces
            .iter()
            .find(|iface| iface.interface_id == route_interface_id)
            .or_else(|| {
                // Fallback: if we can't find by interface ID, try to find by gateway subnet
                if let Some(gateway_ip) = route.gateway {
                    current_device
                        .device
                        .interfaces
                        .iter()
                        .find(|iface| {
                            iface.addresses.iter().any(|addr| {
                                if let Ok(subnet) = addr.to_cidr() {
                                    subnet.contains(&gateway_ip)
                                } else {
                                    false
                                }
                            })
                        })
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                format!(
                    "No suitable interface found for route to {} on device {} (interface ID: {})",
                    route.target, current_device.device.hostname, route_interface_id
                )
            })?;

        // Determine VLAN for this hop
        let hop_vlan = determine_hop_vlan(&request, exit_interface, current_device)?;

        // Add this hop to the path
        path.push(PathHop {
            device: current_device.device.hostname.clone(),
            interface: exit_interface.name.clone(),
            gateway: route.gateway.map(|gw| gw.to_string()),
            network: route.target.to_string(),
            vlan: hop_vlan,
        });

        // If this route has a gateway, try to find the next device
        if let Some(gateway_ip) = route.gateway {
            let next_device = device_states.iter().find(|ds| {
                ds.device
                    .interfaces
                    .iter()
                    .any(|iface| iface.addresses.iter().any(|addr| addr.ip == gateway_ip))
            });

            if let Some(next_dev) = next_device {
                current_device = next_dev;
            } else {
                // Gateway not found in our topology, this is the final hop
                break;
            }
        } else {
            // Direct/local route, this is the final hop
            break;
        }
    }

    if path.is_empty() {
        Err("No path found".to_string())
    } else {
        Ok(path)
    }
}

fn find_source_device<'a>(
    device_states: &'a [DeviceState],
    source: &PathEndpoint,
) -> Result<&'a DeviceState, String> {
    if let Some(source_hostname) = &source.device {
        device_states
            .iter()
            .find(|ds| ds.device.hostname == *source_hostname)
            .ok_or_else(|| format!("Source device '{}' not found", source_hostname))
    } else if let Some(source_device_id) = &source.device_id {
        let device_id = Uuid::parse_str(source_device_id)
            .map_err(|e| format!("Invalid source device ID: {}", e))?;
        device_states
            .iter()
            .find(|ds| ds.device.device_id == device_id)
            .ok_or_else(|| format!("Source device with ID '{}' not found", source_device_id))
    } else if let Some(source_ip_str) = &source.ip {
        let source_ip: IpAddr = source_ip_str
            .parse()
            .map_err(|e| format!("Invalid source IP: {}", e))?;

        // Find device with this IP on any interface
        device_states
            .iter()
            .find(|ds| {
                ds.device.interfaces.iter().any(|iface| {
                    iface
                        .addresses
                        .iter()
                        .any(|addr| addr.can_route(&source_ip).unwrap_or(false))
                })
            })
            .ok_or("No device found with the specified source IP".to_string())
    } else {
        Err("Must specify either source device, source device ID, or source IP".to_string())
    }
}

fn find_destination_device<'a>(
    device_states: &'a [DeviceState],
    destination: &PathEndpoint,
) -> Result<&'a DeviceState, String> {
    if let Some(dest_hostname) = &destination.device {
        device_states
            .iter()
            .find(|ds| ds.device.hostname == *dest_hostname)
            .ok_or_else(|| format!("Destination device '{}' not found", dest_hostname))
    } else if let Some(dest_device_id) = &destination.device_id {
        let device_id = Uuid::parse_str(dest_device_id)
            .map_err(|e| format!("Invalid destination device ID: {}", e))?;
        device_states
            .iter()
            .find(|ds| ds.device.device_id == device_id)
            .ok_or_else(|| format!("Destination device with ID '{}' not found", dest_device_id))
    } else {
        Err("Destination device or device ID must be specified for validation".to_string())
    }
}

fn validate_source_endpoint(
    device: &crate::Device,
    source: &PathEndpoint,
) -> Result<(), String> {
    // If both interface and IP are specified, validate consistency
    if let (Some(source_interface_name), Some(source_ip_str)) = (&source.interface, &source.ip) {
        let source_ip: IpAddr = source_ip_str
            .parse()
            .map_err(|e| format!("Invalid source IP: {}", e))?;

        // Find the specified interface
        let interface = device
            .interfaces
            .iter()
            .find(|iface| iface.name == *source_interface_name)
            .ok_or_else(|| {
                format!(
                    "Interface '{}' not found on device '{}'",
                    source_interface_name, device.hostname
                )
            })?;

        // Check if the source IP exists on this interface
        if !interface
            .can_route(&source_ip)
            .map_err(|err| format!("Failed to parse network address: {:?}", err))?
        {
            return Err(format!(
                "Source IP '{}' is not routable on interface '{}' of device '{}'",
                source_ip, source_interface_name, device.hostname
            ));
        }

        // Validate VLAN if specified
        if let Some(source_vlan) = source.vlan {
            if !interface.vlans.contains(&source_vlan) {
                return Err(format!(
                    "VLAN {} not configured on interface '{}' of device '{}'",
                    source_vlan, source_interface_name, device.hostname
                ));
            }
        }
    }

    Ok(())
}

fn validate_destination_endpoint(
    device: &crate::Device,
    destination: &PathEndpoint,
    dest_network: &cidr::IpCidr,
) -> Result<(), String> {
    // If destination interface is specified, validate it exists
    if let Some(dest_interface_name) = &destination.interface {
        let interface = device
            .interfaces
            .iter()
            .find(|iface| iface.name == *dest_interface_name)
            .ok_or_else(|| {
                format!(
                    "Destination interface '{}' not found on device '{}'",
                    dest_interface_name, device.hostname
                )
            })?;

        // Validate VLAN if specified
        if let Some(dest_vlan) = destination.vlan {
            if !interface.vlans.contains(&dest_vlan) {
                return Err(format!(
                    "VLAN {} not configured on destination interface '{}' of device '{}'",
                    dest_vlan, dest_interface_name, device.hostname
                ));
            }
        }

        // Check if destination network is reachable through this interface
        if let Some(ip_part) = dest_network.to_string().split('/').next() {
            if let Ok(dest_ip) = ip_part.parse::<IpAddr>() {
                if !interface
                    .can_route(&dest_ip)
                    .map_err(|err| format!("Failed to parse network address: {:?}", err))?
                {
                    warn!(
                        "Destination IP '{}' may not be directly reachable on interface '{}' of device '{}'",
                        dest_ip, dest_interface_name, device.hostname
                    );
                }
            }
        }
    }

    Ok(())
}

fn find_best_route<'a>(
    device: &'a crate::Device,
    dest_network: &cidr::IpCidr,
    request: &PathFindRequest,
) -> Result<Option<&'a crate::Route>, String> {
    let dest_str = dest_network.to_string();
    let is_ipv4_destination = if let Some(ip_part) = dest_str.split('/').next() {
        if let Ok(dest_ip) = ip_part.parse::<IpAddr>() {
            dest_ip.is_ipv4()
        } else {
            true // Default to IPv4
        }
    } else {
        true
    };

    // Find matching routes with VLAN consideration
    let matching_route = device
        .routes
        .iter()
        .filter(|route| {
            // Check if destination matches exactly
            if *dest_network == route.target {
                return true;
            }

            // Extract IP and check if contained in route
            if let Some(ip_part) = dest_str.split('/').next() {
                if let Ok(dest_ip) = ip_part.parse::<IpAddr>() {
                    if route.target.contains(&dest_ip) {
                        return true;
                    }
                }
            }

            // Check for default routes
            let route_target_str = route.target.to_string();
            route_target_str == "0.0.0.0/0" || route_target_str == "::/0"
        })
        .filter(|route| {
            // Additional VLAN filtering if source VLAN is specified
            if let Some(source_vlan) = request.source.vlan {
                let route_interface_id = route.interface_id();
                if let Some(interface) = device
                    .interfaces
                    .iter()
                    .find(|iface| iface.interface_id == route_interface_id)
                {
                    // Only use routes through interfaces that support the source VLAN
                    return interface.vlans.is_empty() || interface.vlans.contains(&source_vlan);
                }
            }
            true
        })
        .min_by_key(|route| {
            // Prioritize routes by preference score (lower is better)
            let route_target_str = route.target.to_string();

            // Exact match gets highest priority
            if *dest_network == route.target {
                return 0;
            }

            // Routes that contain the destination IP
            if let Some(ip_part) = dest_str.split('/').next() {
                if let Ok(dest_ip) = ip_part.parse::<IpAddr>() {
                    if route.target.contains(&dest_ip) {
                        return 1;
                    }
                }
            }

            // Default routes matching IP version
            if (is_ipv4_destination && route_target_str == "0.0.0.0/0")
                || (!is_ipv4_destination && route_target_str == "::/0")
            {
                return 2;
            }

            // Default routes of other IP version
            if route_target_str == "0.0.0.0/0" || route_target_str == "::/0" {
                return 3;
            }

            4 // Should not reach here
        });

    Ok(matching_route)
}

fn determine_hop_vlan(
    request: &PathFindRequest,
    interface: &crate::Interface,
    _device: &DeviceState,
) -> Result<Option<u16>, String> {
    // If source VLAN is specified and interface supports it, use that
    if let Some(source_vlan) = request.source.vlan {
        if interface.vlans.contains(&source_vlan) {
            return Ok(Some(source_vlan));
        }
    }

    // If interface has only one VLAN, use that
    if interface.vlans.len() == 1 {
        return Ok(Some(interface.vlans[0]));
    }

    // If interface has no VLANs or multiple VLANs, return None (untagged)
    Ok(None)
}