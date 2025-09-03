use crate::{
    TrailFinderError,
    config::{AppConfig, DeviceState},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};
use tracing::warn;
use uuid::Uuid;
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
    pub incoming_interface: Option<String>,
    pub incoming_vlan: Option<u16>,
    pub outgoing_interface: String,
    pub outgoing_vlan: Option<u16>,
    pub gateway: Option<String>,
    pub network: String,
    pub source_ip: Option<String>,
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
    // Create path collection
    let mut path_hops = Vec::new();

    // Add source hop (hop 0)
    let source_ip = request.source.ip.as_ref().ok_or("Source IP required")?;
    path_hops.push(PathHop {
        device: format!("Source: {}", source_ip),
        incoming_interface: None,
        incoming_vlan: None,
        outgoing_interface: "-".to_string(),
        outgoing_vlan: None,
        gateway: None,
        network: "-".to_string(),
        source_ip: Some(source_ip.clone()),
    });
    // Perform pathfinding with ingress/egress tracking
    let mut current_device = source_device;
    let mut visited_devices = HashSet::new();
    let mut previous_gateway: Option<IpAddr> = None;
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
                    current_device.device.interfaces.iter().find(|iface| {
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
        // Determine outgoing VLAN for this hop
        let outgoing_vlan = determine_hop_vlan(&request, exit_interface, current_device)?;
        // Find incoming interface and VLAN
        let (incoming_interface, incoming_vlan) = if path_hops.len() == 1 {
            // First device hop - find interface that can route the source IP
            find_ingress_interface_for_source(&current_device.device, source_ip, &request)?
        } else if let Some(prev_gw) = previous_gateway {
            // Subsequent hops - find interface that can reach the previous gateway
            find_ingress_interface_for_gateway(&current_device.device, &prev_gw)?
        } else {
            (None, None)
        };
        // Add this hop to the path
        path_hops.push(PathHop {
            device: current_device.device.hostname.clone(),
            incoming_interface,
            incoming_vlan,
            outgoing_interface: exit_interface.name.clone(),
            outgoing_vlan,
            gateway: route.gateway.map(|gw| gw.to_string()),
            network: route.target.to_string(),
            source_ip: None,
        });
        // If this route has a gateway, try to find the next device
        if let Some(gateway_ip) = route.gateway {
            previous_gateway = Some(gateway_ip);
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
    if path_hops.is_empty() {
        Err("No path found".to_string())
    } else {
        Ok(path_hops)
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
fn validate_source_endpoint(device: &crate::Device, source: &PathEndpoint) -> Result<(), String> {
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
        if let Some(source_vlan) = source.vlan
            && !interface.vlans.contains(&source_vlan)
        {
            return Err(format!(
                "VLAN {} not configured on interface '{}' of device '{}'",
                source_vlan, source_interface_name, device.hostname
            ));
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
        if let Some(dest_vlan) = destination.vlan
            && !interface.vlans.contains(&dest_vlan)
        {
            return Err(format!(
                "VLAN {} not configured on destination interface '{}' of device '{}'",
                dest_vlan, dest_interface_name, device.hostname
            ));
        }
        // Check if destination network is reachable through this interface
        if let Some(ip_part) = dest_network.to_string().split('/').next()
            && let Ok(dest_ip) = ip_part.parse::<IpAddr>()
            && !interface
                .can_route(&dest_ip)
                .map_err(|err| format!("Failed to parse network address: {:?}", err))?
        {
            warn!(
                "Destination IP '{}' may not be directly reachable on interface '{}' of device '{}'",
                dest_ip, dest_interface_name, device.hostname
            );
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
            if let Some(ip_part) = dest_str.split('/').next()
                && let Ok(dest_ip) = ip_part.parse::<IpAddr>()
                && route.target.contains(&dest_ip)
            {
                return true;
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
            if let Some(ip_part) = dest_str.split('/').next()
                && let Ok(dest_ip) = ip_part.parse::<IpAddr>()
                && route.target.contains(&dest_ip)
            {
                return 1;
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
    if let Some(source_vlan) = request.source.vlan
        && interface.vlans.contains(&source_vlan)
    {
        return Ok(Some(source_vlan));
    }

    // If interface has only one VLAN, use that
    if interface.vlans.len() == 1 {
        return Ok(Some(interface.vlans[0]));
    }
    // If interface has no VLANs or multiple VLANs, return None (untagged)
    Ok(None)
}
fn find_ingress_interface_for_source(
    device: &crate::Device,
    source_ip: &str,
    request: &PathFindRequest,
) -> Result<(Option<String>, Option<u16>), String> {
    let source_addr: IpAddr = source_ip
        .parse()
        .map_err(|e| format!("Invalid source IP: {}", e))?;
    // If source interface is specified in request, use that
    if let Some(source_interface_name) = &request.source.interface {
        let interface = device
            .interfaces
            .iter()
            .find(|iface| iface.name == *source_interface_name)
            .ok_or_else(|| {
                format!(
                    "Source interface '{}' not found on device '{}'",
                    source_interface_name, device.hostname
                )
            })?;

        let vlan = if let Some(source_vlan) = request.source.vlan {
            Some(source_vlan)
        } else if interface.vlans.len() == 1 {
            Some(interface.vlans[0])
        } else {
            None
        };

        return Ok((Some(source_interface_name.clone()), vlan));
    }
    // Find interface that can route the source IP
    let interface = device
        .interfaces
        .iter()
        .find(|iface| iface.can_route(&source_addr).unwrap_or(false))
        .ok_or_else(|| {
            format!(
                "No interface found that can route source IP {} on device {}",
                source_ip, device.hostname
            )
        })?;
    let vlan = if let Some(source_vlan) = request.source.vlan {
        if interface.vlans.contains(&source_vlan) {
            Some(source_vlan)
        } else {
            None
        }
    } else if interface.vlans.len() == 1 {
        Some(interface.vlans[0])
    } else {
        None
    };
    Ok((Some(interface.name.clone()), vlan))
}
fn find_ingress_interface_for_gateway(
    device: &crate::Device,
    gateway_ip: &IpAddr,
) -> Result<(Option<String>, Option<u16>), String> {
    // Find interface that can reach the gateway (same subnet)
    let interface = device.interfaces.iter().find(|iface| {
        iface.addresses.iter().any(|addr| {
            if let Ok(subnet) = addr.to_cidr() {
                subnet.contains(gateway_ip)
            } else {
                false
            }
        })
    });
    if let Some(iface) = interface {
        let vlan = if iface.vlans.len() == 1 {
            Some(iface.vlans[0])
        } else {
            None
        };
        Ok((Some(iface.name.clone()), vlan))
    } else {
        // Gateway not directly reachable, return None for unknown ingress
        Ok((None, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Device, DeviceType, Interface, InterfaceAddress, Owner, Route, RouteType};
    use cidr::IpCidr;
    use std::net::IpAddr;

    // Helper function to create test device
    fn create_test_device(hostname: &str) -> Device {
        Device::new(
            hostname.to_string(),
            Some(format!("Test {}", hostname)),
            Owner::Named("Test Lab".to_string()),
            DeviceType::Router,
        )
    }

    // Helper function to create test interface
    fn create_test_interface(name: &str, ip: &str, vlans: Vec<u16>) -> Interface {
        let address = InterfaceAddress {
            ip: ip.parse().unwrap(),
            prefix_length: 24,
        };
        Interface::new(
            Uuid::new_v4(),
            name.to_string(),
            vlans,
            vec![address],
            crate::InterfaceType::Ethernet,
            None,
        )
    }

    #[test]
    fn test_pathendpoint_builder_pattern() {
        // Test default construction
        let endpoint = PathEndpoint::new();
        assert!(endpoint.device.is_none());
        assert!(endpoint.device_id.is_none());
        assert!(endpoint.interface.is_none());
        assert!(endpoint.ip.is_none());
        assert!(endpoint.vlan.is_none());

        // Test builder pattern with IP
        let endpoint = PathEndpoint::new().with_ip("192.168.1.1".to_string());
        assert_eq!(endpoint.ip, Some("192.168.1.1".to_string()));
        assert!(endpoint.device.is_none());

        // Test builder pattern chaining
        let endpoint = PathEndpoint::new()
            .with_ip("10.0.0.1".to_string())
            .with_device("router1".to_string())
            .with_interface("eth0".to_string())
            .with_vlan(100);

        assert_eq!(endpoint.ip, Some("10.0.0.1".to_string()));
        assert_eq!(endpoint.device, Some("router1".to_string()));
        assert_eq!(endpoint.interface, Some("eth0".to_string()));
        assert_eq!(endpoint.vlan, Some(100));
    }

    #[test]
    fn test_pathendpoint_default_trait() {
        let endpoint: PathEndpoint = Default::default();
        assert!(endpoint.device.is_none());
        assert!(endpoint.device_id.is_none());
        assert!(endpoint.interface.is_none());
        assert!(endpoint.ip.is_none());
        assert!(endpoint.vlan.is_none());
    }

    #[test]
    fn test_pathhop_structure() {
        let hop = PathHop {
            device: "router1".to_string(),
            incoming_interface: Some("eth0".to_string()),
            incoming_vlan: Some(100),
            outgoing_interface: "eth1".to_string(),
            outgoing_vlan: Some(200),
            gateway: Some("192.168.1.1".to_string()),
            network: "0.0.0.0/0".to_string(),
            source_ip: None,
        };

        assert_eq!(hop.device, "router1");
        assert_eq!(hop.incoming_interface, Some("eth0".to_string()));
        assert_eq!(hop.incoming_vlan, Some(100));
        assert_eq!(hop.outgoing_interface, "eth1");
        assert_eq!(hop.outgoing_vlan, Some(200));
        assert_eq!(hop.gateway, Some("192.168.1.1".to_string()));
        assert_eq!(hop.network, "0.0.0.0/0");
        assert!(hop.source_ip.is_none());
    }

    #[test]
    fn test_pathfind_request_structure() {
        let source = PathEndpoint::new()
            .with_ip("192.168.1.10".to_string())
            .with_device("router1".to_string());

        let destination = PathEndpoint::new().with_ip("10.0.0.0/24".to_string());

        let request = PathFindRequest {
            source: source.clone(),
            destination: destination.clone(),
        };

        assert_eq!(request.source.ip, Some("192.168.1.10".to_string()));
        assert_eq!(request.source.device, Some("router1".to_string()));
        assert_eq!(request.destination.ip, Some("10.0.0.0/24".to_string()));
    }

    #[test]
    fn test_pathfind_result_success() {
        let hop = PathHop {
            device: "router1".to_string(),
            incoming_interface: None,
            incoming_vlan: None,
            outgoing_interface: "eth0".to_string(),
            outgoing_vlan: None,
            gateway: None,
            network: "192.168.1.0/24".to_string(),
            source_ip: None,
        };

        let result = PathFindResult {
            path: vec![hop],
            total_hops: 1,
            success: true,
            error: None,
        };

        assert!(result.success);
        assert_eq!(result.total_hops, 1);
        assert!(result.error.is_none());
        assert_eq!(result.path.len(), 1);
    }

    #[test]
    fn test_pathfind_result_error() {
        let result = PathFindResult {
            path: Vec::new(),
            total_hops: 0,
            success: false,
            error: Some("No route found".to_string()),
        };

        assert!(!result.success);
        assert_eq!(result.total_hops, 0);
        assert_eq!(result.error, Some("No route found".to_string()));
        assert!(result.path.is_empty());
    }

    #[test]
    fn test_find_source_device_by_hostname() {
        let device = create_test_device("router1");
        let device_state = crate::config::DeviceState::new(device, "test config");
        let device_states = vec![device_state];

        let source = PathEndpoint::new().with_device("router1".to_string());
        let result = find_source_device(&device_states, &source);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().device.hostname, "router1");
    }

    #[test]
    fn test_find_source_device_by_hostname_not_found() {
        let device = create_test_device("router1");
        let device_state = crate::config::DeviceState::new(device, "test config");
        let device_states = vec![device_state];

        let source = PathEndpoint::new().with_device("router2".to_string());
        let result = find_source_device(&device_states, &source);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Source device 'router2' not found")
        );
    }

    #[test]
    fn test_find_source_device_by_ip() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![]));
        let device_state = crate::config::DeviceState::new(device, "test config");
        let device_states = vec![device_state];

        let source = PathEndpoint::new().with_ip("192.168.1.5".to_string());
        let result = find_source_device(&device_states, &source);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().device.hostname, "router1");
    }

    #[test]
    fn test_find_source_device_missing_parameters() {
        let device = create_test_device("router1");
        let device_state = crate::config::DeviceState::new(device, "test config");
        let device_states = vec![device_state];

        let source = PathEndpoint::new();
        let result = find_source_device(&device_states, &source);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Must specify either source device")
        );
    }

    #[test]
    fn test_validate_source_endpoint_success() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![100]));

        let source = PathEndpoint::new()
            .with_interface("eth0".to_string())
            .with_ip("192.168.1.5".to_string())
            .with_vlan(100);

        let result = validate_source_endpoint(&device, &source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_source_endpoint_interface_not_found() {
        let device = create_test_device("router1");

        let source = PathEndpoint::new()
            .with_interface("eth0".to_string())
            .with_ip("192.168.1.5".to_string());

        let result = validate_source_endpoint(&device, &source);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Interface 'eth0' not found"));
    }

    #[test]
    fn test_validate_source_endpoint_ip_not_routable() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![]));

        let source = PathEndpoint::new()
            .with_interface("eth0".to_string())
            .with_ip("10.0.0.1".to_string()); // Different subnet

        let result = validate_source_endpoint(&device, &source);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is not routable on interface"));
    }

    #[test]
    fn test_validate_source_endpoint_vlan_not_configured() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![200])); // Only VLAN 200

        let source = PathEndpoint::new()
            .with_interface("eth0".to_string())
            .with_ip("192.168.1.5".to_string())
            .with_vlan(100); // Different VLAN

        let result = validate_source_endpoint(&device, &source);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("VLAN 100 not configured"));
    }

    #[test]
    fn test_find_best_route_exact_match() {
        let mut device = create_test_device("router1");
        let interface = create_test_interface("eth0", "192.168.1.1", vec![]);
        let route = Route {
            target: "192.168.1.0/24".parse::<IpCidr>().unwrap(),
            distance: None,
            gateway: None,
            route_type: RouteType::Local(interface.interface_id),
        };
        device.interfaces.push(interface);

        device.routes.push(route);

        let request = PathFindRequest {
            source: PathEndpoint::new().with_ip("192.168.1.1".to_string()),
            destination: PathEndpoint::new().with_ip("192.168.1.0/24".to_string()),
        };

        let dest_network = "192.168.1.0/24".parse::<IpCidr>().unwrap();
        let result = find_best_route(&device, &dest_network, &request);

        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_find_best_route_no_match() {
        let device = create_test_device("router1");
        let request = PathFindRequest {
            source: PathEndpoint::new().with_ip("192.168.1.1".to_string()),
            destination: PathEndpoint::new().with_ip("10.0.0.1".to_string()),
        };

        let dest_network = "10.0.0.0/24".parse::<IpCidr>().unwrap();
        let result = find_best_route(&device, &dest_network, &request);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_determine_hop_vlan_with_source_vlan() {
        let interface = create_test_interface("eth0", "192.168.1.1", vec![100, 200]);
        let device_state =
            crate::config::DeviceState::new(create_test_device("router1"), "test config");

        let request = PathFindRequest {
            source: PathEndpoint::new().with_vlan(100),
            destination: PathEndpoint::new(),
        };

        let result = determine_hop_vlan(&request, &interface, &device_state);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(100));
    }

    #[test]
    fn test_determine_hop_vlan_single_vlan() {
        let interface = create_test_interface("eth0", "192.168.1.1", vec![100]);
        let device_state =
            crate::config::DeviceState::new(create_test_device("router1"), "test config");

        let request = PathFindRequest {
            source: PathEndpoint::new(),
            destination: PathEndpoint::new(),
        };

        let result = determine_hop_vlan(&request, &interface, &device_state);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(100));
    }

    #[test]
    fn test_determine_hop_vlan_no_vlans() {
        let interface = create_test_interface("eth0", "192.168.1.1", vec![]);
        let device_state =
            crate::config::DeviceState::new(create_test_device("router1"), "test config");

        let request = PathFindRequest {
            source: PathEndpoint::new(),
            destination: PathEndpoint::new(),
        };

        let result = determine_hop_vlan(&request, &interface, &device_state);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_find_ingress_interface_for_source_with_request_interface() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![100]));

        let request = PathFindRequest {
            source: PathEndpoint::new()
                .with_interface("eth0".to_string())
                .with_vlan(100),
            destination: PathEndpoint::new(),
        };

        let result = find_ingress_interface_for_source(&device, "192.168.1.5", &request);
        assert!(result.is_ok());
        let (interface, vlan) = result.unwrap();
        assert_eq!(interface, Some("eth0".to_string()));
        assert_eq!(vlan, Some(100));
    }

    #[test]
    fn test_find_ingress_interface_for_gateway() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![100]));

        let gateway_ip = "192.168.1.254".parse::<IpAddr>().unwrap();
        let result = find_ingress_interface_for_gateway(&device, &gateway_ip);

        assert!(result.is_ok());
        let (interface, vlan) = result.unwrap();
        assert_eq!(interface, Some("eth0".to_string()));
        assert_eq!(vlan, Some(100));
    }

    #[test]
    fn test_find_ingress_interface_for_gateway_not_reachable() {
        let mut device = create_test_device("router1");
        device
            .interfaces
            .push(create_test_interface("eth0", "192.168.1.1", vec![]));

        let gateway_ip = "10.0.0.1".parse::<IpAddr>().unwrap(); // Different subnet
        let result = find_ingress_interface_for_gateway(&device, &gateway_ip);

        assert!(result.is_ok());
        let (interface, vlan) = result.unwrap();
        assert!(interface.is_none());
        assert!(vlan.is_none());
    }
}
