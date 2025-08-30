use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tower_http::services::ServeDir;

use crate::{
    config::AppConfig,
    Device, DeviceType,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
}

#[derive(Serialize)]
pub struct DeviceSummary {
    pub device_id: String,
    pub hostname: String,
    pub name: Option<String>,
    pub device_type: Option<DeviceType>,
    pub brand: Option<String>,
    pub interface_count: usize,
    pub route_count: usize,
    pub last_seen: Option<String>,
}

// DeviceDetail struct removed - we'll use Device directly

#[derive(Serialize)]
pub struct NetworkTopology {
    pub devices: Vec<NetworkDevice>,
    pub connections: Vec<NetworkConnection>,
    pub networks: Vec<NetworkSegment>,
}

#[derive(Serialize)]
pub struct NetworkDevice {
    pub device_id: String,
    pub hostname: String,
    pub device_type: Option<DeviceType>,
    pub position: Option<Position>,
}

#[derive(Serialize)]
pub struct Position {
    pub x: f64,
    pub y: f64,
}

#[derive(Serialize)]
pub struct NetworkConnection {
    pub from: String,
    pub to: String,
    pub interface_from: String,
    pub interface_to: Option<String>,
    pub connection_type: ConnectionType,
}

#[derive(Serialize)]
pub enum ConnectionType {
    DirectLink,
    Gateway,
    SameNetwork,
}

#[derive(Serialize)]
pub struct NetworkSegment {
    pub network: String,
    pub vlan_id: Option<u16>,
    pub devices: Vec<String>,
}

#[derive(Deserialize)]
pub struct PathFindRequest {
    pub source: PathEndpoint,
    pub destination: PathEndpoint,
}

#[derive(Deserialize)]
pub struct PathEndpoint {
    pub device: Option<String>,
    pub interface: Option<String>,
    pub ip: Option<String>,
}

#[derive(Serialize)]
pub struct PathFindResponse {
    pub path: Vec<PathHop>,
    pub total_hops: usize,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct PathHop {
    pub device: String,
    pub interface: String,
    pub gateway: Option<String>,
    pub network: String,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/devices", get(list_devices))
        .route("/api/devices/{device_id}", get(get_device_details))
        .route("/api/topology", get(get_network_topology))
        .route("/api/networks", get(list_networks))
        .route("/api/pathfind", post(find_path))
        .fallback_service(ServeDir::new("web/static"))
        .with_state(state)
}

pub async fn list_devices(
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceSummary>>, StatusCode> {
    let mut devices = Vec::new();

    for device_config in &state.config.devices {
        let device_state = state.config.load_device_state(&device_config.hostname);
        
        let (interface_count, route_count, last_updated, device_id) = match device_state {
            Ok(state) => (
                state.device.interfaces.len(),
                state.device.routes.len(),
                Some(state.timestamp.clone()),
                state.device.device_id.to_string(),
            ),
            Err(_) => (0, 0, None, uuid::Uuid::new_v4().to_string()),
        };

        devices.push(DeviceSummary {
            device_id,
            hostname: device_config.hostname.clone(),
            name: device_config.ip_address.map(|_| "Unknown".to_string()), // TODO: get actual name from device
            device_type: device_config.device_type,
            brand: device_config.brand.as_ref().map(|b| b.to_string()),
            interface_count,
            route_count,
            last_seen: last_updated,
        });
    }

    Ok(Json(devices))
}

pub async fn get_device_details(
    Path(device_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<Device>, StatusCode> {
    
    // Find the device by searching through all device states
    for device_config in &state.config.devices {
        if let Ok(device_state) = state.config.load_device_state(&device_config.hostname) {
            if device_state.device.device_id == device_id {
                return Ok(Json(device_state.device));
            }
        }
    }

    Err(StatusCode::NOT_FOUND)
}

pub async fn get_network_topology(
    State(state): State<AppState>,
) -> Result<Json<NetworkTopology>, StatusCode> {
    let mut devices = Vec::new();
    let mut connections = Vec::new();
    let mut networks = HashMap::<String, NetworkSegment>::new();

    // Load all device states
    let mut device_states = Vec::new();
    for device_config in &state.config.devices {
        if let Ok(device_state) = state.config.load_device_state(&device_config.hostname) {
            device_states.push(device_state);
        }
    }

    // Build device list
    for device_state in &device_states {
        devices.push(NetworkDevice {
            device_id: device_state.device.device_id.to_string(),
            hostname: device_state.device.hostname.clone(),
            device_type: Some(device_state.device.device_type),
            position: None, // TODO: implement layout algorithm
        });
    }

    // Analyze network segments and connections
    for device_state in &device_states {
        for interface in &device_state.device.interfaces {
            for address in &interface.addresses {
                // Create network segment entry
                let network_key = format!("{}/{}", 
                    match address {
                        std::net::IpAddr::V4(ip) => {
                            // Approximate network by zeroing last octet
                            let octets = ip.octets();
                            format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
                        },
                        std::net::IpAddr::V6(_) => address.to_string(), // TODO: handle IPv6 properly
                    },
                    if interface.vlan.is_some() { "24" } else { "24" } // TODO: proper CIDR detection
                );

                let segment = networks.entry(network_key.clone()).or_insert_with(|| {
                    NetworkSegment {
                        network: network_key,
                        vlan_id: interface.vlan,
                        devices: Vec::new(),
                    }
                });

                if !segment.devices.contains(&device_state.device.hostname) {
                    segment.devices.push(device_state.device.hostname.clone());
                }
            }
        }

        // Find gateway connections through routes
        for route in &device_state.device.routes {
            if let Some(gateway_ip) = &route.gateway {
                // Look for devices that have this gateway IP as an interface
                for other_device in &device_states {
                    if other_device.device.hostname == device_state.device.hostname {
                        continue;
                    }
                    
                    for other_interface in &other_device.device.interfaces {
                        if other_interface.addresses.contains(gateway_ip) {
                            connections.push(NetworkConnection {
                                from: device_state.device.hostname.clone(),
                                to: other_device.device.hostname.clone(),
                                interface_from: format!("route-{}", route.target),
                                interface_to: Some(other_interface.name.clone()),
                                connection_type: ConnectionType::Gateway,
                            });
                        }
                    }
                }
            }
        }
    }

    let topology = NetworkTopology {
        devices,
        connections,
        networks: networks.into_values().collect(),
    };

    Ok(Json(topology))
}

pub async fn list_networks(
    State(state): State<AppState>,
) -> Result<Json<Vec<NetworkSegment>>, StatusCode> {
    let topology = get_network_topology(State(state)).await?;
    Ok(Json(topology.0.networks))
}

pub async fn find_path(
    State(state): State<AppState>,
    Json(request): Json<PathFindRequest>,
) -> Result<Json<PathFindResponse>, StatusCode> {
    // Basic pathfinding implementation
    match perform_pathfind(&state, request).await {
        Ok(path) => {
            let hop_count = path.len();
            Ok(Json(PathFindResponse {
                path,
                total_hops: hop_count,
                success: true,
                error: None,
            }))
        }
        Err(error) => Ok(Json(PathFindResponse {
            path: Vec::new(),
            total_hops: 0,
            success: false,
            error: Some(error),
        })),
    }
}

async fn perform_pathfind(
    state: &AppState,
    request: PathFindRequest,
) -> Result<Vec<PathHop>, String> {
    use std::net::IpAddr;
    use cidr::IpCidr;

    // Parse destination IP/network
    let dest_network: IpCidr = request.destination.ip
        .ok_or("No destination IP specified")?
        .parse()
        .map_err(|e| format!("Invalid destination IP/network: {}", e))?;

    // Load all device states
    let mut device_states = Vec::new();
    for device_config in &state.config.devices {
        if let Ok(device_state) = state.config.load_device_state(&device_config.hostname) {
            device_states.push(device_state);
        }
    }

    // Find the source device if specified
    let source_device = if let Some(source_hostname) = &request.source.device {
        device_states.iter().find(|ds| ds.device.hostname == *source_hostname)
            .ok_or(format!("Source device '{}' not found", source_hostname))?
    } else if let Some(source_ip_str) = &request.source.ip {
        let source_ip: IpAddr = source_ip_str.parse()
            .map_err(|e| format!("Invalid source IP: {}", e))?;
        
        // Find device with this IP on any interface
        device_states.iter().find(|ds| {
            ds.device.interfaces.iter().any(|iface| iface.addresses.contains(&source_ip))
        }).ok_or("No device found with the specified source IP")?
    } else {
        return Err("Must specify either source device or source IP".to_string());
    };

    // Simple pathfinding: look for routes to the destination
    let mut path = Vec::new();
    let mut current_device = source_device;
    let mut visited_devices = std::collections::HashSet::new();
    
    // Maximum hops to prevent infinite loops
    let max_hops = 10;
    
    for _hop_count in 0..max_hops {
        // Check if we've been to this device before (loop prevention)
        if visited_devices.contains(&current_device.device.hostname) {
            return Err("Routing loop detected".to_string());
        }
        visited_devices.insert(current_device.device.hostname.clone());

        // Look for a matching route in current device
        let matching_route = current_device.device.routes.iter().find(|route| {
            // Check if destination matches exactly
            if dest_network == route.target {
                return true;
            }
            
            // Extract IP from CIDR notation and check if it's contained in the route
            let dest_str = dest_network.to_string();
            if let Some(ip_part) = dest_str.split('/').next() {
                if let Ok(dest_ip) = ip_part.parse::<IpAddr>() {
                    if route.target.contains(&dest_ip) {
                        return true;
                    }
                }
            }
            
            // Check for default routes (0.0.0.0/0 or ::/0)
            route.target.to_string() == "0.0.0.0/0" || route.target.to_string() == "::/0"
        });

        let route = match matching_route {
            Some(r) => r,
            None => {
                return Err(format!(
                    "No route found to {} from device {}",
                    dest_network,
                    current_device.device.hostname
                ));
            }
        };

        // Determine the exit interface for this route
        let exit_interface = current_device.device.interfaces.iter()
            .find(|iface| iface.interface_id == route.interface_id())
            .map(|iface| iface.name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Add this hop to the path
        path.push(PathHop {
            device: current_device.device.hostname.clone(),
            interface: exit_interface,
            gateway: route.gateway.map(|gw| gw.to_string()),
            network: route.target.to_string(),
        });

        // If this route has a gateway, try to find the next device
        if let Some(gateway_ip) = route.gateway {
            let next_device = device_states.iter().find(|ds| {
                ds.device.interfaces.iter().any(|iface| iface.addresses.contains(&gateway_ip))
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