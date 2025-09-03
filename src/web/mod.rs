use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::{Level, debug, info, instrument, warn};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    Device, DeviceType, PeerConnection, TrailFinderError, config::AppConfig,
    web::on_response::DefaultOnResponse,
};
use uuid::Uuid;

pub(crate) mod on_response;

#[derive(OpenApi)]
#[openapi(
    paths(
        list_devices,
        get_device_details,
        get_network_topology,
        list_networks,
        find_path,
    ),
    components(
        schemas(
            DeviceSummary,
            NetworkTopology,
            NetworkDevice,
            NetworkConnection,
            NetworkSegment,
            PathFindRequest,
            PathFindResponse,
            PathEndpoint,
            PathHop,
            Position,
            ConnectionType,
            Device,
            DeviceType,
        )
    ),
    tags(
        (name = "devices", description = "Device management and information"),
        (name = "topology", description = "Network topology and visualization"),
        (name = "networks", description = "Network segment information"),
        (name = "pathfinding", description = "Network path discovery and analysis")
    ),
    info(
        title = "Trailfinder API",
        description = "Network device discovery and topology analysis API",
        version = "0.1.0",
        license(
            name = "MIT",
            identifier = "MIT"
        )
    )
)]
pub struct ApiDoc;

// Template structs
#[derive(Template, WebTemplate)]
#[template(path = "devices.html")]
struct DevicesTemplate {
    page_name: &'static str,
}

#[derive(Template, WebTemplate)]
#[template(path = "topology.html")]
struct TopologyTemplate {
    page_name: &'static str,
}

#[derive(Template, WebTemplate)]
#[template(path = "pathfinder.html")]
struct PathfinderTemplate {
    page_name: &'static str,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
}

#[derive(Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkTopology {
    pub devices: Vec<NetworkDevice>,
    pub connections: Vec<NetworkConnection>,
    pub networks: Vec<NetworkSegment>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkDevice {
    pub device_id: String,
    pub hostname: String,
    pub device_type: Option<DeviceType>,
    pub position: Option<Position>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Position {
    pub x: f64,
    pub y: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkConnection {
    pub from: String,
    pub to: String,
    pub interface_from: String,
    pub interface_to: Option<String>,
    pub connection_type: ConnectionType,
}

#[derive(Debug, Serialize, ToSchema)]
pub enum ConnectionType {
    DirectLink,
    Gateway,
    SameNetwork,
    Internet,
    CDP,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkSegment {
    pub network: String,
    pub vlan_id: Option<u16>,
    pub devices: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PathFindRequest {
    pub source: PathEndpoint,
    pub destination: PathEndpoint,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PathEndpoint {
    pub device: Option<String>,
    pub device_id: Option<String>,
    pub interface: Option<String>,
    pub ip: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PathFindResponse {
    pub path: Vec<PathHop>,
    pub total_hops: usize,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PathHop {
    pub device: String,
    pub interface: String,
    pub gateway: Option<String>,
    pub network: String,
}

pub fn create_router(state: AppState) -> Router {
    let tracelayer = TraceLayer::new_for_http()
        .on_response(DefaultOnResponse::new())
        .make_span_with(
            DefaultMakeSpan::default()
                .include_headers(false)
                .level(Level::INFO),
        );

    Router::new()
        // HTML page routes
        .route("/", get(serve_devices_page))
        .route("/devices", get(serve_devices_page))
        .route("/topology", get(serve_topology_page))
        .route("/pathfinder", get(serve_pathfinder_page))
        // API routes
        .route("/api/devices", get(list_devices))
        .route("/api/devices/{device_id}", get(get_device_details))
        .route("/api/topology", get(get_network_topology))
        .route("/api/networks", get(list_networks))
        .route("/api/pathfind", post(find_path))
        // API Documentation routes
        .merge(SwaggerUi::new("/api-docs").url("/api-docs/openapi.json", ApiDoc::openapi()))
        // Static assets
        .nest_service("/static", ServeDir::new("web/static"))
        .layer(tracelayer)
        .with_state(state)
}

// HTML Page Handlers
#[instrument(level = "info")]
pub async fn serve_devices_page() -> impl IntoResponse {
    DevicesTemplate {
        page_name: "devices",
    }
}

#[instrument(level = "info")]
pub async fn serve_topology_page() -> impl IntoResponse {
    TopologyTemplate {
        page_name: "topology",
    }
}

#[instrument(level = "info")]
pub async fn serve_pathfinder_page() -> impl IntoResponse {
    PathfinderTemplate {
        page_name: "pathfinder",
    }
}

/// List all devices with summary information
#[utoipa::path(
    get,
    path = "/api/devices",
    responses(
        (status = 200, description = "List of all devices", body = [DeviceSummary]),
        (status = 500, description = "Internal server error")
    ),
    tag = "devices"
)]
#[instrument(skip(state), fields(device_count), level = "info")]
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
            Err(e) => {
                debug!(hostname = %device_config.hostname, error = %e, "Failed to load device state");
                (0, 0, None, uuid::Uuid::new_v4().to_string())
            }
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

    tracing::Span::current().record("device_count", devices.len());
    Ok(Json(devices))
}

/// Get detailed information about a specific device
#[utoipa::path(
    get,
    path = "/api/devices/{device_id}",
    params(
        ("device_id" = Uuid, Path, description = "Device unique identifier")
    ),
    responses(
        (status = 200, description = "Device details", body = Device),
        (status = 404, description = "Device not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "devices"
)]
#[instrument(skip(state), fields(hostname), level = "info")]
pub async fn get_device_details(
    Path(device_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Result<Json<Device>, StatusCode> {
    debug!(%device_id, "Looking up device details");

    // Find the device by searching through all device states
    for device_config in &state.config.devices {
        if let Ok(device_state) = state.config.load_device_state(&device_config.hostname)
            && device_state.device.device_id == device_id
        {
            tracing::Span::current().record("hostname", &device_state.device.hostname);
            debug!(hostname = %device_state.device.hostname, "Found device");
            return Ok(Json(device_state.device));
        }
    }

    warn!(%device_id, "Device not found");
    Err(StatusCode::NOT_FOUND)
}

/// Get the network topology including devices, connections and network segments
#[utoipa::path(
    get,
    path = "/api/topology",
    responses(
        (status = 200, description = "Network topology", body = NetworkTopology),
        (status = 500, description = "Internal server error")
    ),
    tag = "topology"
)]
#[instrument(
    skip(state),
    fields(device_count, connection_count, network_count),
    level = "info"
)]
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
                // TODO: proper CIDR detection
                let network_key = match address.ip {
                    std::net::IpAddr::V4(ip) => {
                        // Use the actual prefix length from the interface address
                        let octets = ip.octets();
                        if address.prefix_length <= 24 {
                            format!(
                                "{}.{}.{}.0/{}",
                                octets[0], octets[1], octets[2], address.prefix_length
                            )
                        } else {
                            format!("{}/{}", address.ip, address.prefix_length)
                        }
                    }
                    std::net::IpAddr::V6(_) => format!("{}/{}", address.ip, address.prefix_length),
                };

                if !interface.vlans.is_empty() {
                    // If the interface has VLANs, treat each VLAN as a separate segment
                    for vlan_id in &interface.vlans {
                        let vlan_network_key = format!("{}-vlan{}", network_key, vlan_id);
                        let segment =
                            networks.entry(vlan_network_key.clone()).or_insert_with(|| {
                                NetworkSegment {
                                    network: vlan_network_key,
                                    vlan_id: Some(*vlan_id),
                                    devices: Vec::new(),
                                }
                            });

                        if !segment.devices.contains(&device_state.device.hostname) {
                            segment.devices.push(device_state.device.hostname.clone());
                        }
                    }
                } else {
                    // If the interface is bare, treat it as a single segment
                    let segment =
                        networks
                            .entry(network_key.clone())
                            .or_insert_with(|| NetworkSegment {
                                network: network_key.clone(),
                                vlan_id: None,
                                devices: Vec::new(),
                            });

                    if !segment.devices.contains(&device_state.device.hostname) {
                        segment.devices.push(device_state.device.hostname.clone());
                    }
                }
            }
        }

        // Find gateway connections through routes
        for route in &device_state.device.routes {
            if let Some(gateway_ip) = &route.gateway {
                let mut gateway_found = false;

                // Look for devices that have this gateway IP as an interface
                for other_device in &device_states {
                    if other_device.device.hostname == device_state.device.hostname {
                        continue;
                    }

                    for other_interface in &other_device.device.interfaces {
                        if other_interface
                            .addresses
                            .iter()
                            .any(|addr| &addr.ip == gateway_ip)
                        {
                            connections.push(NetworkConnection {
                                from: device_state.device.device_id.to_string(),
                                to: other_device.device.device_id.to_string(),
                                interface_from: format!("route-{}", route.target),
                                interface_to: Some(other_interface.name.clone()),
                                connection_type: ConnectionType::Gateway,
                            });
                            gateway_found = true;
                            break;
                        }
                    }
                    if gateway_found {
                        break;
                    }
                }

                // If gateway not found in our devices, it's an external gateway
                if !gateway_found {
                    connections.push(NetworkConnection {
                        from: device_state.device.device_id.to_string(),
                        to: "internet".to_string(),
                        interface_from: format!("route-{}", route.target),
                        interface_to: Some(gateway_ip.to_string()),
                        connection_type: ConnectionType::Internet,
                    });
                }
            }
        }

        // Find CDP/neighbor connections through peer relationships
        for interface in &device_state.device.interfaces {
            for (peer_connection, peer_interface_ids) in &interface.peers {
                for peer_interface_id in peer_interface_ids {
                    // Find the peer interface in other devices
                    for other_device in &device_states {
                        if other_device.device.hostname == device_state.device.hostname {
                            continue;
                        }

                        if let Some(peer_interface) = other_device
                            .device
                            .interfaces
                            .iter()
                            .find(|iface| iface.interface_id == *peer_interface_id)
                        {
                            // Create CDP connection
                            let connection_info = match peer_connection {
                                PeerConnection::Untagged => "CDP",
                                PeerConnection::Vlan(vlan_id) => &format!("CDP-VLAN{}", vlan_id),
                                PeerConnection::Trunk => "CDP-Trunk",
                                PeerConnection::Management => "CDP-Management",
                                PeerConnection::Tunnel(name) => &format!("CDP-Tunnel({})", name),
                            };

                            connections.push(NetworkConnection {
                                from: device_state.device.device_id.to_string(),
                                to: other_device.device.device_id.to_string(),
                                interface_from: format!("{} ({})", interface.name, connection_info),
                                interface_to: Some(peer_interface.name.clone()),
                                connection_type: ConnectionType::CDP,
                            });
                        }
                    }
                }
            }
        }
    }

    // Add internet node if there are any internet connections
    let has_internet_connections = connections
        .iter()
        .any(|conn| matches!(conn.connection_type, ConnectionType::Internet));
    if has_internet_connections {
        devices.push(NetworkDevice {
            device_id: "internet".to_string(),
            hostname: "🌐 Internet".to_string(),
            device_type: None,
            position: None,
        });
    }

    let topology = NetworkTopology {
        devices,
        connections,
        networks: networks.into_values().collect(),
    };

    let span = tracing::Span::current();
    span.record("device_count", topology.devices.len());
    span.record("connection_count", topology.connections.len());
    span.record("network_count", topology.networks.len());

    Ok(Json(topology))
}

/// List all network segments
#[utoipa::path(
    get,
    path = "/api/networks",
    responses(
        (status = 200, description = "List of network segments", body = [NetworkSegment]),
        (status = 500, description = "Internal server error")
    ),
    tag = "networks"
)]
#[instrument(skip(state), level = "info")]
pub async fn list_networks(
    State(state): State<AppState>,
) -> Result<Json<Vec<NetworkSegment>>, StatusCode> {
    let topology = get_network_topology(State(state)).await?;
    Ok(Json(topology.0.networks))
}

/// Find a path between two network endpoints
#[utoipa::path(
    post,
    path = "/api/pathfind",
    request_body = PathFindRequest,
    responses(
        (status = 200, description = "Path finding result", body = PathFindResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "pathfinding"
)]
#[instrument(
    skip(state, request),
    fields(source_device, destination, success, hop_count),
    level = "info"
)]
pub async fn find_path(
    State(state): State<AppState>,
    Json(request): Json<PathFindRequest>,
) -> Result<Json<PathFindResponse>, StatusCode> {
    // Record request details in span
    if let Some(ref device) = request.source.device {
        tracing::Span::current().record("source_device", device);
    }
    if let Some(ref dest) = request.destination.ip {
        tracing::Span::current().record("destination", dest);
    }

    match perform_pathfind(&state, request).await {
        Ok(path) => {
            let hop_count = path.len();
            let span = tracing::Span::current();
            span.record("success", true);
            span.record("hop_count", hop_count);

            Ok(Json(PathFindResponse {
                path,
                total_hops: hop_count,
                success: true,
                error: None,
            }))
        }
        Err(error) => {
            let span = tracing::Span::current();
            span.record("success", false);
            warn!(error = %error, "Pathfinding failed");

            Ok(Json(PathFindResponse {
                path: Vec::new(),
                total_hops: 0,
                success: false,
                error: Some(error),
            }))
        }
    }
}

#[instrument(
    skip(state, request),
    fields(source_ip, dest_network, device_states_loaded),
    level = "info"
)]
async fn perform_pathfind(
    state: &AppState,
    request: PathFindRequest,
) -> Result<Vec<PathHop>, String> {
    use cidr::IpCidr;
    use std::net::IpAddr;

    // Parse destination IP/network
    let dest_network: IpCidr = request
        .destination
        .ip
        .ok_or("No destination IP specified")?
        .parse()
        .map_err(|e| format!("Invalid destination IP/network: {}", e))?;

    tracing::Span::current().record("dest_network", dest_network.to_string());

    if let Some(ref source_ip) = request.source.ip {
        tracing::Span::current().record("source_ip", source_ip);
    }

    // Load all device states
    let mut device_states = Vec::new();
    for device_config in &state.config.devices {
        if let Ok(device_state) = state.config.load_device_state(&device_config.hostname) {
            device_states.push(device_state);
        }
    }

    tracing::Span::current().record("device_states_loaded", device_states.len());

    // Find the source device if specified
    let source_device = if let Some(source_hostname) = &request.source.device {
        device_states
            .iter()
            .find(|ds| ds.device.hostname == *source_hostname)
            .ok_or(format!("Source device '{}' not found", source_hostname))?
    } else if let Some(source_device_id) = &request.source.device_id {
        let device_id = uuid::Uuid::parse_str(source_device_id)
            .map_err(|e| format!("Invalid source device ID: {}", e))?;
        device_states
            .iter()
            .find(|ds| ds.device.device_id == device_id)
            .ok_or(format!(
                "Source device with ID '{}' not found",
                source_device_id
            ))?
    } else if let Some(source_ip_str) = &request.source.ip {
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
            .ok_or("No device found with the specified source IP")?
    } else {
        return Err(
            "Must specify either source device, source device ID, or source IP".to_string(),
        );
    };

    // Validate source interface and IP consistency if both are specified
    if let (Some(source_interface_name), Some(source_ip_str)) =
        (&request.source.interface, &request.source.ip)
    {
        let source_ip: IpAddr = source_ip_str
            .parse()
            .map_err(|e| format!("Invalid source IP: {}", e))?;

        // Find the specified interface on the source device
        let interface = source_device
            .device
            .interfaces
            .iter()
            .find(|iface| iface.name == *source_interface_name)
            .ok_or(format!(
                "Interface '{}' not found on device '{}'",
                source_interface_name, source_device.device.hostname
            ))?;

        // Check if the source IP exists on this interface

        if !interface
            .can_route(&source_ip)
            .map_err(|err| format!("Failed to parse network address: {:?}", err))?
        {
            return Err(format!(
                "Source IP '{}' is not routable on interface '{}' of device '{}'",
                source_ip, source_interface_name, source_device.device.hostname
            ));
        }
    }

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
        // First determine if we're looking for IPv4 or IPv6 routes
        let dest_str = dest_network.to_string();
        let is_ipv4_destination = if let Some(ip_part) = dest_str.split('/').next()
            && let Ok(dest_ip) = ip_part.parse::<IpAddr>()
        {
            dest_ip.is_ipv4()
        } else {
            true // Default to IPv4 if we can't determine
        };

        // Find the best matching route, prioritizing:
        // 1. Exact matches
        // 2. Contained in route target
        // 3. Default routes matching the IP version
        // 4. Default routes of any version as fallback
        let matching_route = current_device
            .device
            .routes
            .iter()
            .filter(|route| {
                // Check if destination matches exactly
                if dest_network == route.target {
                    return true;
                }

                // Extract IP from CIDR notation and check if it's contained in the route
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
            .min_by_key(|route| {
                // Prioritize routes by preference score (lower is better)
                let route_target_str = route.target.to_string();

                // Exact match gets highest priority
                if dest_network == route.target {
                    return 0;
                }

                // Routes that contain the destination IP get second priority
                if let Some(ip_part) = dest_str.split('/').next()
                    && let Ok(dest_ip) = ip_part.parse::<IpAddr>()
                    && route.target.contains(&dest_ip)
                {
                    return 1;
                }

                // Default routes matching IP version get third priority
                if (is_ipv4_destination && route_target_str == "0.0.0.0/0")
                    || (!is_ipv4_destination && route_target_str == "::/0")
                {
                    return 2;
                }

                // Default routes of other IP version get lowest priority
                if route_target_str == "0.0.0.0/0" || route_target_str == "::/0" {
                    return 3;
                }

                // Should not reach here due to filter
                4
            });

        let route = match matching_route {
            Some(r) => r,
            None => {
                return Err(format!(
                    "No route found to {} from device {}",
                    dest_network, current_device.device.hostname
                ));
            }
        };

        // Determine the exit interface for this route
        let route_interface_id = route.interface_id();
        debug!("Looking for interface with ID: {}", route_interface_id);

        let exit_interface = current_device
            .device
            .interfaces
            .iter()
            .find(|iface| {
                debug!("Checking interface {} with ID {}", iface.name, iface.interface_id);
                iface.interface_id == route_interface_id
            })
            .map(|iface| {
                debug!("Found interface by ID: {}", iface.name);
                iface.name.clone()
            })
            .or_else(|| {
                debug!("Interface ID not found, trying gateway subnet matching");
                // If we can't find the interface by ID, try to find it by analyzing the gateway
                if let Some(gateway_ip) = route.gateway {
                    debug!("Trying to find interface for gateway: {}", gateway_ip);
                    // Find interface that can reach this gateway (same subnet)
                    current_device
                        .device
                        .interfaces
                        .iter()
                        .find(|iface| {
                            let found = iface.addresses.iter().any(|addr| {
                                // Check if gateway is in the same subnet as this interface
                                if let Ok(subnet) = addr.to_cidr() {
                                    let contains = subnet.contains(&gateway_ip);
                                    debug!(
                                        "Checking interface {} address {} (subnet: {}) contains gateway {}: {}",
                                        iface.name, addr, subnet, gateway_ip, contains
                                    );
                                    contains
                                } else {
                                    debug!(
                                        "Failed to convert interface {} address {} to CIDR",
                                        iface.name, addr
                                    );
                                    false
                                }
                            });
                            if found {
                                debug!("Found matching interface: {}", iface.name);
                            }
                            found
                        })
                        .map(|iface| {
                            debug!("Using interface from gateway subnet match: {}", iface.name);
                            iface.name.clone()
                        })
                } else {
                    debug!("No gateway IP available for route matching");
                    // For routes without gateways (local routes), we can't easily determine the interface
                    None
                }
            })
            .unwrap_or_else(|| {
                debug!("No interface found, returning 'unknown'");
                "unknown".to_string()
            });

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

/// Start the web server with the given configuration and bind address/port
/// This function is used by both the CLI and tests
pub async fn web_server_command(
    app_config: &AppConfig,
    address: &str,
    port: u16,
) -> Result<(), TrailFinderError> {
    info!("Starting web server on {}:{}", address, port);

    let state = AppState {
        config: Arc::new(app_config.clone()),
    };

    let app = create_router(state);

    let bind_addr = format!("{}:{}", address, port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    info!("🌐 Web UI available at: http://{}", bind_addr);
    info!(
        "📊 API documentation available at: http://{}/api-docs",
        bind_addr
    );
    info!(
        "📋 OpenAPI specification at: http://{}/api-docs/openapi.json",
        bind_addr
    );
    info!("Press Ctrl+C to stop the server");

    axum::serve(listener, app).await?;

    Ok(())
}
