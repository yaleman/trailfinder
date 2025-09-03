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
    pub vlan: Option<u16>,
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
    pub vlan: Option<u16>,
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

    // Convert web request to shared pathfind request
    let pathfind_request = crate::pathfind::PathFindRequest {
        source: crate::pathfind::PathEndpoint {
            device: request.source.device,
            device_id: request.source.device_id,
            interface: request.source.interface,
            ip: request.source.ip,
            vlan: request.source.vlan,
        },
        destination: crate::pathfind::PathEndpoint {
            device: request.destination.device,
            device_id: request.destination.device_id,
            interface: request.destination.interface,
            ip: request.destination.ip,
            vlan: request.destination.vlan,
        },
    };

    match crate::pathfind::find_path(&state.config, pathfind_request).await {
        Ok(result) => {
            let span = tracing::Span::current();
            span.record("success", result.success);
            span.record("hop_count", result.total_hops);

            if result.success {
                // Convert shared PathHop to web PathHop
                let web_path: Vec<PathHop> = result
                    .path
                    .into_iter()
                    .map(|hop| PathHop {
                        device: hop.device,
                        interface: hop.interface,
                        gateway: hop.gateway,
                        network: hop.network,
                        vlan: hop.vlan,
                    })
                    .collect();

                Ok(Json(PathFindResponse {
                    path: web_path,
                    total_hops: result.total_hops,
                    success: true,
                    error: None,
                }))
            } else {
                warn!(error = ?result.error, "Pathfinding failed");
                Ok(Json(PathFindResponse {
                    path: Vec::new(),
                    total_hops: 0,
                    success: false,
                    error: result.error,
                }))
            }
        }
        Err(error) => {
            let span = tracing::Span::current();
            span.record("success", false);
            warn!(error = %error, "Pathfinding failed");

            Ok(Json(PathFindResponse {
                path: Vec::new(),
                total_hops: 0,
                success: false,
                error: Some(error.to_string()),
            }))
        }
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
