use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::{DateTime, Utc};
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    pem::PemObject,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io::BufReader, path::Path as StdPath, sync::Arc};
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::{Level, debug, error, info, instrument, warn};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
};

use crate::{
    Device, DeviceType, Owner, PeerConnection, TrailFinderError, config::AppConfig,
    web::on_response::DefaultOnResponse,
};
use uuid::Uuid;

pub(crate) mod on_response;

/// Extract hostname from X.509 certificate
/// Priority: SAN (Subject Alternative Names) > Common Name (CN)
fn extract_hostname_from_cert(cert_path: &StdPath) -> Result<String, TrailFinderError> {
    let cert_file = fs::File::open(cert_path).map_err(|e| {
        TrailFinderError::Generic(format!("Failed to open certificate file: {}", e))
    })?;

    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Result<Vec<_>, _> = CertificateDer::pem_reader_iter(&mut cert_reader).collect();
    let cert_chain = cert_chain
        .map_err(|e| TrailFinderError::Generic(format!("Failed to parse certificate: {}", e)))?;

    if cert_chain.is_empty() {
        return Err(TrailFinderError::Generic(
            "No certificates found in file".to_string(),
        ));
    }

    // Parse the first certificate
    let cert_der = &cert_chain[0];
    let (_, cert) = parse_x509_certificate(cert_der.as_ref()).map_err(|e| {
        TrailFinderError::Generic(format!("Failed to parse X.509 certificate: {}", e))
    })?;

    // First try to extract from Subject Alternative Names (SAN)
    for extension in cert.extensions() {
        if extension.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME
            && let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension()
        {
            for name in &san.general_names {
                if let GeneralName::DNSName(dns_name) = name {
                    return Ok(dns_name.to_string());
                }
            }
        }
    }

    // Fallback to Common Name (CN) from subject
    let subject = &cert.subject();
    for rdn in subject.iter_common_name() {
        if let Ok(cn) = rdn.as_str() {
            return Ok(cn.to_string());
        }
    }

    Err(TrailFinderError::Generic(
        "No hostname found in certificate (neither SAN nor CN)".to_string(),
    ))
}

/// Parse private key from PEM file, trying multiple formats
/// Supports RSA, ECDSA (including prime256v1/P-256), and PKCS#8 keys
fn parse_private_key_file(key_path: &StdPath) -> Result<PrivateKeyDer<'static>, TrailFinderError> {
    let key_file = fs::File::open(key_path)
        .map_err(|e| TrailFinderError::Generic(format!("Failed to open key file: {}", e)))?;

    let mut key_reader = BufReader::new(key_file);

    // First try the general private_key function which should handle most formats
    match PrivateKeyDer::from_pem_reader(&mut key_reader) {
        Ok(key) => {
            info!("Successfully parsed private key using general parser");
            return Ok(key);
        }
        Err(err) => {
            warn!(
                "General private key parsing failed: {}. Trying specific formats...",
                err
            );
        }
    }

    // If that fails, try specific formats
    // Reset the reader
    let key_file = fs::File::open(key_path)
        .map_err(|e| TrailFinderError::Generic(format!("Failed to reopen key file: {}", e)))?;
    let mut key_reader = BufReader::new(key_file);

    // Try PKCS#8 format (supports both RSA and ECDSA)
    let pkcs8_keys: Result<Vec<_>, _> =
        PrivatePkcs8KeyDer::pem_reader_iter(&mut key_reader).collect();
    if let Ok(keys) = pkcs8_keys
        && !keys.is_empty()
    {
        info!("Successfully parsed PKCS#8 private key");
        return Ok(PrivateKeyDer::Pkcs8(keys[0].clone_key()));
    }

    // Reset and try EC private keys (for ECDSA keys in SEC1 format)
    let key_file = fs::File::open(key_path)
        .map_err(|e| TrailFinderError::Generic(format!("Failed to reopen key file: {}", e)))?;
    let mut key_reader = BufReader::new(key_file);

    let ec_keys: Result<Vec<_>, _> = PrivateSec1KeyDer::pem_reader_iter(&mut key_reader).collect();
    if let Ok(keys) = ec_keys
        && !keys.is_empty()
    {
        info!("Successfully parsed EC private key (ECDSA, including prime256v1/P-256)");
        return Ok(PrivateKeyDer::Sec1(keys[0].clone_key()));
    }

    // Reset and try RSA private keys
    let key_file = fs::File::open(key_path)
        .map_err(|e| TrailFinderError::Generic(format!("Failed to reopen key file: {}", e)))?;
    let mut key_reader = BufReader::new(key_file);

    let rsa_keys: Result<Vec<_>, _> =
        PrivatePkcs1KeyDer::pem_reader_iter(&mut key_reader).collect();
    if let Ok(keys) = rsa_keys
        && !keys.is_empty()
    {
        info!("Successfully parsed RSA private key");
        return Ok(PrivateKeyDer::Pkcs1(keys[0].clone_key()));
    }

    Err(TrailFinderError::Generic(
        "No supported private key found in key file. Supported formats: PKCS#8, EC/ECDSA (including prime256v1/P-256), and RSA".to_string()
    ))
}

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
    pub ip_address: Option<String>,
    pub device_type: Option<DeviceType>,
    pub brand: Option<String>,
    pub interface_count: usize,
    pub route_count: usize,
    pub last_seen: Option<DateTime<Utc>>,
    pub owner: Option<String>,
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
    IPSec,
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
    // New optional fields for enhanced pathfinding
    pub incoming_interface: Option<String>,
    pub incoming_vlan: Option<u16>,
    pub outgoing_interface: Option<String>,
    pub outgoing_vlan: Option<u16>,
    pub source_ip: Option<String>,
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
                Some(state.timestamp),
                state.device.device_id.to_string(),
            ),
            Err(e) => {
                debug!(hostname = %device_config.hostname, error = %e, "Failed to load device state");
                (0, 0, None, uuid::Uuid::new_v4().to_string())
            }
        };

        let owner = match &device_config.owner {
            Owner::Unknown => None,
            Owner::Named(name) => Some(name.clone()),
        };

        devices.push(DeviceSummary {
            device_id,
            hostname: device_config.hostname.clone(),
            ip_address: device_config.ip_address.map(|ip| ip.to_string()),
            owner,
            device_type: device_config.device_type,
            brand: device_config.brand.as_ref().map(|b| b.to_string()),
            interface_count,
            route_count,
            last_seen: last_updated,
        });
    }

    tracing::Span::current().record("device_count", devices.len());
    devices.sort_by(|a, b| a.hostname.cmp(&b.hostname));
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
            info!(hostname = %device_state.device.hostname, owner=&device_state.device.owner.to_string(), "Found device");
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

        // Find IPSec tunnel connections
        for ipsec_peer in &device_state.device.ipsec_peers {
            // Look for devices that match the IPSec peer's remote hostname or IP
            for other_device in &device_states {
                if other_device.device.hostname == device_state.device.hostname {
                    continue;
                }

                let mut peer_matched = false;

                // Check if remote hostname matches another device's hostname
                if let Some(ref remote_hostname) = ipsec_peer.remote_hostname
                    && other_device
                        .device
                        .hostname
                        .contains(&remote_hostname.replace(".example.com", ""))
                {
                    peer_matched = true;
                }

                // Check if remote IP matches another device's interface IP
                if let Some(ref remote_ip) = ipsec_peer.remote_address {
                    for other_interface in &other_device.device.interfaces {
                        if other_interface
                            .addresses
                            .iter()
                            .any(|addr| &addr.ip == remote_ip)
                        {
                            peer_matched = true;
                            break;
                        }
                    }
                }

                if peer_matched {
                    let connection_label = format!(
                        "IPSec-{} ({})",
                        ipsec_peer.peer_name,
                        ipsec_peer
                            .exchange_mode
                            .as_ref()
                            .map(|mode| format!("{:?}", mode))
                            .unwrap_or_else(|| "Unknown".to_string())
                    );

                    connections.push(NetworkConnection {
                        from: device_state.device.device_id.to_string(),
                        to: other_device.device.device_id.to_string(),
                        interface_from: connection_label,
                        interface_to: Some(format!("IPSec-{}", ipsec_peer.peer_name)),
                        connection_type: ConnectionType::IPSec,
                    });
                    break;
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
                        device: hop.device.clone(),
                        interface: hop.outgoing_interface.clone(), // Backward compatibility
                        gateway: hop.gateway.clone(),
                        network: hop.network.clone(),
                        vlan: hop.outgoing_vlan, // Backward compatibility
                        // New fields
                        incoming_interface: hop.incoming_interface,
                        incoming_vlan: hop.incoming_vlan,
                        outgoing_interface: Some(hop.outgoing_interface),
                        outgoing_vlan: hop.outgoing_vlan,
                        source_ip: hop.source_ip,
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
    let state = AppState {
        config: Arc::new(app_config.clone()),
    };

    let app = create_router(state);
    let bind_addr = format!("{}:{}", address, port);

    // Check if TLS is configured
    if app_config.is_tls_configured() {
        let cert_path = app_config.get_tls_cert_file().ok_or_else(|| {
            TrailFinderError::Generic("TLS certificate file not configured".to_string())
        })?;
        let key_path = app_config
            .get_tls_key_file()
            .ok_or_else(|| TrailFinderError::Generic("TLS key file not configured".to_string()))?;

        info!("Starting HTTPS web server on {}:{}", address, port);
        info!("Using TLS certificate: {}", cert_path.display());
        info!("Using TLS key: {}", key_path.display());

        // Determine hostname (explicit override or extract from certificate)
        let (hostname, hostname_source) =
            if let Some(explicit_hostname) = app_config.get_tls_hostname() {
                info!("Using explicit TLS hostname: {}", explicit_hostname);
                (explicit_hostname.to_string(), "explicitly configured")
            } else {
                info!("Extracting hostname from certificate...");
                let extracted = extract_hostname_from_cert(cert_path)?;
                info!("Extracted hostname from certificate: {}", extracted);
                (extracted, "extracted from certificate")
            };

        // Load TLS certificate and key as raw PEM data
        let cert_pem = fs::read_to_string(cert_path).map_err(|e| {
            TrailFinderError::Generic(format!("Failed to read certificate file: {}", e))
        })?;

        // Validate certificate parsing
        let cert_file = fs::File::open(cert_path).map_err(|e| {
            TrailFinderError::Generic(format!(
                "Failed to open certificate file for validation: {}",
                e
            ))
        })?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_validation: Result<Vec<_>, _> =
            CertificateDer::pem_reader_iter(&mut cert_reader).collect();
        match cert_validation {
            Ok(certs) => info!(
                "Successfully validated {} certificate(s) in PEM file",
                certs.len()
            ),
            Err(e) => warn!("Certificate validation warning: {}", e),
        }

        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| TrailFinderError::Generic(format!("Failed to read key file: {}", e)))?;

        // Validate that we can parse the key (for better error messages)
        let key_validation = parse_private_key_file(key_path)?;
        match &key_validation {
            PrivateKeyDer::Pkcs1(_) => info!("Validated RSA private key (PKCS#1 format)"),
            PrivateKeyDer::Pkcs8(_) => info!(
                "Validated private key (PKCS#8 format - supports RSA/ECDSA including prime256v1)"
            ),
            PrivateKeyDer::Sec1(_) => {
                info!("Validated ECDSA private key (SEC1 format - including prime256v1/P-256)")
            }
            _ => info!("Validated private key (unknown format)"),
        }
        let crypto = rustls::crypto::aws_lc_rs::default_provider();
        crypto.install_default().map_err(|_err| {
            TrailFinderError::Crypto("Failed to install AWS-LC-Rust crypto provider".to_string())
        })?;

        let tls_config = RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
            .await
            .map_err(|e| {
                TrailFinderError::Generic(format!("Failed to create TLS config: {}", e))
            })?;

        info!("🔒 Web UI available at: https://{}:{}", hostname, port);
        info!(
            "📊 API documentation available at: https://{}:{}/api-docs",
            hostname, port
        );
        info!(
            "📋 OpenAPI specification at: https://{}:{}/api-docs/openapi.json",
            hostname, port
        );
        info!("🌐 TLS hostname: {} ({})", hostname, hostname_source);
        info!("Press Ctrl+C to stop the server");

        axum_server::bind_rustls(
            bind_addr
                .parse()
                .map_err(|e| TrailFinderError::Generic(format!("Invalid bind address: {}", e)))?,
            tls_config,
        )
        .serve(app.into_make_service())
        .await
        .map_err(|e| TrailFinderError::Generic(format!("HTTPS server error: {}", e)))?;
    } else {
        // HTTP mode (existing behavior)
        info!("Starting HTTP web server on {}:{}", address, port);
        info!(
            "💡 To enable HTTPS, configure tls_cert_file and tls_key_file in your config or use --tls-cert and --tls-key options"
        );

        let listener = tokio::net::TcpListener::bind(&bind_addr)
            .await
            .inspect_err(|err| error!("Failed to bind to {}: {}", bind_addr, err))?;

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
    }

    Ok(())
}
