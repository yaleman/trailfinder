#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

use std::{
    collections::HashMap,
    fmt::Display,
    net::{AddrParseError, IpAddr},
};

use cidr::errors::NetworkParseError;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::ssh::SshError;

pub mod brand;
pub mod cli;
pub mod config;
pub mod pathfind;
pub mod ssh;
#[cfg(test)]
mod tests;
pub mod web;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum DeviceType {
    Router,
    Switch,
    Firewall,
    AccessPoint,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Router => write!(f, "Router"),
            DeviceType::Switch => write!(f, "Switch"),
            DeviceType::Firewall => write!(f, "Firewall"),
            DeviceType::AccessPoint => write!(f, "Access Point"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub enum Owner {
    Unknown,
    Named(String),
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Owner::Unknown => write!(f, "Unknown"),
            Owner::Named(name) => write!(f, "{}", name),
        }
    }
}

impl From<String> for Owner {
    fn from(name: String) -> Self {
        if name == "Unknown" || name.is_empty() {
            Owner::Unknown
        } else {
            Owner::Named(name)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum IpsecExchangeMode {
    Ike,
    Ike2,
}

impl std::fmt::Display for IpsecExchangeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecExchangeMode::Ike => write!(f, "ike"),
            IpsecExchangeMode::Ike2 => write!(f, "ike2"),
        }
    }
}

impl From<&str> for IpsecExchangeMode {
    fn from(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "ike" => IpsecExchangeMode::Ike,
            "ike2" => IpsecExchangeMode::Ike2,
            _ => IpsecExchangeMode::Ike2, // Default to IKE2
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IpsecPeer {
    /// Name of the IPSec peer as configured
    pub peer_name: String,
    /// Remote address/hostname of the peer
    #[schema(value_type = Option<String>, example = "192.168.1.1")]
    pub remote_address: Option<IpAddr>,
    /// Remote hostname if not an IP address
    pub remote_hostname: Option<String>,
    /// Local identity used in the tunnel
    pub local_identity: Option<String>,
    /// Remote identity expected from the peer
    pub remote_identity: Option<String>,
    /// Local networks accessible through this tunnel
    #[schema(value_type = Vec<String>, example = json!(["10.0.0.0/16"]))]
    pub local_networks: Vec<cidr::IpCidr>,
    /// Remote networks accessible through this tunnel
    #[schema(value_type = Vec<String>, example = json!(["10.1.0.0/16"]))]
    pub remote_networks: Vec<cidr::IpCidr>,
    /// Exchange mode (ike, ike2)
    pub exchange_mode: Option<IpsecExchangeMode>,
    /// Whether this peer acts as passive listener
    pub passive: bool,
    /// Comment/description for this peer
    pub comment: Option<String>,
}

impl IpsecPeer {
    pub fn new(peer_name: String) -> Self {
        Self {
            peer_name,
            remote_address: None,
            remote_hostname: None,
            local_identity: None,
            remote_identity: None,
            local_networks: Vec::new(),
            remote_networks: Vec::new(),
            exchange_mode: None,
            passive: false,
            comment: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Device {
    pub device_id: uuid::Uuid,
    pub hostname: String,
    pub name: Option<String>,
    /// Device identity as reported by the device itself (e.g., from CDP, LLDP, or system identity)
    /// This may differ from hostname and is used for neighbor discovery
    pub system_identity: Option<String>,
    pub owner: Owner,
    pub device_type: DeviceType,
    pub routes: Vec<Route>,
    pub interfaces: Vec<Interface>,
    pub ipsec_peers: Vec<IpsecPeer>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Upstream {
    Internet,
    Gateway(IpAddr),
}

#[derive(Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub enum InterfaceType {
    Ethernet,
    Vlan,
    Bridge,
    Loopback,
    VirtualEthernet,
    Other(String),
}

impl Display for InterfaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceType::Ethernet => write!(f, "ether"),
            InterfaceType::Vlan => write!(f, "vlan"),
            InterfaceType::Bridge => write!(f, "bridge"),
            InterfaceType::Loopback => write!(f, "loopback"),
            InterfaceType::VirtualEthernet => write!(f, "veth"),
            InterfaceType::Other(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for InterfaceType {
    fn from(value: &str) -> Self {
        match value {
            "bridge" => InterfaceType::Bridge,
            "ether" | "ethernet" => InterfaceType::Ethernet,
            "vlan" => InterfaceType::Vlan,
            "loopback" => InterfaceType::Loopback,
            "veth" => InterfaceType::VirtualEthernet, // mikrotik
            _ => InterfaceType::Other(value.to_string()),
        }
    }
}

#[derive(Debug)]
pub enum TrailFinderError {
    BadRequest(String),
    Config(String),
    Generic(String),
    InvalidDestination(NetworkParseError),
    InvalidLine(String),
    Io(std::io::Error),
    NoDestinationSpecified,
    NoDevicesConfigured,
    NoRouteFound(String),
    NotFound(String),
    Parse(String),
    Regex(regex::Error),
    Serde(String),
    Ssh(SshError),
    WebDriverError(thirtyfour::error::WebDriverError),
    RoutingLoop(String, Option<Box<pathfind::PathHop>>),
}

impl PartialEq for TrailFinderError {
    fn eq(&self, other: &Self) -> bool {
        // TODO: that's a bit of a hack but it works
        self.to_string() == other.to_string()
    }
}

impl From<AddrParseError> for TrailFinderError {
    fn from(err: AddrParseError) -> Self {
        TrailFinderError::Parse(err.to_string())
    }
}

impl From<thirtyfour::error::WebDriverError> for TrailFinderError {
    fn from(err: thirtyfour::error::WebDriverError) -> Self {
        TrailFinderError::WebDriverError(err)
    }
}

impl From<SshError> for TrailFinderError {
    fn from(err: SshError) -> Self {
        TrailFinderError::Ssh(err)
    }
}

impl From<std::io::Error> for TrailFinderError {
    fn from(err: std::io::Error) -> Self {
        TrailFinderError::Io(err)
    }
}

impl From<serde_json::Error> for TrailFinderError {
    fn from(err: serde_json::Error) -> Self {
        TrailFinderError::Serde(err.to_string())
    }
}

impl From<regex::Error> for TrailFinderError {
    fn from(err: regex::Error) -> Self {
        TrailFinderError::Regex(err)
    }
}

impl From<NetworkParseError> for TrailFinderError {
    fn from(err: NetworkParseError) -> Self {
        TrailFinderError::Parse(err.to_string())
    }
}

impl std::fmt::Display for TrailFinderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrailFinderError::BadRequest(error) => write!(f, "Bad request: {error}"),
            TrailFinderError::Parse(error) => write!(f, "Parse error: {error}"),
            TrailFinderError::InvalidLine(error) => write!(f, "Invalid line: {error}"),
            TrailFinderError::Regex(error) => write!(f, "Regex error: {error}"),
            TrailFinderError::Serde(error) => write!(f, "Serde error: {error}"),
            TrailFinderError::Io(error) => write!(f, "IO error: {error}"),
            TrailFinderError::NotFound(error) => write!(f, "Not found error: {error}"),
            TrailFinderError::Config(error) => write!(f, "Config error: {error}"),
            TrailFinderError::Generic(error) => write!(f, "Generic error: {error}"),
            TrailFinderError::Ssh(error) => write!(f, "SSH error: {error}",),
            TrailFinderError::WebDriverError(error) => write!(f, "WebDriver error: {error}"),
            TrailFinderError::InvalidDestination(err) => {
                write!(f, "Invalid destination address/network: {err}",)
            }
            TrailFinderError::NoRouteFound(err) => write!(f, "No route found: {err}"),
            TrailFinderError::NoDestinationSpecified => {
                write!(f, "No destination specified")
            }
            TrailFinderError::NoDevicesConfigured => {
                write!(f, "No devices exist in configuration")
            }
            TrailFinderError::RoutingLoop(device, hop) => {
                if let Some(hop) = hop {
                    write!(
                        f,
                        "Routing loop detected at device '{}' (last hop: device '{}', outgoing interface '{:?}')",
                        device, hop.device, hop.outgoing_interface
                    )
                } else {
                    write!(f, "Routing loop detected at device '{}'", device)
                }
            }
        }
    }
}

impl std::error::Error for TrailFinderError {}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Eq, PartialEq)]
pub struct InterfaceAddress {
    #[schema(value_type = String, example = "192.168.1.1")]
    pub ip: IpAddr,
    pub prefix_length: u8,
}

impl TryFrom<&str> for InterfaceAddress {
    type Error = TrailFinderError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 2 {
            return Err(TrailFinderError::InvalidLine(format!(
                "Invalid CIDR notation: {}",
                value
            )));
        }

        let ip = parts[0].parse().map_err(|err| {
            TrailFinderError::Parse(format!("Invalid IP address '{}': {}", parts[0], err))
        })?;

        let prefix_length = parts[1].parse().map_err(|err| {
            TrailFinderError::Parse(format!("Invalid prefix length '{}': {}", parts[1], err))
        })?;

        Ok(Self { ip, prefix_length })
    }
}

impl From<(IpAddr, u8)> for InterfaceAddress {
    fn from(value: (IpAddr, u8)) -> Self {
        Self {
            ip: value.0,
            prefix_length: value.1,
        }
    }
}

impl InterfaceAddress {
    pub fn new(ip: IpAddr, prefix_length: u8) -> Self {
        Self { ip, prefix_length }
    }

    pub fn from_cidr(cidr: &cidr::IpCidr) -> Self {
        Self {
            ip: cidr.first_address(),
            prefix_length: cidr.network_length(),
        }
    }

    pub fn to_cidr(&self) -> Result<cidr::IpCidr, cidr::errors::NetworkParseError> {
        // Calculate the network address from the interface address
        match self.ip {
            IpAddr::V4(ipv4) => {
                // Create a mask for the network
                let mask = !((1u32 << (32 - self.prefix_length)) - 1);
                let ip_u32 = u32::from(ipv4);
                let network_u32 = ip_u32 & mask;
                let network_ip = std::net::Ipv4Addr::from(network_u32);
                cidr::Ipv4Cidr::new(network_ip, self.prefix_length).map(cidr::IpCidr::V4)
            }
            IpAddr::V6(ipv6) => {
                // For IPv6, calculate the network address
                let ip_u128 = u128::from(ipv6);
                let mask = !((1u128 << (128 - self.prefix_length)) - 1);
                let network_u128 = ip_u128 & mask;
                let network_ip = std::net::Ipv6Addr::from(network_u128);
                cidr::Ipv6Cidr::new(network_ip, self.prefix_length).map(cidr::IpCidr::V6)
            }
        }
    }

    pub fn can_route(&self, source: &IpAddr) -> Result<bool, cidr::errors::NetworkParseError> {
        if self.ip == *source {
            return Ok(true);
        } else if self.ip.is_ipv4() && source.is_ipv4() {
            // For IPv4, also check if the IP is in the same subnet
            if let Ok(subnet) = self.to_cidr() {
                return Ok(subnet.contains(source));
            }
        } else if self.ip.is_ipv6() && source.is_ipv6() {
            // For IPv6, also check if the IP is in the same subnet
            if let Ok(subnet) = self.to_cidr() {
                return Ok(subnet.contains(source));
            }
        }
        Ok(false)
    }
}

impl Display for InterfaceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix_length)
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub enum PeerConnection {
    /// Direct interface connection, no VLAN tagging
    Untagged,
    /// Connection through specific VLAN ID
    Vlan(u16),
    /// Trunk port carrying multiple VLANs
    Trunk,
    /// Out-of-band management connection
    Management,
    /// VPN or other tunnel connection with identifier
    Tunnel(String),
}

impl Display for PeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerConnection::Untagged => write!(f, "Untagged"),
            PeerConnection::Vlan(id) => write!(f, "VLAN {}", id),
            PeerConnection::Trunk => write!(f, "Trunk"),
            PeerConnection::Management => write!(f, "Management"),
            PeerConnection::Tunnel(name) => write!(f, "Tunnel({})", name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NeighborInfo {
    /// Hostname of the remote device
    pub remote_hostname: String,
    /// Interface name on the remote device (as reported by CDP/LLDP)
    pub remote_interface: String,
    /// MAC address of the remote device interface (if available)
    #[schema(value_type = Option<String>, example = "00:11:22:33:44:55")]
    pub remote_mac_address: Option<MacAddress>,
    /// UUID reference to the local interface
    pub local_interface_id: Uuid,
    /// MAC address of the local interface (if available)
    #[schema(value_type = Option<String>, example = "00:11:22:33:44:55")]
    pub local_mac_address: Option<MacAddress>,
    /// Type of peer connection (VLAN, trunk, etc.)
    pub connection_type: PeerConnection,
    /// Discovery protocol used (CDP, LLDP, etc.)
    pub discovery_protocol: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Interface {
    pub interface_id: Uuid,
    pub name: String,
    pub vlans: Vec<u16>,
    pub addresses: Vec<InterfaceAddress>,
    pub interface_type: InterfaceType,
    pub comment: Option<String>,
    /// MAC address of this interface (if available)
    #[schema(value_type = Option<String>, example = "00:11:22:33:44:55")]
    pub mac_address: Option<MacAddress>,

    /// Storing neighbour discovery data
    neighbour_string_data: HashMap<String, String>,
    /// This stores the peers discovered by CDP and anything else we can figure out
    /// Keyed by connection type (Untagged, VLAN, Trunk, etc.)
    pub peers: HashMap<PeerConnection, Vec<Uuid>>,
}

impl Interface {
    pub fn new(
        interface_id: Uuid,
        name: String,
        vlans: Vec<u16>,
        addresses: Vec<InterfaceAddress>,
        interface_type: InterfaceType,
        comment: Option<String>,
    ) -> Self {
        Self {
            interface_id,
            name,
            vlans,
            addresses,
            interface_type,
            comment,
            mac_address: None,
            neighbour_string_data: Default::default(),
            peers: Default::default(),
        }
    }

    pub fn with_mac_address(mut self, mac_address: MacAddress) -> Self {
        self.mac_address = Some(mac_address);
        self
    }

    pub fn interface_id(&self, device_id: &uuid::Uuid) -> String {
        format!("{}:{}:{}", device_id, self.name, self.interface_type)
    }

    pub fn can_route(&self, source_ip: &IpAddr) -> Result<bool, NetworkParseError> {
        for addr in &self.addresses {
            if addr.can_route(source_ip)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Utility functions for neighbor discovery and VLAN parsing
impl NeighborInfo {
    /// Parse VLAN ID from interface name
    /// Examples: "vlan40" -> Some(40), "Vlan20" -> Some(20), "GigabitEthernet1/0/1" -> None
    pub fn parse_vlan_from_interface_name(interface_name: &str) -> Option<u16> {
        if let Some(vlan_str) = interface_name.strip_prefix("vlan") {
            vlan_str.parse().ok()
        } else if let Some(vlan_str) = interface_name.strip_prefix("Vlan") {
            vlan_str.parse().ok()
        } else {
            None
        }
    }

    /// Determine PeerConnection type from interface name and VLAN information
    pub fn determine_connection_type(
        interface_name: &str,
        vlan_info: Option<u16>,
    ) -> PeerConnection {
        // Check if this is a VLAN interface
        if let Some(vlan_id) = Self::parse_vlan_from_interface_name(interface_name) {
            return PeerConnection::Vlan(vlan_id);
        }

        // Check for explicit VLAN info
        if let Some(vlan_id) = vlan_info {
            return PeerConnection::Vlan(vlan_id);
        }

        // Check for management interfaces
        if interface_name.to_lowercase().contains("management")
            || interface_name.to_lowercase().contains("mgmt")
        {
            return PeerConnection::Management;
        }

        // Check for tunnel interfaces
        if interface_name.to_lowercase().starts_with("tunnel")
            || interface_name.to_lowercase().starts_with("vpn")
        {
            return PeerConnection::Tunnel(interface_name.to_string());
        }

        // Default to untagged for regular physical interfaces
        PeerConnection::Untagged
    }
}

/// Utility functions for device-level operations
impl Device {
    /// Find interface UUID by name
    pub fn find_interface_id_by_name(&self, name: &str) -> Option<Uuid> {
        // First try exact match
        if let Some(interface) = self.interfaces.iter().find(|iface| iface.name == name) {
            return Some(interface.interface_id);
        }

        // Handle cases where the remote interface name contains multiple interfaces separated by '/'
        // This happens when Cisco CDP reports "bridge/sfp-sfpplus1" but MikroTik has separate "bridge" and "sfp-sfpplus1" interfaces
        if name.contains('/') {
            for part in name.split('/') {
                if let Some(interface) = self.interfaces.iter().find(|iface| iface.name == part) {
                    tracing::debug!(
                        "Found interface '{}' by splitting remote interface name '{}'",
                        part,
                        name
                    );
                    return Some(interface.interface_id);
                }
            }
        }

        None
    }

    /// Validate that an interface UUID exists in this device
    pub fn has_interface_id(&self, interface_id: Uuid) -> bool {
        self.interfaces
            .iter()
            .any(|iface| iface.interface_id == interface_id)
    }

    /// Get mutable reference to interface by UUID
    pub fn get_interface_mut(&mut self, interface_id: Uuid) -> Option<&mut Interface> {
        self.interfaces
            .iter_mut()
            .find(|iface| iface.interface_id == interface_id)
    }

    /// Get interface by UUID
    pub fn get_interface(&self, interface_id: Uuid) -> Option<&Interface> {
        self.interfaces
            .iter()
            .find(|iface| iface.interface_id == interface_id)
    }
}

/// Global neighbor discovery and resolution system
pub mod neighbor_resolution {
    use super::*;
    use crate::config::DeviceState;
    use tracing::{debug, info, warn};

    /// Resolve all neighbor relationships across all devices
    /// This processes CDP/LLDP data and establishes bidirectional peer relationships
    pub fn resolve_all_neighbor_relationships(
        device_states: &mut [DeviceState],
    ) -> Result<usize, TrailFinderError> {
        let mut relationships_established = 0;

        // First pass: collect all neighbor data and convert to structured format
        let mut all_neighbor_info: Vec<(usize, Vec<NeighborInfo>)> = Vec::new();

        for (device_index, device_state) in device_states.iter().enumerate() {
            let neighbors = extract_neighbor_info_from_device(device_state)?;
            if !neighbors.is_empty() {
                debug!(
                    "Device {} has {} neighbors",
                    device_state.device.hostname,
                    neighbors.len()
                );
                all_neighbor_info.push((device_index, neighbors));
            }
        }

        // Second pass: resolve neighbors and establish bidirectional relationships
        for (device_index, neighbors) in all_neighbor_info {
            let device_hostname = device_states[device_index].device.hostname.clone();

            for neighbor_info in neighbors {
                // Find the peer device by hostname (with fuzzy matching)
                if let Some(peer_device_index) =
                    find_device_by_hostname_fuzzy(&neighbor_info.remote_hostname, device_states)
                {
                    if peer_device_index == device_index {
                        continue; // Skip self-references
                    }

                    // Validate local interface exists
                    if !device_states[device_index]
                        .device
                        .has_interface_id(neighbor_info.local_interface_id)
                    {
                        warn!(
                            "Invalid local interface ID {} in neighbor data for device {}",
                            neighbor_info.local_interface_id, device_hostname
                        );
                        continue;
                    }

                    // Find peer interface by name
                    let peer_interface_id = if neighbor_info.remote_interface == "unknown" {
                        // For MikroTik neighbor data, we don't know the remote interface
                        // Try bilateral discovery: find the peer device's neighbor data that references us
                        debug!("Attempting bilateral discovery for unknown remote interface");

                        let current_device_hostname = &device_states[device_index].device.hostname;
                        let peer_device = &device_states[peer_device_index].device;

                        // Look through the peer device's interfaces to find one that has neighbor data referencing us
                        let mut found_interface_id = None;
                        for interface in &peer_device.interfaces {
                            for neighbor_data in interface.neighbour_string_data.values() {
                                // Check if this neighbor data references our hostname
                                if let Some(peer_hostname) =
                                    extract_hostname_from_cdp(neighbor_data)
                                    && peer_hostname == *current_device_hostname
                                {
                                    debug!(
                                        "Found bilateral relationship: peer interface '{}' reports neighbor '{}'",
                                        interface.name, peer_hostname
                                    );
                                    found_interface_id = Some(interface.interface_id);
                                    break;
                                }
                            }
                            if found_interface_id.is_some() {
                                break;
                            }
                        }

                        if found_interface_id.is_none() {
                            debug!("No bilateral relationship found for unknown remote interface");
                        }

                        found_interface_id
                    } else {
                        device_states[peer_device_index]
                            .device
                            .find_interface_id_by_name(&neighbor_info.remote_interface)
                    };
                    let peer_device_hostname =
                        device_states[peer_device_index].device.hostname.clone();

                    if let Some(peer_interface_id) = peer_interface_id {
                        // Get interface name for logging before borrowing mutably
                        let local_interface_name = device_states[device_index]
                            .device
                            .get_interface(neighbor_info.local_interface_id)
                            .map(|i| i.name.clone())
                            .unwrap_or_else(|| {
                                debug!(
                                    "Couldn't match interface for local interface ID {}",
                                    neighbor_info.local_interface_id
                                );
                                "unknown".to_string()
                            });

                        // Establish bidirectional peer relationship using split_at_mut to avoid borrow conflicts
                        if device_index < peer_device_index {
                            let (left, right) = device_states.split_at_mut(peer_device_index);
                            establish_bidirectional_peer_relationship(
                                &mut left[device_index],
                                neighbor_info.local_interface_id,
                                &mut right[0],
                                peer_interface_id,
                                &neighbor_info.connection_type,
                            )?;
                        } else {
                            let (left, right) = device_states.split_at_mut(device_index);
                            establish_bidirectional_peer_relationship(
                                &mut right[0],
                                neighbor_info.local_interface_id,
                                &mut left[peer_device_index],
                                peer_interface_id,
                                &neighbor_info.connection_type,
                            )?;
                        }

                        relationships_established += 1;
                        info!(
                            "Established peer relationship: {}:{} <-> {}:{}",
                            device_hostname,
                            local_interface_name,
                            peer_device_hostname,
                            neighbor_info.remote_interface
                        );
                    } else {
                        warn!(
                            "Could not find interface '{}' on peer device '{}'",
                            neighbor_info.remote_interface, neighbor_info.remote_hostname
                        );
                    }
                } else {
                    debug!(
                        "Could not find peer device for hostname '{}'",
                        neighbor_info.remote_hostname
                    );
                }
            }
        }

        info!(
            "Established {} neighbor relationships",
            relationships_established
        );
        Ok(relationships_established)
    }

    /// Extract structured neighbor information from raw CDP/LLDP data
    fn extract_neighbor_info_from_device(
        device_state: &DeviceState,
    ) -> Result<Vec<NeighborInfo>, TrailFinderError> {
        let mut neighbor_infos = Vec::new();

        for interface in &device_state.device.interfaces {
            for raw_neighbor_data in interface.neighbour_string_data.values() {
                // Parse the raw neighbor data based on the discovery protocol
                let neighbor_info = parse_raw_neighbor_data(
                    raw_neighbor_data,
                    interface.interface_id,
                    interface.mac_address,
                )?;

                neighbor_infos.push(neighbor_info);
            }
        }

        Ok(neighbor_infos)
    }

    /// Parse raw neighbor data (CDP/LLDP) into structured NeighborInfo
    fn parse_raw_neighbor_data(
        raw_data: &str,
        local_interface_id: Uuid,
        local_mac: Option<MacAddress>,
    ) -> Result<NeighborInfo, TrailFinderError> {
        // For now, implement basic CDP parsing
        // This is a simplified version - real implementation would be more robust

        // Look for hostname in the raw data
        let remote_hostname = extract_hostname_from_cdp(raw_data)
            .unwrap_or_else(|| "unknown remote hostname".to_string());

        // Look for remote interface
        let remote_interface = extract_remote_interface_from_cdp(raw_data)
            .unwrap_or_else(|| "unknown remote interface".to_string());

        // Determine connection type from interface names
        let connection_type = NeighborInfo::determine_connection_type(&remote_interface, None);

        Ok(NeighborInfo {
            remote_hostname,
            remote_interface,
            remote_mac_address: None, // Would be parsed from CDP data
            local_interface_id,
            local_mac_address: local_mac,
            connection_type,
            discovery_protocol: "CDP".to_string(),
        })
    }

    /// Extract hostname from CDP data
    fn extract_hostname_from_cdp(cdp_data: &str) -> Option<String> {
        // Look for common CDP hostname patterns
        let lines: Vec<&str> = cdp_data.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let line = line.trim();

            if line.starts_with("Device ID:") {
                return Some(line.strip_prefix("Device ID:")?.trim().to_string());
            }

            // Handle MikroTik neighbor format: both terse and tabular formats
            if !line.is_empty() && !line.starts_with('#') && !line.starts_with("Columns:") {
                let parts: Vec<&str> = line.split_whitespace().collect();

                // Try new terse format first - look for identity= key
                if let Some(identity) = crate::brand::mikrotik::find_kv(&parts, "identity") {
                    return Some(identity);
                }

                // Old tabular format: "0  sfp-sfpplus1  10.0.99.2  A0:23:9F:7B:2E:33  C3650.example.com"
                if parts.len() >= 5 && parts[0].chars().all(|c| c.is_numeric()) {
                    return Some(parts[4].to_string());
                }

                // Handle Cisco CDP multi-line format:
                // Line 1: "rb5009.example.com"
                // Line 2: "Ten 1/1/3         98                R    MikroTik  vlan40"
                if parts.len() == 1 && !parts[0].is_empty() && i + 1 < lines.len() {
                    let next_line = lines[i + 1].trim();
                    let next_parts = next_line.split_whitespace().collect::<Vec<&str>>();

                    // Check if next line looks like CDP interface info with 6+ parts (Ten 1/1/3 101 R MikroTik bridge/sfp-sfpplus1)
                    // and the first part doesn't look like a hostname (no dots)
                    if next_parts.len() >= 6 && !next_parts[0].contains('.') {
                        return Some(parts[0].to_string());
                    }
                }

                // Handle Cisco CDP single-line format: "MagickNet         Ten 1/1/3         102               R    MikroTik  vlan40"
                if parts.len() >= 6
                    && !parts[0].starts_with("Device")
                    && !parts[0].starts_with("Capability")
                {
                    return Some(parts[0].to_string());
                }
            }
        }
        None
    }

    /// Extract remote interface from CDP data
    fn extract_remote_interface_from_cdp(cdp_data: &str) -> Option<String> {
        // Look for interface information in CDP data
        for line in cdp_data.lines() {
            let line = line.trim();
            if line.contains("Port ID (outgoing port):") {
                return Some(
                    line.split("Port ID (outgoing port):")
                        .nth(1)?
                        .trim()
                        .to_string(),
                );
            }

            // Handle MikroTik neighbor format - the interface is already parsed and stored elsewhere
            // For MikroTik data, we don't have the remote interface in the neighbor data
            // Return a generic value for now
            if !line.is_empty() && !line.starts_with('#') && !line.starts_with("Columns:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 && parts[0].chars().all(|c| c.is_numeric()) {
                    // MikroTik format doesn't provide remote interface info in neighbor data
                    return Some("unknown".to_string());
                }

                // Handle Cisco CDP format: "MagickNet         Ten 1/1/3         102               R    MikroTik  vlan40"
                // The last field might be the remote interface
                if parts.len() >= 6
                    && !parts[0].starts_with("Device")
                    && !parts[0].starts_with("Capability")
                {
                    return Some(parts.last()?.to_string());
                }
            }
        }
        None
    }

    /// Find device by hostname with fuzzy matching, including system identity
    pub fn find_device_by_hostname_fuzzy(
        hostname: &str,
        device_states: &[DeviceState],
    ) -> Option<usize> {
        // First try exact match against hostname (case-insensitive)
        for (index, device_state) in device_states.iter().enumerate() {
            if device_state.device.hostname.eq_ignore_ascii_case(hostname) {
                return Some(index);
            }
        }

        // Try exact match against system identity (case-insensitive)
        for (index, device_state) in device_states.iter().enumerate() {
            if let Some(ref system_identity) = device_state.device.system_identity
                && system_identity.eq_ignore_ascii_case(hostname)
            {
                return Some(index);
            }
        }

        // Try without domain against hostname (case-insensitive)
        let hostname_short = hostname.split('.').next().unwrap_or(hostname);
        for (index, device_state) in device_states.iter().enumerate() {
            let device_hostname_short = device_state
                .device
                .hostname
                .split('.')
                .next()
                .unwrap_or(&device_state.device.hostname);
            if device_hostname_short.eq_ignore_ascii_case(hostname_short) {
                return Some(index);
            }
        }

        // Try without domain against system identity (case-insensitive)
        for (index, device_state) in device_states.iter().enumerate() {
            if let Some(ref system_identity) = device_state.device.system_identity {
                let identity_short = system_identity.split('.').next().unwrap_or(system_identity);
                if identity_short.eq_ignore_ascii_case(hostname_short) {
                    return Some(index);
                }
            }
        }

        None
    }

    /// Establish bidirectional peer relationship between two interfaces
    fn establish_bidirectional_peer_relationship(
        device_a: &mut DeviceState,
        interface_a_id: Uuid,
        device_b: &mut DeviceState,
        interface_b_id: Uuid,
        connection_type: &PeerConnection,
    ) -> Result<(), TrailFinderError> {
        // Add device B's interface as peer to device A's interface
        if let Some(interface_a) = device_a.device.get_interface_mut(interface_a_id) {
            interface_a
                .peers
                .entry(connection_type.clone())
                .or_default()
                .push(interface_b_id);
        }

        // Add device A's interface as peer to device B's interface
        if let Some(interface_b) = device_b.device.get_interface_mut(interface_b_id) {
            interface_b
                .peers
                .entry(connection_type.clone())
                .or_default()
                .push(interface_a_id);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub enum RouteType {
    Default(Uuid),
    /// Has a gateway
    NextHop(Uuid),
    /// Local to the interface (id)
    Local(Uuid),
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Route {
    pub route_type: RouteType,
    #[schema(value_type = String, example = "192.168.1.0/24")]
    pub target: cidr::IpCidr,
    #[schema(value_type = Option<String>, example = "192.168.1.1")]
    pub gateway: Option<IpAddr>,
    pub distance: Option<u16>,
}

impl Route {
    pub fn interface_id(&self) -> Uuid {
        match self {
            Route {
                route_type: RouteType::Default(interface_id),
                ..
            } => *interface_id,
            Route {
                route_type: RouteType::NextHop(interface_id),
                ..
            } => *interface_id,
            Route {
                route_type: RouteType::Local(interface_id),
                ..
            } => *interface_id,
        }
    }
}

impl Device {
    pub fn new(
        hostname: String,
        name: Option<String>,
        owner: Owner,
        device_type: DeviceType,
    ) -> Self {
        Self {
            device_id: uuid::Uuid::new_v4(),
            hostname,
            name,
            system_identity: None,
            owner,
            device_type,
            routes: Vec::new(),
            interfaces: Vec::new(),
            ipsec_peers: Vec::new(),
        }
    }

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.hostname)
    }

    pub fn find_interface_by_id(&self, interface_id: &str) -> Option<&Interface> {
        self.interfaces
            .iter()
            .find(|iface| iface.interface_id(&self.device_id) == interface_id)
    }

    pub fn with_routes(self, routes: Vec<Route>) -> Self {
        Self { routes, ..self }
    }
    pub fn with_interfaces(self, interfaces: Vec<Interface>) -> Self {
        Self { interfaces, ..self }
    }
    pub fn with_system_identity(self, system_identity: Option<String>) -> Self {
        Self {
            system_identity,
            ..self
        }
    }
    pub fn with_ipsec_peers(self, ipsec_peers: Vec<IpsecPeer>) -> Self {
        Self {
            ipsec_peers,
            ..self
        }
    }
}

#[cfg(test)]
pub(crate) fn setup_test_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_test_writer()
                .with_level(true),
        )
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .try_init();
}

#[cfg(test)]
mod lib_tests {
    use super::*;
    use cidr::Ipv4Cidr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_device_type_display() {
        assert_eq!(DeviceType::Router.to_string(), "Router");
        assert_eq!(DeviceType::Switch.to_string(), "Switch");
        assert_eq!(DeviceType::Firewall.to_string(), "Firewall");
        assert_eq!(DeviceType::AccessPoint.to_string(), "Access Point");
    }

    #[test]
    fn test_device_type_debug() {
        let debug_output = format!("{:?}", DeviceType::Router);
        assert!(debug_output.contains("Router"));
    }

    #[test]
    fn test_owner_from_string() {
        assert!(matches!(Owner::from(String::new()), Owner::Unknown));
        assert!(matches!(Owner::from("".to_string()), Owner::Unknown));

        let owner = Owner::from("Test Owner".to_string());
        if let Owner::Named(name) = owner {
            assert_eq!(name, "Test Owner");
        } else {
            panic!("Expected Named owner");
        }
    }

    #[test]
    fn test_owner_serialization() {
        let unknown = Owner::Unknown;
        let named = Owner::Named("Test".to_string());

        // Test that they can be serialized/deserialized
        let unknown_json = serde_json::to_string(&unknown).unwrap();
        let named_json = serde_json::to_string(&named).unwrap();

        assert!(unknown_json.contains("Unknown"));
        assert!(named_json.contains("Test"));

        let deserialized_unknown: Owner = serde_json::from_str(&unknown_json).unwrap();
        let deserialized_named: Owner = serde_json::from_str(&named_json).unwrap();

        assert!(matches!(deserialized_unknown, Owner::Unknown));
        if let Owner::Named(name) = deserialized_named {
            assert_eq!(name, "Test");
        } else {
            panic!("Expected Named owner after deserialization");
        }
    }

    #[test]
    fn test_interface_type_display() {
        assert_eq!(InterfaceType::Ethernet.to_string(), "ether");
        assert_eq!(InterfaceType::Vlan.to_string(), "vlan");
        assert_eq!(InterfaceType::Bridge.to_string(), "bridge");
        assert_eq!(InterfaceType::Loopback.to_string(), "loopback");
        assert_eq!(InterfaceType::VirtualEthernet.to_string(), "veth");
        assert_eq!(
            InterfaceType::Other("custom".to_string()).to_string(),
            "custom"
        );
    }

    #[test]
    fn test_interface_type_from_str() {
        assert_eq!(InterfaceType::from("bridge"), InterfaceType::Bridge);
        assert_eq!(InterfaceType::from("ether"), InterfaceType::Ethernet);
        assert_eq!(InterfaceType::from("ethernet"), InterfaceType::Ethernet);
        assert_eq!(InterfaceType::from("vlan"), InterfaceType::Vlan);
        assert_eq!(InterfaceType::from("loopback"), InterfaceType::Loopback);
        assert_eq!(InterfaceType::from("veth"), InterfaceType::VirtualEthernet);
        assert_eq!(
            InterfaceType::from("unknown"),
            InterfaceType::Other("unknown".to_string())
        );
    }

    #[test]
    fn test_trailfinder_error_display() {
        let ssh_error = TrailFinderError::Ssh(crate::ssh::SshError::Timeout);
        assert_eq!(ssh_error.to_string(), "SSH error: Operation timed out");

        let generic_error = TrailFinderError::Generic("Test error".to_string());
        assert_eq!(generic_error.to_string(), "Generic error: Test error");

        let config_error = TrailFinderError::Config("Invalid config".to_string());
        assert_eq!(config_error.to_string(), "Config error: Invalid config");

        let not_found_error = TrailFinderError::NotFound("Device not found".to_string());
        assert_eq!(
            not_found_error.to_string(),
            "Not found error: Device not found"
        );

        let parse_error = TrailFinderError::Parse("Parse failed".to_string());
        assert_eq!(parse_error.to_string(), "Parse error: Parse failed");

        let invalid_line_error = TrailFinderError::InvalidLine("Bad line".to_string());
        assert_eq!(invalid_line_error.to_string(), "Invalid line: Bad line");

        let serde_error = TrailFinderError::Serde("JSON error".to_string());
        assert_eq!(serde_error.to_string(), "Serde error: JSON error");
    }

    #[test]
    fn test_trailfinder_error_from_ssh_error() {
        let ssh_err = crate::ssh::SshError::Timeout;
        let tf_err: TrailFinderError = ssh_err.into();
        assert!(matches!(tf_err, TrailFinderError::Ssh(_)));
    }

    #[test]
    fn test_trailfinder_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let tf_err: TrailFinderError = io_err.into();
        assert!(matches!(tf_err, TrailFinderError::Io(_)));
    }

    #[test]
    fn test_trailfinder_error_from_serde_json_error() {
        let invalid_json = "{ invalid json";
        let serde_err = serde_json::from_str::<serde_json::Value>(invalid_json).unwrap_err();
        let tf_err: TrailFinderError = serde_err.into();
        assert!(matches!(tf_err, TrailFinderError::Serde(_)));
    }

    #[test]
    fn test_device_new() {
        let device = Device::new(
            "test-router".to_string(),
            Some("Test Router".to_string()),
            Owner::Named("Lab".to_string()),
            DeviceType::Router,
        );

        assert_eq!(device.hostname, "test-router");
        assert_eq!(device.name, Some("Test Router".to_string()));
        assert!(matches!(device.owner, Owner::Named(ref name) if name == "Lab"));
        assert_eq!(device.device_type, DeviceType::Router);
        assert!(device.routes.is_empty());
        assert!(device.interfaces.is_empty());
        assert!(device.system_identity.is_none());
        // device_id should be a valid UUID
        assert_ne!(device.device_id, uuid::Uuid::nil());
    }

    #[test]
    fn test_device_display_name() {
        let device_with_name = Device::new(
            "router1".to_string(),
            Some("Main Router".to_string()),
            Owner::Unknown,
            DeviceType::Router,
        );
        assert_eq!(device_with_name.display_name(), "Main Router");

        let device_without_name = Device::new(
            "router2".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Router,
        );
        assert_eq!(device_without_name.display_name(), "router2");
    }

    #[test]
    fn test_device_find_interface_by_id() {
        let mut device = Device::new(
            "test-device".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Router,
        );

        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        );
        let interface_id = interface.interface_id(&device.device_id);
        device.interfaces.push(interface);

        let found = device.find_interface_by_id(&interface_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "eth0");

        let not_found = device.find_interface_by_id("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_device_with_routes() {
        let device = Device::new(
            "router".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Router,
        );

        let route = Route {
            route_type: RouteType::Default(uuid::Uuid::new_v4()),
            target: cidr::IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap()),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            distance: Some(1),
        };

        let device_with_routes = device.with_routes(vec![route]);
        assert_eq!(device_with_routes.routes.len(), 1);
    }

    #[test]
    fn test_device_with_interfaces() {
        let device = Device::new(
            "switch".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Switch,
        );

        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        );
        let device_with_interfaces = device.with_interfaces(vec![interface]);
        assert_eq!(device_with_interfaces.interfaces.len(), 1);
        assert_eq!(device_with_interfaces.interfaces[0].name, "eth0");
    }

    #[test]
    fn test_device_with_system_identity() {
        let device = Device::new(
            "router".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Router,
        );

        let device_with_identity = device.with_system_identity(Some("System Identity".to_string()));
        assert_eq!(
            device_with_identity.system_identity,
            Some("System Identity".to_string())
        );

        let device2 = Device::new(
            "router".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Router,
        );
        let device_without_identity = device2.with_system_identity(None);
        assert!(device_without_identity.system_identity.is_none());
    }

    #[test]
    fn test_device_serialization() {
        let device = Device::new(
            "test-device".to_string(),
            Some("Test Device".to_string()),
            Owner::Named("Lab".to_string()),
            DeviceType::Router,
        );

        let json = serde_json::to_string(&device).unwrap();
        let deserialized: Device = serde_json::from_str(&json).unwrap();

        assert_eq!(device.device_id, deserialized.device_id);
        assert_eq!(device.hostname, deserialized.hostname);
        assert_eq!(device.name, deserialized.name);
        assert_eq!(device.device_type, deserialized.device_type);
        assert!(matches!(deserialized.owner, Owner::Named(ref name) if name == "Lab"));
    }

    #[test]
    fn test_interface_new() {
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        );

        assert_eq!(interface.name, "eth0");
        assert_eq!(interface.interface_type, InterfaceType::Ethernet);
        assert!(interface.vlans.is_empty());
        assert!(interface.addresses.is_empty());
        assert!(interface.comment.is_none());
        assert!(interface.mac_address.is_none());
        assert!(interface.peers.is_empty());
    }

    #[test]
    fn test_interface_id_generation() {
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        );
        let device_id = uuid::Uuid::new_v4();

        let id1 = interface.interface_id(&device_id);
        let id2 = interface.interface_id(&device_id);

        // Should be deterministic for same interface and device
        assert_eq!(id1, id2);

        // Should be different for different device
        let other_device_id = uuid::Uuid::new_v4();
        let id3 = interface.interface_id(&other_device_id);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_interface_with_builder_pattern() {
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            Some("Test interface".to_string()),
        )
        .with_mac_address(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));

        assert_eq!(interface.comment, Some("Test interface".to_string()));
        assert!(interface.mac_address.is_some());
    }

    #[test]
    fn test_route_construction() {
        let route_type = RouteType::Default(uuid::Uuid::new_v4());
        let target = cidr::IpCidr::V4(Ipv4Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap());
        let gateway = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let distance = Some(1);

        let route = Route {
            route_type: route_type.clone(),
            target,
            gateway,
            distance,
        };

        assert!(matches!(route.route_type, RouteType::Default(_)));
        assert_eq!(route.target, target);
        assert_eq!(route.gateway, gateway);
        assert_eq!(route.distance, distance);
    }

    #[test]
    fn test_route_type_variants() {
        let interface_id = uuid::Uuid::new_v4();

        let local_route = RouteType::Local(interface_id);
        assert!(matches!(local_route, RouteType::Local(_)));

        let default_route = RouteType::Default(interface_id);
        assert!(matches!(default_route, RouteType::Default(_)));

        let nexthop_route = RouteType::NextHop(interface_id);
        assert!(matches!(nexthop_route, RouteType::NextHop(_)));
    }

    #[test]
    fn test_cidr_parsing_edge_cases() {
        // Test various CIDR formats that should be valid
        let ipv4_cidr = "192.168.1.0/24".parse::<cidr::Ipv4Cidr>();
        assert!(ipv4_cidr.is_ok());

        let ipv6_cidr = "2001:db8::/32".parse::<cidr::Ipv6Cidr>();
        assert!(ipv6_cidr.is_ok());

        // Test invalid CIDR formats
        let invalid_cidr = "invalid.cidr".parse::<cidr::Ipv4Cidr>();
        assert!(invalid_cidr.is_err());
    }

    #[test]
    fn test_mac_address_handling() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        )
        .with_mac_address(mac);

        assert!(interface.mac_address.is_some());
        assert_eq!(interface.mac_address.unwrap(), mac);
    }

    #[test]
    fn test_upstream_enum() {
        let internet = Upstream::Internet;
        assert!(matches!(internet, Upstream::Internet));

        let gateway = Upstream::Gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(matches!(gateway, Upstream::Gateway(_)));
    }

    #[test]
    fn test_empty_device_collections() {
        let device = Device::new(
            "empty-device".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Router,
        );

        assert!(device.routes.is_empty());
        assert!(device.interfaces.is_empty());
        assert!(device.find_interface_by_id("any-id").is_none());
    }

    #[test]
    fn test_device_with_multiple_interfaces() {
        let device = Device::new(
            "multi-interface".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Switch,
        );

        let interfaces = vec![
            Interface::new(
                uuid::Uuid::new_v4(),
                "eth0".to_string(),
                vec![],
                vec![],
                InterfaceType::Ethernet,
                None,
            ),
            Interface::new(
                uuid::Uuid::new_v4(),
                "eth1".to_string(),
                vec![],
                vec![],
                InterfaceType::Ethernet,
                None,
            ),
            Interface::new(
                uuid::Uuid::new_v4(),
                "vlan100".to_string(),
                vec![100],
                vec![],
                InterfaceType::Vlan,
                None,
            ),
        ];

        let device_with_interfaces = device.with_interfaces(interfaces);
        assert_eq!(device_with_interfaces.interfaces.len(), 3);

        // Test finding each interface
        for interface in &device_with_interfaces.interfaces {
            let id = interface.interface_id(&device_with_interfaces.device_id);
            let found = device_with_interfaces.find_interface_by_id(&id);
            assert!(found.is_some());
            assert_eq!(found.unwrap().name, interface.name);
        }
    }

    #[test]
    fn test_interface_with_vlans() {
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![100, 200],
            vec![],
            InterfaceType::Ethernet,
            None,
        );

        assert_eq!(interface.vlans.len(), 2);
        assert!(interface.vlans.contains(&100));
        assert!(interface.vlans.contains(&200));
    }

    #[test]
    fn test_interface_with_addresses() {
        let addr = InterfaceAddress {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            prefix_length: 24,
        };
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![addr],
            InterfaceType::Ethernet,
            None,
        );

        assert_eq!(interface.addresses.len(), 1);
        assert_eq!(
            interface.addresses[0].ip,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(interface.addresses[0].prefix_length, 24);
    }

    #[test]
    fn test_interface_peers() {
        let mut interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            None,
        );

        // Test peers
        interface.peers.insert(
            PeerConnection::Untagged,
            vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()],
        );

        assert_eq!(interface.peers.len(), 1);
        assert!(interface.peers.contains_key(&PeerConnection::Untagged));
        assert_eq!(interface.peers[&PeerConnection::Untagged].len(), 2);
    }

    #[test]
    fn test_interface_serialization() {
        let interface = Interface::new(
            uuid::Uuid::new_v4(),
            "eth0".to_string(),
            vec![],
            vec![],
            InterfaceType::Ethernet,
            Some("Test interface".to_string()),
        )
        .with_mac_address(MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));

        let json = serde_json::to_string(&interface).expect("Failed to serialize interface");
        let deserialized: Interface =
            serde_json::from_str(&json).expect("Failed to deserialize interface");

        assert_eq!(interface.name, deserialized.name);
        assert_eq!(interface.interface_type, deserialized.interface_type);
        assert_eq!(interface.comment, deserialized.comment);
        assert_eq!(interface.mac_address, deserialized.mac_address);
    }

    #[test]
    fn test_route_serialization() {
        let route = Route {
            route_type: RouteType::Default(uuid::Uuid::new_v4()),
            target: cidr::IpCidr::V4(
                Ipv4Cidr::new(Ipv4Addr::new(0, 0, 0, 0), 0).expect("Valid CIDR"),
            ),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            distance: Some(1),
        };

        let json = serde_json::to_string(&route).expect("Failed to serialize route");
        let deserialized: Route = serde_json::from_str(&json).expect("Failed to deserialize route");

        assert_eq!(route.target, deserialized.target);
        assert_eq!(route.gateway, deserialized.gateway);
        assert_eq!(route.distance, deserialized.distance);
    }
}
