use std::{fmt::Display, net::IpAddr};

use cidr::errors::NetworkParseError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ssh::SshError;

pub mod brand;
pub mod config;
pub mod ssh;
pub mod web;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Owner {
    Unknown,
    Named(String),
}

impl From<String> for Owner {
    fn from(name: String) -> Self {
        if name.is_empty() {
            Owner::Unknown
        } else {
            Owner::Named(name)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub device_id: uuid::Uuid,
    pub hostname: String,
    pub name: Option<String>,
    pub owner: Owner,
    pub device_type: DeviceType,
    pub routes: Vec<Route>,
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Upstream {
    Internet,
    Gateway(IpAddr),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    Ssh(SshError),
    Generic(String),
    Config(String),
    NotFound(String),
    Parse(String),
    InvalidLine(String),
    Regex(regex::Error),
    Serde(String),
    Io(std::io::Error),
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
            TrailFinderError::Parse(msg) => write!(f, "Parse error: {}", msg),
            TrailFinderError::InvalidLine(msg) => write!(f, "Invalid line: {}", msg),
            TrailFinderError::Regex(error) => write!(f, "Regex error: {}", error),
            TrailFinderError::Serde(error) => write!(f, "Serde error: {}", error),
            TrailFinderError::Io(error) => write!(f, "IO error: {}", error),
            TrailFinderError::NotFound(error) => write!(f, "Not found error: {}", error),
            TrailFinderError::Config(error) => write!(f, "Config error: {}", error),
            TrailFinderError::Generic(error) => write!(f, "Generic error: {}", error),
            TrailFinderError::Ssh(error) => write!(f, "SSH error: {}", error),
        }
    }
}

impl std::error::Error for TrailFinderError {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Interface {
    pub interface_id: Uuid,
    pub name: String,
    pub vlan: Option<u16>,
    pub addresses: Vec<IpAddr>, // TODO: these should be CIDR's because addresses have subnet masks
    pub interface_type: InterfaceType,
    pub comment: Option<String>,

    neighbour_string_data: Option<String>,
    peer: Option<Uuid>,
}

impl Interface {
    pub fn new(
        interface_id: Uuid,
        name: String,
        vlan: Option<u16>,
        addresses: Vec<IpAddr>,
        interface_type: InterfaceType,
        comment: Option<String>,
    ) -> Self {
        Self {
            interface_id,
            name,
            vlan,
            addresses,
            interface_type,
            comment,
            neighbour_string_data: None,
            peer: None,
        }
    }

    pub fn interface_id(&self, device_id: &uuid::Uuid) -> String {
        format!("{}:{}:{}", device_id, self.name, self.interface_type)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RouteType {
    Default(Uuid),
    /// Has a gateway
    NextHop(Uuid),
    /// Local to the interface (id)
    Local(Uuid),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Route {
    pub route_type: RouteType,
    pub target: cidr::IpCidr,
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
            owner,
            device_type,
            routes: Vec::new(),
            interfaces: Vec::new(),
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
                .with_level(true)
                .with_writer(std::io::stdout),
        )
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .try_init();
}
