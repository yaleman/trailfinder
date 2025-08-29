use std::{fmt::Display, net::IpAddr};

use serde::{Deserialize, Serialize};

pub mod brand;
pub mod config;
pub mod ssh;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DeviceType {
    Router,
    Switch,
    Firewall,
    AccessPoint,
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
    pub name: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub enum TrailFinderError {
    Parse(String),
    InvalidLine(String),
}

impl std::fmt::Display for TrailFinderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrailFinderError::Parse(msg) => write!(f, "Parse error: {}", msg),
            TrailFinderError::InvalidLine(msg) => write!(f, "Invalid line: {}", msg),
        }
    }
}

impl std::error::Error for TrailFinderError {}

#[derive(Debug, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub vlan: Option<u16>,
    pub addresses: Vec<IpAddr>,
    pub interface_type: InterfaceType,
    pub comment: Option<String>,
    // TODO: do we want to have gateways here?
}

impl Interface {
    pub fn interface_id(&self, device_name: &str) -> String {
        format!("{}:{}:{}", device_name, self.name, self.interface_type)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RouteType {
    Default,
    Specific,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Route {
    pub route_type: RouteType,
    pub interface_id: Option<String>,
    pub gateway: Option<IpAddr>,
    pub distance: Option<u16>,
}

impl Device {
    pub fn new(name: Option<String>, owner: Owner, device_type: DeviceType) -> Self {
        let name = name.unwrap_or(uuid::Uuid::new_v4().to_string());
        Self {
            name,
            owner,
            device_type,
            routes: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    pub fn find_interface_by_id(&self, interface_id: &str) -> Option<&Interface> {
        self.interfaces
            .iter()
            .find(|iface| iface.interface_id(&self.name) == interface_id)
    }
}
