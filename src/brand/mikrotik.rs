use cidr::IpCidr;
use regex::Regex;
use tracing::debug;
use tracing::error;
use tracing::info;
use uuid::Uuid;

use super::prelude::*;
use crate::config::{DeviceConfig, DeviceState};
use crate::ssh::SshClient;

pub struct Mikrotik {
    hostname: String,
    name: Option<String>,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
}

pub(crate) fn find_kv(parts: &Vec<&str>, key: &str) -> Option<String> {
    parts
        .iter()
        .find(|&&part| part.starts_with(&format!("{key}=")))
        .map(|s| {
            let comment = s.trim_start_matches(&format!("{key}=")).to_string();
            // strip leading/trailing quotes
            if comment.starts_with('"') && comment.ends_with('"') {
                comment[1..comment.len() - 1].to_string()
            } else {
                comment
            }
        })
}

impl DeviceHandler for Mikrotik {
    fn new(hostname: String, name: Option<String>, owner: Owner, device_type: DeviceType) -> Self {
        Self {
            hostname,
            name,
            owner,
            device_type,
            routes: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    fn interface_by_name(&self, name: &str) -> Option<Uuid> {
        self.interfaces
            .iter()
            .find(|iface| iface.name == name)
            .map(|iface| iface.interface_id)
    }

    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        debug!("input_data: {input_data}");

        let comment_finder = regex::Regex::new(r#";;; (?P<comment>.*?) name=""#)
            .expect("Failed to compile comment-finder regex");

        let mut current_line = String::new();
        let lines = input_data.lines();
        let line_count = lines.clone().count();
        for (line_num, line) in lines.enumerate() {
            let line = line.trim();
            debug!("Parsing line: {line}");
            if line.starts_with('#')
                || line.starts_with(';')
                || line.starts_with("Flags:")
                || line.starts_with("Columns:")
                || line.starts_with("P - passthrough")
            {
                current_line.clear();
                continue;
            }

            if !line.is_empty() {
                current_line.push(' ');
                current_line.push_str(line);
                // debug!("updated line to be {current_line}");
                continue;
            }

            if (!current_line.is_empty() && line.is_empty()) || line_count - 1 == line_num {
                debug!("Found a full line: {current_line}");
            }

            let parts: Vec<&str> = current_line.split_whitespace().collect();

            // Try to find name= first, then default-name=
            let name = find_kv(&parts, "name").ok_or_else(|| {
                TrailFinderError::InvalidLine(format!("Missing name in line: {line}"))
            })?;

            let vlan: Option<u16> = match find_kv(&parts, "vlan_id") {
                Some(vlan_str) => {
                    let res: u16 = vlan_str.parse().map_err(|err| {
                        TrailFinderError::Parse(format!("Invalid vlan_id: {}", err))
                    })?;
                    Some(res)
                }
                None => None,
            };

            // Extract the interface type from the path, not from parts[2] which is the command
            let interface_type: InterfaceType = InterfaceType::from(
                find_kv(&parts, "type")
                    .ok_or_else(|| {
                        TrailFinderError::InvalidLine(format!("Missing type in line: {line}"))
                    })?
                    .as_str(),
            );

            let comment = comment_finder
                .captures(&current_line)
                .and_then(|caps| caps.name("comment").map(|m| m.as_str().to_string()));

            let interface = Interface {
                interface_id: Uuid::new_v4(),
                name,
                vlan,
                addresses: Vec::new(),
                interface_type,
                comment,
                neighbour_string_data: None,
                peer: None,
            };
            debug!("Adding interface: {interface:?}");
            self.interfaces.push(interface);

            if !current_line.is_empty() && line.is_empty() {
                current_line.clear();
            }
        }

        Ok(())
    }

    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        debug!("Parsing Mikrotik routes: {input_data}");
        let mut current_line = String::new();

        let lines = input_data.lines();
        let line_count = lines.clone().count();

        for (line_num, line) in lines.enumerate() {
            if line.starts_with("Flags:") {
                continue;
            }

            if !line.is_empty() && line.starts_with(' ') {
                current_line.push(' ');
                current_line.push_str(line);
                // debug!("updated line to be {current_line}");
                if line_count - 1 != line_num {
                    continue;
                }
            } else if line.is_empty() {
                // debug!("Empty line...");
            } else {
                debug!("Ignoring line: '{line}'");
                continue;
            }

            if (!current_line.is_empty() && line.is_empty()) || line_count - 1 == line_num {
                debug!("Found a full line: {current_line}");
            }

            let parts: Vec<&str> = current_line.split_whitespace().collect();

            let route_addr = find_kv(&parts, "dst-address").ok_or_else(|| {
                TrailFinderError::InvalidLine(format!("Missing dst-address in line: {}", line))
            })?;

            if route_addr.to_ascii_lowercase().starts_with("fe80::") {
                debug!("Ignoring link-local IPv6 address: {route_addr}");
                current_line.clear();
                continue;
            }

            let target: IpCidr = match find_kv(&parts, "dst-address") {
                Some(target_str) => target_str.parse()?,
                None => {
                    return Err(TrailFinderError::InvalidLine(format!(
                        "Missing dst-address in line: {}",
                        line
                    )));
                }
            };

            let distance: Option<u16> = match find_kv(&parts, "distance") {
                Some(vlan_str) => {
                    let res: u16 = vlan_str.parse().map_err(|err| {
                        TrailFinderError::Parse(format!("Invalid distance: {}", err))
                    })?;
                    Some(res)
                }
                None => None,
            };

            let route_type = if route_addr == "0.0.0.0/0" {
                RouteType::Default(uuid::Uuid::new_v4())
            } else if let Some(immediate_gw) = find_kv(&parts, "immediate-gw") {
                // Extract interface name from immediate-gw (it might be "interface" or "address%interface")
                let _interface_name = if let Some(percent_pos) = immediate_gw.find('%') {
                    &immediate_gw[percent_pos + 1..]
                } else {
                    &immediate_gw
                };

                // For now, just create a placeholder UUID - we'll link properly during build if needed
                RouteType::Local(uuid::Uuid::new_v4())
            } else {
                RouteType::NextHop(uuid::Uuid::new_v4())
            };

            // Parse gateway - could be IP address or interface name
            let gateway = find_kv(&parts, "gateway").and_then(|gw_str| {
                // First try to parse as IP address
                if let Ok(ip) = gw_str.parse::<std::net::IpAddr>() {
                    Some(ip)
                } else {
                    // If it's not an IP, it might be an interface name
                    // We'll need to resolve this to an IP later by looking up the interface
                    // For now, we'll look at immediate-gw which often has the actual IP
                    find_kv(&parts, "immediate-gw").and_then(|immediate_gw| {
                        // immediate-gw might be "192.168.1.1%ether1" or just "vlan10"
                        if let Some(percent_pos) = immediate_gw.find('%') {
                            // Extract IP part before %
                            immediate_gw[..percent_pos].parse::<std::net::IpAddr>().ok()
                        } else {
                            // Try parsing the whole thing as IP
                            immediate_gw.parse::<std::net::IpAddr>().ok()
                        }
                    })
                }
            });

            let route = Route {
                target,
                route_type,
                gateway,
                distance,
            };
            // if let Ok(addr) = target.parse::<IpAddr>() {
            //     route.gateway = Some(addr);
            // } else {
            //     // Look for existing interface by name - will be set properly after build
            //     if let Some(existing_interface) =
            //         self.interfaces.iter().find(|iface| iface.name == target)
            //     {
            //         route.interface_id = Some(existing_interface.interface_id)
            //     } else {
            //         // Create a stub interface if not found and add it to interfaces
            //         let stub_interface = Interface {
            //             interface_id: Uuid::new_v4(),
            //             name: target.to_string(),
            //             vlan: None,
            //             addresses: Vec::new(),
            //             interface_type: InterfaceType::Other(target.to_string()),
            //             comment: Some("Referenced from route, not in interface list".to_string()),
            //         };

            //         self.interfaces.push(stub_interface);
            //     }
            // }
            info!("Adding route {route:?}");
            self.routes.push(route);
            if line.is_empty() {
                current_line.clear();
            }
        }
        Ok(())
    }

    fn parse_neighbours(
        &mut self,
        input_data: &str,
        devices: Vec<Device>,
    ) -> Result<usize, TrailFinderError> {
        let mut mods_made = 0;
        let line_parser = Regex::new(
            r#"(?P<interface_id>\d+)\s+(?P<interface_name>\S+)\s+(?P<peer_address>\S+)\s+(?P<peer_mac>\S+)\s+(?P<peer_identity>\S+)"#,
        )?;

        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("Columns:") {
                continue;
            }
            debug!("Parsing CDP line: {line}");
            if let Some(caps) = line_parser.captures(line) {
                let interface_name = caps
                    .name("interface_name")
                    .map(|m| m.as_str())
                    .unwrap_or("");
                // let peer_address = caps.name("peer_address").map(|m| m.as_str()).unwrap_or("");
                // let peer_mac = caps.name("peer_mac").map(|m| m.as_str()).unwrap_or("");
                let peer_identity = caps.name("peer_identity").map(|m| m.as_str()).unwrap_or("");

                // Do something with the extracted values

                // find if we have this interface
                if let Some(existing_interface) = self
                    .interfaces
                    .iter_mut()
                    .find(|iface| iface.name == interface_name)
                {
                    // Interface exists, do something with it
                    existing_interface.neighbour_string_data = Some(line.to_string());
                    mods_made += 1;

                    // try and find the peer identity in the devices list
                    if let Some(peer) = devices.iter().find(|p| p.hostname == peer_identity) {
                        existing_interface.peer = Some(peer.device_id);
                        mods_made += 1;
                    }
                } else {
                    error!("Don't have interface {interface_name} found in CDP data?");
                    continue;
                }
            }
        }

        Ok(mods_made)
    }

    fn build(self) -> Device {
        Device::new(self.hostname, self.name, self.owner, self.device_type)
            .with_routes(self.routes)
            .with_interfaces(self.interfaces)
    }

    fn get_cdp_command(&self) -> String {
        "/ip neighbor/print".to_string()
    }

    fn get_interfaces_command(&self) -> String {
        "/interface print without-paging detail".to_string()
    }

    fn get_routes_command(&self) -> String {
        "/ipv6 route print detail without-paging; /ip route print detail without-paging".to_string()
    }

    #[allow(clippy::manual_async_fn)]
    fn interrogate_device(
        &self,
        ssh_client: &mut SshClient,
        device_config: &DeviceConfig,
        device_type: DeviceType,
    ) -> impl std::future::Future<Output = Result<DeviceState, TrailFinderError>> + Send {
        async move {
            // Get interfaces data
            let interfaces_command = self.get_interfaces_command();
            let interfaces_output = ssh_client.execute_command(&interfaces_command).await?;

            // Get routes data
            let routes_command = self.get_routes_command();
            let routes_output = ssh_client.execute_command(&routes_command).await?;

            // Parse the data using the existing ConfParser implementation
            let mut parser = Mikrotik::new(
                device_config.hostname.clone(),
                None, // DeviceConfig doesn't have a name field
                device_config.owner.clone(),
                device_type,
            );

            parser.parse_interfaces(&interfaces_output)?;
            parser.parse_routes(&routes_output)?;

            let device = parser.build();

            // Combine both outputs for config hash
            let combined_config = format!(
                "{}
{}",
                interfaces_output, routes_output
            );
            Ok(DeviceState::new(device, &combined_config))
        }
    }
}

#[test]
fn test_parse_mikrotik() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let interfaces_input =
        read_to_string("mikrotik_interfaces.txt").expect("Failed to read interfaces file");
    let routes_input = read_to_string("mikrotik_routes.txt").expect("Failed to read routes file");

    let mut parser = Mikrotik::new(
        "test-router.example.com".to_string(),
        Some("test-router".to_string()),
        Owner::Named("Test Lab".to_string()),
        DeviceType::Router,
    );

    // Parse interfaces first
    let interface_result = parser.parse_interfaces(&interfaces_input);
    assert!(interface_result.is_ok(), "Interface parsing should succeed");

    // Parse routes
    let route_result = parser.parse_routes(&routes_input);
    assert!(route_result.is_ok(), "Route parsing should succeed");

    // Build final device
    let device = parser.build();

    // Validate interface parsing results
    assert!(
        !device.interfaces.is_empty(),
        "Should have parsed interfaces"
    );
    assert!(
        device.interfaces.len() >= 10,
        "Should have multiple interfaces"
    );

    // Check for specific interface types
    let bridge_interfaces: Vec<_> = device
        .interfaces
        .iter()
        .filter(|iface| matches!(iface.interface_type, InterfaceType::Bridge))
        .collect();
    assert!(
        !bridge_interfaces.is_empty(),
        "Should have bridge interfaces"
    );

    let ethernet_interfaces: Vec<_> = device
        .interfaces
        .iter()
        .filter(|iface| matches!(iface.interface_type, InterfaceType::Ethernet))
        .collect();
    assert!(
        !ethernet_interfaces.is_empty(),
        "Should have ethernet interfaces"
    );

    let vlan_interfaces: Vec<_> = device
        .interfaces
        .iter()
        .filter(|iface| matches!(iface.interface_type, InterfaceType::Vlan))
        .collect();
    assert!(!vlan_interfaces.is_empty(), "Should have VLAN interfaces");

    // Validate route parsing results
    assert!(!device.routes.is_empty(), "Should have parsed routes");
    assert!(device.routes.len() >= 5, "Should have multiple routes");

    // Check for default route
    let default_routes: Vec<_> = device
        .routes
        .iter()
        .filter(|route| matches!(route.route_type, RouteType::Default(_)))
        .collect();
    assert!(!default_routes.is_empty(), "Should have default route");

    // Validate interface ID generation works
    if let Some(first_interface) = device.interfaces.first() {
        let interface_id = first_interface.interface_id(&device.device_id);
        assert!(!interface_id.is_empty(), "Interface ID should not be empty");
        assert!(
            interface_id.contains(&device.device_id.to_string()),
            "Interface ID should contain device ID"
        );
        assert!(
            interface_id.contains(&first_interface.name),
            "Interface ID should contain interface name"
        );
    }

    // Test interface lookup by ID
    if let Some(first_interface) = device.interfaces.first() {
        let interface_id = first_interface.interface_id(&device.device_id);
        let found_interface = device.find_interface_by_id(&interface_id);
        assert!(
            found_interface.is_some(),
            "Should be able to find interface by ID"
        );
        assert_eq!(
            found_interface.unwrap().name,
            first_interface.name,
            "Found interface should match original"
        );
    }

    println!(
        "✅ Parsed {} interfaces and {} routes successfully",
        device.interfaces.len(),
        device.routes.len()
    );
}

#[test]
fn test_mikrotik_interface_types() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let interfaces_input =
        read_to_string("mikrotik_interfaces.txt").expect("Failed to read interfaces file");

    let mut parser = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );
    parser
        .parse_interfaces(&interfaces_input)
        .expect("Failed to parse interfaces");
    let device = parser.build();

    // Check that we parsed different interface types correctly
    let interface_types: std::collections::HashMap<String, usize> = device
        .interfaces
        .iter()
        .map(|iface| format!("{:?}", iface.interface_type))
        .fold(std::collections::HashMap::new(), |mut acc, itype| {
            *acc.entry(itype).or_insert(0) += 1;
            acc
        });

    println!("Interface type distribution: {:?}", interface_types);

    // Should have multiple types
    assert!(
        interface_types.len() >= 3,
        "Should have multiple interface types"
    );
    assert!(
        interface_types.contains_key("Bridge"),
        "Should have Bridge interfaces"
    );
    assert!(
        interface_types.contains_key("Ethernet"),
        "Should have Ethernet interfaces"
    );
    assert!(
        interface_types.contains_key("Vlan"),
        "Should have VLAN interfaces"
    );
}

#[test]
fn test_mikrotik_route_types() {
    crate::setup_test_logging();

    use std::fs::read_to_string;

    let routes_input = read_to_string("mikrotik_routes.txt").expect("Failed to read routes file");

    let mut parser = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );
    parser
        .parse_routes(&routes_input)
        .expect("Failed to parse routes");
    let device = parser.build();

    // Check that we have both default and specific routes
    let default_count = device
        .routes
        .iter()
        .filter(|route| matches!(route.route_type, RouteType::Default(_)))
        .count();
    let specific_count = device
        .routes
        .iter()
        .filter(|route| matches!(route.route_type, RouteType::NextHop(_)))
        .count();

    assert!(default_count > 0, "Should have default routes");
    assert!(specific_count > 0, "Should have specific routes");

    println!(
        "✅ Found {} default routes and {} specific routes",
        default_count, specific_count
    );
}

#[test]
fn test_mikrotik_cdp() {
    use crate::brand::cisco::Cisco;

    let test_data = r#"Columns: INTERFACE, ADDRESS, MAC-ADDRESS, IDENTITY
#  INTERFACE     ADDRESS    MAC-ADDRESS        IDENTITY
0  sfp-sfpplus1  10.0.99.2  A0:23:9F:FF:FF:33  test-cisco.example.com
   bridge"#;

    let mut device = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let test_cisco = Cisco::test_device().build();
    let result = device.parse_neighbours(test_data, vec![test_cisco]);
    assert!(result.is_ok(), "CDP parsing should succeed");
}
