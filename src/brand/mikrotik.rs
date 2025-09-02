use cidr::IpCidr;
use regex::Regex;
use tracing::debug;
use tracing::error;
use tracing::info;
use uuid::Uuid;

use super::prelude::*;
use crate::InterfaceAddress;
use crate::config::{DeviceConfig, DeviceState};

use crate::ssh::SshClient;

pub struct Mikrotik {
    hostname: String,
    name: Option<String>,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
    system_identity: Option<String>,
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
            system_identity: None,
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

            // Parse MAC address from mac-address= field
            let mac_address = find_kv(&parts, "mac-address").and_then(|mac_str| {
                use std::str::FromStr;
                mac_address::MacAddress::from_str(&mac_str)
                    .inspect_err(|e| {
                        debug!("Failed to parse MAC address '{}': {}", mac_str, e);
                    })
                    .ok()
            });

            let interface = Interface {
                interface_id: Uuid::new_v4(),
                name,
                vlans: vlan.map(|v| vec![v]).unwrap_or_default(),
                addresses: Vec::new(),
                interface_type,
                comment,
                mac_address,
                neighbour_string_data: Default::default(),
                peers: Default::default(),
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
                    if existing_interface.neighbour_string_data.get(peer_identity)
                        != Some(&line.to_string())
                    {
                        existing_interface
                            .neighbour_string_data
                            .insert(peer_identity.to_string(), line.to_string());
                        mods_made += 1;
                    }

                    // try and find the peer identity in the devices list
                    if let Some(peer) = devices.iter().find(|p| p.hostname == peer_identity) {
                        existing_interface
                            .peers
                            .entry(crate::PeerConnection::Untagged)
                            .or_default()
                            .push(peer.device_id);
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

    fn parse_identity(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        debug!("Parsing Mikrotik identity: {input_data}");
        for line in input_data.lines() {
            let line = line.trim();
            if line.starts_with("name:") {
                self.system_identity = Some(
                    line.strip_prefix("name:")
                        .ok_or(TrailFinderError::InvalidLine(
                            "Missing 'name:' prefix".to_string(),
                        ))?
                        .trim()
                        .to_string(),
                );
                return Ok(());
            }
        }

        Err(TrailFinderError::InvalidLine(
            "Missing identity data".to_string(),
        ))
    }

    fn build(self) -> Device {
        Device::new(self.hostname, self.name, self.owner, self.device_type)
            .with_routes(self.routes)
            .with_interfaces(self.interfaces)
            .with_system_identity(self.system_identity)
    }

    fn parse_ip_addresses(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        for line in input_data.lines() {
            let parts = line.split_whitespace().collect();
            if line.trim().is_empty() {
                continue;
            }
            debug!("handling line: {line}");
            if let Some(addr_str) = find_kv(&parts, "address") {
                let addr = match InterfaceAddress::try_from(addr_str.as_str()) {
                    Err(err) => {
                        error!("Failed to parse address '{}': {}", addr_str, err);
                        continue;
                    }
                    Ok(addr) => addr,
                };

                // see if we already have this assigned to an interface
                if !self
                    .interfaces
                    .iter()
                    .any(|iface| iface.addresses.contains(&addr))
                {
                    // we can carry on and add it
                    let interface_name = match find_kv(&parts, "actual-interface") {
                        Some(val) => val,
                        None => match find_kv(&parts, "interface") {
                            Some(val) => val,
                            None => {
                                error!("Could not find interface name for address {addr}");
                                continue;
                            }
                        },
                    };

                    debug!("Interface: {interface_name} address={addr}");
                    if let Some(existing_interface) = self
                        .interfaces
                        .iter_mut()
                        .find(|iface| iface.name == interface_name)
                    {
                        existing_interface.addresses.push(addr.clone());
                        info!(
                            "Added address {addr} to interface {}",
                            existing_interface.name
                        );
                    } else {
                        error!("Could not find interface {interface_name} for address {addr}");
                    }
                } else {
                    debug!("Already have {addr}");
                }
            } else {
                debug!("couldn't find an address kv!");
            }
        }
        Ok(())
    }

    fn get_cdp_command(&self) -> String {
        "/ip neighbor print terse without-paging proplist=interface,address,mac-address,identity"
            .to_string()
    }

    const GET_IP_COMMAND: &'static str = "/ip address print terse; /ipv6 address print terse";
    const GET_IDENTITY_COMMAND: &'static str = "/system identity print";

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
            // Parse the data using the existing ConfParser implementation
            let mut parser = Mikrotik::new(
                device_config.hostname.clone(),
                None, // DeviceConfig doesn't have a name field
                device_config.owner.clone(),
                device_type,
            );

            // Get interfaces data
            let interfaces_output = ssh_client
                .execute_command(&self.get_interfaces_command())
                .await?;

            parser.parse_interfaces(&interfaces_output)?;

            let routes_output = ssh_client
                .execute_command(&self.get_routes_command())
                .await?;
            parser.parse_routes(&routes_output)?;

            let cdp_output = ssh_client.execute_command(&self.get_cdp_command()).await?;

            // Store raw CDP data in interfaces for later global processing
            parser.store_raw_cdp_data(&cdp_output)?;

            // Get system identity
            let identity_output = ssh_client
                .execute_command(Self::GET_IDENTITY_COMMAND)
                .await
                .unwrap_or_default();
            parser.parse_identity(&identity_output)?;

            parser.parse_ip_addresses(
                ssh_client
                    .execute_command(Self::GET_IP_COMMAND)
                    .await?
                    .as_str(),
            )?;

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

impl Mikrotik {
    /// Store raw CDP/neighbor data in interfaces for later global processing
    pub fn store_raw_cdp_data(&mut self, input_data: &str) -> Result<usize, TrailFinderError> {
        debug!("Storing raw CDP data: {input_data}");
        // Parse MikroTik neighbor discovery output in terse format
        // Example format: 0 interface=sfp-sfpplus1,bridge address=10.0.99.2 mac-address=A0:23:9F:7B:2E:33 identity=C3650.example.com
        let mut mods_made = 0;

        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || !line.chars().next().unwrap_or(' ').is_ascii_digit() {
                continue;
            }

            debug!("Parsing neighbor line: {line}");

            // Split line into parts for key-value parsing
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Extract key values using find_kv
            let interface_name = find_kv(&parts, "interface");
            let peer_address = find_kv(&parts, "address");
            let _peer_mac = find_kv(&parts, "mac-address");
            let peer_identity = find_kv(&parts, "identity");

            if let (Some(interface_name), Some(peer_identity)) = (&interface_name, &peer_identity) {
                debug!(
                    "Found neighbor: interface={}, identity={}",
                    interface_name, peer_identity
                );

                // Handle comma-separated interface names (e.g., "sfp-sfpplus1,bridge")
                let interface_names: Vec<&str> = interface_name.split(',').collect();

                for iface_name in interface_names {
                    let iface_name = iface_name.trim();
                    if let Some(interface) = self
                        .interfaces
                        .iter_mut()
                        .find(|interface| interface.name == iface_name)
                    {
                        debug!(
                            "Successfully found peer interface: {} for peer: {}",
                            interface.name, peer_identity
                        );

                        // Create a unique key for this neighbor
                        let neighbor_key = if let Some(address) = &peer_address {
                            format!("{}@{}", peer_identity, address)
                        } else {
                            peer_identity.clone()
                        };

                        // Store the entire line as raw neighbor data for this interface
                        interface
                            .neighbour_string_data
                            .insert(neighbor_key, line.to_string());
                        mods_made += 1;
                    } else {
                        debug!(
                            "Could not find interface {} for peer {}",
                            iface_name, peer_identity
                        );
                    }
                }
            } else {
                debug!("Could not parse neighbor data from line: {}", line);
            }
        }

        Ok(mods_made)
    }
}

#[test]
fn test_parse_mikrotik() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let interfaces_input = read_to_string("src/tests/mikrotik_interfaces.txt")
        .expect("Failed to read interfaces file");
    let routes_input =
        read_to_string("src/tests/mikrotik_routes.txt").expect("Failed to read routes file");

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

    let address_data = std::fs::read_to_string("src/tests/mikrotik_addresses.txt")
        .expect("Failed to read address file");

    parser
        .parse_ip_addresses(&address_data)
        .expect("Failed to parse IP addresses");

    assert!(!parser.interfaces.is_empty(), "Should have interfaces");
    assert!(parser.interfaces.iter().any(|iface| {
        iface
            .addresses
            .iter()
            .any(|addr| addr.to_string() == "123.123.123.230/22")
    }));
    assert!(parser.interfaces.iter().any(|iface| {
        iface.addresses.iter().any(|addr| {
            addr.to_string() == "2001:388:30bc:cafe::beef/128" && iface.name == "ether1"
        })
    }));

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

    let interfaces_input = read_to_string("src/tests/mikrotik_interfaces.txt")
        .expect("Failed to read interfaces file");

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

    let routes_input =
        read_to_string("src/tests/mikrotik_routes.txt").expect("Failed to read routes file");

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
fn test_mikrotik_store_raw_cdp_data() {
    crate::setup_test_logging();

    let test_cdp_data = r#"0 interface=sfp-sfpplus1,bridge address=10.0.99.2 mac-address=A0:23:9F:7B:2E:33 identity=C3650.example.com
1 interface=bridge address=10.0.5.1 mac-address=A0:23:9F:7B:2E:34 identity=test-cisco.example.com"#;

    let mut device = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // First, create an interface that the CDP data references
    let test_interface = Interface {
        interface_id: Uuid::new_v4(),
        name: "sfp-sfpplus1".to_string(),
        vlans: Vec::new(),
        addresses: Vec::new(),
        interface_type: InterfaceType::Ethernet,
        comment: None,
        mac_address: None,
        neighbour_string_data: std::collections::HashMap::new(),
        peers: std::collections::HashMap::new(),
    };

    device.interfaces.push(test_interface);

    // Add a bridge interface too since the test data references it
    let bridge_interface = Interface {
        interface_id: Uuid::new_v4(),
        name: "bridge".to_string(),
        vlans: Vec::new(),
        addresses: Vec::new(),
        interface_type: InterfaceType::Bridge,
        comment: None,
        mac_address: None,
        neighbour_string_data: std::collections::HashMap::new(),
        peers: std::collections::HashMap::new(),
    };
    device.interfaces.push(bridge_interface);

    // Test the store_raw_cdp_data method
    let result = device.store_raw_cdp_data(test_cdp_data);
    assert!(result.is_ok(), "CDP data storage should succeed");
    assert_eq!(
        result.unwrap(),
        3,
        "Should store three neighbor entries (2 from line 1, 1 from line 2)"
    );

    // Verify that the neighbor data was stored
    let sfp_interface = device
        .interfaces
        .iter()
        .find(|iface| iface.name == "sfp-sfpplus1")
        .expect("Should find sfp-sfpplus1 interface");

    assert!(
        !sfp_interface.neighbour_string_data.is_empty(),
        "Should have neighbor data stored"
    );

    // Check that the CDP data contains the expected identity
    let has_cisco_neighbor = sfp_interface
        .neighbour_string_data
        .values()
        .any(|data| data.contains("C3650.example.com"));
    assert!(has_cisco_neighbor, "Should have C3650 neighbor data");

    // Also check bridge interface has the second neighbor
    let bridge_interface = device
        .interfaces
        .iter()
        .find(|iface| iface.name == "bridge")
        .expect("Should find bridge interface");

    let has_bridge_neighbor = bridge_interface
        .neighbour_string_data
        .values()
        .any(|data| data.contains("test-cisco.example.com"));
    assert!(
        has_bridge_neighbor,
        "Should have test-cisco neighbor data on bridge"
    );
}

#[test]
fn test_parse_mikrotik_identity() {
    crate::setup_test_logging();

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test normal identity output
    let identity_output = "name: MyMikroTik\n";
    mikrotik
        .parse_identity(identity_output)
        .expect("Failed to parse identity");
    assert_eq!(mikrotik.system_identity, Some("MyMikroTik".to_string()));

    // Test with extra whitespace
    let identity_output = "   name:   EdgeRouter-X   \n";
    mikrotik
        .parse_identity(identity_output)
        .expect("Failed to parse");
    assert_eq!(mikrotik.system_identity, Some("EdgeRouter-X".to_string()));

    // Test empty output
    assert!(mikrotik.parse_identity("").is_err());

    // Test output without name field
    let identity_output = "some other line\nanother line\n";
    assert!(mikrotik.parse_identity(identity_output).is_err());
}
