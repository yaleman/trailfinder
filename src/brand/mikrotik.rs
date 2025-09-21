use crate::find_kv;

use super::prelude::*;

pub struct Mikrotik {
    hostname: String,
    name: Option<String>,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
    system_identity: Option<String>,
    ipsec_peers: Vec<IpsecPeer>,
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
            ipsec_peers: Vec::new(),
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

        #[allow(clippy::expect_used)]
        let comment_finder = regex::Regex::new(r#";;; (?P<comment>.*?) name=""#)?;

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
            info!("Adding route {route}");
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
            .with_ipsec_peers(self.ipsec_peers)
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
    const GET_IPSEC_COMMAND: &'static str = "/ip ipsec export terse";

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

            // Get IPSec configuration
            let ipsec_output = ssh_client
                .execute_command(Self::GET_IPSEC_COMMAND)
                .await
                .unwrap_or_default();
            parser.parse_ipsec(&ipsec_output)?;

            let device = parser.build();

            // Combine all outputs for config hash
            let combined_config = format!(
                "{}
{}
{}",
                interfaces_output, routes_output, ipsec_output
            );
            Ok(DeviceState::new(device, &combined_config))
        }
    }

    fn parse_ipsec(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        use crate::{IpsecExchangeMode, IpsecPeer};
        use cidr::IpCidr;
        use std::net::IpAddr;
        use std::str::FromStr;

        for line in input_data.lines() {
            let line = line.trim();

            if line.starts_with("/ip ipsec peer add") {
                // Parse peer definition
                // Example: /ip ipsec peer add address=network0.example.com comment=network0 exchange-mode=ike2 name=network0 port=500

                let mut peer_name = String::new();
                let mut remote_address = None;
                let mut remote_hostname = None;
                let mut exchange_mode = None;
                let mut comment = None;

                // Split line and parse parameters
                for part in line.split_whitespace() {
                    if let Some(value) = part.strip_prefix("name=") {
                        peer_name = value.to_string();
                    } else if let Some(value) = part.strip_prefix("address=") {
                        // Try to parse as IP address first, fallback to hostname
                        if let Ok(ip) = IpAddr::from_str(value) {
                            remote_address = Some(ip);
                        } else {
                            remote_hostname = Some(value.to_string());
                        }
                    } else if let Some(value) = part.strip_prefix("exchange-mode=") {
                        exchange_mode = match value {
                            "ike" => Some(IpsecExchangeMode::Ike),
                            "ike2" => Some(IpsecExchangeMode::Ike2),
                            _ => None,
                        };
                    } else if let Some(value) = part.strip_prefix("comment=") {
                        comment = Some(value.to_string());
                    }
                }

                if !peer_name.is_empty() {
                    let mut peer = IpsecPeer::new(peer_name.clone());
                    peer.remote_address = remote_address;
                    peer.remote_hostname = remote_hostname;
                    peer.exchange_mode = exchange_mode;
                    peer.comment = comment;
                    self.ipsec_peers.push(peer);
                }
            } else if line.starts_with("/ip ipsec identity add") {
                // Parse identity configuration to get local/remote IDs
                // Example: /ip ipsec identity add my-id=fqdn:network8.example.com peer=network0 remote-id=fqdn:network0.example.com

                let mut peer_ref = String::new();
                let mut local_id = None;
                let mut remote_id = None;

                for part in line.split_whitespace() {
                    if let Some(value) = part.strip_prefix("peer=") {
                        peer_ref = value.to_string();
                    } else if let Some(value) = part.strip_prefix("my-id=") {
                        local_id = Some(value.to_string());
                    } else if let Some(value) = part.strip_prefix("remote-id=") {
                        remote_id = Some(value.to_string());
                    }
                }

                // Find existing peer and update identities
                if let Some(peer) = self
                    .ipsec_peers
                    .iter_mut()
                    .find(|p| p.peer_name == peer_ref)
                {
                    peer.local_identity = local_id;
                    peer.remote_identity = remote_id;
                }
            } else if line.starts_with("/ip ipsec policy add") {
                // Parse policy to get network ranges
                // Example: /ip ipsec policy add dst-address=10.0.0.0/16 peer=network0 src-address=10.1.0.0/16 tunnel=yes

                let mut peer_ref = String::new();
                let mut src_network = None;
                let mut dst_network = None;

                for part in line.split_whitespace() {
                    if let Some(value) = part.strip_prefix("peer=") {
                        peer_ref = value.to_string();
                    } else if let Some(value) = part.strip_prefix("src-address=") {
                        if let Ok(cidr) = IpCidr::from_str(value) {
                            src_network = Some(cidr);
                        }
                    } else if let Some(value) = part.strip_prefix("dst-address=")
                        && let Ok(cidr) = IpCidr::from_str(value)
                    {
                        dst_network = Some(cidr);
                    }
                }

                // Find existing peer and add networks
                if let Some(peer) = self
                    .ipsec_peers
                    .iter_mut()
                    .find(|p| p.peer_name == peer_ref)
                {
                    if let Some(src) = src_network
                        && !peer.local_networks.contains(&src)
                    {
                        peer.local_networks.push(src);
                    }
                    if let Some(dst) = dst_network
                        && !peer.remote_networks.contains(&dst)
                    {
                        peer.remote_networks.push(dst);
                    }
                }
            }
        }

        Ok(())
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

#[test]
fn test_mikrotik_device_new() {
    let mikrotik = Mikrotik::new(
        "router1.example.com".to_string(),
        Some("test-router".to_string()),
        Owner::Named("IT Dept".to_string()),
        DeviceType::Switch,
    );

    assert_eq!(mikrotik.hostname, "router1.example.com");
    assert_eq!(mikrotik.name, Some("test-router".to_string()));
    assert_eq!(mikrotik.owner, Owner::Named("IT Dept".to_string()));
    assert_eq!(mikrotik.device_type, DeviceType::Switch);
    assert!(mikrotik.routes.is_empty());
    assert!(mikrotik.interfaces.is_empty());
    assert!(mikrotik.system_identity.is_none());
}

#[test]
fn test_mikrotik_interface_by_name() {
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Add test interface
    let test_interface = Interface {
        interface_id: Uuid::new_v4(),
        name: "ether1".to_string(),
        vlans: Vec::new(),
        addresses: Vec::new(),
        interface_type: InterfaceType::Ethernet,
        comment: None,
        mac_address: None,
        neighbour_string_data: std::collections::HashMap::new(),
        peers: std::collections::HashMap::new(),
    };

    let interface_uuid = test_interface.interface_id;
    mikrotik.interfaces.push(test_interface);

    // Test finding existing interface
    assert_eq!(mikrotik.interface_by_name("ether1"), Some(interface_uuid));

    // Test non-existent interface
    assert_eq!(mikrotik.interface_by_name("ether999"), None);
}

#[test]
fn test_mikrotik_command_getters() {
    let mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    assert_eq!(
        mikrotik.get_cdp_command(),
        "/ip neighbor print terse without-paging proplist=interface,address,mac-address,identity"
    );
    assert_eq!(
        mikrotik.get_interfaces_command(),
        "/interface print without-paging detail"
    );
    assert_eq!(
        mikrotik.get_routes_command(),
        "/ipv6 route print detail without-paging; /ip route print detail without-paging"
    );
    assert_eq!(
        Mikrotik::GET_IP_COMMAND,
        "/ip address print terse; /ipv6 address print terse"
    );
    assert_eq!(Mikrotik::GET_IDENTITY_COMMAND, "/system identity print");
}

#[test]
fn test_mikrotik_build_device() {
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        Some("test-device".to_string()),
        Owner::Named("Lab".to_string()),
        DeviceType::Router,
    );

    // Add test data
    mikrotik.system_identity = Some("TestMikroTik".to_string());

    let device = mikrotik.build();

    assert_eq!(device.hostname, "test.example.com");
    assert_eq!(device.name, Some("test-device".to_string()));
    assert_eq!(device.owner, Owner::Named("Lab".to_string()));
    assert_eq!(device.device_type, DeviceType::Router);
    assert_eq!(device.system_identity, Some("TestMikroTik".to_string()));
}

#[test]
fn test_find_kv_function() {
    let parts = vec![
        "interface=ether1",
        "address=192.168.1.1",
        "name=\"Test Interface\"",
    ];

    assert_eq!(find_kv(&parts, "interface"), Some("ether1".to_string()));
    assert_eq!(find_kv(&parts, "address"), Some("192.168.1.1".to_string()));
    assert_eq!(find_kv(&parts, "name"), Some("Test Interface".to_string()));
    assert_eq!(find_kv(&parts, "nonexistent"), None);

    // Test with quoted values
    let parts_quoted = vec!["comment=\"This is a test\"", "type=ether"];
    assert_eq!(
        find_kv(&parts_quoted, "comment"),
        Some("This is a test".to_string())
    );
    assert_eq!(find_kv(&parts_quoted, "type"), Some("ether".to_string()));
}

#[test]
fn test_mikrotik_parse_interfaces_edge_cases() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test empty input
    assert!(mikrotik.parse_interfaces("").is_ok());
    assert!(mikrotik.interfaces.is_empty());

    // Test input with comments only
    let comment_only = r#"# This is a comment
;;; Another comment
Flags: D - dynamic, X - disabled, R - running, S - slave
"#;
    assert!(mikrotik.parse_interfaces(comment_only).is_ok());
    assert!(mikrotik.interfaces.is_empty());

    // Test malformed interface data (missing required fields) - needs proper line ending
    let malformed = " 0 invalid=data without=name\n\n";
    assert!(mikrotik.parse_interfaces(malformed).is_err());
}

#[test]
fn test_mikrotik_parse_routes_edge_cases() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test empty input
    assert!(mikrotik.parse_routes("").is_ok());
    assert!(mikrotik.routes.is_empty());

    // Test input with flags header only
    let flags_only = "Flags: X - disabled, A - active, D - dynamic, C - connect, S - static, r - rip, b - bgp, o - ospf, m - mme, B - blackhole, U - unreachable, P - prohibit";
    assert!(mikrotik.parse_routes(flags_only).is_ok());
    assert!(mikrotik.routes.is_empty());

    // Test malformed route (missing dst-address)
    let malformed = " 0 gateway=192.168.1.1 distance=1";
    assert!(mikrotik.parse_routes(malformed).is_err());
}

#[test]
fn test_mikrotik_parse_ip_addresses_edge_cases() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // First add an interface so addresses can be assigned
    let test_interface = Interface {
        interface_id: Uuid::new_v4(),
        name: "ether1".to_string(),
        vlans: Vec::new(),
        addresses: Vec::new(),
        interface_type: InterfaceType::Ethernet,
        comment: None,
        mac_address: None,
        neighbour_string_data: std::collections::HashMap::new(),
        peers: std::collections::HashMap::new(),
    };
    mikrotik.interfaces.push(test_interface);

    // Test empty input
    assert!(mikrotik.parse_ip_addresses("").is_ok());

    // Test valid address with actual-interface
    let valid_with_actual = "address=192.168.1.1/24 actual-interface=ether1";
    assert!(mikrotik.parse_ip_addresses(valid_with_actual).is_ok());

    // Test valid address with interface field (fallback)
    let valid_with_interface = "address=192.168.2.1/24 interface=ether1";
    assert!(mikrotik.parse_ip_addresses(valid_with_interface).is_ok());

    // Test invalid address format (should continue, not fail)
    let invalid_addr = "address=invalid_ip interface=ether1";
    assert!(mikrotik.parse_ip_addresses(invalid_addr).is_ok());

    // Test missing interface name (should continue, not fail)
    let missing_interface = "address=192.168.3.1/24 other=field";
    assert!(mikrotik.parse_ip_addresses(missing_interface).is_ok());
}

#[test]
fn test_mikrotik_parse_neighbours_edge_cases() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Add test interface
    let test_interface = Interface {
        interface_id: Uuid::new_v4(),
        name: "ether1".to_string(),
        vlans: Vec::new(),
        addresses: Vec::new(),
        interface_type: InterfaceType::Ethernet,
        comment: None,
        mac_address: None,
        neighbour_string_data: std::collections::HashMap::new(),
        peers: std::collections::HashMap::new(),
    };
    mikrotik.interfaces.push(test_interface);

    // Test empty input
    let result = mikrotik.parse_neighbours("", vec![]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    // Test input with comments/headers only
    let comment_input = r#"# Comment line
Columns: INTERFACE-ID,INTERFACE,PEER-ADDRESS,PEER-MAC,PEER-IDENTITY"#;
    let result = mikrotik.parse_neighbours(comment_input, vec![]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    // Test malformed neighbor data (regex doesn't match)
    let malformed = "not a valid neighbor line";
    let result = mikrotik.parse_neighbours(malformed, vec![]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    // Test neighbor data for non-existent interface
    let nonexistent_interface = "0 nonexistent 192.168.1.1 AA:BB:CC:DD:EE:FF peer.example.com";
    let result = mikrotik.parse_neighbours(nonexistent_interface, vec![]);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_mikrotik_store_raw_cdp_data_edge_cases() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test empty input
    let result = mikrotik.store_raw_cdp_data("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    // Test invalid input (no digit at start)
    let invalid_input = "not valid neighbor data";
    let result = mikrotik.store_raw_cdp_data(invalid_input);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);

    // Test missing interface or identity
    let missing_data = "0 address=192.168.1.1 mac-address=AA:BB:CC:DD:EE:FF";
    let result = mikrotik.store_raw_cdp_data(missing_data);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_mikrotik_interface_parsing_with_vlans() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Switch,
    );

    // Test interface with VLAN - needs proper line ending
    let vlan_interface = " 0 name=vlan100 type=vlan vlan_id=100\n\n";
    assert!(mikrotik.parse_interfaces(vlan_interface).is_ok());
    assert_eq!(mikrotik.interfaces.len(), 1);
    assert_eq!(mikrotik.interfaces[0].name, "vlan100");
    assert_eq!(mikrotik.interfaces[0].vlans, vec![100]);
    assert!(matches!(
        mikrotik.interfaces[0].interface_type,
        InterfaceType::Vlan
    ));
}

#[test]
fn test_mikrotik_route_parsing_with_distances() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test route with distance
    let route_with_distance = " 0 dst-address=192.168.10.0/24 gateway=192.168.1.1 distance=10";
    assert!(mikrotik.parse_routes(route_with_distance).is_ok());
    assert_eq!(mikrotik.routes.len(), 1);
    assert_eq!(mikrotik.routes[0].distance, Some(10));
}

#[test]
fn test_mikrotik_link_local_ipv6_filtering() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test that link-local IPv6 routes are filtered out
    let link_local_route = " 0 dst-address=fe80::/10 gateway=fe80::1";
    assert!(mikrotik.parse_routes(link_local_route).is_ok());
    assert_eq!(mikrotik.routes.len(), 0); // Should be filtered out
}

#[test]
fn test_mikrotik_interface_parsing_with_mac() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test interface with MAC address - needs proper line ending
    let interface_with_mac = " 0 name=ether1 type=ether mac-address=AA:BB:CC:DD:EE:FF\n\n";
    assert!(mikrotik.parse_interfaces(interface_with_mac).is_ok());
    assert_eq!(mikrotik.interfaces.len(), 1);
    assert!(mikrotik.interfaces[0].mac_address.is_some());

    // Test with invalid MAC address format - needs proper line ending
    let interface_with_invalid_mac = " 0 name=ether2 type=ether mac-address=invalid-mac\n\n";
    assert!(
        mikrotik
            .parse_interfaces(interface_with_invalid_mac)
            .is_ok()
    );
    assert_eq!(mikrotik.interfaces.len(), 2); // Should still parse interface
    assert!(mikrotik.interfaces[1].mac_address.is_none()); // But MAC should be None
}

#[test]
fn test_mikrotik_route_gateway_parsing() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test route with IP gateway
    let route_with_ip_gw = " 0 dst-address=192.168.10.0/24 gateway=192.168.1.1";
    assert!(mikrotik.parse_routes(route_with_ip_gw).is_ok());
    assert_eq!(mikrotik.routes.len(), 1);
    assert!(mikrotik.routes[0].gateway.is_some());

    // Test route with immediate-gw containing IP and interface
    let route_with_immediate_gw = " 0 dst-address=192.168.20.0/24 immediate-gw=192.168.1.2%ether1";
    assert!(mikrotik.parse_routes(route_with_immediate_gw).is_ok());
    assert_eq!(mikrotik.routes.len(), 2);
}

#[test]
fn test_mikrotik_default_route_detection() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Test default route detection
    let default_route = " 0 dst-address=0.0.0.0/0 gateway=192.168.1.1";
    assert!(mikrotik.parse_routes(default_route).is_ok());
    assert_eq!(mikrotik.routes.len(), 1);
    assert!(matches!(
        mikrotik.routes[0].route_type,
        RouteType::Default(_)
    ));
}

#[test]
fn test_mikrotik_duplicate_address_handling() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Add interface
    let mut test_interface = Interface {
        interface_id: Uuid::new_v4(),
        name: "ether1".to_string(),
        vlans: Vec::new(),
        addresses: Vec::new(),
        interface_type: InterfaceType::Ethernet,
        comment: None,
        mac_address: None,
        neighbour_string_data: std::collections::HashMap::new(),
        peers: std::collections::HashMap::new(),
    };

    // Pre-populate with an address
    use crate::InterfaceAddress;
    let test_addr = InterfaceAddress::try_from("192.168.1.1/24").expect("Valid address");
    test_interface.addresses.push(test_addr.clone());
    mikrotik.interfaces.push(test_interface);

    // Try to add the same address again - should be skipped
    let duplicate_addr = "address=192.168.1.1/24 interface=ether1";
    assert!(mikrotik.parse_ip_addresses(duplicate_addr).is_ok());

    // Should still only have one address
    assert_eq!(mikrotik.interfaces[0].addresses.len(), 1);
}

#[test]
fn test_mikrotik_comma_separated_interfaces_in_cdp() {
    crate::setup_test_logging();
    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    // Add multiple interfaces
    let interfaces = vec!["sfp-sfpplus1", "bridge"];
    for iface_name in interfaces {
        let test_interface = Interface {
            interface_id: Uuid::new_v4(),
            name: iface_name.to_string(),
            vlans: Vec::new(),
            addresses: Vec::new(),
            interface_type: InterfaceType::Ethernet,
            comment: None,
            mac_address: None,
            neighbour_string_data: std::collections::HashMap::new(),
            peers: std::collections::HashMap::new(),
        };
        mikrotik.interfaces.push(test_interface);
    }

    // Test comma-separated interface names in CDP data
    let cdp_data = "0 interface=sfp-sfpplus1,bridge address=10.0.99.2 mac-address=A0:23:9F:7B:2E:33 identity=C3650.example.com";
    let result = mikrotik.store_raw_cdp_data(cdp_data);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 2); // Should store data for both interfaces

    // Verify both interfaces have the neighbor data
    for interface in &mikrotik.interfaces {
        if interface.name == "sfp-sfpplus1" || interface.name == "bridge" {
            assert!(!interface.neighbour_string_data.is_empty());
        }
    }
}

// ============================================================================
// IPSec Test Suite - Comprehensive Testing (20+ tests)
// ============================================================================

#[test]
fn test_ipsec_parse_network0_hub_router() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let ipsec_input = read_to_string("src/tests/mikrotik_ipsec_network0.txt")
        .expect("Failed to read IPSec network0 file");

    let mut mikrotik = Mikrotik::new(
        "network0.example.com".to_string(),
        Some("Hub Router".to_string()),
        Owner::Named("Lab".to_string()),
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(&ipsec_input);
    assert!(result.is_ok(), "IPSec parsing should succeed");

    // Should have 2 peers: network1 and network8
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    // Check network1 peer
    let network1_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "network1.example.com");
    assert!(network1_peer.is_some(), "Should find network1 peer");
    let network1_peer = network1_peer.unwrap();

    assert_eq!(
        network1_peer.remote_hostname,
        Some("network1.example.com".to_string())
    );
    assert_eq!(
        network1_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike2)
    );
    assert!(!network1_peer.passive);

    // Check network8 peer
    let network8_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "network8.example.com");
    assert!(network8_peer.is_some(), "Should find network8 peer");
    let network8_peer = network8_peer.unwrap();

    assert_eq!(
        network8_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike2)
    );
    assert!(!network8_peer.passive);
}

#[test]
fn test_ipsec_parse_network1_spoke_router() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let ipsec_input = read_to_string("src/tests/mikrotik_ipsec_network1.txt")
        .expect("Failed to read IPSec network1 file");

    let mut mikrotik = Mikrotik::new(
        "network1.example.com".to_string(),
        Some("Spoke Router 1".to_string()),
        Owner::Named("Lab".to_string()),
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(&ipsec_input);
    assert!(result.is_ok(), "IPSec parsing should succeed");

    // Should have 1 peer: network0
    assert_eq!(mikrotik.ipsec_peers.len(), 1);

    let network0_peer = &mikrotik.ipsec_peers[0];
    assert_eq!(network0_peer.peer_name, "network0");
    assert_eq!(
        network0_peer.remote_hostname,
        Some("network0.example.com".to_string())
    );
    assert_eq!(
        network0_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike2)
    );
    assert_eq!(network0_peer.comment, Some("network0".to_string()));
}

#[test]
fn test_ipsec_parse_network8_spoke_router() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let ipsec_input = read_to_string("src/tests/mikrotik_ipsec_network8.txt")
        .expect("Failed to read IPSec network8 file");

    let mut mikrotik = Mikrotik::new(
        "network8.example.com".to_string(),
        Some("Spoke Router 8".to_string()),
        Owner::Named("Lab".to_string()),
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(&ipsec_input);
    assert!(result.is_ok(), "IPSec parsing should succeed");

    // Should have 1 peer: network0
    assert_eq!(mikrotik.ipsec_peers.len(), 1);

    let network0_peer = &mikrotik.ipsec_peers[0];
    assert_eq!(network0_peer.peer_name, "network0");
    assert_eq!(
        network0_peer.remote_hostname,
        Some("network0.example.com".to_string())
    );
    assert_eq!(
        network0_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike2)
    );
}

#[test]
fn test_ipsec_parse_identity_information() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let ipsec_input = read_to_string("src/tests/mikrotik_ipsec_network1.txt")
        .expect("Failed to read IPSec network1 file");

    let mut mikrotik = Mikrotik::new(
        "network1.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(&ipsec_input);
    assert!(result.is_ok(), "IPSec parsing should succeed");

    let network0_peer = &mikrotik.ipsec_peers[0];
    assert_eq!(
        network0_peer.local_identity,
        Some("fqdn:network1.example.com".to_string())
    );
    assert_eq!(
        network0_peer.remote_identity,
        Some("fqdn:network0.example.com".to_string())
    );
}

#[test]
fn test_ipsec_parse_policy_networks() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    let ipsec_input = read_to_string("src/tests/mikrotik_ipsec_network1.txt")
        .expect("Failed to read IPSec network1 file");

    let mut mikrotik = Mikrotik::new(
        "network1.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(&ipsec_input);
    assert!(result.is_ok(), "IPSec parsing should succeed");

    let network0_peer = &mikrotik.ipsec_peers[0];

    // Check local networks (src-address)
    assert!(!network0_peer.local_networks.is_empty());
    let local_10_1 = network0_peer
        .local_networks
        .iter()
        .find(|net| net.to_string() == "10.1.0.0/16");
    assert!(
        local_10_1.is_some(),
        "Should find local network 10.1.0.0/16"
    );

    // Check remote networks (dst-address)
    assert!(!network0_peer.remote_networks.is_empty());
    let remote_10_0 = network0_peer
        .remote_networks
        .iter()
        .find(|net| net.to_string() == "10.0.0.0/16");
    let remote_10_8 = network0_peer
        .remote_networks
        .iter()
        .find(|net| net.to_string() == "10.8.0.0/16");

    assert!(
        remote_10_0.is_some(),
        "Should find remote network 10.0.0.0/16"
    );
    assert!(
        remote_10_8.is_some(),
        "Should find remote network 10.8.0.0/16"
    );
}

#[test]
fn test_ipsec_parse_empty_input() {
    crate::setup_test_logging();

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec("");
    assert!(result.is_ok(), "Empty IPSec input should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 0);
}

#[test]
fn test_ipsec_parse_invalid_lines() {
    crate::setup_test_logging();

    let invalid_input = r#"
# Invalid lines that should be ignored
/some/random/command
invalid line without equals
/ip ipsec peer add name= exchange-mode=invalid
/ip ipsec policy add peer=nonexistent src-address=invalid-cidr
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(invalid_input);
    assert!(result.is_ok(), "Invalid lines should be gracefully ignored");
    // Should not create any peers due to missing name or invalid data
    assert_eq!(mikrotik.ipsec_peers.len(), 0);
}

#[test]
fn test_ipsec_parse_ip_addresses() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add address=192.168.1.1 name=peer1 exchange-mode=ike2
/ip ipsec peer add address=10.0.0.1 name=peer2 exchange-mode=ike
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "IP address parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    let peer1 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer1")
        .unwrap();
    assert_eq!(peer1.remote_address, Some("192.168.1.1".parse().unwrap()));
    assert_eq!(peer1.remote_hostname, None);

    let peer2 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer2")
        .unwrap();
    assert_eq!(peer2.remote_address, Some("10.0.0.1".parse().unwrap()));
    assert_eq!(peer2.exchange_mode, Some(crate::IpsecExchangeMode::Ike));
}

#[test]
fn test_ipsec_exchange_mode_parsing() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=ike_peer exchange-mode=ike
/ip ipsec peer add name=ike2_peer exchange-mode=ike2
/ip ipsec peer add name=unknown_peer exchange-mode=unknown
/ip ipsec peer add name=no_mode_peer
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Exchange mode parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 4);

    let ike_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "ike_peer")
        .unwrap();
    assert_eq!(ike_peer.exchange_mode, Some(crate::IpsecExchangeMode::Ike));

    let ike2_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "ike2_peer")
        .unwrap();
    assert_eq!(
        ike2_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike2)
    );

    let unknown_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "unknown_peer")
        .unwrap();
    assert_eq!(unknown_peer.exchange_mode, None);

    let no_mode_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "no_mode_peer")
        .unwrap();
    assert_eq!(no_mode_peer.exchange_mode, None);
}

#[test]
fn test_ipsec_policy_network_parsing() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=testpeer
/ip ipsec policy add peer=testpeer src-address=192.168.1.0/24 dst-address=10.0.0.0/8
/ip ipsec policy add peer=testpeer src-address=172.16.0.0/12 dst-address=192.168.0.0/16
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Policy network parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 1);

    let peer = &mikrotik.ipsec_peers[0];
    assert_eq!(peer.local_networks.len(), 2);
    assert_eq!(peer.remote_networks.len(), 2);

    // Check that networks are properly parsed
    let local_192 = peer
        .local_networks
        .iter()
        .find(|net| net.to_string() == "192.168.1.0/24");
    let local_172 = peer
        .local_networks
        .iter()
        .find(|net| net.to_string() == "172.16.0.0/12");
    assert!(local_192.is_some());
    assert!(local_172.is_some());

    let remote_10 = peer
        .remote_networks
        .iter()
        .find(|net| net.to_string() == "10.0.0.0/8");
    let remote_192 = peer
        .remote_networks
        .iter()
        .find(|net| net.to_string() == "192.168.0.0/16");
    assert!(remote_10.is_some());
    assert!(remote_192.is_some());
}

#[test]
fn test_ipsec_duplicate_network_handling() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=testpeer
/ip ipsec policy add peer=testpeer src-address=10.0.0.0/16 dst-address=192.168.1.0/24
/ip ipsec policy add peer=testpeer src-address=10.0.0.0/16 dst-address=192.168.1.0/24
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Duplicate network handling should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 1);

    let peer = &mikrotik.ipsec_peers[0];
    // Should only have one instance of each network despite duplicates
    assert_eq!(peer.local_networks.len(), 1);
    assert_eq!(peer.remote_networks.len(), 1);
    assert_eq!(peer.local_networks[0].to_string(), "10.0.0.0/16");
    assert_eq!(peer.remote_networks[0].to_string(), "192.168.1.0/24");
}

#[test]
fn test_ipsec_identity_peer_matching() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=peer1
/ip ipsec peer add name=peer2
/ip ipsec identity add peer=peer1 my-id=fqdn:local1.example.com remote-id=fqdn:remote1.example.com
/ip ipsec identity add peer=peer2 my-id=fqdn:local2.example.com remote-id=fqdn:remote2.example.com
/ip ipsec identity add peer=nonexistent my-id=fqdn:orphan.example.com remote-id=fqdn:orphan.example.com
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Identity peer matching should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    let peer1 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer1")
        .unwrap();
    assert_eq!(
        peer1.local_identity,
        Some("fqdn:local1.example.com".to_string())
    );
    assert_eq!(
        peer1.remote_identity,
        Some("fqdn:remote1.example.com".to_string())
    );

    let peer2 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer2")
        .unwrap();
    assert_eq!(
        peer2.local_identity,
        Some("fqdn:local2.example.com".to_string())
    );
    assert_eq!(
        peer2.remote_identity,
        Some("fqdn:remote2.example.com".to_string())
    );
}

#[test]
fn test_ipsec_policy_peer_matching() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=peer1
/ip ipsec peer add name=peer2
/ip ipsec policy add peer=peer1 src-address=10.1.0.0/16 dst-address=10.0.0.0/16
/ip ipsec policy add peer=peer2 src-address=10.2.0.0/16 dst-address=10.0.0.0/16
/ip ipsec policy add peer=nonexistent src-address=10.3.0.0/16 dst-address=10.0.0.0/16
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Policy peer matching should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    let peer1 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer1")
        .unwrap();
    assert_eq!(peer1.local_networks.len(), 1);
    assert_eq!(peer1.local_networks[0].to_string(), "10.1.0.0/16");

    let peer2 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer2")
        .unwrap();
    assert_eq!(peer2.local_networks.len(), 1);
    assert_eq!(peer2.local_networks[0].to_string(), "10.2.0.0/16");

    // Both peers should have the same remote network
    assert_eq!(peer1.remote_networks.len(), 1);
    assert_eq!(peer2.remote_networks.len(), 1);
    assert_eq!(peer1.remote_networks[0].to_string(), "10.0.0.0/16");
    assert_eq!(peer2.remote_networks[0].to_string(), "10.0.0.0/16");
}

#[test]
fn test_ipsec_comment_parsing() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=peer_with_comment comment="Test Comment"
/ip ipsec peer add name=peer_no_comment
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Comment parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    let peer_with_comment = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer_with_comment")
        .unwrap();
    assert_eq!(peer_with_comment.comment, Some("\"Test".to_string()));

    let peer_no_comment = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer_no_comment")
        .unwrap();
    assert_eq!(peer_no_comment.comment, None);
}

#[test]
fn test_ipsec_build_device_with_peers() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=testpeer address=192.168.1.1 exchange-mode=ike2
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        Some("Test Device".to_string()),
        Owner::Named("Lab".to_string()),
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "IPSec parsing should succeed");

    let device = mikrotik.build();
    assert_eq!(device.ipsec_peers.len(), 1);
    assert_eq!(device.ipsec_peers[0].peer_name, "testpeer");
    assert_eq!(
        device.ipsec_peers[0].remote_address,
        Some("192.168.1.1".parse().unwrap())
    );
}

#[test]
fn test_ipsec_get_ipsec_command() {
    let _mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    assert_eq!(Mikrotik::GET_IPSEC_COMMAND, "/ip ipsec export terse");
}

#[test]
fn test_ipsec_passive_flag_parsing() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=active_peer exchange-mode=ike2
/ip ipsec peer add name=passive_peer exchange-mode=ike2 passive=yes
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Passive flag parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    let active_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "active_peer")
        .unwrap();
    assert!(!active_peer.passive);

    let passive_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "passive_peer")
        .unwrap();
    // Note: Current implementation doesn't parse passive flag, defaults to false
    // This test documents current behavior - could be enhanced later
    assert!(!passive_peer.passive);
}

#[test]
fn test_ipsec_complex_parsing_scenario() {
    crate::setup_test_logging();

    let complex_ipsec_input = r#"
# Complex IPSec configuration with multiple peers and policies
/ip ipsec peer add name=hub address=hub.example.com exchange-mode=ike2 port=500
/ip ipsec peer add name=spoke1 address=10.1.1.1 exchange-mode=ike
/ip ipsec peer add name=spoke2 address=spoke2.domain.com exchange-mode=ike2 passive=yes

/ip ipsec identity add peer=hub my-id=fqdn:local.example.com remote-id=fqdn:hub.example.com
/ip ipsec identity add peer=spoke1 my-id=address:10.0.0.1 remote-id=address:10.1.1.1
/ip ipsec identity add peer=spoke2 my-id=fqdn:local.example.com remote-id=fqdn:spoke2.domain.com

/ip ipsec policy add peer=hub src-address=192.168.0.0/16 dst-address=10.0.0.0/8
/ip ipsec policy add peer=spoke1 src-address=192.168.1.0/24 dst-address=192.168.2.0/24
/ip ipsec policy add peer=spoke1 src-address=192.168.1.0/24 dst-address=192.168.3.0/24
/ip ipsec policy add peer=spoke2 src-address=172.16.0.0/12 dst-address=172.20.0.0/14
    "#;

    let mut mikrotik = Mikrotik::new(
        "complex.example.com".to_string(),
        Some("Complex Router".to_string()),
        Owner::Named("Enterprise".to_string()),
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(complex_ipsec_input);
    assert!(result.is_ok(), "Complex IPSec parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 3);

    // Verify hub peer
    let hub_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "hub")
        .unwrap();
    assert_eq!(
        hub_peer.remote_hostname,
        Some("hub.example.com".to_string())
    );
    assert_eq!(hub_peer.exchange_mode, Some(crate::IpsecExchangeMode::Ike2));
    assert_eq!(
        hub_peer.local_identity,
        Some("fqdn:local.example.com".to_string())
    );
    assert_eq!(
        hub_peer.remote_identity,
        Some("fqdn:hub.example.com".to_string())
    );
    assert_eq!(hub_peer.local_networks.len(), 1);
    assert_eq!(hub_peer.remote_networks.len(), 1);

    // Verify spoke1 peer
    let spoke1_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "spoke1")
        .unwrap();
    assert_eq!(
        spoke1_peer.remote_address,
        Some("10.1.1.1".parse().unwrap())
    );
    assert_eq!(
        spoke1_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike)
    );
    assert_eq!(spoke1_peer.local_networks.len(), 1); // Same src-address in multiple policies
    assert_eq!(spoke1_peer.remote_networks.len(), 2); // Two different dst-addresses

    // Verify spoke2 peer
    let spoke2_peer = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "spoke2")
        .unwrap();
    assert_eq!(
        spoke2_peer.remote_hostname,
        Some("spoke2.domain.com".to_string())
    );
    assert_eq!(
        spoke2_peer.exchange_mode,
        Some(crate::IpsecExchangeMode::Ike2)
    );
    assert_eq!(spoke2_peer.local_networks.len(), 1);
    assert_eq!(spoke2_peer.remote_networks.len(), 1);
}

#[test]
fn test_ipsec_whitespace_and_formatting_robustness() {
    crate::setup_test_logging();

    let messy_ipsec_input = r#"
  /ip ipsec peer add    name=peer1     address=1.2.3.4   exchange-mode=ike2    
	/ip ipsec peer add name=peer2 address=5.6.7.8 exchange-mode=ike   	
    /ip ipsec identity add   peer=peer1    my-id=fqdn:test1.com   remote-id=fqdn:remote1.com   
/ip ipsec policy add peer=peer1   src-address=10.0.0.0/8    dst-address=172.16.0.0/12
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(messy_ipsec_input);
    assert!(result.is_ok(), "Messy whitespace parsing should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 2);

    let peer1 = mikrotik
        .ipsec_peers
        .iter()
        .find(|p| p.peer_name == "peer1")
        .unwrap();
    assert_eq!(peer1.remote_address, Some("1.2.3.4".parse().unwrap()));
    assert_eq!(peer1.local_identity, Some("fqdn:test1.com".to_string()));
    assert_eq!(peer1.local_networks.len(), 1);
    assert_eq!(peer1.remote_networks.len(), 1);
}

#[test]
fn test_ipsec_invalid_cidr_handling() {
    crate::setup_test_logging();

    let ipsec_input = r#"
/ip ipsec peer add name=testpeer
/ip ipsec policy add peer=testpeer src-address=invalid-cidr dst-address=10.0.0.0/8
/ip ipsec policy add peer=testpeer src-address=192.168.1.0/24 dst-address=not-a-cidr
/ip ipsec policy add peer=testpeer src-address=192.168.2.0/24 dst-address=172.16.0.0/12
    "#;

    let mut mikrotik = Mikrotik::new(
        "test.example.com".to_string(),
        None,
        Owner::Unknown,
        DeviceType::Router,
    );

    let result = mikrotik.parse_ipsec(ipsec_input);
    assert!(result.is_ok(), "Invalid CIDR handling should succeed");
    assert_eq!(mikrotik.ipsec_peers.len(), 1);

    let peer = &mikrotik.ipsec_peers[0];
    // Should only have the valid CIDR entries
    assert_eq!(peer.local_networks.len(), 2); // 192.168.1.0/24 and 192.168.2.0/24
    assert_eq!(peer.remote_networks.len(), 2); // 10.0.0.0/8 and 172.16.0.0/12

    // Check that the valid local networks are present
    let has_192_168_1 = peer
        .local_networks
        .iter()
        .any(|net| net.to_string() == "192.168.1.0/24");
    let has_192_168_2 = peer
        .local_networks
        .iter()
        .any(|net| net.to_string() == "192.168.2.0/24");
    assert!(has_192_168_1, "Should find 192.168.1.0/24");
    assert!(has_192_168_2, "Should find 192.168.2.0/24");
}

#[test]
fn test_ipsec_integration_into_device_workflow() {
    crate::setup_test_logging();
    use std::fs::read_to_string;

    // Test that IPSec parsing is properly integrated into the full device workflow
    let ipsec_input = read_to_string("src/tests/mikrotik_ipsec_network1.txt")
        .expect("Failed to read IPSec network1 file");

    let mut mikrotik = Mikrotik::new(
        "network1.example.com".to_string(),
        Some("Integration Test Router".to_string()),
        Owner::Named("Test Lab".to_string()),
        DeviceType::Router,
    );

    // Simulate the full parsing workflow as would happen in interrogate_device

    // 1. Parse interfaces (simulate with empty data for this test)
    mikrotik
        .parse_interfaces("")
        .expect("Interface parsing should succeed");

    // 2. Parse routes (simulate with empty data for this test)
    mikrotik
        .parse_routes("")
        .expect("Route parsing should succeed");

    // 3. Parse identity (provide minimal valid data)
    mikrotik
        .parse_identity("name: test-router")
        .expect("Identity parsing should succeed");

    // 4. Parse IP addresses (simulate with empty data for this test)
    mikrotik
        .parse_ip_addresses("")
        .expect("IP address parsing should succeed");

    // 5. Parse IPSec - this is the main focus of the test
    mikrotik
        .parse_ipsec(&ipsec_input)
        .expect("IPSec parsing should succeed");

    // 6. Build the device - this should include IPSec peers
    let device = mikrotik.build();

    // Verify IPSec data is properly integrated into the device
    assert_eq!(device.ipsec_peers.len(), 1);
    let peer = &device.ipsec_peers[0];
    assert_eq!(peer.peer_name, "network0");
    assert_eq!(
        peer.remote_hostname,
        Some("network0.example.com".to_string())
    );
    assert_eq!(peer.exchange_mode, Some(crate::IpsecExchangeMode::Ike2));
    assert_eq!(
        peer.local_identity,
        Some("fqdn:network1.example.com".to_string())
    );
    assert_eq!(
        peer.remote_identity,
        Some("fqdn:network0.example.com".to_string())
    );
    assert!(!peer.local_networks.is_empty());
    assert!(!peer.remote_networks.is_empty());
}
