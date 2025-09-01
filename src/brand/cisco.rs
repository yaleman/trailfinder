use cidr::IpCidr;
use regex::Regex;
use std::str::FromStr;
use tracing::{debug, error, trace};
use uuid::Uuid;

use super::prelude::*;
use crate::config::{DeviceConfig, DeviceState};
use crate::ssh::SshClient;

pub struct Cisco {
    hostname: String,
    name: Option<String>,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
}

impl Cisco {
    #[cfg(test)]
    pub fn test_device() -> Self {
        Self {
            hostname: "test-cisco.example.com".to_string(),
            name: Some("Test Cisco Device".to_string()),
            owner: Owner::Unknown,
            device_type: DeviceType::Switch,
            routes: Vec::new(),
            interfaces: Vec::new(),
        }
    }
}

impl DeviceHandler for Cisco {
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
        let lines: Vec<&str> = input_data.lines().map(|l| l.trim()).collect();
        let mac_regex = Regex::new(r"address is ([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})")?;
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i];
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }

            // Parse Cisco "show interfaces" output
            // Look for interface lines like "GigabitEthernet0/1 is up, line protocol is up"
            // or "Vlan1 is up, line protocol is up"
            if line.contains(" is ") && (line.contains(" up") || line.contains(" down")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    i += 1;
                    continue;
                }

                let interface_name = parts[0].to_string();

                // Determine interface type from name
                let interface_type = if interface_name.to_lowercase().starts_with("gigabitethernet")
                    || interface_name.to_lowercase().starts_with("gi")
                    || interface_name.to_lowercase().starts_with("fastethernet")
                    || interface_name.to_lowercase().starts_with("fa")
                    || interface_name.to_lowercase().starts_with("ethernet")
                {
                    InterfaceType::Ethernet
                } else if interface_name.to_lowercase().starts_with("vlan") {
                    InterfaceType::Vlan
                } else if interface_name.to_lowercase().starts_with("loopback")
                    || interface_name.to_lowercase().starts_with("lo")
                {
                    InterfaceType::Loopback
                } else {
                    InterfaceType::Other(interface_name.clone())
                };

                // Extract VLAN ID if it's a VLAN interface
                let vlan = if interface_type == InterfaceType::Vlan {
                    interface_name
                        .strip_prefix("Vlan")
                        .or_else(|| interface_name.strip_prefix("vlan"))
                        .and_then(|vlan_str| vlan_str.parse::<u16>().ok())
                } else {
                    None
                };

                // Parse MAC address from the following lines
                let mut mac_address = None;
                let mut j = i + 1;

                // Look ahead for MAC address in "Hardware is ... address is ..." line
                while j < lines.len() && j < i + 10 {
                    // Limit look-ahead to avoid infinite loops
                    let detail_line = lines[j];
                    if detail_line.is_empty() {
                        break; // End of this interface block
                    }

                    // Look for "Hardware is ... address is 0050.56c0.0001"
                    if detail_line.contains("Hardware is") && detail_line.contains("address is") {
                        // Extract MAC address using regex
                        if let Some(captures) = mac_regex.captures(detail_line)
                            && let Some(mac_match) = captures.get(1)
                        {
                            // Convert Cisco format (0050.56c0.0001) to standard format (005056c00001)
                            mac_address = mac_address::MacAddress::from_str(
                                &mac_match.as_str().replace(".", ""),
                            )
                            .inspect_err(|e| {
                                debug!(
                                    "Failed to parse MAC address '{}': {}",
                                    mac_match.as_str(),
                                    e
                                );
                            })
                            .ok();
                        }
                        break;
                    }
                    j += 1;
                }

                let interface = Interface {
                    interface_id: Uuid::new_v4(),
                    name: interface_name,
                    vlans: vlan.map(|v| vec![v]).unwrap_or_default(),
                    addresses: Vec::new(), // IP addresses would need separate parsing
                    interface_type,
                    comment: None,
                    mac_address,
                    neighbour_string_data: Default::default(),
                    peers: Default::default(),
                };

                self.interfaces.push(interface);
            }
            i += 1;
        }

        Ok(())
    }

    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        let route_finder = Regex::new(r#"(?P<target>[\d\.]+\d+)"#)?;

        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let target_matches = route_finder.captures(line);

            let target: IpCidr = if let Some(captures) = target_matches {
                match captures
                    .name("target")
                    .and_then(|m| m.as_str().parse::<cidr::IpCidr>().ok())
                {
                    Some(cidr) => cidr,
                    None => {
                        return Err(TrailFinderError::Parse(format!(
                            "Failed to parse target CIDR in line: {}",
                            line
                        )));
                    }
                }
            } else {
                continue;
            };

            // Parse Cisco "show ip route" output
            // Look for routes like:
            // "S*    0.0.0.0/0 [1/0] via 192.168.1.1"
            // "C     192.168.1.0/24 is directly connected, Vlan1"
            // "S     10.0.0.0/8 [1/0] via 192.168.1.254"

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            // Determine route type
            let route_type = if target.to_string() == "0.0.0.0/0" || parts[0].contains("*") {
                RouteType::Default(uuid::Uuid::new_v4()) // TODO: fix this
            } else {
                RouteType::NextHop(uuid::Uuid::new_v4()) // TODO: fix this
            };

            // Look for gateway information
            let mut gateway = None;
            let mut distance = None;

            for (i, part) in parts.iter().enumerate() {
                if *part == "via" && i + 1 < parts.len() {
                    // Try to parse the next part as an IP address
                    if let Ok(addr) = parts[i + 1].parse::<std::net::IpAddr>() {
                        gateway = Some(addr);
                    }
                } else if *part == "connected," && i + 1 < parts.len() {
                    // Directly connected interface
                    // interface_name = Some(parts[i + 1].to_string());
                } else if part.starts_with('[') && part.contains('/') && part.ends_with(']') {
                    // Administrative distance/metric in format [distance/metric]
                    let distance_str = part.trim_matches(['[', ']']);
                    if let Some(slash_pos) = distance_str.find('/')
                        && let Ok(dist) = distance_str[..slash_pos].parse::<u16>()
                    {
                        distance = Some(dist);
                    }
                }
            }

            let route = Route {
                target,
                route_type,
                gateway,
                distance,
            };

            self.routes.push(route);
        }

        Ok(())
    }

    fn parse_neighbours(
        &mut self,
        input_data: &str,
        _devices: Vec<Device>,
    ) -> Result<usize, TrailFinderError> {
        let mut mods_made = 0;
        let interface_parser = Regex::new(
            r#"Interface: (?<interface>\S+),\s+Port ID \(outgoing port\):\s*(?P<outgoing_port_id>\S+)"#,
        )?;

        let mut current_data = String::new();

        let lines = input_data.lines().collect::<Vec<&str>>();
        let num_lines = lines.len();
        for (line_no, line) in lines.iter().enumerate() {
            // debug!("Handling line #{line_no}: {line}");

            if line_no == num_lines - 1 || line.starts_with("---") {
                if current_data.is_empty() {
                    continue;
                }
                debug!("Found a full line");
            } else {
                current_data.push_str(&format!("{}\n", line));
                continue;
            }

            debug!("Full block: {current_data}");

            let interface_name = interface_parser.captures(&current_data).map(|caps| {
                let interface_name = caps.name("interface").map(|m| m.as_str().to_string());
                let port_id = caps
                    .name("outgoing_port_id")
                    .map(|m| m.as_str().to_string());

                (interface_name, port_id)
            });

            // find if have this interface already, and print a success/fail message
            if let Some((Some(interface_name), Some(port_id))) = interface_name {
                if let Some(interface) = self
                    .interfaces
                    .iter_mut()
                    .find(|interface| interface.name == interface_name)
                {
                    debug!("Successfully found peer interface: {}", interface.name);
                    if interface.neighbour_string_data.get(&port_id) != Some(&current_data) {
                        debug!(
                            "Updating neighbour data for interface from: \n{:?}\nto\n{:?}",
                            interface.neighbour_string_data,
                            Some(current_data.clone())
                        );
                        interface
                            .neighbour_string_data
                            .insert(port_id, current_data.clone());
                        mods_made += 1;
                        current_data.clear()
                    }
                } else {
                    error!("Can't find interface: {interface_name:?}");
                }
            }

            if line.starts_with("---") {
                trace!("Starting a new device on next line...");
                current_data.clear();
            }
        }

        Ok(mods_made)
    }

    fn build(self) -> Device {
        let mut device = Device::new(self.hostname, self.name, self.owner, self.device_type);
        device.routes = self.routes;
        device.interfaces = self.interfaces;

        device
    }

    fn get_cdp_command(&self) -> String {
        "show cdp neighbors".to_string()
    }

    fn get_interfaces_command(&self) -> String {
        "show interfaces".to_string()
    }

    fn get_routes_command(&self) -> String {
        "show ip route".to_string()
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

            // Get CDP/neighbor data
            let cdp_command = self.get_cdp_command();
            let cdp_output = ssh_client.execute_command(&cdp_command).await?;

            // Parse the data using the existing ConfParser implementation
            let mut parser = Cisco::new(
                device_config.hostname.clone(),
                None, // DeviceConfig doesn't have a name field
                device_config.owner.clone(),
                device_type,
            );

            parser.parse_interfaces(&interfaces_output)?;
            parser.parse_routes(&routes_output)?;

            // Store raw CDP data in interfaces for later global processing
            parser.store_raw_cdp_data(&cdp_output)?;

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

impl Cisco {
    /// Store raw CDP/neighbor data in interfaces for later global processing
    pub fn store_raw_cdp_data(&mut self, input_data: &str) -> Result<usize, TrailFinderError> {
        debug!("Storing raw CDP data: {input_data}");

        // Parse Cisco CDP neighbor output
        // Example output format:
        // Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
        // c3650.example.co Gig 1/0/1         144             R S   WS-C3750  Gig 1/0/1

        let mut mods_made = 0;

        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with("Device ID")
                || line.starts_with("Capability Codes:")
            {
                continue;
            }

            // Parse each line to extract neighbor information
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let device_id = parts[0];
                let local_interface = parts[1..3].join(" "); // Handle "Gig 1/0/1" format

                // Find the interface and store the neighbor data
                // Try both short and long interface names
                let interface_candidates = vec![
                    local_interface.clone(),
                    local_interface.replace("Gig ", "GigabitEthernet"),
                    local_interface.replace("Fa ", "FastEthernet"),
                    local_interface.replace("Te ", "TenGigabitEthernet"),
                    local_interface.replace("Ten ", "TenGigabitEthernet"),
                    // Also try without the space for cases where the format is different
                    local_interface.replace("Gig", "GigabitEthernet"),
                    local_interface.replace("Fa", "FastEthernet"),
                    local_interface.replace("Te", "TenGigabitEthernet"),
                    local_interface.replace("Ten", "TenGigabitEthernet"),
                ];

                let mut found_interface = false;
                for candidate in interface_candidates {
                    if let Some(existing_interface) = self
                        .interfaces
                        .iter_mut()
                        .find(|iface| iface.name == candidate || iface.name.contains(&candidate))
                    {
                        // Store the raw neighbor data
                        let neighbor_key = format!("{}@{}", device_id, candidate);
                        if existing_interface.neighbour_string_data.get(&neighbor_key)
                            != Some(&line.to_string())
                        {
                            existing_interface
                                .neighbour_string_data
                                .insert(neighbor_key, line.to_string());
                            mods_made += 1;
                        }
                        found_interface = true;
                        break;
                    }
                }

                if !found_interface {
                    debug!(
                        "Interface {} not found for neighbor data: {line}",
                        local_interface
                    );
                }
            }
        }

        Ok(mods_made)
    }
}

#[cfg(test)]
mod tests {
    use crate::setup_test_logging;

    use super::*;

    #[test]
    fn test_cisco_interface_parsing() {
        let cisco_interfaces = r#"
GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is 0050.56c0.0001 (bia 0050.56c0.0001)
  Internet address is 192.168.1.10/24
FastEthernet0/2 is down, line protocol is down
  Hardware is Fast Ethernet, address is 0050.56c0.0002 (bia 0050.56c0.0002)
Vlan1 is up, line protocol is up
  Hardware is EtherSVI, address is 0050.56c0.0003 (bia 0050.56c0.0003)
  Internet address is 192.168.10.1/24
Loopback0 is up, line protocol is up
  Hardware is Loopback
"#;

        let mut parser = Cisco::new(
            "cisco-test.example.com".to_string(),
            Some("cisco-test".to_string()),
            Owner::Named("Test Lab".to_string()),
            DeviceType::Switch,
        );

        let result = parser.parse_interfaces(cisco_interfaces);
        assert!(result.is_ok(), "Interface parsing should succeed");

        let device = parser.build();
        assert!(
            !device.interfaces.is_empty(),
            "Should have parsed interfaces"
        );

        // Check for expected interface types
        let ethernet_interfaces: Vec<_> = device
            .interfaces
            .iter()
            .filter(|iface| matches!(iface.interface_type, InterfaceType::Ethernet))
            .collect();
        assert!(
            !ethernet_interfaces.is_empty(),
            "Should have Ethernet interfaces"
        );

        let vlan_interfaces: Vec<_> = device
            .interfaces
            .iter()
            .filter(|iface| matches!(iface.interface_type, InterfaceType::Vlan))
            .collect();
        assert!(!vlan_interfaces.is_empty(), "Should have VLAN interfaces");

        // Check VLAN number extraction
        let vlan1 = device.interfaces.iter().find(|iface| iface.name == "Vlan1");
        assert!(vlan1.is_some(), "Should find Vlan1 interface");
        assert_eq!(vlan1.unwrap().vlans, vec![1], "VLAN number should be 1");
    }

    #[test]
    fn test_cisco_route_parsing() {
        let cisco_routes = r#"
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area

Gateway of last resort is 192.168.1.1 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.168.1.1
C     192.168.1.0/24 is directly connected, GigabitEthernet0/1
L     192.168.1.10/32 is directly connected, GigabitEthernet0/1
C     192.168.10.0/24 is directly connected, Vlan1
S     10.0.0.0/8 [1/0] via 192.168.1.254
"#;

        let mut parser = Cisco::new(
            "cisco-test.example.com".to_string(),
            Some("cisco-test".to_string()),
            Owner::Named("Test Lab".to_string()),
            DeviceType::Router,
        );

        let result = parser.parse_routes(cisco_routes);
        assert!(result.is_ok(), "Route parsing should succeed");

        let device = parser.build();
        assert!(!device.routes.is_empty(), "Should have parsed routes");

        // Check for default route
        let default_routes: Vec<_> = device
            .routes
            .iter()
            .filter(|route| matches!(route.route_type, RouteType::Default(_)))
            .collect();
        assert!(!default_routes.is_empty(), "Should have default route");

        // Check for specific routes
        let specific_routes: Vec<_> = device
            .routes
            .iter()
            .filter(|route| matches!(route.route_type, RouteType::NextHop(_)))
            .collect();
        assert!(!specific_routes.is_empty(), "Should have specific routes");

        println!(
            "✅ Parsed {} interfaces and {} routes successfully",
            device.interfaces.len(),
            device.routes.len()
        );
    }

    #[test]
    fn test_parse_cisco_cdp() {
        setup_test_logging();

        let input_data = r#"-------------------------
Device ID: Housenet
Entry address(es):
  IP address: 10.0.40.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): vlan40
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1

-------------------------
Device ID: Housenet
Entry address(es):
  IP address: 10.0.5.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): vlan20
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1

-------------------------
Device ID: Housenet
Entry address(es):
  IP address: 10.0.0.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): vlan10
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1

-------------------------
Device ID: Housenet
Entry address(es):
  IP address: 192.168.88.1
Platform: MikroTik,  Capabilities: Router
Interface: TenGigabitEthernet1/1/3,  Port ID (outgoing port): bridge/sfp-sfpplus1
Holdtime : 93 sec

Version :
7.16.1 (stable) 2024-10-10 14:03:32

advertisement version: 1


Total cdp entries displayed : 4"#;

        let test_interface_data = r#"Vlan1 is administratively down, line protocol is down , Autostate Enabled
GigabitEthernet0/0 is up, line protocol is up
GigabitEthernet1/0/1 is up, line protocol is up (connected)
GigabitEthernet1/0/2 is down, line protocol is down (notconnect)
GigabitEthernet1/0/3 is up, line protocol is up (connected)
GigabitEthernet1/0/4 is down, line protocol is down (notconnect)
GigabitEthernet1/0/5 is up, line protocol is up (connected)
GigabitEthernet1/0/6 is up, line protocol is up (connected)
GigabitEthernet1/0/7 is up, line protocol is up (connected)
GigabitEthernet1/0/8 is down, line protocol is down (notconnect)
GigabitEthernet1/0/9 is up, line protocol is up (connected)
GigabitEthernet1/0/10 is down, line protocol is down (notconnect)
GigabitEthernet1/0/11 is down, line protocol is down (notconnect)
GigabitEthernet1/0/12 is down, line protocol is down (notconnect)
GigabitEthernet1/0/13 is up, line protocol is up (connected)
GigabitEthernet1/0/14 is up, line protocol is up (connected)
GigabitEthernet1/0/15 is up, line protocol is up (connected)
GigabitEthernet1/0/16 is up, line protocol is up (connected)
GigabitEthernet1/0/17 is down, line protocol is down (notconnect)
GigabitEthernet1/0/18 is down, line protocol is down (notconnect)
GigabitEthernet1/0/19 is up, line protocol is up (connected)
GigabitEthernet1/0/20 is down, line protocol is down (notconnect)
GigabitEthernet1/0/21 is up, line protocol is up (connected)
GigabitEthernet1/0/22 is down, line protocol is down (notconnect)
GigabitEthernet1/0/23 is up, line protocol is up (connected)
GigabitEthernet1/0/24 is down, line protocol is down (notconnect)
GigabitEthernet1/0/25 is up, line protocol is up (connected)
GigabitEthernet1/0/26 is down, line protocol is down (notconnect)
GigabitEthernet1/0/27 is up, line protocol is up (connected)
GigabitEthernet1/0/28 is down, line protocol is down (notconnect)
GigabitEthernet1/0/29 is down, line protocol is down (notconnect)
GigabitEthernet1/0/30 is down, line protocol is down (notconnect)
GigabitEthernet1/0/31 is down, line protocol is down (notconnect)
GigabitEthernet1/0/32 is down, line protocol is down (notconnect)
GigabitEthernet1/0/33 is down, line protocol is down (notconnect)
GigabitEthernet1/0/34 is down, line protocol is down (notconnect)
GigabitEthernet1/0/35 is down, line protocol is down (notconnect)
GigabitEthernet1/0/36 is down, line protocol is down (notconnect)
GigabitEthernet1/0/37 is up, line protocol is up (connected)
GigabitEthernet1/0/38 is down, line protocol is down (notconnect)
GigabitEthernet1/0/39 is up, line protocol is up (connected)
GigabitEthernet1/0/40 is down, line protocol is down (notconnect)
GigabitEthernet1/0/41 is up, line protocol is up (connected)
GigabitEthernet1/0/42 is up, line protocol is up (connected)
GigabitEthernet1/0/43 is up, line protocol is up (connected)
GigabitEthernet1/0/44 is up, line protocol is up (connected)
GigabitEthernet1/0/45 is up, line protocol is up (connected)
GigabitEthernet1/0/46 is up, line protocol is up (connected)
GigabitEthernet1/0/47 is up, line protocol is up (connected)
GigabitEthernet1/0/48 is up, line protocol is up (connected)
GigabitEthernet1/1/1 is down, line protocol is down (notconnect)
GigabitEthernet1/1/2 is down, line protocol is down (notconnect)
TenGigabitEthernet1/1/3 is up, line protocol is up (connected)
TenGigabitEthernet1/1/4 is down, line protocol is down (notconnect)
Port-channel2 is up, line protocol is up (connected)
Connection to c3650.housenet.yaleman.org closed by remote host."#;

        let mut device = Cisco::new(
            "test.example.com".to_string(),
            None,
            Owner::Unknown,
            DeviceType::Switch,
        );
        device
            .parse_interfaces(test_interface_data)
            .expect("Failed to parse interfaces");

        device.parse_routes("").expect("Failed to parse routes");
        let mut attempts = 0;
        while let Ok(changes) = device.parse_neighbours(input_data, vec![]) {
            if changes == 0 {
                println!("Finished parsing neighbours after {attempts} attempts");
                break;
            }
            attempts += 1;
            if attempts > 100 {
                panic!("Too many attempts to parse neighbours");
            }
        }
    }
}
