use super::prelude::*;

pub struct Cisco {
    name: String,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
}

impl ConfParser for Cisco {
    fn new(name: Option<String>, owner: Owner, device_type: DeviceType) -> Self {
        Self {
            name: name.unwrap_or(uuid::Uuid::new_v4().to_string()),
            owner,
            device_type,
            routes: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    fn parse_interfaces(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse Cisco "show interfaces" output
            // Look for interface lines like "GigabitEthernet0/1 is up, line protocol is up"
            // or "Vlan1 is up, line protocol is up"
            if line.contains(" is ") && (line.contains(" up") || line.contains(" down")) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
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

                let interface = Interface {
                    name: interface_name,
                    vlan,
                    addresses: Vec::new(), // IP addresses would need separate parsing
                    interface_type,
                    comment: None,
                };

                self.interfaces.push(interface);
            }
        }

        Ok(())
    }

    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse Cisco "show ip route" output
            // Look for routes like:
            // "S*    0.0.0.0/0 [1/0] via 192.168.1.1"
            // "C     192.168.1.0/24 is directly connected, Vlan1"
            // "S     10.0.0.0/8 [1/0] via 192.168.1.254"

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let route_code = parts[0];
            let network = parts[1];

            // Determine route type
            let route_type = if network == "0.0.0.0/0" || route_code.contains("*") {
                RouteType::Default
            } else {
                RouteType::Specific
            };

            // Look for gateway information
            let mut gateway = None;
            let mut interface_name = None;
            let mut distance = None;

            for (i, part) in parts.iter().enumerate() {
                if *part == "via" && i + 1 < parts.len() {
                    // Try to parse the next part as an IP address
                    if let Ok(addr) = parts[i + 1].parse::<std::net::IpAddr>() {
                        gateway = Some(addr);
                    }
                } else if *part == "connected," && i + 1 < parts.len() {
                    // Directly connected interface
                    interface_name = Some(parts[i + 1].to_string());
                } else if part.starts_with('[') && part.contains('/') && part.ends_with(']') {
                    // Administrative distance/metric in format [distance/metric]
                    let distance_str = part.trim_matches(['[', ']']);
                    if let Some(slash_pos) = distance_str.find('/') {
                        if let Ok(dist) = distance_str[..slash_pos].parse::<u16>() {
                            distance = Some(dist);
                        }
                    }
                }
            }

            // Create interface_id if we have an interface name
            let interface_id = interface_name.map(|name| {
                // Find the interface in our parsed interfaces to get the proper ID
                if let Some(interface) = self.interfaces.iter().find(|iface| iface.name == name) {
                    interface.interface_id(&self.name)
                } else {
                    // Create a temporary interface for ID generation
                    let temp_interface = Interface {
                        name: name.clone(),
                        vlan: None,
                        addresses: Vec::new(),
                        interface_type: InterfaceType::Other(name),
                        comment: None,
                    };
                    temp_interface.interface_id(&self.name)
                }
            });

            let route = Route {
                route_type,
                interface_id,
                gateway,
                distance,
            };

            self.routes.push(route);
        }

        Ok(())
    }

    fn build(self) -> Device {
        Device {
            name: self.name,
            owner: self.owner,
            device_type: self.device_type,
            routes: self.routes,
            interfaces: self.interfaces,
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(vlan1.unwrap().vlan, Some(1), "VLAN number should be 1");
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
            .filter(|route| matches!(route.route_type, RouteType::Default))
            .collect();
        assert!(!default_routes.is_empty(), "Should have default route");

        // Check for specific routes
        let specific_routes: Vec<_> = device
            .routes
            .iter()
            .filter(|route| matches!(route.route_type, RouteType::Specific))
            .collect();
        assert!(!specific_routes.is_empty(), "Should have specific routes");

        println!(
            "✅ Parsed {} interfaces and {} routes successfully",
            device.interfaces.len(),
            device.routes.len()
        );
    }
}
