use cidr::IpCidr;
use regex::Regex;
use uuid::Uuid;

use super::DeviceInterrogator;
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

impl ConfParser for Cisco {
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
                    interface_id: Uuid::new_v4(),
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

    fn build(self) -> Device {
        let mut device = Device::new(self.hostname, self.name, self.owner, self.device_type);
        device.routes = self.routes;
        device.interfaces = self.interfaces;

        device
    }
}

impl DeviceInterrogator for Cisco {
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

            // Parse the data using the existing ConfParser implementation
            let mut parser = Cisco::new(
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
}
