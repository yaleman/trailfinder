use super::prelude::*;

pub struct Mikrotik {
    name: String,
    owner: Owner,
    device_type: DeviceType,
    routes: Vec<Route>,
    interfaces: Vec<Interface>,
}

impl ConfParser for Mikrotik {
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
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                return Err(TrailFinderError::Parse(format!(
                    "Invalid line format: {}",
                    line
                )));
            }

            // Try to find name= first, then default-name=
            let name =
                if let Some(name_part) = parts.iter().find(|&&part| part.starts_with("name=")) {
                    name_part.trim_start_matches("name=").to_string()
                } else if let Some(default_name_part) = parts
                    .iter()
                    .find(|&&part| part.starts_with("default-name="))
                {
                    default_name_part
                        .trim_start_matches("default-name=")
                        .to_string()
                } else {
                    return Err(TrailFinderError::InvalidLine(format!(
                        "Missing interface name or default-name in line: {}",
                        line
                    )));
                };

            let vlan = parts
                .iter()
                .find(|&&part| part.starts_with("vlan-id="))
                .and_then(|s| s.trim_start_matches("vlan-id=").parse::<u16>().ok());

            let comment = parts
                .iter()
                .find(|&&part| part.starts_with("comment="))
                .map(|s| {
                    let comment = s.trim_start_matches("comment=").to_string();
                    // strip leading/trailing quotes
                    if comment.starts_with('"') && comment.ends_with('"') {
                        comment[1..comment.len() - 1].to_string()
                    } else {
                        comment
                    }
                });

            // Extract the interface type from the path, not from parts[2] which is the command
            let interface_type = if let Some(path_part) = parts.get(1) {
                // parts[1] should be something like "bridge", "ethernet", "vlan", etc.
                (*path_part).into()
            } else {
                InterfaceType::Other("unknown".to_string())
            };

            let interface = Interface {
                name,
                vlan,
                addresses: Vec::new(),
                interface_type,
                comment,
            };
            self.interfaces.push(interface);
        }
        Ok(())
    }

    fn parse_routes(&mut self, input_data: &str) -> Result<(), TrailFinderError> {
        for line in input_data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return Err(TrailFinderError::InvalidLine(format!(
                    "Invalid line format: {}",
                    line
                )));
            }
            let route_addr = parts[1];
            let target = parts[2];
            let distance: u16 = parts[3]
                .parse()
                .map_err(|err| TrailFinderError::Parse(format!("Invalid distance: {}", err)))?;
            let route_type = if route_addr == "0.0.0.0/0" {
                RouteType::Default
            } else {
                RouteType::Specific
            };
            let mut route = Route {
                route_type,
                interface_id: None,
                gateway: None,
                distance: Some(distance),
            };
            if let Ok(addr) = target.parse::<IpAddr>() {
                route.gateway = Some(addr);
            } else {
                // Look for existing interface by name
                if let Some(existing_interface) =
                    self.interfaces.iter().find(|iface| iface.name == target)
                {
                    route.interface_id = Some(existing_interface.interface_id(&self.name));
                } else {
                    // Create a stub interface if not found and add it to interfaces
                    let stub_interface = Interface {
                        name: target.to_string(),
                        vlan: None,
                        addresses: Vec::new(),
                        interface_type: InterfaceType::Other(target.to_string()),
                        comment: Some("Referenced from route, not in interface list".to_string()),
                    };

                    route.interface_id = Some(stub_interface.interface_id(&self.name));
                    self.interfaces.push(stub_interface);
                }
            }
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

#[test]
fn test_parse_mikrotik() {
    use std::fs::read_to_string;
    
    let interfaces_input =
        read_to_string("mikrotik_interfaces.txt").expect("Failed to read interfaces file");
    let routes_input = read_to_string("mikrotik_routes.txt").expect("Failed to read routes file");
    
    let mut parser = Mikrotik::new(Some("test-router".to_string()), Owner::Named("Test Lab".to_string()), DeviceType::Router);
    
    // Parse interfaces first
    let interface_result = parser.parse_interfaces(&interfaces_input);
    assert!(interface_result.is_ok(), "Interface parsing should succeed");
    
    // Parse routes
    let route_result = parser.parse_routes(&routes_input);
    assert!(route_result.is_ok(), "Route parsing should succeed");
    
    // Build final device
    let device = parser.build();
    
    // Validate interface parsing results
    assert!(!device.interfaces.is_empty(), "Should have parsed interfaces");
    assert!(device.interfaces.len() >= 10, "Should have multiple interfaces");
    
    // Check for specific interface types
    let bridge_interfaces: Vec<_> = device.interfaces.iter()
        .filter(|iface| matches!(iface.interface_type, InterfaceType::Bridge))
        .collect();
    assert!(!bridge_interfaces.is_empty(), "Should have bridge interfaces");
    
    let ethernet_interfaces: Vec<_> = device.interfaces.iter()
        .filter(|iface| matches!(iface.interface_type, InterfaceType::Ethernet))
        .collect();
    assert!(!ethernet_interfaces.is_empty(), "Should have ethernet interfaces");
    
    let vlan_interfaces: Vec<_> = device.interfaces.iter()
        .filter(|iface| matches!(iface.interface_type, InterfaceType::Vlan))
        .collect();
    assert!(!vlan_interfaces.is_empty(), "Should have VLAN interfaces");
    
    // Validate route parsing results
    assert!(!device.routes.is_empty(), "Should have parsed routes");
    assert!(device.routes.len() >= 5, "Should have multiple routes");
    
    // Check for default route
    let default_routes: Vec<_> = device.routes.iter()
        .filter(|route| matches!(route.route_type, RouteType::Default))
        .collect();
    assert!(!default_routes.is_empty(), "Should have default route");
    
    // Check that routes have proper interface references
    let routes_with_interfaces: Vec<_> = device.routes.iter()
        .filter(|route| route.interface_id.is_some())
        .collect();
    assert!(!routes_with_interfaces.is_empty(), "Should have routes with interface references");
    
    // Validate interface ID generation works
    if let Some(first_interface) = device.interfaces.first() {
        let interface_id = first_interface.interface_id(&device.name);
        assert!(!interface_id.is_empty(), "Interface ID should not be empty");
        assert!(interface_id.contains(&device.name), "Interface ID should contain device name");
        assert!(interface_id.contains(&first_interface.name), "Interface ID should contain interface name");
    }
    
    // Test interface lookup by ID
    if let Some(first_interface) = device.interfaces.first() {
        let interface_id = first_interface.interface_id(&device.name);
        let found_interface = device.find_interface_by_id(&interface_id);
        assert!(found_interface.is_some(), "Should be able to find interface by ID");
        assert_eq!(found_interface.unwrap().name, first_interface.name, "Found interface should match original");
    }
    
    println!("✅ Parsed {} interfaces and {} routes successfully", 
             device.interfaces.len(), device.routes.len());
}

#[test]
fn test_mikrotik_interface_types() {
    use std::fs::read_to_string;
    
    let interfaces_input =
        read_to_string("mikrotik_interfaces.txt").expect("Failed to read interfaces file");
    
    let mut parser = Mikrotik::new(None, Owner::Unknown, DeviceType::Router);
    parser.parse_interfaces(&interfaces_input).expect("Failed to parse interfaces");
    let device = parser.build();
    
    // Check that we parsed different interface types correctly
    let interface_types: std::collections::HashMap<String, usize> = device.interfaces.iter()
        .map(|iface| format!("{:?}", iface.interface_type))
        .fold(std::collections::HashMap::new(), |mut acc, itype| {
            *acc.entry(itype).or_insert(0) += 1;
            acc
        });
    
    println!("Interface type distribution: {:?}", interface_types);
    
    // Should have multiple types
    assert!(interface_types.len() >= 3, "Should have multiple interface types");
    assert!(interface_types.contains_key("Bridge"), "Should have Bridge interfaces");
    assert!(interface_types.contains_key("Ethernet"), "Should have Ethernet interfaces");
    assert!(interface_types.contains_key("Vlan"), "Should have VLAN interfaces");
}

#[test]
fn test_mikrotik_route_types() {
    use std::fs::read_to_string;
    
    let routes_input = read_to_string("mikrotik_routes.txt").expect("Failed to read routes file");
    
    let mut parser = Mikrotik::new(None, Owner::Unknown, DeviceType::Router);
    parser.parse_routes(&routes_input).expect("Failed to parse routes");
    let device = parser.build();
    
    // Check that we have both default and specific routes
    let default_count = device.routes.iter()
        .filter(|route| matches!(route.route_type, RouteType::Default))
        .count();
    let specific_count = device.routes.iter()
        .filter(|route| matches!(route.route_type, RouteType::Specific))
        .count();
    
    assert!(default_count > 0, "Should have default routes");
    assert!(specific_count > 0, "Should have specific routes");
    
    println!("✅ Found {} default routes and {} specific routes", default_count, specific_count);
}
