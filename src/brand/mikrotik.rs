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
            if line.trim().is_empty() {
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

            let interface_type = parts[2].into();

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
            if line.trim().is_empty() {
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
    let mut parser = Mikrotik::new(None, Owner::Unknown, DeviceType::Router);
    parser
        .parse_interfaces(&interfaces_input)
        .expect("Failed to parse interfaces");
    let res = parser.parse_routes(&routes_input);
    let device = parser.build();
    dbg!(&device);
    assert!(res.is_ok());
}
